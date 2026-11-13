//! One bounded, serialized ntfy actor. HTTP framing, signed messages,
//! correlation and pacing are implemented in their respective sibling modules.

use std::io;
use std::time::{Duration, SystemTime};

use futures_util::{Stream, StreamExt, TryStreamExt};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::codec::LinesCodecError;
use tokio_util::sync::CancellationToken;

use crate::message::SignedPayload;
use crate::pacing::{
    HostGate, MIN_HOST_INTERVAL, MISSING_RETRY_AFTER_BACKOFF, OPERATION_WINDOW, OperationBudget,
    PacingSnapshot, reconnect_delay,
};
use crate::transport::{
    NtfyError, NtfyEvent, NtfyOperation, TryPublishError, build_client, check_publish_fresh,
    ndjson_lines, parse_ntfy_line, publish, subscribe,
};

pub use crate::transport::NtfyConfig;

/// Loaded non-secret pacing bytes. Missing history is not evidence about HTTP
/// operations performed by an older binary.
#[derive(Debug)]
pub enum NtfyPacingLoad {
    /// No pacing snapshot exists; apply one ordinary initial host cooldown.
    Missing,
    /// Opaque snapshot bytes owned by the discovery pacing schema.
    Snapshot(Vec<u8>),
}

/// Service-owned durable storage for non-secret ntfy pacing state.
/// Implementations must fail closed and atomically replace the snapshot.
pub trait NtfyPacingStore: std::fmt::Debug + Send + Sync {
    /// Load the previous snapshot without modifying it.
    fn load(&mut self) -> Result<NtfyPacingLoad, String>;
    /// Durably replace the complete snapshot before the next HTTP operation.
    fn save(&mut self, snapshot: &[u8]) -> Result<(), String>;
}

pub(crate) const HEALTHY_CONNECTION_RESET: Duration = Duration::from_secs(60 * 60);
const SUBSCRIPTION_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// Cloneable daemon-side control handle for the transport actor.
#[derive(Debug, Clone)]
pub struct NtfyHandle {
    outgoing: mpsc::Sender<SignedPayload>,
    cancel: CancellationToken,
}

impl NtfyHandle {
    /// Queue one already-signed payload without waiting for HTTP or channel capacity.
    pub fn try_publish(&self, payload: SignedPayload) -> Result<(), TryPublishError> {
        payload
            .to_json()
            .map_err(|e| TryPublishError::InvalidPayload(e.to_string()))?;
        self.outgoing.try_send(payload).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => TryPublishError::Full,
            mpsc::error::TrySendError::Closed(_) => TryPublishError::Closed,
        })
    }

    /// Cancel connection attempts, backoff sleeps, publishing and stream reads.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }
}

/// One serialized ntfy actor. Spawn `run` independently of the UDP loop.
/// Run exactly one actor per ntfy host; do not create an actor per publication.
#[derive(Debug)]
pub struct NtfyTransport {
    config: NtfyConfig,
    client: reqwest::Client,
    outgoing: mpsc::Receiver<SignedPayload>,
    events: mpsc::Sender<NtfyEvent>,
    cancel: CancellationToken,
    pacing_store: Option<Box<dyn NtfyPacingStore>>,
    pacing_reason: Option<String>,
}

impl NtfyTransport {
    /// Create bounded command/event channels and the corresponding daemon handle.
    pub fn channel(
        config: NtfyConfig,
        capacity: usize,
    ) -> Result<(Self, NtfyHandle, mpsc::Receiver<NtfyEvent>), NtfyError> {
        Self::channel_inner(config, capacity, None)
    }

    /// Create an actor whose rolling operation starts and explicit retry delays
    /// survive process restarts. Persistence happens before every HTTP attempt.
    pub fn channel_with_pacing_store(
        config: NtfyConfig,
        capacity: usize,
        store: Box<dyn NtfyPacingStore>,
    ) -> Result<(Self, NtfyHandle, mpsc::Receiver<NtfyEvent>), NtfyError> {
        Self::channel_inner(config, capacity, Some(store))
    }

    fn channel_inner(
        config: NtfyConfig,
        capacity: usize,
        pacing_store: Option<Box<dyn NtfyPacingStore>>,
    ) -> Result<(Self, NtfyHandle, mpsc::Receiver<NtfyEvent>), NtfyError> {
        if capacity == 0 {
            return Err(NtfyError::InvalidChannelCapacity);
        }
        let client = build_client(&config)?;
        let (outgoing_tx, outgoing) = mpsc::channel(capacity);
        let (events, event_rx) = mpsc::channel(capacity);
        let cancel = CancellationToken::new();
        let handle = NtfyHandle {
            outgoing: outgoing_tx,
            cancel: cancel.clone(),
        };
        Ok((
            Self {
                config,
                client,
                outgoing,
                events,
                cancel,
                pacing_store,
                pacing_reason: None,
            },
            handle,
            event_rx,
        ))
    }

    /// Run until cancellation, a closed event channel, or scheduler overflow.
    /// Budget exhaustion waits for the same rolling window; it never resets the budget.
    /// Subscription failures reconnect; individual publishes are never auto-retried.
    pub async fn run(self) -> Result<(), NtfyError> {
        match self.run_inner().await {
            Err(NtfyError::Cancelled) => Ok(()),
            result => result,
        }
    }

    async fn run_inner(mut self) -> Result<(), NtfyError> {
        let mut gate = HostGate::default();
        let mut budget = OperationBudget::new(self.config.operation_budget);
        let mut failures = 0u32;
        let mut pending_publish = None;
        self.restore_pacing(&mut gate, &mut budget).await?;

        loop {
            self.wait_for_turn(&gate).await?;
            match self
                .reserve_operation(&mut gate, &mut budget, NtfyOperation::Subscribe)
                .await
            {
                Ok(()) => {}
                Err(NtfyError::DailyBudgetExhausted(_)) => continue,
                Err(error) => return Err(error),
            }
            let subscribe_wall = SystemTime::now();

            let response = match subscribe(&self.client, &self.config, &self.cancel).await {
                Ok(response) => response,
                Err(error) => {
                    failures = failures.saturating_add(1).min(16);
                    let delay = required_retry_after(&error)
                        .unwrap_or(Duration::ZERO)
                        .max(reconnect_delay(failures));
                    self.defer_pacing(&mut gate, &mut budget, delay, error.to_string())?;
                    self.report_with_retry(&error, &gate).await?;
                    continue;
                }
            };
            let byte_stream = response.bytes_stream().map_err(io::Error::other);
            let lines = ndjson_lines(byte_stream);
            tokio::pin!(lines);
            let connected_at = Instant::now();
            let result = self
                .run_connected(
                    &mut lines,
                    &mut gate,
                    &mut budget,
                    subscribe_wall,
                    &mut pending_publish,
                    SUBSCRIPTION_IDLE_TIMEOUT,
                )
                .await;
            if let Some(payload) = pending_publish.take() {
                let detail = match &result {
                    Ok(()) => "subscription ended before the queued POST".to_owned(),
                    Err(error) => format!("subscription ended before the queued POST: {error}"),
                };
                if !matches!(&result, Err(NtfyError::EventChannelClosed)) {
                    self.emit(NtfyEvent::PublishFailed {
                        kind: payload.kind(),
                        request_id: payload.request_id(),
                        detail,
                    })
                    .await?;
                }
            }
            let error = match result {
                Ok(()) => return Ok(()),
                Err(error @ NtfyError::Cancelled)
                | Err(error @ NtfyError::EventChannelClosed)
                | Err(error @ NtfyError::ScheduleOverflow) => return Err(error),
                Err(error) => error,
            };
            failures = failures_after_connection(failures, connected_at.elapsed());
            self.defer_pacing(
                &mut gate,
                &mut budget,
                reconnect_delay(failures),
                error.to_string(),
            )?;
            self.report_with_retry(&error, &gate).await?;
        }
    }

    async fn run_connected<S>(
        &mut self,
        lines: &mut S,
        gate: &mut HostGate,
        budget: &mut OperationBudget,
        subscribe_wall: SystemTime,
        pending_publish: &mut Option<SignedPayload>,
        idle_timeout: Duration,
    ) -> Result<(), NtfyError>
    where
        S: Stream<Item = Result<String, LinesCodecError>> + Unpin,
    {
        let mut commands_closed = false;
        let mut announced_ready = false;
        let mut idle_deadline = Instant::now() + idle_timeout;

        loop {
            let publish_at = if announced_ready && pending_publish.is_some() {
                Some(gate.ready_at(Instant::now())?)
            } else {
                None
            };
            tokio::select! {
                _ = self.cancel.cancelled() => return Err(NtfyError::Cancelled),
                _ = tokio::time::sleep_until(idle_deadline) => {
                    return Err(NtfyError::Stream(format!(
                        "no NDJSON data or keepalive for {} seconds",
                        idle_timeout.as_secs()
                    )));
                }
                line = lines.next() => {
                    match line {
                        None => return Err(NtfyError::Stream("server closed NDJSON stream".to_owned())),
                        Some(Err(error)) => return Err(NtfyError::Stream(error.to_string())),
                        Some(Ok(line)) => {
                            idle_deadline = Instant::now() + idle_timeout;
                            let parsed = parse_ntfy_line(
                                &line,
                                &self.config.topic,
                                subscribe_wall,
                                self.config.replay_cached,
                            );
                            if !announced_ready && !line.is_empty() && !matches!(&parsed, Some(Err(_))) {
                                announced_ready = true;
                                self.emit(NtfyEvent::Subscribed {
                                    cached_replay: self.config.replay_cached,
                                }).await?;
                            }
                            if let Some(event) = parsed {
                                match event {
                                    Ok(event) => self.emit(event).await?,
                                    Err(error) => self.report(&error).await?,
                                }
                            }
                        }
                    }
                }
                command = self.outgoing.recv(), if !commands_closed && pending_publish.is_none() => {
                    match command {
                        Some(payload) => *pending_publish = Some(payload),
                        None => commands_closed = true,
                    }
                }
                _ = async {
                    if let Some(at) = publish_at {
                        tokio::time::sleep_until(at).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                }, if announced_ready && pending_publish.is_some() => {
                    let payload = pending_publish.take().expect("branch requires a payload");
                    if let Err(error) = check_publish_fresh(&payload, SystemTime::now()) {
                        self.report(&error).await?;
                        self.emit(NtfyEvent::PublishFailed {
                            kind: payload.kind(),
                            request_id: payload.request_id(),
                            detail: error.to_string(),
                        }).await?;
                        continue;
                    }
                    match self.reserve_operation(gate, budget, NtfyOperation::Publish).await {
                        Ok(()) => {}
                        Err(error @ NtfyError::DailyBudgetExhausted(_)) => {
                            self.emit(NtfyEvent::PublishFailed {
                                kind: payload.kind(),
                                request_id: payload.request_id(),
                                detail: error.to_string(),
                            }).await?;
                            continue;
                        }
                        Err(error) => return Err(error),
                    }
                    match publish(&self.client, &self.config, &self.cancel, &payload).await {
                        Ok(()) => {
                            self.emit(NtfyEvent::Published {
                                kind: payload.kind(),
                                request_id: payload.request_id(),
                            }).await?;
                        }
                        Err(error @ NtfyError::Cancelled) => return Err(error),
                        Err(error) => {
                            if let Some(delay) = required_retry_after(&error) {
                                self.defer_pacing(gate, budget, delay, error.to_string())?;
                                self.report_with_retry(&error, gate).await?;
                            } else {
                                self.report(&error).await?;
                            }
                            self.emit(NtfyEvent::PublishFailed {
                                kind: payload.kind(),
                                request_id: payload.request_id(),
                                detail: error.to_string(),
                            }).await?;
                            // Deliberately consume the failed command. A daemon may
                            // explicitly build a fresh record later; no retry loop.
                        }
                    }
                }
            }
        }
    }

    async fn wait_for_turn(&self, gate: &HostGate) -> Result<(), NtfyError> {
        let at = gate.ready_at(Instant::now())?;
        tokio::select! {
            _ = self.cancel.cancelled() => Err(NtfyError::Cancelled),
            _ = tokio::time::sleep_until(at) => Ok(()),
        }
    }

    async fn reserve_operation(
        &mut self,
        gate: &mut HostGate,
        budget: &mut OperationBudget,
        operation: NtfyOperation,
    ) -> Result<(), NtfyError> {
        let now = Instant::now();
        if let Err(error) = budget.reserve(now) {
            let retry_after = budget.recovery_delay(now).unwrap_or(OPERATION_WINDOW);
            self.defer_pacing(gate, budget, retry_after, error.to_string())?;
            let effective_wait = gate.remaining(Instant::now())?;
            self.emit(NtfyEvent::Error {
                operation,
                detail: error.to_string(),
                retry_after: Some(effective_wait),
            })
            .await?;
            return Err(error);
        }
        gate.note_start(now);
        self.pacing_reason = None;
        self.persist_pacing(gate, budget)?;
        Ok(())
    }

    fn defer_pacing(
        &mut self,
        gate: &mut HostGate,
        budget: &mut OperationBudget,
        delay: Duration,
        reason: String,
    ) -> Result<(), NtfyError> {
        let now = Instant::now();
        let previous = gate.remaining(now)?;
        gate.defer(now, delay)?;
        if delay >= previous || self.pacing_reason.is_none() {
            let mut reason = reason;
            if reason.len() > 4096 {
                let mut boundary = 4096;
                while !reason.is_char_boundary(boundary) {
                    boundary -= 1;
                }
                reason.truncate(boundary);
            }
            self.pacing_reason = Some(reason);
        }
        self.persist_pacing(gate, budget)
    }

    fn persist_pacing(
        &mut self,
        gate: &HostGate,
        budget: &OperationBudget,
    ) -> Result<(), NtfyError> {
        let Some(store) = &mut self.pacing_store else {
            return Ok(());
        };
        let now = Instant::now();
        let wall_now = SystemTime::now();
        let snapshot = PacingSnapshot {
            operation_starts_unix_ms: budget.starts_unix_ms(now, wall_now),
            not_before_unix_ms: gate.not_before_unix_ms(now, wall_now)?,
            reason: self.pacing_reason.clone(),
            ..PacingSnapshot::empty()
        };
        let bytes = serde_json::to_vec(&snapshot)
            .map_err(|error| NtfyError::PacingState(error.to_string()))?;
        store.save(&bytes).map_err(NtfyError::PacingState)
    }

    async fn restore_pacing(
        &mut self,
        gate: &mut HostGate,
        budget: &mut OperationBudget,
    ) -> Result<(), NtfyError> {
        let Some(store) = &mut self.pacing_store else {
            return Ok(());
        };
        let loaded = store.load().map_err(NtfyError::PacingState)?;
        match loaded {
            NtfyPacingLoad::Missing => {
                // A one-time migration must not invent legacy HTTP timestamps.
                // Apply only the normal host cooldown, then persist that gate so
                // a restart cannot restart the cooldown itself.
                gate.defer(Instant::now(), MIN_HOST_INTERVAL)?;
                self.pacing_reason = None;
                self.persist_pacing(gate, budget)?;
            }
            NtfyPacingLoad::Snapshot(bytes) => {
                let snapshot: PacingSnapshot = serde_json::from_slice(&bytes)
                    .map_err(|error| NtfyError::PacingState(error.to_string()))?;
                snapshot
                    .validate(self.config.operation_budget)
                    .map_err(NtfyError::PacingState)?;
                let now = Instant::now();
                let wall_now = SystemTime::now();
                budget.restore(&snapshot.operation_starts_unix_ms, now, wall_now);
                gate.restore(snapshot.not_before_unix_ms, now, wall_now)?;
                self.pacing_reason = snapshot.reason;
                let remaining = gate.remaining(now)?;
                if !remaining.is_zero() {
                    if let Some(reason) = &self.pacing_reason {
                        self.emit(NtfyEvent::Error {
                            operation: NtfyOperation::Subscribe,
                            detail: reason.clone(),
                            retry_after: Some(remaining),
                        })
                        .await?;
                    }
                } else {
                    self.pacing_reason = None;
                }
            }
        }
        Ok(())
    }

    async fn report_with_retry(&self, error: &NtfyError, gate: &HostGate) -> Result<(), NtfyError> {
        self.emit(NtfyEvent::Error {
            operation: error.operation(),
            detail: error.to_string(),
            retry_after: Some(gate.remaining(Instant::now())?),
        })
        .await
    }

    async fn report(&self, error: &NtfyError) -> Result<(), NtfyError> {
        self.emit(NtfyEvent::Error {
            operation: error.operation(),
            detail: error.to_string(),
            retry_after: error.retry_after(),
        })
        .await
    }

    async fn emit(&self, event: NtfyEvent) -> Result<(), NtfyError> {
        tokio::select! {
            _ = self.cancel.cancelled() => Err(NtfyError::Cancelled),
            result = self.events.send(event) => result.map_err(|_| NtfyError::EventChannelClosed),
        }
    }
}

fn failures_after_connection(failures: u32, connected_for: Duration) -> u32 {
    if connected_for >= HEALTHY_CONNECTION_RESET {
        1
    } else {
        failures.saturating_add(1).min(16)
    }
}

fn required_retry_after(error: &NtfyError) -> Option<Duration> {
    match error {
        NtfyError::HttpStatus {
            status: 429,
            retry_after: None,
            ..
        } => Some(MISSING_RETRY_AFTER_BACKOFF),
        _ => error.retry_after(),
    }
}

#[cfg(test)]
mod tests;
