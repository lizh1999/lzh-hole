//! One bounded, serialized ntfy actor per host. The actor owns every topic of
//! every relationship it serves, one shared host gate, one rolling operation
//! budget and one durable pacing snapshot.
//! HTTP framing, signed messages, correlation and pacing are implemented in
//! their respective sibling modules.

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{StreamExt, TryStreamExt};
use lzh_hole_types::RelationshipId;
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
    MAX_NTFY_TOPICS, NtfyError, NtfyEvent, NtfyOperation, TryPublishError, build_client,
    check_publish_fresh, ndjson_lines, parse_ntfy_line, publish, subscribe,
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
const MAX_TRACKED_FAILURES: u32 = 16;

/// Lifecycle of one relationship's subscription inside the single host actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubscriptionState {
    /// No stream and no request in flight; waiting for `next_attempt`.
    Idle,
    /// One subscribe HTTP request is in flight for this relationship.
    Connecting,
    /// An established NDJSON stream is read by a reader task.
    Streaming,
}

#[derive(Debug, Clone)]
struct Subscription {
    state: SubscriptionState,
    failures: u32,
    next_attempt: Instant,
    announced: bool,
    last_activity: Instant,
    connected_at: Instant,
}

/// Per-relationship subscription bookkeeping.
///
/// It deliberately owns no gate, budget or pacing state: every relationship of
/// one host shares the actor's single `HostGate` and `OperationBudget`, so
/// adding relationships can never add host operations per unit of time.
#[derive(Debug)]
pub(crate) struct Scheduler {
    subscriptions: BTreeMap<RelationshipId, Subscription>,
}

impl Scheduler {
    pub(crate) fn new(
        relationships: impl IntoIterator<Item = RelationshipId>,
        now: Instant,
    ) -> Self {
        let subscriptions = relationships
            .into_iter()
            .map(|relationship| {
                (
                    relationship,
                    Subscription {
                        state: SubscriptionState::Idle,
                        failures: 0,
                        next_attempt: now,
                        announced: false,
                        last_activity: now,
                        connected_at: now,
                    },
                )
            })
            .collect();
        Self { subscriptions }
    }

    fn get(&self, relationship: &RelationshipId) -> Option<&Subscription> {
        self.subscriptions.get(relationship)
    }

    pub(crate) fn state(&self, relationship: &RelationshipId) -> Option<SubscriptionState> {
        self.get(relationship)
            .map(|subscription| subscription.state)
    }

    pub(crate) fn failures(&self, relationship: &RelationshipId) -> Option<u32> {
        self.get(relationship)
            .map(|subscription| subscription.failures)
    }

    pub(crate) fn next_attempt(&self, relationship: &RelationshipId) -> Option<Instant> {
        self.get(relationship)
            .map(|subscription| subscription.next_attempt)
    }

    pub(crate) fn is_announced(&self, relationship: &RelationshipId) -> bool {
        self.get(relationship)
            .is_some_and(|subscription| subscription.announced)
    }

    /// A payload may be POSTed only on an established, announced stream of its
    /// own relationship. Response headers alone are not subscription health.
    pub(crate) fn publish_ready(&self, relationship: &RelationshipId) -> bool {
        self.get(relationship).is_some_and(|subscription| {
            subscription.state == SubscriptionState::Streaming && subscription.announced
        })
    }

    pub(crate) fn connected_for(&self, relationship: &RelationshipId, now: Instant) -> Duration {
        self.get(relationship)
            .map(|subscription| now.saturating_duration_since(subscription.connected_at))
            .unwrap_or_default()
    }

    pub(crate) fn note_subscribe_started(&mut self, relationship: RelationshipId, now: Instant) {
        if let Some(subscription) = self.subscriptions.get_mut(&relationship) {
            subscription.state = SubscriptionState::Connecting;
            subscription.announced = false;
            subscription.last_activity = now;
        }
    }

    pub(crate) fn note_subscribed(&mut self, relationship: RelationshipId, now: Instant) {
        if let Some(subscription) = self.subscriptions.get_mut(&relationship) {
            subscription.state = SubscriptionState::Streaming;
            subscription.announced = false;
            subscription.connected_at = now;
            subscription.last_activity = now;
        }
    }

    pub(crate) fn note_activity(&mut self, relationship: RelationshipId, now: Instant) {
        if let Some(subscription) = self.subscriptions.get_mut(&relationship) {
            subscription.last_activity = now;
        }
    }

    pub(crate) fn note_announced(&mut self, relationship: RelationshipId, now: Instant) {
        if let Some(subscription) = self.subscriptions.get_mut(&relationship) {
            subscription.announced = true;
            subscription.last_activity = now;
        }
    }

    /// Count one more consecutive failure for this relationship only.
    pub(crate) fn bump_failures(&mut self, relationship: &RelationshipId) -> u32 {
        let Some(subscription) = self.subscriptions.get_mut(relationship) else {
            return 0;
        };
        subscription.failures = subscription
            .failures
            .saturating_add(1)
            .min(MAX_TRACKED_FAILURES);
        subscription.failures
    }

    pub(crate) fn set_failures(&mut self, relationship: &RelationshipId, failures: u32) {
        if let Some(subscription) = self.subscriptions.get_mut(relationship) {
            subscription.failures = failures.min(MAX_TRACKED_FAILURES);
        }
    }

    /// Return this relationship to `Idle` with its own bounded backoff. Other
    /// relationships keep their own failure counts and attempt times.
    pub(crate) fn schedule_reconnect(
        &mut self,
        relationship: RelationshipId,
        now: Instant,
        delay: Duration,
    ) -> Result<(), NtfyError> {
        let at = now.checked_add(delay).ok_or(NtfyError::ScheduleOverflow)?;
        let Some(subscription) = self.subscriptions.get_mut(&relationship) else {
            return Ok(());
        };
        subscription.state = SubscriptionState::Idle;
        subscription.announced = false;
        subscription.next_attempt = at;
        Ok(())
    }

    /// Relationship whose own backoff has expired at `at`, oldest first.
    pub(crate) fn due_subscribe(&self, at: Instant) -> Option<RelationshipId> {
        self.subscriptions
            .iter()
            .filter(|(_, subscription)| {
                subscription.state == SubscriptionState::Idle && subscription.next_attempt <= at
            })
            .min_by_key(|(relationship, subscription)| (subscription.next_attempt, **relationship))
            .map(|(relationship, _)| *relationship)
    }

    /// Earliest per-relationship backoff deadline still outstanding.
    pub(crate) fn earliest_attempt(&self) -> Option<Instant> {
        self.subscriptions
            .values()
            .filter(|subscription| subscription.state == SubscriptionState::Idle)
            .map(|subscription| subscription.next_attempt)
            .min()
    }

    /// Earliest idle deadline among established streams.
    pub(crate) fn idle_deadline(&self, timeout: Duration) -> Option<Instant> {
        self.subscriptions
            .values()
            .filter(|subscription| subscription.state == SubscriptionState::Streaming)
            .filter_map(|subscription| subscription.last_activity.checked_add(timeout))
            .min()
    }

    /// A streaming relationship whose idle deadline has already passed.
    pub(crate) fn expired_idle(&self, now: Instant, timeout: Duration) -> Option<RelationshipId> {
        self.subscriptions
            .iter()
            .filter(|(_, subscription)| subscription.state == SubscriptionState::Streaming)
            .filter_map(|(relationship, subscription)| {
                subscription
                    .last_activity
                    .checked_add(timeout)
                    .filter(|deadline| *deadline <= now)
                    .map(|deadline| (deadline, *relationship))
            })
            .min()
            .map(|(_, relationship)| relationship)
    }
}

/// What the single host actor may do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NextOperation {
    /// Nothing is due yet; sleep until this instant and decide again.
    Wait(Instant),
    /// No timed work remains; wait for an external event.
    Idle,
    /// Start one subscribe HTTP request for this relationship.
    Subscribe(RelationshipId),
    /// POST the queued payload of this relationship.
    Publish(RelationshipId),
}

/// Pure scheduling decision for the single host actor.
///
/// Every candidate host operation - an initial subscribe, a reconnect and a
/// publish alike - is offered to the one shared `HostGate`, so the number of
/// relationships can never raise the number of operations per unit of time.
/// `ready_publishes` lists relationships with a queued payload whose own stream
/// is already announced, in daemon queue order.
pub(crate) fn next_host_operation(
    scheduler: &Scheduler,
    gate: &HostGate,
    ready_publishes: &[RelationshipId],
    last: Option<NtfyOperation>,
    now: Instant,
) -> Result<NextOperation, NtfyError> {
    let gate_ready = gate.ready_at(now)?;
    let subscribe = scheduler.due_subscribe(gate_ready);
    let publish = ready_publishes.first().copied();
    let chosen = match (subscribe, publish) {
        (None, None) => None,
        (Some(relationship), None) => Some(NextOperation::Subscribe(relationship)),
        (None, Some(relationship)) => Some(NextOperation::Publish(relationship)),
        // Alternate so neither reconnects nor publishes can starve the other.
        (Some(subscribe), Some(publish)) => Some(match last {
            Some(NtfyOperation::Publish) => NextOperation::Subscribe(subscribe),
            _ => NextOperation::Publish(publish),
        }),
    };
    if let Some(operation) = chosen {
        if gate_ready <= now {
            return Ok(operation);
        }
        return Ok(NextOperation::Wait(gate_ready));
    }
    // Nothing can start even when the gate opens; wake at the earliest backoff.
    Ok(match scheduler.earliest_attempt() {
        Some(at) => NextOperation::Wait(at.max(gate_ready)),
        None => NextOperation::Idle,
    })
}

/// One queued publication for one relationship's topic.
#[derive(Debug)]
pub(crate) struct PublishCommand {
    pub(crate) relationship: RelationshipId,
    pub(crate) payload: SignedPayload,
}

/// Messages a reader task sends back to the actor. A reader task never performs
/// HTTP, never sleeps to decide a reconnect and never touches the pacing store.
#[derive(Debug)]
pub(crate) enum StreamMessage {
    /// One bounded NDJSON line, or its framing failure.
    Line {
        relationship: RelationshipId,
        line: Result<String, LinesCodecError>,
    },
    /// The stream ended or failed; only the actor decides when to reconnect.
    Closed {
        relationship: RelationshipId,
        detail: String,
    },
}

async fn read_stream(
    relationship: RelationshipId,
    response: reqwest::Response,
    lines_tx: mpsc::Sender<StreamMessage>,
    token: CancellationToken,
) {
    let byte_stream = response.bytes_stream().map_err(io::Error::other);
    let lines = ndjson_lines(byte_stream);
    tokio::pin!(lines);
    loop {
        let next = tokio::select! {
            _ = token.cancelled() => return,
            next = lines.next() => next,
        };
        let (message, closed) = match next {
            None => (
                StreamMessage::Closed {
                    relationship,
                    detail: "server closed NDJSON stream".to_owned(),
                },
                true,
            ),
            Some(Err(error)) => (
                StreamMessage::Closed {
                    relationship,
                    detail: error.to_string(),
                },
                true,
            ),
            Some(Ok(line)) => (
                StreamMessage::Line {
                    relationship,
                    line: Ok(line),
                },
                false,
            ),
        };
        let sent = tokio::select! {
            _ = token.cancelled() => return,
            result = lines_tx.send(message) => result.is_ok(),
        };
        if closed || !sent {
            return;
        }
    }
}

async fn sleep_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending::<()>().await,
    }
}

/// Bounded internal reader channel: one slot per topic per event-channel slot,
/// hard-capped so a stalled daemon can never grow memory without bound.
fn stream_capacity(capacity: usize) -> usize {
    capacity.saturating_mul(MAX_NTFY_TOPICS).clamp(1, 1024)
}

/// Cloneable daemon-side control handle for the transport actor.
#[derive(Debug, Clone)]
pub struct NtfyHandle {
    outgoing: mpsc::Sender<PublishCommand>,
    served: Arc<BTreeMap<RelationshipId, String>>,
    cancel: CancellationToken,
}

impl NtfyHandle {
    /// Queue one already-signed payload for one relationship's topic.
    ///
    /// Refuses a relationship this actor does not serve. Never waits for HTTP
    /// or channel capacity.
    pub fn try_publish(
        &self,
        relationship: RelationshipId,
        payload: SignedPayload,
    ) -> Result<(), TryPublishError> {
        if !self.served.contains_key(&relationship) {
            return Err(TryPublishError::UnknownRelationship(relationship));
        }
        payload
            .to_json()
            .map_err(|e| TryPublishError::InvalidPayload(e.to_string()))?;
        self.outgoing
            .try_send(PublishCommand {
                relationship,
                payload,
            })
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => TryPublishError::Full,
                mpsc::error::TrySendError::Closed(_) => TryPublishError::Closed,
            })
    }

    /// Cancel connection attempts, backoff sleeps, publishing and stream reads.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }
}

/// Mutable state of one host actor, shared by every relationship it serves.
#[derive(Debug)]
struct ActorState {
    gate: HostGate,
    budget: OperationBudget,
    scheduler: Scheduler,
    pending: VecDeque<PublishCommand>,
    readers: BTreeMap<RelationshipId, CancellationToken>,
    subscribe_walls: BTreeMap<RelationshipId, SystemTime>,
    last: Option<NtfyOperation>,
    capacity: usize,
    commands_closed: bool,
}

impl ActorState {
    fn new(config: &NtfyConfig, capacity: usize, now: Instant) -> Self {
        Self {
            gate: HostGate::default(),
            budget: OperationBudget::new(config.operation_budget),
            scheduler: Scheduler::new(config.relationships(), now),
            pending: VecDeque::new(),
            readers: BTreeMap::new(),
            subscribe_walls: BTreeMap::new(),
            last: None,
            capacity,
            commands_closed: false,
        }
    }

    /// Relationships with a queued payload whose own stream is announced.
    fn ready_publishes(&self) -> Vec<RelationshipId> {
        let mut ready: Vec<RelationshipId> = Vec::new();
        for command in &self.pending {
            if !ready.contains(&command.relationship)
                && self.scheduler.publish_ready(&command.relationship)
            {
                ready.push(command.relationship);
            }
        }
        ready
    }

    fn stop_reader(&mut self, relationship: &RelationshipId) {
        if let Some(token) = self.readers.remove(relationship) {
            token.cancel();
        }
        self.subscribe_walls.remove(relationship);
    }
}

/// One serialized ntfy actor per host. Spawn `run` independently of the UDP loop.
/// Run exactly one actor per ntfy host; do not create an actor per publication
/// and do not create an actor per relationship. All topics of one host share
/// this actor's single host gate, rolling budget and durable pacing snapshot.
#[derive(Debug)]
pub struct NtfyTransport {
    config: NtfyConfig,
    client: reqwest::Client,
    outgoing: mpsc::Receiver<PublishCommand>,
    events: mpsc::Sender<NtfyEvent>,
    cancel: CancellationToken,
    pacing_store: Option<Box<dyn NtfyPacingStore>>,
    pacing_reason: Option<String>,
    capacity: usize,
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
        if config.relationships().next().is_none() {
            return Err(NtfyError::Config(
                "ntfy actor needs at least one relationship-bound topic; use NtfyConfig::multi or NtfyConfig::with_relationship".to_owned(),
            ));
        }
        let client = build_client(&config)?;
        let (outgoing_tx, outgoing) = mpsc::channel(capacity);
        let (events, event_rx) = mpsc::channel(capacity);
        let cancel = CancellationToken::new();
        let handle = NtfyHandle {
            outgoing: outgoing_tx,
            served: Arc::new(config.topics.clone()),
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
                capacity,
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
        let mut state = ActorState::new(&self.config, self.capacity, Instant::now());
        // The actor keeps one sender alive for its whole run, so a closed reader
        // channel cannot be observed while this actor is running.
        let (lines_tx, mut lines_rx) =
            mpsc::channel::<StreamMessage>(stream_capacity(self.capacity));
        self.restore_pacing(&mut state.gate, &mut state.budget)
            .await?;
        loop {
            self.drain_streams(&mut state, &mut lines_rx).await?;
            self.expire_idle(&mut state).await?;
            self.drain_commands(&mut state);
            let ready = state.ready_publishes();
            let decision = next_host_operation(
                &state.scheduler,
                &state.gate,
                &ready,
                state.last,
                Instant::now(),
            )?;
            match decision {
                NextOperation::Subscribe(relationship) => {
                    self.start_subscribe(&mut state, relationship, &lines_tx)
                        .await?;
                }
                NextOperation::Publish(relationship) => {
                    self.run_publish(&mut state, relationship).await?;
                }
                NextOperation::Wait(at) => {
                    self.wait_for_change(&mut state, &mut lines_rx, Some(at))
                        .await?;
                }
                NextOperation::Idle => {
                    self.wait_for_change(&mut state, &mut lines_rx, None)
                        .await?;
                }
            }
        }
    }

    fn drain_commands(&mut self, state: &mut ActorState) {
        while !state.commands_closed && state.pending.len() < state.capacity {
            match self.outgoing.try_recv() {
                Ok(command) => state.pending.push_back(command),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    state.commands_closed = true;
                    break;
                }
            }
        }
    }

    async fn drain_streams(
        &mut self,
        state: &mut ActorState,
        lines_rx: &mut mpsc::Receiver<StreamMessage>,
    ) -> Result<(), NtfyError> {
        while let Ok(message) = lines_rx.try_recv() {
            self.handle_stream_message(state, message).await?;
        }
        Ok(())
    }

    async fn handle_stream_message(
        &mut self,
        state: &mut ActorState,
        message: StreamMessage,
    ) -> Result<(), NtfyError> {
        match message {
            StreamMessage::Closed {
                relationship,
                detail,
            } => {
                self.fail_stream(state, relationship, Instant::now(), detail)
                    .await
            }
            StreamMessage::Line { relationship, line } => {
                let now = Instant::now();
                let line = match line {
                    Ok(line) => line,
                    Err(error) => {
                        return self
                            .fail_stream(state, relationship, now, error.to_string())
                            .await;
                    }
                };
                if state.scheduler.state(&relationship) != Some(SubscriptionState::Streaming) {
                    return Ok(());
                }
                state.scheduler.note_activity(relationship, now);
                let Some(topic) = self.config.topic_for(&relationship) else {
                    return Ok(());
                };
                let subscribe_wall = state
                    .subscribe_walls
                    .get(&relationship)
                    .copied()
                    .unwrap_or(UNIX_EPOCH);
                let parsed = parse_ntfy_line(
                    &line,
                    relationship,
                    topic,
                    subscribe_wall,
                    self.config.replay_cached,
                );
                if !state.scheduler.is_announced(&relationship)
                    && !line.is_empty()
                    && !matches!(&parsed, Some(Err(_)))
                {
                    state.scheduler.note_announced(relationship, now);
                    self.emit(NtfyEvent::Subscribed {
                        relationship,
                        cached_replay: self.config.replay_cached,
                    })
                    .await?;
                }
                match parsed {
                    Some(Ok(event)) => self.emit(event).await,
                    Some(Err(error)) => self.report(Some(relationship), &error).await,
                    None => Ok(()),
                }
            }
        }
    }

    async fn expire_idle(&mut self, state: &mut ActorState) -> Result<(), NtfyError> {
        loop {
            let now = Instant::now();
            let Some(relationship) = state.scheduler.expired_idle(now, SUBSCRIPTION_IDLE_TIMEOUT)
            else {
                return Ok(());
            };
            let detail = format!(
                "no NDJSON data or keepalive for {} seconds",
                SUBSCRIPTION_IDLE_TIMEOUT.as_secs()
            );
            self.fail_stream(state, relationship, now, detail).await?;
        }
    }

    /// End one relationship's stream and give it its own bounded backoff. The
    /// shared host gate and rolling budget are left alone, so other
    /// relationships keep their own reconnect rhythm.
    async fn fail_stream(
        &mut self,
        state: &mut ActorState,
        relationship: RelationshipId,
        now: Instant,
        detail: String,
    ) -> Result<(), NtfyError> {
        match state.scheduler.state(&relationship) {
            Some(SubscriptionState::Streaming) | Some(SubscriptionState::Connecting) => {}
            _ => return Ok(()),
        }
        let connected_for = state.scheduler.connected_for(&relationship, now);
        let previous = state.scheduler.failures(&relationship).unwrap_or(0);
        let failures = failures_after_connection(previous, connected_for);
        state.scheduler.set_failures(&relationship, failures);
        state.stop_reader(&relationship);
        state
            .scheduler
            .schedule_reconnect(relationship, now, reconnect_delay(failures))?;
        let error = NtfyError::Stream(detail);
        self.report_with_retry(Some(relationship), &error, state)
            .await
    }

    async fn start_subscribe(
        &mut self,
        state: &mut ActorState,
        relationship: RelationshipId,
        lines_tx: &mpsc::Sender<StreamMessage>,
    ) -> Result<(), NtfyError> {
        state
            .scheduler
            .note_subscribe_started(relationship, Instant::now());
        // A hostname that cannot be resolved makes the request impossible, so
        // it must neither spend a rolling budget operation nor escalate this
        // relationship's backoff: the next attempt gets the ordinary host
        // interval instead.
        match self.preflight_resolve(NtfyOperation::Subscribe).await {
            Ok(()) => {}
            Err(error @ NtfyError::Cancelled) => return Err(error),
            Err(error) => {
                let now = Instant::now();
                state.stop_reader(&relationship);
                state
                    .scheduler
                    .schedule_reconnect(relationship, now, MIN_HOST_INTERVAL)?;
                return self
                    .report_with_retry(Some(relationship), &error, state)
                    .await;
            }
        }
        match self
            .reserve_operation(
                &mut state.gate,
                &mut state.budget,
                NtfyOperation::Subscribe,
                Some(relationship),
            )
            .await
        {
            Ok(()) => {}
            Err(NtfyError::DailyBudgetExhausted(_)) => {
                // The gate now carries the rolling-window recovery delay; put the
                // relationship back to Idle so the scheduler retries it later.
                state.scheduler.schedule_reconnect(
                    relationship,
                    Instant::now(),
                    MIN_HOST_INTERVAL,
                )?;
                return Ok(());
            }
            Err(error) => return Err(error),
        }
        state.last = Some(NtfyOperation::Subscribe);
        let subscribe_wall = SystemTime::now();
        let response = match subscribe(&self.client, &self.config, relationship, &self.cancel).await
        {
            Ok(response) => response,
            Err(error @ NtfyError::Cancelled) => return Err(error),
            Err(error) => {
                let now = Instant::now();
                let failures = state.scheduler.bump_failures(&relationship);
                state.stop_reader(&relationship);
                state
                    .scheduler
                    .schedule_reconnect(relationship, now, reconnect_delay(failures))?;
                // Retry-After is host-level: it applies to every relationship.
                if let Some(delay) = required_retry_after(&error) {
                    self.defer_pacing(
                        &mut state.gate,
                        &mut state.budget,
                        delay,
                        error.to_string(),
                    )?;
                }
                return self
                    .report_with_retry(Some(relationship), &error, state)
                    .await;
            }
        };
        let token = CancellationToken::new();
        state.readers.insert(relationship, token.clone());
        state.subscribe_walls.insert(relationship, subscribe_wall);
        state
            .scheduler
            .note_subscribed(relationship, Instant::now());
        tokio::spawn(read_stream(relationship, response, lines_tx.clone(), token));
        Ok(())
    }

    async fn run_publish(
        &mut self,
        state: &mut ActorState,
        relationship: RelationshipId,
    ) -> Result<(), NtfyError> {
        let Some(index) = state
            .pending
            .iter()
            .position(|command| command.relationship == relationship)
        else {
            return Ok(());
        };
        let command = state.pending.remove(index).expect("index from position");
        let payload = command.payload;
        if let Err(error) = check_publish_fresh(&payload, SystemTime::now()) {
            self.report(Some(relationship), &error).await?;
            return self
                .emit(NtfyEvent::PublishFailed {
                    relationship,
                    kind: payload.kind(),
                    request_id: payload.request_id(),
                    detail: error.to_string(),
                })
                .await;
        }
        // A name that cannot be resolved makes the POST impossible, so the
        // command is failed here rather than after spending a budget operation.
        if let Err(error) = self.preflight_resolve(NtfyOperation::Publish).await {
            if matches!(error, NtfyError::Cancelled) {
                return Err(error);
            }
            self.report(Some(relationship), &error).await?;
            return self
                .emit(NtfyEvent::PublishFailed {
                    relationship,
                    kind: payload.kind(),
                    request_id: payload.request_id(),
                    detail: error.to_string(),
                })
                .await;
        }
        match self
            .reserve_operation(
                &mut state.gate,
                &mut state.budget,
                NtfyOperation::Publish,
                Some(relationship),
            )
            .await
        {
            Ok(()) => {}
            Err(error @ NtfyError::DailyBudgetExhausted(_)) => {
                return self
                    .emit(NtfyEvent::PublishFailed {
                        relationship,
                        kind: payload.kind(),
                        request_id: payload.request_id(),
                        detail: error.to_string(),
                    })
                    .await;
            }
            Err(error) => return Err(error),
        }
        state.last = Some(NtfyOperation::Publish);
        match publish(
            &self.client,
            &self.config,
            relationship,
            &self.cancel,
            &payload,
        )
        .await
        {
            Ok(()) => {
                self.emit(NtfyEvent::Published {
                    relationship,
                    kind: payload.kind(),
                    request_id: payload.request_id(),
                })
                .await
            }
            Err(error @ NtfyError::Cancelled) => Err(error),
            Err(error) => {
                if let Some(delay) = required_retry_after(&error) {
                    self.defer_pacing(
                        &mut state.gate,
                        &mut state.budget,
                        delay,
                        error.to_string(),
                    )?;
                    self.report_with_retry(Some(relationship), &error, state)
                        .await?;
                } else {
                    self.report(Some(relationship), &error).await?;
                }
                // Deliberately consume the failed command. A daemon may
                // explicitly build a fresh record later; no retry loop.
                self.emit(NtfyEvent::PublishFailed {
                    relationship,
                    kind: payload.kind(),
                    request_id: payload.request_id(),
                    detail: error.to_string(),
                })
                .await
            }
        }
    }

    async fn wait_for_change(
        &mut self,
        state: &mut ActorState,
        lines_rx: &mut mpsc::Receiver<StreamMessage>,
        deadline: Option<Instant>,
    ) -> Result<(), NtfyError> {
        let idle = state.scheduler.idle_deadline(SUBSCRIPTION_IDLE_TIMEOUT);
        let wake = match (deadline, idle) {
            (Some(deadline), Some(idle)) => Some(deadline.min(idle)),
            (deadline, idle) => deadline.or(idle),
        };
        let can_queue = state.pending.len() < state.capacity && !state.commands_closed;
        tokio::select! {
            _ = self.cancel.cancelled() => Err(NtfyError::Cancelled),
            message = lines_rx.recv() => {
                match message {
                    Some(message) => self.handle_stream_message(state, message).await,
                    // The actor owns one sender for its whole run.
                    None => Ok(()),
                }
            }
            command = self.outgoing.recv(), if can_queue => {
                match command {
                    Some(command) => {
                        state.pending.push_back(command);
                        Ok(())
                    }
                    // The daemon dropped its handle; keep serving subscriptions.
                    None => {
                        state.commands_closed = true;
                        Ok(())
                    }
                }
            }
            () = sleep_until(wake) => Ok(()),
        }
    }

    /// Resolve the base URL hostname once, before any host operation is reserved.
    ///
    /// This is deliberately not a host operation: it takes no turn on the shared
    /// gate, writes no pacing snapshot and spends nothing of the rolling budget,
    /// so a network whose gateway runs no resolver cannot burn that budget on
    /// requests that can never succeed. An IP literal host has no name to
    /// resolve, and a configuration without an injected resolver keeps the
    /// request path as its only resolution. The resolver bounds its own time;
    /// cancellation still wins over waiting for an answer.
    async fn preflight_resolve(&self, operation: NtfyOperation) -> Result<(), NtfyError> {
        let Some(resolver) = self.config.resolver() else {
            return Ok(());
        };
        let Some(host) = self.config.base_host() else {
            return Ok(());
        };
        if host.parse::<std::net::IpAddr>().is_ok() {
            return Ok(());
        }
        let resolved = tokio::select! {
            _ = self.cancel.cancelled() => return Err(NtfyError::Cancelled),
            result = resolver.resolve_once(host) => result,
        };
        resolved.map_err(|detail| NtfyError::Http {
            operation,
            detail: format!("preflight resolve of {host}: {detail}"),
        })
    }

    async fn reserve_operation(
        &mut self,
        gate: &mut HostGate,
        budget: &mut OperationBudget,
        operation: NtfyOperation,
        relationship: Option<RelationshipId>,
    ) -> Result<(), NtfyError> {
        let now = Instant::now();
        if let Err(error) = budget.reserve(now) {
            let retry_after = budget.recovery_delay(now).unwrap_or(OPERATION_WINDOW);
            self.defer_pacing(gate, budget, retry_after, error.to_string())?;
            let effective_wait = gate.remaining(Instant::now())?;
            self.emit(NtfyEvent::Error {
                relationship,
                operation,
                detail: error.to_string(),
                retry_after: Some(effective_wait),
            })
            .await?;
            return Err(error);
        }
        gate.note_start(now);
        self.pacing_reason = None;
        self.persist_pacing(gate, budget)
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
                            relationship: None,
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

    async fn report_with_retry(
        &self,
        relationship: Option<RelationshipId>,
        error: &NtfyError,
        state: &ActorState,
    ) -> Result<(), NtfyError> {
        let now = Instant::now();
        let mut retry_after = state.gate.remaining(now)?;
        if let Some(relationship) = relationship
            && let Some(at) = state.scheduler.next_attempt(&relationship)
        {
            retry_after = retry_after.max(at.saturating_duration_since(now));
        }
        self.emit(NtfyEvent::Error {
            relationship,
            operation: error.operation(),
            detail: error.to_string(),
            retry_after: Some(retry_after),
        })
        .await
    }

    async fn report(
        &self,
        relationship: Option<RelationshipId>,
        error: &NtfyError,
    ) -> Result<(), NtfyError> {
        self.emit(NtfyEvent::Error {
            relationship,
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
        failures.saturating_add(1).min(MAX_TRACKED_FAILURES)
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
