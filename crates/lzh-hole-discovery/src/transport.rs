//! HTTPS transport, bounded NDJSON framing and ntfy wire classification.
//! No business UDP socket is created or owned here.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures_util::Stream;
use serde::Deserialize;
use tokio_util::codec::{FramedRead, LinesCodec, LinesCodecError};
use tokio_util::io::StreamReader;
use tokio_util::sync::CancellationToken;

use crate::exchange::Delivery;
use crate::message::{MessageKind, RequestId, SignedPayload};
use crate::pacing::{DEFAULT_OPERATION_BUDGET, parse_retry_after};

/// Maximum NDJSON line, including ntfy metadata but excluding the newline.
pub const MAX_NTFY_LINE_BYTES: usize = 16 * 1024;
pub(crate) const CONNECT_AND_HEADERS_TIMEOUT: Duration = Duration::from_secs(25);
pub(crate) const PUBLISH_TIMEOUT: Duration = Duration::from_secs(25);
const USER_AGENT: &str = "lzh-hole-ntfy/1";

/// Validated ntfy connection settings. Production pacing cannot be lowered.
#[derive(Debug, Clone)]
pub struct NtfyConfig {
    base_url: reqwest::Url,
    pub(crate) topic: String,
    pub(crate) replay_cached: bool,
    pub(crate) operation_budget: u32,
    resolve_addr: Option<SocketAddr>,
}

impl NtfyConfig {
    /// Use an HTTPS ntfy base URL and an ASCII `[A-Za-z0-9_-]` topic (1..=64).
    pub fn new(base_url: &str, topic: &str) -> Result<Self, NtfyError> {
        let mut base_url = reqwest::Url::parse(base_url)
            .map_err(|e| NtfyError::Config(format!("base URL: {e}")))?;
        if base_url.scheme() != "https" || base_url.host_str().is_none() {
            return Err(NtfyError::Config(
                "ntfy base URL must be absolute HTTPS".to_owned(),
            ));
        }
        if !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(NtfyError::Config(
                "ntfy base URL must not contain credentials, query or fragment".to_owned(),
            ));
        }
        if topic.is_empty()
            || topic.len() > 64
            || !topic
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(NtfyError::Config("invalid ntfy topic".to_owned()));
        }
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        Ok(Self {
            base_url,
            topic: topic.to_owned(),
            replay_cached: false,
            operation_budget: DEFAULT_OPERATION_BUDGET,
            resolve_addr: None,
        })
    }

    /// Resolve the existing HTTPS hostname to one public IPv4 without changing
    /// its SNI, certificate hostname, origin, topic or serialized host pacing.
    pub fn with_resolve_ip(mut self, ip: std::net::Ipv4Addr) -> Result<Self, NtfyError> {
        if lzh_hole_protocol::path::classify(ip).is_some() {
            return Err(NtfyError::Config(format!(
                "resolve override must be a public IPv4 address, not {ip}"
            )));
        }
        let host = self
            .base_url
            .host_str()
            .ok_or_else(|| NtfyError::Config("base URL has no host".to_owned()))?;
        if host.parse::<std::net::IpAddr>().is_ok() {
            return Err(NtfyError::Config(
                "resolve override requires a DNS hostname in the base URL".to_owned(),
            ));
        }
        let port = self
            .base_url
            .port_or_known_default()
            .ok_or_else(|| NtfyError::Config("base URL has no HTTPS port".to_owned()))?;
        self.resolve_addr = Some(SocketAddr::new(ip.into(), port));
        Ok(self)
    }

    /// Opt into `since=all`. Cached requests still never trigger automatic replies.
    pub fn with_cached_replay(mut self, enabled: bool) -> Self {
        self.replay_cached = enabled;
        self
    }

    fn subscribe_url(&self) -> Result<reqwest::Url, NtfyError> {
        let mut url = self
            .base_url
            .join(&format!("{}/json", self.topic))
            .map_err(|e| NtfyError::Config(format!("subscription URL: {e}")))?;
        if self.replay_cached {
            url.query_pairs_mut().append_pair("since", "all");
        }
        Ok(url)
    }

    fn publish_url(&self) -> Result<reqwest::Url, NtfyError> {
        self.base_url
            .join(&self.topic)
            .map_err(|e| NtfyError::Config(format!("publish URL: {e}")))
    }
}

/// Build the single HTTPS client used by one serialized transport actor.
pub(crate) fn build_client(config: &NtfyConfig) -> Result<reqwest::Client, NtfyError> {
    let mut client = reqwest::Client::builder()
        .connect_timeout(CONNECT_AND_HEADERS_TIMEOUT)
        // Redirects would be extra host operations outside the serialized gate.
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(USER_AGENT);
    if let Some(address) = config.resolve_addr {
        let host = config
            .base_url
            .host_str()
            .ok_or_else(|| NtfyError::Config("base URL has no host".to_owned()))?;
        client = client.resolve(host, address);
    }
    client
        .build()
        .map_err(|error| NtfyError::Config(format!("HTTP client: {error}")))
}

/// Which serialized host operation produced a diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfyOperation {
    /// A new streaming subscription, including a reconnect.
    Subscribe,
    /// One signed payload publication. Failed publishes are not automatically resent.
    Publish,
}

impl fmt::Display for NtfyOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NtfyOperation::Subscribe => f.write_str("subscribe"),
            NtfyOperation::Publish => f.write_str("publish"),
        }
    }
}

/// Events emitted by the independent transport task.
#[derive(Debug, Clone)]
pub enum NtfyEvent {
    /// The NDJSON response headers were accepted.
    Subscribed {
        /// Whether this subscription explicitly requested cached history.
        cached_replay: bool,
    },
    /// A shape-checked signed payload. The daemon must still call `verify`.
    Received {
        /// Signed payload; not authenticated by the transport itself.
        payload: SignedPayload,
        /// Live versus cached hint classification.
        delivery: Delivery,
        /// ntfy's diagnostic message ID; it is not a signed correlation ID.
        ntfy_id: String,
    },
    /// A publish returned HTTP 200. This is not peer receipt or UDP health.
    Published {
        /// Signed kind that was queued.
        kind: MessageKind,
        /// Signed request/reply ID.
        request_id: RequestId,
    },
    /// A dequeued payload was not published and will not be automatically retried.
    /// The daemon must cancel any matching request and build a fresh record/sequence.
    PublishFailed {
        /// Signed kind that was dequeued.
        kind: MessageKind,
        /// Signed request/reply ID.
        request_id: RequestId,
        /// Safe reason, including disconnect, expiry or an HTTP failure.
        detail: String,
    },
    /// A transport/protocol error. Subscription failures reconnect with bounded backoff.
    Error {
        /// Operation that failed.
        operation: NtfyOperation,
        /// Safe diagnostic text; no private key material is included.
        detail: String,
        /// Retry-After duration supplied by the server, when usable.
        retry_after: Option<Duration>,
    },
}

/// Transport, scheduling or channel failure.
#[derive(Debug, thiserror::Error)]
pub enum NtfyError {
    /// Invalid fixed transport configuration.
    #[error("ntfy config: {0}")]
    Config(String),
    /// Queue capacity must be nonzero.
    #[error("ntfy channel capacity must be nonzero")]
    InvalidChannelCapacity,
    /// An HTTP request failed before a valid response.
    #[error("ntfy {operation}: {detail}")]
    Http {
        /// Operation kind.
        operation: NtfyOperation,
        /// Safe error text.
        detail: String,
    },
    /// Waiting for response headers exceeded its bound.
    #[error("ntfy {operation} timed out")]
    Timeout {
        /// Operation kind.
        operation: NtfyOperation,
    },
    /// The actual connected HTTP peer was in the resolver Fake-IP range.
    #[error("ntfy {operation} connected to refused Fake-IP address {address}")]
    FakeIp {
        /// Operation that connected.
        operation: NtfyOperation,
        /// Actual socket address reported by reqwest.
        address: SocketAddr,
    },
    /// The signed record expired while waiting for its serialized POST turn.
    #[error(
        "ntfy publish of {kind:?}/{request_id} expired at {expires_at_unix_ms}; refusing stale POST"
    )]
    PublishExpired {
        /// Signed kind that will not be posted.
        kind: MessageKind,
        /// Signed request/reply ID that will not be posted.
        request_id: RequestId,
        /// Original signed expiry; it is never extended in place.
        expires_at_unix_ms: u64,
    },
    /// A non-success HTTP status. Retry-After is retained for the scheduler.
    #[error("ntfy {operation} returned HTTP {status}")]
    HttpStatus {
        /// Operation kind.
        operation: NtfyOperation,
        /// Numeric HTTP status.
        status: u16,
        /// Parsed Retry-After, if valid.
        retry_after: Option<Duration>,
    },
    /// Successful subscription did not advertise NDJSON.
    #[error("ntfy subscription returned unexpected Content-Type {0:?}")]
    ContentType(Option<String>),
    /// Framing or the long-lived body stream failed.
    #[error("ntfy subscription stream: {0}")]
    Stream(String),
    /// An NDJSON control/message record violated protocol bounds.
    #[error("ntfy protocol: {0}")]
    Protocol(String),
    /// Durable pacing could not be loaded or committed; no HTTP attempt is allowed.
    #[error("ntfy durable pacing state: {0}")]
    PacingState(String),
    /// The rolling operation budget was exhausted; no further operation is attempted.
    #[error("ntfy rolling 24 hour operation budget of {0} exhausted")]
    DailyBudgetExhausted(u32),
    /// A hostile/extreme delay cannot be represented safely; do not retry early.
    #[error("ntfy retry delay is not representable; refusing an early retry")]
    ScheduleOverflow,
    /// The daemon dropped its event receiver.
    #[error("ntfy event channel closed")]
    EventChannelClosed,
    /// Cooperative cancellation requested by the daemon.
    #[error("ntfy transport cancelled")]
    Cancelled,
}

impl NtfyError {
    pub(crate) fn operation(&self) -> NtfyOperation {
        match self {
            NtfyError::Http { operation, .. }
            | NtfyError::Timeout { operation }
            | NtfyError::HttpStatus { operation, .. } => *operation,
            _ => NtfyOperation::Subscribe,
        }
    }

    pub(crate) fn retry_after(&self) -> Option<Duration> {
        match self {
            NtfyError::HttpStatus { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}
/// Non-async enqueue failure, suitable for a UDP-owning daemon loop.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TryPublishError {
    /// The bounded queue is full. Apply backpressure in daemon state, not UDP.
    #[error("ntfy publish queue is full")]
    Full,
    /// Transport has stopped or been cancelled.
    #[error("ntfy publish queue is closed")]
    Closed,
    /// The signed payload violated its schema or size bound.
    #[error("invalid signed payload: {0}")]
    InvalidPayload(String),
}
pub(crate) async fn subscribe(
    client: &reqwest::Client,
    config: &NtfyConfig,
    cancel: &CancellationToken,
) -> Result<reqwest::Response, NtfyError> {
    let url = config.subscribe_url()?;
    let request = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/x-ndjson")
        .header(reqwest::header::CACHE_CONTROL, "no-cache");
    let response = tokio::select! {
        _ = cancel.cancelled() => return Err(NtfyError::Cancelled),
        result = tokio::time::timeout(CONNECT_AND_HEADERS_TIMEOUT, request.send()) => {
            match result {
                Err(_) => return Err(NtfyError::Timeout { operation: NtfyOperation::Subscribe }),
                Ok(Err(error)) => return Err(http_error(NtfyOperation::Subscribe, error)),
                Ok(Ok(response)) => response,
            }
        }
    };
    check_remote_addr(&response, NtfyOperation::Subscribe)?;
    if !response.status().is_success() {
        return Err(status_error(NtfyOperation::Subscribe, &response));
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let is_ndjson = content_type
        .as_deref()
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .is_some_and(|value| value.eq_ignore_ascii_case("application/x-ndjson"));
    if !is_ndjson {
        return Err(NtfyError::ContentType(content_type));
    }
    Ok(response)
}
pub(crate) async fn publish(
    client: &reqwest::Client,
    config: &NtfyConfig,
    cancel: &CancellationToken,
    payload: &SignedPayload,
) -> Result<(), NtfyError> {
    check_publish_fresh(payload, SystemTime::now())?;
    let body = payload
        .to_json()
        .map_err(|e| NtfyError::Protocol(e.to_string()))?;
    let request = client
        .post(config.publish_url()?)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(reqwest::header::CACHE_CONTROL, "no-cache")
        .body(body);
    let response = tokio::select! {
        _ = cancel.cancelled() => return Err(NtfyError::Cancelled),
        result = tokio::time::timeout(PUBLISH_TIMEOUT, request.send()) => {
            match result {
                Err(_) => return Err(NtfyError::Timeout { operation: NtfyOperation::Publish }),
                Ok(Err(error)) => return Err(http_error(NtfyOperation::Publish, error)),
                Ok(Ok(response)) => response,
            }
        }
    };
    check_remote_addr(&response, NtfyOperation::Publish)?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(status_error(NtfyOperation::Publish, &response));
    }
    Ok(())
}
fn check_remote_addr(
    response: &reqwest::Response,
    operation: NtfyOperation,
) -> Result<(), NtfyError> {
    if let Some(address @ SocketAddr::V4(v4)) = response.remote_addr()
        && lzh_hole_protocol::path::classify(*v4.ip())
            == Some(lzh_hole_protocol::path::EndpointReject::FakeIp)
    {
        return Err(NtfyError::FakeIp { operation, address });
    }
    Ok(())
}

fn http_error(operation: NtfyOperation, error: reqwest::Error) -> NtfyError {
    NtfyError::Http {
        operation,
        detail: error.to_string(),
    }
}

fn status_error(operation: NtfyOperation, response: &reqwest::Response) -> NtfyError {
    NtfyError::HttpStatus {
        operation,
        status: response.status().as_u16(),
        retry_after: response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| parse_retry_after(value, SystemTime::now())),
    }
}
pub(crate) fn check_publish_fresh(
    payload: &SignedPayload,
    now: SystemTime,
) -> Result<(), NtfyError> {
    let expires_at_unix_ms = payload
        .expires_at_unix_ms()
        .map_err(|error| NtfyError::Protocol(error.to_string()))?;
    let now_ms = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .min(u64::MAX as u128) as u64;
    if now_ms >= expires_at_unix_ms {
        return Err(NtfyError::PublishExpired {
            kind: payload.kind(),
            request_id: payload.request_id(),
            expires_at_unix_ms,
        });
    }
    Ok(())
}

/// Convert a reqwest byte stream to bounded NDJSON lines without hand-written SSE parsing.
pub(crate) fn ndjson_lines<S>(stream: S) -> impl Stream<Item = Result<String, LinesCodecError>>
where
    S: Stream<Item = Result<Bytes, io::Error>>,
{
    let reader = StreamReader::new(Box::pin(stream));
    FramedRead::new(reader, LinesCodec::new_with_max_length(MAX_NTFY_LINE_BYTES))
}

#[derive(Debug, Deserialize)]
struct WireMessage {
    event: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    topic: String,
    #[serde(default)]
    time: u64,
    #[serde(default)]
    message: Option<String>,
}

pub(crate) fn parse_ntfy_line(
    line: &str,
    expected_topic: &str,
    subscribe_wall: SystemTime,
    cached_replay: bool,
) -> Option<Result<NtfyEvent, NtfyError>> {
    if line.is_empty() {
        return None;
    }
    let message: WireMessage = match serde_json::from_str(line) {
        Ok(message) => message,
        Err(error) => {
            return Some(Err(NtfyError::Protocol(format!("NDJSON: {error}"))));
        }
    };
    match message.event.as_str() {
        "open" | "keepalive" => None,
        "message" => Some(parse_wire_message(
            message,
            expected_topic,
            subscribe_wall,
            cached_replay,
        )),
        other => Some(Err(NtfyError::Protocol(format!(
            "unsupported ntfy event {other:?}"
        )))),
    }
}

fn parse_wire_message(
    message: WireMessage,
    expected_topic: &str,
    subscribe_wall: SystemTime,
    cached_replay: bool,
) -> Result<NtfyEvent, NtfyError> {
    if message.topic != expected_topic {
        return Err(NtfyError::Protocol("message topic mismatch".to_owned()));
    }
    if message.id.is_empty()
        || message.id.len() > 64
        || !message
            .id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(NtfyError::Protocol("invalid ntfy message ID".to_owned()));
    }
    let body = message
        .message
        .ok_or_else(|| NtfyError::Protocol("message has no payload".to_owned()))?;
    let payload =
        SignedPayload::from_json(&body).map_err(|e| NtfyError::Protocol(e.to_string()))?;
    let subscribe_ms = subscribe_wall
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .min(u64::MAX as u128) as u64;
    let message_ms = message.time.saturating_mul(1000);
    let delivery = if message_ms < subscribe_ms || (cached_replay && message.time == 0) {
        Delivery::Cached
    } else {
        Delivery::Live
    };
    Ok(NtfyEvent::Received {
        payload,
        delivery,
        ntfy_id: message.id,
    })
}

#[cfg(test)]
mod tests;
