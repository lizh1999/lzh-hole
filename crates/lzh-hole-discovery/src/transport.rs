//! HTTPS transport, bounded NDJSON framing and ntfy wire classification.
//! No business UDP socket is created or owned here.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures_util::Stream;
use lzh_hole_types::RelationshipId;
use serde::Deserialize;
use tokio_util::codec::{FramedRead, LinesCodec, LinesCodecError};
use tokio_util::io::StreamReader;
use tokio_util::sync::CancellationToken;

use crate::exchange::Delivery;
use crate::message::{MessageKind, RequestId, SignedPayload};
use crate::pacing::{DEFAULT_OPERATION_BUDGET, parse_retry_after};

/// Maximum NDJSON line, including ntfy metadata but excluding the newline.
pub const MAX_NTFY_LINE_BYTES: usize = 16 * 1024;
/// Most topics one host actor may subscribe to at once.
pub const MAX_NTFY_TOPICS: usize = 8;
pub(crate) const CONNECT_AND_HEADERS_TIMEOUT: Duration = Duration::from_secs(25);
pub(crate) const PUBLISH_TIMEOUT: Duration = Duration::from_secs(25);
/// Local admission margin: the easy scan (30 s), bounded POST (25 s), and
/// parsing/scheduling slack (5 s). This is not a propagation-time guarantee.
pub const MIN_PUNCH_OFFER_REMAINING_MS: u64 = 30_000 + PUBLISH_TIMEOUT.as_millis() as u64 + 5_000;
const USER_AGENT: &str = "lzh-hole-ntfy/1";

/// Validated ntfy connection settings. Production pacing cannot be lowered.
#[derive(Debug, Clone)]
pub struct NtfyConfig {
    base_url: reqwest::Url,
    pub(crate) topics: BTreeMap<RelationshipId, String>,
    /// Topic from [`NtfyConfig::new`] that is not bound to a relationship yet.
    unbound_topic: Option<String>,
    pub(crate) replay_cached: bool,
    pub(crate) operation_budget: u32,
    resolve_addr: Option<SocketAddr>,
    resolver: Option<NtfyResolver>,
}

fn validated_base_url(base_url: &str) -> Result<reqwest::Url, NtfyError> {
    let mut base_url =
        reqwest::Url::parse(base_url).map_err(|e| NtfyError::Config(format!("base URL: {e}")))?;
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
    if !base_url.path().ends_with('/') {
        let path = format!("{}/", base_url.path());
        base_url.set_path(&path);
    }
    Ok(base_url)
}

fn validate_topic(topic: &str) -> Result<(), NtfyError> {
    if topic.is_empty()
        || topic.len() > 64
        || !topic
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(NtfyError::Config("invalid ntfy topic".to_owned()));
    }
    Ok(())
}

impl NtfyConfig {
    #[cfg(test)]
    pub(crate) fn with_loopback_publish_url(mut self, port: u16) -> Self {
        self.base_url = reqwest::Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        self
    }

    /// Use an HTTPS ntfy base URL and an ASCII `[A-Za-z0-9_-]` topic (1..=64).
    ///
    /// The topic is not bound to a relationship yet. Call
    /// [`NtfyConfig::with_relationship`] before creating an actor so every event
    /// and every publish can be attributed to exactly one relationship.
    pub fn new(base_url: &str, topic: &str) -> Result<Self, NtfyError> {
        let base_url = validated_base_url(base_url)?;
        validate_topic(topic)?;
        Ok(Self {
            base_url,
            topics: BTreeMap::new(),
            unbound_topic: Some(topic.to_owned()),
            replay_cached: false,
            operation_budget: DEFAULT_OPERATION_BUDGET,
            resolve_addr: None,
            resolver: None,
        })
    }

    /// Bind the single topic of a [`NtfyConfig::new`] configuration to one relationship.
    pub fn with_relationship(mut self, relationship: RelationshipId) -> Result<Self, NtfyError> {
        let Some(topic) = self.unbound_topic.take() else {
            return Err(NtfyError::Config(
                "with_relationship requires a single-topic configuration".to_owned(),
            ));
        };
        self.topics.insert(relationship, topic);
        Ok(self)
    }

    /// Multi-topic configuration for one host.
    ///
    /// Every topic must satisfy the same `[A-Za-z0-9_-]{1,64}` rule as
    /// [`NtfyConfig::new`]. Refuses an empty map, more than `MAX_NTFY_TOPICS`
    /// entries and duplicate topic strings across different relationships.
    pub fn multi(
        base_url: &str,
        topics: &BTreeMap<RelationshipId, String>,
    ) -> Result<Self, NtfyError> {
        let base_url = validated_base_url(base_url)?;
        if topics.is_empty() {
            return Err(NtfyError::Config(
                "ntfy configuration needs at least one topic".to_owned(),
            ));
        }
        if topics.len() > MAX_NTFY_TOPICS {
            return Err(NtfyError::Config(format!(
                "ntfy configuration supports at most {MAX_NTFY_TOPICS} topics, got {}",
                topics.len()
            )));
        }
        let mut seen = BTreeSet::new();
        for topic in topics.values() {
            validate_topic(topic)?;
            if !seen.insert(topic.as_str()) {
                return Err(NtfyError::Config(
                    "two relationships share one ntfy topic".to_owned(),
                ));
            }
        }
        Ok(Self {
            base_url,
            topics: topics.clone(),
            unbound_topic: None,
            replay_cached: false,
            operation_budget: DEFAULT_OPERATION_BUDGET,
            resolve_addr: None,
            resolver: None,
        })
    }

    /// How many topics this actor serves.
    pub fn topic_count(&self) -> usize {
        self.topics.len() + usize::from(self.unbound_topic.is_some())
    }

    /// Relationships this actor serves, in stable order.
    pub(crate) fn relationships(&self) -> impl Iterator<Item = RelationshipId> + '_ {
        self.topics.keys().copied()
    }

    /// Topic of one served relationship, if this actor serves it.
    pub(crate) fn topic_for(&self, relationship: &RelationshipId) -> Option<&str> {
        self.topics.get(relationship).map(String::as_str)
    }

    /// Host of the base URL, for a lookup that precedes any host operation.
    pub(crate) fn base_host(&self) -> Option<&str> {
        self.base_url.host_str()
    }

    /// The injected resolver, when this configuration has one.
    pub(crate) fn resolver(&self) -> Option<&NtfyResolver> {
        self.resolver.as_ref()
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
    /// Resolve the ntfy hostname with a platform-supplied resolver.
    ///
    /// Every address the resolver returns is still checked against the refused
    /// ranges before any connection is attempted, so an injected resolver
    /// cannot make the transport connect to a Fake-IP or private address.
    pub fn with_resolver(mut self, resolver: NtfyResolver) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Opt into replaying cached messages. Cached requests still never trigger
    /// automatic replies.
    pub fn with_cached_replay(mut self, enabled: bool) -> Self {
        self.replay_cached = enabled;
        self
    }

    /// NDJSON subscription URL of one served relationship.
    pub(crate) fn subscribe_url_for(
        &self,
        relationship: &RelationshipId,
    ) -> Result<reqwest::Url, NtfyError> {
        let topic = self.topic_of(relationship)?;
        let mut url = self
            .base_url
            .join(&format!("{topic}/json"))
            .map_err(|e| NtfyError::Config(format!("subscription URL: {e}")))?;
        if self.replay_cached {
            url.query_pairs_mut().append_pair("since", "all");
        }
        Ok(url)
    }

    /// Publish URL of one served relationship.
    pub(crate) fn publish_url_for(
        &self,
        relationship: &RelationshipId,
    ) -> Result<reqwest::Url, NtfyError> {
        let topic = self.topic_of(relationship)?;
        self.base_url
            .join(topic)
            .map_err(|e| NtfyError::Config(format!("publish URL: {e}")))
    }

    fn topic_of(&self, relationship: &RelationshipId) -> Result<&str, NtfyError> {
        self.topic_for(relationship).ok_or_else(|| {
            NtfyError::Config(format!(
                "this ntfy actor does not serve relationship {}",
                relationship.to_hex()
            ))
        })
    }
}

/// A hostname resolver supplied by the platform layer.
///
/// The transport never reads the host resolver configuration. A resolver that
/// hands out Fake-IP addresses produces connections whose reachability depends
/// on a proxy tunnel, and a coordination channel may not depend on that.
#[derive(Clone)]
pub struct NtfyResolver(Arc<dyn reqwest::dns::Resolve>);

impl NtfyResolver {
    /// Wrap any resolver, including the gateway DNS resolver of this crate.
    pub fn new<R: reqwest::dns::Resolve + 'static>(resolver: R) -> Self {
        Self(Arc::new(resolver))
    }

    /// Resolve one hostname once, outside any HTTP request.
    ///
    /// The answer is deliberately not filtered here: this only answers whether
    /// the name can be resolved at all, and the address policy that decides
    /// what may be connected to still belongs to the request path.
    pub(crate) async fn resolve_once(&self, host: &str) -> Result<(), String> {
        let name: reqwest::dns::Name = host
            .parse()
            .map_err(|_| format!("{host:?} is not a resolvable DNS name"))?;
        self.0
            .resolve(name)
            .await
            .map(|_| ())
            .map_err(|error| describe_error(error.as_ref()))
    }
}

impl fmt::Debug for NtfyResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NtfyResolver")
    }
}

/// Refuses any resolved address we would not have chosen ourselves.
///
/// This runs before a socket is created, so a refused address costs no
/// connection, no signed record, no sequence and no part of the rolling
/// operation budget.
#[derive(Clone)]
struct GuardedResolver {
    inner: Arc<dyn reqwest::dns::Resolve>,
}

impl fmt::Debug for GuardedResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GuardedResolver")
    }
}

/// Why a resolved address may not be connected to.
#[derive(Debug, thiserror::Error)]
enum ResolveRefusal {
    /// The injected resolver itself failed.
    #[error("{0}")]
    Failed(String),
    /// An address is in a range we refuse.
    #[error("refused address {address}: {reason}")]
    Refused {
        /// Address that will not be connected to.
        address: SocketAddr,
        /// Stable reject reason.
        reason: &'static str,
    },
    /// The resolver produced nothing usable.
    #[error("no usable address")]
    Empty,
}

/// Deepest error source chain folded into one diagnostic.
const MAX_ERROR_SOURCE_DEPTH: usize = 4;
/// Longest diagnostic kept from one failed HTTP operation.
const MAX_ERROR_DETAIL_BYTES: usize = 512;

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let inner = self.inner.clone();
        Box::pin(async move {
            let addrs = inner
                .resolve(name)
                .await
                .map_err(|error| boxed(ResolveRefusal::Failed(describe_error(error.as_ref()))))?;
            let mut kept: Vec<SocketAddr> = Vec::new();
            for address in addrs {
                if let SocketAddr::V4(v4) = address
                    && let Some(reason) = lzh_hole_protocol::path::classify(*v4.ip())
                {
                    return Err(boxed(ResolveRefusal::Refused {
                        address,
                        reason: reason.as_str(),
                    }));
                }
                if !kept.contains(&address) {
                    kept.push(address);
                }
            }
            if kept.is_empty() {
                return Err(boxed(ResolveRefusal::Empty));
            }
            let addrs: reqwest::dns::Addrs = Box::new(kept.into_iter());
            Ok(addrs)
        })
    }
}

fn boxed(error: ResolveRefusal) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(error)
}

/// Flatten an error and its sources into one bounded diagnostic string.
fn describe_error<E: std::error::Error + ?Sized>(error: &E) -> String {
    let mut detail = error.to_string();
    let mut source = error.source();
    let mut depth = 0usize;
    while let Some(current) = source {
        if depth >= MAX_ERROR_SOURCE_DEPTH {
            detail.push_str("; ...");
            break;
        }
        detail.push_str("; ");
        detail.push_str(&current.to_string());
        source = current.source();
        depth += 1;
    }
    truncate_detail(detail)
}

fn truncate_detail(mut detail: String) -> String {
    if detail.len() <= MAX_ERROR_DETAIL_BYTES {
        return detail;
    }
    let mut cut = MAX_ERROR_DETAIL_BYTES;
    while cut > 0 && !detail.is_char_boundary(cut) {
        cut -= 1;
    }
    detail.truncate(cut);
    detail.push_str("...");
    detail
}

/// Build the single HTTPS client used by one serialized transport actor.
pub(crate) fn build_client(config: &NtfyConfig) -> Result<reqwest::Client, NtfyError> {
    let mut client = reqwest::Client::builder()
        .connect_timeout(CONNECT_AND_HEADERS_TIMEOUT)
        // Redirects would be extra host operations outside the serialized gate.
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(USER_AGENT)
        // A system proxy would turn one host operation into an operation of a
        // host we never chose, over a path we never verified.
        .no_proxy();
    if let Some(resolver) = &config.resolver {
        client = client.dns_resolver(Arc::new(GuardedResolver {
            inner: resolver.0.clone(),
        }));
    }
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
    /// The NDJSON stream of one relationship delivered its first usable line.
    Subscribed {
        /// Relationship whose topic is now streaming.
        relationship: RelationshipId,
        /// Whether this subscription explicitly requested cached history.
        cached_replay: bool,
    },
    /// A shape-checked signed payload. The daemon must still call `verify`.
    Received {
        /// Relationship whose topic carried this line.
        relationship: RelationshipId,
        /// Signed payload; not authenticated by the transport itself.
        payload: SignedPayload,
        /// Live versus cached hint classification.
        delivery: Delivery,
        /// ntfy's diagnostic message ID; it is not a signed correlation ID.
        ntfy_id: String,
    },
    /// A publish returned HTTP 200. This is not peer receipt or UDP health.
    Published {
        /// Relationship whose topic was posted to.
        relationship: RelationshipId,
        /// Signed kind that was queued.
        kind: MessageKind,
        /// Signed request/reply ID.
        request_id: RequestId,
    },
    /// A dequeued payload was not published and will not be automatically retried.
    /// The daemon must cancel any matching request and build a fresh record/sequence.
    PublishFailed {
        /// Relationship whose topic was targeted.
        relationship: RelationshipId,
        /// Signed kind that was dequeued.
        kind: MessageKind,
        /// Signed request/reply ID.
        request_id: RequestId,
        /// Safe reason, including disconnect, expiry or an HTTP failure.
        detail: String,
    },
    /// A transport/protocol error. Subscription failures reconnect with bounded backoff.
    Error {
        /// The relationship whose stream failed, or `None` for a host-level
        /// failure that cannot be attributed to one topic.
        relationship: Option<RelationshipId>,
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
    /// An offer cannot leave enough time for a full easy scan, or was revoked.
    #[error(
        "ntfy publish of {kind:?}/{request_id} has no usable punch window before {expires_at_unix_ms}"
    )]
    PublishOfferUnavailable {
        /// Signed kind that will not be posted.
        kind: MessageKind,
        /// Original signed correlation.
        request_id: RequestId,
        /// Original hard deadline; never extended in place.
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
            | NtfyError::FakeIp { operation, .. }
            | NtfyError::HttpStatus { operation, .. } => *operation,
            NtfyError::PublishExpired { .. } | NtfyError::PublishOfferUnavailable { .. } => {
                NtfyOperation::Publish
            }
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
    /// This actor does not serve the requested relationship.
    #[error("ntfy actor does not serve relationship {0}")]
    UnknownRelationship(RelationshipId),
}
pub(crate) async fn subscribe(
    client: &reqwest::Client,
    config: &NtfyConfig,
    relationship: RelationshipId,
    cancel: &CancellationToken,
) -> Result<reqwest::Response, NtfyError> {
    let url = config.subscribe_url_for(&relationship)?;
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
    relationship: RelationshipId,
    cancel: &CancellationToken,
    payload: &SignedPayload,
) -> Result<(), NtfyError> {
    publish_with_clock(
        client,
        config,
        relationship,
        cancel,
        payload,
        SystemTime::now,
    )
    .await
}

// The injected clock keeps the two pre-HTTP admission boundaries deterministic
// in offline tests. Production always uses SystemTime::now via publish above.
pub(crate) async fn publish_with_clock(
    client: &reqwest::Client,
    config: &NtfyConfig,
    relationship: RelationshipId,
    cancel: &CancellationToken,
    payload: &SignedPayload,
    mut now: impl FnMut() -> SystemTime,
) -> Result<(), NtfyError> {
    check_publish_fresh(payload, now())?;
    let body = payload
        .to_json()
        .map_err(|e| NtfyError::Protocol(e.to_string()))?;
    let request = client
        .post(config.publish_url_for(&relationship)?)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(reqwest::header::CACHE_CONTROL, "no-cache")
        .body(body);
    check_publish_fresh(payload, now())?;
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
        detail: describe_error(&error),
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
    let record = payload
        .contact_record()
        .map_err(|error| NtfyError::Protocol(error.to_string()))?;
    let expires_at_unix_ms = record.expires_at_unix_ms;
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
    if record.flags & crate::record::FLAG_PUNCH_OFFER != 0
        && expires_at_unix_ms <= now_ms.saturating_add(MIN_PUNCH_OFFER_REMAINING_MS)
    {
        return Err(NtfyError::PublishOfferUnavailable {
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
    relationship: RelationshipId,
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
            relationship,
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
    relationship: RelationshipId,
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
        relationship,
        payload,
        delivery,
        ntfy_id: message.id,
    })
}

#[cfg(test)]
mod tests;
