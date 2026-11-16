//! Doctor DTOs, independent of protocol engine and service implementation types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Maximum distinct drop-reason keys retained in one snapshot.
pub const MAX_DROP_REASONS: usize = 32;
/// Maximum UTF-8 byte length of one drop-reason key.
pub const MAX_DROP_REASON_BYTES: usize = 64;
/// Maximum peers one snapshot may carry, matching the protocol mesh bound.
pub const MAX_PEERS_IN_SNAPSHOT: usize = 8;
/// Maximum candidate hints retained per peer in one snapshot.
pub const MAX_CANDIDATES_PER_PEER: usize = 32;

/// Health of one measured subsystem. `Unknown` never means healthy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentState {
    /// No actual observation has been supplied yet.
    #[default]
    Unknown,
    /// Initialization is in progress and has not succeeded.
    Starting,
    /// A real probe or state update established health.
    Healthy,
    /// Operating with an observed impairment.
    Degraded,
    /// An actual operation failed.
    Failed,
    /// Deliberately stopped.
    Stopped,
    /// The subsystem is absent by configuration.
    NotConfigured,
}

/// Latest actual observation for ntfy, STUN, session, TUN or routes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentStatus {
    /// Measured state, defaulting to `Unknown`.
    pub state: ComponentState,
    /// Non-secret diagnostic detail supplied by the owning subsystem.
    pub detail: Option<String>,
    /// Last successful observation, if one actually happened.
    pub last_success_unix_ms: Option<u64>,
    /// Last state transition, if supplied by the subsystem.
    pub last_change_unix_ms: Option<u64>,
}

/// Daemon lifecycle, intentionally separate from overlay connectivity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonState {
    /// No lifecycle update has been supplied.
    #[default]
    Unknown,
    /// The process is initializing.
    Starting,
    /// The resident process/control plane is running; networking may still be down.
    Running,
    /// Shutdown was requested.
    Stopping,
    /// The process is stopped.
    Stopped,
    /// The daemon failed.
    Failed,
}

/// Process-local daemon status.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonStatus {
    /// Resident-process lifecycle only.
    pub state: DaemonState,
    /// Actual daemon PID when known.
    pub pid: Option<u32>,
    /// Actual process start time when known.
    pub started_unix_ms: Option<u64>,
    /// Non-secret lifecycle detail.
    pub detail: Option<String>,
}

/// IPv4-over-UDP dataplane byte counters. Counters are not health evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ByteCounters {
    /// All UDP datagram bytes received on the physical socket, including rejected input.
    pub udp_rx: u64,
    /// UDP payload bytes sent to the selected direct peer and STUN servers.
    pub udp_tx: u64,
    /// IPv4 packet bytes read from utun.
    pub tun_rx: u64,
    /// IPv4 packet bytes written to utun.
    pub tun_tx: u64,
}

/// Bounded drop accounting, split by stable non-secret reason codes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DropCounters {
    /// Total dropped packets, including reasons not individually retained.
    pub total: u64,
    /// At most 32 stable reason keys such as `bad_mac` or `route_missing`.
    pub reasons: BTreeMap<String, u64>,
}

impl DropCounters {
    /// Add a drop count without allowing unbounded attacker-controlled keys.
    pub fn record(&mut self, reason: &str, count: u64) -> bool {
        if reason.is_empty()
            || reason.len() > MAX_DROP_REASON_BYTES
            || !reason
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return false;
        }
        self.total = self.total.saturating_add(count);
        if let Some(value) = self.reasons.get_mut(reason) {
            *value = value.saturating_add(count);
            return true;
        }
        if self.reasons.len() >= MAX_DROP_REASONS {
            return false;
        }
        self.reasons.insert(reason.to_owned(), count);
        true
    }
}

/// Transparent-overlay evidence, separate from daemon/component health.
/// External acceptance reports separately evaluate functional and P0 criteria.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayHealth {
    /// Authenticated direct UDP reachability, or None when not measured.
    pub direct_reachable: Option<bool>,
    /// Current direct-path health, or None when not measured.
    pub currently_healthy: Option<bool>,
    /// Non-secret reason the overlay is unhealthy or unmeasured.
    pub detail: Option<String>,
}

/// Discovery origin, not authenticated connectivity evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryOrigin {
    /// Interface-scoped Bonjour observation.
    Lan,
    /// Verified public coordination record.
    Public,
}

/// Selected direct path, populated only from the protocol engine's actual path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentPathStatus {
    /// Process-local, never-reused physical socket identifier.
    pub transport_id: u64,
    /// Actual bound physical interface name.
    pub interface: String,
    /// Actual bound IPv4 UDP endpoint.
    pub local_endpoint: String,
    /// Authenticated remote IPv4 UDP endpoint.
    pub remote_endpoint: String,
    /// LAN or public path policy.
    pub kind: DiscoveryOrigin,
}

/// One eligible transport-bound discovery hint; never proof of peer health.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateStatus {
    /// Backend that supplied the hint.
    pub origin: DiscoveryOrigin,
    /// Physical socket on which this candidate may be attempted.
    pub transport_id: u64,
    /// Candidate remote IPv4 UDP endpoint.
    pub remote_endpoint: String,
}

/// Bounded discovery accounting, independent of actual session health.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryCounters {
    /// Accepted normalized discovery updates.
    pub accepted_updates: u64,
    /// Rejected or capacity-limited discovery updates.
    pub rejected_updates: u64,
    /// Source-specific withdrawals, including expiry.
    pub withdrawals: u64,
}

/// Hole-punch state. Every field is an observation, never a promise that a
/// punch will succeed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PunchStatus {
    /// Attempt phase, or `idle` when nothing is running.
    pub state: String,
    /// Which side this host is playing, when an attempt is running.
    pub role: Option<String>,
    /// This host's own measured mapping behaviour.
    pub local_mapping: String,
    /// The peer's mapping behaviour as published in its last accepted record.
    pub peer_mapping: String,
    /// Why no attempt is running, when one was considered and declined.
    pub blocked_by: Option<String>,
    /// Why the last attempt ended without a path.
    pub last_failure: Option<String>,
    /// Punch frames handed to the kernel during the current attempt.
    pub probes_sent: u64,
    /// Punch sockets currently open.
    pub sockets_open: u16,
    /// The port that produced a hit, once there is one.
    pub hit_port: Option<u16>,
    /// When the current attempt started, on the daemon's UNIX clock.
    pub started_unix_ms: Option<u64>,
}

/// One pinned peer's actual observations. Every field is an observation,
/// never a promise of reachability.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerStatus {
    /// Lowercase hex relationship id, exactly 32 characters.
    pub relationship_id: String,
    /// This peer's overlay /32 virtual IPv4 address.
    pub peer_vip: String,
    /// This peer's pinned discovery public key.
    pub peer_key: String,
    /// Pairing role of this node in this relationship: `initiator` or `responder`.
    pub role: String,
    /// Latest authenticated session observation for this peer.
    pub session: ComponentStatus,
    /// End-to-end direct-path evidence for this peer.
    pub overlay: OverlayHealth,
    /// Latest ntfy coordination observation for this relationship.
    pub ntfy: ComponentStatus,
    /// This peer's currently selected path, if any.
    pub current_path: Option<CurrentPathStatus>,
    /// This peer's eligible transport-bound candidates, never online evidence.
    pub candidates: Vec<CandidateStatus>,
    /// This peer's hole-punch state.
    pub punch: PunchStatus,
    /// Dataplane byte counters attributed to this peer.
    pub bytes: ByteCounters,
    /// Dataplane drop counters attributed to this peer.
    pub drops: DropCounters,
}

/// Fresh doctor data returned to the local management client.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSnapshot {
    /// Resident process lifecycle.
    pub daemon: DaemonStatus,
    /// Latest ntfy observation.
    pub ntfy: ComponentStatus,
    /// Latest local Bonjour discovery observation; not peer health.
    pub lan: ComponentStatus,
    /// Latest STUN observation on the physical data socket.
    pub stun: ComponentStatus,
    /// Cross-peer aggregate of `peers[].session`; see [`ServiceSnapshot::set_peers`].
    /// Never more optimistic than the worst peer.
    pub session: ComponentStatus,
    /// Latest actual utun state; default is Unknown, not created.
    pub tun: ComponentStatus,
    /// Latest actual /32 host-route state; default is Unknown, not installed.
    pub routes: ComponentStatus,
    /// Dataplane byte counters.
    pub bytes: ByteCounters,
    /// Dataplane drop counters and bounded reasons.
    pub drops: DropCounters,
    /// Cross-peer aggregate of `peers[].overlay`; see [`ServiceSnapshot::set_peers`].
    /// `Some(true)` only when every peer measured `Some(true)`.
    pub overlay: OverlayHealth,
    /// Hole-punch state; default is an idle, unclassified snapshot.
    pub punch: PunchStatus,
    /// Always `None`: a selected path belongs to exactly one peer, so a
    /// node-level path would be ambiguous. See `peers[].current_path`.
    pub current_path: Option<CurrentPathStatus>,
    /// Always empty: candidates belong to one peer each and are only reported
    /// in `peers[].candidates`, capped at [`MAX_CANDIDATES_PER_PEER`] per peer.
    pub candidates: Vec<CandidateStatus>,
    /// Per-peer observations, at most MAX_PEERS_IN_SNAPSHOT entries.
    pub peers: Vec<PeerStatus>,
    /// Truthful backend update accounting.
    pub discovery: DiscoveryCounters,
    /// Timestamp of the latest snapshot update, zero if not supplied.
    pub updated_unix_ms: u64,
}

/// Worst-case severity rank of a component state; a higher rank is worse.
///
/// `Failed` > `Degraded` > `Starting` > `Unknown` > `Stopped` > `NotConfigured` > `Healthy`.
///
/// `Unknown` deliberately outranks `Stopped`, `NotConfigured` and `Healthy`:
/// an unmeasured peer must never let an aggregate claim health, because
/// "not measured" is not evidence of anything. It stays below `Starting`,
/// `Degraded` and `Failed`, which are actual observations of an ongoing or
/// failed operation and therefore strictly more informative.
const fn state_severity(state: ComponentState) -> u8 {
    match state {
        ComponentState::Failed => 6,
        ComponentState::Degraded => 5,
        ComponentState::Starting => 4,
        ComponentState::Unknown => 3,
        ComponentState::Stopped => 2,
        ComponentState::NotConfigured => 1,
        ComponentState::Healthy => 0,
    }
}

/// Stable lowercase label for one component state, matching its wire form.
const fn state_label(state: ComponentState) -> &'static str {
    match state {
        ComponentState::Unknown => "unknown",
        ComponentState::Starting => "starting",
        ComponentState::Healthy => "healthy",
        ComponentState::Degraded => "degraded",
        ComponentState::Failed => "failed",
        ComponentState::Stopped => "stopped",
        ComponentState::NotConfigured => "not_configured",
    }
}

/// Aggregate one three-state measurement across peers, never upgrading it.
///
/// * any `Some(false)` wins and yields `Some(false)`;
/// * otherwise a single unmeasured (`None`) peer makes the aggregate `None`,
///   because unmeasured is not healthy;
/// * `Some(true)` only when every peer measured `Some(true)`;
/// * no peers at all yields `None`.
fn aggregate_measured(values: impl IntoIterator<Item = Option<bool>>) -> Option<bool> {
    let mut seen = false;
    let mut unmeasured = false;
    for value in values {
        seen = true;
        match value {
            Some(false) => return Some(false),
            Some(true) => {}
            None => unmeasured = true,
        }
    }
    if !seen || unmeasured {
        None
    } else {
        Some(true)
    }
}

/// Maximum of the supplied optional timestamps, or `None` when all are `None`.
fn max_timestamp(values: impl IntoIterator<Item = Option<u64>>) -> Option<u64> {
    values.into_iter().flatten().max()
}

impl ServiceSnapshot {
    /// Construct an initializing snapshot without claiming network/TUN success.
    pub fn starting(pid: u32, started_unix_ms: u64) -> Self {
        Self {
            daemon: DaemonStatus {
                state: DaemonState::Starting,
                pid: Some(pid),
                started_unix_ms: Some(started_unix_ms),
                detail: None,
            },
            updated_unix_ms: started_unix_ms,
            ..Self::default()
        }
    }

    /// Mark only the resident process as running. Overlay health is independent.
    pub fn mark_daemon_running(&mut self, observed_unix_ms: u64) {
        self.daemon.state = DaemonState::Running;
        self.updated_unix_ms = observed_unix_ms;
    }

    /// Replace the per-peer list and recompute the node-level aggregate fields.
    ///
    /// Refuses (returns false and leaves the snapshot completely unchanged)
    /// when the list is empty or longer than MAX_PEERS_IN_SNAPSHOT. Each peer's
    /// candidate list is truncated to MAX_CANDIDATES_PER_PEER.
    ///
    /// This is the single place where aggregation rules live; the service owner
    /// supplies per-peer observations and must not re-implement them. The call
    /// is all-or-nothing: every aggregate below is computed first and only then
    /// committed, so a rejected call leaves `peers` and all aggregates exactly
    /// as they were.
    ///
    /// Aggregation rules:
    ///
    /// * `overlay.direct_reachable` and `overlay.currently_healthy` are the
    ///   three-state AND of the per-peer values: `Some(true)` only when *every*
    ///   peer measured `Some(true)`, `Some(false)` as soon as one peer measured
    ///   `Some(false)`, and `None` when no peer is negative but at least one is
    ///   unmeasured. Unmeasured never becomes healthy. An empty peer list is
    ///   refused, so aggregates are never derived from "no peers".
    /// * `session.state` is the worst per-peer state, with severity
    ///   `Failed` > `Degraded` > `Starting` > `Unknown` > `Stopped` >
    ///   `NotConfigured` > `Healthy` (see [`state_severity`]). `Unknown`
    ///   outranks `Healthy` so an unmeasured peer cannot be laundered into a
    ///   healthy node-level claim.
    /// * `session.detail` and `overlay.detail` are regenerated and always state
    ///   the peer count, the healthy/measured counts, and that the selected
    ///   path is per-peer (`peers[].current_path`). Per-peer reasons stay in
    ///   `peers[]`; the aggregate never invents a node-level cause.
    /// * `session.last_success_unix_ms` and `session.last_change_unix_ms` are
    ///   the maximum of the per-peer values, and `None` when every peer is
    ///   `None`.
    /// * `current_path` is always set to `None` and `candidates` is always
    ///   emptied: a path and a candidate belong to exactly one peer, so a
    ///   node-level value would be ambiguous rather than informative.
    ///
    /// All other node-level fields (`daemon`, `ntfy`, `lan`, `stun`, `tun`,
    /// `routes`, `bytes`, `drops`, `punch`, `discovery`, `updated_unix_ms`) are
    /// left untouched; their per-peer counterparts live in `peers[]`.
    pub fn set_peers(&mut self, mut peers: Vec<PeerStatus>) -> bool {
        if peers.is_empty() || peers.len() > MAX_PEERS_IN_SNAPSHOT {
            return false;
        }
        for peer in &mut peers {
            peer.candidates.truncate(MAX_CANDIDATES_PER_PEER);
        }

        let total = peers.len();
        let worst_state = peers
            .iter()
            .map(|peer| peer.session.state)
            .max_by_key(|state| state_severity(*state))
            .unwrap_or(ComponentState::Unknown);
        let healthy_peers = peers
            .iter()
            .filter(|peer| peer.session.state == ComponentState::Healthy)
            .count();
        let last_success_unix_ms =
            max_timestamp(peers.iter().map(|peer| peer.session.last_success_unix_ms));
        let last_change_unix_ms =
            max_timestamp(peers.iter().map(|peer| peer.session.last_change_unix_ms));
        let direct_reachable =
            aggregate_measured(peers.iter().map(|peer| peer.overlay.direct_reachable));
        let currently_healthy =
            aggregate_measured(peers.iter().map(|peer| peer.overlay.currently_healthy));
        let reachable_peers = peers
            .iter()
            .filter(|peer| peer.overlay.direct_reachable == Some(true))
            .count();
        let healthy_path_peers = peers
            .iter()
            .filter(|peer| peer.overlay.currently_healthy == Some(true))
            .count();

        let session = ComponentStatus {
            state: worst_state,
            detail: Some(format!(
                "aggregate of {total} peers: worst session state {}, {healthy_peers}/{total} healthy; per-peer detail in peers[]",
                state_label(worst_state),
            )),
            last_success_unix_ms,
            last_change_unix_ms,
        };
        let overlay = OverlayHealth {
            direct_reachable,
            currently_healthy,
            detail: Some(format!(
                "aggregate of {total} peers: {reachable_peers}/{total} direct_reachable, {healthy_path_peers}/{total} currently_healthy; current_path is per-peer, see peers[].current_path",
            )),
        };

        self.session = session;
        self.overlay = overlay;
        self.current_path = None;
        self.candidates.clear();
        self.peers = peers;
        true
    }
}

/// Fresh doctor result supplied by the service owner.
pub type DoctorReport = ServiceSnapshot;

/// The only public control request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum ControlRequest {
    /// Ask the service owner for fresh actual subsystem observations.
    Doctor,
}

impl<'de> Deserialize<'de> for ControlRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum WireCommand {
            Doctor,
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireRequest {
            command: WireCommand,
        }

        let WireRequest { command } = WireRequest::deserialize(deserializer)?;
        let WireCommand::Doctor = command;
        Ok(Self::Doctor)
    }
}

/// Stable machine-readable control error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlErrorCode {
    /// peer_cred UID was neither root nor the configured manager.
    Unauthorized,
    /// Malformed, oversized or unknown request.
    BadRequest,
    /// Command queue/service is full, closed or otherwise unavailable.
    Unavailable,
    /// Bounded request/command wait expired.
    Timeout,
    /// The service owner rejected the requested operation.
    Rejected,
    /// Response encoding or another internal invariant failed.
    Internal,
}

/// One bounded JSON response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlResponse {
    /// Fresh doctor observations from the service owner.
    Doctor {
        /// Actual daemon/ntfy/stun/session/tun/routes/counter state.
        report: Box<DoctorReport>,
    },
    /// Request failed.
    Error {
        /// Stable error code.
        code: ControlErrorCode,
        /// Bounded non-secret diagnostic.
        message: String,
    },
}

#[cfg(test)]
mod tests;
