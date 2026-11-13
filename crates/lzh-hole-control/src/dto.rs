//! Doctor DTOs, independent of protocol engine and service implementation types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Maximum distinct drop-reason keys retained in one snapshot.
pub const MAX_DROP_REASONS: usize = 32;
/// Maximum UTF-8 byte length of one drop-reason key.
pub const MAX_DROP_REASON_BYTES: usize = 64;

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
    /// Latest authenticated peer session observation.
    pub session: ComponentStatus,
    /// Latest actual utun state; default is Unknown, not created.
    pub tun: ComponentStatus,
    /// Latest actual /32 host-route state; default is Unknown, not installed.
    pub routes: ComponentStatus,
    /// Dataplane byte counters.
    pub bytes: ByteCounters,
    /// Dataplane drop counters and bounded reasons.
    pub drops: DropCounters,
    /// End-to-end direct-path evidence, independent of daemon Running.
    pub overlay: OverlayHealth,
    /// Current selected path, including its real physical socket.
    pub current_path: Option<CurrentPathStatus>,
    /// At most 32 eligible transport-bound candidates, not online evidence.
    pub candidates: Vec<CandidateStatus>,
    /// Truthful backend update accounting.
    pub discovery: DiscoveryCounters,
    /// Timestamp of the latest snapshot update, zero if not supplied.
    pub updated_unix_ms: u64,
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
