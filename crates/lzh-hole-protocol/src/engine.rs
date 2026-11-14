//! Bounded, no-socket engine for one authenticated IPv4-over-UDP peer.
//!
//! The daemon owns sockets, clocks and the TUN device. This engine owns the
//! existing handshake, session sequence/replay state and health challenges.
//! DATA and control frames deliberately share both sequence spaces. A correct
//! MAC authenticates a peer frame, but only a completed return-path challenge
//! selects its actual source endpoint; DATA from every other endpoint is
//! refused before it can enter the replay window or the TUN queue.

use std::collections::VecDeque;
use std::net::Ipv4Addr;

use etherparse::Ipv4HeaderSlice;

use crate::crypto::verify_frame_mac;
use crate::handshake::{
    CLOCK_SKEW_TOLERANCE_MS, Handshake, HandshakeConfig, HandshakeEvent, HandshakeReject,
};
use crate::health::{
    Health, HealthState, OFFLINE_AFTER_MS, PathContext, PendingPing, PongOutcome, ping_flags,
    pong_flags,
};
use crate::path::{
    Endpoint, EndpointReject, PathCandidate, PathEndpoint, PathKind, TransportPolicy, classify,
    validate_remote_target,
};
use crate::punch::{PunchConfig, PunchEvent, PunchFrame, PunchState};
use crate::session::SessionKeys;
use crate::wire::{
    CtrlPayload, Direction, FrameType, MAX_PAYLOAD_LEN, ParsedFrame, ProbePayload, WireError,
    encode_frame, parse_frame,
};
use lzh_hole_types::{BootId, DiscoveryPublicKey, RelationshipId, Role, Secret32, TransportId};

/// Maximum combined configured and unexpired learned targets for one peer.
pub const MAX_ENGINE_CANDIDATES: usize = 16;
/// Maximum number of endpoints simultaneously awaiting return-path proof.
pub const MAX_PENDING_PATHS: usize = 16;
/// Maximum queued UDP frames, including handshake and health traffic.
pub const MAX_UDP_OUTBOX: usize = 64;
/// Maximum authenticated IPv4 packets waiting for the daemon's TUN writer.
pub const MAX_IPV4_INBOX: usize = 32;
/// Largest IPv4 packet carried in one DATA frame (the UDP payload MTU).
pub const IPV4_MTU: usize = MAX_PAYLOAD_LEN;
/// Successful return-path probes sent to one endpoint per session.
pub const MAX_PATH_PROBES_PER_ENDPOINT: usize = 8;
/// A session with no usable health round trip is rebuilt after this interval.
pub const PATH_CONFIRM_TIMEOUT_MS: u64 = OFFLINE_AFTER_MS;

/// Queued punch events awaiting the daemon. The authoritative punch state
/// lives in `PunchState`, so overflowing this queue loses a notification but
/// never a decision.
const MAX_PUNCH_EVENTS: usize = 16;

const PATH_PROBE_INTERVAL_MS: u64 = 1_000;
const RESPONDER_PROBE_INTERVAL_MS: u64 = 1_000;
const LEARNED_PATH_TTL_MS: u64 = CLOCK_SKEW_TOLERANCE_MS;

/// Filtering applied both to configured candidates and peer-reflexive sources.
#[derive(Debug, Clone)]
pub struct CandidatePolicy {
    /// Exact local endpoints which must never be targeted.
    pub own_endpoints: Vec<Endpoint>,
    /// Coordination, overlay or other addresses which are never peer targets.
    pub forbidden_addresses: Vec<Ipv4Addr>,
    /// STUN servers are queried, never used as peer endpoints.
    pub stun_servers: Vec<Endpoint>,
    /// Keep the production public-unicast filter enabled. Closed-loop tests may
    /// explicitly disable it while the always-invalid ranges remain refused.
    pub require_public_unicast: bool,
}

impl Default for CandidatePolicy {
    fn default() -> Self {
        Self {
            own_endpoints: Vec::new(),
            forbidden_addresses: Vec::new(),
            stun_servers: Vec::new(),
            require_public_unicast: true,
        }
    }
}

/// Static configuration for one single-peer engine.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Existing authenticated handshake configuration.
    pub handshake: HandshakeConfig,
    /// The fixed virtual IPv4 address assigned to the local TUN interface.
    pub self_vip: Ipv4Addr,
    /// The fixed virtual IPv4 address assigned to the peer.
    pub peer_vip: Ipv4Addr,
    /// Candidate and peer-reflexive target policy.
    pub candidate_policy: CandidatePolicy,
}

/// Why an engine could not be constructed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EngineBuildError {
    /// Both TUN endpoints would have the same address.
    #[error("self and peer virtual IPv4 addresses must differ")]
    SameVirtualAddress,
    /// The existing handshake rejected the pinned relationship.
    #[error("handshake configuration rejected: {0:?}")]
    Handshake(HandshakeReject),
}

/// Structural or addressing rejection for one complete IPv4 packet or fragment.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Ipv4Reject {
    /// The DATA MTU is fixed by the existing wire format.
    #[error("IPv4 packet of {0} bytes exceeds the {IPV4_MTU} byte MTU")]
    TooLarge(usize),
    /// Etherparse rejected the version, IHL or available header bytes.
    #[error("malformed IPv4 header")]
    Malformed,
    /// The IPv4 total length must describe exactly the DATA payload.
    #[error("IPv4 total length {declared} does not match {actual} bytes")]
    LengthMismatch {
        /// Value in the IPv4 header.
        declared: usize,
        /// Actual packet bytes.
        actual: usize,
    },
    /// The IPv4 header checksum did not verify.
    #[error("bad IPv4 header checksum")]
    BadChecksum,
    /// Source was not the expected local or peer VIP.
    #[error("wrong IPv4 source {actual}, expected {expected}")]
    WrongSource {
        /// Required source.
        expected: Ipv4Addr,
        /// Source in the packet.
        actual: Ipv4Addr,
    },
    /// Destination was not the expected peer or local VIP.
    #[error("wrong IPv4 destination {actual}, expected {expected}")]
    WrongDestination {
        /// Required destination.
        expected: Ipv4Addr,
        /// Destination in the packet.
        actual: Ipv4Addr,
    },
}

/// Why a local IPv4 packet was not queued.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    /// The engine was explicitly closed.
    #[error("engine is closed")]
    Closed,
    /// No actual endpoint has completed return-path verification.
    #[error("no verified active endpoint")]
    NoActivePath,
    /// The bounded UDP outbox has no room; the caller may retry later.
    #[error("UDP outbox is full")]
    OutboxFull,
    /// The current session cannot safely allocate another sequence number.
    #[error("session sequence space exhausted")]
    SequenceExhausted,
    /// The supplied TUN packet failed validation.
    #[error(transparent)]
    Ipv4(#[from] Ipv4Reject),
    /// The existing wire encoder refused the DATA payload.
    #[error(transparent)]
    Wire(#[from] WireError),
}

/// One datagram the daemon should send on the retained physical UDP socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpFrame {
    /// Retained physical socket to send through.
    pub transport: TransportId,
    /// Actual destination selected or being challenged by the engine.
    pub target: Endpoint,
    /// Complete wire frame, including its MAC.
    pub bytes: Vec<u8>,
}

/// Result of replacing the configured candidate list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateUpdate {
    /// Unique, policy-compliant candidates retained.
    pub accepted: usize,
    /// Invalid, duplicate, closed-engine or over-capacity inputs ignored.
    pub rejected: usize,
}

/// Monotonic diagnostic counters. Values describe engine queueing and
/// verification, not proof that the operating system transmitted a datagram.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EngineCounters {
    /// Complete UDP frames accepted into the outbox.
    pub udp_queued: u64,
    /// Generated frames discarded because the outbox was full.
    pub udp_out_dropped: u64,
    /// Local IPv4 packets accepted into the UDP outbox.
    pub ipv4_tx_queued: u64,
    /// Authenticated IPv4 packets accepted from the selected endpoint.
    pub ipv4_rx_accepted: u64,
    /// Accepted packets discarded because the bounded TUN inbox was full.
    pub ipv4_in_dropped: u64,
    /// Structurally malformed wire frames.
    pub malformed_frames: u64,
    /// Frames whose relationship, session or direction was not current.
    pub stale_frames: u64,
    /// Session frames with a bad MAC.
    pub bad_mac: u64,
    /// Authenticated frames refused by the replay window.
    pub replay_rejected: u64,
    /// Session frames from a source that is not the selected active endpoint.
    pub wrong_endpoint: u64,
    /// DATA payloads which failed IPv4 structural, checksum or VIP checks.
    pub invalid_ipv4: u64,
    /// Control payloads with wrong identities, epochs or invalid health nonces.
    pub control_rejected: u64,
    /// Handshake frames rejected by the existing handshake engine.
    pub handshake_rejected: u64,
    /// New current sessions installed (shadow sessions are not counted).
    pub sessions_installed: u64,
    /// Actual endpoints selected only after a return-path PONG.
    pub paths_selected: u64,
    /// Local invalidations which cleared an old session before reconnecting.
    pub reconnects: u64,
    /// Health PINGs queued.
    pub pings_sent: u64,
    /// Health PONGs queued.
    pub pongs_sent: u64,
}

/// A read-only view suitable for daemon state reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineSnapshot {
    /// Selected local transport and actual remote endpoint.
    pub selected_path: Option<PathEndpoint>,
    /// Current session, even while its endpoint is still being proved.
    pub session_id: Option<u64>,
    /// The only endpoint currently accepted for DATA injection.
    pub selected_endpoint: Option<Endpoint>,
    /// Coarse health based on fresh normal health PONGs.
    pub health: Health,
    /// Our own current-session/current-endpoint round trip is fresh.
    pub direct_reachable: bool,
    /// Both sides have fresh evidence for this same session and endpoint.
    pub currently_healthy: bool,
    /// Number of retained configured candidates.
    pub candidate_count: usize,
    /// Endpoints awaiting bounded return-path verification.
    pub pending_path_count: usize,
    /// Queued datagrams not yet taken by the daemon.
    pub queued_udp_frames: usize,
    /// Verified packets not yet taken by the TUN writer.
    pub queued_ipv4_packets: usize,
    /// Health round trips, including explicitly marked path probes.
    pub round_trips: u64,
    /// Verification and queue counters.
    pub counters: EngineCounters,
    /// Whether `close` has permanently stopped this instance.
    pub closed: bool,
}

#[derive(Debug)]
struct CandidateState {
    path: PathEndpoint,
    kind: PathKind,
    last_probe_ms: Option<u64>,
    configured: bool,
    learned_until_ms: Option<u64>,
}

#[derive(Debug)]
struct PathProbeState {
    path: PathEndpoint,
    session_id: u64,
    next_probe_ms: u64,
    sent: usize,
}

#[derive(Debug, Default)]
struct ProbeBudget {
    // Proactive HELLO/retries/PROBE/path-PING share 10/s total and 2/s per path.
    // DATA, normal health and immediate authenticated replies are exempt.
    recent: VecDeque<(u64, PathEndpoint)>,
}

impl ProbeBudget {
    fn allow(&mut self, path: PathEndpoint, now_ms: u64) -> bool {
        self.recent
            .retain(|(at, _)| now_ms.saturating_sub(*at) < 1_000);
        if self.recent.len() >= 10 || self.recent.iter().filter(|(_, p)| *p == path).count() >= 2 {
            return false;
        }
        self.recent.push_back((now_ms, path));
        true
    }
}

#[derive(Debug)]
enum QueueError {
    NoSession,
    OutboxFull,
    SequenceExhausted,
    Wire(WireError),
}

/// One authenticated peer with no socket, TUN or async runtime ownership.
pub struct PeerEngine {
    hs: Handshake,
    role: Role,
    relationship_id: RelationshipId,
    self_key: DiscoveryPublicKey,
    peer_key: DiscoveryPublicKey,
    boot_id: BootId,
    generation: u64,
    self_vip: Ipv4Addr,
    peer_vip: Ipv4Addr,
    policy: CandidatePolicy,
    transports: Option<Vec<TransportPolicy>>,
    ping_paths: VecDeque<([u8; 32], PathEndpoint)>,
    probe_budget: ProbeBudget,
    punch: Option<PunchState>,
    punch_events: VecDeque<PunchEvent>,
    candidates: Vec<CandidateState>,
    path_probes: Vec<PathProbeState>,
    path_session: Option<u64>,
    session_path: Option<PathEndpoint>,
    responder_cursor: usize,
    now_ms: u64,
    selected: Option<PathEndpoint>,
    health: HealthState,
    udp_out: VecDeque<UdpFrame>,
    ipv4_in: VecDeque<Vec<u8>>,
    counters: EngineCounters,
    closed: bool,
}

impl std::fmt::Debug for PeerEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerEngine")
            .field("role", &self.role)
            .field("session_id", &self.hs.session().map(|s| s.keys.session_id))
            .field("selected", &self.selected)
            .field("candidates", &self.candidates.len())
            .field("pending_paths", &self.path_probes.len())
            .field("punch", &self.punch.as_ref().map(PunchState::phase))
            .field("queued_udp", &self.udp_out.len())
            .field("queued_ipv4", &self.ipv4_in.len())
            .field("closed", &self.closed)
            .finish()
    }
}

impl PeerEngine {
    /// Construct an engine from the same pinned relationship and PSK used by P0.
    pub fn new(config: EngineConfig, psk: &Secret32) -> Result<Self, EngineBuildError> {
        if config.self_vip == config.peer_vip {
            return Err(EngineBuildError::SameVirtualAddress);
        }
        let relationship_id = config.handshake.relationship_id;
        let self_key = config.handshake.me;
        let peer_key = config.handshake.peer;
        let boot_id = config.handshake.boot_id;
        let generation = config.handshake.generation;
        let hs = Handshake::new(config.handshake, psk).map_err(EngineBuildError::Handshake)?;
        let role = hs.role();
        Ok(Self {
            hs,
            role,
            relationship_id,
            self_key,
            peer_key,
            boot_id,
            generation,
            self_vip: config.self_vip,
            peer_vip: config.peer_vip,
            policy: config.candidate_policy,
            transports: None,
            ping_paths: VecDeque::new(),
            probe_budget: ProbeBudget::default(),
            punch: None,
            punch_events: VecDeque::new(),
            candidates: Vec::new(),
            path_probes: Vec::new(),
            path_session: None,
            session_path: None,
            responder_cursor: 0,
            now_ms: 0,
            selected: None,
            health: HealthState::new(),
            udp_out: VecDeque::new(),
            ipv4_in: VecDeque::new(),
            counters: EngineCounters::default(),
            closed: false,
        })
    }

    /// Replace the bounded candidate set. Existing verified paths remain in use
    /// until they fail; the new set is used immediately when no session exists.
    pub fn set_candidates(&mut self, endpoints: &[Endpoint]) -> CandidateUpdate {
        let paths = endpoints
            .iter()
            .map(|remote| PathCandidate {
                path: PathEndpoint {
                    transport: TransportId(0),
                    remote: *remote,
                },
                kind: PathKind::Public,
            })
            .collect::<Vec<_>>();
        self.set_paths(&paths)
    }

    /// Replace trusted socket facts. Omitted sockets are explicitly removed.
    /// At most sixteen policies and sixteen subnets per socket are retained.
    pub fn set_transports(&mut self, policies: &[TransportPolicy]) {
        let old = self
            .transports
            .as_ref()
            .map(|p| p.iter().map(|p| p.transport).collect::<Vec<_>>())
            .unwrap_or_default();
        let mut retained = Vec::<TransportPolicy>::new();
        for policy in policies.iter().take(MAX_ENGINE_CANDIDATES) {
            if retained.iter().any(|p| p.transport == policy.transport) {
                continue;
            }
            if self.transports.as_ref().is_some_and(|old| {
                old.iter().any(|p| {
                    p.transport == policy.transport && p.local_endpoint != policy.local_endpoint
                })
            }) {
                continue;
            }
            retained.push(TransportPolicy {
                transport: policy.transport,
                local_endpoint: policy.local_endpoint,
                lan_subnets: policy
                    .lan_subnets
                    .iter()
                    .take(MAX_ENGINE_CANDIDATES)
                    .copied()
                    .filter(|subnet| subnet.contains_host(policy.local_endpoint.ip))
                    .collect(),
            });
        }
        self.transports = Some(retained);
        for transport in old {
            if !self
                .transports
                .as_ref()
                .is_some_and(|p| p.iter().any(|p| p.transport == transport))
            {
                self.remove_transport(transport);
            }
        }
        let candidates = std::mem::take(&mut self.candidates);
        self.candidates = candidates
            .into_iter()
            .filter(|c| self.may_path(c.path, c.kind))
            .collect();
        for path in self.hs.pending_paths() {
            if !self.may_source(path) {
                self.hs.remove_path(path);
            }
        }
        if self.session_path.is_some_and(|p| !self.may_source(p)) {
            self.invalidate_session();
        }
        let queued = std::mem::take(&mut self.udp_out);
        self.udp_out = queued
            .into_iter()
            .filter(|f| {
                self.may_source(PathEndpoint {
                    transport: f.transport,
                    remote: f.target,
                })
            })
            .collect();
    }

    /// Replace discovery hints without resetting unchanged candidates' timers.
    /// Discovery withdrawal never tears down an authenticated selected path.
    pub fn set_paths(&mut self, paths: &[PathCandidate]) -> CandidateUpdate {
        let mut update = CandidateUpdate {
            accepted: 0,
            rejected: 0,
        };
        let previous = std::mem::take(&mut self.candidates);
        if self.closed {
            update.rejected = paths.len();
            return update;
        }
        for old in &previous {
            if old
                .learned_until_ms
                .is_some_and(|until| until > self.now_ms)
                && self.may_path(old.path, old.kind)
            {
                self.candidates.push(CandidateState {
                    path: old.path,
                    kind: old.kind,
                    last_probe_ms: old.last_probe_ms,
                    configured: false,
                    learned_until_ms: old.learned_until_ms,
                });
            }
        }
        for candidate in paths
            .iter()
            .filter(|c| c.kind == PathKind::Lan)
            .chain(paths.iter().filter(|c| c.kind == PathKind::Public))
            .copied()
        {
            if !self.may_path(candidate.path, candidate.kind) {
                update.rejected += 1;
                continue;
            }
            if let Some(existing) = self
                .candidates
                .iter_mut()
                .find(|c| c.path == candidate.path)
            {
                if existing.configured {
                    update.rejected += 1;
                } else {
                    existing.configured = true;
                    existing.kind = candidate.kind;
                    update.accepted += 1;
                }
                continue;
            }
            if self.candidates.len() >= MAX_ENGINE_CANDIDATES {
                update.rejected += 1;
                continue;
            }
            let last_probe_ms = previous
                .iter()
                .find(|old| old.path == candidate.path)
                .and_then(|old| old.last_probe_ms);
            self.candidates.push(CandidateState {
                path: candidate.path,
                kind: candidate.kind,
                last_probe_ms,
                configured: true,
                learned_until_ms: None,
            });
            update.accepted += 1;
        }
        self.candidates.sort_by_key(|c| c.kind != PathKind::Lan);
        update
    }

    /// Invalidate a retired local socket, but retain other viable candidates.
    /// Transport IDs must never be reused during the daemon lifetime.
    pub fn remove_transport(&mut self, transport: TransportId) {
        if self.transports.is_none() {
            self.transports = Some(Vec::new());
        }
        if let Some(policies) = &mut self.transports {
            policies.retain(|p| p.transport != transport);
        }
        self.candidates.retain(|c| c.path.transport != transport);
        self.path_probes.retain(|p| p.path.transport != transport);
        self.ping_paths.retain(|(_, p)| p.transport != transport);
        self.udp_out.retain(|f| f.transport != transport);
        self.hs.remove_transport(transport);
        if self.selected.is_some_and(|p| p.transport == transport)
            || (self.selected.is_none()
                && self.session_path.is_some_and(|p| p.transport == transport))
        {
            self.invalidate_session();
        }
    }

    /// Feed one UDP payload and its actual source address into the engine.
    /// Invalid network input is counted and ignored rather than returned as a
    /// local operational error. Replies are taken with `next_udp_frame`.
    pub fn handle_datagram(&mut self, source: Endpoint, datagram: &[u8], now_ms: u64) {
        self.handle_datagram_on(TransportId(0), source, datagram, now_ms);
    }

    /// Receive from the actual local socket; discovery cannot override it.
    pub fn handle_datagram_on(
        &mut self,
        transport: TransportId,
        remote: Endpoint,
        datagram: &[u8],
        now_ms: u64,
    ) {
        let source = PathEndpoint { transport, remote };
        if self.closed {
            return;
        }
        self.expire_learned_paths(now_ms);
        self.maybe_reconnect(now_ms);
        if !self.may_source(source) {
            self.counters.wrong_endpoint += 1;
            return;
        }
        let parsed = match parse_frame(datagram) {
            Ok(parsed) => parsed,
            Err(_) => {
                self.counters.malformed_frames += 1;
                return;
            }
        };
        if parsed.header.relationship_id != self.relationship_id {
            self.counters.stale_frames += 1;
            return;
        }
        // A punch frame is owned entirely by the punch state machine. It never
        // reaches the handshake, the transcript, the replay window or a
        // sequence space, and it never allocates session state. Slot 0 is the
        // ordinary data socket, which is what an easy side scans from.
        if parsed.header.frame_type == FrameType::Punch {
            self.handle_punch_datagram(0, transport, remote, datagram, now_ms);
            return;
        }
        if parsed.header.frame_type.is_sessionless() {
            if matches!(
                parsed.header.frame_type,
                FrameType::Hello | FrameType::Challenge | FrameType::Finish
            ) && self.udp_out.len() >= MAX_UDP_OUTBOX
            {
                self.counters.udp_out_dropped += 1;
                return;
            }
            let events = self.hs.handle_frame_on(transport, datagram, remote, now_ms);
            // A valid responder PROBE can seed a one-sided discovery exchange.
            // Deduplication and the candidate/attempt bounds prevent allocation
            // growth; the normal handshake timer performs the actual attempt.
            if parsed.header.frame_type == FrameType::Probe
                && events.is_empty()
                && self.role == Role::Initiator
                && self.hs.session().is_none()
            {
                self.learn_path(source, now_ms);
            }
            self.process_handshake_events(events, Some(source), now_ms);
        } else {
            self.handle_session_frame(parsed, source, now_ms);
        }
        self.drive_path_probes(now_ms);
    }

    /// Begin a hole-punch attempt.
    ///
    /// Refused whenever a path is already selected or a session exists: a
    /// punch must never preempt a working path. This is the single place that
    /// rule is enforced.
    pub fn start_punch(&mut self, config: PunchConfig, now_ms: u64) -> bool {
        if self.closed || self.punch.is_some() {
            return false;
        }
        if self.selected.is_some() || self.hs.session().is_some() {
            return false;
        }
        let key = self.hs.punch_key();
        self.punch = Some(PunchState::new(config, key, now_ms));
        true
    }

    /// Whether a punch attempt is running.
    pub fn punch_active(&self) -> bool {
        self.punch.is_some()
    }

    /// Borrow the punch state for diagnostics.
    pub fn punch_state(&self) -> Option<&PunchState> {
        self.punch.as_ref()
    }

    /// Advance the punch state machine. Punch traffic has its own budget and
    /// never touches `ProbeBudget` or the data outbox.
    pub fn punch_tick(
        &mut self,
        now_ms: u64,
        nonce: &mut dyn FnMut() -> [u8; 32],
    ) -> Vec<PunchEvent> {
        let events = match self.punch.as_mut() {
            Some(punch) => punch.tick(now_ms, nonce),
            None => return Vec::new(),
        };
        for event in &events {
            self.push_punch_event(*event);
        }
        events
    }

    /// Take the oldest queued punch frame. The daemon paces these with its own
    /// token bucket; this engine never decides a transmission rate.
    pub fn next_punch_frame(&mut self) -> Option<PunchFrame> {
        self.punch.as_mut().and_then(PunchState::next_frame)
    }

    /// Feed a datagram that arrived on a punch socket.
    ///
    /// Punch sockets are not engine transports, so this is a separate entry
    /// point from `handle_datagram_on`. The learned endpoint, when one is
    /// produced, becomes an ordinary candidate subject to the same target
    /// policy as any other.
    pub fn handle_punch_datagram(
        &mut self,
        slot: u16,
        transport: TransportId,
        remote: Endpoint,
        datagram: &[u8],
        now_ms: u64,
    ) -> Vec<PunchEvent> {
        if self.closed {
            return Vec::new();
        }
        if validate_remote_target(
            &remote,
            &self.policy.own_endpoints,
            &self.policy.forbidden_addresses,
            &self.policy.stun_servers,
        )
        .is_err()
        {
            self.counters.wrong_endpoint = self.counters.wrong_endpoint.saturating_add(1);
            return Vec::new();
        }
        let events = match self.punch.as_mut() {
            Some(punch) => punch.handle_inbound(slot, remote, datagram, now_ms),
            None => return Vec::new(),
        };
        for event in &events {
            if let PunchEvent::Learned { peer } | PunchEvent::Promote { peer, .. } = event {
                self.learn_path(
                    PathEndpoint {
                        transport,
                        remote: *peer,
                    },
                    now_ms,
                );
            }
        }
        for event in &events {
            self.push_punch_event(*event);
        }
        events
    }

    /// Stop any punch attempt and release its state.
    pub fn stop_punch(&mut self) {
        if let Some(punch) = self.punch.as_mut() {
            punch.stop();
        }
        self.punch = None;
        self.punch_events.clear();
    }

    /// Take queued punch events. Separate from the punch state so a missed
    /// notification never loses the underlying decision.
    pub fn take_punch_events(&mut self) -> Vec<PunchEvent> {
        self.punch_events.drain(..).collect()
    }

    fn push_punch_event(&mut self, event: PunchEvent) {
        if self.punch_events.len() >= MAX_PUNCH_EVENTS {
            self.punch_events.pop_front();
        }
        self.punch_events.push_back(event);
    }

    /// Record a peer-reflexive source as a bounded learned candidate.
    fn learn_path(&mut self, source: PathEndpoint, now_ms: u64) {
        if let Some(existing) = self.candidates.iter_mut().find(|c| c.path == source) {
            existing.learned_until_ms = Some(now_ms.saturating_add(LEARNED_PATH_TTL_MS));
            return;
        }
        if self.candidates.len() >= MAX_ENGINE_CANDIDATES {
            // Authenticated reachability evidence takes precedence over discovery
            // hints, but never displaces the installed session's current path.
            let replaceable = |candidate: &CandidateState| {
                self.selected != Some(candidate.path) && self.session_path != Some(candidate.path)
            };
            let index = self
                .candidates
                .iter()
                .rposition(|candidate| candidate.configured && replaceable(candidate))
                .or_else(|| self.candidates.iter().rposition(replaceable));
            let Some(index) = index else {
                return;
            };
            self.candidates.remove(index);
        }
        self.candidates.insert(
            0,
            CandidateState {
                path: source,
                kind: if crate::path::is_private(source.remote.ip) {
                    PathKind::Lan
                } else {
                    PathKind::Public
                },
                last_probe_ms: None,
                configured: false,
                learned_until_ms: Some(now_ms.saturating_add(LEARNED_PATH_TTL_MS)),
            },
        );
    }

    /// Advance retransmission, health and failure timers without performing IO.
    pub fn tick(&mut self, now_ms: u64) {
        if self.closed {
            return;
        }
        self.expire_learned_paths(now_ms);
        self.maybe_reconnect(now_ms);
        self.health.expire(now_ms);

        if self.hs.session().is_none() {
            self.drive_handshake(now_ms);
        }
        let available = MAX_UDP_OUTBOX.saturating_sub(self.udp_out.len());
        let mut admitted = 0;
        let budget = &mut self.probe_budget;
        let events = self.hs.tick_with_budget(now_ms, |transport, remote| {
            if admitted >= available || !budget.allow(PathEndpoint { transport, remote }, now_ms) {
                return false;
            }
            admitted += 1;
            true
        });
        self.process_handshake_events(events, None, now_ms);
        self.drive_health(now_ms);
    }

    /// Validate and queue one complete local TUN IPv4 packet or fragment.
    /// There is no business-packet retransmission after the frame is drained.
    pub fn send_ipv4(&mut self, packet: &[u8], now_ms: u64) -> Result<(), SendError> {
        if self.closed {
            return Err(SendError::Closed);
        }
        self.validate_ipv4(packet, false)?;
        self.maybe_reconnect(now_ms);
        let target = self.selected.ok_or(SendError::NoActivePath)?;
        match self.queue_session_frame(FrameType::Data, target, packet) {
            Ok(()) => {
                self.counters.ipv4_tx_queued += 1;
                Ok(())
            }
            Err(QueueError::NoSession) => Err(SendError::NoActivePath),
            Err(QueueError::OutboxFull) => Err(SendError::OutboxFull),
            Err(QueueError::SequenceExhausted) => Err(SendError::SequenceExhausted),
            Err(QueueError::Wire(error)) => Err(SendError::Wire(error)),
        }
    }

    /// Take the oldest datagram. The daemon should send it immediately on the
    /// same physical socket used for discovery and report no false send success.
    pub fn next_udp_frame(&mut self) -> Option<UdpFrame> {
        self.udp_out.pop_front()
    }

    /// Take the oldest authenticated, VIP-checked packet for the TUN writer.
    /// Fragments are passed through independently for the OS IP stack to handle.
    pub fn next_ipv4_packet(&mut self) -> Option<Vec<u8>> {
        self.ipv4_in.pop_front()
    }

    /// Snapshot selected path, health, queue depths and verification counters.
    pub fn snapshot(&self, now_ms: u64) -> EngineSnapshot {
        let (direct_reachable, currently_healthy) =
            self.current_context().map_or((false, false), |context| {
                (
                    self.health.local_confirmed(now_ms, &context),
                    self.health.bilateral_confirmed(now_ms, &context),
                )
            });
        EngineSnapshot {
            session_id: self.hs.session().map(|session| session.keys.session_id),
            selected_path: self.selected,
            selected_endpoint: self.selected.map(|p| p.remote),
            health: if self.selected.is_some() {
                self.health.health(now_ms)
            } else {
                Health::Unknown
            },
            direct_reachable,
            currently_healthy,
            candidate_count: self.candidates.len(),
            pending_path_count: self.path_probes.len(),
            queued_udp_frames: self.udp_out.len(),
            queued_ipv4_packets: self.ipv4_in.len(),
            round_trips: self.health.round_trips(),
            counters: self.counters,
            closed: self.closed,
        }
    }

    /// Permanently stop this instance and release every bounded queue and
    /// handshake entry. No timer or received packet can revive a closed engine.
    pub fn close(&mut self) {
        self.closed = true;
        self.hs.reset();
        self.candidates.clear();
        self.path_probes.clear();
        self.path_session = None;
        self.session_path = None;
        self.selected = None;
        self.health = HealthState::new();
        self.ping_paths.clear();
        self.udp_out.clear();
        self.ipv4_in.clear();
    }

    fn may_target(&self, endpoint: Endpoint) -> bool {
        if self.policy.require_public_unicast {
            return validate_remote_target(
                &endpoint,
                &self.policy.own_endpoints,
                &self.policy.forbidden_addresses,
                &self.policy.stun_servers,
            )
            .is_ok();
        }
        if endpoint.port == 0
            || self.policy.own_endpoints.contains(&endpoint)
            || self.policy.stun_servers.contains(&endpoint)
            || self.policy.forbidden_addresses.contains(&endpoint.ip)
        {
            return false;
        }
        !matches!(
            classify(endpoint.ip),
            Some(
                EndpointReject::ThisNetwork
                    | EndpointReject::Broadcast
                    | EndpointReject::Multicast
                    | EndpointReject::Reserved
                    | EndpointReject::FakeIp
                    | EndpointReject::Documentation
            )
        )
    }

    fn expire_learned_paths(&mut self, now_ms: u64) {
        self.now_ms = self.now_ms.max(now_ms);
        self.candidates.retain(|c| {
            c.configured || c.learned_until_ms.is_some_and(|until| until > self.now_ms)
        });
    }

    fn may_path(&self, path: PathEndpoint, kind: PathKind) -> bool {
        let Some(transports) = &self.transports else {
            return path.transport == TransportId(0)
                && kind == PathKind::Public
                && self.may_target(path.remote);
        };
        let Some(policy) = transports.iter().find(|p| p.transport == path.transport) else {
            return false;
        };
        let endpoint = path.remote;
        if endpoint.port == 0
            || endpoint.ip == self.self_vip
            || endpoint.ip == self.peer_vip
            || self.policy.forbidden_addresses.contains(&endpoint.ip)
            || self.policy.own_endpoints.contains(&endpoint)
            || self.policy.stun_servers.contains(&endpoint)
            || transports.iter().any(|p| p.local_endpoint == endpoint)
        {
            return false;
        }
        match kind {
            PathKind::Public => validate_remote_target(
                &endpoint,
                &self.policy.own_endpoints,
                &self.policy.forbidden_addresses,
                &self.policy.stun_servers,
            )
            .is_ok(),
            PathKind::Lan => {
                !transports
                    .iter()
                    .any(|p| p.local_endpoint.ip == endpoint.ip)
                    && policy.lan_subnets.iter().any(|s| {
                        s.contains_host(policy.local_endpoint.ip) && s.contains_host(endpoint.ip)
                    })
            }
        }
    }

    fn may_source(&self, path: PathEndpoint) -> bool {
        self.may_path(path, PathKind::Public) || self.may_path(path, PathKind::Lan)
    }

    fn validate_ipv4(&self, packet: &[u8], inbound: bool) -> Result<(), Ipv4Reject> {
        if packet.len() > IPV4_MTU {
            return Err(Ipv4Reject::TooLarge(packet.len()));
        }
        let header = Ipv4HeaderSlice::from_slice(packet).map_err(|_| Ipv4Reject::Malformed)?;
        let declared = usize::from(header.total_len());
        if declared != packet.len() || declared < header.slice().len() {
            return Err(Ipv4Reject::LengthMismatch {
                declared,
                actual: packet.len(),
            });
        }
        if header.header_checksum() != header.to_header().calc_header_checksum() {
            return Err(Ipv4Reject::BadChecksum);
        }
        let (expected_source, expected_destination) = if inbound {
            (self.peer_vip, self.self_vip)
        } else {
            (self.self_vip, self.peer_vip)
        };
        if header.source_addr() != expected_source {
            return Err(Ipv4Reject::WrongSource {
                expected: expected_source,
                actual: header.source_addr(),
            });
        }
        if header.destination_addr() != expected_destination {
            return Err(Ipv4Reject::WrongDestination {
                expected: expected_destination,
                actual: header.destination_addr(),
            });
        }
        Ok(())
    }

    fn path_context(&self, source: PathEndpoint) -> Option<PathContext> {
        let session = self.hs.session()?;
        Some(PathContext {
            endpoint: source.remote,
            session_id: session.keys.session_id,
            generation: self.generation,
            peer_generation: session.peer_generation,
            local_boot_id: self.boot_id,
            peer_boot_id: session.peer_boot_id,
            selected: self.path_session == Some(session.keys.session_id)
                && self.selected == Some(source),
        })
    }

    fn current_context(&self) -> Option<PathContext> {
        self.path_context(self.selected?)
    }

    fn local_confirmed(&self, now_ms: u64) -> bool {
        self.current_context()
            .is_some_and(|context| self.health.local_confirmed(now_ms, &context))
    }

    fn bilateral_confirmed(&self, now_ms: u64) -> bool {
        self.current_context()
            .is_some_and(|context| self.health.bilateral_confirmed(now_ms, &context))
    }

    fn queue_frame(&mut self, target: PathEndpoint, bytes: Vec<u8>) -> bool {
        if self.udp_out.len() >= MAX_UDP_OUTBOX {
            self.counters.udp_out_dropped += 1;
            return false;
        }
        self.udp_out.push_back(UdpFrame {
            transport: target.transport,
            target: target.remote,
            bytes,
        });
        self.counters.udp_queued += 1;
        true
    }

    fn queue_session_frame(
        &mut self,
        frame_type: FrameType,
        target: PathEndpoint,
        payload: &[u8],
    ) -> Result<(), QueueError> {
        if self.udp_out.len() >= MAX_UDP_OUTBOX {
            return Err(QueueError::OutboxFull);
        }
        let (session_id, sequence, key) = {
            let session = self.hs.session_mut().ok_or(QueueError::NoSession)?;
            if session.sequence_exhausted() {
                return Err(QueueError::SequenceExhausted);
            }
            (
                session.keys.session_id,
                session.next_tx_seq(),
                session.keys.tx_key(self.role).clone(),
            )
        };
        let bytes = encode_frame(
            frame_type,
            SessionKeys::tx_direction(self.role),
            self.relationship_id,
            session_id,
            sequence,
            payload,
            &key,
        )
        .map_err(QueueError::Wire)?;
        if self.queue_frame(target, bytes) {
            Ok(())
        } else {
            Err(QueueError::OutboxFull)
        }
    }

    fn accept_replay(&mut self, sequence: u64) -> bool {
        let Some(session) = self.hs.session_mut() else {
            return false;
        };
        if session.rx.would_accept(sequence).is_err() {
            self.counters.replay_rejected += 1;
            return false;
        }
        if session.rx.accept(sequence).is_err() {
            self.counters.replay_rejected += 1;
            return false;
        }
        true
    }

    fn handle_session_frame(&mut self, parsed: ParsedFrame<'_>, source: PathEndpoint, now_ms: u64) {
        if !self.may_source(source) || self.session_path != Some(source) {
            self.counters.wrong_endpoint += 1;
            return;
        }
        let Some(session) = self.hs.session() else {
            self.counters.stale_frames += 1;
            return;
        };
        let session_id = session.keys.session_id;
        if parsed.header.session_id != session_id
            || parsed.header.direction != SessionKeys::rx_direction(self.role)
        {
            self.counters.stale_frames += 1;
            return;
        }
        if !verify_frame_mac(
            session.keys.rx_key(self.role),
            &parsed.raw_header(),
            parsed.payload,
            parsed.mac,
        ) {
            self.counters.bad_mac += 1;
            return;
        }

        let mut control = None;
        match parsed.header.frame_type {
            FrameType::Data => {
                if self.validate_ipv4(parsed.payload, true).is_err() {
                    self.counters.invalid_ipv4 += 1;
                    return;
                }
                if self.path_session != Some(session_id) || self.selected != Some(source) {
                    self.counters.wrong_endpoint += 1;
                    if self.selected.is_none() && self.path_session == Some(session_id) {
                        self.queue_path_target(source);
                    }
                    return;
                }
            }
            FrameType::CtrlPing | FrameType::CtrlPong => {
                if parsed.header.frame_type == FrameType::CtrlPing
                    && (self.selected.is_some_and(|selected| selected != source)
                        || (self.selected.is_none()
                            && !self.path_probes.iter().any(|p| p.path == source)))
                {
                    self.counters.wrong_endpoint += 1;
                    return;
                }
                let decoded = if parsed.header.frame_type == FrameType::CtrlPing {
                    CtrlPayload::decode_ping(parsed.payload)
                } else {
                    CtrlPayload::decode_pong(parsed.payload)
                };
                let Ok(decoded) = decoded else {
                    self.counters.control_rejected += 1;
                    return;
                };
                if decoded.sender != self.peer_key
                    || decoded.receiver != self.self_key
                    || decoded.boot_id != session.peer_boot_id
                    || decoded.generation != session.peer_generation
                    || now_ms.abs_diff(decoded.issued_at_unix_ms) > CLOCK_SKEW_TOLERANCE_MS
                {
                    self.counters.control_rejected += 1;
                    return;
                }
                control = Some(decoded);
            }
            _ => {
                self.counters.malformed_frames += 1;
                return;
            }
        }

        if parsed.header.frame_type == FrameType::CtrlPong {
            let pong = control.expect("validated PONG");
            if !self
                .ping_paths
                .iter()
                .any(|(nonce, path)| *nonce == pong.nonce && *path == source)
            {
                self.counters.control_rejected += 1;
                return;
            }
            let Some(context) = self.path_context(source) else {
                self.counters.control_rejected += 1;
                return;
            };
            let replay_ok = self
                .hs
                .session()
                .is_some_and(|session| session.rx.would_accept(parsed.header.sequence).is_ok());
            if !replay_ok {
                self.counters.replay_rejected += 1;
                return;
            }

            // Validate the nonce, actual source and complete path context on a
            // speculative health state. Neither the replay window nor live
            // health is committed until this returns Accepted.
            let mut validated_health = self.health.clone();
            let PongOutcome::Accepted { path_probe, .. } =
                validated_health.on_pong(&pong, source.remote, &context, now_ms)
            else {
                self.counters.control_rejected += 1;
                return;
            };
            if !self.accept_replay(parsed.header.sequence) {
                return;
            }
            self.health = validated_health;
            self.ping_paths.retain(|(nonce, _)| *nonce != pong.nonce);
            if path_probe && self.selected.is_none() && self.path_session == Some(session_id) {
                self.selected = Some(source);
                self.path_probes.clear();
                self.health.invalidate_endpoint(source.remote);
                self.counters.paths_selected += 1;
            }
            return;
        }

        // DATA and PING share the same replay window as PONG. PING deliberately
        // remains valid from an unknown source so it can prove a return path.
        if !self.accept_replay(parsed.header.sequence) {
            return;
        }
        match parsed.header.frame_type {
            FrameType::Data => {
                self.counters.ipv4_rx_accepted += 1;
                if self.ipv4_in.len() >= MAX_IPV4_INBOX {
                    self.counters.ipv4_in_dropped += 1;
                } else {
                    self.ipv4_in.push_back(parsed.payload.to_vec());
                }
            }
            FrameType::CtrlPing => {
                let ping = control.expect("validated PING");
                // Only registered return paths may affect health/replay.
                if let Some(context) = self.path_context(source) {
                    self.health.on_ping(&ping, source.remote, &context, now_ms);
                }
                self.send_pong(source, ping.nonce, ping.path_probe(), now_ms);
            }
            _ => unreachable!("PONG returned above; other types matched earlier"),
        }
    }

    fn process_handshake_events(
        &mut self,
        events: Vec<HandshakeEvent>,
        source: Option<PathEndpoint>,
        now_ms: u64,
    ) {
        let mut target_hint = None;
        for event in events {
            match event {
                HandshakeEvent::Send {
                    transport,
                    target,
                    frames,
                } => {
                    let target = PathEndpoint {
                        transport,
                        remote: target,
                    };
                    target_hint = Some(target);
                    for frame in frames {
                        if self.may_source(target) {
                            self.queue_frame(target, frame);
                        }
                    }
                }
                HandshakeEvent::SessionInstalled { session_id } => {
                    if self
                        .hs
                        .session()
                        .is_some_and(|s| s.keys.session_id == session_id)
                        && self.path_session != Some(session_id)
                    {
                        self.path_session = Some(session_id);
                        self.session_path = source.or(target_hint);
                        self.selected = None;
                        self.health = HealthState::new();
                        self.path_probes.clear();
                        self.counters.sessions_installed += 1;
                        if let Some(winner) = self.session_path {
                            self.queue_path_target(winner);
                        }
                    }
                }
                HandshakeEvent::AckReceived { .. } => {}
                HandshakeEvent::AttemptExpired => self.counters.handshake_rejected += 1,
                HandshakeEvent::Dropped(reason) => {
                    if reason == HandshakeReject::BadMac {
                        self.counters.bad_mac += 1;
                    } else {
                        self.counters.handshake_rejected += 1;
                    }
                }
            }
        }
        self.drive_path_probes(now_ms);
    }

    fn drive_handshake(&mut self, now_ms: u64) {
        match self.role {
            Role::Initiator => {
                let targets = self
                    .candidates
                    .iter()
                    .map(|candidate| candidate.path)
                    .collect::<Vec<_>>();
                for target in targets {
                    if self.hs.has_attempt_on(target.transport, target.remote)
                        || self.udp_out.len() >= MAX_UDP_OUTBOX
                        || !self.probe_budget.allow(target, now_ms)
                    {
                        continue;
                    }
                    match self
                        .hs
                        .start_attempt_on(target.transport, target.remote, now_ms)
                    {
                        Ok(events) => self.process_handshake_events(events, None, now_ms),
                        Err(_) => self.counters.handshake_rejected += 1,
                    }
                }
            }
            Role::Responder => {
                for offset in 0..self.candidates.len() {
                    let index = (offset + self.responder_cursor) % self.candidates.len();
                    let due = self.candidates[index].last_probe_ms.is_none_or(|last| {
                        now_ms.saturating_sub(last) >= RESPONDER_PROBE_INTERVAL_MS
                    });
                    if !due {
                        continue;
                    }
                    self.candidates[index].last_probe_ms = Some(now_ms);
                    self.send_responder_probe(self.candidates[index].path, now_ms);
                }
                self.responder_cursor = if self.candidates.is_empty() {
                    0
                } else {
                    (self.responder_cursor % self.candidates.len() + 1) % self.candidates.len()
                };
            }
        }
    }

    fn send_responder_probe(&mut self, target: PathEndpoint, now_ms: u64) {
        if !self.probe_budget.allow(target, now_ms) {
            return;
        }
        let mut nonce = [0u8; 32];
        if getrandom::fill(&mut nonce).is_err() {
            self.counters.control_rejected += 1;
            return;
        }
        let payload = ProbePayload {
            sender: self.self_key,
            receiver: self.peer_key,
            boot_id: self.boot_id,
            generation: self.generation,
            issued_at_unix_ms: now_ms,
            probe_nonce: nonce,
        }
        .encode();
        let key = self.hs.probe_key();
        match encode_frame(
            FrameType::Probe,
            Direction::HiToLo,
            self.relationship_id,
            0,
            0,
            &payload,
            &key,
        ) {
            Ok(frame) => {
                self.queue_frame(target, frame);
            }
            Err(_) => self.counters.control_rejected += 1,
        }
    }

    fn queue_path_target(&mut self, path: PathEndpoint) {
        let Some(session_id) = self.path_session else {
            return;
        };
        if self.selected.is_some()
            || self.session_path != Some(path)
            || !self.may_source(path)
            || self
                .path_probes
                .iter()
                .any(|probe| probe.path == path && probe.session_id == session_id)
        {
            return;
        }
        if self.path_probes.len() >= MAX_PENDING_PATHS {
            return;
        }
        self.path_probes.push(PathProbeState {
            path,
            session_id,
            next_probe_ms: 0,
            sent: 0,
        });
    }

    fn drive_path_probes(&mut self, now_ms: u64) {
        if self.selected.is_some() || !self.health.has_room() {
            return;
        }
        for index in 0..self.path_probes.len() {
            if !self.health.has_room() {
                break;
            }
            let probe = &self.path_probes[index];
            let due = self.path_session == Some(probe.session_id)
                && probe.sent < MAX_PATH_PROBES_PER_ENDPOINT
                && now_ms >= probe.next_probe_ms;
            if !due {
                continue;
            }
            let endpoint = probe.path;
            let sent = self.send_ping(endpoint, true, now_ms);
            let probe = &mut self.path_probes[index];
            probe.next_probe_ms = now_ms.saturating_add(PATH_PROBE_INTERVAL_MS);
            if sent {
                probe.sent += 1;
            }
        }
    }

    fn drive_health(&mut self, now_ms: u64) {
        if self.hs.session().is_none() {
            return;
        }
        let Some(target) = self.selected else {
            self.drive_path_probes(now_ms);
            return;
        };
        let bilateral = self.bilateral_confirmed(now_ms);
        if self.health.has_room() && self.health.ping_due(now_ms, bilateral) {
            self.send_ping(target, false, now_ms);
        }
    }

    fn send_ping(&mut self, target: PathEndpoint, path_probe: bool, now_ms: u64) -> bool {
        if !self.health.has_room() || self.session_path != Some(target) {
            return false;
        }
        if path_probe && !self.probe_budget.allow(target, now_ms) {
            return false;
        }
        let mut nonce = [0u8; 32];
        if getrandom::fill(&mut nonce).is_err() {
            self.counters.control_rejected += 1;
            return false;
        }
        let payload = CtrlPayload {
            sender: self.self_key,
            receiver: self.peer_key,
            nonce,
            boot_id: self.boot_id,
            generation: self.generation,
            issued_at_unix_ms: now_ms,
            flags: ping_flags(self.local_confirmed(now_ms), path_probe, false),
        }
        .encode();
        if self
            .queue_session_frame(FrameType::CtrlPing, target, &payload)
            .is_err()
        {
            return false;
        }
        let Some(session) = self.hs.session() else {
            return false;
        };
        self.health.register_sent(
            PendingPing {
                nonce,
                endpoint: target.remote,
                boot_id: self.boot_id,
                peer_boot_id: session.peer_boot_id,
                generation: self.generation,
                peer_generation: session.peer_generation,
                session_id: session.keys.session_id,
                sent_ms: now_ms,
                path_probe,
            },
            now_ms,
        );
        self.counters.pings_sent += 1;
        if self.ping_paths.len() >= 64 {
            self.ping_paths.pop_front();
        }
        self.ping_paths.push_back((nonce, target));
        true
    }

    fn send_pong(
        &mut self,
        target: PathEndpoint,
        nonce: [u8; 32],
        echo_path_probe: bool,
        now_ms: u64,
    ) {
        let payload = CtrlPayload {
            sender: self.self_key,
            receiver: self.peer_key,
            nonce,
            boot_id: self.boot_id,
            generation: self.generation,
            issued_at_unix_ms: now_ms,
            flags: pong_flags(self.local_confirmed(now_ms), echo_path_probe),
        }
        .encode();
        if self
            .queue_session_frame(FrameType::CtrlPong, target, &payload)
            .is_ok()
        {
            self.counters.pongs_sent += 1;
        }
    }

    fn maybe_reconnect(&mut self, now_ms: u64) -> bool {
        let Some(session) = self.hs.session() else {
            return false;
        };
        let session_id = session.keys.session_id;
        let exhausted = session.sequence_exhausted();
        let session_age = now_ms.saturating_sub(session.created_ms);
        let no_round_trip = self.health.last_valid_reply_age_ms(now_ms).is_none();
        let confirmation_timed_out = self.path_session == Some(session_id)
            && session_age >= PATH_CONFIRM_TIMEOUT_MS
            && (self.selected.is_none() || no_round_trip);
        let offline = self.selected.is_some() && self.health.health(now_ms) == Health::Offline;
        if !exhausted && !confirmation_timed_out && !offline {
            return false;
        }
        self.invalidate_session();
        true
    }

    fn invalidate_session(&mut self) {
        self.hs.reset();
        self.path_session = None;
        self.session_path = None;
        self.selected = None;
        self.path_probes.clear();
        self.health = HealthState::new();
        self.ping_paths.clear();
        self.udp_out.clear();
        self.ipv4_in.clear();
        for candidate in &mut self.candidates {
            candidate.last_probe_ms = None;
        }
        self.counters.reconnects += 1;
    }
}

#[cfg(test)]
#[path = "engine/tests.rs"]
mod unit_tests;
