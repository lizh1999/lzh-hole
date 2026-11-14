//! Bounded punch socket pool, rate-limited drain and trigger policy.
//!
//! Everything here is deliberately separate from the data plane. Punch sockets
//! live in their own pool with ephemeral ports, punch frames drain through
//! their own token bucket, and the engine's data outbox and probe budget are
//! never touched. The only moment the two worlds meet is promotion: the socket
//! that actually completed a punch joins the ordinary transport set, keeping
//! the identifier it already had.

use std::collections::BTreeMap;
use std::future::poll_fn;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::task::Poll;

use lzh_hole_discovery::MappingBehavior;
use lzh_hole_net::socket::{AsyncPhysicalSocket, RecvMeta};
use lzh_hole_protocol::path::PathKind;
use lzh_hole_protocol::punch::{
    PUNCH_BURST, PUNCH_DEADLINE_MS, PUNCH_HARD_DEADLINE_MS, PUNCH_HARD_SOCKETS, PunchConfig,
    PunchEvent, PunchRole,
};
use lzh_hole_types::TransportId;

use super::transport::TransportIds;
use super::*;

const MAX_DATAGRAM_BYTES: usize = 64 * 1024;

/// Consecutive punch send failures tolerated before the attempt is abandoned.
///
/// Frames are consumed from the state machine's outbox before transmission, so
/// a socket that silently stopped sending would otherwise let the whole grid be
/// walked with nothing on the wire and then be misreported as exhausted.
pub(super) const PUNCH_MAX_SEND_FAILURES: u32 = 32;

/// Initial delay before a second punch attempt.
pub(super) const PUNCH_RETRY_MIN_MS: u64 = 30_000;
/// Longest delay between punch attempts.
pub(super) const PUNCH_RETRY_MAX_MS: u64 = 15 * 60_000;

/// Reserve only this process's soft descriptor budget; never change a hard or
/// system-wide limit. launchd commonly starts services with a soft limit of 256.
fn punch_soft_limit(count: usize, limits: &libc::rlimit) -> io::Result<libc::rlim_t> {
    let required = (count + 128).next_power_of_two() as libc::rlim_t;
    if limits.rlim_cur >= required {
        return Ok(limits.rlim_cur);
    }
    if limits.rlim_max < required {
        return Err(io::Error::other(format!(
            "punch needs RLIMIT_NOFILE >= {required}, hard limit is {}",
            limits.rlim_max
        )));
    }
    Ok(required)
}

fn reserve_punch_descriptors(count: usize) -> io::Result<()> {
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: limits is a live writable rlimit and RLIMIT_NOFILE is valid.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let target = punch_soft_limit(count, &limits)?;
    if target != limits.rlim_cur {
        limits.rlim_cur = target;
        // SAFETY: limits is initialized, the hard limit is unchanged, and the
        // requested soft limit was checked not to exceed it. Only this process changes.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limits) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub(super) struct PunchSocket {
    pub id: TransportId,
    pub slot: u16,
    pub interface: String,
    pub socket: AsyncPhysicalSocket,
}

pub(super) struct PunchDatagram {
    pub id: TransportId,
    pub slot: u16,
    pub result: io::Result<(usize, RecvMeta)>,
    pub buffer: Vec<u8>,
}

/// Transient sockets used only to emit punch frames.
///
/// Bounded by construction: `open` refuses to exceed the configured count, and
/// every exit path -- success, failure, topology change, daemon shutdown --
/// goes through `close_all`.
pub(super) struct PunchSockets {
    sockets: BTreeMap<TransportId, PunchSocket>,
    by_slot: BTreeMap<u16, TransportId>,
    receive_cursor: usize,
    scratch: Vec<u8>,
    interface: String,
    address: Ipv4Addr,
}

impl Default for PunchSockets {
    fn default() -> Self {
        Self {
            sockets: BTreeMap::new(),
            by_slot: BTreeMap::new(),
            receive_cursor: 0,
            scratch: Vec::new(),
            interface: String::new(),
            address: Ipv4Addr::UNSPECIFIED,
        }
    }
}

impl std::fmt::Debug for PunchSockets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PunchSockets")
            .field("open", &self.sockets.len())
            .field("interface", &self.interface)
            .field("address", &self.address)
            .finish()
    }
}

impl PunchSockets {
    /// Open `count` sockets on one interface and address.
    ///
    /// Every socket takes an ephemeral local port. Reusing the configured data
    /// port would collide with the long-lived socket on the same address, and
    /// the transport set would simply hand back the existing identifier.
    ///
    /// A partial failure closes whatever was already opened, so a failed
    /// attempt never leaves descriptors behind.
    pub fn open(
        &mut self,
        ids: &mut TransportIds,
        interface: &str,
        address: Ipv4Addr,
        count: usize,
    ) -> io::Result<()> {
        if !self.sockets.is_empty() {
            return Err(io::Error::other("punch sockets already open"));
        }
        let count = count.clamp(1, PUNCH_HARD_SOCKETS);
        reserve_punch_descriptors(count)?;
        for slot in 0..count {
            let slot = slot as u16;
            let id = match ids.reserve() {
                Ok(id) => id,
                Err(error) => {
                    self.close_all();
                    return Err(error);
                }
            };
            let socket = match AsyncPhysicalSocket::open(interface, address, 0) {
                Ok(socket) => socket,
                Err(error) => {
                    self.close_all();
                    return Err(error);
                }
            };
            self.sockets.insert(
                id,
                PunchSocket {
                    id,
                    slot,
                    interface: interface.to_owned(),
                    socket,
                },
            );
            self.by_slot.insert(slot, id);
        }
        self.scratch = vec![0; MAX_DATAGRAM_BYTES];
        self.interface = interface.to_owned();
        self.address = address;
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        !self.sockets.is_empty()
    }

    pub fn len(&self) -> usize {
        self.sockets.len()
    }

    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    pub fn get(&self, id: TransportId) -> Option<&PunchSocket> {
        self.sockets.get(&id)
    }

    /// The transport identifier currently occupying a slot.
    pub fn slot_id(&self, slot: u16) -> Option<TransportId> {
        self.by_slot.get(&slot).copied()
    }

    /// Remove one socket so it can be handed to the data plane.
    pub fn take(&mut self, id: TransportId) -> Option<PunchSocket> {
        let socket = self.sockets.remove(&id)?;
        self.by_slot.remove(&socket.slot);
        Some(socket)
    }

    /// Drop every socket. Safe to call repeatedly.
    pub fn close_all(&mut self) {
        self.sockets.clear();
        self.by_slot.clear();
        self.receive_cursor = 0;
        self.interface.clear();
        self.address = Ipv4Addr::UNSPECIFIED;
    }

    pub async fn recv(&mut self) -> PunchDatagram {
        let Self {
            sockets,
            receive_cursor,
            scratch,
            ..
        } = self;
        poll_fn(|context| {
            let count = sockets.len();
            if count == 0 {
                return Poll::Pending;
            }
            let start = *receive_cursor % count;
            let ordered = sockets
                .values()
                .enumerate()
                .skip(start)
                .chain(sockets.values().enumerate().take(start));
            for (index, punch) in ordered {
                if let Poll::Ready(result) = punch.socket.poll_recv_from(context, scratch) {
                    *receive_cursor = (index + 1) % count;
                    let buffer = match &result {
                        Ok((size, _)) => scratch[..*size].to_vec(),
                        Err(_) => Vec::new(),
                    };
                    return Poll::Ready(PunchDatagram {
                        id: punch.id,
                        slot: punch.slot,
                        result,
                        buffer,
                    });
                }
            }
            Poll::Pending
        })
        .await
    }
}

/// Monotonic token bucket. Punch traffic gets its own so the data plane's
/// probe budget is never spent on a port scan.
#[derive(Debug)]
pub(super) struct TokenBucket {
    rate_per_second: u32,
    burst: u32,
    tokens: u32,
    remainder: u64,
    last_ms: u64,
}

impl TokenBucket {
    pub fn new(rate_per_second: u32, burst: u32, now_ms: u64) -> Self {
        let rate_per_second = rate_per_second.max(1);
        let burst = burst.max(1);
        Self {
            rate_per_second,
            burst,
            tokens: burst,
            remainder: 0,
            last_ms: now_ms,
        }
    }

    /// Tokens available now, capped at the burst size.
    pub fn refill(&mut self, now_ms: u64) -> u32 {
        let elapsed = now_ms.saturating_sub(self.last_ms);
        self.last_ms = self.last_ms.max(now_ms);
        let credit = u64::from(self.rate_per_second)
            .saturating_mul(elapsed)
            .saturating_add(self.remainder);
        let tokens = u64::from(self.tokens).saturating_add(credit / 1_000);
        self.remainder = if tokens >= u64::from(self.burst) {
            0
        } else {
            credit % 1_000
        };
        self.tokens = tokens.min(u64::from(self.burst)) as u32;
        self.tokens
    }

    /// Spend up to `wanted` tokens, returning how many were granted.
    pub fn take(&mut self, wanted: u32) -> u32 {
        let granted = wanted.min(self.tokens);
        self.tokens -= granted;
        granted
    }
}

/// Why a punch attempt is not running, for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PunchBlock {
    /// Both peers are behind endpoint-dependent mappings.
    BothHard,
    /// A mapping behaviour could not be classified.
    MappingUnknown,
    /// No public peer candidate is available.
    NoPublicCandidate,
    /// No retained socket has a classified public mapping to punch from.
    NoClassifiedTransport,
    /// Disabled by configuration.
    Disabled,
    /// Waiting out the retry backoff.
    BackingOff,
    /// The ntfy budget is blocked, so coordination is not possible.
    NtfyBlocked,
    /// A healthy path already exists.
    HealthyPath,
    /// Wait for a signed, still-live hard-side window before scanning.
    WaitingForOffer,
}

impl PunchBlock {
    pub const fn as_str(self) -> &'static str {
        match self {
            PunchBlock::BothHard => "both_hard",
            PunchBlock::MappingUnknown => "mapping_unknown",
            PunchBlock::NoPublicCandidate => "no_public_candidate",
            PunchBlock::NoClassifiedTransport => "no_classified_transport",
            PunchBlock::Disabled => "disabled",
            PunchBlock::BackingOff => "backing_off",
            PunchBlock::NtfyBlocked => "ntfy_blocked",
            PunchBlock::HealthyPath => "healthy_path",
            PunchBlock::WaitingForOffer => "waiting_for_offer",
        }
    }
}

impl Daemon {
    /// Whether a punch window is currently open on this host.
    pub(super) fn punch_offer_active(&self) -> bool {
        self.punch_sockets.is_active()
    }

    /// An offer expires with the actual hard-side socket window, not an hour later.
    pub(super) fn punch_offer_deadline(&self) -> Option<u64> {
        if !self.punch_offer_active() {
            return None;
        }
        self.punch_started_ms
            .map(|started| started.saturating_add(PUNCH_HARD_DEADLINE_MS))
    }

    /// This host's own mapping verdict, reduced across retained sockets.
    pub(super) fn local_mapping(&self) -> MappingBehavior {
        lzh_hole_discovery::aggregate_mapping(
            self.public
                .mapping_behaviors()
                .into_iter()
                .map(|(_, profile)| profile.mapping),
        )
    }

    /// The peer's mapping verdict, as published in its last accepted record.
    pub(super) fn peer_mapping(&self) -> MappingBehavior {
        MappingBehavior::from_record_flags(self.peer_record_flags)
    }

    /// Start a punch attempt if every precondition holds.
    ///
    /// This never runs while a path is healthy, which is what keeps a working
    /// tunnel completely undisturbed.
    pub(super) fn maybe_start_punch(&mut self, now_ms: u64) {
        self.reap_promoted_transports(now_ms);
        if !self.resolved.config.punch.enabled {
            self.punch_block = Some(PunchBlock::Disabled);
            return;
        }
        if self.punch_sockets.is_active() {
            return;
        }
        let Some(engine) = self.engine.as_ref() else {
            return;
        };
        if engine.punch_active() {
            return;
        }
        let snapshot = engine.snapshot(now_ms);
        if snapshot.session_id.is_some() || snapshot.selected_path.is_some() {
            self.punch_block = Some(PunchBlock::HealthyPath);
            return;
        }
        if self.ntfy_waiting() {
            self.punch_block = Some(PunchBlock::NtfyBlocked);
            return;
        }
        if now_ms < self.next_punch_attempt_ms {
            self.punch_block = Some(PunchBlock::BackingOff);
            return;
        }

        let local = self.local_mapping();
        let peer = self.peer_mapping();
        let role = match (local, peer) {
            (MappingBehavior::EndpointDependent, MappingBehavior::EndpointIndependent) => {
                PunchRole::Hard
            }
            (MappingBehavior::EndpointIndependent, MappingBehavior::EndpointDependent) => {
                PunchRole::Easy
            }
            (MappingBehavior::EndpointDependent, MappingBehavior::EndpointDependent) => {
                self.punch_block = Some(PunchBlock::BothHard);
                return;
            }
            _ => {
                self.punch_block = Some(PunchBlock::MappingUnknown);
                return;
            }
        };

        if role == PunchRole::Easy
            && (self.peer_record_flags & lzh_hole_discovery::record::FLAG_PUNCH_OFFER == 0
                || self.peer_record_expires_ms <= now_ms.saturating_add(PUNCH_DEADLINE_MS))
        {
            self.punch_block = Some(PunchBlock::WaitingForOffer);
            return;
        }

        // Punch from a socket whose mapping behaviour is actually known, and
        // whose address is the one that produced a public mapping.
        let Some((origin_transport, interface, address)) = self.punch_origin(local) else {
            self.punch_block = Some(PunchBlock::NoClassifiedTransport);
            return;
        };
        let Some(target) = self
            .paths
            .iter()
            .find(|candidate| {
                candidate.kind == PathKind::Public && candidate.path.transport == origin_transport
            })
            .map(|candidate| candidate.path.remote)
        else {
            self.punch_block = Some(PunchBlock::NoPublicCandidate);
            return;
        };

        // The hard-side socket count is a protocol constant, not a tunable.
        // The easy side's grid step is fixed too, and a block narrower than
        // twice that step can be stepped straight over, so the two must move
        // together. Exposing one without the other would let an operator
        // silently disable punching.
        let hard_sockets = PUNCH_HARD_SOCKETS;
        if role == PunchRole::Hard
            && let Err(error) =
                self.punch_sockets
                    .open(&mut self.transport_ids, &interface, address, hard_sockets)
        {
            self.punch_failure = Some(format!("punch sockets: {error}"));
            self.schedule_punch_retry(now_ms);
            return;
        }

        let direction = if self.resolved.relationship.self_public_key
            < self.resolved.relationship.peer_public_key
        {
            lzh_hole_protocol::wire::Direction::LoToHi
        } else {
            lzh_hole_protocol::wire::Direction::HiToLo
        };
        let config = PunchConfig {
            role,
            peer_endpoint: target,
            local_key: self.resolved.relationship.self_public_key,
            peer_key: self.resolved.relationship.peer_public_key,
            relationship_id: self.resolved.relationship.relationship_id,
            boot_id: self.boot_id,
            generation: self.generation,
            direction,
            hard_sockets: hard_sockets as u16,
        };
        let started = self
            .engine
            .as_mut()
            .is_some_and(|engine| engine.start_punch(config, now_ms));
        if !started {
            self.punch_sockets.close_all();
            self.schedule_punch_retry(now_ms);
            return;
        }
        self.punch_bucket = TokenBucket::new(
            self.resolved.config.punch.rate_per_second(),
            PUNCH_BURST,
            self.monotonic_ms(),
        );
        self.punch_block = None;
        self.punch_failure = None;
        self.punch_started_ms = Some(now_ms);
        self.punch_hit_port = None;
        // Pin the socket the role decision was based on. Re-deriving it per
        // drain from the candidate projection would let the scan drift onto a
        // socket whose mapping behaviour is not the one that was classified.
        self.punch_origin_transport = Some(origin_transport);
        self.punch_send_failures = 0;
        self.refresh_public_request();
    }

    /// The interface and address a punch should originate from.
    fn punch_origin(&self, local: MappingBehavior) -> Option<(TransportId, String, Ipv4Addr)> {
        self.transports.iter().find_map(|socket| {
            let profile = self.public.mapping_behavior(socket.id.0);
            // A hard side must punch from a socket that is itself hard;
            // an easy side from one that is itself easy. Anything else would
            // make the role decision a lie.
            let matches_role = match local {
                MappingBehavior::EndpointDependent => {
                    profile.mapping == MappingBehavior::EndpointDependent
                }
                _ => profile.mapping == MappingBehavior::EndpointIndependent,
            };
            matches_role.then(|| (socket.id, socket.interface.clone(), *socket.local.ip()))
        })
    }

    fn schedule_punch_retry(&mut self, now_ms: u64) {
        let next = self
            .punch_backoff_ms
            .clamp(PUNCH_RETRY_MIN_MS, PUNCH_RETRY_MAX_MS);
        self.next_punch_attempt_ms = now_ms.saturating_add(next);
        self.punch_backoff_ms = next.saturating_mul(2).min(PUNCH_RETRY_MAX_MS);
    }

    /// Advance the punch state machine and act on its events.
    pub(super) fn drive_punch(&mut self, now_ms: u64) {
        let rng_failed = std::cell::Cell::new(false);
        let mut nonce_source = || {
            let mut bytes = [0u8; 32];
            match getrandom::fill(&mut bytes) {
                Ok(()) => bytes,
                Err(_) => {
                    // Never substitute a constant. The receiver deduplicates by
                    // nonce, so a repeated value would silently kill the attempt
                    // after its first frame; the attempt is abandoned instead.
                    rng_failed.set(true);
                    [0u8; 32]
                }
            }
        };
        let events = match self.engine.as_mut() {
            Some(engine) => {
                engine.punch_tick(now_ms, &mut nonce_source);
                engine.take_punch_events()
            }
            None => Vec::new(),
        };
        if rng_failed.get() {
            self.punch_failure = Some("randomness unavailable".to_owned());
            self.finish_punch(now_ms);
            return;
        }
        self.apply_punch_events(events, now_ms);
        self.poll_punch_completion(now_ms);
    }

    /// Feed one datagram that arrived on a punch socket into the engine.
    pub(super) fn handle_punch_udp(&mut self, event: PunchDatagram, now_ms: u64) {
        let (size, metadata) = match event.result {
            Ok(value) => value,
            Err(error) => {
                self.record_drop("punch_recv_failed", 1);
                self.punch_failure = Some(format!("punch receive failed: {error}"));
                // A failing punch socket is not evidence about the data plane,
                // so only that one socket is dropped.
                self.punch_sockets.take(event.id);
                return;
            }
        };
        let Some(socket) = self.punch_sockets.get(event.id) else {
            return;
        };
        if metadata
            .ifindex
            .is_some_and(|index| index != socket.socket.get_ref().bound_ifindex())
        {
            self.record_drop("punch_wrong_interface", 1);
            return;
        }
        // A punch datagram addressed to some other local address is not ours,
        // exactly as on the data plane.
        if metadata
            .dest
            .is_some_and(|dest| dest != self.punch_sockets.address())
        {
            self.record_drop("punch_wrong_destination", 1);
            return;
        }
        let remote = endpoint(metadata.source);
        let datagram = event.buffer[..size].to_vec();
        let events = match self.engine.as_mut() {
            Some(engine) => {
                engine.handle_punch_datagram(event.slot, event.id, remote, &datagram, now_ms);
                engine.take_punch_events()
            }
            None => Vec::new(),
        };
        self.bytes.udp_rx = self.bytes.udp_rx.saturating_add(size as u64);
        self.apply_punch_events(events, now_ms);
    }

    fn apply_punch_events(&mut self, events: Vec<PunchEvent>, now_ms: u64) {
        for event in events {
            match event {
                PunchEvent::Promote { slot, peer } => {
                    self.punch_hit_port = Some(peer.port);
                    self.promote_punch_slot(slot, now_ms);
                }
                PunchEvent::Learned { peer } => {
                    self.punch_hit_port = Some(peer.port);
                    // The learned endpoint is now an ordinary candidate and the
                    // engine's challenge flow takes it from here. The attempt
                    // itself stays alive until its confirmations have drained.
                }
                PunchEvent::Failed(failure) => {
                    self.punch_failure = Some(failure.as_str().to_owned());
                    self.finish_punch(now_ms);
                }
            }
        }
    }

    /// Retire the attempt once the state machine says it is finished.
    ///
    /// A hit no longer finishes immediately: confirmation frames are still owed
    /// and are generated on the next tick, so completion is observed here
    /// instead of being assumed at the moment of the hit.
    pub(super) fn poll_punch_completion(&mut self, now_ms: u64) {
        let Some(engine) = self.engine.as_ref() else {
            return;
        };
        let Some(state) = engine.punch_state() else {
            return;
        };
        match state.phase() {
            lzh_hole_protocol::punch::PunchPhase::Done => self.finish_punch(now_ms),
            lzh_hole_protocol::punch::PunchPhase::Failed => {
                if self.punch_failure.is_none() {
                    self.punch_failure = state
                        .failure()
                        .map(|failure| failure.as_str().to_owned())
                        .or_else(|| Some("punch failed".to_owned()));
                }
                self.finish_punch(now_ms);
            }
            _ => {}
        }
    }

    /// Move the winning punch socket into the data plane, keeping its id.
    fn promote_punch_slot(&mut self, slot: u16, now_ms: u64) {
        let Some(id) = self.punch_sockets.slot_id(slot) else {
            self.punch_failure = Some("promoted slot is gone".to_owned());
            self.finish_punch(now_ms);
            return;
        };
        let Some(socket) = self.punch_sockets.take(id) else {
            self.punch_failure = Some("promoted socket is gone".to_owned());
            self.finish_punch(now_ms);
            return;
        };
        let interface = socket.interface.clone();
        let outcome = self.transports.adopt(id, interface, socket.socket);
        match outcome {
            Ok(()) => {
                // The promoted socket is a real transport now, so discovery and
                // the engine must both learn about it. Deliberately not
                // `refresh_network`: re-enumerating interfaces here could retire
                // transports and cancel this very attempt mid-promotion.
                self.public.add_transport(
                    id.0,
                    self.resolved.config.stun_seeds.clone(),
                    self.monotonic_ms(),
                );
                self.sync_engine_transports();
                // Confirmations queued for this slot must still be sendable,
                // and they now live in the data plane rather than the pool.
                self.promoted_slot = Some((slot, id));
                self.promoted_transports.insert(
                    id,
                    now_ms.saturating_add(lzh_hole_protocol::engine::PATH_CONFIRM_TIMEOUT_MS),
                );
                self.punch_failure = None;
                // Every other punch socket is useless once one has won.
                self.punch_sockets.close_all();
            }
            Err(error) => {
                // Refuse honestly rather than evicting a working data socket.
                self.punch_failure = Some(format!("punch promotion refused: {error}"));
                self.finish_punch(now_ms);
            }
        }
    }

    /// Retain only an active winner or a transport with a selected session.
    /// Others have one bounded grace period to complete the ordinary handshake.
    fn reap_promoted_transports(&mut self, now_ms: u64) {
        let selected = self
            .engine
            .as_ref()
            .and_then(|engine| engine.snapshot(now_ms).selected_path)
            .map(|path| path.transport);
        let active = self.promoted_slot.map(|(_, id)| id);
        let mut expired = Vec::new();
        for (id, deadline) in &mut self.promoted_transports {
            if selected == Some(*id) || active == Some(*id) {
                *deadline =
                    now_ms.saturating_add(lzh_hole_protocol::engine::PATH_CONFIRM_TIMEOUT_MS);
            } else if now_ms >= *deadline {
                expired.push(*id);
            }
        }
        for id in expired {
            self.retire_transport(id);
        }
    }

    fn finish_punch(&mut self, now_ms: u64) {
        self.punch_sockets.close_all();
        if let Some(engine) = self.engine.as_mut() {
            engine.stop_punch();
        }
        self.punch_started_ms = None;
        self.punch_origin_transport = None;
        self.promoted_slot = None;
        self.refresh_public_request();
        self.punch_send_failures = 0;
        if self.punch_failure.is_some() {
            self.schedule_punch_retry(now_ms);
        } else {
            self.punch_backoff_ms = PUNCH_RETRY_MIN_MS;
            self.next_punch_attempt_ms = now_ms.saturating_add(PUNCH_RETRY_MIN_MS);
        }
    }

    /// Resolve slots by role: hard slot zero is not the easy data socket.
    fn punch_transport(&self, slot: u16) -> Option<TransportId> {
        let role = self.engine.as_ref()?.punch_state()?.role();
        match role {
            PunchRole::Easy => self.punch_origin_transport.filter(|_| slot == 0),
            PunchRole::Hard => self.punch_sockets.slot_id(slot).or_else(|| {
                self.promoted_slot
                    .filter(|(winner, _)| *winner == slot)
                    .map(|(_, id)| id)
            }),
        }
    }

    /// Send queued punch frames, rate limited by this module's own bucket.
    pub(super) async fn drain_punch(&mut self, now_ms: u64) {
        if !self.punch_sockets.is_active() {
            // The easy side scans from its ordinary data socket, so frames can
            // still be queued with no punch sockets open at all.
            let has_frames = self
                .engine
                .as_ref()
                .and_then(|engine| engine.punch_state())
                .is_some();
            if !has_frames {
                return;
            }
        }
        let available = self.punch_bucket.refill(self.monotonic_ms());
        if available == 0 {
            return;
        }
        let mut budget = available;
        while budget > 0 {
            let frame = match self.engine.as_mut() {
                Some(engine) => engine.next_punch_frame(),
                None => None,
            };
            let Some(frame) = frame else {
                break;
            };
            self.punch_bucket.take(1);
            let target = SocketAddrV4::new(frame.target.ip, frame.target.port);
            let socket = self.punch_transport(frame.slot).and_then(|id| {
                self.punch_sockets
                    .get(id)
                    .map(|socket| &socket.socket)
                    .or_else(|| self.transports.get(id).map(|socket| &socket.socket))
            });
            let sent = socket.is_some_and(|socket| matches!(socket.try_send_to(&frame.bytes, target), Ok(size) if size == frame.bytes.len()));
            if sent {
                self.bytes.udp_tx = self.bytes.udp_tx.saturating_add(frame.bytes.len() as u64);
                self.punch_send_failures = 0;
            } else {
                // A single per-destination failure is not evidence that any
                // socket disappeared, exactly as on the data plane. A run of
                // them is: the frame was already consumed from the outbox, so
                // continuing would walk the grid with nothing on the wire.
                self.record_drop("punch_send_failed", 1);
                self.punch_send_failures = self.punch_send_failures.saturating_add(1);
                if self.punch_send_failures >= PUNCH_MAX_SEND_FAILURES {
                    self.punch_failure = Some("punch send failures".to_owned());
                    self.finish_punch(now_ms);
                    return;
                }
            }
            budget -= 1;
        }
    }

    /// A doctor view of the punch subsystem. Observations only.
    pub(super) fn punch_status(&self) -> PunchStatus {
        let state = self
            .engine
            .as_ref()
            .and_then(|engine| engine.punch_state())
            .map(|state| state.phase().as_str().to_owned())
            .unwrap_or_else(|| "idle".to_owned());
        let role = self
            .engine
            .as_ref()
            .and_then(|engine| engine.punch_state())
            .map(|state| state.role().as_str().to_owned());
        let probes_sent = self
            .engine
            .as_ref()
            .and_then(|engine| engine.punch_state())
            .map(|state| state.probes_sent())
            .unwrap_or(0);
        PunchStatus {
            state,
            role,
            local_mapping: self.local_mapping().as_str().to_owned(),
            peer_mapping: self.peer_mapping().as_str().to_owned(),
            blocked_by: self.punch_block.map(|block| block.as_str().to_owned()),
            last_failure: self.punch_failure.clone(),
            probes_sent,
            sockets_open: self.punch_sockets.len() as u16,
            hit_port: self.punch_hit_port,
            started_unix_ms: self.punch_started_ms,
        }
    }

    /// Abandon any punch attempt and release its sockets.
    pub(super) fn stop_punch(&mut self, now_ms: u64) {
        let active = self.punch_sockets.is_active()
            || self.promoted_slot.is_some()
            || self
                .engine
                .as_ref()
                .is_some_and(|engine| engine.punch_active());
        if !active {
            return;
        }
        // Tearing down after a socket was already promoted is not a failed
        // punch: the path was found, the attempt is simply being closed out.
        if self.promoted_slot.is_none() {
            self.punch_failure = Some("cancelled".to_owned());
        }
        self.finish_punch(now_ms);
    }
}
#[cfg(test)]
#[path = "punch/network_tests.rs"]
mod network_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn punch_descriptor_budget_respects_the_hard_limit_and_never_lowers_a_limit() {
        let launchd = libc::rlimit {
            rlim_cur: 256,
            rlim_max: 1_024,
        };
        assert_eq!(punch_soft_limit(PUNCH_HARD_SOCKETS, &launchd).unwrap(), 512);
        assert_eq!(punch_soft_limit(8, &launchd).unwrap(), 256);
        let capped = libc::rlimit {
            rlim_cur: 256,
            rlim_max: 256,
        };
        assert!(punch_soft_limit(PUNCH_HARD_SOCKETS, &capped).is_err());
        let higher = libc::rlimit {
            rlim_cur: 4_096,
            rlim_max: 8_192,
        };
        assert_eq!(
            punch_soft_limit(PUNCH_HARD_SOCKETS, &higher).unwrap(),
            4_096
        );
    }

    #[test]
    fn the_token_bucket_refills_by_elapsed_time_and_caps_at_the_burst() {
        let mut bucket = TokenBucket::new(400, 100, 1_000);
        // A fresh bucket starts full.
        assert_eq!(bucket.refill(1_000), 100);
        assert_eq!(bucket.take(100), 100);
        assert_eq!(
            bucket.refill(1_000),
            0,
            "an empty bucket grants nothing at once"
        );
        // 400 per second means 40 in 100 ms.
        assert_eq!(bucket.refill(1_100), 40);
        assert_eq!(
            bucket.take(1_000),
            40,
            "take never exceeds what is available"
        );
        // A long idle period still cannot exceed the burst.
        assert_eq!(bucket.refill(60_000), 100, "refill is capped at the burst");
    }

    #[test]
    fn a_backwards_clock_never_mints_tokens() {
        let mut bucket = TokenBucket::new(400, 100, 5_000);
        assert_eq!(bucket.refill(5_000), 100);
        assert_eq!(bucket.take(100), 100);
        // A timestamp that moved backwards must grant nothing: elapsed time is
        // clamped at zero rather than wrapping into a huge refill.
        assert_eq!(bucket.refill(1_000), 0);
        assert_eq!(bucket.refill(999), 0);
        // Once the clock moves forward again, normal accrual resumes.
        assert_eq!(
            bucket.refill(1_099),
            0,
            "time below the high-water clock grants no credit"
        );
        assert_eq!(bucket.refill(5_100), 40);
    }

    #[test]
    fn frequent_events_preserve_fractional_token_credit() {
        let mut bucket = TokenBucket::new(400, 100, 0);
        bucket.take(100);
        let mut sent = 0;
        for now in 1..=1_000 {
            bucket.refill(now);
            sent += bucket.take(1);
        }
        assert_eq!(sent, 400);
        let mut slow = TokenBucket::new(1, 100, 0);
        slow.take(100);
        for now in 1..1_000 {
            assert_eq!(slow.refill(now), 0);
        }
        assert_eq!(slow.refill(1_000), 1);
    }

    #[test]
    fn the_bucket_rate_is_never_zero() {
        // A misconfigured rate must not wedge the feature silently.
        let mut bucket = TokenBucket::new(0, 0, 0);
        assert!(bucket.refill(1_000) >= 1);
    }

    #[test]
    fn a_closed_punch_pool_reports_itself_inactive_and_bound() {
        let sockets = PunchSockets::default();
        assert!(!sockets.is_active());
        assert_eq!(sockets.len(), 0);
        assert_eq!(sockets.address(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(sockets.slot_id(0), None);
        assert!(sockets.get(TransportId(1)).is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn opening_punch_sockets_gives_each_slot_its_own_identifier() {
        let mut ids = TransportIds::default();
        let mut sockets = PunchSockets::default();
        sockets
            .open(&mut ids, "lo0", Ipv4Addr::LOCALHOST, 8)
            .expect("open");
        assert!(sockets.is_active());
        assert_eq!(sockets.len(), 8);
        let mut seen = std::collections::BTreeSet::new();
        for slot in 0..8u16 {
            let id = sockets.slot_id(slot).expect("slot is occupied");
            assert_ne!(id, TransportId(0), "identifier zero is reserved");
            assert!(seen.insert(id), "slot {slot} reused an identifier");
        }
        assert_eq!(seen.len(), 8);
        // Re-opening while sockets exist is refused rather than leaking.
        assert!(
            sockets
                .open(&mut ids, "lo0", Ipv4Addr::LOCALHOST, 8)
                .is_err()
        );
        // Taking one socket frees exactly that slot.
        let id = sockets.slot_id(3).unwrap();
        let taken = sockets.take(id).expect("take");
        assert_eq!(taken.slot, 3);
        assert_eq!(sockets.len(), 7);
        assert_eq!(sockets.slot_id(3), None);
        // Closing releases everything and is safe to repeat.
        sockets.close_all();
        sockets.close_all();
        assert!(!sockets.is_active());
        assert_eq!(sockets.len(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn punch_sockets_carry_traffic_between_slots() {
        let mut ids = TransportIds::default();
        let mut sockets = PunchSockets::default();
        sockets
            .open(&mut ids, "lo0", Ipv4Addr::LOCALHOST, 2)
            .expect("open");
        let first = sockets.slot_id(0).unwrap();
        let second = sockets.slot_id(1).unwrap();
        let target = sockets.get(second).unwrap().socket.get_ref().local_addr();
        sockets
            .get(first)
            .unwrap()
            .socket
            .send_to(b"punch", target)
            .await
            .unwrap();
        let datagram = tokio::time::timeout(std::time::Duration::from_secs(2), sockets.recv())
            .await
            .expect("a datagram arrives");
        assert_eq!(datagram.id, second);
        assert_eq!(datagram.slot, 1);
        assert_eq!(datagram.buffer, b"punch");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_failed_open_leaves_no_sockets_behind() {
        let mut ids = TransportIds::default();
        let mut sockets = PunchSockets::default();
        assert!(
            sockets
                .open(&mut ids, "not-an-interface", Ipv4Addr::LOCALHOST, 8)
                .is_err()
        );
        assert!(
            !sockets.is_active(),
            "a failed open must not retain sockets"
        );
        assert_eq!(sockets.len(), 0);
        // And the pool is immediately reusable.
        assert!(
            sockets
                .open(&mut ids, "lo0", Ipv4Addr::LOCALHOST, 2)
                .is_ok()
        );
        assert_eq!(sockets.len(), 2);
    }

    fn test_engine(daemon: &mut Daemon) {
        daemon.engine = Some(
            lifecycle::make_engine(
                &daemon.resolved,
                &Secret32::from_bytes([0x5a; 32]),
                daemon.boot_id,
                daemon.generation,
            )
            .unwrap(),
        );
    }

    fn start_test_punch(daemon: &mut Daemon, role: PunchRole, now: u64) {
        assert!(daemon.engine.as_mut().unwrap().start_punch(
            PunchConfig {
                role,
                peer_endpoint: endpoint("210.22.105.194:51000".parse().unwrap()),
                local_key: daemon.resolved.relationship.self_public_key,
                peer_key: daemon.resolved.relationship.peer_public_key,
                relationship_id: daemon.resolved.relationship.relationship_id,
                boot_id: daemon.boot_id,
                generation: daemon.generation,
                direction: if daemon.resolved.relationship.self_public_key
                    < daemon.resolved.relationship.peer_public_key
                {
                    lzh_hole_protocol::Direction::LoToHi
                } else {
                    lzh_hole_protocol::Direction::HiToLo
                },
                hard_sockets: PUNCH_HARD_SOCKETS as u16,
            },
            now
        ));
        daemon.punch_started_ms = Some(now);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hard_slot_zero_keeps_its_socket_through_promotion_and_is_reclaimed() {
        let (_temp, mut daemon) = super::super::tests::offline_daemon();
        test_engine(&mut daemon);
        let data = daemon
            .transports
            .open(&mut daemon.transport_ids, "lo0", Ipv4Addr::LOCALHOST, 0)
            .unwrap();
        daemon.punch_origin_transport = Some(data);
        for attempt in 0..16u64 {
            let now = 1_800_000_000_000 + attempt * 60_000;
            daemon
                .punch_sockets
                .open(&mut daemon.transport_ids, "lo0", Ipv4Addr::LOCALHOST, 1)
                .unwrap();
            start_test_punch(&mut daemon, PunchRole::Hard, now);
            let winner = daemon.punch_sockets.slot_id(0).unwrap();
            assert_ne!(winner, data);
            assert_eq!(daemon.punch_transport(0), Some(winner));
            daemon.promote_punch_slot(0, now);
            assert_eq!(daemon.punch_transport(0), Some(winner));
            assert!(daemon.transports.get(winner).is_some());
            daemon.finish_punch(now);
            daemon.reap_promoted_transports(
                now + lzh_hole_protocol::engine::PATH_CONFIRM_TIMEOUT_MS - 1,
            );
            assert!(
                daemon.transports.get(winner).is_some(),
                "handshake grace is retained"
            );
            daemon
                .reap_promoted_transports(now + lzh_hole_protocol::engine::PATH_CONFIRM_TIMEOUT_MS);
            assert!(daemon.transports.get(winner).is_none());
            assert_eq!(daemon.transports.iter().count(), 1);
            assert!(daemon.promoted_transports.is_empty());
        }
        start_test_punch(&mut daemon, PunchRole::Easy, 1_800_001_000_000);
        daemon.punch_origin_transport = Some(data);
        assert_eq!(daemon.punch_transport(0), Some(data));
        assert_eq!(daemon.punch_transport(1), None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn an_easy_side_waits_for_a_live_offer_without_burning_retry_backoff() {
        use lzh_hole_discovery::stun::{ATTR_MAPPED_ADDRESS, MAGIC_COOKIE, MSG_BINDING_SUCCESS};
        let (_temp, mut daemon) = super::super::tests::offline_daemon();
        test_engine(&mut daemon);
        let data = daemon
            .transports
            .open(&mut daemon.transport_ids, "lo0", Ipv4Addr::LOCALHOST, 0)
            .unwrap();
        let servers = vec![
            "8.8.8.8:3478".parse().unwrap(),
            "8.8.4.4:3478".parse().unwrap(),
        ];
        daemon.public.add_transport(data.0, servers.clone(), 0);
        for (index, server) in servers.iter().enumerate() {
            let transaction = [index as u8 + 1; 12];
            let now = index as u64 * 5_001;
            daemon
                .public
                .start_stun(data.0, transaction, now)
                .unwrap()
                .unwrap();
            let mut reply = Vec::new();
            reply.extend_from_slice(&MSG_BINDING_SUCCESS.to_be_bytes());
            reply.extend_from_slice(&12u16.to_be_bytes());
            reply.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
            reply.extend_from_slice(&transaction);
            reply.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
            reply.extend_from_slice(&8u16.to_be_bytes());
            reply.extend_from_slice(&[0, 1]);
            reply.extend_from_slice(&51_000u16.to_be_bytes());
            reply.extend_from_slice(&[210, 22, 105, 195]);
            daemon
                .public
                .receive_stun(data.0, *server, &reply, now + 1)
                .unwrap();
        }
        daemon.sync_engine_transports();
        daemon.paths = vec![PathCandidate {
            path: lzh_hole_protocol::path::PathEndpoint {
                transport: data,
                remote: endpoint("210.22.105.194:51000".parse().unwrap()),
            },
            kind: PathKind::Public,
        }];
        daemon.peer_record_flags = lzh_hole_discovery::record::FLAG_MAPPING_EDM;
        let now = 1_800_000_000_000;
        daemon.peer_record_expires_ms = now + 180_000;
        for offset in 0..10 {
            daemon.maybe_start_punch(now + offset);
        }
        assert_eq!(daemon.punch_block, Some(PunchBlock::WaitingForOffer));
        assert_eq!(daemon.next_punch_attempt_ms, 0);
        daemon.peer_record_flags |= lzh_hole_discovery::record::FLAG_PUNCH_OFFER;
        daemon.peer_record_expires_ms = now + PUNCH_DEADLINE_MS;
        daemon.maybe_start_punch(now);
        assert!(
            !daemon.engine.as_ref().unwrap().punch_active(),
            "expired or nearly closed windows are not scanned"
        );
        daemon.peer_record_expires_ms = now + 180_000;
        daemon.maybe_start_punch(now);
        assert_eq!(
            daemon
                .engine
                .as_ref()
                .unwrap()
                .punch_state()
                .unwrap()
                .role(),
            PunchRole::Easy
        );
        assert_eq!(daemon.punch_transport(0), Some(data));
    }

    #[test]
    fn punch_block_reasons_are_stable_snake_case() {
        for block in [
            PunchBlock::BothHard,
            PunchBlock::MappingUnknown,
            PunchBlock::NoPublicCandidate,
            PunchBlock::NoClassifiedTransport,
            PunchBlock::Disabled,
            PunchBlock::BackingOff,
            PunchBlock::NtfyBlocked,
            PunchBlock::HealthyPath,
            PunchBlock::WaitingForOffer,
        ] {
            let name = block.as_str();
            assert!(!name.is_empty());
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{name}"
            );
        }
    }
}
