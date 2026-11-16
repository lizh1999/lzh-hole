//! Bounded punch socket pool, rate-limited drain and trigger policy.
//!
//! Everything here is deliberately separate from the data plane. Punch sockets
//! live in their own pool with ephemeral ports, punch frames drain through
//! their own token bucket, and the engine's data outbox and probe budget are
//! never touched. The only moment the two worlds meet is promotion: the socket
//! that actually completed a punch joins the ordinary transport set, keeping
//! the identifier it already had.
//!
//! # One attempt for the whole mesh
//!
//! Punch sockets are a node-level descriptor budget, and a scan is only
//! meaningful against one peer's NAT at a time. Running two scans at once would
//! spend twice the descriptors to learn nothing extra, and would let one
//! relationship's role decision be perturbed by another's traffic. So:
//!
//! * the socket pool stays node-level, but every slot remembers which
//!   relationship opened it;
//! * Daemon::punch holds at most one PunchAttempt;
//! * every other relationship that also wants a punch queues, and
//!   Daemon::peer_punch_status says so instead of claiming an attempt;
//! * backoff, last failure and decline reason are per relationship
//!   (PunchPeerState), so one relationship losing repeatedly never delays
//!   another.
//!
//! Nothing is pooled across relationships beyond the socket budget itself: a
//! candidate only ever comes from that relationship's own projected paths, and
//! every inbound datagram, frame and event is routed to the engine that owns
//! the relationship it belongs to.

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
use lzh_hole_types::{RelationshipId, TransportId};

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

/// One transient punch socket, permanently attributed to one relationship.
pub(super) struct PunchSocket {
    pub id: TransportId,
    pub slot: u16,
    /// The relationship that opened this slot. A datagram read from this socket
    /// may only ever be handed to this relationship's engine.
    pub relationship: RelationshipId,
    pub interface: String,
    pub socket: AsyncPhysicalSocket,
}

pub(super) struct PunchDatagram {
    pub id: TransportId,
    pub slot: u16,
    /// Carried from the socket itself rather than re-derived, so the routing
    /// decision cannot drift between the read and the dispatch.
    pub relationship: RelationshipId,
    pub result: io::Result<(usize, RecvMeta)>,
    pub buffer: Vec<u8>,
}

/// Transient sockets used only to emit punch frames.
///
/// Bounded by construction: open refuses to exceed the configured count, and
/// every exit path -- success, failure, topology change, daemon shutdown --
/// goes through close_all.
///
/// The pool is node-level, but it is never anonymous: every socket records the
/// relationship that opened it, and PunchSockets::relationship reports the
/// single owner of the currently open window.
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
            .field("relationship", &self.relationship())
            .finish()
    }
}

impl PunchSockets {
    /// Open count sockets on one interface and address, for one relationship.
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
        relationship: RelationshipId,
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
                    relationship,
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

    /// The relationship every currently open slot belongs to.
    ///
    /// Only one attempt runs at a time, so an open pool has exactly one owner.
    pub fn relationship(&self) -> Option<RelationshipId> {
        self.sockets
            .values()
            .next()
            .map(|socket| socket.relationship)
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
                        relationship: punch.relationship,
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

    /// Spend up to wanted tokens, returning how many were granted.
    pub fn take(&mut self, wanted: u32) -> u32 {
        let granted = wanted.min(self.tokens);
        self.tokens -= granted;
        granted
    }
}

/// One running hole-punch attempt, attributed to exactly one relationship.
#[derive(Debug)]
pub(super) struct PunchAttempt {
    pub relationship: RelationshipId,
    /// The socket the role decision was based on, pinned for the whole
    /// attempt so the scan cannot drift onto a differently-behaving socket.
    pub origin_transport: Option<TransportId>,
    pub started_ms: u64,
    pub hit_port: Option<u16>,
}

/// Per-relationship punch bookkeeping that must survive between attempts.
///
/// Kept beside the peers in Daemon::punch_states, so removing a relationship
/// removes its backoff, its last failure and its queue reason with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PunchPeerState {
    pub backoff_ms: u64,
    pub next_attempt_ms: u64,
    /// Why the last attempt for this relationship ended without a path.
    pub failure: Option<String>,
    /// Why no attempt is running for this relationship right now.
    pub declined: Option<String>,
}

impl Default for PunchPeerState {
    fn default() -> Self {
        Self {
            backoff_ms: PUNCH_RETRY_MIN_MS,
            next_attempt_ms: 0,
            failure: None,
            declined: None,
        }
    }
}

/// Per-relationship punch bookkeeping, kept beside the peers so removing a
/// relationship removes its backoff too.
pub(super) fn punch_state(
    states: &mut BTreeMap<RelationshipId, PunchPeerState>,
    relationship: RelationshipId,
) -> &mut PunchPeerState {
    states.entry(relationship).or_default()
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
    /// Another relationship holds the single node-level punch window, so this
    /// one is queued. Never a claim that an attempt is running for it.
    Queued,
    /// This relationship's engine or peer runtime is absent, so no punch can be
    /// routed to it at all.
    Unavailable,
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
            PunchBlock::Queued => "queued",
            PunchBlock::Unavailable => "unavailable",
        }
    }
}

/// Everything needed to start one attempt, derived without mutating anything.
#[derive(Debug, Clone)]
struct PunchPlan {
    role: PunchRole,
    origin_transport: TransportId,
    interface: String,
    address: Ipv4Addr,
    /// Always this relationship's own projected public candidate.
    target: Endpoint,
}

/// A read-only view of one relationship's punch state machine.
#[derive(Debug, Clone)]
struct PunchView {
    state: String,
    role: Option<String>,
    probes_sent: u64,
}

impl Daemon {
    /// Whether a punch window is currently open.
    ///
    /// Test-only: production reads punch_offer_relationship, which answers the
    /// same question and also says whose window it is.
    #[cfg(test)]
    pub(super) fn punch_offer_active(&self) -> bool {
        self.punch_sockets.is_active()
    }

    /// The one relationship whose punch window is open, if any.
    ///
    /// A window only exists while hard-side sockets are actually open, so an
    /// easy-side scan never advertises an address with nothing behind it.
    pub(super) fn punch_offer_relationship(&self) -> Option<RelationshipId> {
        self.punch_sockets.relationship()
    }

    /// Signed-record expiry cap for one relationship: Some(deadline) only
    /// while that relationship's own punch window is open, None otherwise.
    pub(super) fn punch_offer_deadline_for(&self, relationship: RelationshipId) -> Option<u64> {
        if self.punch_offer_relationship() != Some(relationship) {
            return None;
        }
        self.punch
            .as_ref()
            .filter(|attempt| attempt.relationship == relationship)
            .map(|attempt| attempt.started_ms.saturating_add(PUNCH_HARD_DEADLINE_MS))
    }

    /// This host's own mapping behaviour, reduced across every retained socket.
    pub(super) fn local_mapping(&self) -> MappingBehavior {
        lzh_hole_discovery::aggregate_mapping(
            self.public
                .mapping_behaviors()
                .into_iter()
                .map(|(_, profile)| profile.mapping),
        )
    }

    /// One peer's mapping behaviour, from that relationship's last accepted record.
    ///
    /// Only that relationship's own peer_record_flags is read. Another
    /// relationship's flags must never influence this one's role decision.
    pub(super) fn peer_mapping(&self, relationship: RelationshipId) -> MappingBehavior {
        self.peers
            .get(&relationship)
            .map(|peer| MappingBehavior::from_record_flags(peer.peer_record_flags))
            .unwrap_or(MappingBehavior::Unknown)
    }

    /// Coordination flags to publish with one relationship's next record.
    ///
    /// The mapping verdict is this host's own measurement. The punch offer bit
    /// is set only while THIS relationship's punch window is actually open,
    /// so a peer never scans an address that has no sockets behind it and one
    /// relationship's offer never leaks into another relationship's record.
    pub(super) fn record_flags_for(&self, relationship: RelationshipId) -> u8 {
        let mut flags = self.local_mapping().record_flags();
        if self.punch_offer_relationship() == Some(relationship) {
            flags |= lzh_hole_discovery::record::FLAG_PUNCH_OFFER;
        }
        flags
    }

    /// Consider every relationship and start at most one attempt.
    ///
    /// This never runs while a path is healthy, which is what keeps a working
    /// tunnel completely undisturbed, and it never runs a second attempt beside
    /// a live one.
    ///
    /// Selection is fair without a cursor: the startable relationship whose own
    /// next_attempt_ms is earliest wins, and finishing an attempt always pushes
    /// that relationship's own schedule into the future. A relationship
    /// therefore cannot monopolise the window.
    pub(super) fn maybe_start_punch(&mut self, now_ms: u64) {
        self.reap_promoted_transports(now_ms);
        let order = self.peer_order.clone();

        // Phase one: evaluate every relationship without mutating anything.
        let mut plans: Vec<(RelationshipId, Result<PunchPlan, PunchBlock>)> =
            Vec::with_capacity(order.len());
        for relationship in &order {
            plans.push((*relationship, self.punch_plan(*relationship, now_ms)));
        }

        let running = self.punch.as_ref().map(|attempt| attempt.relationship);

        // Phase two: pick at most one relationship to actually start.
        let mut chosen: Option<(RelationshipId, PunchPlan)> = None;
        if running.is_none() {
            for (relationship, plan) in &plans {
                let Ok(plan) = plan else { continue };
                let due = self.next_attempt_ms(*relationship);
                let better = match &chosen {
                    None => true,
                    Some((best, _)) => (due, *relationship) < (self.next_attempt_ms(*best), *best),
                };
                if better {
                    chosen = Some((*relationship, plan.clone()));
                }
            }
        }

        // Phase three: record why every relationship is or is not punching.
        for (relationship, plan) in &plans {
            let declined = if running == Some(*relationship) {
                None
            } else if let Err(block) = plan {
                Some(block.as_str().to_owned())
            } else if let Some(holder) = running {
                Some(format!(
                    "{}: relationship {} holds the single punch window",
                    PunchBlock::Queued.as_str(),
                    holder.to_hex()
                ))
            } else if let Some((winner, _)) = &chosen
                && winner != relationship
            {
                Some(format!(
                    "{}: relationship {} was selected for this round",
                    PunchBlock::Queued.as_str(),
                    winner.to_hex()
                ))
            } else {
                None
            };
            punch_state(&mut self.punch_states, *relationship).declined = declined;
        }

        let Some((relationship, plan)) = chosen else {
            return;
        };
        self.start_punch_for(relationship, plan, now_ms);
    }

    fn next_attempt_ms(&self, relationship: RelationshipId) -> u64 {
        self.punch_states
            .get(&relationship)
            .map_or(0, |state| state.next_attempt_ms)
    }

    /// Everything a punch needs, from this relationship's own state only.
    ///
    /// Pure: it reads the node-level socket and mapping facts plus exactly one
    /// relationship's engine, peer flags and projected paths.
    fn punch_plan(
        &self,
        relationship: RelationshipId,
        now_ms: u64,
    ) -> Result<PunchPlan, PunchBlock> {
        if !self.resolved.config.punch.enabled {
            return Err(PunchBlock::Disabled);
        }
        let Some(peer) = self.peers.get(&relationship) else {
            return Err(PunchBlock::Unavailable);
        };
        let Some(engine) = self.engines.as_ref().and_then(|set| set.get(relationship)) else {
            return Err(PunchBlock::Unavailable);
        };
        // A punch must never preempt a working path; the engine enforces this
        // too, and this is the honest reason to report.
        let snapshot = engine.snapshot(now_ms);
        if snapshot.session_id.is_some() || snapshot.selected_path.is_some() {
            return Err(PunchBlock::HealthyPath);
        }
        if peer.ntfy.waiting() {
            return Err(PunchBlock::NtfyBlocked);
        }
        if now_ms < self.next_attempt_ms(relationship) {
            return Err(PunchBlock::BackingOff);
        }

        let local = self.local_mapping();
        // Only this relationship's own published flags decide the role.
        let remote = self.peer_mapping(relationship);
        let role = match (local, remote) {
            (MappingBehavior::EndpointDependent, MappingBehavior::EndpointIndependent) => {
                PunchRole::Hard
            }
            (MappingBehavior::EndpointIndependent, MappingBehavior::EndpointDependent) => {
                PunchRole::Easy
            }
            (MappingBehavior::EndpointDependent, MappingBehavior::EndpointDependent) => {
                return Err(PunchBlock::BothHard);
            }
            _ => return Err(PunchBlock::MappingUnknown),
        };

        if role == PunchRole::Easy
            && (peer.peer_record_flags & lzh_hole_discovery::record::FLAG_PUNCH_OFFER == 0
                || peer.peer_record_expires_ms <= now_ms.saturating_add(PUNCH_DEADLINE_MS))
        {
            return Err(PunchBlock::WaitingForOffer);
        }

        // Punch from a socket whose mapping behaviour is actually known, and
        // whose address is the one that produced a public mapping.
        let Some((origin_transport, interface, address)) = self.punch_origin(local) else {
            return Err(PunchBlock::NoClassifiedTransport);
        };

        // INVARIANT: a punch target may only ever come from this relationship's
        // own projected path set. Another relationship's candidates are not
        // reachable from here, and an absent set is a refusal, not a fallback.
        let Some(target) = self.paths.get(&relationship).and_then(|paths| {
            paths
                .iter()
                .find(|candidate| {
                    candidate.kind == PathKind::Public
                        && candidate.path.transport == origin_transport
                })
                .map(|candidate| candidate.path.remote)
        }) else {
            return Err(PunchBlock::NoPublicCandidate);
        };

        Ok(PunchPlan {
            role,
            origin_transport,
            interface,
            address,
            target,
        })
    }

    fn start_punch_for(&mut self, relationship: RelationshipId, plan: PunchPlan, now_ms: u64) {
        // The hard-side socket count is a protocol constant, not a tunable.
        // The easy side's grid step is fixed too, and a block narrower than
        // twice that step can be stepped straight over, so the two must move
        // together. Exposing one without the other would let an operator
        // silently disable punching.
        let hard_sockets = PUNCH_HARD_SOCKETS;
        if plan.role == PunchRole::Hard
            && let Err(error) = self.punch_sockets.open(
                &mut self.transport_ids,
                relationship,
                &plan.interface,
                plan.address,
                hard_sockets,
            )
        {
            self.note_punch_failure(relationship, format!("punch sockets: {error}"));
            self.schedule_punch_retry(relationship, now_ms);
            return;
        }

        let Some(peer) = self.peers.get(&relationship) else {
            self.punch_sockets.close_all();
            return;
        };
        let direction = if peer.relationship.self_public_key < peer.relationship.peer_public_key {
            lzh_hole_protocol::wire::Direction::LoToHi
        } else {
            lzh_hole_protocol::wire::Direction::HiToLo
        };
        let config = PunchConfig {
            role: plan.role,
            peer_endpoint: plan.target,
            local_key: peer.relationship.self_public_key,
            peer_key: peer.relationship.peer_public_key,
            relationship_id: relationship,
            boot_id: self.boot_id,
            generation: self.generation,
            direction,
            hard_sockets: hard_sockets as u16,
        };

        // The engine that owns the relationship is the only authority that may
        // admit a punch target, and start_punch still applies the full target
        // policy. This is never bypassed.
        let started = self
            .engines
            .as_mut()
            .and_then(|set| set.get_mut(relationship))
            .is_some_and(|engine| engine.start_punch(config, now_ms));
        if !started {
            self.punch_sockets.close_all();
            self.note_punch_failure(relationship, "engine refused the punch target".to_owned());
            self.schedule_punch_retry(relationship, now_ms);
            return;
        }

        self.punch_bucket = TokenBucket::new(
            self.resolved.config.punch.rate_per_second(),
            PUNCH_BURST,
            self.monotonic_ms(),
        );
        {
            let state = punch_state(&mut self.punch_states, relationship);
            state.failure = None;
            state.declined = None;
        }
        self.punch = Some(PunchAttempt {
            relationship,
            // Pin the socket the role decision was based on. Re-deriving it per
            // drain from the candidate projection would let the scan drift onto
            // a socket whose mapping behaviour is not the one that was classified.
            origin_transport: Some(plan.origin_transport),
            started_ms: now_ms,
            hit_port: None,
        });
        self.punch_send_failures = 0;
        self.refresh_public_requests();
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

    fn note_punch_failure(&mut self, relationship: RelationshipId, reason: String) {
        punch_state(&mut self.punch_states, relationship).failure = Some(reason);
    }

    fn schedule_punch_retry(&mut self, relationship: RelationshipId, now_ms: u64) {
        let state = punch_state(&mut self.punch_states, relationship);
        let next = state
            .backoff_ms
            .clamp(PUNCH_RETRY_MIN_MS, PUNCH_RETRY_MAX_MS);
        state.next_attempt_ms = now_ms.saturating_add(next);
        state.backoff_ms = next.saturating_mul(2).min(PUNCH_RETRY_MAX_MS);
    }

    /// Advance the punch state machine and act on its events.
    pub(super) fn drive_punch(&mut self, now_ms: u64) {
        let Some(relationship) = self.punch.as_ref().map(|attempt| attempt.relationship) else {
            // Nothing is running. Drain and account for anything an engine
            // still holds rather than letting it accumulate.
            let stray = self
                .engines
                .as_mut()
                .map(|set| set.take_punch_events())
                .unwrap_or_default();
            if !stray.is_empty() {
                self.record_drop("punch_event_without_attempt", stray.len() as u64);
            }
            return;
        };
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
        if let Some(engine) = self
            .engines
            .as_mut()
            .and_then(|set| set.get_mut(relationship))
        {
            engine.punch_tick(now_ms, &mut nonce_source);
        }
        if rng_failed.get() {
            self.note_punch_failure(relationship, "randomness unavailable".to_owned());
            self.finish_punch(now_ms);
            return;
        }
        let events = self
            .engines
            .as_mut()
            .map(|set| set.take_punch_events())
            .unwrap_or_default();
        self.apply_punch_events(relationship, events, now_ms);
        self.poll_punch_completion(relationship, now_ms);
    }

    /// Feed one datagram that arrived on a punch socket into its own engine.
    ///
    /// Routing is by the slot's recorded relationship, and the datagram is only
    /// delivered while that exact relationship's attempt is the running one. A
    /// late datagram for a finished attempt is dropped and counted; it is never
    /// handed to an arbitrary engine.
    pub(super) fn handle_punch_udp(&mut self, event: PunchDatagram, now_ms: u64) {
        let owner = event.relationship;
        let running = self.punch.as_ref().map(|attempt| attempt.relationship);
        if running != Some(owner) {
            self.record_drop("punch_datagram_not_owned", 1);
            return;
        }
        let (size, metadata) = match event.result {
            Ok(value) => value,
            Err(error) => {
                self.record_drop("punch_recv_failed", 1);
                self.note_punch_failure(owner, format!("punch receive failed: {error}"));
                // A failing punch socket is not evidence about the data plane,
                // so only that one socket is dropped.
                self.punch_sockets.take(event.id);
                return;
            }
        };
        let Some(socket) = self.punch_sockets.get(event.id) else {
            self.record_drop("punch_socket_gone", 1);
            return;
        };
        if socket.relationship != owner {
            self.record_drop("punch_socket_wrong_relationship", 1);
            return;
        }
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
        if let Some(engine) = self.engines.as_mut().and_then(|set| set.get_mut(owner)) {
            engine.handle_punch_datagram(event.slot, event.id, remote, &datagram, now_ms);
        }
        // Node-level and per-relationship accounting, exactly as the data plane
        // attributes its own bytes.
        self.bytes.udp_rx = self.bytes.udp_rx.saturating_add(size as u64);
        if let Some(peer) = self.peers.get_mut(&owner) {
            peer.bytes.udp_rx = peer.bytes.udp_rx.saturating_add(size as u64);
        }
        let events = self
            .engines
            .as_mut()
            .map(|set| set.take_punch_events())
            .unwrap_or_default();
        self.apply_punch_events(owner, events, now_ms);
    }

    /// Apply punch events, each to the relationship that produced it.
    fn apply_punch_events(
        &mut self,
        owner: RelationshipId,
        events: Vec<(RelationshipId, PunchEvent)>,
        now_ms: u64,
    ) {
        for (relationship, event) in events {
            if relationship != owner {
                // One relationship's hit must never finish or advance another's.
                self.record_drop("punch_event_wrong_relationship", 1);
                continue;
            }
            if self.punch.as_ref().map(|attempt| attempt.relationship) != Some(owner) {
                self.record_drop("punch_event_without_attempt", 1);
                continue;
            }
            match event {
                PunchEvent::Promote { slot, peer } => {
                    if let Some(attempt) = self
                        .punch
                        .as_mut()
                        .filter(|attempt| attempt.relationship == owner)
                    {
                        attempt.hit_port = Some(peer.port);
                    }
                    self.promote_punch_slot(owner, slot, now_ms);
                }
                PunchEvent::Learned { peer } => {
                    if let Some(attempt) = self
                        .punch
                        .as_mut()
                        .filter(|attempt| attempt.relationship == owner)
                    {
                        attempt.hit_port = Some(peer.port);
                    }
                    // The learned endpoint is now an ordinary candidate and the
                    // engine's challenge flow takes it from here. The attempt
                    // itself stays alive until its confirmations have drained.
                }
                PunchEvent::Failed(failure) => {
                    self.note_punch_failure(owner, failure.as_str().to_owned());
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
    fn poll_punch_completion(&mut self, relationship: RelationshipId, now_ms: u64) {
        let outcome = self
            .engines
            .as_ref()
            .and_then(|set| set.get(relationship))
            .and_then(|engine| engine.punch_state())
            .map(|state| {
                (
                    state.phase(),
                    state.failure().map(|failure| failure.as_str().to_owned()),
                )
            });
        let Some((phase, failure)) = outcome else {
            return;
        };
        match phase {
            lzh_hole_protocol::punch::PunchPhase::Done => self.finish_punch(now_ms),
            lzh_hole_protocol::punch::PunchPhase::Failed => {
                if self
                    .punch_states
                    .get(&relationship)
                    .and_then(|state| state.failure.as_ref())
                    .is_none()
                {
                    self.note_punch_failure(
                        relationship,
                        failure.unwrap_or_else(|| "punch failed".to_owned()),
                    );
                }
                self.finish_punch(now_ms);
            }
            _ => {}
        }
    }

    /// Move the winning punch socket into the data plane, keeping its id.
    fn promote_punch_slot(&mut self, relationship: RelationshipId, slot: u16, now_ms: u64) {
        let Some(id) = self.punch_sockets.slot_id(slot) else {
            self.note_punch_failure(relationship, "promoted slot is gone".to_owned());
            self.finish_punch(now_ms);
            return;
        };
        let Some(socket) = self.punch_sockets.take(id) else {
            self.note_punch_failure(relationship, "promoted socket is gone".to_owned());
            self.finish_punch(now_ms);
            return;
        };
        if socket.relationship != relationship {
            self.note_punch_failure(
                relationship,
                "promoted socket belongs to another relationship".to_owned(),
            );
            self.finish_punch(now_ms);
            return;
        }
        let interface = socket.interface.clone();
        let outcome = self.transports.adopt(id, interface, socket.socket);
        match outcome {
            Ok(()) => {
                // The promoted socket is a real transport now, so discovery and
                // the engine must both learn about it. Deliberately not
                // refresh_network: re-enumerating interfaces here could retire
                // transports and cancel this very attempt mid-promotion.
                self.public.add_transport(
                    id.0,
                    self.resolved.config.stun_seeds.clone(),
                    self.monotonic_ms(),
                );
                self.sync_engine_transports();
                // Confirmations queued for this slot must still be sendable,
                // and they now live in the data plane rather than the pool.
                self.promoted_slot = Some((relationship, slot, id));
                self.promoted_transports.insert(
                    id,
                    (
                        relationship,
                        now_ms.saturating_add(lzh_hole_protocol::engine::PATH_CONFIRM_TIMEOUT_MS),
                    ),
                );
                punch_state(&mut self.punch_states, relationship).failure = None;
                // Every other punch socket is useless once one has won.
                self.punch_sockets.close_all();
            }
            Err(error) => {
                // Refuse honestly rather than evicting a working data socket.
                self.note_punch_failure(relationship, format!("punch promotion refused: {error}"));
                self.finish_punch(now_ms);
            }
        }
    }

    /// Retain only an active winner or a transport with a selected session.
    /// Others have one bounded grace period to complete the ordinary handshake.
    ///
    /// A promoted socket is only ever kept alive by the relationship that
    /// promoted it; another peer's healthy session never extends its grace.
    fn reap_promoted_transports(&mut self, now_ms: u64) {
        let active = self.promoted_slot.map(|(_, _, id)| id);
        let entries = self
            .promoted_transports
            .iter()
            .map(|(id, (relationship, deadline))| (*id, *relationship, *deadline))
            .collect::<Vec<_>>();
        let mut expired = Vec::new();
        for (id, relationship, deadline) in entries {
            let selected = self
                .engines
                .as_ref()
                .and_then(|set| set.get(relationship))
                .and_then(|engine| engine.snapshot(now_ms).selected_path)
                .map(|path| path.transport);
            if selected == Some(id) || active == Some(id) {
                self.promoted_transports.insert(
                    id,
                    (
                        relationship,
                        now_ms.saturating_add(lzh_hole_protocol::engine::PATH_CONFIRM_TIMEOUT_MS),
                    ),
                );
            } else if now_ms >= deadline {
                expired.push(id);
            }
        }
        for id in expired {
            self.retire_transport(id);
        }
    }

    /// Close out the running attempt, whichever relationship owns it.
    fn finish_punch(&mut self, now_ms: u64) {
        let relationship = self
            .punch
            .as_ref()
            .map(|attempt| attempt.relationship)
            .or_else(|| self.punch_sockets.relationship())
            .or_else(|| self.promoted_slot.map(|(relationship, _, _)| relationship));
        self.punch_sockets.close_all();
        if let Some(relationship) = relationship
            && let Some(engine) = self
                .engines
                .as_mut()
                .and_then(|set| set.get_mut(relationship))
        {
            engine.stop_punch();
        }
        self.punch = None;
        self.promoted_slot = None;
        self.punch_send_failures = 0;
        if let Some(relationship) = relationship {
            let failed = self
                .punch_states
                .get(&relationship)
                .and_then(|state| state.failure.as_ref())
                .is_some();
            let state = punch_state(&mut self.punch_states, relationship);
            if failed {
                let next = state
                    .backoff_ms
                    .clamp(PUNCH_RETRY_MIN_MS, PUNCH_RETRY_MAX_MS);
                state.next_attempt_ms = now_ms.saturating_add(next);
                state.backoff_ms = next.saturating_mul(2).min(PUNCH_RETRY_MAX_MS);
            } else {
                state.failure = None;
                state.backoff_ms = PUNCH_RETRY_MIN_MS;
                state.next_attempt_ms = now_ms.saturating_add(PUNCH_RETRY_MIN_MS);
            }
        }
        self.refresh_public_requests();
    }

    /// Resolve slots by role, and only for the relationship that owns them.
    ///
    /// Hard slot zero is not the easy data socket, and no relationship may ever
    /// resolve another relationship's slot.
    fn punch_transport(&self, relationship: RelationshipId, slot: u16) -> Option<TransportId> {
        let attempt = self
            .punch
            .as_ref()
            .filter(|attempt| attempt.relationship == relationship)?;
        let role = self
            .engines
            .as_ref()?
            .get(relationship)?
            .punch_state()?
            .role();
        match role {
            PunchRole::Easy => attempt.origin_transport.filter(|_| slot == 0),
            PunchRole::Hard => self.punch_sockets.slot_id(slot).or_else(|| {
                self.promoted_slot
                    .filter(|(owner, winner, _)| *owner == relationship && *winner == slot)
                    .map(|(_, _, id)| id)
            }),
        }
    }

    /// Send queued punch frames, rate limited by this module's own bucket.
    ///
    /// Frames are pulled through the peer set so a frame is always attributed
    /// to the relationship that queued it, and only the running attempt's
    /// frames are ever transmitted.
    pub(super) async fn drain_punch(&mut self, now_ms: u64) {
        let Some(owner) = self.punch.as_ref().map(|attempt| attempt.relationship) else {
            return;
        };
        if !self.punch_sockets.is_active() {
            // The easy side scans from its ordinary data socket, so frames can
            // still be queued with no punch sockets open at all.
            let has_frames = self
                .engines
                .as_ref()
                .and_then(|set| set.get(owner))
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
            let frame = match self.engines.as_mut() {
                Some(set) => set.next_punch_frame(),
                None => None,
            };
            let Some((relationship, frame)) = frame else {
                break;
            };
            budget -= 1;
            if relationship != owner {
                // A frame queued by any other relationship is refused here and
                // never reaches a socket.
                self.record_drop("punch_frame_wrong_relationship", 1);
                continue;
            }
            self.punch_bucket.take(1);
            let target = SocketAddrV4::new(frame.target.ip, frame.target.port);
            let socket = self.punch_transport(owner, frame.slot).and_then(|id| {
                self.punch_sockets
                    .get(id)
                    .map(|socket| &socket.socket)
                    .or_else(|| self.transports.get(id).map(|socket| &socket.socket))
            });
            let sent = socket.is_some_and(|socket| matches!(socket.try_send_to(&frame.bytes, target), Ok(size) if size == frame.bytes.len()));
            if sent {
                self.bytes.udp_tx = self.bytes.udp_tx.saturating_add(frame.bytes.len() as u64);
                if let Some(peer) = self.peers.get_mut(&owner) {
                    peer.bytes.udp_tx = peer.bytes.udp_tx.saturating_add(frame.bytes.len() as u64);
                }
                self.punch_send_failures = 0;
            } else {
                // A single per-destination failure is not evidence that any
                // socket disappeared, exactly as on the data plane. A run of
                // them is: the frame was already consumed from the outbox, so
                // continuing would walk the grid with nothing on the wire.
                self.record_drop("punch_send_failed", 1);
                self.punch_send_failures = self.punch_send_failures.saturating_add(1);
                if self.punch_send_failures >= PUNCH_MAX_SEND_FAILURES {
                    self.note_punch_failure(owner, "punch send failures".to_owned());
                    self.finish_punch(now_ms);
                    return;
                }
            }
        }
    }

    fn punch_view(&self, relationship: RelationshipId) -> PunchView {
        let Some(state) = self
            .engines
            .as_ref()
            .and_then(|set| set.get(relationship))
            .and_then(|engine| engine.punch_state())
        else {
            return PunchView {
                state: "idle".to_owned(),
                role: None,
                probes_sent: 0,
            };
        };
        PunchView {
            state: state.phase().as_str().to_owned(),
            role: Some(state.role().as_str().to_owned()),
            probes_sent: state.probes_sent(),
        }
    }

    /// Node-level punch status: the running attempt, or why none is running.
    ///
    /// With no attempt running this reports the distinct reasons every
    /// relationship declined, so a mesh that cannot punch at all is visible as
    /// such rather than as an idle subsystem.
    pub(super) fn node_punch_status(&self) -> PunchStatus {
        if let Some(attempt) = self.punch.as_ref() {
            let relationship = attempt.relationship;
            let view = self.punch_view(relationship);
            return PunchStatus {
                state: view.state,
                role: view.role,
                local_mapping: self.local_mapping().as_str().to_owned(),
                peer_mapping: self.peer_mapping(relationship).as_str().to_owned(),
                blocked_by: None,
                last_failure: self
                    .punch_states
                    .get(&relationship)
                    .and_then(|state| state.failure.clone()),
                probes_sent: view.probes_sent,
                sockets_open: self.punch_sockets.len() as u16,
                hit_port: attempt.hit_port,
                started_unix_ms: Some(attempt.started_ms),
            };
        }
        let mut reasons: Vec<String> = Vec::new();
        for relationship in &self.peer_order {
            if let Some(declined) = self
                .punch_states
                .get(relationship)
                .and_then(|state| state.declined.clone())
                && !reasons.contains(&declined)
            {
                reasons.push(declined);
            }
        }
        // The most recently rescheduled relationship is the one whose attempt
        // ended last, so its failure is the node-level last failure.
        let last_failure = self
            .peer_order
            .iter()
            .filter_map(|relationship| self.punch_states.get(relationship))
            .filter(|state| state.failure.is_some())
            .max_by_key(|state| state.next_attempt_ms)
            .and_then(|state| state.failure.clone());
        PunchStatus {
            state: "idle".to_owned(),
            role: None,
            local_mapping: self.local_mapping().as_str().to_owned(),
            peer_mapping: self.node_peer_mapping(),
            blocked_by: (!reasons.is_empty()).then(|| reasons.join("; ")),
            last_failure,
            probes_sent: 0,
            sockets_open: 0,
            hit_port: None,
            started_unix_ms: None,
        }
    }

    /// One relationship's punch status, including an honest queued reason.
    ///
    /// A relationship that is not the running one reports idle, no role, no
    /// start time and no open sockets of its own, together with the non-empty
    /// reason it is not punching. It never borrows the running attempt's facts.
    pub(super) fn peer_punch_status(&self, relationship: RelationshipId) -> PunchStatus {
        let running = self
            .punch
            .as_ref()
            .filter(|attempt| attempt.relationship == relationship);
        let state = self.punch_states.get(&relationship);
        let failure = state.and_then(|state| state.failure.clone());
        match running {
            Some(attempt) => {
                let view = self.punch_view(relationship);
                PunchStatus {
                    state: view.state,
                    role: view.role,
                    local_mapping: self.local_mapping().as_str().to_owned(),
                    peer_mapping: self.peer_mapping(relationship).as_str().to_owned(),
                    blocked_by: None,
                    last_failure: failure,
                    probes_sent: view.probes_sent,
                    sockets_open: self.punch_sockets.len() as u16,
                    hit_port: attempt.hit_port,
                    started_unix_ms: Some(attempt.started_ms),
                }
            }
            None => PunchStatus {
                state: "idle".to_owned(),
                role: None,
                local_mapping: self.local_mapping().as_str().to_owned(),
                peer_mapping: self.peer_mapping(relationship).as_str().to_owned(),
                blocked_by: state.and_then(|state| state.declined.clone()),
                last_failure: failure,
                probes_sent: 0,
                sockets_open: 0,
                hit_port: None,
                started_unix_ms: None,
            },
        }
    }

    /// Node-level peer mapping verdict: one peer's, or the honest mixture.
    fn node_peer_mapping(&self) -> String {
        let mut verdicts: Vec<&'static str> = Vec::new();
        for relationship in &self.peer_order {
            let verdict = self.peer_mapping(*relationship).as_str();
            if !verdicts.contains(&verdict) {
                verdicts.push(verdict);
            }
        }
        match verdicts.len() {
            0 => MappingBehavior::Unknown.as_str().to_owned(),
            1 => verdicts[0].to_owned(),
            _ => format!("mixed({})", verdicts.join(",")),
        }
    }

    /// Abandon any punch attempt and release its sockets.
    ///
    /// Used when an interface disappears and at shutdown: the attempt is given
    /// up rather than left holding dead descriptors.
    pub(super) fn stop_punch(&mut self, now_ms: u64) {
        let running = self.punch.as_ref().map(|attempt| attempt.relationship);
        let socket_owner = self.punch_sockets.relationship();
        if running.is_none() && socket_owner.is_none() && self.promoted_slot.is_none() {
            return;
        }
        let relationship = running
            .or(socket_owner)
            .or_else(|| self.promoted_slot.map(|(relationship, _, _)| relationship));
        // Tearing down after a socket was already promoted is not a failed
        // punch: the path was found, the attempt is simply being closed out.
        if let Some(relationship) = relationship
            && self.promoted_slot.is_none()
        {
            self.note_punch_failure(relationship, "cancelled".to_owned());
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
    use lzh_hole_protocol::engine::PeerEngine;
    use lzh_hole_protocol::mesh::PeerSet;
    use lzh_hole_protocol::path::PathEndpoint;
    use lzh_hole_store::{PAIRING_VERSION, Relationship, Role};
    use lzh_hole_types::{DiscoveryPublicKey, Secret32};

    const NOW: u64 = 1_800_000_000_000;

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
        assert_eq!(sockets.relationship(), None);
        assert!(sockets.get(TransportId(1)).is_none());
    }

    #[test]
    fn a_fresh_relationship_starts_at_the_minimum_backoff_with_no_history() {
        let state = PunchPeerState::default();
        assert_eq!(state.backoff_ms, PUNCH_RETRY_MIN_MS);
        assert_eq!(state.next_attempt_ms, 0);
        assert_eq!(state.failure, None);
        assert_eq!(state.declined, None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn opening_punch_sockets_gives_each_slot_its_own_identifier_and_one_owner() {
        let relationship = RelationshipId::from_bytes([0x31; 16]);
        let mut ids = TransportIds::default();
        let mut sockets = PunchSockets::default();
        sockets
            .open(&mut ids, relationship, "lo0", Ipv4Addr::LOCALHOST, 8)
            .expect("open");
        assert!(sockets.is_active());
        assert_eq!(sockets.len(), 8);
        assert_eq!(sockets.relationship(), Some(relationship));
        let mut seen = std::collections::BTreeSet::new();
        for slot in 0..8u16 {
            let id = sockets.slot_id(slot).expect("slot is occupied");
            assert_ne!(id, TransportId(0), "identifier zero is reserved");
            assert!(seen.insert(id), "slot {slot} reused an identifier");
            assert_eq!(
                sockets.get(id).unwrap().relationship,
                relationship,
                "every slot remembers which relationship opened it"
            );
        }
        assert_eq!(seen.len(), 8);
        // Re-opening while sockets exist is refused rather than leaking.
        assert!(
            sockets
                .open(&mut ids, relationship, "lo0", Ipv4Addr::LOCALHOST, 8)
                .is_err()
        );
        // Taking one socket frees exactly that slot.
        let id = sockets.slot_id(3).unwrap();
        let taken = sockets.take(id).expect("take");
        assert_eq!(taken.slot, 3);
        assert_eq!(taken.relationship, relationship);
        assert_eq!(sockets.len(), 7);
        assert_eq!(sockets.slot_id(3), None);
        // Closing releases everything and is safe to repeat.
        sockets.close_all();
        sockets.close_all();
        assert!(!sockets.is_active());
        assert_eq!(sockets.len(), 0);
        assert_eq!(sockets.relationship(), None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn punch_sockets_carry_traffic_between_slots_and_tag_the_relationship() {
        let relationship = RelationshipId::from_bytes([0x32; 16]);
        let mut ids = TransportIds::default();
        let mut sockets = PunchSockets::default();
        sockets
            .open(&mut ids, relationship, "lo0", Ipv4Addr::LOCALHOST, 2)
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
        assert_eq!(datagram.relationship, relationship);
        assert_eq!(datagram.buffer, b"punch");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_failed_open_leaves_no_sockets_behind() {
        let relationship = RelationshipId::from_bytes([0x33; 16]);
        let mut ids = TransportIds::default();
        let mut sockets = PunchSockets::default();
        assert!(
            sockets
                .open(
                    &mut ids,
                    relationship,
                    "not-an-interface",
                    Ipv4Addr::LOCALHOST,
                    8
                )
                .is_err()
        );
        assert!(
            !sockets.is_active(),
            "a failed open must not retain sockets"
        );
        assert_eq!(sockets.len(), 0);
        assert_eq!(sockets.relationship(), None);
        // And the pool is immediately reusable.
        assert!(
            sockets
                .open(&mut ids, relationship, "lo0", Ipv4Addr::LOCALHOST, 2)
                .is_ok()
        );
        assert_eq!(sockets.len(), 2);
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
            PunchBlock::Queued,
            PunchBlock::Unavailable,
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

    // ----------------------------------------------------------------- mesh
    // Two pinned peers, one shared uplink, one identity. Everything below is a
    // single-process simulation: no ntfy, no TUN, no privileged operation.

    struct Mesh {
        _temp: tempfile::TempDir,
        daemon: Daemon,
        relationships: Vec<RelationshipId>,
        transport: TransportId,
        targets: BTreeMap<RelationshipId, Endpoint>,
    }

    impl Mesh {
        fn rel(&self, index: usize) -> RelationshipId {
            self.relationships[index]
        }

        fn other(&self, relationship: RelationshipId) -> RelationshipId {
            *self
                .relationships
                .iter()
                .find(|candidate| **candidate != relationship)
                .expect("the other relationship")
        }
    }

    fn relationship_for(
        self_key: DiscoveryPublicKey,
        peer_seed: [u8; 32],
        id: [u8; 16],
        peer_vip: &str,
    ) -> Relationship {
        let peer_key = DiscoveryPublicKey::from_bytes(
            SigningKey::from_bytes(&peer_seed)
                .verifying_key()
                .to_bytes(),
        );
        Relationship {
            pairing_version: PAIRING_VERSION,
            pairing_id: RelationshipId::from_bytes(id),
            relationship_id: RelationshipId::from_bytes(id),
            self_public_key: self_key,
            peer_public_key: peer_key,
            role: Role::Initiator,
            self_vip: "10.203.0.1".to_owned(),
            peer_vip: peer_vip.to_owned(),
            finalised_unix_ms: 1,
        }
    }

    /// Two coherent STUN answers from two distinct destinations.
    fn classify_local_mapping(daemon: &mut Daemon, transport: TransportId, ports: [u16; 2]) {
        use lzh_hole_discovery::stun::{ATTR_MAPPED_ADDRESS, MAGIC_COOKIE, MSG_BINDING_SUCCESS};
        let servers: Vec<SocketAddrV4> = vec![
            "8.8.8.8:3478".parse().unwrap(),
            "8.8.4.4:3478".parse().unwrap(),
        ];
        daemon.public.add_transport(transport.0, servers.clone(), 0);
        for (index, server) in servers.iter().enumerate() {
            let transaction = [index as u8 + 1; 12];
            let now = index as u64 * 5_001;
            daemon
                .public
                .start_stun(transport.0, transaction, now)
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
            reply.extend_from_slice(&ports[index].to_be_bytes());
            reply.extend_from_slice(&[210, 22, 105, 193]);
            daemon
                .public
                .receive_stun(transport.0, *server, &reply, now + 1)
                .unwrap();
        }
    }

    /// A two-peer offline daemon with one classified endpoint-independent
    /// uplink, a distinct public candidate per relationship, and each peer
    /// advertising an endpoint-dependent mapping with no open punch window.
    fn mesh() -> Mesh {
        let temp = tempfile::Builder::new()
            .prefix("lzh-hole-punch-mesh-")
            .tempdir()
            .unwrap();
        let state = StateDir::open(&temp.path().join("state")).unwrap();
        let seed = [7u8; 32];
        state.store_seed(&seed).unwrap();
        let self_key = DiscoveryPublicKey::from_bytes(
            SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
        );

        let rel_a = relationship_for(self_key, [0x11; 32], [0xa1; 16], "10.203.0.2");
        let rel_b = relationship_for(self_key, [0x22; 32], [0xa2; 16], "10.203.0.3");
        let psk_a = Secret32::from_bytes([0x51; 32]);
        let psk_b = Secret32::from_bytes([0x52; 32]);
        state.finalise(&rel_a, &psk_a).unwrap();
        state.finalise(&rel_b, &psk_b).unwrap();

        let config = ServiceConfig {
            state_dir: state.path().to_path_buf(),
            control_socket: temp.path().join("control").join("control.sock"),
            // Daemon::new never binds the control socket; only run_async does.
            management_uid: 0,
            interface: None,
            bind_ip: None,
            udp_port: 51000,
            stun_seeds: vec![
                "8.8.8.8:3478".parse().unwrap(),
                "8.8.4.4:3478".parse().unwrap(),
            ],
            ntfy: crate::config::NtfyConfig {
                base_url: "https://ntfy.sh".to_owned(),
                resolve_ip: None,
                dns_server: None,
            },
            lan: crate::config::LanConfig::default(),
            mtu: 1200,
            punch: crate::config::PunchConfig::default(),
        };
        let resolved = config.resolve(vec![rel_a.clone(), rel_b.clone()]).unwrap();

        let (snapshots, _) = watch::channel(ServiceSnapshot::starting(1, now_unix_ms()));
        let mut daemon = Daemon::new(
            resolved,
            false,
            RuntimeComponents::offline_for_test(),
            snapshots,
        )
        .unwrap();

        let relationships = daemon.peer_order.clone();
        assert_eq!(relationships.len(), 2, "the harness pins exactly two peers");

        // One node-level uplink, shared by every relationship.
        let transport = daemon
            .transports
            .open(&mut daemon.transport_ids, "lo0", Ipv4Addr::LOCALHOST, 0)
            .unwrap();
        classify_local_mapping(&mut daemon, transport, [51_000, 51_000]);

        let mut engines = PeerSet::new(daemon.resolved.self_vip, self_key);
        let stun_servers = daemon
            .resolved
            .config
            .stun_seeds
            .iter()
            .map(|server| endpoint(*server))
            .collect::<Vec<_>>();
        for (relationship, psk) in [(&rel_a, &psk_a), (&rel_b, &psk_b)] {
            engines
                .insert(
                    EngineConfig {
                        handshake: HandshakeConfig {
                            relationship_id: relationship.relationship_id,
                            me: self_key,
                            peer: relationship.peer_public_key,
                            boot_id: daemon.boot_id,
                            generation: daemon.generation,
                        },
                        self_vip: daemon.resolved.self_vip,
                        peer_vip: relationship
                            .peer_vip
                            .parse::<Ipv4Addr>()
                            .expect("paired peer vip"),
                        candidate_policy: CandidatePolicy {
                            own_endpoints: Vec::new(),
                            forbidden_addresses: Vec::new(),
                            stun_servers: stun_servers.clone(),
                            require_public_unicast: true,
                        },
                    },
                    psk,
                )
                .unwrap();
        }
        daemon.engines = Some(engines);
        daemon.sync_engine_transports();

        // Each relationship owns a different public candidate.
        let mut targets = BTreeMap::new();
        for (index, relationship) in relationships.iter().enumerate() {
            let target = Endpoint::new(
                Ipv4Addr::new(210, 22, 105, 194 + index as u8),
                51_000 + index as u16,
            );
            targets.insert(*relationship, target);
            daemon.paths.insert(
                *relationship,
                vec![PathCandidate {
                    path: PathEndpoint {
                        transport,
                        remote: target,
                    },
                    kind: PathKind::Public,
                }],
            );
        }

        // Every peer claims an endpoint-dependent mapping and no open window.
        for relationship in &relationships {
            let peer = daemon.peers.get_mut(relationship).unwrap();
            peer.peer_record_flags = lzh_hole_discovery::record::FLAG_MAPPING_EDM;
            peer.peer_record_expires_ms = NOW + 180_000;
        }

        Mesh {
            _temp: temp,
            daemon,
            relationships,
            transport,
            targets,
        }
    }

    /// Give every relationship a live, signed hard-side window.
    fn arm_offers(mesh: &mut Mesh, expires_ms: u64) {
        for relationship in &mesh.relationships {
            let peer = mesh.daemon.peers.get_mut(relationship).unwrap();
            peer.peer_record_flags |= lzh_hole_discovery::record::FLAG_PUNCH_OFFER;
            peer.peer_record_expires_ms = expires_ms;
        }
    }

    fn engine_of(daemon: &mut Daemon, relationship: RelationshipId) -> &mut PeerEngine {
        daemon
            .engines
            .as_mut()
            .expect("mesh engines")
            .get_mut(relationship)
            .expect("the relationship's own engine")
    }

    fn start_test_punch(
        daemon: &mut Daemon,
        relationship: RelationshipId,
        role: PunchRole,
        origin: TransportId,
        target: Endpoint,
        now: u64,
    ) {
        let (self_key, peer_key) = {
            let peer = daemon.peers.get(&relationship).expect("pinned peer");
            (
                peer.relationship.self_public_key,
                peer.relationship.peer_public_key,
            )
        };
        let config = PunchConfig {
            role,
            peer_endpoint: target,
            local_key: self_key,
            peer_key,
            relationship_id: relationship,
            boot_id: daemon.boot_id,
            generation: daemon.generation,
            direction: if self_key < peer_key {
                lzh_hole_protocol::wire::Direction::LoToHi
            } else {
                lzh_hole_protocol::wire::Direction::HiToLo
            },
            hard_sockets: PUNCH_HARD_SOCKETS as u16,
        };
        assert!(engine_of(daemon, relationship).start_punch(config, now));
        daemon.punch = Some(PunchAttempt {
            relationship,
            origin_transport: Some(origin),
            started_ms: now,
            hit_port: None,
        });
        daemon.punch_send_failures = 0;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn only_one_relationship_punches_and_the_other_reports_that_it_is_queued() {
        let mut mesh = mesh();
        arm_offers(&mut mesh, NOW + 180_000);
        let a = mesh.rel(0);
        let b = mesh.rel(1);

        mesh.daemon.maybe_start_punch(NOW);
        let winner = mesh
            .daemon
            .punch
            .as_ref()
            .expect("exactly one attempt starts")
            .relationship;
        assert!(winner == a || winner == b);
        let loser = mesh.other(winner);

        let active = mesh
            .relationships
            .iter()
            .filter(|relationship| {
                mesh.daemon
                    .engines
                    .as_ref()
                    .unwrap()
                    .get(**relationship)
                    .is_some_and(|engine| engine.punch_active())
            })
            .count();
        assert_eq!(active, 1, "only one engine may ever be punching");

        // The queued relationship never claims a running attempt.
        let queued = mesh.daemon.peer_punch_status(loser);
        assert_eq!(queued.state, "idle");
        assert!(queued.role.is_none());
        assert!(queued.started_unix_ms.is_none());
        assert!(queued.hit_port.is_none());
        assert_eq!(queued.sockets_open, 0);
        assert_eq!(queued.probes_sent, 0);
        let blocked = queued
            .blocked_by
            .expect("a queued relationship must say why it is queued");
        assert!(blocked.contains(PunchBlock::Queued.as_str()), "{blocked}");
        assert!(blocked.contains(&winner.to_hex()), "{blocked}");

        // The running relationship reports the real attempt.
        let running = mesh.daemon.peer_punch_status(winner);
        assert_ne!(running.state, "idle");
        assert_eq!(running.role.as_deref(), Some(PunchRole::Easy.as_str()));
        assert_eq!(running.started_unix_ms, Some(NOW));
        assert!(running.blocked_by.is_none());

        // And a second pass never starts a second attempt.
        mesh.daemon.maybe_start_punch(NOW + 10);
        assert_eq!(
            mesh.daemon.punch.as_ref().unwrap().relationship,
            winner,
            "the single window stays with the running relationship"
        );
        assert!(!mesh.daemon.punch_sockets.is_active());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn punch_selection_rotates_between_relationships() {
        let mut mesh = mesh();
        let a = mesh.rel(0);
        let b = mesh.rel(1);

        let mut chosen = Vec::new();
        for round in 0..4u64 {
            let at = NOW + round * 600_000;
            // A real peer republishes its record every round. Arming the offer
            // once would let it expire long before the later rounds, and an
            // expired offer is an honest reason not to punch.
            arm_offers(&mut mesh, at + 180_000);
            mesh.daemon.maybe_start_punch(at);
            let winner = mesh
                .daemon
                .punch
                .as_ref()
                .expect("an attempt starts")
                .relationship;
            chosen.push(winner);
            // Ending the attempt pushes that relationship's own schedule out.
            mesh.daemon.stop_punch(at);
            assert!(mesh.daemon.punch.is_none());
        }
        assert!(
            chosen.contains(&a) && chosen.contains(&b),
            "one relationship monopolised the window: {chosen:?}"
        );
        assert_eq!(chosen.len(), 4);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_relationship_only_ever_punches_its_own_candidate() {
        let mut mesh = mesh();
        arm_offers(&mut mesh, NOW + 180_000);
        let a = mesh.rel(0);
        let b = mesh.rel(1);
        let target_a = mesh.targets[&a];
        let target_b = mesh.targets[&b];
        assert_ne!(target_a.ip, target_b.ip);
        let transport = mesh.transport;

        // B has no projected path of its own. It must decline rather than
        // borrow A's candidate.
        mesh.daemon.paths.remove(&b);
        mesh.daemon.maybe_start_punch(NOW);
        let winner = mesh
            .daemon
            .punch
            .as_ref()
            .expect("A still starts")
            .relationship;
        assert_eq!(winner, a);
        assert_eq!(
            mesh.daemon.peer_punch_status(b).blocked_by.as_deref(),
            Some(PunchBlock::NoPublicCandidate.as_str())
        );
        // Frames are queued by the state machine's tick, not by start_punch.
        mesh.daemon.drive_punch(NOW);
        let frame = engine_of(&mut mesh.daemon, a)
            .next_punch_frame()
            .expect("the easy side probes immediately");
        assert_eq!(frame.target.ip, target_a.ip);
        assert_ne!(frame.target.ip, target_b.ip);
        mesh.daemon.stop_punch(NOW);

        // With its own path restored, B punches its own target and never A's.
        mesh.daemon.paths.insert(
            b,
            vec![PathCandidate {
                path: PathEndpoint {
                    transport,
                    remote: target_b,
                },
                kind: PathKind::Public,
            }],
        );
        mesh.daemon.maybe_start_punch(NOW);
        let winner = mesh
            .daemon
            .punch
            .as_ref()
            .expect("B now starts")
            .relationship;
        assert_eq!(winner, b, "A is backing off and B is due");
        mesh.daemon.drive_punch(NOW);
        let frame = engine_of(&mut mesh.daemon, b)
            .next_punch_frame()
            .expect("the easy side probes immediately");
        assert_eq!(frame.target.ip, target_b.ip);
        assert_ne!(frame.target.ip, target_a.ip);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_foreign_punch_event_never_touches_the_running_relationship() {
        let mut mesh = mesh();
        arm_offers(&mut mesh, NOW + 180_000);
        mesh.daemon.maybe_start_punch(NOW);
        let owner = mesh.daemon.punch.as_ref().unwrap().relationship;
        let other = mesh.other(owner);

        let foreign = Endpoint::new(Ipv4Addr::new(203, 0, 113, 9), 40_000);
        mesh.daemon.apply_punch_events(
            owner,
            vec![(other, PunchEvent::Learned { peer: foreign })],
            NOW,
        );
        assert!(
            mesh.daemon.punch.is_some(),
            "a foreign event must not end the running attempt"
        );
        assert_eq!(mesh.daemon.punch.as_ref().unwrap().relationship, owner);
        assert!(mesh.daemon.punch.as_ref().unwrap().hit_port.is_none());
        assert!(mesh.daemon.peer_punch_status(other).hit_port.is_none());
        assert_eq!(
            mesh.daemon
                .io_drops
                .reasons
                .get("punch_event_wrong_relationship")
                .copied(),
            Some(1)
        );

        // The owner's own event does apply, and only to the owner.
        let own = Endpoint::new(Ipv4Addr::new(203, 0, 113, 10), 40_001);
        mesh.daemon.apply_punch_events(
            owner,
            vec![(owner, PunchEvent::Learned { peer: own })],
            NOW,
        );
        assert_eq!(mesh.daemon.punch.as_ref().unwrap().hit_port, Some(40_001));
        assert!(mesh.daemon.peer_punch_status(other).hit_port.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn backoff_failure_and_queue_reason_are_per_relationship() {
        let mut mesh = mesh();
        arm_offers(&mut mesh, NOW + 180_000);
        let a = mesh.rel(0);
        let b = mesh.rel(1);

        let b_backoff = mesh.daemon.punch_states[&b].backoff_ms;
        assert_eq!(b_backoff, PUNCH_RETRY_MIN_MS);
        assert_eq!(mesh.daemon.punch_states[&b].next_attempt_ms, 0);

        // Keep B far in the future so A is unambiguously the due relationship.
        mesh.daemon
            .punch_states
            .get_mut(&b)
            .unwrap()
            .next_attempt_ms = NOW + 3_600_000;

        for round in 0..2u64 {
            let at = NOW + round * 1_000;
            mesh.daemon
                .punch_states
                .get_mut(&a)
                .unwrap()
                .next_attempt_ms = 0;
            mesh.daemon.maybe_start_punch(at);
            assert_eq!(mesh.daemon.punch.as_ref().unwrap().relationship, a);
            mesh.daemon.note_punch_failure(a, "deadline".to_owned());
            mesh.daemon.finish_punch(at);
        }

        let state_a = &mesh.daemon.punch_states[&a];
        assert_eq!(state_a.failure.as_deref(), Some("deadline"));
        assert_eq!(state_a.backoff_ms, PUNCH_RETRY_MIN_MS * 4);
        assert!(state_a.next_attempt_ms > NOW);

        let state_b = &mesh.daemon.punch_states[&b];
        assert_eq!(state_b.backoff_ms, b_backoff, "B's backoff is untouched");
        assert_eq!(state_b.next_attempt_ms, NOW + 3_600_000);
        assert_eq!(state_b.failure, None, "B never inherited A's failure");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_datagram_only_reaches_the_relationship_that_owns_the_slot() {
        let mut mesh = mesh();
        arm_offers(&mut mesh, NOW + 180_000);
        let a = mesh.rel(0);
        let b = mesh.rel(1);

        mesh.daemon
            .punch_sockets
            .open(
                &mut mesh.daemon.transport_ids,
                a,
                "lo0",
                Ipv4Addr::LOCALHOST,
                2,
            )
            .unwrap();
        assert_eq!(mesh.daemon.punch_sockets.relationship(), Some(a));
        let id = mesh.daemon.punch_sockets.slot_id(0).unwrap();

        let late = |relationship: RelationshipId| PunchDatagram {
            id,
            slot: 0,
            relationship,
            result: Err(io::Error::other("synthetic")),
            buffer: Vec::new(),
        };

        // No attempt is running: a late datagram is dropped, never delivered.
        mesh.daemon.handle_punch_udp(late(a), NOW);
        assert!(mesh.daemon.punch.is_none());
        assert!(!engine_of(&mut mesh.daemon, a).punch_active());
        assert_eq!(
            mesh.daemon
                .io_drops
                .reasons
                .get("punch_datagram_not_owned")
                .copied(),
            Some(1)
        );

        // An attempt for B does not make A's socket deliverable.
        let target_b = mesh.targets[&b];
        let transport = mesh.transport;
        start_test_punch(
            &mut mesh.daemon,
            b,
            PunchRole::Easy,
            transport,
            target_b,
            NOW,
        );
        mesh.daemon.handle_punch_udp(late(a), NOW);
        assert_eq!(mesh.daemon.punch.as_ref().unwrap().relationship, b);
        assert!(!engine_of(&mut mesh.daemon, a).punch_active());

        // And the pool's own attribution is authoritative: a datagram claiming B
        // on A's socket is refused even though B is the running attempt.
        let forged = PunchDatagram {
            id,
            slot: 0,
            relationship: b,
            result: Ok((
                4,
                RecvMeta {
                    source: "210.22.105.200:40000".parse().unwrap(),
                    ifindex: None,
                    dest: None,
                },
            )),
            buffer: b"junk".to_vec(),
        };
        mesh.daemon.handle_punch_udp(forged, NOW);
        assert_eq!(
            mesh.daemon
                .io_drops
                .reasons
                .get("punch_socket_wrong_relationship")
                .copied(),
            Some(1)
        );
        assert!(!engine_of(&mut mesh.daemon, a).punch_active());
        assert_eq!(mesh.daemon.punch.as_ref().unwrap().hit_port, None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn the_offer_bit_and_its_deadline_belong_to_exactly_one_relationship() {
        let mut mesh = mesh();
        let a = mesh.rel(0);
        let b = mesh.rel(1);
        let transport = mesh.transport;

        assert!(!mesh.daemon.punch_offer_active());
        assert_eq!(mesh.daemon.punch_offer_relationship(), None);
        assert_eq!(mesh.daemon.punch_offer_deadline_for(a), None);
        assert_eq!(mesh.daemon.punch_offer_deadline_for(b), None);
        assert_eq!(
            mesh.daemon.record_flags_for(a) & lzh_hole_discovery::record::FLAG_PUNCH_OFFER,
            0
        );

        let target_a = mesh.targets[&a];
        start_test_punch(
            &mut mesh.daemon,
            a,
            PunchRole::Hard,
            transport,
            target_a,
            1_000,
        );
        mesh.daemon
            .punch_sockets
            .open(
                &mut mesh.daemon.transport_ids,
                a,
                "lo0",
                Ipv4Addr::LOCALHOST,
                1,
            )
            .unwrap();

        assert!(mesh.daemon.punch_offer_active());
        assert_eq!(mesh.daemon.punch_offer_relationship(), Some(a));
        assert_eq!(
            mesh.daemon.punch_offer_deadline_for(a),
            Some(1_000 + PUNCH_HARD_DEADLINE_MS)
        );
        assert_eq!(mesh.daemon.punch_offer_deadline_for(b), None);

        let flags_a = mesh.daemon.record_flags_for(a);
        let flags_b = mesh.daemon.record_flags_for(b);
        assert_ne!(flags_a & lzh_hole_discovery::record::FLAG_PUNCH_OFFER, 0);
        assert_eq!(
            flags_b & lzh_hole_discovery::record::FLAG_PUNCH_OFFER,
            0,
            "one relationship's offer must never leak into another's record"
        );
        assert_eq!(
            flags_a & lzh_hole_discovery::record::FLAG_MAPPING_EDM,
            flags_b & lzh_hole_discovery::record::FLAG_MAPPING_EDM,
            "the mapping verdict is this host's own measurement for both"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_promoted_slot_keeps_its_identifier_and_is_reclaimed_per_relationship() {
        let mut mesh = mesh();
        let a = mesh.rel(0);
        let b = mesh.rel(1);
        let data = mesh.transport;

        for attempt in 0..4u64 {
            let now = NOW + attempt * 60_000;
            let relationship = if attempt % 2 == 0 { a } else { b };
            let other = mesh.other(relationship);
            let target = mesh.targets[&relationship];
            mesh.daemon
                .punch_sockets
                .open(
                    &mut mesh.daemon.transport_ids,
                    relationship,
                    "lo0",
                    Ipv4Addr::LOCALHOST,
                    1,
                )
                .unwrap();
            start_test_punch(
                &mut mesh.daemon,
                relationship,
                PunchRole::Hard,
                data,
                target,
                now,
            );
            let winner = mesh.daemon.punch_sockets.slot_id(0).unwrap();
            assert_ne!(winner, data);
            assert_eq!(mesh.daemon.punch_transport(relationship, 0), Some(winner));
            assert_eq!(
                mesh.daemon.punch_transport(other, 0),
                None,
                "another relationship never resolves this slot"
            );
            mesh.daemon.promote_punch_slot(relationship, 0, now);
            assert_eq!(mesh.daemon.punch_transport(relationship, 0), Some(winner));
            assert_eq!(mesh.daemon.promoted_slot, Some((relationship, 0, winner)));
            assert!(mesh.daemon.transports.get(winner).is_some());
            mesh.daemon.finish_punch(now);

            mesh.daemon.reap_promoted_transports(
                now + lzh_hole_protocol::engine::PATH_CONFIRM_TIMEOUT_MS - 1,
            );
            assert!(
                mesh.daemon.transports.get(winner).is_some(),
                "handshake grace is retained"
            );
            mesh.daemon
                .reap_promoted_transports(now + lzh_hole_protocol::engine::PATH_CONFIRM_TIMEOUT_MS);
            assert!(mesh.daemon.transports.get(winner).is_none());
            assert_eq!(mesh.daemon.transports.iter().count(), 1);
            assert!(mesh.daemon.promoted_transports.is_empty());
        }

        // The easy side resolves slot zero to its pinned origin socket only.
        let target_a = mesh.targets[&a];
        start_test_punch(
            &mut mesh.daemon,
            a,
            PunchRole::Easy,
            data,
            target_a,
            NOW + 1_000_000,
        );
        assert_eq!(mesh.daemon.punch_transport(a, 0), Some(data));
        assert_eq!(mesh.daemon.punch_transport(a, 1), None);
        assert_eq!(mesh.daemon.punch_transport(b, 0), None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn an_easy_side_waits_for_a_live_offer_without_burning_retry_backoff() {
        let mut mesh = mesh();
        let a = mesh.rel(0);
        let relationships = mesh.relationships.clone();

        for offset in 0..10 {
            mesh.daemon.maybe_start_punch(NOW + offset);
        }
        assert!(mesh.daemon.punch.is_none());
        for relationship in &relationships {
            assert_eq!(
                mesh.daemon
                    .peer_punch_status(*relationship)
                    .blocked_by
                    .as_deref(),
                Some(PunchBlock::WaitingForOffer.as_str())
            );
            assert_eq!(
                mesh.daemon.punch_states[relationship].next_attempt_ms, 0,
                "waiting for an offer must not burn retry backoff"
            );
        }

        // A window that is already nearly closed is not scanned.
        {
            let peer = mesh.daemon.peers.get_mut(&a).unwrap();
            peer.peer_record_flags |= lzh_hole_discovery::record::FLAG_PUNCH_OFFER;
            peer.peer_record_expires_ms = NOW + PUNCH_DEADLINE_MS;
        }
        mesh.daemon.maybe_start_punch(NOW);
        assert!(
            mesh.daemon.punch.is_none(),
            "expired or nearly closed windows are not scanned"
        );

        // A live window is.
        mesh.daemon
            .peers
            .get_mut(&a)
            .unwrap()
            .peer_record_expires_ms = NOW + 180_000;
        mesh.daemon.maybe_start_punch(NOW);
        let attempt = mesh
            .daemon
            .punch
            .as_ref()
            .expect("a live offer starts a scan");
        assert_eq!(attempt.relationship, a);
        assert_eq!(
            engine_of(&mut mesh.daemon, a).punch_state().unwrap().role(),
            PunchRole::Easy
        );
        assert_eq!(mesh.daemon.punch_transport(a, 0), Some(mesh.transport));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn an_idle_node_reports_every_relationships_reason_and_never_a_running_attempt() {
        let mut mesh = mesh();
        // No offers, so nothing can start.
        mesh.daemon.maybe_start_punch(NOW);
        let node = mesh.daemon.node_punch_status();
        assert_eq!(node.state, "idle");
        assert!(node.role.is_none());
        assert!(node.started_unix_ms.is_none());
        assert_eq!(node.sockets_open, 0);
        assert_eq!(node.peer_mapping, "edm", "both peers agree");
        let blocked = node.blocked_by.expect("an idle node says why");
        assert!(
            blocked.contains(PunchBlock::WaitingForOffer.as_str()),
            "{blocked}"
        );

        // One attempt running: the node reports exactly that relationship.
        arm_offers(&mut mesh, NOW + 180_000);
        mesh.daemon.maybe_start_punch(NOW);
        let owner = mesh.daemon.punch.as_ref().unwrap().relationship;
        let node = mesh.daemon.node_punch_status();
        assert_ne!(node.state, "idle");
        assert_eq!(node.role.as_deref(), Some(PunchRole::Easy.as_str()));
        assert_eq!(node.started_unix_ms, Some(NOW));
        assert!(node.blocked_by.is_none());
        assert_eq!(node.peer_mapping, mesh.daemon.peer_mapping(owner).as_str());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_relationship_without_an_engine_declines_rather_than_punching() {
        let mut mesh = mesh();
        arm_offers(&mut mesh, NOW + 180_000);
        let a = mesh.rel(0);
        mesh.daemon.engines = None;
        mesh.daemon.maybe_start_punch(NOW);
        assert!(mesh.daemon.punch.is_none());
        assert_eq!(
            mesh.daemon.peer_punch_status(a).blocked_by.as_deref(),
            Some(PunchBlock::Unavailable.as_str())
        );
        assert!(!mesh.daemon.punch_sockets.is_active());
    }
}
