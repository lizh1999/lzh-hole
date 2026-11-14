//! Bounded, no-socket hole-punch state machine for one authenticated peer.
//!
//! The daemon owns every socket, the clock and the random source. This module
//! owns only the decision of *which* frame to send *where*, and the bounded
//! bookkeeping needed to recognise a peer's punch frame when one arrives.
//!
//! Why a grid and not a birthday attack: the hard side's NAT was measured to
//! allocate contiguous external ports for successive sockets towards the same
//! destination. Opening K sockets therefore occupies roughly K adjacent ports,
//! so an easy side walking a grid of step G <= K/2 across the port space is
//! guaranteed to land inside that block. That is a deterministic hit, not a
//! probabilistic one, and it needs about a quarter of the probes a birthday
//! attack would need for the same K.
//!
//! Nothing here allocates session state, consumes a sequence number, enters the
//! handshake transcript or touches the replay window. A punch frame is
//! sessionless and is authenticated with the static punch key alone.

use std::collections::VecDeque;
use std::fmt;

use crate::crypto::{Key32, verify_frame_mac};
use crate::handshake::CLOCK_SKEW_TOLERANCE_MS;
use crate::path::Endpoint;
use crate::wire::{
    Direction, FrameType, PUNCH_PAYLOAD_LEN, PunchPayload, encode_frame, parse_frame,
};
use lzh_hole_types::{BootId, DiscoveryPublicKey, RelationshipId};

/// Sockets the hard side opens. Total cost is about
/// `hard_sockets + 65535 / grid_step`, minimised near 256.
pub const PUNCH_HARD_SOCKETS: usize = 256;
/// Easy-side grid step. Half the hard-side block width, leaving room for the
/// allocation noise observed on a real carrier NAT.
pub const PUNCH_GRID_STEP: u16 = 128;
/// Probes needed to walk the whole usable port space at the default step.
pub const PUNCH_MAX_PROBES: usize = 512;
/// Easy-side scan deadline, including time for in-flight confirmations.
pub const PUNCH_DEADLINE_MS: u64 = 30_000;
/// Hard-side window includes paced signaling and peer record propagation.
pub const PUNCH_HARD_DEADLINE_MS: u64 = 180_000;
/// Measured ceiling: a real carrier NAT started dropping confirmations at
/// roughly 20k packets per second, while 400 per second always got through.
pub const PUNCH_RATE_PER_SECOND: u32 = 400;
/// Token bucket burst.
pub const PUNCH_BURST: u32 = 100;
/// Queued punch frames. Deliberately separate from the engine's data outbox.
pub const PUNCH_OUTBOX: usize = 512;
/// Hard-side re-send interval, comfortably below a typical UDP NAT timeout.
pub const PUNCH_KEEPALIVE_MS: u64 = 10_000;
/// Bounded nonce ring used to drop duplicate inbound punch frames.
pub const PUNCH_MAX_NONCES: usize = 512;
/// How long queued frames may sit undrained before the attempt is abandoned
/// as a stalled daemon. At the nominal 400 packets per second the whole outbox
/// drains in well under two seconds, so this only fires when nothing is taking
/// frames at all.
pub const PUNCH_STALL_MS: u64 = 5_000;
/// First port the easy side probes. Well-known ports are never NAT-mapped.
pub const PUNCH_FIRST_PORT: u16 = 1024;
/// Frames pushed after a hit, to confirm the reverse direction.
pub const PUNCH_CONFIRM_FRAMES: usize = 6;
/// How long confirmation frames may keep being generated after a hit.
///
/// The scanning deadline stops applying once a hit lands, so confirmations need
/// their own bound; otherwise a daemon that stopped ticking would leave the
/// attempt in `Holding` forever.
pub const PUNCH_CONFIRM_TIMEOUT_MS: u64 = 5_000;

/// Which side of the punch this peer is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchRole {
    /// Behind an endpoint-dependent mapping. Opens many sockets towards the
    /// peer's single endpoint so their external ports form a contiguous block.
    Hard,
    /// Behind an endpoint-independent mapping. Walks a grid over the hard
    /// side's address from its one stable data socket.
    Easy,
}

impl PunchRole {
    /// Stable snake_case identifier for diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            PunchRole::Hard => "hard",
            PunchRole::Easy => "easy",
        }
    }
}

/// Observable phase of one attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchPhase {
    /// No attempt running.
    Idle,
    /// Probing or holding sockets open.
    Scanning,
    /// A hit was recorded and confirmation frames are still draining.
    Holding,
    /// A hit was recorded and the daemon has been told.
    Done,
    /// The attempt ended without a path.
    Failed,
}

impl PunchPhase {
    /// Stable snake_case identifier for diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            PunchPhase::Idle => "idle",
            PunchPhase::Scanning => "scanning",
            PunchPhase::Holding => "holding",
            PunchPhase::Done => "done",
            PunchPhase::Failed => "failed",
        }
    }
}

/// Why an attempt ended without a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchFailure {
    /// The attempt ran past its deadline.
    Deadline,
    /// The port grid was walked to exhaustion with no hit.
    ProbesExhausted,
    /// Both peers are behind endpoint-dependent mappings.
    BothHard,
    /// A mapping behaviour could not be classified, so no role could be chosen.
    MappingUnknown,
    /// The daemon stopped draining the punch outbox for long enough that the
    /// queue stayed saturated.
    OutboxSaturated,
}

impl PunchFailure {
    /// Stable snake_case identifier for diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            PunchFailure::Deadline => "deadline",
            PunchFailure::ProbesExhausted => "probes_exhausted",
            PunchFailure::BothHard => "both_hard",
            PunchFailure::MappingUnknown => "mapping_unknown",
            PunchFailure::OutboxSaturated => "outbox_saturated",
        }
    }
}

/// One queued punch frame, tagged with the socket slot that must send it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PunchFrame {
    /// Hard side: which punch socket. Easy side: always 0, the data socket.
    pub slot: u16,
    /// Destination address.
    pub target: Endpoint,
    /// Complete encoded frame.
    pub bytes: Vec<u8>,
}

/// Something the daemon must act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchEvent {
    /// Hard side: the named slot received a valid punch frame. Promote that
    /// socket to a real transport and close the rest.
    Promote {
        /// Winning slot index.
        slot: u16,
        /// The peer endpoint as it actually appeared on the wire.
        peer: Endpoint,
    },
    /// Easy side: a punch frame arrived from an endpoint that is not yet a
    /// candidate. Feed it to the engine's existing learned-path logic.
    Learned {
        /// The peer endpoint as it actually appeared on the wire.
        peer: Endpoint,
    },
    /// The attempt ended without a path.
    Failed(PunchFailure),
}

/// Static inputs for one attempt.
#[derive(Debug, Clone)]
pub struct PunchConfig {
    /// Which side this peer is.
    pub role: PunchRole,
    /// Hard side: the peer's complete endpoint. Easy side: only the address is
    /// used; the port is replaced by each grid step.
    pub peer_endpoint: Endpoint,
    /// Our own pinned discovery key.
    pub local_key: DiscoveryPublicKey,
    /// The pinned peer discovery key.
    pub peer_key: DiscoveryPublicKey,
    /// Relationship this attempt belongs to.
    pub relationship_id: RelationshipId,
    /// Our process epoch.
    pub boot_id: BootId,
    /// Our network generation.
    pub generation: u64,
    /// Our direction as a sender. The inbound direction must be its flip.
    pub direction: Direction,
    /// Sockets the hard side opens, clamped to `1..=PUNCH_HARD_SOCKETS`.
    pub hard_sockets: u16,
}

impl PunchConfig {
    /// Clamp the hard-side socket count into its supported range.
    pub fn normalized_hard_sockets(&self) -> usize {
        usize::from(self.hard_sockets).clamp(1, PUNCH_HARD_SOCKETS)
    }
}

/// A monotone, bounded sequence of ports to probe.
///
/// Abstracted so the grid can later be swapped for a randomised sequence if a
/// NAT is found that does not allocate contiguously.
pub trait PortSequence: fmt::Debug + Send {
    /// Next port, or `None` once the sequence is exhausted.
    fn next_port(&mut self) -> Option<u16>;
    /// Ports handed out so far.
    fn taken(&self) -> usize;
}

/// Evenly spaced grid over the usable port space.
#[derive(Debug, Clone)]
pub struct GridSequence {
    next: u32,
    step: u16,
    taken: usize,
    max: usize,
}

impl GridSequence {
    /// A grid starting at `first`, advancing by `step`, capped at `max` ports.
    pub fn new(first: u16, step: u16, max: usize) -> Self {
        Self {
            next: u32::from(first),
            step: step.max(1),
            taken: 0,
            max,
        }
    }

    /// The default grid used by the easy side.
    pub fn default_grid() -> Self {
        Self::new(PUNCH_FIRST_PORT, PUNCH_GRID_STEP, PUNCH_MAX_PROBES)
    }
}

impl PortSequence for GridSequence {
    fn next_port(&mut self) -> Option<u16> {
        if self.taken >= self.max || self.next > u32::from(u16::MAX) {
            return None;
        }
        let port = self.next as u16;
        self.next = self.next.saturating_add(u32::from(self.step));
        self.taken += 1;
        Some(port)
    }

    fn taken(&self) -> usize {
        self.taken
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SlotState {
    slot: u16,
    last_send_ms: u64,
}

/// A hit awaiting its confirmation frames.
///
/// Confirmations are generated in `tick`, never in `handle_inbound`, because
/// only `tick` receives the caller's randomness. Generating them inline would
/// mean either reusing the peer's nonce or reaching for entropy the sans-I/O
/// boundary forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConfirmState {
    slot: u16,
    target: Endpoint,
    sent: usize,
    deadline_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SeenNonce {
    boot_id: BootId,
    generation: u64,
    nonce: [u8; 32],
}

/// The punch state machine. Holds no socket and performs no I/O.
pub struct PunchState {
    config: PunchConfig,
    key: Key32,
    phase: PunchPhase,
    started_ms: u64,
    deadline_ms: u64,
    slots: Vec<SlotState>,
    ports: Box<dyn PortSequence>,
    outbox: VecDeque<PunchFrame>,
    nonces: VecDeque<SeenNonce>,
    probes_sent: u64,
    dropped: u64,
    ports_exhausted: bool,
    last_tick_ms: Option<u64>,
    last_outbox_len: usize,
    stalled_ms: u64,
    failure: Option<PunchFailure>,
    hit_port: Option<u16>,
    notified: bool,
    confirm: Option<ConfirmState>,
}

impl fmt::Debug for PunchState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PunchState")
            .field("role", &self.config.role)
            .field("phase", &self.phase)
            .field("slots", &self.slots.len())
            .field("probes_sent", &self.probes_sent)
            .field("dropped", &self.dropped)
            .field("outbox", &self.outbox.len())
            .field("nonces", &self.nonces.len())
            .field("hit_port", &self.hit_port)
            .field("failure", &self.failure)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl PunchState {
    /// Begin an attempt. The caller has already decided a punch is warranted.
    pub fn new(config: PunchConfig, key: Key32, now_ms: u64) -> Self {
        let slots = match config.role {
            PunchRole::Hard => (0..config.normalized_hard_sockets())
                .map(|slot| SlotState {
                    slot: slot as u16,
                    last_send_ms: now_ms.saturating_sub(PUNCH_KEEPALIVE_MS),
                })
                .collect(),
            PunchRole::Easy => Vec::new(),
        };
        Self {
            phase: PunchPhase::Scanning,
            started_ms: now_ms,
            deadline_ms: now_ms.saturating_add(match config.role {
                PunchRole::Hard => PUNCH_HARD_DEADLINE_MS,
                PunchRole::Easy => PUNCH_DEADLINE_MS,
            }),
            slots,
            ports: Box::new(GridSequence::default_grid()),
            outbox: VecDeque::new(),
            nonces: VecDeque::new(),
            probes_sent: 0,
            dropped: 0,
            ports_exhausted: false,
            last_tick_ms: None,
            last_outbox_len: 0,
            stalled_ms: 0,
            failure: None,
            hit_port: None,
            notified: false,
            confirm: None,
            config,
            key,
        }
    }

    /// Replace the port sequence. Only used by tests and future fallbacks.
    pub fn set_port_sequence(&mut self, ports: Box<dyn PortSequence>) {
        self.ports = ports;
    }

    /// Current phase.
    pub fn phase(&self) -> PunchPhase {
        self.phase
    }

    /// Which side this attempt is.
    pub fn role(&self) -> PunchRole {
        self.config.role
    }

    /// Why the attempt failed, if it did.
    pub fn failure(&self) -> Option<PunchFailure> {
        self.failure
    }

    /// Frames handed to the daemon so far. This counts frames queued for
    /// transmission, not packets the kernel acknowledged.
    pub fn probes_sent(&self) -> u64 {
        self.probes_sent
    }

    /// Frames dropped because the outbox was full.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// The peer port observed on the frame that produced a hit.
    ///
    /// On the easy side this is the hard side's real external port, which is
    /// the interesting number. On the hard side it is the easy side's port; the
    /// port of *our* socket that got hit is the slot in `PunchEvent::Promote`.
    pub fn hit_port(&self) -> Option<u16> {
        self.hit_port
    }

    /// Sockets the hard side is holding open.
    pub fn sockets_open(&self) -> u16 {
        self.slots.len() as u16
    }

    /// Queued frames not yet taken by the daemon.
    pub fn outbox_len(&self) -> usize {
        self.outbox.len()
    }

    /// Retained inbound nonces.
    pub fn nonce_ring_len(&self) -> usize {
        self.nonces.len()
    }

    /// When the attempt started, on the caller's monotonic clock.
    pub fn started_ms(&self) -> u64 {
        self.started_ms
    }

    /// Take the oldest queued frame. The daemon paces these with its own token
    /// bucket; this module never decides a transmission rate.
    pub fn next_frame(&mut self) -> Option<PunchFrame> {
        let frame = self.outbox.pop_front();
        if self.outbox.is_empty() && self.confirm.is_none() && self.phase == PunchPhase::Holding {
            self.phase = PunchPhase::Done;
        }
        frame
    }

    /// Whether confirmation frames are still owed.
    pub fn confirm_pending(&self) -> bool {
        self.confirm.is_some()
    }

    /// Advance timers and refill the outbox.
    pub fn tick(&mut self, now_ms: u64, nonce: &mut dyn FnMut() -> [u8; 32]) -> Vec<PunchEvent> {
        if !matches!(self.phase, PunchPhase::Scanning | PunchPhase::Holding) {
            return Vec::new();
        }
        if self.phase == PunchPhase::Holding {
            self.tick_confirm(now_ms, nonce);
            return Vec::new();
        }
        if now_ms >= self.deadline_ms {
            return self.fail(if self.ports_exhausted && self.outbox.is_empty() {
                PunchFailure::ProbesExhausted
            } else {
                PunchFailure::Deadline
            });
        }
        self.note_progress(now_ms);
        if self.stalled_ms >= PUNCH_STALL_MS {
            return self.fail(PunchFailure::OutboxSaturated);
        }
        match self.config.role {
            PunchRole::Hard => self.tick_hard(now_ms, nonce),
            PunchRole::Easy => self.tick_easy(now_ms, nonce),
        }
    }

    /// Generate outstanding confirmation frames with fresh nonces.
    fn tick_confirm(&mut self, now_ms: u64, nonce: &mut dyn FnMut() -> [u8; 32]) {
        let Some(mut confirm) = self.confirm else {
            return;
        };
        if now_ms >= confirm.deadline_ms {
            // The hit already happened; only the confirmations are abandoned.
            self.confirm = None;
            return;
        }
        while confirm.sent < PUNCH_CONFIRM_FRAMES {
            if self.outbox.len() >= PUNCH_OUTBOX {
                self.dropped = self.dropped.saturating_add(1);
                break;
            }
            match self.encode(now_ms, nonce) {
                Ok(bytes) => {
                    self.outbox.push_back(PunchFrame {
                        slot: confirm.slot,
                        target: confirm.target,
                        bytes,
                    });
                    confirm.sent += 1;
                }
                Err(()) => {
                    self.dropped = self.dropped.saturating_add(1);
                    break;
                }
            }
        }
        self.confirm = (confirm.sent < PUNCH_CONFIRM_FRAMES).then_some(confirm);
    }

    fn tick_hard(&mut self, now_ms: u64, nonce: &mut dyn FnMut() -> [u8; 32]) -> Vec<PunchEvent> {
        let target = self.config.peer_endpoint;
        for index in 0..self.slots.len() {
            let due = now_ms
                >= self.slots[index]
                    .last_send_ms
                    .saturating_add(PUNCH_KEEPALIVE_MS);
            if !due {
                continue;
            }
            let slot = self.slots[index].slot;
            let bytes = match self.encode(now_ms, nonce) {
                Ok(bytes) => bytes,
                Err(()) => {
                    self.dropped = self.dropped.saturating_add(1);
                    continue;
                }
            };
            if self.outbox.len() >= PUNCH_OUTBOX {
                self.dropped = self.dropped.saturating_add(1);
                continue;
            }
            self.outbox.push_back(PunchFrame {
                slot,
                target,
                bytes,
            });
            self.slots[index].last_send_ms = now_ms;
            self.probes_sent = self.probes_sent.saturating_add(1);
        }
        Vec::new()
    }

    fn tick_easy(&mut self, now_ms: u64, nonce: &mut dyn FnMut() -> [u8; 32]) -> Vec<PunchEvent> {
        let ip = self.config.peer_endpoint.ip;
        loop {
            if self.outbox.len() >= PUNCH_OUTBOX {
                // Still work left but nowhere to put it.
                break;
            }
            let Some(port) = self.ports.next_port() else {
                // The sequence ran out, which can happen before the probe cap
                // because the port space itself ends at 65535.
                self.ports_exhausted = true;
                break;
            };
            let bytes = match self.encode(now_ms, nonce) {
                Ok(bytes) => bytes,
                Err(()) => {
                    self.dropped = self.dropped.saturating_add(1);
                    continue;
                }
            };
            self.outbox.push_back(PunchFrame {
                slot: 0,
                target: Endpoint::new(ip, port),
                bytes,
            });
            self.probes_sent = self.probes_sent.saturating_add(1);
        }
        // Taking the last frame only means it was handed to the daemon. Keep
        // accepting replies until the attempt deadline, not just one tick.
        Vec::new()
    }

    /// Accumulate time during which queued frames were never taken.
    ///
    /// The outbox can never be a reliable capacity signal on its own: the
    /// default grid yields fewer ports than the outbox holds, so "full" is
    /// unreachable on the easy side. What actually indicates a stalled daemon
    /// is frames sitting in the queue across ticks without the length ever
    /// shrinking.
    fn note_progress(&mut self, now_ms: u64) {
        let elapsed = self
            .last_tick_ms
            .map_or(0, |previous| now_ms.saturating_sub(previous));
        self.last_tick_ms = Some(now_ms);
        if self.outbox.len() < self.last_outbox_len {
            // The daemon took at least one frame since the previous tick.
            self.stalled_ms = 0;
        } else if !self.outbox.is_empty() {
            self.stalled_ms = self.stalled_ms.saturating_add(elapsed);
        } else {
            self.stalled_ms = 0;
        }
        self.last_outbox_len = self.outbox.len();
    }

    /// Feed one datagram that arrived on a punch slot.
    pub fn handle_inbound(
        &mut self,
        slot: u16,
        source: Endpoint,
        datagram: &[u8],
        now_ms: u64,
    ) -> Vec<PunchEvent> {
        // Keep validating and recording during Holding so duplicate frames
        // are still deduplicated, but only the first hit produces an event.
        if !matches!(self.phase, PunchPhase::Scanning | PunchPhase::Holding) {
            return Vec::new();
        }
        let parsed = match parse_frame(datagram) {
            Ok(parsed) => parsed,
            Err(_) => return Vec::new(),
        };
        if parsed.header.frame_type != FrameType::Punch {
            return Vec::new();
        }
        if parsed.header.relationship_id != self.config.relationship_id {
            return Vec::new();
        }
        if !verify_frame_mac(&self.key, &parsed.raw_header(), parsed.payload, parsed.mac) {
            return Vec::new();
        }
        let payload = match PunchPayload::decode(parsed.payload) {
            Ok(payload) => payload,
            Err(_) => return Vec::new(),
        };
        if payload.sender != self.config.peer_key || payload.receiver != self.config.local_key {
            return Vec::new();
        }
        // A punch frame has no fixed direction, so the sender's pinned role
        // decides which direction byte is legitimate.
        if parsed.header.direction != self.config.direction.flipped() {
            return Vec::new();
        }
        if now_ms.abs_diff(payload.issued_at_unix_ms) > CLOCK_SKEW_TOLERANCE_MS {
            return Vec::new();
        }
        let seen = SeenNonce {
            boot_id: payload.boot_id,
            generation: payload.generation,
            nonce: payload.punch_nonce,
        };
        if self.nonces.contains(&seen) {
            return Vec::new();
        }
        if self.nonces.len() >= PUNCH_MAX_NONCES {
            self.nonces.pop_front();
        }
        self.nonces.push_back(seen);

        if self.phase == PunchPhase::Holding {
            // Already hit. The ring above still absorbed the duplicate.
            return Vec::new();
        }
        self.hit_port = Some(source.port);
        self.phase = PunchPhase::Holding;
        // Scanning is over. In particular, hard-side frames refer to sockets
        // the daemon is about to close; they must not precede confirmations.
        self.outbox.clear();
        // Only record what is owed. The frames themselves are built in `tick`,
        // which is the single place that owns the caller's randomness.
        self.confirm = Some(ConfirmState {
            slot,
            target: source,
            sent: 0,
            deadline_ms: now_ms.saturating_add(PUNCH_CONFIRM_TIMEOUT_MS),
        });
        if self.notified {
            return Vec::new();
        }
        self.notified = true;
        match self.config.role {
            PunchRole::Hard => vec![PunchEvent::Promote { slot, peer: source }],
            PunchRole::Easy => vec![PunchEvent::Learned { peer: source }],
        }
    }

    fn encode(&self, now_ms: u64, nonce: &mut dyn FnMut() -> [u8; 32]) -> Result<Vec<u8>, ()> {
        let payload = PunchPayload {
            sender: self.config.local_key,
            receiver: self.config.peer_key,
            boot_id: self.config.boot_id,
            generation: self.config.generation,
            issued_at_unix_ms: now_ms,
            punch_nonce: nonce(),
        };
        debug_assert_eq!(payload.encode().len(), PUNCH_PAYLOAD_LEN);
        encode_frame(
            FrameType::Punch,
            self.config.direction,
            self.config.relationship_id,
            0,
            0,
            &payload.encode(),
            &self.key,
        )
        .map_err(|_| ())
    }

    fn fail(&mut self, failure: PunchFailure) -> Vec<PunchEvent> {
        self.phase = PunchPhase::Failed;
        self.failure = Some(failure);
        self.outbox.clear();
        self.confirm = None;
        vec![PunchEvent::Failed(failure)]
    }

    /// Stop the attempt and discard queued frames.
    pub fn stop(&mut self) {
        self.outbox.clear();
        self.confirm = None;
        if matches!(self.phase, PunchPhase::Scanning | PunchPhase::Holding) {
            self.phase = PunchPhase::Idle;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::parse_frame;

    const T0: u64 = 1_762_920_000_000;

    fn pk(b: u8) -> DiscoveryPublicKey {
        DiscoveryPublicKey::from_bytes([b; 32])
    }

    fn boot(b: u8) -> BootId {
        BootId::from_bytes([b; 16])
    }

    fn ep(ip: [u8; 4], port: u16) -> Endpoint {
        Endpoint::new(std::net::Ipv4Addr::from(ip), port)
    }

    fn key() -> Key32 {
        Key32::from_bytes([5u8; 32])
    }

    /// The lo side: direction LoToHi, local key is the smaller one.
    fn lo_config(role: PunchRole, hard_sockets: u16) -> PunchConfig {
        PunchConfig {
            role,
            peer_endpoint: ep([203, 0, 113, 9], 40000),
            local_key: pk(0x00),
            peer_key: pk(0x20),
            relationship_id: RelationshipId::from_bytes([7u8; 16]),
            boot_id: boot(0x80),
            generation: 1,
            direction: Direction::LoToHi,
            hard_sockets,
        }
    }

    /// The hi side, mirrored so a frame from one verifies on the other.
    fn hi_config(role: PunchRole, hard_sockets: u16) -> PunchConfig {
        PunchConfig {
            local_key: pk(0x20),
            peer_key: pk(0x00),
            direction: Direction::HiToLo,
            boot_id: boot(0x90),
            generation: 2,
            ..lo_config(role, hard_sockets)
        }
    }

    fn counter() -> impl FnMut() -> [u8; 32] {
        let mut n = 0u8;
        move || {
            n = n.wrapping_add(1);
            [n; 32]
        }
    }

    fn drain(state: &mut PunchState) -> Vec<PunchFrame> {
        let mut out = Vec::new();
        while let Some(frame) = state.next_frame() {
            out.push(frame);
        }
        out
    }

    #[test]
    fn the_grid_step_and_the_hard_block_width_are_a_matched_pair() {
        // The whole design rests on this: an easy side walking a grid of step G
        // is only guaranteed to land inside the hard side's block when the block
        // is at least G wide, and half-width is the tolerance that absorbs the
        // allocation noise seen on a real carrier NAT.
        assert!(
            PUNCH_GRID_STEP as usize * 2 <= PUNCH_HARD_SOCKETS,
            "grid step {} needs at least {} hard-side sockets, only {} are opened",
            PUNCH_GRID_STEP,
            PUNCH_GRID_STEP as usize * 2,
            PUNCH_HARD_SOCKETS
        );
        // And the probe cap must actually cover the port space at that step.
        let needed = (u32::from(u16::MAX) - u32::from(PUNCH_FIRST_PORT))
            .div_ceil(u32::from(PUNCH_GRID_STEP));
        assert!(
            needed as usize <= PUNCH_MAX_PROBES,
            "{needed} probes needed at step {} but the cap is {PUNCH_MAX_PROBES}",
            PUNCH_GRID_STEP
        );
    }

    #[test]
    fn grid_is_monotonic_bounded_and_skips_well_known_ports() {
        let mut grid = GridSequence::default_grid();
        let mut previous = 0u16;
        let mut count = 0usize;
        while let Some(port) = grid.next_port() {
            assert!(port >= PUNCH_FIRST_PORT, "port {port} below the floor");
            if count > 0 {
                assert_eq!(
                    port,
                    previous + PUNCH_GRID_STEP,
                    "grid must advance by exactly one step"
                );
            }
            previous = port;
            count += 1;
            assert!(count <= PUNCH_MAX_PROBES, "grid exceeded its cap");
        }
        assert_eq!(grid.taken(), count);
        // The port space ends before the probe cap, so the sequence is bounded
        // by whichever comes first.
        assert!(count > 0 && count <= PUNCH_MAX_PROBES);
        // Exhausted sequences stay exhausted.
        assert_eq!(grid.next_port(), None);
    }

    #[test]
    fn grid_always_intersects_a_block_at_least_as_wide_as_its_step() {
        // The deterministic-hit property the whole design rests on: for any
        // contiguous block of width >= the grid step, some grid point lands
        // inside it. Checked over the entire usable port space.
        let step = PUNCH_GRID_STEP;
        let mut sequence = GridSequence::default_grid();
        let points: Vec<u16> = std::iter::from_fn(|| sequence.next_port()).collect();
        assert!(!points.is_empty());
        let last_start = u32::from(u16::MAX) - u32::from(step);
        for start in u32::from(PUNCH_FIRST_PORT)..=last_start {
            let low = start as u16;
            let high = low + step;
            let index = points.partition_point(|&p| p < low);
            assert!(
                index < points.len() && points[index] < high,
                "grid with step {step} missed the block [{low}, {high})"
            );
        }
    }

    #[test]
    fn a_step_wider_than_the_block_can_miss_it() {
        // The converse, so the G <= K/2 rule is not just asserted but shown to
        // be load-bearing.
        let mut sequence = GridSequence::new(PUNCH_FIRST_PORT, 512, PUNCH_MAX_PROBES);
        let points: Vec<u16> = std::iter::from_fn(|| sequence.next_port()).collect();
        let narrow = 8u16;
        // Offset by half a step so the blocks sit between grid points rather
        // than on them, which is the only way a wide grid can miss them.
        let missed = (u32::from(PUNCH_FIRST_PORT) + 256..60000)
            .step_by(512)
            .any(|start| {
                let low = start as u16;
                let high = low + narrow;
                !points.iter().any(|&p| p >= low && p < high)
            });
        assert!(
            missed,
            "a 512-wide grid should be able to skip an 8-wide block"
        );
    }

    #[test]
    fn easy_side_walks_the_grid_over_the_peer_address_only() {
        let mut state = PunchState::new(lo_config(PunchRole::Easy, 0), key(), T0);
        state.tick(T0, &mut counter());
        let frames = drain(&mut state);
        assert_eq!(frames[0].target.port, PUNCH_FIRST_PORT);
        assert_eq!(frames[1].target.port, PUNCH_FIRST_PORT + PUNCH_GRID_STEP);
        for frame in &frames {
            // Only the port varies; the address is the peer's advertised one.
            assert_eq!(frame.target.ip, ep([203, 0, 113, 9], 0).ip);
            assert_eq!(frame.slot, 0, "the easy side uses its data socket");
        }
        assert_eq!(state.sockets_open(), 0);
        assert_eq!(state.role(), PunchRole::Easy);
    }

    #[test]
    fn a_drained_grid_waits_for_replies_until_its_deadline() {
        let mut state = PunchState::new(lo_config(PunchRole::Easy, 0), key(), T0);
        let mut nonce = counter();
        state.tick(T0, &mut nonce);
        assert!(!drain(&mut state).is_empty());
        assert!(state.tick(T0 + 250, &mut nonce).is_empty());
        assert!(
            state
                .tick(T0 + PUNCH_DEADLINE_MS - 1, &mut nonce)
                .is_empty()
        );
        assert_eq!(state.phase(), PunchPhase::Scanning);
        assert_eq!(
            state.tick(T0 + PUNCH_DEADLINE_MS, &mut nonce),
            vec![PunchEvent::Failed(PunchFailure::ProbesExhausted)]
        );
    }

    #[test]
    fn a_late_reply_to_the_last_grid_batch_is_still_accepted() {
        let mut easy = PunchState::new(lo_config(PunchRole::Easy, 0), key(), T0);
        easy.tick(T0, &mut counter());
        drain(&mut easy);
        easy.tick(T0 + 250, &mut counter());
        let hard = PunchState::new(hi_config(PunchRole::Hard, 256), key(), T0);
        let frame = valid_punch_frame(&hard, T0 + 1_000, 0xee);
        assert!(matches!(
            easy.handle_inbound(0, ep([198, 51, 100, 7], 65_408), &frame, T0 + 1_000)
                .as_slice(),
            [PunchEvent::Learned { .. }]
        ));
    }

    #[test]
    fn a_hit_discards_queued_frames_for_losing_sockets() {
        let mut hard = PunchState::new(hi_config(PunchRole::Hard, 256), key(), T0);
        hard.tick(T0, &mut counter());
        for _ in 0..100 {
            hard.next_frame().unwrap();
        }
        assert_eq!(hard.outbox_len(), 156);
        let easy = PunchState::new(lo_config(PunchRole::Easy, 0), key(), T0);
        let frame = valid_punch_frame(&easy, T0, 0xef);
        hard.handle_inbound(0, ep([198, 51, 100, 7], 51_000), &frame, T0);
        assert_eq!(hard.outbox_len(), 0);
        hard.tick(T0 + 250, &mut counter());
        let confirms = drain(&mut hard);
        assert_eq!(confirms.len(), PUNCH_CONFIRM_FRAMES);
        assert!(confirms.iter().all(|frame| frame.slot == 0));
    }

    #[test]
    fn the_hard_window_covers_paced_signaling_and_peer_propagation() {
        let mut hard = PunchState::new(hi_config(PunchRole::Hard, 256), key(), T0);
        hard.tick(T0, &mut counter());
        drain(&mut hard);
        assert!(hard.tick(T0 + 120_000, &mut counter()).is_empty());
        drain(&mut hard);
        assert_eq!(hard.phase(), PunchPhase::Scanning);
        assert_eq!(
            hard.tick(T0 + PUNCH_HARD_DEADLINE_MS, &mut counter()),
            vec![PunchEvent::Failed(PunchFailure::Deadline)]
        );
    }

    #[test]
    fn deadline_fails_the_attempt_and_clears_queued_frames() {
        let mut state = PunchState::new(lo_config(PunchRole::Easy, 0), key(), T0);
        state.tick(T0, &mut counter());
        assert!(state.outbox_len() > 0);
        let events = state.tick(T0 + PUNCH_DEADLINE_MS, &mut counter());
        assert_eq!(events, vec![PunchEvent::Failed(PunchFailure::Deadline)]);
        assert_eq!(state.outbox_len(), 0);
        assert_eq!(state.next_frame(), None);
    }

    #[test]
    fn hard_side_fills_every_slot_once_then_respects_keepalive() {
        let mut state = PunchState::new(hi_config(PunchRole::Hard, 8), key(), T0);
        state.tick(T0, &mut counter());
        let first = drain(&mut state);
        assert_eq!(first.len(), 8, "one frame per slot on the first tick");
        let mut slots: Vec<u16> = first.iter().map(|f| f.slot).collect();
        slots.sort_unstable();
        assert_eq!(slots, (0..8u16).collect::<Vec<_>>());
        for frame in &first {
            // The hard side targets the peer's exact advertised endpoint.
            assert_eq!(frame.target, ep([203, 0, 113, 9], 40000));
        }
        // Nothing is due before the keepalive interval.
        state.tick(T0 + PUNCH_KEEPALIVE_MS - 1, &mut counter());
        assert_eq!(state.outbox_len(), 0);
        // Every slot is due again afterwards.
        state.tick(T0 + PUNCH_KEEPALIVE_MS, &mut counter());
        assert_eq!(drain(&mut state).len(), 8);
        assert_eq!(state.sockets_open(), 8);
    }

    #[test]
    fn hard_socket_count_is_clamped_to_its_supported_range() {
        assert_eq!(lo_config(PunchRole::Hard, 0).normalized_hard_sockets(), 1);
        assert_eq!(
            lo_config(PunchRole::Hard, u16::MAX).normalized_hard_sockets(),
            PUNCH_HARD_SOCKETS
        );
        assert_eq!(lo_config(PunchRole::Hard, 64).normalized_hard_sockets(), 64);
    }

    #[test]
    fn a_stalled_daemon_fails_the_attempt_within_the_stall_window() {
        // An easy side whose frames are never taken fills the outbox on the
        // first tick and then sits there, exactly as a stalled daemon looks.
        let mut state = PunchState::new(lo_config(PunchRole::Easy, 0), key(), T0);
        let mut nonce = counter();
        let mut failed = None;
        let mut failed_at = 0u64;
        for step in 0..64u64 {
            let now = T0 + step * 500;
            for event in state.tick(now, &mut nonce) {
                if let PunchEvent::Failed(reason) = event {
                    failed = Some(reason);
                    failed_at = now;
                }
            }
            assert!(
                state.outbox_len() <= PUNCH_OUTBOX,
                "outbox grew past its bound"
            );
            if failed.is_some() {
                break;
            }
        }
        assert_eq!(failed, Some(PunchFailure::OutboxSaturated));
        assert_eq!(state.phase(), PunchPhase::Failed);
        assert_eq!(state.outbox_len(), 0);
        // It fires on the stall window, not on the much longer deadline.
        assert!(
            failed_at - T0 >= PUNCH_STALL_MS,
            "fired before the stall window"
        );
        assert!(
            failed_at - T0 < PUNCH_DEADLINE_MS,
            "the deadline won the race"
        );
    }

    #[test]
    fn a_draining_daemon_is_never_mistaken_for_a_stall() {
        let mut state = PunchState::new(lo_config(PunchRole::Easy, 0), key(), T0);
        let mut nonce = counter();
        for step in 0..40u64 {
            let events = state.tick(T0 + step * 500, &mut nonce);
            let stalled = events
                .iter()
                .any(|event| matches!(event, PunchEvent::Failed(PunchFailure::OutboxSaturated)));
            assert!(
                !stalled,
                "a daemon that takes frames must never look stalled"
            );
            drain(&mut state);
        }
    }

    fn valid_punch_frame(sender: &PunchState, now_ms: u64, nonce_byte: u8) -> Vec<u8> {
        punch_frame_with_nonce(sender, now_ms, [nonce_byte; 32])
    }

    fn punch_frame_with_nonce(sender: &PunchState, now_ms: u64, punch_nonce: [u8; 32]) -> Vec<u8> {
        let payload = PunchPayload {
            sender: sender.config.local_key,
            receiver: sender.config.peer_key,
            boot_id: sender.config.boot_id,
            generation: sender.config.generation,
            issued_at_unix_ms: now_ms,
            punch_nonce,
        };
        encode_frame(
            FrameType::Punch,
            sender.config.direction,
            sender.config.relationship_id,
            0,
            0,
            &payload.encode(),
            &key(),
        )
        .unwrap()
    }

    #[test]
    fn hard_side_promotes_exactly_once_and_queues_confirmations() {
        let mut hard = PunchState::new(hi_config(PunchRole::Hard, 4), key(), T0);
        let source = ep([198, 51, 100, 7], 51234);
        let frame = valid_punch_frame(
            &PunchState::new(lo_config(PunchRole::Easy, 0), key(), T0),
            T0,
            0xaa,
        );
        let events = hard.handle_inbound(2, source, &frame, T0);
        assert_eq!(
            events,
            vec![PunchEvent::Promote {
                slot: 2,
                peer: source
            }]
        );
        assert_eq!(hard.hit_port(), Some(51234));
        // Nothing is queued yet: frames are only ever built in `tick`, which is
        // the one place that owns the caller's randomness.
        assert_eq!(hard.outbox_len(), 0);
        assert!(hard.confirm_pending());
        hard.tick(T0, &mut counter());
        let confirms = drain(&mut hard);
        assert_eq!(confirms.len(), PUNCH_CONFIRM_FRAMES);
        let mut nonces = std::collections::BTreeSet::new();
        for confirm in &confirms {
            assert_eq!(confirm.slot, 2, "confirmations come from the winning slot");
            assert_eq!(confirm.target, source, "and target the observed source");
            let parsed = parse_frame(&confirm.bytes).unwrap();
            let payload = PunchPayload::decode(parsed.payload).unwrap();
            // The inbound frame carried 0xaa. A confirmation must never echo
            // the peer's own nonce back onto the wire.
            assert_ne!(
                payload.punch_nonce, [0xaa; 32],
                "must not echo the peer nonce"
            );
            assert!(
                nonces.insert(payload.punch_nonce),
                "every confirmation needs its own nonce"
            );
        }
        assert_eq!(nonces.len(), PUNCH_CONFIRM_FRAMES);
        assert_eq!(hard.phase(), PunchPhase::Done);
        // A second identical frame is deduplicated and promotes nothing further.
        assert!(hard.handle_inbound(2, source, &frame, T0).is_empty());
        // And a different slot cannot promote after the hit either.
        let other = valid_punch_frame(
            &PunchState::new(lo_config(PunchRole::Easy, 0), key(), T0),
            T0,
            0xbb,
        );
        assert!(hard.handle_inbound(3, source, &other, T0).is_empty());
    }

    #[test]
    fn easy_side_learns_exactly_once() {
        let mut easy = PunchState::new(lo_config(PunchRole::Easy, 0), key(), T0);
        let source = ep([198, 51, 100, 7], 14528);
        let frame = valid_punch_frame(
            &PunchState::new(hi_config(PunchRole::Hard, 4), key(), T0),
            T0,
            0xcc,
        );
        let events = easy.handle_inbound(0, source, &frame, T0);
        assert_eq!(events, vec![PunchEvent::Learned { peer: source }]);
        assert_eq!(easy.hit_port(), Some(14528));
        easy.tick(T0, &mut counter());
        let confirms = drain(&mut easy);
        assert_eq!(confirms.len(), PUNCH_CONFIRM_FRAMES);
        for confirm in &confirms {
            assert_eq!(confirm.slot, 0);
            assert_eq!(confirm.target, source);
        }
    }

    #[test]
    fn nonce_ring_is_bounded_and_deduplicates() {
        let mut easy = PunchState::new(lo_config(PunchRole::Easy, 0), key(), T0);
        let source = ep([198, 51, 100, 7], 40000);
        let hard = PunchState::new(hi_config(PunchRole::Hard, 4), key(), T0);
        // Every frame carries a distinct nonce, so only the ring bound can
        // stop it growing. The first frame hits; the rest are absorbed.
        for i in 0..(PUNCH_MAX_NONCES + 40) {
            let mut nonce = [0u8; 32];
            nonce[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let frame = punch_frame_with_nonce(&hard, T0, nonce);
            let events = easy.handle_inbound(0, source, &frame, T0);
            if i == 0 {
                assert_eq!(events, vec![PunchEvent::Learned { peer: source }]);
            } else {
                assert!(events.is_empty(), "only the first hit may produce an event");
            }
            assert!(easy.nonce_ring_len() <= PUNCH_MAX_NONCES);
        }
        assert_eq!(easy.nonce_ring_len(), PUNCH_MAX_NONCES);
        assert_eq!(easy.phase(), PunchPhase::Holding);
        // A replay of an already-seen nonce is refused without growing the ring.
        let mut replay = [0u8; 32];
        replay[..8].copy_from_slice(&0u64.to_be_bytes());
        let frame = punch_frame_with_nonce(&hard, T0, replay);
        assert!(easy.handle_inbound(0, source, &frame, T0).is_empty());
        assert_eq!(easy.nonce_ring_len(), PUNCH_MAX_NONCES);
    }

    #[test]
    fn confirmations_are_abandoned_after_their_own_timeout() {
        // A hit cancels the scanning deadline, so confirmations need a bound of
        // their own or a daemon that stopped ticking would wedge the attempt in
        // Holding forever.
        let mut easy = PunchState::new(lo_config(PunchRole::Easy, 0), key(), T0);
        let source = ep([198, 51, 100, 7], 40_000);
        let frame = valid_punch_frame(
            &PunchState::new(hi_config(PunchRole::Hard, 4), key(), T0),
            T0,
            0x31,
        );
        easy.handle_inbound(0, source, &frame, T0);
        assert!(easy.confirm_pending());
        easy.tick(T0 + PUNCH_CONFIRM_TIMEOUT_MS, &mut counter());
        assert!(!easy.confirm_pending());
        assert!(drain(&mut easy).is_empty());
        assert_eq!(easy.phase(), PunchPhase::Done);
        // The hit itself is unaffected; only the confirmations were abandoned.
        assert_eq!(easy.hit_port(), Some(40_000));
    }

    #[test]
    fn inbound_validation_rejects_every_forgery() {
        let source = ep([198, 51, 100, 7], 40000);
        let good = valid_punch_frame(
            &PunchState::new(hi_config(PunchRole::Hard, 4), key(), T0),
            T0,
            0x11,
        );

        // A well-formed frame from the real peer is accepted.
        let mut ok = PunchState::new(lo_config(PunchRole::Easy, 0), key(), T0);
        assert_eq!(ok.handle_inbound(0, source, &good, T0).len(), 1);

        let reject = |frame: &[u8], now: u64| {
            let mut state = PunchState::new(lo_config(PunchRole::Easy, 0), key(), T0);
            state.handle_inbound(0, source, frame, now).is_empty()
        };

        // Tampered MAC.
        let mut bad_mac = good.clone();
        let last = bad_mac.len() - 1;
        bad_mac[last] ^= 1;
        assert!(reject(&bad_mac, T0), "bad MAC must be refused");

        // Wrong key entirely.
        let wrong_key = {
            let payload = PunchPayload {
                sender: pk(0x20),
                receiver: pk(0x00),
                boot_id: boot(0x90),
                generation: 2,
                issued_at_unix_ms: T0,
                punch_nonce: [0x12; 32],
            };
            encode_frame(
                FrameType::Punch,
                Direction::HiToLo,
                RelationshipId::from_bytes([7u8; 16]),
                0,
                0,
                &payload.encode(),
                &Key32::from_bytes([6u8; 32]),
            )
            .unwrap()
        };
        assert!(reject(&wrong_key, T0), "wrong MAC key must be refused");

        // Sender is not the pinned peer.
        let wrong_sender = {
            let payload = PunchPayload {
                sender: pk(0x40),
                receiver: pk(0x00),
                boot_id: boot(0x90),
                generation: 2,
                issued_at_unix_ms: T0,
                punch_nonce: [0x13; 32],
            };
            encode_frame(
                FrameType::Punch,
                Direction::HiToLo,
                RelationshipId::from_bytes([7u8; 16]),
                0,
                0,
                &payload.encode(),
                &key(),
            )
            .unwrap()
        };
        assert!(reject(&wrong_sender, T0), "unpinned sender must be refused");

        // Direction does not match the sender's pinned role.
        let wrong_direction = {
            let payload = PunchPayload {
                sender: pk(0x20),
                receiver: pk(0x00),
                boot_id: boot(0x90),
                generation: 2,
                issued_at_unix_ms: T0,
                punch_nonce: [0x14; 32],
            };
            encode_frame(
                FrameType::Punch,
                Direction::LoToHi,
                RelationshipId::from_bytes([7u8; 16]),
                0,
                0,
                &payload.encode(),
                &key(),
            )
            .unwrap()
        };
        assert!(
            reject(&wrong_direction, T0),
            "direction inconsistent with the sender role must be refused"
        );

        // Wrong relationship.
        let wrong_relationship = {
            let payload = PunchPayload {
                sender: pk(0x20),
                receiver: pk(0x00),
                boot_id: boot(0x90),
                generation: 2,
                issued_at_unix_ms: T0,
                punch_nonce: [0x15; 32],
            };
            encode_frame(
                FrameType::Punch,
                Direction::HiToLo,
                RelationshipId::from_bytes([9u8; 16]),
                0,
                0,
                &payload.encode(),
                &key(),
            )
            .unwrap()
        };
        assert!(
            reject(&wrong_relationship, T0),
            "wrong relationship must be refused"
        );

        // Clock skew beyond tolerance, in both directions.
        assert!(
            reject(&good, T0 + CLOCK_SKEW_TOLERANCE_MS + 1),
            "stale frame must be refused"
        );
        assert!(
            reject(&good, T0 - CLOCK_SKEW_TOLERANCE_MS - 1),
            "future frame must be refused"
        );
        // ...but exactly at the tolerance boundary it is still accepted.
        assert!(!reject(&good, T0 + CLOCK_SKEW_TOLERANCE_MS));

        // Not a punch frame at all.
        let hello = encode_frame(
            FrameType::Hello,
            Direction::LoToHi,
            RelationshipId::from_bytes([7u8; 16]),
            0,
            0,
            &[0u8; crate::wire::HANDSHAKE_PAYLOAD_LEN],
            &key(),
        )
        .unwrap();
        assert!(reject(&hello, T0), "a non-punch frame must be ignored");

        // Truncated and empty input.
        assert!(reject(&good[..40], T0));
        assert!(reject(&[], T0));
    }

    #[test]
    fn every_emitted_frame_is_a_valid_punch_frame() {
        for role in [PunchRole::Hard, PunchRole::Easy] {
            let mut state = PunchState::new(lo_config(role, 4), key(), T0);
            state.tick(T0, &mut counter());
            let frames = drain(&mut state);
            assert!(!frames.is_empty());
            for frame in &frames {
                let parsed = parse_frame(&frame.bytes).unwrap();
                assert_eq!(parsed.header.frame_type, FrameType::Punch);
                assert_eq!(parsed.header.session_id, 0);
                assert_eq!(parsed.header.sequence, 0);
                assert_eq!(parsed.header.direction, Direction::LoToHi);
                assert_eq!(parsed.payload.len(), PUNCH_PAYLOAD_LEN);
                let payload = PunchPayload::decode(parsed.payload).unwrap();
                assert_eq!(payload.sender, pk(0x00));
                assert_eq!(payload.receiver, pk(0x20));
                assert_eq!(payload.issued_at_unix_ms, T0);
                // No amplification: a punch frame is exactly probe-sized.
                assert_eq!(
                    frame.bytes.len(),
                    crate::wire::FRAME_OVERHEAD + PUNCH_PAYLOAD_LEN
                );
            }
        }
    }

    #[test]
    fn stop_clears_queued_frames_and_returns_to_idle() {
        let mut state = PunchState::new(lo_config(PunchRole::Easy, 0), key(), T0);
        state.tick(T0, &mut counter());
        assert!(state.outbox_len() > 0);
        state.stop();
        assert_eq!(state.outbox_len(), 0);
        assert_eq!(state.phase(), PunchPhase::Idle);
        assert_eq!(state.next_frame(), None);
        // A stopped machine produces nothing further.
        assert!(state.tick(T0 + 1, &mut counter()).is_empty());
    }

    #[test]
    fn a_finished_attempt_ignores_later_ticks_and_inbound() {
        let mut easy = PunchState::new(lo_config(PunchRole::Easy, 0), key(), T0);
        let source = ep([198, 51, 100, 7], 40000);
        let frame = valid_punch_frame(
            &PunchState::new(hi_config(PunchRole::Hard, 4), key(), T0),
            T0,
            0x21,
        );
        easy.handle_inbound(0, source, &frame, T0);
        easy.tick(T0, &mut counter());
        assert_eq!(drain(&mut easy).len(), PUNCH_CONFIRM_FRAMES);
        assert_eq!(easy.phase(), PunchPhase::Done);
        assert!(easy.tick(T0 + 1, &mut counter()).is_empty());
        assert!(easy.handle_inbound(0, source, &frame, T0).is_empty());
        assert_eq!(easy.outbox_len(), 0);
    }

    #[test]
    fn debug_output_never_reveals_the_key() {
        let state = PunchState::new(lo_config(PunchRole::Easy, 0), key(), T0);
        let rendered = format!("{state:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("0505"));
    }
}
