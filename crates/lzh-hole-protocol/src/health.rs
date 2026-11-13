//! Health challenges and the promotion rule for reporting a direct path.
//!
//! Receiving an ACK or business data never establishes health on its own. A
//! side reports Direct / currently_healthy only when it has completed its own
//! PING -> matching PONG round trip on the currently verified endpoint of the
//! current session, AND has seen the peer assert the same for itself.
//!
//! local_confirmed is recomputed from live state every time it is read. It is
//! never sticky after a first success.

use std::collections::VecDeque;

use crate::path::Endpoint;
use crate::wire::{CtrlPayload, FLAG_LOCAL_CONFIRMED, FLAG_PATH_PROBE, WireError};
use lzh_hole_types::BootId;

/// Outstanding challenge nonces per direction.
pub const MAX_PENDING_PINGS: usize = 4;
/// How long a challenge may wait for its response.
pub const PING_DEADLINE_MS: u64 = 10_000;
/// Challenge interval while still confirming.
pub const CONFIRM_INTERVAL_MS: u64 = 1_000;
/// Challenge interval once confirmed.
pub const STEADY_INTERVAL_MS: u64 = 5_000;
/// No valid reply for this long: Suspect.
pub const SUSPECT_AFTER_MS: u64 = 20_000;
/// No valid reply for this long: Offline.
pub const OFFLINE_AFTER_MS: u64 = 30_000;
/// Bounded outbound PONG queue.
pub const PONG_QUEUE_CAPACITY: usize = 8;

/// Coarse health of the current path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// Bidirectional round trip is fresh.
    Healthy,
    /// Replies have stopped arriving but we are not yet offline.
    Suspect,
    /// No valid reply for long enough to declare the path down.
    Offline,
    /// Nothing has ever been confirmed.
    Unknown,
}

/// One outstanding challenge, bound to where and when it was sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPing {
    /// The fresh nonce.
    pub nonce: [u8; 32],
    /// Endpoint it went to.
    pub endpoint: Endpoint,
    /// Local process epoch at send time.
    pub boot_id: BootId,
    /// Peer's process epoch at send time.
    pub peer_boot_id: BootId,
    /// Local network generation at send time.
    pub generation: u64,
    /// Peer's network generation at send time.
    pub peer_generation: u64,
    /// Session it was sent under.
    pub session_id: u64,
    /// When it was actually put on the wire.
    pub sent_ms: u64,
    /// Whether this challenge is a return-path probe.
    pub path_probe: bool,
}

/// What a received PONG turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PongOutcome {
    /// A first, unique answer to one of our outstanding challenges.
    Accepted {
        /// Round trip time in milliseconds.
        rtt_ms: u64,
        /// Whether it answered a path probe.
        path_probe: bool,
    },
    /// The nonce was already answered. Does not refresh health.
    Duplicate,
    /// No such outstanding challenge.
    Unknown,
    /// The answer is bound to a stale session, generation or endpoint.
    Stale,
    /// The peer reused a nonce with a different frame.
    NonceReuse,
}

/// A bounded queue that drops its oldest entry rather than growing.
#[derive(Debug, Default, Clone)]
pub struct BoundedQueue<T> {
    items: VecDeque<T>,
    dropped: u64,
}

impl<T> BoundedQueue<T> {
    /// An empty queue with the given capacity.
    pub fn new() -> Self {
        Self {
            items: VecDeque::new(),
            dropped: 0,
        }
    }

    /// Push, dropping the oldest entry when full.
    pub fn push(&mut self, item: T) {
        if self.items.len() >= PONG_QUEUE_CAPACITY {
            self.items.pop_front();
            self.dropped += 1;
        }
        self.items.push_back(item);
    }

    /// Take the oldest entry.
    pub fn pop(&mut self) -> Option<T> {
        self.items.pop_front()
    }

    /// Current depth.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// How many entries were discarded to stay bounded.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

/// The complete context in which a health observation is meaningful.
///
/// A PONG or a peer confirmation is only evidence when it belongs to the same
/// selected endpoint, session and both epochs. The selected flag is false while
/// we are still proving an endpoint; it prevents an unselected source from ever
/// contributing to a bilateral confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathContext {
    /// The endpoint the observation came from.
    pub endpoint: Endpoint,
    /// Current session.
    pub session_id: u64,
    /// Local network generation.
    pub generation: u64,
    /// Peer's network generation.
    pub peer_generation: u64,
    /// Local process epoch.
    pub local_boot_id: BootId,
    /// Peer's process epoch.
    pub peer_boot_id: BootId,
    /// Whether this endpoint is the currently selected path.
    pub selected: bool,
}

/// Live health bookkeeping for one peer.
#[derive(Debug, Clone)]
pub struct HealthState {
    pending: Vec<PendingPing>,
    answered: VecDeque<[u8; 32]>,
    last_round_trip: Option<RoundTrip>,
    peer_confirmation: Option<PeerConfirmation>,
    last_ping_sent_ms: Option<u64>,
    last_valid_reply_ms: Option<u64>,
    round_trips: u64,
    duplicates: u64,
    stale: u64,
    unknown: u64,
    peer_pings: u64,
    outbox: BoundedQueue<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RoundTrip {
    at_ms: u64,
    context: PathContext,
}

/// A peer's bit0 claim, bound to the exact path and epochs it arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeerConfirmation {
    at_ms: u64,
    context: PathContext,
}

impl Default for HealthState {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthState {
    /// Fresh state with nothing confirmed.
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
            answered: VecDeque::new(),
            last_round_trip: None,
            peer_confirmation: None,
            last_ping_sent_ms: None,
            last_valid_reply_ms: None,
            round_trips: 0,
            duplicates: 0,
            stale: 0,
            unknown: 0,
            peer_pings: 0,
            outbox: BoundedQueue::new(),
        }
    }

    /// Outstanding challenges.
    pub fn pending(&self) -> &[PendingPing] {
        &self.pending
    }

    /// Completed round trips.
    pub fn round_trips(&self) -> u64 {
        self.round_trips
    }

    /// Duplicate answers seen.
    pub fn duplicates(&self) -> u64 {
        self.duplicates
    }

    /// Answers discarded as stale.
    pub fn stale(&self) -> u64 {
        self.stale
    }

    /// Answers that matched nothing.
    pub fn unknown(&self) -> u64 {
        self.unknown
    }

    /// Peer challenges received.
    pub fn peer_pings(&self) -> u64 {
        self.peer_pings
    }

    /// Age of the last valid reply, if any.
    pub fn last_valid_reply_age_ms(&self, now_ms: u64) -> Option<u64> {
        self.last_valid_reply_ms.map(|t| now_ms.saturating_sub(t))
    }

    /// Whether a challenge is due.
    pub fn ping_due(&self, now_ms: u64, bilateral: bool) -> bool {
        let interval = if bilateral {
            STEADY_INTERVAL_MS
        } else {
            CONFIRM_INTERVAL_MS
        };
        match self.last_ping_sent_ms {
            None => true,
            Some(last) => now_ms.saturating_sub(last) >= interval,
        }
    }

    /// Whether there is room for another outstanding challenge.
    pub fn has_room(&self) -> bool {
        self.pending.len() < MAX_PENDING_PINGS
    }

    /// Record a challenge that was ACTUALLY put on the wire.
    pub fn register_sent(&mut self, ping: PendingPing, now_ms: u64) {
        if self.pending.len() >= MAX_PENDING_PINGS {
            self.pending.remove(0);
        }
        self.last_ping_sent_ms = Some(now_ms);
        self.pending.push(ping);
    }

    /// Expire challenges that passed their deadline.
    pub fn expire(&mut self, now_ms: u64) {
        self.pending
            .retain(|p| now_ms.saturating_sub(p.sent_ms) < PING_DEADLINE_MS);
    }

    /// Process a PONG in the full current path and epoch context.
    ///
    /// A stale answer never refreshes anything and never clears a still-valid
    /// pending challenge. Only an explicit generation, session or epoch change
    /// invalidates that state.
    pub fn on_pong(
        &mut self,
        pong: &CtrlPayload,
        source: Endpoint,
        ctx: &PathContext,
        now_ms: u64,
    ) -> PongOutcome {
        if pong.rekey_request() {
            return PongOutcome::NonceReuse;
        }
        let Some(idx) = self.pending.iter().position(|p| p.nonce == pong.nonce) else {
            if self.answered.iter().any(|n| *n == pong.nonce) {
                self.duplicates += 1;
                return PongOutcome::Duplicate;
            }
            self.unknown += 1;
            return PongOutcome::Unknown;
        };
        let pending = self.pending[idx].clone();
        if now_ms.saturating_sub(pending.sent_ms) >= PING_DEADLINE_MS {
            self.stale += 1;
            self.pending.remove(idx);
            return PongOutcome::Stale;
        }
        let context_matches = pending.session_id == ctx.session_id
            && pending.generation == ctx.generation
            && pending.peer_generation == ctx.peer_generation
            && pending.boot_id == ctx.local_boot_id
            && pending.peer_boot_id == ctx.peer_boot_id
            && pending.endpoint == source
            && pong.boot_id == ctx.peer_boot_id
            && pong.generation == ctx.peer_generation
            && (!ctx.selected || source == ctx.endpoint);
        if !context_matches {
            self.stale += 1;
            return PongOutcome::Stale;
        }
        if self.answered.iter().any(|n| *n == pong.nonce) {
            self.duplicates += 1;
            return PongOutcome::Duplicate;
        }
        self.pending.remove(idx);
        self.answered.push_back(pong.nonce);
        while self.answered.len() > 256 {
            self.answered.pop_front();
        }
        let rtt_ms = now_ms.saturating_sub(pending.sent_ms);
        self.round_trips += 1;
        if !pending.path_probe {
            self.last_round_trip = Some(RoundTrip {
                at_ms: now_ms,
                context: *ctx,
            });
            self.last_valid_reply_ms = Some(now_ms);
        }
        if pong.local_confirmed() && ctx.selected && source == ctx.endpoint {
            self.peer_confirmation = Some(PeerConfirmation {
                at_ms: now_ms,
                context: *ctx,
            });
        }
        PongOutcome::Accepted {
            rtt_ms,
            path_probe: pending.path_probe,
        }
    }

    /// Process a PING from the peer and report whether we must answer it.
    ///
    /// bit0 only ever records the peer's own recent round trip. It is bound to
    /// the selected endpoint, session and both epochs; anything else is counted
    /// but cannot refresh the peer confirmation.
    pub fn on_ping(
        &mut self,
        ping: &CtrlPayload,
        source: Endpoint,
        ctx: &PathContext,
        now_ms: u64,
    ) -> bool {
        self.peer_pings += 1;
        if ping.local_confirmed()
            && ctx.selected
            && source == ctx.endpoint
            && ping.boot_id == ctx.peer_boot_id
            && ping.generation == ctx.peer_generation
        {
            self.peer_confirmation = Some(PeerConfirmation {
                at_ms: now_ms,
                context: *ctx,
            });
        }
        true
    }

    /// Queue a PONG we owe the peer, bounded and drop-oldest.
    pub fn queue_pong(&mut self, nonce: [u8; 32]) {
        self.outbox.push(nonce);
    }

    /// Take the next owed PONG.
    pub fn take_pong(&mut self) -> Option<[u8; 32]> {
        self.outbox.pop()
    }

    /// How many owed PONGs were dropped to stay bounded.
    pub fn pongs_dropped(&self) -> u64 {
        self.outbox.dropped()
    }

    /// Whether our own round trip is currently fresh for this exact path.
    pub fn local_confirmed(&self, now_ms: u64, ctx: &PathContext) -> bool {
        if !ctx.selected {
            return false;
        }
        let Some(rt) = self.last_round_trip else {
            return false;
        };
        rt.context == *ctx && now_ms.saturating_sub(rt.at_ms) < SUSPECT_AFTER_MS
    }

    /// Whether the peer's own claim is currently fresh for this exact path.
    pub fn peer_confirmed(&self, now_ms: u64, ctx: &PathContext) -> bool {
        if !ctx.selected {
            return false;
        }
        self.peer_confirmation.is_some_and(|confirmation| {
            confirmation.context == *ctx
                && now_ms.saturating_sub(confirmation.at_ms) < SUSPECT_AFTER_MS
        })
    }

    /// The full promotion rule: both sides' evidence must be for the SAME
    /// current path, session and both epochs.
    pub fn bilateral_confirmed(&self, now_ms: u64, ctx: &PathContext) -> bool {
        self.local_confirmed(now_ms, ctx) && self.peer_confirmed(now_ms, ctx)
    }

    /// Coarse health, from the age of the last valid reply only.
    pub fn health(&self, now_ms: u64) -> Health {
        match self.last_valid_reply_ms {
            None => Health::Unknown,
            Some(t) => {
                let age = now_ms.saturating_sub(t);
                if age < SUSPECT_AFTER_MS {
                    Health::Healthy
                } else if age < OFFLINE_AFTER_MS {
                    Health::Suspect
                } else {
                    Health::Offline
                }
            }
        }
    }

    /// Drop everything bound to an older local generation.
    pub fn invalidate_generation(&mut self, generation: u64) {
        self.pending.retain(|p| p.generation == generation);
        if self
            .last_round_trip
            .is_some_and(|rt| rt.context.generation != generation)
        {
            self.last_round_trip = None;
        }
        if self
            .peer_confirmation
            .is_some_and(|c| c.context.generation != generation)
        {
            self.peer_confirmation = None;
        }
    }

    /// Drop everything bound to an older session.
    pub fn invalidate_session(&mut self, session_id: u64) {
        self.pending.retain(|p| p.session_id == session_id);
        if self
            .last_round_trip
            .is_some_and(|rt| rt.context.session_id != session_id)
        {
            self.last_round_trip = None;
            self.last_valid_reply_ms = None;
        }
        if self
            .peer_confirmation
            .is_some_and(|c| c.context.session_id != session_id)
        {
            self.peer_confirmation = None;
        }
    }

    /// Drop everything bound to an older peer epoch.
    pub fn invalidate_peer_epoch(&mut self, peer_boot_id: BootId, peer_generation: u64) {
        self.pending
            .retain(|p| p.peer_boot_id == peer_boot_id && p.peer_generation == peer_generation);
        if self.last_round_trip.is_some_and(|rt| {
            rt.context.peer_boot_id != peer_boot_id || rt.context.peer_generation != peer_generation
        }) {
            self.last_round_trip = None;
        }
        if self.peer_confirmation.is_some_and(|c| {
            c.context.peer_boot_id != peer_boot_id || c.context.peer_generation != peer_generation
        }) {
            self.peer_confirmation = None;
        }
    }

    /// Drop evidence that does not belong to the currently selected endpoint.
    pub fn invalidate_endpoint(&mut self, endpoint: Endpoint) {
        self.pending.retain(|p| p.endpoint == endpoint);
        if self
            .last_round_trip
            .is_some_and(|rt| rt.context.endpoint != endpoint)
        {
            self.last_round_trip = None;
        }
        if self
            .peer_confirmation
            .is_some_and(|c| c.context.endpoint != endpoint)
        {
            self.peer_confirmation = None;
        }
    }

    /// Explicitly clear the peer's claim without touching our own round trip.
    pub fn clear_peer_confirmation(&mut self) {
        self.peer_confirmation = None;
    }
}

/// Build the flags byte for a PING we are about to send.
pub const fn ping_flags(local_confirmed: bool, path_probe: bool, rekey_request: bool) -> u8 {
    let mut flags = 0u8;
    if local_confirmed {
        flags |= FLAG_LOCAL_CONFIRMED;
    }
    if path_probe {
        flags |= FLAG_PATH_PROBE;
    }
    if rekey_request {
        flags |= crate::wire::FLAG_REKEY_REQUEST;
    }
    flags
}

/// Build the flags byte for a PONG: bit1 echoes, bit0 is our own health, bit2
/// must be zero.
pub const fn pong_flags(local_confirmed: bool, echo_path_probe: bool) -> u8 {
    let mut flags = 0u8;
    if local_confirmed {
        flags |= FLAG_LOCAL_CONFIRMED;
    }
    if echo_path_probe {
        flags |= FLAG_PATH_PROBE;
    }
    flags
}

/// Parse a PING, mapping wire errors for the caller.
pub fn parse_ping(payload: &[u8]) -> Result<CtrlPayload, WireError> {
    CtrlPayload::decode_ping(payload)
}

/// Parse a PONG, mapping wire errors for the caller.
pub fn parse_pong(payload: &[u8]) -> Result<CtrlPayload, WireError> {
    CtrlPayload::decode_pong(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lzh_hole_types::DiscoveryPublicKey;

    fn ep(port: u16) -> Endpoint {
        Endpoint::new("210.22.105.194".parse().unwrap(), port)
    }

    fn boot() -> BootId {
        BootId::from_bytes([7u8; 16])
    }

    fn ctrl(nonce: [u8; 32], flags: u8) -> CtrlPayload {
        CtrlPayload {
            sender: DiscoveryPublicKey::from_bytes([1u8; 32]),
            receiver: DiscoveryPublicKey::from_bytes([2u8; 32]),
            nonce,
            boot_id: boot(),
            generation: 1,
            issued_at_unix_ms: 0,
            flags,
        }
    }

    fn ctx(session_id: u64, generation: u64, endpoint: Endpoint, selected: bool) -> PathContext {
        PathContext {
            endpoint,
            session_id,
            generation,
            peer_generation: generation,
            local_boot_id: boot(),
            peer_boot_id: boot(),
            selected,
        }
    }

    fn state_with_round_trip(now: u64) -> HealthState {
        let mut h = HealthState::new();
        let nonce = [9u8; 32];
        h.register_sent(
            PendingPing {
                nonce,
                endpoint: ep(51000),
                boot_id: boot(),
                peer_boot_id: boot(),
                generation: 1,
                peer_generation: 1,
                session_id: 42,
                sent_ms: now,
                path_probe: false,
            },
            now,
        );
        let outcome = h.on_pong(
            &ctrl(nonce, 0),
            ep(51000),
            &ctx(42, 1, ep(51000), true),
            now + 5,
        );
        assert!(matches!(outcome, PongOutcome::Accepted { rtt_ms: 5, .. }));
        h
    }

    #[test]
    fn a_round_trip_confirms_locally() {
        let h = state_with_round_trip(1_000);
        assert!(h.local_confirmed(1_010, &ctx(42, 1, ep(51000), true)));
        assert_eq!(h.round_trips(), 1);
        // Not bilateral until the peer asserts its own confirmation.
        assert!(!h.bilateral_confirmed(1_010, &ctx(42, 1, ep(51000), true)));
    }

    #[test]
    fn local_confirmed_is_not_sticky() {
        let h = state_with_round_trip(1_000);
        // The PONG arrived 5 ms after the PING, so freshness ages from 1_005.
        const REPLIED_AT: u64 = 1_005;
        assert!(h.local_confirmed(
            REPLIED_AT + SUSPECT_AFTER_MS - 1,
            &ctx(42, 1, ep(51000), true)
        ));
        // Once the reply ages out it must go false again.
        assert!(!h.local_confirmed(REPLIED_AT + SUSPECT_AFTER_MS, &ctx(42, 1, ep(51000), true)));
        assert!(!h.local_confirmed(REPLIED_AT + 60_000, &ctx(42, 1, ep(51000), true)));
    }

    #[test]
    fn local_confirmed_is_bound_to_session_generation_and_endpoint() {
        let h = state_with_round_trip(1_000);
        assert!(
            !h.local_confirmed(1_010, &ctx(43, 1, ep(51000), true)),
            "other session"
        );
        assert!(
            !h.local_confirmed(1_010, &ctx(42, 2, ep(51000), true)),
            "other generation"
        );
        assert!(
            !h.local_confirmed(1_010, &ctx(42, 1, ep(51001), true)),
            "other endpoint"
        );
    }

    #[test]
    fn bilateral_needs_the_peer_to_confirm_too() {
        let mut h = state_with_round_trip(1_000);
        // The peer asserts confirmation via a PING with bit0.
        h.on_ping(
            &ctrl([3u8; 32], FLAG_LOCAL_CONFIRMED),
            ep(51000),
            &ctx(42, 1, ep(51000), true),
            1_010,
        );
        assert!(h.bilateral_confirmed(1_010, &ctx(42, 1, ep(51000), true)));
        // And that claim also expires.
        assert!(!h.bilateral_confirmed(1_010 + SUSPECT_AFTER_MS, &ctx(42, 1, ep(51000), true)));
    }

    #[test]
    fn duplicate_answers_do_not_refresh_health() {
        let mut h = state_with_round_trip(1_000);
        let nonce = [9u8; 32];
        let before = h.last_valid_reply_age_ms(2_000);
        assert_eq!(
            h.on_pong(
                &ctrl(nonce, 0),
                ep(51000),
                &ctx(42, 1, ep(51000), true),
                2_000
            ),
            PongOutcome::Duplicate
        );
        assert_eq!(h.last_valid_reply_age_ms(2_000), before);
        assert_eq!(h.duplicates(), 1);
        assert_eq!(h.round_trips(), 1, "a duplicate is not a second round trip");
    }

    #[test]
    fn unknown_and_stale_answers_are_counted_not_trusted() {
        let mut h = HealthState::new();
        assert_eq!(
            h.on_pong(
                &ctrl([1u8; 32], 0),
                ep(51000),
                &ctx(42, 1, ep(51000), true),
                0
            ),
            PongOutcome::Unknown
        );
        assert_eq!(h.unknown(), 1);

        h.register_sent(
            PendingPing {
                nonce: [2u8; 32],
                endpoint: ep(51000),
                boot_id: boot(),
                peer_boot_id: boot(),
                generation: 1,
                peer_generation: 1,
                session_id: 42,
                sent_ms: 0,
                path_probe: false,
            },
            0,
        );
        // Wrong source endpoint.
        assert_eq!(
            h.on_pong(
                &ctrl([2u8; 32], 0),
                ep(51001),
                &ctx(42, 1, ep(51001), true),
                5
            ),
            PongOutcome::Stale
        );
        assert_eq!(h.stale(), 1);
        assert_eq!(h.round_trips(), 0);
    }

    #[test]
    fn answers_from_another_generation_are_discarded() {
        let mut h = HealthState::new();
        h.register_sent(
            PendingPing {
                nonce: [4u8; 32],
                endpoint: ep(51000),
                boot_id: boot(),
                peer_boot_id: boot(),
                generation: 1,
                peer_generation: 1,
                session_id: 42,
                sent_ms: 0,
                path_probe: false,
            },
            0,
        );
        assert_eq!(
            h.on_pong(
                &ctrl([4u8; 32], 0),
                ep(51000),
                &ctx(42, 2, ep(51000), true),
                5
            ),
            PongOutcome::Stale
        );
        // A stale answer does not erase the still-valid pending challenge, and
        // it certainly does not confirm anything.
        assert_eq!(h.pending().len(), 1);
        assert!(!h.local_confirmed(5, &ctx(42, 1, ep(51000), true)));
        // The answer for the real generation is still accepted afterwards.
        assert!(matches!(
            h.on_pong(
                &ctrl([4u8; 32], 0),
                ep(51000),
                &ctx(42, 1, ep(51000), true),
                6
            ),
            PongOutcome::Accepted { .. }
        ));
    }

    #[test]
    fn a_path_probe_does_not_refresh_health() {
        let mut h = HealthState::new();
        h.register_sent(
            PendingPing {
                nonce: [5u8; 32],
                endpoint: ep(51000),
                boot_id: boot(),
                peer_boot_id: boot(),
                generation: 1,
                peer_generation: 1,
                session_id: 42,
                sent_ms: 0,
                path_probe: true,
            },
            0,
        );
        let outcome = h.on_pong(
            &ctrl([5u8; 32], 0),
            ep(51000),
            &ctx(42, 1, ep(51000), true),
            5,
        );
        assert!(matches!(
            outcome,
            PongOutcome::Accepted {
                path_probe: true,
                ..
            }
        ));
        assert!(!h.local_confirmed(5, &ctx(42, 1, ep(51000), true)));
        assert_eq!(h.last_valid_reply_age_ms(5), None);
    }

    #[test]
    fn pending_pings_are_bounded() {
        let mut h = HealthState::new();
        for i in 0..(MAX_PENDING_PINGS + 3) {
            h.register_sent(
                PendingPing {
                    nonce: [i as u8; 32],
                    endpoint: ep(51000),
                    boot_id: boot(),
                    peer_boot_id: boot(),
                    generation: 1,
                    peer_generation: 1,
                    session_id: 42,
                    sent_ms: 0,
                    path_probe: false,
                },
                0,
            );
        }
        assert_eq!(h.pending().len(), MAX_PENDING_PINGS);
        assert!(!h.has_room() || h.pending().len() == MAX_PENDING_PINGS);
    }

    #[test]
    fn expired_challenges_are_dropped() {
        let mut h = HealthState::new();
        h.register_sent(
            PendingPing {
                nonce: [6u8; 32],
                endpoint: ep(51000),
                boot_id: boot(),
                peer_boot_id: boot(),
                generation: 1,
                peer_generation: 1,
                session_id: 42,
                sent_ms: 0,
                path_probe: false,
            },
            0,
        );
        h.expire(PING_DEADLINE_MS - 1);
        assert_eq!(h.pending().len(), 1);
        h.expire(PING_DEADLINE_MS);
        assert!(h.pending().is_empty());
    }

    #[test]
    fn health_thresholds_are_twenty_and_thirty_seconds() {
        let h = state_with_round_trip(1_000);
        // Freshness ages from the PONG, which arrived 5 ms after the PING.
        const REPLIED_AT: u64 = 1_005;
        assert_eq!(h.health(REPLIED_AT), Health::Healthy);
        assert_eq!(h.health(REPLIED_AT + SUSPECT_AFTER_MS - 1), Health::Healthy);
        assert_eq!(h.health(REPLIED_AT + SUSPECT_AFTER_MS), Health::Suspect);
        assert_eq!(h.health(REPLIED_AT + OFFLINE_AFTER_MS - 1), Health::Suspect);
        assert_eq!(h.health(REPLIED_AT + OFFLINE_AFTER_MS), Health::Offline);
        assert_eq!(HealthState::new().health(0), Health::Unknown);
    }

    #[test]
    fn ping_interval_switches_on_confirmation() {
        let mut h = HealthState::new();
        assert!(h.ping_due(0, false));
        h.register_sent(
            PendingPing {
                nonce: [8u8; 32],
                endpoint: ep(51000),
                boot_id: boot(),
                peer_boot_id: boot(),
                generation: 1,
                peer_generation: 1,
                session_id: 42,
                sent_ms: 1_000,
                path_probe: false,
            },
            1_000,
        );
        assert!(!h.ping_due(1_500, false));
        assert!(h.ping_due(1_000 + CONFIRM_INTERVAL_MS, false));
        // Steady state is slower.
        assert!(!h.ping_due(1_000 + CONFIRM_INTERVAL_MS, true));
        assert!(h.ping_due(1_000 + STEADY_INTERVAL_MS, true));
    }

    #[test]
    fn pong_queue_is_bounded_and_drops_oldest() {
        let mut q: BoundedQueue<u8> = BoundedQueue::new();
        for i in 0..(PONG_QUEUE_CAPACITY + 3) {
            q.push(i as u8);
        }
        assert_eq!(q.len(), PONG_QUEUE_CAPACITY);
        assert_eq!(q.dropped(), 3);
        // Oldest were discarded, newest survive.
        assert_eq!(q.pop(), Some(3));
    }

    #[test]
    fn owed_pongs_are_bounded() {
        let mut h = HealthState::new();
        for i in 0..(PONG_QUEUE_CAPACITY + 5) {
            h.queue_pong([i as u8; 32]);
        }
        assert_eq!(h.pongs_dropped(), 5);
        assert!(h.take_pong().is_some());
    }

    #[test]
    fn flag_builders_match_the_contract() {
        assert_eq!(ping_flags(false, false, false), 0);
        assert_eq!(ping_flags(true, false, false), FLAG_LOCAL_CONFIRMED);
        assert_eq!(ping_flags(false, true, false), FLAG_PATH_PROBE);
        assert_eq!(ping_flags(false, false, true), 0b100);
        assert_eq!(ping_flags(true, true, true), 0b111);
        // A PONG can never carry the rekey bit.
        assert_eq!(pong_flags(true, true) & 0b100, 0);
        assert_eq!(pong_flags(true, true), 0b011);
    }

    #[test]
    fn generation_and_session_invalidation_clear_state() {
        let mut h = state_with_round_trip(1_000);
        assert!(h.local_confirmed(1_010, &ctx(42, 1, ep(51000), true)));
        h.invalidate_generation(2);
        assert!(!h.local_confirmed(1_010, &ctx(42, 1, ep(51000), true)));
        assert!(h.pending().is_empty());

        let mut h = state_with_round_trip(1_000);
        h.invalidate_session(43);
        assert!(!h.local_confirmed(1_010, &ctx(42, 1, ep(51000), true)));
        assert_eq!(h.last_valid_reply_age_ms(2_000), None);
    }

    #[test]
    fn a_pong_carrying_the_rekey_bit_is_refused() {
        let mut h = HealthState::new();
        h.register_sent(
            PendingPing {
                nonce: [7u8; 32],
                endpoint: ep(51000),
                boot_id: boot(),
                peer_boot_id: boot(),
                generation: 1,
                peer_generation: 1,
                session_id: 42,
                sent_ms: 0,
                path_probe: false,
            },
            0,
        );
        assert_eq!(
            h.on_pong(
                &ctrl([7u8; 32], 0b100),
                ep(51000),
                &ctx(42, 1, ep(51000), true),
                5
            ),
            PongOutcome::NonceReuse
        );
        assert_eq!(h.round_trips(), 0);
    }
}

#[cfg(test)]
mod epoch_binding_tests {
    use super::*;
    use lzh_hole_types::DiscoveryPublicKey;

    fn ep(port: u16) -> Endpoint {
        Endpoint::new("210.22.105.194".parse().unwrap(), port)
    }

    fn local_boot() -> BootId {
        BootId::from_bytes([1u8; 16])
    }

    fn peer_boot() -> BootId {
        BootId::from_bytes([2u8; 16])
    }

    fn ctx(session: u64, generation: u64, endpoint: Endpoint, selected: bool) -> PathContext {
        PathContext {
            endpoint,
            session_id: session,
            generation,
            peer_generation: generation,
            local_boot_id: local_boot(),
            peer_boot_id: peer_boot(),
            selected,
        }
    }

    fn ctx_with_peer(
        session: u64,
        generation: u64,
        peer_generation: u64,
        peer: BootId,
        endpoint: Endpoint,
    ) -> PathContext {
        PathContext {
            peer_generation,
            peer_boot_id: peer,
            ..ctx(session, generation, endpoint, true)
        }
    }

    fn ctrl(nonce: [u8; 32], flags: u8) -> CtrlPayload {
        CtrlPayload {
            sender: DiscoveryPublicKey::from_bytes([1u8; 32]),
            receiver: DiscoveryPublicKey::from_bytes([2u8; 32]),
            nonce,
            boot_id: peer_boot(),
            generation: 1,
            issued_at_unix_ms: 0,
            flags,
        }
    }

    fn pending(nonce: [u8; 32], sent_ms: u64) -> PendingPing {
        PendingPing {
            nonce,
            endpoint: ep(51000),
            boot_id: local_boot(),
            peer_boot_id: peer_boot(),
            generation: 1,
            peer_generation: 1,
            session_id: 42,
            sent_ms,
            path_probe: false,
        }
    }

    fn established() -> (HealthState, PathContext) {
        let mut h = HealthState::new();
        let context = ctx(42, 1, ep(51000), true);
        h.register_sent(pending([9u8; 32], 1_000), 1_000);
        assert!(matches!(
            h.on_pong(&ctrl([9u8; 32], 0), ep(51000), &context, 1_005),
            PongOutcome::Accepted { .. }
        ));
        h.on_ping(
            &ctrl([3u8; 32], FLAG_LOCAL_CONFIRMED),
            ep(51000),
            &context,
            1_006,
        );
        (h, context)
    }

    #[test]
    fn bit0_from_an_unselected_endpoint_does_not_confirm() {
        let mut h = HealthState::new();
        let context = ctx(42, 1, ep(51000), true);
        h.register_sent(pending([9u8; 32], 1_000), 1_000);
        h.on_pong(&ctrl([9u8; 32], 0), ep(51000), &context, 1_005);
        assert!(!h.bilateral_confirmed(1_006, &context));
        // Same session and epoch, but a different source endpoint.
        h.on_ping(
            &ctrl([3u8; 32], FLAG_LOCAL_CONFIRMED),
            ep(51001),
            &context,
            1_006,
        );
        assert!(!h.bilateral_confirmed(1_006, &context));
        // The selected endpoint's bit0 is the one that counts.
        h.on_ping(
            &ctrl([3u8; 32], FLAG_LOCAL_CONFIRMED),
            ep(51000),
            &context,
            1_007,
        );
        assert!(h.bilateral_confirmed(1_007, &context));
    }

    #[test]
    fn an_unselected_pong_can_never_be_bilateral() {
        let mut h = HealthState::new();
        let unselected = ctx(42, 1, ep(51000), false);
        h.register_sent(pending([9u8; 32], 1_000), 1_000);
        assert!(matches!(
            h.on_pong(&ctrl([9u8; 32], 0), ep(51000), &unselected, 1_005),
            PongOutcome::Accepted { .. }
        ));
        assert!(!h.local_confirmed(1_005, &unselected));
        assert!(!h.bilateral_confirmed(1_005, &unselected));
    }

    #[test]
    fn old_session_old_generation_and_old_epoch_do_not_confirm() {
        let (h, current) = established();
        assert!(h.bilateral_confirmed(1_010, &current));
        assert!(!h.bilateral_confirmed(1_010, &ctx(43, 1, ep(51000), true)));
        assert!(!h.bilateral_confirmed(1_010, &ctx(42, 2, ep(51000), true)));
        let old_epoch = ctx_with_peer(42, 1, 1, BootId::from_bytes([9u8; 16]), ep(51000));
        assert!(!h.bilateral_confirmed(1_010, &old_epoch));
        let old_peer_generation = ctx_with_peer(42, 1, 2, peer_boot(), ep(51000));
        assert!(!h.bilateral_confirmed(1_010, &old_peer_generation));
    }

    #[test]
    fn a_replayed_pong_does_not_refresh_health_or_round_trip_count() {
        let (mut h, context) = established();
        let before_age = h.last_valid_reply_age_ms(2_000);
        assert_eq!(
            h.on_pong(&ctrl([9u8; 32], 0), ep(51000), &context, 2_000),
            PongOutcome::Duplicate
        );
        assert_eq!(h.round_trips(), 1);
        assert_eq!(h.last_valid_reply_age_ms(2_000), before_age);
        assert_eq!(h.duplicates(), 1);
    }

    #[test]
    fn one_way_bit0_is_not_a_bilateral_confirmation() {
        let mut h = HealthState::new();
        let context = ctx(42, 1, ep(51000), true);
        h.on_ping(
            &ctrl([3u8; 32], FLAG_LOCAL_CONFIRMED),
            ep(51000),
            &context,
            1_000,
        );
        assert!(!h.local_confirmed(1_000, &context));
        assert!(!h.bilateral_confirmed(1_000, &context));
    }

    #[test]
    fn peer_confirmation_expires_independently_of_our_round_trip() {
        let (h, context) = established();
        assert!(h.peer_confirmed(1_006 + SUSPECT_AFTER_MS - 1, &context));
        assert!(!h.peer_confirmed(1_006 + SUSPECT_AFTER_MS, &context));
        // Our own reply can still be fresh while the peer's claim is stale.
        assert!(h.local_confirmed(1_005 + SUSPECT_AFTER_MS - 1, &context));
        assert!(!h.bilateral_confirmed(1_006 + SUSPECT_AFTER_MS, &context));
    }

    #[test]
    fn invalidating_the_peer_epoch_clears_both_sides_of_the_evidence() {
        let (mut h, context) = established();
        assert!(h.bilateral_confirmed(1_010, &context));
        h.invalidate_peer_epoch(BootId::from_bytes([9u8; 16]), 9);
        assert!(!h.local_confirmed(1_010, &context));
        assert!(!h.peer_confirmed(1_010, &context));
        assert!(!h.bilateral_confirmed(1_010, &context));
    }

    #[test]
    fn a_pong_from_the_old_epoch_is_stale_and_keeps_the_pending_challenge() {
        let mut h = HealthState::new();
        let current = ctx(42, 1, ep(51000), true);
        h.register_sent(pending([9u8; 32], 1_000), 1_000);
        let old = ctx_with_peer(42, 1, 1, BootId::from_bytes([9u8; 16]), ep(51000));
        assert_eq!(
            h.on_pong(&ctrl([9u8; 32], 0), ep(51000), &old, 1_005),
            PongOutcome::Stale
        );
        assert_eq!(h.pending().len(), 1);
        assert_eq!(h.round_trips(), 0);
        assert!(matches!(
            h.on_pong(&ctrl([9u8; 32], 0), ep(51000), &current, 1_006),
            PongOutcome::Accepted { .. }
        ));
    }

    #[test]
    fn invalidating_the_session_clears_the_peer_claim_too() {
        let (mut h, context) = established();
        assert!(h.bilateral_confirmed(1_010, &context));
        h.invalidate_session(43);
        assert!(!h.local_confirmed(1_010, &context));
        assert!(!h.peer_confirmed(1_010, &context));
        assert!(!h.bilateral_confirmed(1_010, &context));
    }

    #[test]
    fn bit0_is_only_the_peers_own_round_trip_not_a_joint_state() {
        let (h, context) = established();
        assert!(h.local_confirmed(1_010, &context));
        // The peer claim exists, but it is not a separate third state and it is
        // not derived from bilateral_confirmed itself.
        assert!(h.peer_confirmed(1_010, &context));
        assert!(h.bilateral_confirmed(1_010, &context));
    }
}
