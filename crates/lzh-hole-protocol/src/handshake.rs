//! Bounded, authenticated handshake engine.
//!
//! Roles are canonical: the holder of the lexicographically smaller pinned key
//! is the initiator and sends HELLO; the other side sends PROBE and CHALLENGE.
//! Every derived key and every frame here is pinned by
//! tests/fixtures/wire-v1.json.
//!
//! Bounded by construction: at most 32 pending attempts and 16 responder
//! entries, 4 KiB per entry, and 256 authenticated PROBE nonce records, all
//! charged against 128 KiB of handshake state in total.

use crate::crypto::{
    Key32, LABEL_KDF_CHALLENGE, LABEL_KDF_FINISH, LABEL_KDF_HELLO, LABEL_KDF_KEY_I2R,
    LABEL_KDF_KEY_R2I, LABEL_KDF_SESSION_ID, Prk, extract_prk, frame_mac, info, transcript_hash,
    verify_frame_mac,
};
use crate::path::{Endpoint, PathEndpoint};
use crate::replay::ReplayWindow;
use crate::session::{Session, SessionKeys};
use crate::wire::{
    AckPayload, ChallengePayload, Direction, FinishPayload, FrameType, Header, HelloPayload,
    ProbePayload, WireError, encode_frame, parse_frame,
};
use lzh_hole_types::{
    BootId, DiscoveryPublicKey, RelationshipId, Role, Roles, Secret32, TransportId,
};

/// Pending attempts we will track for one relationship.
pub const MAX_PENDING_ATTEMPTS: usize = 32;
/// Responder-side per-source HELLO entries.
pub const MAX_RESPONDER_ENTRIES: usize = 16;
/// Documented per-entry budget: four 314-byte frames plus keys and metadata.
pub const MAX_ENTRY_BYTES: usize = 4096;
/// Total handshake state budget.
pub const MAX_HANDSHAKE_STATE_BYTES: usize = 128 * 1024;
/// Shadow (unconfirmed, non-preempting) sessions.
pub const MAX_SHADOW_SESSIONS: usize = 2;
/// How long one attempt may live.
pub const ATTEMPT_TTL_MS: u64 = 90_000;
/// Retransmission interval.
pub const RETRANSMIT_INTERVAL_MS: u64 = 1_000;
/// Retransmissions allowed per entry within its TTL.
pub const MAX_RETRANSMITS: u32 = 8;
/// Bound on a rekey intent.
pub const REKEY_INTENT_TTL_MS: u64 = 90_000;
/// Tolerance for a handshake timestamp.
pub const CLOCK_SKEW_TOLERANCE_MS: u64 = 120_000;
/// Authenticated PROBE nonces retained through their entire freshness window.
/// When full, new probes fail closed rather than evicting live replay evidence.
pub const MAX_SEEN_PROBES: usize = 256;

/// Why a handshake step did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeReject {
    /// Structural problem with the frame.
    Wire(WireError),
    /// MAC did not verify. Never answered, never clears state.
    BadMac,
    /// Frame belongs to another relationship.
    WrongRelationship,
    /// Frame names keys that are not ours.
    WrongIdentity,
    /// Timestamp outside the tolerance.
    ClockSkew,
    /// Nothing matched this frame.
    NoMatchingAttempt,
    /// A table is full; the new work is refused, existing work is untouched.
    TableFull(&'static str),
    /// Session id zero, or a genuine collision with a different transcript.
    SessionIdRejected,
    /// A stale handshake tried to preempt a healthy session.
    WouldPreemptHealthySession,
}

/// Something the caller should do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeEvent {
    /// Send these frames to this endpoint.
    Send {
        /// Physical local socket bound to this handshake.
        transport: TransportId,
        /// Where to send.
        target: Endpoint,
        /// Complete frames.
        frames: Vec<Vec<u8>>,
    },
    /// A session became usable (responder side, still unconfirmed by health).
    SessionInstalled {
        /// The new session id.
        session_id: u64,
    },
    /// The peer acknowledged our FINISH.
    AckReceived {
        /// The session id.
        session_id: u64,
    },
    /// An attempt expired and may be restarted with fresh nonces.
    AttemptExpired,
    /// A frame was dropped, with the reason, for diagnostics.
    Dropped(HandshakeReject),
}

/// Static configuration for one relationship.
#[derive(Debug, Clone)]
pub struct HandshakeConfig {
    /// Relationship id.
    pub relationship_id: RelationshipId,
    /// Our own discovery public key.
    pub me: DiscoveryPublicKey,
    /// The pinned peer key.
    pub peer: DiscoveryPublicKey,
    /// Our process epoch.
    pub boot_id: BootId,
    /// Our network generation.
    pub generation: u64,
}

/// One in-flight initiator attempt.
#[derive(Debug)]
struct Attempt {
    transport: TransportId,
    nonce_i: [u8; 32],
    hello: Vec<u8>,
    finish: Option<Vec<u8>>,
    th1: [u8; 32],
    th2: Option<[u8; 32]>,
    target: Endpoint,
    created_ms: u64,
    last_send_ms: u64,
    sends: u32,
    awaiting_ack: bool,
}

impl Attempt {
    fn bytes(&self) -> usize {
        self.hello.len() + self.finish.as_ref().map_or(0, Vec::len) + 128
    }
}

/// One responder-side entry, keyed by the initiator nonce.
#[derive(Debug)]
struct ResponderEntry {
    transport: TransportId,
    nonce_i: [u8; 32],
    nonce_r: [u8; 32],
    hello: Vec<u8>,
    challenge: Vec<u8>,
    source: Endpoint,
    created_ms: u64,
    last_send_ms: u64,
    sends: u32,
    session_id: Option<u64>,
    ack: Option<Vec<u8>>,
}

impl ResponderEntry {
    fn bytes(&self) -> usize {
        self.hello.len() + self.challenge.len() + self.ack.as_ref().map_or(0, Vec::len) + 128
    }
}

/// A bounded, time-limited authorisation to start a new handshake.
#[derive(Debug, Clone, Copy)]
struct RekeyIntent {
    granted_ms: u64,
}

#[derive(Debug)]
struct SeenProbe {
    boot_id: BootId,
    generation: u64,
    nonce: [u8; 32],
    expires_ms: u64,
}

/// The handshake engine for one relationship.
pub struct Handshake {
    cfg: HandshakeConfig,
    role: Role,
    prk: Prk,
    attempts: Vec<Attempt>,
    responder: Vec<ResponderEntry>,
    pub(crate) session: Option<Session>,
    shadow: Vec<Session>,
    rekey: Option<RekeyIntent>,
    handshake_state_bytes: usize,
    // Pinned relationship/identity, independent of packet source.
    seen_probes: Vec<SeenProbe>,
}

impl std::fmt::Debug for Handshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handshake")
            .field("role", &self.role)
            .field("attempts", &self.attempts.len())
            .field("responder", &self.responder.len())
            .field("session", &self.session.as_ref().map(|s| s.keys.session_id))
            .field("shadow", &self.shadow.len())
            .field("rekey", &self.rekey.is_some())
            .finish()
    }
}

impl Handshake {
    /// Build an engine. The PSK is consumed into the PRK and not retained.
    pub fn new(cfg: HandshakeConfig, psk: &Secret32) -> Result<Self, HandshakeReject> {
        let roles = Roles::new(cfg.me, cfg.peer).map_err(|_| HandshakeReject::WrongIdentity)?;
        let role = roles
            .role_of(cfg.me)
            .ok_or(HandshakeReject::WrongIdentity)?;
        let prk = extract_prk(cfg.relationship_id.as_bytes(), psk.expose_bytes());
        Ok(Self {
            cfg,
            role,
            prk,
            attempts: Vec::new(),
            responder: Vec::new(),
            session: None,
            shadow: Vec::new(),
            rekey: None,
            handshake_state_bytes: 0,
            seen_probes: Vec::new(),
        })
    }

    /// Our role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The installed session, if any.
    pub fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    /// The installed session, mutably.
    pub fn session_mut(&mut self) -> Option<&mut Session> {
        self.session.as_mut()
    }

    /// Discard the installed session and every in-flight handshake entry.
    ///
    /// This is a local invalidation operation, not a rekey: it emits nothing and
    /// a subsequent initiator attempt uses fresh nonces. It is intended for a
    /// caller that has declared the old path offline or is cancelling its work.
    pub fn reset(&mut self) {
        self.attempts.clear();
        self.responder.clear();
        self.session = None;
        self.shadow.clear();
        self.rekey = None;
        self.recompute_state_bytes();
    }

    /// Current handshake state size, for the documented budget.
    pub fn state_bytes(&self) -> usize {
        self.handshake_state_bytes
    }

    /// Number of in-flight initiator attempts.
    pub fn pending_attempts(&self) -> usize {
        self.attempts.len()
    }

    pub(crate) fn has_attempt_on(&self, transport: TransportId, target: Endpoint) -> bool {
        self.attempts
            .iter()
            .any(|a| a.transport == transport && a.target == target)
    }

    /// Number of responder-side entries.
    pub fn responder_entries(&self) -> usize {
        self.responder.len()
    }

    /// The static PROBE key, for the responder's keepalive probes.
    pub fn probe_key(&self) -> Key32 {
        let roles = Roles::new(self.cfg.me, self.cfg.peer).expect("validated at construction");
        self.prk.probe_key(roles.lo.as_bytes(), roles.hi.as_bytes())
    }

    fn roles(&self) -> Roles {
        Roles::new(self.cfg.me, self.cfg.peer).expect("validated at construction")
    }

    fn recompute_state_bytes(&mut self) {
        self.handshake_state_bytes = self
            .attempts
            .iter()
            .map(Attempt::bytes)
            .chain(self.responder.iter().map(ResponderEntry::bytes))
            .sum::<usize>()
            + self.seen_probes.len() * std::mem::size_of::<SeenProbe>();
    }

    fn has_room(&self, extra: usize) -> bool {
        self.handshake_state_bytes + extra <= MAX_HANDSHAKE_STATE_BYTES
    }

    /// Grant a rekey intent. Bounded to REKEY_INTENT_TTL_MS.
    pub fn grant_rekey_intent(&mut self, now_ms: u64) {
        // Explicit local authorization starts a separate bounded competition;
        // ordinary packets cannot clear the already chosen FINISH winner.
        self.attempts.clear();
        self.recompute_state_bytes();
        self.rekey = Some(RekeyIntent { granted_ms: now_ms });
    }

    /// Whether a rekey intent is currently live.
    pub fn rekey_intent_live(&self, now_ms: u64) -> bool {
        self.rekey
            .is_some_and(|i| now_ms.saturating_sub(i.granted_ms) < REKEY_INTENT_TTL_MS)
    }

    /// Start a new initiator attempt against one target.
    pub fn start_attempt(
        &mut self,
        target: Endpoint,
        now_ms: u64,
    ) -> Result<Vec<HandshakeEvent>, HandshakeReject> {
        self.start_attempt_on(TransportId(0), target, now_ms)
    }

    /// Start an attempt bound to one local physical transport.
    pub fn start_attempt_on(
        &mut self,
        transport: TransportId,
        target: Endpoint,
        now_ms: u64,
    ) -> Result<Vec<HandshakeEvent>, HandshakeReject> {
        if self.role != Role::Initiator {
            return Err(HandshakeReject::WouldPreemptHealthySession);
        }
        if self.attempts.len() >= MAX_PENDING_ATTEMPTS {
            return Err(HandshakeReject::TableFull("attempts"));
        }
        if !self.has_room(1024) {
            return Err(HandshakeReject::TableFull("handshake_state_bytes"));
        }
        let mut nonce_i = [0u8; 32];
        getrandom::fill(&mut nonce_i).map_err(|_| HandshakeReject::SessionIdRejected)?;
        let roles = self.roles();
        let k_hello = self.prk.expand32(&info(
            LABEL_KDF_HELLO,
            &[roles.lo.as_bytes(), roles.hi.as_bytes(), &nonce_i],
        ));
        let hello = encode_frame(
            FrameType::Hello,
            Direction::LoToHi,
            self.cfg.relationship_id,
            0,
            0,
            &HelloPayload {
                lo_pub: roles.lo,
                hi_pub: roles.hi,
                nonce_i,
                boot_id: self.cfg.boot_id,
                generation: self.cfg.generation,
                issued_at_unix_ms: now_ms,
            }
            .encode(),
            &k_hello,
        )
        .map_err(HandshakeReject::Wire)?;
        let th1 = transcript_hash(&[hello.as_slice()]);
        let frame = hello.clone();
        self.attempts.push(Attempt {
            transport,
            nonce_i,
            hello,
            finish: None,
            th1,
            th2: None,
            target,
            created_ms: now_ms,
            last_send_ms: now_ms,
            sends: 1,
            awaiting_ack: false,
        });
        self.recompute_state_bytes();
        Ok(vec![HandshakeEvent::Send {
            transport,
            target,
            frames: vec![frame],
        }])
    }

    /// Expire stale attempts and produce any due retransmissions.
    pub fn tick(&mut self, now_ms: u64) -> Vec<HandshakeEvent> {
        self.tick_with_budget(now_ms, |_, _| true)
    }

    /// Admission precedes retry count/time mutation; deferred work remains due.
    pub(crate) fn tick_with_budget(
        &mut self,
        now_ms: u64,
        mut admit: impl FnMut(TransportId, Endpoint) -> bool,
    ) -> Vec<HandshakeEvent> {
        let mut events = Vec::new();
        self.seen_probes.retain(|p| now_ms <= p.expires_ms);
        let before = self.attempts.len() + self.responder.len();

        self.attempts
            .retain(|a| now_ms.saturating_sub(a.created_ms) < ATTEMPT_TTL_MS);
        self.responder
            .retain(|e| now_ms.saturating_sub(e.created_ms) < ATTEMPT_TTL_MS);
        if self.attempts.len() + self.responder.len() != before {
            events.push(HandshakeEvent::AttemptExpired);
        }
        if self
            .rekey
            .is_some_and(|i| now_ms.saturating_sub(i.granted_ms) >= REKEY_INTENT_TTL_MS)
        {
            self.rekey = None;
        }

        for attempt in &mut self.attempts {
            if now_ms.saturating_sub(attempt.last_send_ms) < RETRANSMIT_INTERVAL_MS {
                continue;
            }
            if attempt.sends >= MAX_RETRANSMITS {
                continue;
            }
            let frame = if attempt.awaiting_ack {
                attempt.finish.clone()
            } else {
                Some(attempt.hello.clone())
            };
            if let Some(frame) = frame {
                if !admit(attempt.transport, attempt.target) {
                    continue;
                }
                attempt.last_send_ms = now_ms;
                attempt.sends += 1;
                events.push(HandshakeEvent::Send {
                    transport: attempt.transport,
                    target: attempt.target,
                    frames: vec![frame],
                });
            }
        }

        // The responder never retransmits on a timer. A CHALLENGE or ACK is only
        // ever sent in response to a newly received valid request, so one
        // received packet can never produce more than one reply.

        self.recompute_state_bytes();
        events
    }

    /// Feed one received datagram in. Returns events, including any reply.
    ///
    /// Nothing is answered unless the MAC verifies. Invalid input never clears
    /// pending state.
    pub fn handle_frame(
        &mut self,
        datagram: &[u8],
        source: Endpoint,
        now_ms: u64,
    ) -> Vec<HandshakeEvent> {
        self.handle_frame_on(TransportId(0), datagram, source, now_ms)
    }

    /// Receive a frame on its actual retained local socket.
    pub fn handle_frame_on(
        &mut self,
        transport: TransportId,
        datagram: &[u8],
        source: Endpoint,
        now_ms: u64,
    ) -> Vec<HandshakeEvent> {
        let parsed = match parse_frame(datagram) {
            Ok(p) => p,
            Err(e) => return vec![HandshakeEvent::Dropped(HandshakeReject::Wire(e))],
        };
        if parsed.header.relationship_id != self.cfg.relationship_id {
            return vec![HandshakeEvent::Dropped(HandshakeReject::WrongRelationship)];
        }
        match parsed.header.frame_type {
            FrameType::Hello => self.handle_hello(datagram, &parsed, transport, source, now_ms),
            FrameType::Challenge => {
                self.handle_challenge(datagram, &parsed, transport, source, now_ms)
            }
            FrameType::Finish => self.handle_finish(datagram, &parsed, transport, source, now_ms),
            FrameType::Ack => self.handle_ack(&parsed, transport, source, now_ms),
            FrameType::Probe => self.handle_probe(&parsed, now_ms),
            _ => vec![HandshakeEvent::Dropped(HandshakeReject::NoMatchingAttempt)],
        }
    }

    fn fresh_enough(issued_at_unix_ms: u64, now_ms: u64) -> bool {
        let delta = now_ms.abs_diff(issued_at_unix_ms);
        delta <= CLOCK_SKEW_TOLERANCE_MS
    }

    fn handle_probe(
        &mut self,
        parsed: &crate::wire::ParsedFrame<'_>,
        now_ms: u64,
    ) -> Vec<HandshakeEvent> {
        // A PROBE is never answered and never allocates session state.
        let key = self.probe_key();
        if !verify_frame_mac(&key, &parsed.raw_header(), parsed.payload, parsed.mac) {
            return vec![HandshakeEvent::Dropped(HandshakeReject::BadMac)];
        }
        let probe = match ProbePayload::decode(parsed.payload) {
            Ok(p) => p,
            Err(e) => return vec![HandshakeEvent::Dropped(HandshakeReject::Wire(e))],
        };
        let roles = self.roles();
        if probe.sender != roles.hi || probe.receiver != roles.lo {
            return vec![HandshakeEvent::Dropped(HandshakeReject::WrongIdentity)];
        }
        if !Self::fresh_enough(probe.issued_at_unix_ms, now_ms) {
            return vec![HandshakeEvent::Dropped(HandshakeReject::ClockSkew)];
        }
        self.seen_probes.retain(|p| now_ms <= p.expires_ms);
        self.recompute_state_bytes();
        if self.seen_probes.iter().any(|p| {
            p.boot_id == probe.boot_id
                && p.generation == probe.generation
                && p.nonce == probe.probe_nonce
        }) {
            return vec![HandshakeEvent::Dropped(HandshakeReject::NoMatchingAttempt)];
        }
        if self.seen_probes.len() >= MAX_SEEN_PROBES
            || !self.has_room(std::mem::size_of::<SeenProbe>())
        {
            return vec![HandshakeEvent::Dropped(HandshakeReject::TableFull(
                "seen_probes",
            ))];
        }
        self.seen_probes.push(SeenProbe {
            boot_id: probe.boot_id,
            generation: probe.generation,
            nonce: probe.probe_nonce,
            expires_ms: probe
                .issued_at_unix_ms
                .saturating_add(CLOCK_SKEW_TOLERANCE_MS),
        });
        self.recompute_state_bytes();
        Vec::new()
    }

    fn handle_hello(
        &mut self,
        datagram: &[u8],
        parsed: &crate::wire::ParsedFrame<'_>,
        transport: TransportId,
        source: Endpoint,
        now_ms: u64,
    ) -> Vec<HandshakeEvent> {
        if self.role != Role::Responder {
            return vec![HandshakeEvent::Dropped(
                HandshakeReject::WouldPreemptHealthySession,
            )];
        }
        let hello = match HelloPayload::decode(parsed.payload) {
            Ok(h) => h,
            Err(e) => return vec![HandshakeEvent::Dropped(HandshakeReject::Wire(e))],
        };
        let roles = self.roles();
        if hello.lo_pub != roles.lo || hello.hi_pub != roles.hi {
            return vec![HandshakeEvent::Dropped(HandshakeReject::WrongIdentity)];
        }
        let k_hello = self.prk.expand32(&info(
            LABEL_KDF_HELLO,
            &[roles.lo.as_bytes(), roles.hi.as_bytes(), &hello.nonce_i],
        ));
        if !verify_frame_mac(&k_hello, &parsed.raw_header(), parsed.payload, parsed.mac) {
            return vec![HandshakeEvent::Dropped(HandshakeReject::BadMac)];
        }
        if !Self::fresh_enough(hello.issued_at_unix_ms, now_ms) {
            return vec![HandshakeEvent::Dropped(HandshakeReject::ClockSkew)];
        }

        // A duplicate HELLO must reproduce the same CHALLENGE bytes.
        if let Some(entry) = self
            .responder
            .iter_mut()
            .find(|e| e.nonce_i == hello.nonce_i && e.hello.as_slice() == datagram)
        {
            if entry.transport != transport || entry.source != source {
                return vec![HandshakeEvent::Dropped(HandshakeReject::NoMatchingAttempt)];
            }
            if now_ms.saturating_sub(entry.last_send_ms) >= RETRANSMIT_INTERVAL_MS
                && entry.sends < MAX_RETRANSMITS
            {
                entry.last_send_ms = now_ms;
                entry.sends += 1;
                let frame = entry.ack.clone().unwrap_or_else(|| entry.challenge.clone());
                return vec![HandshakeEvent::Send {
                    transport,
                    target: entry.source,
                    frames: vec![frame],
                }];
            }
            return Vec::new();
        }

        if self.responder.len() >= MAX_RESPONDER_ENTRIES {
            return vec![HandshakeEvent::Dropped(HandshakeReject::TableFull(
                "responder",
            ))];
        }
        if !self.has_room(2048) {
            return vec![HandshakeEvent::Dropped(HandshakeReject::TableFull(
                "handshake_state_bytes",
            ))];
        }

        let mut nonce_r = [0u8; 32];
        if getrandom::fill(&mut nonce_r).is_err() {
            return vec![HandshakeEvent::Dropped(HandshakeReject::SessionIdRejected)];
        }
        let th1 = transcript_hash(&[datagram]);
        let k_chal = self.prk.expand32(&info(
            LABEL_KDF_CHALLENGE,
            &[
                roles.lo.as_bytes(),
                roles.hi.as_bytes(),
                &hello.nonce_i,
                &nonce_r,
                &th1,
            ],
        ));
        let challenge = match encode_frame(
            FrameType::Challenge,
            Direction::HiToLo,
            self.cfg.relationship_id,
            0,
            0,
            &ChallengePayload {
                hi_pub: roles.hi,
                lo_pub: roles.lo,
                nonce_i: hello.nonce_i,
                nonce_r,
                th1,
                boot_id: self.cfg.boot_id,
                generation: self.cfg.generation,
                issued_at_unix_ms: now_ms,
            }
            .encode(),
            &k_chal,
        ) {
            Ok(f) => f,
            Err(e) => return vec![HandshakeEvent::Dropped(HandshakeReject::Wire(e))],
        };
        let frame = challenge.clone();
        self.responder.push(ResponderEntry {
            transport,
            nonce_i: hello.nonce_i,
            nonce_r,
            hello: datagram.to_vec(),
            challenge,
            source,
            created_ms: now_ms,
            last_send_ms: now_ms,
            sends: 1,
            session_id: None,
            ack: None,
        });
        self.recompute_state_bytes();
        vec![HandshakeEvent::Send {
            transport,
            target: source,
            frames: vec![frame],
        }]
    }

    fn handle_challenge(
        &mut self,
        datagram: &[u8],
        parsed: &crate::wire::ParsedFrame<'_>,
        transport: TransportId,
        source: Endpoint,
        now_ms: u64,
    ) -> Vec<HandshakeEvent> {
        if self.role != Role::Initiator {
            return vec![HandshakeEvent::Dropped(HandshakeReject::NoMatchingAttempt)];
        }
        let challenge = match ChallengePayload::decode(parsed.payload) {
            Ok(c) => c,
            Err(e) => return vec![HandshakeEvent::Dropped(HandshakeReject::Wire(e))],
        };
        let roles = self.roles();
        if challenge.lo_pub != roles.lo || challenge.hi_pub != roles.hi {
            return vec![HandshakeEvent::Dropped(HandshakeReject::WrongIdentity)];
        }
        let Some(idx) = self
            .attempts
            .iter()
            .position(|a| a.nonce_i == challenge.nonce_i)
        else {
            return vec![HandshakeEvent::Dropped(HandshakeReject::NoMatchingAttempt)];
        };
        let expected_th1 = self.attempts[idx].th1;
        if self.attempts[idx].transport != transport || self.attempts[idx].target != source {
            return vec![HandshakeEvent::Dropped(HandshakeReject::NoMatchingAttempt)];
        }
        // Once FINISH has selected a transcript, no other path may create a
        // competing session. Keep only the winning attempt after authentication.
        if self.attempts.iter().any(|a| a.awaiting_ack) && !self.attempts[idx].awaiting_ack {
            return vec![HandshakeEvent::Dropped(
                HandshakeReject::WouldPreemptHealthySession,
            )];
        }
        if challenge.th1 != expected_th1 {
            return vec![HandshakeEvent::Dropped(HandshakeReject::NoMatchingAttempt)];
        }
        let k_chal = self.prk.expand32(&info(
            LABEL_KDF_CHALLENGE,
            &[
                roles.lo.as_bytes(),
                roles.hi.as_bytes(),
                &challenge.nonce_i,
                &challenge.nonce_r,
                &challenge.th1,
            ],
        ));
        if !verify_frame_mac(&k_chal, &parsed.raw_header(), parsed.payload, parsed.mac) {
            return vec![HandshakeEvent::Dropped(HandshakeReject::BadMac)];
        }
        if !Self::fresh_enough(challenge.issued_at_unix_ms, now_ms) {
            return vec![HandshakeEvent::Dropped(HandshakeReject::ClockSkew)];
        }

        // Idempotent: a duplicate CHALLENGE reproduces the same FINISH, but
        // only within the same 1 s and 8-total-send budget. The first FINISH is
        // included in that count; a single received packet never produces more
        // than one reply.
        if let Some(existing) = self.attempts[idx].finish.clone() {
            if now_ms.saturating_sub(self.attempts[idx].last_send_ms) >= RETRANSMIT_INTERVAL_MS
                && self.attempts[idx].sends < MAX_RETRANSMITS
            {
                let attempt = &mut self.attempts[idx];
                attempt.last_send_ms = now_ms;
                attempt.sends += 1;
                return vec![HandshakeEvent::Send {
                    transport,
                    target: attempt.target,
                    frames: vec![existing],
                }];
            }
            return Vec::new();
        }

        let hello = self.attempts[idx].hello.clone();
        let th2 = transcript_hash(&[hello.as_slice(), datagram]);
        let k_fin = self.prk.expand32(&info(
            LABEL_KDF_FINISH,
            &[
                roles.lo.as_bytes(),
                roles.hi.as_bytes(),
                &challenge.nonce_i,
                &challenge.nonce_r,
                &challenge.th1,
                &th2,
            ],
        ));
        let finish = match encode_frame(
            FrameType::Finish,
            Direction::LoToHi,
            self.cfg.relationship_id,
            0,
            0,
            &FinishPayload {
                lo_pub: roles.lo,
                hi_pub: roles.hi,
                nonce_i: challenge.nonce_i,
                nonce_r: challenge.nonce_r,
                th1: challenge.th1,
                th2,
                boot_id: self.cfg.boot_id,
                generation: self.cfg.generation,
                issued_at_unix_ms: now_ms,
            }
            .encode(),
            &k_fin,
        ) {
            Ok(f) => f,
            Err(e) => return vec![HandshakeEvent::Dropped(HandshakeReject::Wire(e))],
        };

        let th3 = transcript_hash(&[hello.as_slice(), datagram, finish.as_slice()]);
        let keys = match self.derive_keys(
            &challenge.nonce_i,
            &challenge.nonce_r,
            &challenge.th1,
            &th2,
            &th3,
        ) {
            Ok(k) => k,
            Err(e) => return vec![HandshakeEvent::Dropped(e)],
        };

        {
            let attempt = &mut self.attempts[idx];
            attempt.finish = Some(finish.clone());
            attempt.th2 = Some(th2);
            attempt.awaiting_ack = true;
            attempt.last_send_ms = now_ms;
            attempt.sends += 1;
        }
        self.recompute_state_bytes();

        // The initiator can derive the session itself; th3 needs only frames it
        // already holds. Installing it lets it answer PINGs immediately.
        let session = Session {
            keys,
            tx_seq: 1,
            rx: ReplayWindow::new(),
            hello,
            challenge: datagram.to_vec(),
            finish: finish.clone(),
            created_ms: now_ms,
            ack_seen: false,
            ack_sent: false,
            local_boot_id: self.cfg.boot_id,
            peer_boot_id: challenge.boot_id,
            peer_generation: challenge.generation,
        };
        let session_id = session.keys.session_id;
        self.install_session(session, now_ms, false);

        let target = self.attempts[idx].target;
        self.attempts.retain(|a| a.nonce_i == challenge.nonce_i);
        self.recompute_state_bytes();
        vec![
            HandshakeEvent::Send {
                transport,
                target,
                frames: vec![finish],
            },
            HandshakeEvent::SessionInstalled { session_id },
        ]
    }

    fn handle_finish(
        &mut self,
        datagram: &[u8],
        parsed: &crate::wire::ParsedFrame<'_>,
        transport: TransportId,
        source: Endpoint,
        now_ms: u64,
    ) -> Vec<HandshakeEvent> {
        if self.role != Role::Responder {
            return vec![HandshakeEvent::Dropped(HandshakeReject::NoMatchingAttempt)];
        }
        let finish = match FinishPayload::decode(parsed.payload) {
            Ok(f) => f,
            Err(e) => return vec![HandshakeEvent::Dropped(HandshakeReject::Wire(e))],
        };
        let roles = self.roles();
        if finish.lo_pub != roles.lo || finish.hi_pub != roles.hi {
            return vec![HandshakeEvent::Dropped(HandshakeReject::WrongIdentity)];
        }
        let Some(idx) = self
            .responder
            .iter()
            .position(|e| e.nonce_i == finish.nonce_i && e.nonce_r == finish.nonce_r)
        else {
            return vec![HandshakeEvent::Dropped(HandshakeReject::NoMatchingAttempt)];
        };
        let expected_th2 = transcript_hash(&[
            self.responder[idx].hello.as_slice(),
            self.responder[idx].challenge.as_slice(),
        ]);
        if self.responder[idx].transport != transport || self.responder[idx].source != source {
            return vec![HandshakeEvent::Dropped(HandshakeReject::NoMatchingAttempt)];
        }
        if finish.th1 != transcript_hash(&[self.responder[idx].hello.as_slice()])
            || finish.th2 != expected_th2
        {
            return vec![HandshakeEvent::Dropped(HandshakeReject::NoMatchingAttempt)];
        }
        let k_fin = self.prk.expand32(&info(
            LABEL_KDF_FINISH,
            &[
                roles.lo.as_bytes(),
                roles.hi.as_bytes(),
                &finish.nonce_i,
                &finish.nonce_r,
                &finish.th1,
                &finish.th2,
            ],
        ));
        if !verify_frame_mac(&k_fin, &parsed.raw_header(), parsed.payload, parsed.mac) {
            return vec![HandshakeEvent::Dropped(HandshakeReject::BadMac)];
        }
        if !Self::fresh_enough(finish.issued_at_unix_ms, now_ms) {
            return vec![HandshakeEvent::Dropped(HandshakeReject::ClockSkew)];
        }

        let th3 = transcript_hash(&[
            self.responder[idx].hello.as_slice(),
            self.responder[idx].challenge.as_slice(),
            datagram,
        ]);
        let keys = match self.derive_keys(
            &finish.nonce_i,
            &finish.nonce_r,
            &finish.th1,
            &finish.th2,
            &th3,
        ) {
            Ok(k) => k,
            Err(e) => return vec![HandshakeEvent::Dropped(e)],
        };

        // Idempotent repeat: same session id, same transcript -> same ACK.
        // This is not a collision. It is still bounded exactly like the first
        // response: at most one reply per second and at most 8 sends for this
        // entry, with the first ACK counted.
        if let Some(existing) = self.responder[idx].ack.clone() {
            if self.responder[idx].session_id == Some(keys.session_id) {
                if now_ms.saturating_sub(self.responder[idx].last_send_ms) >= RETRANSMIT_INTERVAL_MS
                    && self.responder[idx].sends < MAX_RETRANSMITS
                {
                    let entry = &mut self.responder[idx];
                    entry.last_send_ms = now_ms;
                    entry.sends += 1;
                    return vec![HandshakeEvent::Send {
                        transport,
                        target: source,
                        frames: vec![existing],
                    }];
                }
                return Vec::new();
            }
            return vec![HandshakeEvent::Dropped(HandshakeReject::SessionIdRejected)];
        }

        let ack = match encode_frame(
            FrameType::Ack,
            Direction::HiToLo,
            self.cfg.relationship_id,
            0,
            0,
            &AckPayload {
                hi_pub: roles.hi,
                lo_pub: roles.lo,
                th3,
                boot_id: self.cfg.boot_id,
                generation: self.cfg.generation,
                issued_at_unix_ms: now_ms,
            }
            .encode(),
            keys.tx_key(Role::Responder),
        ) {
            Ok(f) => f,
            Err(e) => return vec![HandshakeEvent::Dropped(HandshakeReject::Wire(e))],
        };

        let session = Session {
            keys,
            tx_seq: 1,
            rx: ReplayWindow::new(),
            hello: self.responder[idx].hello.clone(),
            challenge: self.responder[idx].challenge.clone(),
            finish: datagram.to_vec(),
            created_ms: now_ms,
            ack_seen: false,
            ack_sent: true,
            local_boot_id: self.cfg.boot_id,
            peer_boot_id: finish.boot_id,
            peer_generation: finish.generation,
        };
        let session_id = session.keys.session_id;
        self.responder[idx].session_id = Some(session_id);
        self.responder[idx].ack = Some(ack.clone());
        self.responder[idx].last_send_ms = now_ms;
        self.responder[idx].sends += 1;
        self.recompute_state_bytes();
        self.install_session(session, now_ms, false);

        vec![
            HandshakeEvent::Send {
                transport,
                target: source,
                frames: vec![ack],
            },
            HandshakeEvent::SessionInstalled { session_id },
        ]
    }

    fn handle_ack(
        &mut self,
        parsed: &crate::wire::ParsedFrame<'_>,
        transport: TransportId,
        source: Endpoint,
        now_ms: u64,
    ) -> Vec<HandshakeEvent> {
        if self.role != Role::Initiator {
            return vec![HandshakeEvent::Dropped(HandshakeReject::NoMatchingAttempt)];
        }
        let ack = match AckPayload::decode(parsed.payload) {
            Ok(a) => a,
            Err(e) => return vec![HandshakeEvent::Dropped(HandshakeReject::Wire(e))],
        };
        let roles = self.roles();
        if ack.lo_pub != roles.lo || ack.hi_pub != roles.hi {
            return vec![HandshakeEvent::Dropped(HandshakeReject::WrongIdentity)];
        }
        let Some(session) = self.session.as_ref() else {
            return vec![HandshakeEvent::Dropped(HandshakeReject::NoMatchingAttempt)];
        };
        if !self
            .attempts
            .iter()
            .any(|a| a.awaiting_ack && a.transport == transport && a.target == source)
        {
            return vec![HandshakeEvent::Dropped(HandshakeReject::NoMatchingAttempt)];
        }
        if !verify_frame_mac(
            session.keys.rx_key(self.role),
            &parsed.raw_header(),
            parsed.payload,
            parsed.mac,
        ) {
            return vec![HandshakeEvent::Dropped(HandshakeReject::BadMac)];
        }
        if ack.th3 != session.keys.th3 {
            return vec![HandshakeEvent::Dropped(HandshakeReject::NoMatchingAttempt)];
        }
        if !Self::fresh_enough(ack.issued_at_unix_ms, now_ms) {
            return vec![HandshakeEvent::Dropped(HandshakeReject::ClockSkew)];
        }
        let session_id = session.keys.session_id;
        if let Some(s) = self.session.as_mut() {
            s.ack_seen = true;
        }
        vec![HandshakeEvent::AckReceived { session_id }]
    }

    fn derive_keys(
        &self,
        nonce_i: &[u8; 32],
        nonce_r: &[u8; 32],
        th1: &[u8; 32],
        th2: &[u8; 32],
        th3: &[u8; 32],
    ) -> Result<SessionKeys, HandshakeReject> {
        let roles = self.roles();
        let lo = roles.lo.as_bytes();
        let hi = roles.hi.as_bytes();
        let session_id = u64::from_be_bytes(self.prk.expand8(&info(
            LABEL_KDF_SESSION_ID,
            &[lo, hi, nonce_i, nonce_r, th3],
        )));
        if session_id == 0 {
            return Err(HandshakeReject::SessionIdRejected);
        }
        // A different transcript that lands on the same id is a real collision.
        if let Some(existing) = self.session.as_ref()
            && existing.keys.session_id == session_id
            && existing.keys.th3 != *th3
        {
            return Err(HandshakeReject::SessionIdRejected);
        }
        let _ = th1;
        let _ = th2;
        Ok(SessionKeys {
            session_id,
            k_i2r: self
                .prk
                .expand32(&info(LABEL_KDF_KEY_I2R, &[lo, hi, nonce_i, nonce_r, th3])),
            k_r2i: self
                .prk
                .expand32(&info(LABEL_KDF_KEY_R2I, &[lo, hi, nonce_i, nonce_r, th3])),
            th3: *th3,
        })
    }

    /// Install a session.
    ///
    /// `force` is used for a locally authorised rekey. Without it, a new
    /// session must not displace a healthy one: it goes to the bounded shadow
    /// table instead.
    fn install_session(&mut self, session: Session, _now_ms: u64, force: bool) {
        // P0 does not implement rekey. A rekey intent therefore NEVER causes a
        // switch: it is recorded and bounded, but promoting a new session over a
        // healthy one requires a full make-before-break rekey that does not
        // exist yet. Only the absence of any session lets a new one install.
        let replace = force || self.session.is_none();
        if replace {
            if let Some(old) = self.session.take() {
                self.shadow.push(old);
                while self.shadow.len() > MAX_SHADOW_SESSIONS {
                    self.shadow.remove(0);
                }
            }
            self.session = Some(session);
            self.rekey = None;
        } else {
            self.shadow.push(session);
            while self.shadow.len() > MAX_SHADOW_SESSIONS {
                self.shadow.remove(0);
            }
        }
    }

    /// Promote a shadow session, used after bilateral confirmation of a
    /// locally authorised rekey.
    pub fn promote_shadow(&mut self, session_id: u64) -> bool {
        let Some(idx) = self
            .shadow
            .iter()
            .position(|s| s.keys.session_id == session_id)
        else {
            return false;
        };
        let new = self.shadow.remove(idx);
        if let Some(old) = self.session.take() {
            self.shadow.push(old);
            while self.shadow.len() > MAX_SHADOW_SESSIONS {
                self.shadow.remove(0);
            }
        }
        self.session = Some(new);
        true
    }

    /// Number of shadow sessions held.
    pub fn shadow_len(&self) -> usize {
        self.shadow.len()
    }

    /// Forget pending work on a socket that will never be used again.
    pub fn remove_transport(&mut self, transport: TransportId) {
        self.attempts.retain(|a| a.transport != transport);
        self.responder.retain(|e| e.transport != transport);
        self.recompute_state_bytes();
    }

    pub(crate) fn pending_paths(&self) -> Vec<PathEndpoint> {
        self.attempts
            .iter()
            .map(|a| PathEndpoint {
                transport: a.transport,
                remote: a.target,
            })
            .chain(self.responder.iter().map(|e| PathEndpoint {
                transport: e.transport,
                remote: e.source,
            }))
            .collect()
    }

    pub(crate) fn remove_path(&mut self, path: PathEndpoint) {
        self.attempts
            .retain(|a| a.transport != path.transport || a.target != path.remote);
        self.responder
            .retain(|e| e.transport != path.transport || e.source != path.remote);
        self.recompute_state_bytes();
    }

    /// MAC a frame we are about to send under the current session.
    pub fn mac_for(&self, header: &Header, payload: &[u8]) -> Option<[u8; 32]> {
        let session = self.session.as_ref()?;
        Some(frame_mac(
            session.keys.tx_key(self.role),
            &header.to_bytes(),
            payload,
        ))
    }
}

#[cfg(test)]
mod tests;
