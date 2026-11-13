//! Authenticated session state and direction-specific keys.

use lzh_hole_types::{BootId, Role};

use crate::crypto::Key32;
use crate::replay::ReplayWindow;
use crate::wire::Direction;

/// How close to `u64::MAX` the outbound sequence may get before a session is
/// treated as exhausted. Sequence wraparound is never permitted.
pub const SESSION_SEQ_EXHAUSTION_MARGIN: u64 = 1024;

/// The derived material for one established session.
#[derive(Debug)]
pub struct SessionKeys {
    /// Session identifier, never zero.
    pub session_id: u64,
    /// lo to hi key.
    pub k_i2r: Key32,
    /// hi to lo key.
    pub k_r2i: Key32,
    /// Final transcript hash.
    pub th3: [u8; 32],
}

impl SessionKeys {
    /// The key used to MAC frames we send.
    pub fn tx_key(&self, role: Role) -> &Key32 {
        match role {
            Role::Initiator => &self.k_i2r,
            Role::Responder => &self.k_r2i,
        }
    }

    /// The key used to verify frames we receive.
    pub fn rx_key(&self, role: Role) -> &Key32 {
        match role {
            Role::Initiator => &self.k_r2i,
            Role::Responder => &self.k_i2r,
        }
    }

    /// The direction our frames travel.
    pub fn tx_direction(role: Role) -> Direction {
        match role {
            Role::Initiator => Direction::LoToHi,
            Role::Responder => Direction::HiToLo,
        }
    }

    /// The direction the peer's frames travel.
    pub fn rx_direction(role: Role) -> Direction {
        Self::tx_direction(role).flipped()
    }
}

/// An installed session.
#[derive(Debug)]
pub struct Session {
    /// Derived keys.
    pub keys: SessionKeys,
    /// Next sequence number we will send.
    pub tx_seq: u64,
    /// Replay window for the peer's direction.
    pub rx: ReplayWindow,
    /// The three transcript frames, kept so an ACK can be reproduced exactly.
    pub hello: Vec<u8>,
    /// The CHALLENGE frame.
    pub challenge: Vec<u8>,
    /// The FINISH frame.
    pub finish: Vec<u8>,
    /// When this session was installed.
    pub created_ms: u64,
    /// Whether we have seen the peer's ACK.
    pub ack_seen: bool,
    /// Whether we have sent our ACK.
    pub ack_sent: bool,
    /// Local process epoch for this session.
    pub local_boot_id: BootId,
    /// Peer's process epoch for this session.
    pub peer_boot_id: BootId,
    /// Peer's network generation for this session.
    pub peer_generation: u64,
}

impl Session {
    /// Allocate the next outbound sequence number.
    ///
    /// Saturating: the caller must check `sequence_exhausted` first. Wrapping
    /// would replay a sequence the peer has already accepted.
    pub fn next_tx_seq(&mut self) -> u64 {
        let seq = self.tx_seq;
        self.tx_seq = self.tx_seq.saturating_add(1);
        seq
    }

    /// Whether no further frame may safely be sent on this session.
    pub fn sequence_exhausted(&self) -> bool {
        self.tx_seq >= u64::MAX - SESSION_SEQ_EXHAUSTION_MARGIN
    }

    /// Session rekey remains unsupported; an offline session is rebuilt instead.
    pub const fn rekey_supported() -> bool {
        false
    }
}
