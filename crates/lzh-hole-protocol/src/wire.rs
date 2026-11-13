//! Frame header and payload codecs for wire version 1.
//!
//! Every offset here is specified in doc/protocol.md and pinned by
//! tests/fixtures/wire-v1.json. The Rust encoder is cross-checked against
//! that fixture in crates/lzh-hole-discovery/tests/fixture_vectors.rs.

use lzh_hole_types::{BootId, DiscoveryPublicKey, RelationshipId};

/// Frame magic, ASCII "LZH1".
pub const MAGIC: u32 = 0x4C5A_4831;
/// Wire version implemented here.
pub const VERSION: u8 = 1;
/// Fixed header length, excluding the trailing MAC.
pub const HEADER_LEN: usize = 42;
/// Full HMAC-SHA256 tag length.
pub const MAC_LEN: usize = 32;
/// Header plus MAC.
pub const FRAME_OVERHEAD: usize = HEADER_LEN + MAC_LEN;
/// Uniform payload length of HELLO, CHALLENGE, FINISH and ACK.
pub const HANDSHAKE_PAYLOAD_LEN: usize = 240;
/// PROBE payload length.
pub const PROBE_PAYLOAD_LEN: usize = 128;
/// PING and PONG payload length.
pub const CTRL_PAYLOAD_LEN: usize = 136;
/// Largest permitted DATA payload.
pub const MAX_PAYLOAD_LEN: usize = 1400;
/// Every handshake frame is exactly this long, so no response is ever larger
/// than its request.
pub const HANDSHAKE_FRAME_LEN: usize = FRAME_OVERHEAD + HANDSHAKE_PAYLOAD_LEN;

/// flags bit: the sender has completed its own PING/PONG round trip.
pub const FLAG_LOCAL_CONFIRMED: u8 = 0b0000_0001;
/// flags bit: this PING is a return-path probe for a pending endpoint.
pub const FLAG_PATH_PROBE: u8 = 0b0000_0010;
/// flags bit: the sender requests a rekey. Only legal on a PING.
pub const FLAG_REKEY_REQUEST: u8 = 0b0000_0100;
/// Bits that must be zero in every control frame.
pub const FLAG_RESERVED_MASK: u8 = 0b1111_1000;

/// Frame type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameType {
    /// Initiator opens an attempt.
    Hello,
    /// Responder answers a valid HELLO.
    Challenge,
    /// Initiator proves it derived the session.
    Finish,
    /// Responder proves it received FINISH.
    Ack,
    /// Responder keeps its own NAT mapping open. Never answered.
    Probe,
    /// Plaintext IPv4 packet.
    Data,
    /// Health challenge.
    CtrlPing,
    /// Health response.
    CtrlPong,
}

impl FrameType {
    /// The on-wire byte.
    pub const fn as_u8(self) -> u8 {
        match self {
            FrameType::Hello => 0x01,
            FrameType::Challenge => 0x02,
            FrameType::Finish => 0x03,
            FrameType::Ack => 0x04,
            FrameType::Probe => 0x05,
            FrameType::Data => 0x10,
            FrameType::CtrlPing => 0x20,
            FrameType::CtrlPong => 0x21,
        }
    }

    /// Parse a type byte.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(FrameType::Hello),
            0x02 => Some(FrameType::Challenge),
            0x03 => Some(FrameType::Finish),
            0x04 => Some(FrameType::Ack),
            0x05 => Some(FrameType::Probe),
            0x10 => Some(FrameType::Data),
            0x20 => Some(FrameType::CtrlPing),
            0x21 => Some(FrameType::CtrlPong),
            _ => None,
        }
    }

    /// Whether this type is part of the handshake transcript.
    pub const fn is_handshake(self) -> bool {
        matches!(
            self,
            FrameType::Hello | FrameType::Challenge | FrameType::Finish | FrameType::Ack
        )
    }

    /// Whether this frame carries no session, and so must use session_id 0 and
    /// sequence 0.
    pub const fn is_sessionless(self) -> bool {
        self.is_handshake() || matches!(self, FrameType::Probe)
    }

    /// Whether the direction of this frame type is fixed.
    pub const fn has_fixed_direction(self) -> bool {
        self.is_sessionless()
    }

    /// The direction this frame type must carry, when fixed.
    pub const fn required_direction(self) -> Direction {
        match self {
            FrameType::Hello | FrameType::Finish => Direction::LoToHi,
            FrameType::Challenge | FrameType::Ack | FrameType::Probe => Direction::HiToLo,
            FrameType::Data | FrameType::CtrlPing | FrameType::CtrlPong => Direction::LoToHi,
        }
    }

    /// Fixed payload length, when the type has one.
    pub const fn fixed_payload_len(self) -> Option<usize> {
        match self {
            FrameType::Hello | FrameType::Challenge | FrameType::Finish | FrameType::Ack => {
                Some(HANDSHAKE_PAYLOAD_LEN)
            }
            FrameType::Probe => Some(PROBE_PAYLOAD_LEN),
            FrameType::CtrlPing | FrameType::CtrlPong => Some(CTRL_PAYLOAD_LEN),
            FrameType::Data => None,
        }
    }
}

/// Which way a frame travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// lo to hi.
    LoToHi,
    /// hi to lo.
    HiToLo,
}

impl Direction {
    /// The on-wire byte.
    pub const fn as_u8(self) -> u8 {
        match self {
            Direction::LoToHi => 0,
            Direction::HiToLo => 1,
        }
    }

    /// Parse a direction byte.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Direction::LoToHi),
            1 => Some(Direction::HiToLo),
            _ => None,
        }
    }

    /// The opposite direction.
    pub const fn flipped(self) -> Self {
        match self {
            Direction::LoToHi => Direction::HiToLo,
            Direction::HiToLo => Direction::LoToHi,
        }
    }
}

/// Why a frame or payload was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// Fewer bytes than the fixed overhead.
    #[error("frame shorter than 74 bytes")]
    TooShort,
    /// Magic mismatch.
    #[error("bad magic")]
    BadMagic,
    /// Unsupported version.
    #[error("unsupported version {0}")]
    BadVersion(u8),
    /// Unknown frame type byte.
    #[error("unknown frame type {0:#04x}")]
    UnknownFrameType(u8),
    /// Direction byte not 0 or 1, or not the one this type requires.
    #[error("bad direction byte {0}")]
    BadDirection(u8),
    /// Header flags must be zero in v1.
    #[error("header flags must be zero")]
    NonZeroFrameFlags,
    /// payload_len disagrees with the buffer length.
    #[error("payload_len {declared} does not match {actual} available bytes")]
    PayloadLenMismatch {
        /// Value from the header.
        declared: usize,
        /// Bytes actually present.
        actual: usize,
    },
    /// Payload above the cap.
    #[error("payload of {0} bytes exceeds the 1400 byte cap")]
    PayloadTooLarge(usize),
    /// Payload length is not the fixed size for this type.
    #[error("payload of {got} bytes, expected {expected} for this frame type")]
    WrongFixedPayloadLen {
        /// Required length.
        expected: usize,
        /// Supplied length.
        got: usize,
    },
    /// Padding byte was not zero.
    #[error("non-zero padding at payload offset {0}")]
    NonZeroPadding(usize),
    /// Reserved byte was not zero.
    #[error("non-zero reserved byte at payload offset {0}")]
    NonZeroReserved(usize),
    /// A PONG carried the rekey request bit.
    #[error("PONG must not set the rekey request bit")]
    PongRekeyBitSet,
    /// A control frame set a reserved flag bit.
    #[error("reserved flag bits set: {0:#04x}")]
    ReservedFlagBits(u8),
    /// A sessionless frame carried a session id or a non-zero sequence.
    #[error("sessionless frame must use session_id 0 and sequence 0")]
    SessionlessNotZero,
    /// A session frame carried session id 0 or sequence 0.
    #[error("session frame must use a non-zero session_id and sequence >= 1")]
    SessionFrameNotNumbered,
}

/// The fixed 42-byte header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Frame type.
    pub frame_type: FrameType,
    /// Travel direction.
    pub direction: Direction,
    /// Relationship this frame belongs to.
    pub relationship_id: RelationshipId,
    /// Session identifier, or 0 for a sessionless frame.
    pub session_id: u64,
    /// Per-direction sequence, or 0 for a sessionless frame.
    pub sequence: u64,
    /// Payload length in bytes.
    pub payload_len: u16,
}

impl Header {
    /// Serialise to exactly HEADER_LEN bytes.
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&MAGIC.to_be_bytes());
        out[4] = VERSION;
        out[5] = self.frame_type.as_u8();
        out[6] = self.direction.as_u8();
        out[7] = 0;
        out[8..24].copy_from_slice(self.relationship_id.as_bytes());
        out[24..32].copy_from_slice(&self.session_id.to_be_bytes());
        out[32..40].copy_from_slice(&self.sequence.to_be_bytes());
        out[40..42].copy_from_slice(&self.payload_len.to_be_bytes());
        out
    }

    /// Parse and structurally validate a header.
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() < HEADER_LEN {
            return Err(WireError::TooShort);
        }
        if u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) != MAGIC {
            return Err(WireError::BadMagic);
        }
        if bytes[4] != VERSION {
            return Err(WireError::BadVersion(bytes[4]));
        }
        let frame_type =
            FrameType::from_u8(bytes[5]).ok_or(WireError::UnknownFrameType(bytes[5]))?;
        let direction = Direction::from_u8(bytes[6]).ok_or(WireError::BadDirection(bytes[6]))?;
        if bytes[7] != 0 {
            return Err(WireError::NonZeroFrameFlags);
        }
        let header = Self {
            frame_type,
            direction,
            relationship_id: RelationshipId::from_bytes(bytes[8..24].try_into().expect("16 bytes")),
            session_id: u64::from_be_bytes(bytes[24..32].try_into().expect("8 bytes")),
            sequence: u64::from_be_bytes(bytes[32..40].try_into().expect("8 bytes")),
            payload_len: u16::from_be_bytes(bytes[40..42].try_into().expect("2 bytes")),
        };
        header.check_session_numbering()?;
        Ok(header)
    }

    /// Enforce the reserved session-zero rule.
    pub fn check_session_numbering(&self) -> Result<(), WireError> {
        if self.frame_type.is_sessionless() {
            if self.session_id != 0 || self.sequence != 0 {
                return Err(WireError::SessionlessNotZero);
            }
        } else if self.session_id == 0 || self.sequence == 0 {
            return Err(WireError::SessionFrameNotNumbered);
        }
        Ok(())
    }
}

/// A structurally parsed frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedFrame<'a> {
    /// Parsed header.
    pub header: Header,
    /// Payload bytes, excluding the MAC.
    pub payload: &'a [u8],
    /// The trailing 32-byte tag.
    pub mac: &'a [u8],
}

impl ParsedFrame<'_> {
    /// The header bytes the MAC is computed over.
    pub fn raw_header(&self) -> [u8; HEADER_LEN] {
        self.header.to_bytes()
    }
}

/// Assemble a complete frame.
pub fn encode_frame(
    frame_type: FrameType,
    direction: Direction,
    relationship_id: RelationshipId,
    session_id: u64,
    sequence: u64,
    payload: &[u8],
    key: &crate::crypto::Key32,
) -> Result<Vec<u8>, WireError> {
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(WireError::PayloadTooLarge(payload.len()));
    }
    if let Some(expected) = frame_type.fixed_payload_len()
        && payload.len() != expected
    {
        return Err(WireError::WrongFixedPayloadLen {
            expected,
            got: payload.len(),
        });
    }
    let header = Header {
        frame_type,
        direction,
        relationship_id,
        session_id,
        sequence,
        payload_len: payload.len() as u16,
    };
    header.check_session_numbering()?;
    let raw = header.to_bytes();
    let mac = crate::crypto::frame_mac(key, &raw, payload);
    let mut out = Vec::with_capacity(FRAME_OVERHEAD + payload.len());
    out.extend_from_slice(&raw);
    out.extend_from_slice(payload);
    out.extend_from_slice(&mac);
    Ok(out)
}

/// Structural parse only. The caller must verify the MAC before trusting any
/// field, and must not allocate state before doing so.
pub fn parse_frame(buf: &[u8]) -> Result<ParsedFrame<'_>, WireError> {
    if buf.len() < FRAME_OVERHEAD {
        return Err(WireError::TooShort);
    }
    let header = Header::parse(&buf[..HEADER_LEN])?;
    let declared = usize::from(header.payload_len);
    let actual = buf.len() - FRAME_OVERHEAD;
    if declared != actual {
        return Err(WireError::PayloadLenMismatch { declared, actual });
    }
    if declared > MAX_PAYLOAD_LEN {
        return Err(WireError::PayloadTooLarge(declared));
    }
    if let Some(expected) = header.frame_type.fixed_payload_len()
        && declared != expected
    {
        return Err(WireError::WrongFixedPayloadLen {
            expected,
            got: declared,
        });
    }
    if header.frame_type.has_fixed_direction()
        && header.direction != header.frame_type.required_direction()
    {
        return Err(WireError::BadDirection(header.direction.as_u8()));
    }
    Ok(ParsedFrame {
        header,
        payload: &buf[HEADER_LEN..HEADER_LEN + declared],
        mac: &buf[HEADER_LEN + declared..],
    })
}

fn check_zero_padding(payload: &[u8], from: usize) -> Result<(), WireError> {
    for (i, byte) in payload.iter().enumerate().skip(from) {
        if *byte != 0 {
            return Err(WireError::NonZeroPadding(i));
        }
    }
    Ok(())
}

fn take<const N: usize>(payload: &[u8], off: usize) -> [u8; N] {
    payload[off..off + N].try_into().expect("slice is N bytes")
}

fn u64_at(payload: &[u8], off: usize) -> u64 {
    u64::from_be_bytes(take::<8>(payload, off))
}

/// A field that has a fixed big-endian wire representation.
pub trait WireField: Sized {
    /// Number of bytes on the wire.
    const LEN: usize;
    /// Write into the start of out, which is at least LEN bytes.
    fn write_to(&self, out: &mut [u8]);
    /// Read from the start of bytes, which is at least LEN bytes.
    fn read_from(bytes: &[u8]) -> Self;
}

impl WireField for u64 {
    const LEN: usize = 8;

    fn write_to(&self, out: &mut [u8]) {
        out[..8].copy_from_slice(&self.to_be_bytes());
    }

    fn read_from(bytes: &[u8]) -> Self {
        u64::from_be_bytes(bytes[..8].try_into().expect("8 bytes"))
    }
}

impl WireField for [u8; 32] {
    const LEN: usize = 32;

    fn write_to(&self, out: &mut [u8]) {
        out[..32].copy_from_slice(self);
    }

    fn read_from(bytes: &[u8]) -> Self {
        bytes[..32].try_into().expect("32 bytes")
    }
}

impl WireField for DiscoveryPublicKey {
    const LEN: usize = 32;

    fn write_to(&self, out: &mut [u8]) {
        out[..32].copy_from_slice(self.as_bytes());
    }

    fn read_from(bytes: &[u8]) -> Self {
        Self::from_bytes(bytes[..32].try_into().expect("32 bytes"))
    }
}

impl WireField for BootId {
    const LEN: usize = 16;

    fn write_to(&self, out: &mut [u8]) {
        out[..16].copy_from_slice(self.as_bytes());
    }

    fn read_from(bytes: &[u8]) -> Self {
        Self::from_bytes(bytes[..16].try_into().expect("16 bytes"))
    }
}

macro_rules! handshake_payload {
    ($name:ident, $used:expr, { $($field:ident : $ty:ty = $off:expr),* $(,)? }) => {
        /// Fixed-size handshake payload with canonical zero padding.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name {
            $(
                /// Payload field.
                pub $field: $ty,
            )*
        }

        impl $name {
            /// Number of meaningful bytes before the zero padding.
            pub const USED: usize = $used;

            /// Serialise with canonical zero padding.
            pub fn encode(&self) -> [u8; HANDSHAKE_PAYLOAD_LEN] {
                let mut out = [0u8; HANDSHAKE_PAYLOAD_LEN];
                $(
                    self.$field.write_to(&mut out[$off..$off + <$ty as WireField>::LEN]);
                )*
                out
            }

            /// Parse and validate canonical zero padding.
            pub fn decode(payload: &[u8]) -> Result<Self, WireError> {
                if payload.len() != HANDSHAKE_PAYLOAD_LEN {
                    return Err(WireError::WrongFixedPayloadLen {
                        expected: HANDSHAKE_PAYLOAD_LEN,
                        got: payload.len(),
                    });
                }
                check_zero_padding(payload, Self::USED)?;
                Ok(Self {
                    $(
                        $field: <$ty as WireField>::read_from(
                            &payload[$off..$off + <$ty as WireField>::LEN],
                        ),
                    )*
                })
            }
        }
    };
}

handshake_payload!(HelloPayload, 128, {
    lo_pub: DiscoveryPublicKey = 0,
    hi_pub: DiscoveryPublicKey = 32,
    nonce_i: [u8; 32] = 64,
    boot_id: BootId = 96,
    generation: u64 = 112,
    issued_at_unix_ms: u64 = 120,
});

handshake_payload!(ChallengePayload, 192, {
    hi_pub: DiscoveryPublicKey = 0,
    lo_pub: DiscoveryPublicKey = 32,
    nonce_i: [u8; 32] = 64,
    nonce_r: [u8; 32] = 96,
    th1: [u8; 32] = 128,
    boot_id: BootId = 160,
    generation: u64 = 176,
    issued_at_unix_ms: u64 = 184,
});

handshake_payload!(FinishPayload, 224, {
    lo_pub: DiscoveryPublicKey = 0,
    hi_pub: DiscoveryPublicKey = 32,
    nonce_i: [u8; 32] = 64,
    nonce_r: [u8; 32] = 96,
    th1: [u8; 32] = 128,
    th2: [u8; 32] = 160,
    boot_id: BootId = 192,
    generation: u64 = 208,
    issued_at_unix_ms: u64 = 216,
});

handshake_payload!(AckPayload, 128, {
    hi_pub: DiscoveryPublicKey = 0,
    lo_pub: DiscoveryPublicKey = 32,
    th3: [u8; 32] = 64,
    boot_id: BootId = 96,
    generation: u64 = 112,
    issued_at_unix_ms: u64 = 120,
});

/// PROBE payload, exactly PROBE_PAYLOAD_LEN bytes with no padding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbePayload {
    /// Sender public key (hi).
    pub sender: DiscoveryPublicKey,
    /// Receiver public key (lo).
    pub receiver: DiscoveryPublicKey,
    /// Sender process epoch.
    pub boot_id: BootId,
    /// Sender network generation.
    pub generation: u64,
    /// Issue time.
    pub issued_at_unix_ms: u64,
    /// Fresh nonce, used only to count distinct probes.
    pub probe_nonce: [u8; 32],
}

impl ProbePayload {
    /// Serialise.
    pub fn encode(&self) -> [u8; PROBE_PAYLOAD_LEN] {
        let mut out = [0u8; PROBE_PAYLOAD_LEN];
        out[0..32].copy_from_slice(self.sender.as_bytes());
        out[32..64].copy_from_slice(self.receiver.as_bytes());
        out[64..80].copy_from_slice(self.boot_id.as_bytes());
        out[80..88].copy_from_slice(&self.generation.to_be_bytes());
        out[88..96].copy_from_slice(&self.issued_at_unix_ms.to_be_bytes());
        out[96..128].copy_from_slice(&self.probe_nonce);
        out
    }

    /// Parse.
    pub fn decode(payload: &[u8]) -> Result<Self, WireError> {
        if payload.len() != PROBE_PAYLOAD_LEN {
            return Err(WireError::WrongFixedPayloadLen {
                expected: PROBE_PAYLOAD_LEN,
                got: payload.len(),
            });
        }
        Ok(Self {
            sender: DiscoveryPublicKey::from_bytes(take(payload, 0)),
            receiver: DiscoveryPublicKey::from_bytes(take(payload, 32)),
            boot_id: BootId::from_bytes(take(payload, 64)),
            generation: u64_at(payload, 80),
            issued_at_unix_ms: u64_at(payload, 88),
            probe_nonce: take(payload, 96),
        })
    }
}

/// PING and PONG share this layout. Only the meaning of nonce differs: fresh on
/// a PING, an echo on a PONG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtrlPayload {
    /// Sender public key.
    pub sender: DiscoveryPublicKey,
    /// Receiver public key.
    pub receiver: DiscoveryPublicKey,
    /// Fresh challenge nonce (PING) or the answered nonce (PONG).
    pub nonce: [u8; 32],
    /// Sender process epoch.
    pub boot_id: BootId,
    /// Sender network generation.
    pub generation: u64,
    /// Issue time.
    pub issued_at_unix_ms: u64,
    /// Flag bits.
    pub flags: u8,
}

/// Offset of the flags byte in a control payload.
pub const CTRL_FLAGS_OFFSET: usize = 128;
/// Offset of the reserved tail in a control payload.
pub const CTRL_RESERVED_OFFSET: usize = 129;

impl CtrlPayload {
    /// Serialise.
    pub fn encode(&self) -> [u8; CTRL_PAYLOAD_LEN] {
        let mut out = [0u8; CTRL_PAYLOAD_LEN];
        out[0..32].copy_from_slice(self.sender.as_bytes());
        out[32..64].copy_from_slice(self.receiver.as_bytes());
        out[64..96].copy_from_slice(&self.nonce);
        out[96..112].copy_from_slice(self.boot_id.as_bytes());
        out[112..120].copy_from_slice(&self.generation.to_be_bytes());
        out[120..128].copy_from_slice(&self.issued_at_unix_ms.to_be_bytes());
        out[CTRL_FLAGS_OFFSET] = self.flags;
        out
    }

    /// Parse a PING, enforcing the PING flag rules.
    pub fn decode_ping(payload: &[u8]) -> Result<Self, WireError> {
        let ctrl = Self::decode_raw(payload)?;
        if ctrl.flags & FLAG_RESERVED_MASK != 0 {
            return Err(WireError::ReservedFlagBits(ctrl.flags & FLAG_RESERVED_MASK));
        }
        Ok(ctrl)
    }

    /// Parse a PONG. A PONG must never carry the rekey request bit.
    pub fn decode_pong(payload: &[u8]) -> Result<Self, WireError> {
        let ctrl = Self::decode_raw(payload)?;
        if ctrl.flags & FLAG_RESERVED_MASK != 0 {
            return Err(WireError::ReservedFlagBits(ctrl.flags & FLAG_RESERVED_MASK));
        }
        if ctrl.flags & FLAG_REKEY_REQUEST != 0 {
            return Err(WireError::PongRekeyBitSet);
        }
        Ok(ctrl)
    }

    fn decode_raw(payload: &[u8]) -> Result<Self, WireError> {
        if payload.len() != CTRL_PAYLOAD_LEN {
            return Err(WireError::WrongFixedPayloadLen {
                expected: CTRL_PAYLOAD_LEN,
                got: payload.len(),
            });
        }
        if let Some(offset) = payload[CTRL_RESERVED_OFFSET..].iter().position(|b| *b != 0) {
            return Err(WireError::NonZeroReserved(CTRL_RESERVED_OFFSET + offset));
        }
        Ok(Self {
            sender: DiscoveryPublicKey::from_bytes(take(payload, 0)),
            receiver: DiscoveryPublicKey::from_bytes(take(payload, 32)),
            nonce: take(payload, 64),
            boot_id: BootId::from_bytes(take(payload, 96)),
            generation: u64_at(payload, 112),
            issued_at_unix_ms: u64_at(payload, 120),
            flags: payload[CTRL_FLAGS_OFFSET],
        })
    }

    /// Whether the sender claims its own round trip is complete.
    pub const fn local_confirmed(&self) -> bool {
        self.flags & FLAG_LOCAL_CONFIRMED != 0
    }

    /// Whether this is a return-path probe.
    pub const fn path_probe(&self) -> bool {
        self.flags & FLAG_PATH_PROBE != 0
    }

    /// Whether the sender requests a rekey. Only meaningful on a PING.
    pub const fn rekey_request(&self) -> bool {
        self.flags & FLAG_REKEY_REQUEST != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Key32;

    fn k(b: u8) -> Key32 {
        Key32::from_bytes([b; 32])
    }

    fn rel() -> RelationshipId {
        RelationshipId::from_bytes((0..16).collect::<Vec<u8>>().try_into().unwrap())
    }

    fn pk(start: u8) -> DiscoveryPublicKey {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = start.wrapping_add(i as u8);
        }
        DiscoveryPublicKey::from_bytes(out)
    }

    fn boot(start: u8) -> BootId {
        let mut out = [0u8; 16];
        for (i, b) in out.iter_mut().enumerate() {
            *b = start.wrapping_add(i as u8);
        }
        BootId::from_bytes(out)
    }

    #[test]
    fn header_round_trips() {
        let header = Header {
            frame_type: FrameType::CtrlPing,
            direction: Direction::LoToHi,
            relationship_id: rel(),
            session_id: 0x1122_3344_5566_7788,
            sequence: 42,
            payload_len: 136,
        };
        let raw = header.to_bytes();
        assert_eq!(raw.len(), HEADER_LEN);
        assert_eq!(&raw[0..4], &MAGIC.to_be_bytes());
        assert_eq!(raw[4], VERSION);
        assert_eq!(raw[5], 0x20);
        assert_eq!(raw[6], 0);
        assert_eq!(raw[7], 0);
        assert_eq!(Header::parse(&raw).unwrap(), header);
    }

    #[test]
    fn all_handshake_frames_have_the_same_length() {
        assert_eq!(HANDSHAKE_FRAME_LEN, 314);
        for ft in [
            FrameType::Hello,
            FrameType::Challenge,
            FrameType::Finish,
            FrameType::Ack,
        ] {
            assert_eq!(ft.fixed_payload_len(), Some(HANDSHAKE_PAYLOAD_LEN));
        }
    }

    #[test]
    fn sessionless_frames_must_be_zero_numbered() {
        for ft in [
            FrameType::Hello,
            FrameType::Challenge,
            FrameType::Finish,
            FrameType::Ack,
            FrameType::Probe,
        ] {
            assert!(ft.is_sessionless());
            let bad = Header {
                frame_type: ft,
                direction: ft.required_direction(),
                relationship_id: rel(),
                session_id: 1,
                sequence: 0,
                payload_len: 0,
            };
            assert_eq!(
                bad.check_session_numbering(),
                Err(WireError::SessionlessNotZero)
            );
        }
    }

    #[test]
    fn session_frames_must_be_numbered_from_one() {
        let base = Header {
            frame_type: FrameType::Data,
            direction: Direction::LoToHi,
            relationship_id: rel(),
            session_id: 0,
            sequence: 1,
            payload_len: 0,
        };
        assert_eq!(
            base.check_session_numbering(),
            Err(WireError::SessionFrameNotNumbered)
        );
        let zero_seq = Header {
            session_id: 9,
            sequence: 0,
            ..base
        };
        assert_eq!(
            zero_seq.check_session_numbering(),
            Err(WireError::SessionFrameNotNumbered)
        );
    }

    #[test]
    fn header_rejects_bad_magic_version_type_direction_and_flags() {
        let good = Header {
            frame_type: FrameType::Hello,
            direction: Direction::LoToHi,
            relationship_id: rel(),
            session_id: 0,
            sequence: 0,
            payload_len: 240,
        }
        .to_bytes();

        let mut m = good;
        m[0] ^= 1;
        assert_eq!(Header::parse(&m), Err(WireError::BadMagic));
        let mut v = good;
        v[4] = 2;
        assert_eq!(Header::parse(&v), Err(WireError::BadVersion(2)));
        let mut t = good;
        t[5] = 0x7f;
        assert_eq!(Header::parse(&t), Err(WireError::UnknownFrameType(0x7f)));
        let mut d = good;
        d[6] = 9;
        assert_eq!(Header::parse(&d), Err(WireError::BadDirection(9)));
        let mut f = good;
        f[7] = 1;
        assert_eq!(Header::parse(&f), Err(WireError::NonZeroFrameFlags));
        assert_eq!(Header::parse(&good[..41]), Err(WireError::TooShort));
    }

    #[test]
    fn reflected_handshake_direction_is_refused() {
        let frame = encode_frame(
            FrameType::Hello,
            Direction::HiToLo,
            rel(),
            0,
            0,
            &[0u8; HANDSHAKE_PAYLOAD_LEN],
            &k(1),
        )
        .unwrap();
        assert_eq!(parse_frame(&frame), Err(WireError::BadDirection(1)));
    }

    #[test]
    fn payload_len_must_match_the_buffer() {
        let frame = encode_frame(
            FrameType::Probe,
            Direction::HiToLo,
            rel(),
            0,
            0,
            &[7u8; PROBE_PAYLOAD_LEN],
            &k(1),
        )
        .unwrap();
        let mut short = frame.clone();
        short.remove(HEADER_LEN);
        assert!(matches!(
            parse_frame(&short),
            Err(WireError::PayloadLenMismatch { .. })
        ));
        let mut long = frame;
        long.push(0);
        assert!(matches!(
            parse_frame(&long),
            Err(WireError::PayloadLenMismatch { .. })
        ));
    }

    #[test]
    fn data_payload_cap_is_enforced() {
        assert!(matches!(
            encode_frame(
                FrameType::Data,
                Direction::LoToHi,
                rel(),
                1,
                1,
                &vec![0u8; MAX_PAYLOAD_LEN + 1],
                &k(1)
            ),
            Err(WireError::PayloadTooLarge(_))
        ));
        assert!(
            encode_frame(
                FrameType::Data,
                Direction::LoToHi,
                rel(),
                1,
                1,
                &vec![0u8; MAX_PAYLOAD_LEN],
                &k(1)
            )
            .is_ok()
        );
    }

    #[test]
    fn fixed_payload_length_is_enforced_per_type() {
        assert!(matches!(
            encode_frame(
                FrameType::Hello,
                Direction::LoToHi,
                rel(),
                0,
                0,
                &[0u8; 128],
                &k(1)
            ),
            Err(WireError::WrongFixedPayloadLen {
                expected: 240,
                got: 128
            })
        ));
    }

    #[test]
    fn hello_round_trips_and_rejects_nonzero_padding() {
        let hello = HelloPayload {
            lo_pub: pk(0x00),
            hi_pub: pk(0x20),
            nonce_i: [0x40; 32],
            boot_id: boot(0x80),
            generation: 7,
            issued_at_unix_ms: 1_762_920_000_000,
        };
        let encoded = hello.encode();
        assert_eq!(encoded.len(), HANDSHAKE_PAYLOAD_LEN);
        assert_eq!(HelloPayload::decode(&encoded).unwrap(), hello);
        assert!(encoded[HelloPayload::USED..].iter().all(|b| *b == 0));

        let mut tampered = encoded;
        tampered[HelloPayload::USED + 5] = 1;
        assert_eq!(
            HelloPayload::decode(&tampered),
            Err(WireError::NonZeroPadding(HelloPayload::USED + 5))
        );
    }

    #[test]
    fn used_lengths_match_the_contract() {
        assert_eq!(HelloPayload::USED, 128);
        assert_eq!(ChallengePayload::USED, 192);
        assert_eq!(FinishPayload::USED, 224);
        assert_eq!(AckPayload::USED, 128);
    }

    #[test]
    fn finish_padding_check_catches_the_fixture_negative_offset() {
        let mut payload = FinishPayload {
            lo_pub: pk(0x00),
            hi_pub: pk(0x20),
            nonce_i: [0x40; 32],
            nonce_r: [0x60; 32],
            th1: [0x11; 32],
            th2: [0x22; 32],
            boot_id: boot(0x80),
            generation: 7,
            issued_at_unix_ms: 1,
        }
        .encode();
        payload[229] = 1;
        assert_eq!(
            FinishPayload::decode(&payload),
            Err(WireError::NonZeroPadding(229))
        );
    }

    #[test]
    fn every_handshake_payload_validates_its_padding() {
        let mut p = [0u8; HANDSHAKE_PAYLOAD_LEN];
        p[239] = 9;
        assert!(HelloPayload::decode(&p).is_err());
        assert!(ChallengePayload::decode(&p).is_err());
        assert!(FinishPayload::decode(&p).is_err());
        assert!(AckPayload::decode(&p).is_err());
    }

    #[test]
    fn all_handshake_payloads_round_trip() {
        let challenge = ChallengePayload {
            hi_pub: pk(0x20),
            lo_pub: pk(0x00),
            nonce_i: [0x40; 32],
            nonce_r: [0x60; 32],
            th1: [0x11; 32],
            boot_id: boot(0x90),
            generation: 3,
            issued_at_unix_ms: 2,
        };
        assert_eq!(
            ChallengePayload::decode(&challenge.encode()).unwrap(),
            challenge
        );
        let ack = AckPayload {
            hi_pub: pk(0x20),
            lo_pub: pk(0x00),
            th3: [0x33; 32],
            boot_id: boot(0x90),
            generation: 3,
            issued_at_unix_ms: 3,
        };
        assert_eq!(AckPayload::decode(&ack.encode()).unwrap(), ack);
    }

    #[test]
    fn pong_must_never_carry_the_rekey_bit() {
        let mut payload = CtrlPayload {
            sender: pk(0x20),
            receiver: pk(0x00),
            nonce: [0xe0; 32],
            boot_id: boot(0x90),
            generation: 3,
            issued_at_unix_ms: 1,
            flags: FLAG_LOCAL_CONFIRMED | FLAG_PATH_PROBE,
        }
        .encode();
        assert!(CtrlPayload::decode_pong(&payload).is_ok());
        payload[CTRL_FLAGS_OFFSET] |= FLAG_REKEY_REQUEST;
        assert_eq!(
            CtrlPayload::decode_pong(&payload),
            Err(WireError::PongRekeyBitSet)
        );
        assert!(CtrlPayload::decode_ping(&payload).is_ok());
    }

    #[test]
    fn reserved_flag_bits_and_reserved_bytes_are_refused() {
        let base = CtrlPayload {
            sender: pk(0x00),
            receiver: pk(0x20),
            nonce: [0xe0; 32],
            boot_id: boot(0x80),
            generation: 7,
            issued_at_unix_ms: 1,
            flags: 0,
        };
        let mut payload = base.encode();
        payload[CTRL_FLAGS_OFFSET] = 0b0000_1000;
        assert_eq!(
            CtrlPayload::decode_ping(&payload),
            Err(WireError::ReservedFlagBits(0b0000_1000))
        );
        let mut payload = base.encode();
        payload[CTRL_RESERVED_OFFSET + 2] = 1;
        assert_eq!(
            CtrlPayload::decode_ping(&payload),
            Err(WireError::NonZeroReserved(CTRL_RESERVED_OFFSET + 2))
        );
    }

    #[test]
    fn ctrl_flag_accessors_match_the_bits() {
        let ctrl = CtrlPayload {
            sender: pk(0x00),
            receiver: pk(0x20),
            nonce: [1u8; 32],
            boot_id: boot(0x80),
            generation: 1,
            issued_at_unix_ms: 1,
            flags: FLAG_LOCAL_CONFIRMED | FLAG_REKEY_REQUEST,
        };
        assert!(ctrl.local_confirmed());
        assert!(!ctrl.path_probe());
        assert!(ctrl.rekey_request());
    }

    #[test]
    fn probe_payload_round_trips() {
        let probe = ProbePayload {
            sender: pk(0x20),
            receiver: pk(0x00),
            boot_id: boot(0x90),
            generation: 3,
            issued_at_unix_ms: 1_762_920_000_050,
            probe_nonce: [0xc0; 32],
        };
        let encoded = probe.encode();
        assert_eq!(encoded.len(), PROBE_PAYLOAD_LEN);
        assert_eq!(ProbePayload::decode(&encoded).unwrap(), probe);
    }

    #[test]
    fn frame_type_table_is_exactly_as_specified() {
        for (ft, byte) in [
            (FrameType::Hello, 0x01u8),
            (FrameType::Challenge, 0x02),
            (FrameType::Finish, 0x03),
            (FrameType::Ack, 0x04),
            (FrameType::Probe, 0x05),
            (FrameType::Data, 0x10),
            (FrameType::CtrlPing, 0x20),
            (FrameType::CtrlPong, 0x21),
        ] {
            assert_eq!(ft.as_u8(), byte);
            assert_eq!(FrameType::from_u8(byte), Some(ft));
        }
        for byte in [0x00u8, 0x06, 0x0f, 0x11, 0x22, 0xff] {
            assert_eq!(FrameType::from_u8(byte), None);
        }
    }

    #[test]
    fn direction_flips() {
        assert_eq!(Direction::LoToHi.flipped(), Direction::HiToLo);
        assert_eq!(Direction::HiToLo.flipped(), Direction::LoToHi);
        assert_eq!(Direction::from_u8(0), Some(Direction::LoToHi));
        assert_eq!(Direction::from_u8(1), Some(Direction::HiToLo));
        assert_eq!(Direction::from_u8(2), None);
    }
}
