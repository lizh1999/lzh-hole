//! Public pairing results and durable high-water values shared by store and
//! discovery. Private seeds and offer/acceptance workflows remain in `store`.

use serde::{Deserialize, Serialize};

use crate::{BootId, DiscoveryPublicKey, RelationshipId};

/// The finalised public relationship, written only after both sides confirm.
/// This is the existing version-2 on-disk shape; field names are compatibility
/// contract, not a newly versioned DTO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relationship {
    /// Pairing protocol version.
    pub pairing_version: u32,
    /// Pairing attempt from which this relationship came.
    pub pairing_id: RelationshipId,
    /// Random relationship identifier.
    pub relationship_id: RelationshipId,
    /// Our own discovery public key.
    pub self_public_key: DiscoveryPublicKey,
    /// Pinned peer public key.
    pub peer_public_key: DiscoveryPublicKey,
    /// Pairing-offer role, distinct from the canonical wire role.
    pub role: PairingRole,
    /// Our overlay address in its existing string representation.
    pub self_vip: String,
    /// Peer's overlay address in its existing string representation.
    pub peer_vip: String,
    /// Completion timestamp.
    pub finalised_unix_ms: u64,
}

/// Which side of the pairing exchange this host performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingRole {
    /// Created the signed offer.
    Initiator,
    /// Accepted the signed offer.
    Responder,
}

/// Durable anti-rollback state for one peer's contact-record stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecordState {
    /// Highest accepted sequence.
    pub highest_seq: u64,
    /// Canonical signed transcript and signature used for idempotency and
    /// equivocation checks. This is public coordination data, not a PSK.
    pub accepted_bytes: Vec<u8>,
    /// Boot ID of the accepted record.
    pub boot_id: BootId,
    /// Generation of the accepted record.
    pub generation: u64,
}
