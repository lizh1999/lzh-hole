//! Minimal shared domain types for lzh-hole.
//!
//! This crate contains no sockets, filesystem state machines, HTTP, Tokio or
//! service lifecycle. Protocol policy and durable workflows live downstream.

mod endpoint;
mod identity;
mod pairing;
mod secret;

pub use endpoint::Endpoint;
pub use identity::{BootId, DiscoveryPublicKey, IdentityError, RelationshipId, Role, Roles};
pub use pairing::{PairingRole, PeerRecordState, Relationship};
pub use secret::{Secret32, SecretError};

/// Opaque daemon-lifetime physical transport identity. Zero is the legacy socket.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransportId(pub u64);
