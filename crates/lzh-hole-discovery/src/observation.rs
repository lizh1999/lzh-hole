//! Runtime hints, deliberately separate from wire-v1 `CandidateSource`.
//!
//! Consumers key their registry by observation ID, not endpoint. Removing one
//! announcement must not remove another announcement supporting the same path.

use lzh_hole_types::Endpoint;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DiscoveryOrigin {
    Lan,
    Public,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObservationId {
    pub origin: DiscoveryOrigin,
    pub serial: u64,
}

/// Interface identity belongs to the service, including its revocation epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LanScope {
    pub interface: u32,
    pub generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CandidateScope {
    Lan(LanScope),
    Public,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HintSource {
    Mdns,
    VerifiedContactRecord,
}

/// A discovery hint, never reachability, authentication or peer-health evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateHint {
    pub remote: Endpoint,
    pub scope: CandidateScope,
    pub observation_id: ObservationId,
    /// Monotonic deadline on the caller's clock, not a UNIX timestamp.
    pub expires_at_ms: u64,
    pub source: HintSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryUpdate {
    /// Refreshing the same ID only changes metadata, not path identity.
    Upsert(CandidateHint),
    Remove(ObservationId),
}
