//! Candidate provenance and endpoint policy shared with the sans-I/O protocol.

pub use crate::observation::{
    CandidateHint, CandidateScope, DiscoveryOrigin, DiscoveryUpdate, HintSource, LanScope,
    ObservationId,
};
pub use lzh_hole_protocol::path::{
    Candidate, CandidateSource, EndpointReject, RejectedCandidate, classify, is_private,
    partition_candidates, validate_publishable, validate_remote_target,
};
pub use lzh_hole_types::Endpoint;
