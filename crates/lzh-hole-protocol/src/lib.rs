//! Sans-I/O wire, handshake, session, health and authenticated IPv4 engine.
//!
//! No filesystem, HTTP, socket, Tokio or libc dependency is permitted here.
//! Callers own clocks, random OS integration at the composition boundary is
//! limited to the existing CSPRNG calls, and all network I/O.

pub mod crypto;
pub mod engine;
pub mod handshake;
pub mod health;
pub mod path;
pub mod replay;
pub mod session;
pub mod wire;

pub use crypto::{Key32, Prk, extract_prk};
pub use engine::{
    CandidatePolicy, CandidateUpdate, EngineBuildError, EngineConfig, EngineCounters,
    EngineSnapshot, Ipv4Reject, PeerEngine, SendError, UdpFrame,
};
pub use handshake::{Handshake, HandshakeConfig, HandshakeEvent, HandshakeReject};
pub use health::{Health, HealthState, PathContext, PendingPing, PongOutcome};
pub use lzh_hole_types::Endpoint;
pub use path::{
    Candidate, CandidateSource, EndpointReject, RejectedCandidate, classify, is_private,
    partition_candidates, validate_publishable, validate_remote_target,
};
pub use replay::{ReplayReject, ReplayWindow};
pub use session::{Session, SessionKeys};
pub use wire::{Direction, FrameType, Header, ParsedFrame, WireError};
