//! Signed ntfy discovery, candidate records and STUN sans-I/O codecs.
//!
//! Storage is committed by `store` through service orchestration. This crate
//! never opens a business UDP socket; the service sends STUN frames on the same
//! physical socket used by the authenticated peer engine.

pub mod candidate;
pub mod exchange;
pub mod message;
pub mod ntfy;
pub mod pacing;
pub mod peer_record;
pub mod record;
pub mod stun;
pub mod transport;

pub use exchange::{Delivery, ExchangeAction, ExchangeError, ExchangeTracker};
pub use message::{
    MessageKind, PayloadError, RequestId, SignedPayload, VerifiedPayload, topic_for_relationship,
};
pub use ntfy::{NtfyConfig, NtfyHandle, NtfyPacingLoad, NtfyPacingStore, NtfyTransport};
pub use peer_record::{PeerRecordPolicy, PeerRecordReject, ValidatedPeerRecord};
pub use record::{
    AcceptOutcome, ContactRecord, MAX_LIFETIME_MS, PeerRecordState, RecordCandidate, RecordError,
    reserve_sequence,
};
pub use transport::{NtfyError, NtfyEvent, NtfyOperation, TryPublishError};
