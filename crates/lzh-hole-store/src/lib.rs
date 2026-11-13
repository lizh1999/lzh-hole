//! Identity, pairing, private persistence and durable anti-rollback state.
//!
//! This crate performs no network or service orchestration. Contact-record
//! validation remains in `discovery`; only the small shared high-water value
//! crosses the boundary.

#![allow(unsafe_code)]

mod high_water;
mod pairing;
mod secret;

pub use high_water::{HighWaterError, PeerRecordCache};
pub use lzh_hole_types::Secret32;
pub use pairing::{
    Acceptance, IDENTITY_FILE, LOCK_FILE, MAX_PAIR_FILE_BYTES, OFFER_FILE, Offer, PAIRING_VERSION,
    PSK_FILE, PairingError, RELATIONSHIP_FILE, Relationship, Role, SEQUENCE_FILE, StateDir,
    build_acceptance, build_offer, offer_transcript, public_key_of_seed, public_key_of_signing_key,
    read_pair_file, verify_acceptance, write_pair_file,
};
pub use secret::{
    FileLock, MAX_SECRET_FILE_BYTES, SECRET_DIR_MODE, SECRET_FILE_MODE, SecretError,
    ensure_private_dir, read_private_bytes, read_secret_file, write_private_bytes,
    write_secret_file,
};
