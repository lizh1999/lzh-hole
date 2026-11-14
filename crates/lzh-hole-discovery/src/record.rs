//! The public coordination record carried inside an authenticated ntfy payload.
//!
//! It carries coordination data only. It never carries a PSK, a session key or
//! business payload.

use std::net::Ipv4Addr;

pub use lzh_hole_protocol::path::{CandidateSource, Endpoint};
pub use lzh_hole_types::PeerRecordState;
use lzh_hole_types::{BootId, DiscoveryPublicKey, RelationshipId};

/// Record magic, ASCII "LZ".
pub const RECORD_MAGIC: u16 = 0x4C5A;
/// Schema version implemented here.
pub const RECORD_SCHEMA_VERSION: u8 = 1;
/// record_type for a contact record.
pub const RECORD_TYPE_CONTACT: u8 = 1;
/// Fixed part of the record body, before the candidate array.
pub const RECORD_FIXED_LEN: usize = 134;
/// Bytes per candidate.
pub const CANDIDATE_LEN: usize = 8;
/// Maximum candidates in one record.
pub const MAX_CANDIDATES: usize = 8;
/// Default record lifetime.
pub const DEFAULT_LIFETIME_MS: u64 = 600_000;
/// Hard cap on a record lifetime.
pub const MAX_LIFETIME_MS: u64 = 3_600_000;

/// flags bit: the publisher's NAT uses endpoint-dependent mapping, so it can
/// only ever be the hard side of a hole punch.
pub const FLAG_MAPPING_EDM: u8 = 0b0000_0001;
/// flags bit: the publisher could not classify its mapping behaviour, so no
/// punch role may be assigned to it.
pub const FLAG_MAPPING_UNKNOWN: u8 = 0b0000_0010;
/// flags bit: the publisher has opened a punch window; its address should be
/// scanned rather than targeted on the advertised port alone.
pub const FLAG_PUNCH_OFFER: u8 = 0b0000_0100;
/// Flag bits that must be zero. A record setting any of them is refused.
pub const FLAG_RESERVED_MASK: u8 = 0b1111_1000;

/// Why a record could not be built or parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    /// Magic mismatch.
    #[error("bad record magic")]
    BadMagic,
    /// Unsupported schema version.
    #[error("unsupported record schema version {0}")]
    BadSchemaVersion(u8),
    /// Unsupported record type.
    #[error("unsupported record type {0}")]
    BadRecordType(u8),
    /// Body length does not match the candidate count.
    #[error("body length {got} does not match {expected} for {count} candidates")]
    BadBodyLength {
        /// Length implied by the candidate count.
        expected: usize,
        /// Actual length.
        got: usize,
        /// Declared candidate count.
        count: usize,
    },
    /// Candidate count outside 1..=8.
    #[error("candidate count {0} outside 1..=8")]
    BadCandidateCount(usize),
    /// Two candidates share an endpoint.
    #[error("duplicate candidate endpoint {0}")]
    DuplicateCandidate(Endpoint),
    /// A candidate source class is not publishable.
    #[error("candidate source class {0} is not publishable in v1")]
    UnpublishableSource(u8),
    /// A reserved flag bit was set.
    #[error("reserved record flag bits set: {0:#04x}")]
    ReservedFlagBits(u8),
    /// A reserved byte was not zero.
    #[error("non-zero reserved byte at body offset {0}")]
    NonZeroReserved(usize),
    /// Expiry is not after issue time.
    #[error("expires_at {expires} is not after issued_at {issued}")]
    ExpiryNotAfterIssue {
        /// Issue time.
        issued: u64,
        /// Expiry time.
        expires: u64,
    },
    /// Lifetime above the cap.
    #[error("lifetime {0} ms exceeds the {MAX_LIFETIME_MS} ms cap")]
    LifetimeTooLong(u64),
    /// The record sequence would overflow.
    #[error("record sequence overflow")]
    SequenceOverflow,
    /// Sequence or generation monotonicity violated.
    #[error("record rejected: {reason}")]
    Monotonicity {
        /// Human-readable reason.
        reason: String,
    },
    /// A cached record was read after its expiry.
    #[error("record expired at {expires} (now {now})")]
    Expired {
        /// Expiry time.
        expires: u64,
        /// Current time.
        now: u64,
    },
}

/// One candidate inside a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordCandidate {
    /// The endpoint.
    pub endpoint: Endpoint,
    /// How the publisher learned it.
    pub source: CandidateSource,
}

impl RecordCandidate {
    /// Serialise to CANDIDATE_LEN bytes.
    pub fn encode(&self) -> [u8; CANDIDATE_LEN] {
        let mut out = [0u8; CANDIDATE_LEN];
        out[0..4].copy_from_slice(&self.endpoint.ip.octets());
        out[4..6].copy_from_slice(&self.endpoint.port.to_be_bytes());
        out[6] = self.source.as_u8();
        out[7] = 0;
        out
    }
}

/// The signed plaintext contact record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactRecord {
    /// Relationship this record belongs to.
    pub relationship_id: RelationshipId,
    /// Publisher key. Must equal the ntfy payload signing key.
    pub sender: DiscoveryPublicKey,
    /// The peer this record is addressed to. Must equal the reader's own key.
    pub receiver: DiscoveryPublicKey,
    /// Persistent monotonic microsecond sequence. Must equal the packet
    /// timestamp.
    pub record_seq: u64,
    /// Issue time.
    pub issued_at_unix_ms: u64,
    /// Expiry time. Fixed at build time; never extended by a cache hit.
    pub expires_at_unix_ms: u64,
    /// Publisher process epoch.
    pub boot_id: BootId,
    /// Publisher network generation, monotonic within one boot.
    pub generation: u64,
    /// Candidate endpoints, 1..=8, pairwise distinct.
    pub candidates: Vec<RecordCandidate>,
    /// Coordination flag bits. Only the named bits may be set; the rest are
    /// reserved and a record setting one is refused.
    pub flags: u8,
}

impl ContactRecord {
    /// Serialise the record body.
    pub fn encode_body(&self) -> Result<Vec<u8>, RecordError> {
        self.validate()?;
        let mut out = Vec::with_capacity(RECORD_FIXED_LEN + CANDIDATE_LEN * self.candidates.len());
        out.extend_from_slice(&RECORD_MAGIC.to_be_bytes());
        out.push(RECORD_SCHEMA_VERSION);
        out.push(RECORD_TYPE_CONTACT);
        out.extend_from_slice(self.relationship_id.as_bytes());
        out.extend_from_slice(self.sender.as_bytes());
        out.extend_from_slice(self.receiver.as_bytes());
        out.extend_from_slice(&self.record_seq.to_be_bytes());
        out.extend_from_slice(&self.issued_at_unix_ms.to_be_bytes());
        out.extend_from_slice(&self.expires_at_unix_ms.to_be_bytes());
        out.extend_from_slice(self.boot_id.as_bytes());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.push(self.candidates.len() as u8);
        out.push(self.flags);
        for candidate in &self.candidates {
            out.extend_from_slice(&candidate.encode());
        }
        Ok(out)
    }

    /// Parse a record body.
    pub fn decode_body(body: &[u8]) -> Result<Self, RecordError> {
        if body.len() < RECORD_FIXED_LEN {
            return Err(RecordError::BadBodyLength {
                expected: RECORD_FIXED_LEN,
                got: body.len(),
                count: 0,
            });
        }
        if u16::from_be_bytes([body[0], body[1]]) != RECORD_MAGIC {
            return Err(RecordError::BadMagic);
        }
        if body[2] != RECORD_SCHEMA_VERSION {
            return Err(RecordError::BadSchemaVersion(body[2]));
        }
        if body[3] != RECORD_TYPE_CONTACT {
            return Err(RecordError::BadRecordType(body[3]));
        }
        let count = usize::from(body[132]);
        let flags = body[133];
        if flags & FLAG_RESERVED_MASK != 0 {
            return Err(RecordError::ReservedFlagBits(flags & FLAG_RESERVED_MASK));
        }
        if count == 0 || count > MAX_CANDIDATES {
            return Err(RecordError::BadCandidateCount(count));
        }
        let expected = RECORD_FIXED_LEN + CANDIDATE_LEN * count;
        if body.len() != expected {
            return Err(RecordError::BadBodyLength {
                expected,
                got: body.len(),
                count,
            });
        }
        let mut candidates = Vec::with_capacity(count);
        for i in 0..count {
            let off = RECORD_FIXED_LEN + CANDIDATE_LEN * i;
            let raw = &body[off..off + CANDIDATE_LEN];
            if raw[7] != 0 {
                return Err(RecordError::NonZeroReserved(off + 7));
            }
            let source =
                CandidateSource::from_u8(raw[6]).ok_or(RecordError::UnpublishableSource(raw[6]))?;
            candidates.push(RecordCandidate {
                endpoint: Endpoint::new(
                    Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]),
                    u16::from_be_bytes([raw[4], raw[5]]),
                ),
                source,
            });
        }
        let record = Self {
            relationship_id: RelationshipId::from_bytes(body[4..20].try_into().expect("16")),
            sender: DiscoveryPublicKey::from_bytes(body[20..52].try_into().expect("32")),
            receiver: DiscoveryPublicKey::from_bytes(body[52..84].try_into().expect("32")),
            record_seq: u64::from_be_bytes(body[84..92].try_into().expect("8")),
            issued_at_unix_ms: u64::from_be_bytes(body[92..100].try_into().expect("8")),
            expires_at_unix_ms: u64::from_be_bytes(body[100..108].try_into().expect("8")),
            boot_id: BootId::from_bytes(body[108..124].try_into().expect("16")),
            generation: u64::from_be_bytes(body[124..132].try_into().expect("8")),
            candidates,
            flags,
        };
        record.validate()?;
        Ok(record)
    }

    /// Structural and policy validation, without any time or signature check.
    pub fn validate(&self) -> Result<(), RecordError> {
        if self.flags & FLAG_RESERVED_MASK != 0 {
            return Err(RecordError::ReservedFlagBits(
                self.flags & FLAG_RESERVED_MASK,
            ));
        }
        if self.candidates.is_empty() || self.candidates.len() > MAX_CANDIDATES {
            return Err(RecordError::BadCandidateCount(self.candidates.len()));
        }
        for (i, a) in self.candidates.iter().enumerate() {
            if !a.source.is_publishable() {
                return Err(RecordError::UnpublishableSource(a.source.as_u8()));
            }
            for b in &self.candidates[i + 1..] {
                if a.endpoint == b.endpoint {
                    return Err(RecordError::DuplicateCandidate(a.endpoint));
                }
            }
        }
        if self.expires_at_unix_ms <= self.issued_at_unix_ms {
            return Err(RecordError::ExpiryNotAfterIssue {
                issued: self.issued_at_unix_ms,
                expires: self.expires_at_unix_ms,
            });
        }
        let lifetime = self.expires_at_unix_ms - self.issued_at_unix_ms;
        if lifetime > MAX_LIFETIME_MS {
            return Err(RecordError::LifetimeTooLong(lifetime));
        }
        Ok(())
    }

    /// Whether the publisher reports endpoint-dependent mapping.
    pub const fn mapping_edm(&self) -> bool {
        self.flags & FLAG_MAPPING_EDM != 0
    }

    /// Whether the publisher could not classify its mapping behaviour.
    pub const fn mapping_unknown(&self) -> bool {
        self.flags & FLAG_MAPPING_UNKNOWN != 0
    }

    /// Whether the publisher has opened a punch window.
    pub const fn punch_offer(&self) -> bool {
        self.flags & FLAG_PUNCH_OFFER != 0
    }

    /// Whether the record is expired at now_unix_ms.
    pub fn is_expired(&self, now_unix_ms: u64) -> bool {
        now_unix_ms >= self.expires_at_unix_ms
    }

    /// Refuse an expired record. Checked even for an idempotent cache hit, so a
    /// cached record is never revived by being read again.
    pub fn check_not_expired(&self, now_unix_ms: u64) -> Result<(), RecordError> {
        if self.is_expired(now_unix_ms) {
            return Err(RecordError::Expired {
                expires: self.expires_at_unix_ms,
                now: now_unix_ms,
            });
        }
        Ok(())
    }
}

/// Reserve the next record sequence.
///
/// seq = max(max(durable, highest_valid_network) + 1, now_us), bounded by
/// i64::MAX so it stays representable in the BEP44 sequence field. All
/// arithmetic is checked.
pub fn reserve_sequence(
    durable: u64,
    highest_valid_network: u64,
    now_us: u64,
) -> Result<u64, RecordError> {
    let floor = durable.max(highest_valid_network);
    let next = floor.checked_add(1).ok_or(RecordError::SequenceOverflow)?;
    let seq = next.max(now_us);
    if seq > i64::MAX as u64 {
        return Err(RecordError::SequenceOverflow);
    }
    Ok(seq)
}

/// The outcome of applying a freshly resolved record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptOutcome {
    /// Newer than anything seen. The caller must persist the new high-water
    /// mark durably before using it.
    Accepted,
    /// Same sequence and byte-identical packet. The caller may use the cached
    /// view but must not refresh issue or expiry times.
    Idempotent,
}

/// Apply monotonicity, idempotency and expiry rules to a resolved record.
pub fn accept_resolved(
    state: Option<&PeerRecordState>,
    record: &ContactRecord,
    packet_bytes: &[u8],
    now_unix_ms: u64,
) -> Result<AcceptOutcome, RecordError> {
    record.check_not_expired(now_unix_ms)?;
    let Some(state) = state else {
        return Ok(AcceptOutcome::Accepted);
    };
    if record.record_seq < state.highest_seq {
        return Err(RecordError::Monotonicity {
            reason: format!(
                "rollback: seq {} below high-water {}",
                record.record_seq, state.highest_seq
            ),
        });
    }
    if record.record_seq == state.highest_seq {
        if packet_bytes == state.accepted_bytes.as_slice() {
            return Ok(AcceptOutcome::Idempotent);
        }
        return Err(RecordError::Monotonicity {
            reason: "same sequence with different packet bytes".to_owned(),
        });
    }
    if record.boot_id == state.boot_id && record.generation < state.generation {
        return Err(RecordError::Monotonicity {
            reason: format!(
                "generation {} went backwards within one boot (was {})",
                record.generation, state.generation
            ),
        });
    }
    Ok(AcceptOutcome::Accepted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(start: u8) -> DiscoveryPublicKey {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = start.wrapping_add(i as u8);
        }
        DiscoveryPublicKey::from_bytes(out)
    }

    fn sample() -> ContactRecord {
        ContactRecord {
            relationship_id: RelationshipId::from_bytes(
                (0..16).collect::<Vec<u8>>().try_into().unwrap(),
            ),
            sender: pk(0x20),
            receiver: pk(0x00),
            record_seq: 1_762_920_000_000_000,
            issued_at_unix_ms: 1_762_920_000_000,
            expires_at_unix_ms: 1_762_920_600_000,
            boot_id: BootId::from_bytes((0x90u8..0xa0).collect::<Vec<u8>>().try_into().unwrap()),
            generation: 3,
            candidates: vec![
                RecordCandidate {
                    endpoint: Endpoint::new(Ipv4Addr::new(210, 22, 105, 194), 51000),
                    source: CandidateSource::Stun,
                },
                RecordCandidate {
                    endpoint: Endpoint::new(Ipv4Addr::new(38, 58, 103, 204), 51000),
                    source: CandidateSource::Stun,
                },
            ],
            flags: 0,
        }
    }

    #[test]
    fn body_round_trips_with_the_specified_length() {
        let record = sample();
        let body = record.encode_body().unwrap();
        assert_eq!(body.len(), RECORD_FIXED_LEN + 2 * CANDIDATE_LEN);
        assert_eq!(body.len(), 150);
        assert_eq!(ContactRecord::decode_body(&body).unwrap(), record);
    }

    #[test]
    fn magic_schema_and_type_are_enforced() {
        let mut body = sample().encode_body().unwrap();
        body[0] ^= 1;
        assert_eq!(
            ContactRecord::decode_body(&body),
            Err(RecordError::BadMagic)
        );
        let mut body = sample().encode_body().unwrap();
        body[2] = 9;
        assert_eq!(
            ContactRecord::decode_body(&body),
            Err(RecordError::BadSchemaVersion(9))
        );
        let mut body = sample().encode_body().unwrap();
        body[3] = 9;
        assert_eq!(
            ContactRecord::decode_body(&body),
            Err(RecordError::BadRecordType(9))
        );
    }

    #[test]
    fn reserved_flag_bits_and_reserved_bytes_must_be_zero() {
        let mut body = sample().encode_body().unwrap();
        body[133] = FLAG_RESERVED_MASK;
        assert_eq!(
            ContactRecord::decode_body(&body),
            Err(RecordError::ReservedFlagBits(FLAG_RESERVED_MASK))
        );
        // A single reserved bit is enough.
        let mut body = sample().encode_body().unwrap();
        body[133] = 0b0000_1000;
        assert_eq!(
            ContactRecord::decode_body(&body),
            Err(RecordError::ReservedFlagBits(0b0000_1000))
        );
        let mut body = sample().encode_body().unwrap();
        body[RECORD_FIXED_LEN + 7] = 1;
        assert_eq!(
            ContactRecord::decode_body(&body),
            Err(RecordError::NonZeroReserved(RECORD_FIXED_LEN + 7))
        );
    }

    #[test]
    fn named_flag_bits_round_trip_and_never_disturb_the_body_layout() {
        let baseline = sample().encode_body().unwrap();
        for flags in [
            0u8,
            FLAG_MAPPING_EDM,
            FLAG_MAPPING_UNKNOWN,
            FLAG_PUNCH_OFFER,
            FLAG_MAPPING_EDM | FLAG_PUNCH_OFFER,
            FLAG_MAPPING_UNKNOWN | FLAG_PUNCH_OFFER,
        ] {
            let mut record = sample();
            record.flags = flags;
            let body = record.encode_body().unwrap();
            // Only the flags byte differs; the layout is untouched.
            assert_eq!(body.len(), baseline.len());
            for (index, (a, b)) in body.iter().zip(baseline.iter()).enumerate() {
                if index != 133 {
                    assert_eq!(a, b, "byte {index} changed when only flags did");
                }
            }
            let decoded = ContactRecord::decode_body(&body).unwrap();
            assert_eq!(decoded.flags, flags);
            assert_eq!(decoded.mapping_edm(), flags & FLAG_MAPPING_EDM != 0);
            assert_eq!(decoded.mapping_unknown(), flags & FLAG_MAPPING_UNKNOWN != 0);
            assert_eq!(decoded.punch_offer(), flags & FLAG_PUNCH_OFFER != 0);
        }
    }

    #[test]
    fn a_record_without_flags_still_parses_as_endpoint_independent() {
        // Backward compatibility: a peer predating these flags sets none, and
        // an unclassified-but-silent record must not be read as hard.
        let record = sample();
        assert_eq!(record.flags, 0);
        let decoded = ContactRecord::decode_body(&record.encode_body().unwrap()).unwrap();
        assert!(!decoded.mapping_edm());
        assert!(!decoded.mapping_unknown());
        assert!(!decoded.punch_offer());
    }

    #[test]
    fn encoding_refuses_reserved_flag_bits_before_signing() {
        let mut record = sample();
        record.flags = FLAG_RESERVED_MASK;
        assert_eq!(
            record.encode_body(),
            Err(RecordError::ReservedFlagBits(FLAG_RESERVED_MASK))
        );
    }

    #[test]
    fn candidate_count_bounds_are_enforced() {
        let mut record = sample();
        record.candidates.clear();
        assert!(matches!(
            record.encode_body(),
            Err(RecordError::BadCandidateCount(0))
        ));
        let mut record = sample();
        record.candidates = (0..9)
            .map(|i| RecordCandidate {
                endpoint: Endpoint::new(Ipv4Addr::new(210, 22, 105, 194), 51000 + i),
                source: CandidateSource::Stun,
            })
            .collect();
        assert!(matches!(
            record.encode_body(),
            Err(RecordError::BadCandidateCount(9))
        ));
    }

    #[test]
    fn eight_candidates_are_allowed() {
        let mut record = sample();
        record.candidates = (0..8)
            .map(|i| RecordCandidate {
                endpoint: Endpoint::new(Ipv4Addr::new(210, 22, 105, 194), 51000 + i),
                source: CandidateSource::Stun,
            })
            .collect();
        let body = record.encode_body().unwrap();
        assert_eq!(body.len(), RECORD_FIXED_LEN + 8 * CANDIDATE_LEN);
        assert_eq!(ContactRecord::decode_body(&body).unwrap(), record);
    }

    #[test]
    fn duplicates_are_refused_but_same_ip_other_port_is_fine() {
        let mut record = sample();
        record.candidates[1] = record.candidates[0];
        assert!(matches!(
            record.encode_body(),
            Err(RecordError::DuplicateCandidate(_))
        ));
        let mut record = sample();
        record.candidates[1] = RecordCandidate {
            endpoint: Endpoint::new(record.candidates[0].endpoint.ip, 51001),
            source: CandidateSource::Stun,
        };
        assert!(record.encode_body().is_ok());
    }

    #[test]
    fn lifetime_rules_are_enforced() {
        let mut record = sample();
        record.expires_at_unix_ms = record.issued_at_unix_ms;
        assert!(matches!(
            record.encode_body(),
            Err(RecordError::ExpiryNotAfterIssue { .. })
        ));
        let mut record = sample();
        record.expires_at_unix_ms = record.issued_at_unix_ms + MAX_LIFETIME_MS + 1;
        assert!(matches!(
            record.encode_body(),
            Err(RecordError::LifetimeTooLong(_))
        ));
        let mut record = sample();
        record.expires_at_unix_ms = record.issued_at_unix_ms + DEFAULT_LIFETIME_MS;
        assert!(record.encode_body().is_ok());
    }

    #[test]
    fn expiry_blocks_even_an_idempotent_cache_hit() {
        let record = sample();
        let bytes = vec![1u8, 2, 3];
        let state = PeerRecordState {
            highest_seq: record.record_seq,
            accepted_bytes: bytes.clone(),
            boot_id: record.boot_id,
            generation: record.generation,
        };
        assert_eq!(
            accept_resolved(Some(&state), &record, &bytes, record.issued_at_unix_ms + 1).unwrap(),
            AcceptOutcome::Idempotent
        );
        assert!(matches!(
            accept_resolved(Some(&state), &record, &bytes, record.expires_at_unix_ms),
            Err(RecordError::Expired { .. })
        ));
        assert!(matches!(
            accept_resolved(
                Some(&state),
                &record,
                &bytes,
                record.expires_at_unix_ms + 100_000
            ),
            Err(RecordError::Expired { .. })
        ));
    }

    #[test]
    fn rollback_and_equivocation_are_refused() {
        let record = sample();
        let ahead = PeerRecordState {
            highest_seq: record.record_seq + 10,
            accepted_bytes: vec![9u8],
            boot_id: record.boot_id,
            generation: record.generation,
        };
        assert!(accept_resolved(Some(&ahead), &record, &[9u8], record.issued_at_unix_ms).is_err());
        let same = PeerRecordState {
            highest_seq: record.record_seq,
            accepted_bytes: vec![1u8],
            boot_id: record.boot_id,
            generation: record.generation,
        };
        assert!(accept_resolved(Some(&same), &record, &[2u8], record.issued_at_unix_ms).is_err());
        assert_eq!(
            accept_resolved(Some(&same), &record, &[1u8], record.issued_at_unix_ms).unwrap(),
            AcceptOutcome::Idempotent
        );
    }

    #[test]
    fn generation_may_reset_only_with_a_new_boot_id() {
        let mut record = sample();
        record.generation = 1;
        let state = PeerRecordState {
            highest_seq: record.record_seq - 1,
            accepted_bytes: vec![],
            boot_id: record.boot_id,
            generation: 5,
        };
        assert!(accept_resolved(Some(&state), &record, &[7u8], record.issued_at_unix_ms).is_err());
        record.generation = 5;
        assert_eq!(
            accept_resolved(Some(&state), &record, &[7u8], record.issued_at_unix_ms).unwrap(),
            AcceptOutcome::Accepted
        );
        record.generation = 0;
        record.boot_id = BootId::from_bytes([0x77; 16]);
        assert_eq!(
            accept_resolved(Some(&state), &record, &[7u8], record.issued_at_unix_ms).unwrap(),
            AcceptOutcome::Accepted
        );
    }

    #[test]
    fn first_record_is_accepted() {
        let record = sample();
        assert_eq!(
            accept_resolved(None, &record, &[1u8], record.issued_at_unix_ms).unwrap(),
            AcceptOutcome::Accepted
        );
    }

    #[test]
    fn sequence_reservation_is_monotonic_and_bounded() {
        assert_eq!(reserve_sequence(10, 20, 1000).unwrap(), 1000);
        assert_eq!(reserve_sequence(5000, 20, 1000).unwrap(), 5001);
        assert_eq!(reserve_sequence(10, 9000, 1000).unwrap(), 9001);
        for (d, n, now) in [
            (0u64, 0u64, 0u64),
            (1, 1, 1),
            (1_000_000, 2_000_000, 5),
            (i64::MAX as u64 - 10, 0, 0),
        ] {
            let seq = reserve_sequence(d, n, now).unwrap();
            assert!(seq > d.max(n));
            assert!(seq >= now);
        }
    }

    #[test]
    fn sequence_reservation_refuses_overflow() {
        assert_eq!(
            reserve_sequence(u64::MAX, 0, 0),
            Err(RecordError::SequenceOverflow)
        );
        assert_eq!(
            reserve_sequence(i64::MAX as u64, 0, 0),
            Err(RecordError::SequenceOverflow)
        );
        assert_eq!(
            reserve_sequence(i64::MAX as u64 - 1, 0, 0).unwrap(),
            i64::MAX as u64
        );
    }

    #[test]
    fn unpublishable_source_is_refused() {
        let mut body = sample().encode_body().unwrap();
        body[RECORD_FIXED_LEN + 6] = 9;
        assert!(matches!(
            ContactRecord::decode_body(&body),
            Err(RecordError::UnpublishableSource(9))
        ));
    }

    #[test]
    fn truncated_and_extended_bodies_are_refused() {
        let body = sample().encode_body().unwrap();
        assert!(ContactRecord::decode_body(&body[..RECORD_FIXED_LEN - 1]).is_err());
        assert!(ContactRecord::decode_body(&body[..body.len() - 1]).is_err());
        let mut long = body;
        long.push(0);
        assert!(matches!(
            ContactRecord::decode_body(&long),
            Err(RecordError::BadBodyLength { .. })
        ));
    }
}
