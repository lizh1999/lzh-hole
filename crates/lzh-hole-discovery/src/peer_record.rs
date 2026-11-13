//! Validation of a resolved peer record, and the persistent anti-rollback
//! cache that backs it.
//!
//! A signature only proves who wrote a record. Everything below re-checks what
//! the record claims before any address is used as a target.

use std::net::Ipv4Addr;

use crate::record::{AcceptOutcome, ContactRecord, MAX_CANDIDATES};
use lzh_hole_protocol::path::{Endpoint, EndpointReject, validate_remote_target};
use lzh_hole_types::{DiscoveryPublicKey, PeerRecordState, RelationshipId};

/// Tolerance for a record issued slightly in the future.
pub const CLOCK_SKEW_TOLERANCE_MS: u64 = 120_000;

/// Why a resolved peer record was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PeerRecordReject {
    /// The record belongs to another relationship.
    #[error("record is for relationship {got}, expected {expected}")]
    WrongRelationship {
        /// Observed.
        got: RelationshipId,
        /// Expected.
        expected: RelationshipId,
    },
    /// The sender is not the pinned peer.
    #[error("sender {got} is not the pinned peer {expected}")]
    WrongSender {
        /// Observed.
        got: DiscoveryPublicKey,
        /// Expected.
        expected: DiscoveryPublicKey,
    },
    /// The record is not addressed to us.
    #[error("receiver {got} is not our own key {expected}")]
    WrongReceiver {
        /// Observed.
        got: DiscoveryPublicKey,
        /// Expected.
        expected: DiscoveryPublicKey,
    },
    /// The body sequence disagrees with the signed packet timestamp.
    #[error("record_seq {record} does not equal packet timestamp {packet}")]
    SequenceTimestampMismatch {
        /// From the body.
        record: u64,
        /// From the packet.
        packet: u64,
    },
    /// The record has expired.
    #[error("record expired at {expires}, now {now}")]
    Expired {
        /// Expiry.
        expires: u64,
        /// Current time.
        now: u64,
    },
    /// The record claims to be from the future.
    #[error("record issued at {issued}, which is more than {tolerance} ms ahead of {now}")]
    IssuedInFuture {
        /// Issue time.
        issued: u64,
        /// Current time.
        now: u64,
        /// Allowed tolerance.
        tolerance: u64,
    },
    /// The lifetime is longer than we accept.
    #[error("lifetime {actual} ms exceeds the {max} ms cap")]
    LifetimeTooLong {
        /// Observed lifetime.
        actual: u64,
        /// Cap.
        max: u64,
    },
    /// Generation went backwards within one boot.
    #[error("generation {got} is below {expected} for the same boot id")]
    GenerationWentBackwards {
        /// Observed.
        got: u64,
        /// Last accepted.
        expected: u64,
    },
    /// The sequence went backwards.
    #[error("sequence {seq} is below the high-water mark {high_water}")]
    Rollback {
        /// Observed sequence.
        seq: u64,
        /// High-water mark.
        high_water: u64,
    },
    /// Same sequence, different bytes.
    #[error("sequence {seq} was already accepted with different content")]
    Equivocation {
        /// The sequence.
        seq: u64,
    },
    /// No usable candidate survived filtering.
    #[error("no usable candidate in the record")]
    NoUsableCandidate,
    /// Too many candidates.
    #[error("{count} candidates exceeds the limit of {MAX_CANDIDATES}")]
    TooManyCandidates {
        /// Observed count.
        count: usize,
    },
    /// Two candidates share an endpoint.
    #[error("duplicate candidate {0}")]
    DuplicateCandidate(Endpoint),
    /// A candidate was refused.
    #[error("candidate {endpoint} refused: {reject}")]
    CandidateRejected {
        /// The endpoint.
        endpoint: Endpoint,
        /// Why.
        reject: EndpointReject,
    },
}

/// Everything needed to judge one resolved record.
#[derive(Debug, Clone)]
pub struct PeerRecordPolicy {
    /// Our relationship.
    pub relationship_id: RelationshipId,
    /// Our own discovery key: the record must be addressed to it.
    pub self_key: DiscoveryPublicKey,
    /// The pinned peer key: the record must be signed by and claim it.
    pub peer_key: DiscoveryPublicKey,
    /// Current time.
    pub now_unix_ms: u64,
    /// Tolerance for a record issued in the future.
    pub clock_skew_tolerance_ms: u64,
    /// Longest lifetime we accept.
    pub max_lifetime_ms: u64,
    /// Configured STUN servers, which are never peer candidates.
    pub stun_servers: Vec<Endpoint>,
    /// Our own endpoints, which we must never target.
    pub own_endpoints: Vec<Endpoint>,
    /// Addresses we must never target at all.
    pub forbidden_addresses: Vec<Ipv4Addr>,
    /// Whether public-unicast filtering is enforced.
    ///
    /// True in production. False only in the explicitly marked local test mode,
    /// which the report records so a local pass is never mistaken for a real
    /// network pass.
    pub require_public_unicast: bool,
}

impl PeerRecordPolicy {
    /// A production policy with public-unicast filtering on.
    pub fn new(
        relationship_id: RelationshipId,
        self_key: DiscoveryPublicKey,
        peer_key: DiscoveryPublicKey,
        now_unix_ms: u64,
    ) -> Self {
        Self {
            relationship_id,
            self_key,
            peer_key,
            now_unix_ms,
            clock_skew_tolerance_ms: CLOCK_SKEW_TOLERANCE_MS,
            max_lifetime_ms: crate::record::MAX_LIFETIME_MS,
            stun_servers: Vec::new(),
            own_endpoints: Vec::new(),
            forbidden_addresses: Vec::new(),
            require_public_unicast: true,
        }
    }
}

/// A record that passed every check, with its usable targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPeerRecord {
    /// The record itself.
    pub record: ContactRecord,
    /// Candidate targets that passed filtering, in record order.
    pub targets: Vec<Endpoint>,
    /// Candidates that were refused, with reasons, for diagnostics.
    pub rejected: Vec<(Endpoint, EndpointReject)>,
}

/// Validate a resolved record against the policy.
///
/// `packet_timestamp` is the timestamp of the signed packet the record arrived
/// in; the body's record_seq must equal it.
pub fn validate(
    record: &ContactRecord,
    packet_timestamp: u64,
    policy: &PeerRecordPolicy,
) -> Result<ValidatedPeerRecord, PeerRecordReject> {
    if record.relationship_id != policy.relationship_id {
        return Err(PeerRecordReject::WrongRelationship {
            got: record.relationship_id,
            expected: policy.relationship_id,
        });
    }
    if record.sender != policy.peer_key {
        return Err(PeerRecordReject::WrongSender {
            got: record.sender,
            expected: policy.peer_key,
        });
    }
    if record.receiver != policy.self_key {
        return Err(PeerRecordReject::WrongReceiver {
            got: record.receiver,
            expected: policy.self_key,
        });
    }
    if record.record_seq != packet_timestamp {
        return Err(PeerRecordReject::SequenceTimestampMismatch {
            record: record.record_seq,
            packet: packet_timestamp,
        });
    }
    if record.is_expired(policy.now_unix_ms) {
        return Err(PeerRecordReject::Expired {
            expires: record.expires_at_unix_ms,
            now: policy.now_unix_ms,
        });
    }
    if record.issued_at_unix_ms > policy.now_unix_ms + policy.clock_skew_tolerance_ms {
        return Err(PeerRecordReject::IssuedInFuture {
            issued: record.issued_at_unix_ms,
            now: policy.now_unix_ms,
            tolerance: policy.clock_skew_tolerance_ms,
        });
    }
    let lifetime = record
        .expires_at_unix_ms
        .saturating_sub(record.issued_at_unix_ms);
    if lifetime > policy.max_lifetime_ms {
        return Err(PeerRecordReject::LifetimeTooLong {
            actual: lifetime,
            max: policy.max_lifetime_ms,
        });
    }
    if record.candidates.len() > MAX_CANDIDATES {
        return Err(PeerRecordReject::TooManyCandidates {
            count: record.candidates.len(),
        });
    }

    let mut targets = Vec::new();
    let mut rejected = Vec::new();
    for (i, candidate) in record.candidates.iter().enumerate() {
        if record.candidates[..i]
            .iter()
            .any(|c| c.endpoint == candidate.endpoint)
        {
            return Err(PeerRecordReject::DuplicateCandidate(candidate.endpoint));
        }
        let verdict = if policy.require_public_unicast {
            validate_remote_target(
                &candidate.endpoint,
                &policy.own_endpoints,
                &policy.forbidden_addresses,
                &policy.stun_servers,
            )
        } else {
            // Local test mode: still refuse port zero, STUN servers and our own
            // exact endpoints, but allow private and loopback addresses.
            test_mode_target_check(candidate.endpoint, policy)
        };
        match verdict {
            Ok(()) => targets.push(candidate.endpoint),
            Err(reject) => rejected.push((candidate.endpoint, reject)),
        }
    }
    if targets.is_empty() {
        return Err(PeerRecordReject::NoUsableCandidate);
    }
    Ok(ValidatedPeerRecord {
        record: record.clone(),
        targets,
        rejected,
    })
}

fn test_mode_target_check(
    endpoint: Endpoint,
    policy: &PeerRecordPolicy,
) -> Result<(), EndpointReject> {
    if endpoint.port == 0 {
        return Err(EndpointReject::PortZero);
    }
    if policy.stun_servers.contains(&endpoint) {
        return Err(EndpointReject::StunServerAddress);
    }
    if policy.own_endpoints.contains(&endpoint) {
        return Err(EndpointReject::ForbiddenEndpoint);
    }
    if policy.forbidden_addresses.contains(&endpoint.ip) {
        return Err(EndpointReject::ForbiddenAddress);
    }
    // Still refuse the ranges that are never a peer in any mode.
    if let Some(reject) = lzh_hole_protocol::path::classify(endpoint.ip)
        && matches!(
            reject,
            EndpointReject::PortZero
                | EndpointReject::ThisNetwork
                | EndpointReject::Broadcast
                | EndpointReject::Multicast
                | EndpointReject::Reserved
                | EndpointReject::FakeIp
                | EndpointReject::Documentation
        )
    {
        return Err(reject);
    }
    Ok(())
}

/// The pure anti-rollback decision produced after record validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordAcceptance {
    /// Newer accepted record or byte-identical idempotent read.
    pub outcome: AcceptOutcome,
    /// State that the service must durably commit before using candidates.
    /// `None` for an idempotent read, which never extends record lifetime.
    pub state_to_persist: Option<PeerRecordState>,
}

/// Apply monotonicity, idempotency and epoch rules without performing I/O.
pub fn evaluate_acceptance(
    record: &ContactRecord,
    accepted_bytes: &[u8],
    previous: Option<&PeerRecordState>,
) -> Result<RecordAcceptance, PeerRecordReject> {
    if let Some(state) = previous {
        if record.record_seq < state.highest_seq {
            return Err(PeerRecordReject::Rollback {
                seq: record.record_seq,
                high_water: state.highest_seq,
            });
        }
        if record.record_seq == state.highest_seq {
            if state.accepted_bytes == accepted_bytes {
                return Ok(RecordAcceptance {
                    outcome: AcceptOutcome::Idempotent,
                    state_to_persist: None,
                });
            }
            return Err(PeerRecordReject::Equivocation {
                seq: record.record_seq,
            });
        }
        if record.boot_id == state.boot_id && record.generation < state.generation {
            return Err(PeerRecordReject::GenerationWentBackwards {
                got: record.generation,
                expected: state.generation,
            });
        }
    }
    Ok(RecordAcceptance {
        outcome: AcceptOutcome::Accepted,
        state_to_persist: Some(PeerRecordState {
            highest_seq: record.record_seq,
            accepted_bytes: accepted_bytes.to_vec(),
            boot_id: record.boot_id,
            generation: record.generation,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::RecordCandidate;
    use lzh_hole_protocol::path::CandidateSource;
    use lzh_hole_types::BootId;

    fn key(b: u8) -> DiscoveryPublicKey {
        DiscoveryPublicKey::from_bytes([b; 32])
    }

    fn rel() -> RelationshipId {
        RelationshipId::from_bytes([9u8; 16])
    }

    fn now() -> u64 {
        1_800_000_000_000
    }

    fn record_with(candidates: Vec<Endpoint>) -> ContactRecord {
        ContactRecord {
            relationship_id: rel(),
            sender: key(2),
            receiver: key(1),
            record_seq: 1_800_000_000_000_000,
            issued_at_unix_ms: now(),
            expires_at_unix_ms: now() + 600_000,
            boot_id: BootId::from_bytes([7u8; 16]),
            generation: 3,
            candidates: candidates
                .into_iter()
                .map(|endpoint| RecordCandidate {
                    endpoint,
                    source: CandidateSource::Stun,
                })
                .collect(),
        }
    }

    fn policy() -> PeerRecordPolicy {
        PeerRecordPolicy::new(rel(), key(1), key(2), now())
    }

    fn public_ep(port: u16) -> Endpoint {
        Endpoint::new(Ipv4Addr::new(210, 22, 105, 194), port)
    }

    #[test]
    fn a_well_formed_record_is_accepted() {
        let record = record_with(vec![public_ep(51000), public_ep(51001)]);
        let v = validate(&record, record.record_seq, &policy()).unwrap();
        assert_eq!(v.targets.len(), 2);
        assert!(v.rejected.is_empty());
    }

    #[test]
    fn identity_binding_is_enforced() {
        let mut record = record_with(vec![public_ep(51000)]);
        record.relationship_id = RelationshipId::from_bytes([1u8; 16]);
        assert!(matches!(
            validate(&record, record.record_seq, &policy()),
            Err(PeerRecordReject::WrongRelationship { .. })
        ));

        let mut record = record_with(vec![public_ep(51000)]);
        record.sender = key(3);
        assert!(matches!(
            validate(&record, record.record_seq, &policy()),
            Err(PeerRecordReject::WrongSender { .. })
        ));

        let mut record = record_with(vec![public_ep(51000)]);
        record.receiver = key(3);
        assert!(matches!(
            validate(&record, record.record_seq, &policy()),
            Err(PeerRecordReject::WrongReceiver { .. })
        ));
    }

    #[test]
    fn sequence_must_equal_the_packet_timestamp() {
        let record = record_with(vec![public_ep(51000)]);
        assert!(matches!(
            validate(&record, record.record_seq + 1, &policy()),
            Err(PeerRecordReject::SequenceTimestampMismatch { .. })
        ));
    }

    #[test]
    fn expiry_and_future_issue_are_enforced() {
        let mut record = record_with(vec![public_ep(51000)]);
        record.expires_at_unix_ms = now();
        assert!(matches!(
            validate(&record, record.record_seq, &policy()),
            Err(PeerRecordReject::Expired { .. })
        ));

        let mut record = record_with(vec![public_ep(51000)]);
        record.issued_at_unix_ms = now() + CLOCK_SKEW_TOLERANCE_MS + 1;
        record.expires_at_unix_ms = record.issued_at_unix_ms + 600_000;
        assert!(matches!(
            validate(&record, record.record_seq, &policy()),
            Err(PeerRecordReject::IssuedInFuture { .. })
        ));

        // Just inside the tolerance is fine.
        let mut record = record_with(vec![public_ep(51000)]);
        record.issued_at_unix_ms = now() + CLOCK_SKEW_TOLERANCE_MS;
        record.expires_at_unix_ms = record.issued_at_unix_ms + 600_000;
        assert!(validate(&record, record.record_seq, &policy()).is_ok());
    }

    #[test]
    fn lifetime_cap_is_enforced() {
        let mut record = record_with(vec![public_ep(51000)]);
        record.expires_at_unix_ms = record.issued_at_unix_ms + crate::record::MAX_LIFETIME_MS + 1;
        assert!(matches!(
            validate(&record, record.record_seq, &policy()),
            Err(PeerRecordReject::LifetimeTooLong { .. })
        ));
    }

    #[test]
    fn duplicates_are_refused_and_private_targets_are_filtered() {
        let record = record_with(vec![public_ep(51000), public_ep(51000)]);
        assert!(matches!(
            validate(&record, record.record_seq, &policy()),
            Err(PeerRecordReject::DuplicateCandidate(_))
        ));

        let record = record_with(vec![
            public_ep(51000),
            Endpoint::new(Ipv4Addr::new(192, 168, 8, 164), 51000),
            Endpoint::new(Ipv4Addr::new(198, 18, 0, 241), 443),
        ]);
        let v = validate(&record, record.record_seq, &policy()).unwrap();
        assert_eq!(v.targets, vec![public_ep(51000)]);
        assert_eq!(v.rejected.len(), 2);
        assert_eq!(v.rejected[0].1, EndpointReject::Private);
        assert_eq!(v.rejected[1].1, EndpointReject::FakeIp);
    }

    #[test]
    fn a_record_with_no_usable_candidate_is_refused() {
        let record = record_with(vec![Endpoint::new(Ipv4Addr::new(10, 0, 0, 1), 1)]);
        assert!(matches!(
            validate(&record, record.record_seq, &policy()),
            Err(PeerRecordReject::NoUsableCandidate)
        ));
    }

    #[test]
    fn our_own_endpoint_is_never_a_target() {
        let mine = public_ep(51000);
        let record = record_with(vec![mine, public_ep(51001)]);
        let mut p = policy();
        p.own_endpoints = vec![mine];
        let v = validate(&record, record.record_seq, &p).unwrap();
        assert_eq!(v.targets, vec![public_ep(51001)]);
        assert_eq!(v.rejected[0].1, EndpointReject::ForbiddenEndpoint);
    }

    #[test]
    fn stun_servers_are_never_targets() {
        let seed = Endpoint::new(Ipv4Addr::new(116, 162, 157, 195), 3478);
        let record = record_with(vec![seed, public_ep(51000)]);
        let mut p = policy();
        p.stun_servers = vec![seed];
        let v = validate(&record, record.record_seq, &p).unwrap();
        assert_eq!(v.targets, vec![public_ep(51000)]);
        assert_eq!(v.rejected[0].1, EndpointReject::StunServerAddress);
    }

    #[test]
    fn test_mode_allows_private_but_not_fake_ip_or_our_own() {
        let mine = Endpoint::new(Ipv4Addr::LOCALHOST, 51000);
        let record = record_with(vec![
            Endpoint::new(Ipv4Addr::new(127, 0, 0, 1), 51001),
            Endpoint::new(Ipv4Addr::new(198, 18, 0, 241), 443),
            mine,
        ]);
        let mut p = policy();
        p.require_public_unicast = false;
        p.own_endpoints = vec![mine];
        let v = validate(&record, record.record_seq, &p).unwrap();
        assert_eq!(
            v.targets,
            vec![Endpoint::new(Ipv4Addr::new(127, 0, 0, 1), 51001)]
        );
        assert_eq!(v.rejected.len(), 2);
        assert_eq!(v.rejected[0].1, EndpointReject::FakeIp);
        assert_eq!(v.rejected[1].1, EndpointReject::ForbiddenEndpoint);
    }

    #[test]
    fn acceptance_is_pure_and_enforces_rollback_idempotency_and_equivocation() {
        let record = record_with(vec![public_ep(51000)]);
        let bytes = b"packet-bytes";
        let first = evaluate_acceptance(&record, bytes, None).unwrap();
        assert_eq!(first.outcome, AcceptOutcome::Accepted);
        let state = first.state_to_persist.unwrap();
        assert_eq!(state.highest_seq, record.record_seq);

        let second = evaluate_acceptance(&record, bytes, Some(&state)).unwrap();
        assert_eq!(second.outcome, AcceptOutcome::Idempotent);
        assert!(second.state_to_persist.is_none());
        assert!(matches!(
            evaluate_acceptance(&record, b"different", Some(&state)),
            Err(PeerRecordReject::Equivocation { .. })
        ));

        let mut older = record.clone();
        older.record_seq -= 1;
        assert!(matches!(
            evaluate_acceptance(&older, b"old", Some(&state)),
            Err(PeerRecordReject::Rollback { .. })
        ));
    }

    #[test]
    fn acceptance_refuses_generation_regression_within_one_boot() {
        let record = record_with(vec![public_ep(51000)]);
        let state = evaluate_acceptance(&record, b"a", None)
            .unwrap()
            .state_to_persist
            .unwrap();
        let mut lower_generation = record.clone();
        lower_generation.record_seq += 10;
        lower_generation.generation = record.generation - 1;
        assert!(matches!(
            evaluate_acceptance(&lower_generation, b"b", Some(&state)),
            Err(PeerRecordReject::GenerationWentBackwards { .. })
        ));

        let mut new_boot = lower_generation;
        new_boot.generation = 0;
        new_boot.boot_id = BootId::from_bytes([1; 16]);
        assert!(evaluate_acceptance(&new_boot, b"c", Some(&state)).is_ok());
    }

    #[test]
    fn eight_candidates_are_allowed_and_nine_are_not() {
        let eight: Vec<Endpoint> = (0..8).map(|i| public_ep(51000 + i)).collect();
        let record = record_with(eight);
        assert_eq!(
            validate(&record, record.record_seq, &policy())
                .unwrap()
                .targets
                .len(),
            8
        );
        // ContactRecord::validate refuses nine before we ever get here.
        let nine: Vec<Endpoint> = (0..9).map(|i| public_ep(51000 + i)).collect();
        let record = record_with(nine);
        assert!(matches!(
            validate(&record, record.record_seq, &policy()),
            Err(PeerRecordReject::TooManyCandidates { .. })
        ));
    }
}
