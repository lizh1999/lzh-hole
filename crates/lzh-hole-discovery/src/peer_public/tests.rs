use super::*;
use crate::{
    ContactRecord, MessageKind, PayloadError, PeerRecordPolicy, PeerRecordReject, RecordCandidate,
    SignedPayload,
    candidate::CandidateSource,
    public::PublicDiscovery,
    stun::{ATTR_MAPPED_ADDRESS, MAGIC_COOKIE, MSG_BINDING_SUCCESS},
};
use ed25519_dalek::SigningKey;
use lzh_hole_types::{BootId, DiscoveryPublicKey, RelationshipId};
use std::net::{Ipv4Addr, SocketAddrV4};

const NOW: u64 = 1_800_000_000_000;

fn server() -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 3478)
}
fn endpoint(port: u16) -> Endpoint {
    Endpoint::new(Ipv4Addr::new(210, 22, 105, 194), port)
}
fn response(transaction: [u8; 12], mapped: Endpoint) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MSG_BINDING_SUCCESS.to_be_bytes());
    out.extend_from_slice(&12_u16.to_be_bytes());
    out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(&transaction);
    out.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
    out.extend_from_slice(&8_u16.to_be_bytes());
    out.extend_from_slice(&[0, 1]);
    out.extend_from_slice(&mapped.port.to_be_bytes());
    out.extend_from_slice(&mapped.ip.octets());
    out
}

/// Build a signed contact record for one specific relationship and peer pair.
fn payload_for(
    relationship: RelationshipId,
    sender_seed: u8,
    receiver_seed: u8,
    seq: u64,
    ports: &[u16],
) -> (SignedPayload, PeerRecordPolicy) {
    let sender = SigningKey::from_bytes(&[sender_seed; 32]);
    let receiver = SigningKey::from_bytes(&[receiver_seed; 32]);
    let sender_key = DiscoveryPublicKey::from_bytes(sender.verifying_key().to_bytes());
    let receiver_key = DiscoveryPublicKey::from_bytes(receiver.verifying_key().to_bytes());
    let record = ContactRecord {
        relationship_id: relationship,
        sender: sender_key,
        receiver: receiver_key,
        record_seq: seq,
        issued_at_unix_ms: NOW,
        expires_at_unix_ms: NOW + 600_000,
        boot_id: BootId::from_bytes([1; 16]),
        generation: 1,
        candidates: ports
            .iter()
            .map(|port| RecordCandidate {
                endpoint: endpoint(*port),
                source: CandidateSource::Stun,
            })
            .collect(),
        flags: 0,
    };
    let signed = SignedPayload::sign(
        MessageKind::Request,
        RequestId::from_bytes([1; 16]),
        &record,
        &sender,
    )
    .unwrap();
    (
        signed,
        PeerRecordPolicy::new(relationship, receiver_key, sender_key, NOW),
    )
}

fn payload(seq: u64, ports: &[u16]) -> (SignedPayload, PeerRecordPolicy) {
    payload_for(RelationshipId::from_bytes([9; 16]), 7, 8, seq, ports)
}

fn hint(updates: &[DiscoveryUpdate]) -> CandidateHint {
    match updates.last().unwrap() {
        DiscoveryUpdate::Upsert(hint) => *hint,
        _ => panic!("expected upsert"),
    }
}

#[test]
fn public_candidates_require_successful_highwater_commit_and_replace_then_expire() {
    let mut peer = PeerPublic::new();
    let (signed, policy) = payload(100, &[50_000]);
    let verified = signed.verify(&policy, None).unwrap();
    assert_eq!(
        peer.accept_verified(&verified, NOW, 10, |_| Err("disk full")),
        Err(PublicAcceptError::Commit("disk full"))
    );
    assert!(peer.expire(10).updates.is_empty());
    let mut durable = None;
    let updates = peer
        .accept_verified(&verified, NOW, 10, |state| {
            durable = Some(state.clone());
            Ok::<_, ()>(())
        })
        .unwrap();
    let first = hint(&updates);
    assert_eq!(first.expires_at_ms, 600_010);
    assert_eq!(first.source, HintSource::VerifiedContactRecord);
    let (new_signed, policy) = payload(101, &[50_001]);
    let newer = new_signed.verify(&policy, durable.as_ref()).unwrap();
    assert_eq!(
        peer.accept_verified(&newer, NOW + 100, 110, |_| Err("disk full")),
        Err(PublicAcceptError::Commit("disk full"))
    );
    assert_eq!(peer.candidates.get(&first.remote), Some(&first));
    let updates = peer
        .accept_verified(&newer, NOW + 100, 110, |_| Ok::<_, ()>(()))
        .unwrap();
    assert_eq!(updates[0], DiscoveryUpdate::Remove(first.observation_id));
    let second = hint(&updates);
    assert_ne!(first.observation_id, second.observation_id);
    assert_eq!(
        peer.accept_verified(&verified, NOW + 100, 110, |_| Ok::<_, ()>(())),
        Err(PublicAcceptError::Stale)
    );
    assert_eq!(
        peer.expire(600_010).updates,
        vec![DiscoveryUpdate::Remove(second.observation_id)]
    );
}

#[test]
fn duplicate_record_does_not_extend_expiry_even_after_wallclock_regression_or_removal() {
    let mut peer = PeerPublic::new();
    let (signed, policy) = payload(100, &[50_000]);
    let verified = signed.verify(&policy, None).unwrap();
    let durable = verified.state_to_persist().unwrap().clone();
    let first = hint(
        &peer
            .accept_verified(&verified, NOW, 10, |_| Ok::<_, ()>(()))
            .unwrap(),
    );
    let duplicate = signed.verify(&policy, Some(&durable)).unwrap();
    let second = hint(
        &peer
            .accept_verified(&duplicate, NOW - 10_000, 100, |_| {
                panic!("idempotent read must not require another write");
                #[allow(unreachable_code)]
                Ok::<_, ()>(())
            })
            .unwrap(),
    );
    assert_eq!(first, second);
    peer.expire(600_010);
    assert_eq!(
        peer.accept_verified(&duplicate, NOW - 10_000, 600_011, |_| Ok::<_, ()>(())),
        Err(PublicAcceptError::Expired)
    );
}

#[test]
fn request_pacing_is_per_relationship_and_survives_node_level_socket_churn() {
    let mut peer = PeerPublic::new();
    let mut node = PublicDiscovery::new();
    let id = RequestId::from_bytes([1; 16]);
    assert!(peer.request_due(0));
    assert!(peer.request_started(id, NOW + 100, NOW, 0));
    assert!(!peer.request_started(id, NOW + 100, NOW, 1));
    node.add_transport(1, vec![server()], 0);
    node.start_stun(1, [1; 12], 0).unwrap().unwrap();
    node.expire_sockets(100);
    assert_eq!(
        peer.pending_request().unwrap().id,
        id,
        "node-level expiry must not cancel a relationship's correlation"
    );
    assert_eq!(peer.expire(100).expired_request, Some(id));
    assert!(peer.pending_request().is_none());
    assert!(!peer.request_due(30_099));
    assert!(peer.request_due(30_100));
    assert!(peer.request_started(id, NOW + 600_000, NOW, 30_100));
    peer.expire(33_100);
    assert_eq!(peer.pending_request().unwrap().id, id);
    node.remove_transport(1);
    assert_eq!(peer.pending_request().unwrap().id, id);
    peer.request_matched(id, 33_101);
    assert!(!peer.request_due(33_101));
    assert!(peer.request_due(33_101 + REQUEST_REFRESH_MS));
}

#[test]
fn retries_retain_thirty_minute_cap_without_identical_refresh_acceleration() {
    let mut peer = PeerPublic::new();
    for failure in 1..=20u32 {
        let now = u64::from(failure) * 10_000_000;
        peer.request_queue_failed(now);
        let delay = 30_000u64
            .saturating_mul(1 << (failure - 1).min(6))
            .min(30 * 60_000);
        assert!(!peer.request_due(now + delay - 1));
        assert!(peer.request_due(now + delay));
        assert_eq!(peer.request_refresh_needed(now + 1, &[], 0), None);
        assert!(!peer.request_due(now + delay - 1));
    }
}

#[test]
fn coordination_flag_changes_refresh_even_when_node_mappings_do_not_change() {
    let mut node = PublicDiscovery::new();
    let mut peer = PeerPublic::new();
    let second: SocketAddrV4 = "8.8.4.4:3478".parse().unwrap();
    node.add_transport(1, vec![server(), second], 0);
    node.start_stun(1, [1; 12], 0).unwrap();
    node.receive_stun(1, server(), &response([1; 12], endpoint(40_001)), 1)
        .unwrap();
    let flags = node.mapping_behavior(1).mapping.record_flags();
    assert_eq!(flags, crate::record::FLAG_MAPPING_UNKNOWN);
    peer.request_refresh_needed(1, &[], flags);
    let id = RequestId::from_bytes([1; 16]);
    assert!(peer.request_started(id, NOW + 600_000, NOW, 1));
    peer.request_matched(id, 2);
    node.start_stun(1, [2; 12], 5_001).unwrap();
    node.receive_stun(1, second, &response([2; 12], endpoint(40_001)), 5_002)
        .unwrap();
    let flags = node.mapping_behavior(1).mapping.record_flags();
    assert_eq!(flags, 0);
    peer.request_refresh_needed(5_002, &[], flags);
    assert!(
        peer.request_due(5_002),
        "UNKNOWN to EIM refreshes a stable mapping"
    );
    assert!(peer.request_started(id, NOW + 600_000, NOW, 5_002));
    assert_eq!(
        peer.request_refresh_needed(5_003, &[], crate::record::FLAG_PUNCH_OFFER),
        Some(id)
    );
    assert_eq!(
        peer.request_refresh_needed(5_004, &[], crate::record::FLAG_PUNCH_OFFER),
        None
    );
}

/// One relationship's rejections, re-reads and pacing must never be observable
/// in another relationship's high-water mark, candidates or pending request.
#[test]
fn per_relationship_state_is_isolated_between_peer_public_instances() {
    let rel_a = RelationshipId::from_bytes([0xA; 16]);
    let rel_b = RelationshipId::from_bytes([0xB; 16]);
    let mut a = PeerPublic::new();
    let mut b = PeerPublic::new();

    let (signed_a, policy_a) = payload_for(rel_a, 7, 8, 10, &[50_000]);
    let verified_a = signed_a.verify(&policy_a, None).unwrap();
    let hint_a = hint(
        &a.accept_verified(&verified_a, NOW, 10, |_| Ok::<_, ()>(()))
            .unwrap(),
    );

    // B accepts the very same sequence number from its own peer: sequence
    // spaces are per relationship, so A's high-water mark cannot shadow B.
    let (signed_b, policy_b) = payload_for(rel_b, 11, 12, 10, &[50_001]);
    let verified_b = signed_b.verify(&policy_b, None).unwrap();
    let hint_b = hint(
        &b.accept_verified(&verified_b, NOW, 10, |_| Ok::<_, ()>(()))
            .unwrap(),
    );

    let id_a = RequestId::from_bytes([1; 16]);
    let id_b = RequestId::from_bytes([2; 16]);
    assert!(a.request_started(id_a, NOW + 600_000, NOW, 10));
    assert!(b.request_started(id_b, NOW + 600_000, NOW, 10));
    let b_deadline = b.record_deadline_ms;
    let b_candidates = b.candidates.clone();
    let b_next_id = b.next_id;
    let b_next_request_ms = b.next_request_ms;

    // Rollback against A's own high-water mark.
    let (older_a, older_policy_a) = payload_for(rel_a, 7, 8, 9, &[50_002]);
    let older_a = older_a.verify(&older_policy_a, None).unwrap();
    assert_eq!(
        a.accept_verified(&older_a, NOW, 20, |_| Ok::<_, ()>(())),
        Err(PublicAcceptError::Stale)
    );

    // A record that is already expired on the wire clock.
    assert_eq!(
        a.accept_verified(&verified_a, NOW + 600_001, 20, |_| Ok::<_, ()>(())),
        Err(PublicAcceptError::Expired)
    );

    // An idempotent re-read of A's record writes nothing and extends nothing.
    let durable_a = verified_a.state_to_persist().unwrap().clone();
    let duplicate_a = signed_a.verify(&policy_a, Some(&durable_a)).unwrap();
    let repeat_a = hint(
        &a.accept_verified(&duplicate_a, NOW + 1_000, 1_010, |_| {
            panic!("idempotent read must not require another write");
            #[allow(unreachable_code)]
            Ok::<_, ()>(())
        })
        .unwrap(),
    );
    assert_eq!(repeat_a, hint_a);

    // None of A's rejections or re-reads is observable in B.
    assert_eq!(b.highest_record_seq, Some(10));
    assert_eq!(b.record_deadline_ms, b_deadline);
    assert_eq!(b.candidates, b_candidates);
    assert_eq!(b.candidates.get(&hint_b.remote), Some(&hint_b));
    assert_eq!(b.next_id, b_next_id);
    assert_eq!(b.next_request_ms, b_next_request_ms);
    assert_eq!(b.pending_request().unwrap().id, id_b);
    assert!(b.expire(20).updates.is_empty());
    assert_eq!(b.pending_request().unwrap().id, id_b);

    // A itself is exactly where its one accepted record left it.
    assert_eq!(a.highest_record_seq, Some(10));
    assert_eq!(a.candidates.len(), 1);
    assert_eq!(a.candidates.get(&hint_a.remote), Some(&hint_a));
    assert_eq!(a.pending_request().unwrap().id, id_a);

    // B still advances on its own, and doing so leaves A alone.
    let (newer_b, newer_policy_b) = payload_for(rel_b, 11, 12, 11, &[50_003]);
    let newer_b = newer_b.verify(&newer_policy_b, None).unwrap();
    let updates_b = b
        .accept_verified(&newer_b, NOW + 10, 20, |_| Ok::<_, ()>(()))
        .unwrap();
    assert_eq!(updates_b[0], DiscoveryUpdate::Remove(hint_b.observation_id));
    assert_eq!(b.highest_record_seq, Some(11));
    assert_eq!(a.highest_record_seq, Some(10));
    assert_eq!(a.candidates.get(&hint_a.remote), Some(&hint_a));
}

/// The moved anti-rollback, idempotency and equivocation rules behave exactly as
/// they did before the node-level/per-relationship split.
#[test]
fn anti_rollback_idempotency_and_equivocation_are_unchanged_after_the_split() {
    let mut peer = PeerPublic::new();
    let (signed, policy) = payload(10, &[50_000]);
    let verified = signed.verify(&policy, None).unwrap();
    let first = hint(
        &peer
            .accept_verified(&verified, NOW, 10, |_| Ok::<_, ()>(()))
            .unwrap(),
    );
    let durable = verified.state_to_persist().unwrap().clone();
    assert_eq!(peer.highest_record_seq, Some(10));

    // seq 9 after seq 10 is a rollback and changes nothing.
    let (older, older_policy) = payload(9, &[50_009]);
    let older = older.verify(&older_policy, None).unwrap();
    assert_eq!(
        peer.accept_verified(&older, NOW, 20, |_| Ok::<_, ()>(())),
        Err(PublicAcceptError::Stale)
    );
    assert_eq!(peer.highest_record_seq, Some(10));
    assert_eq!(peer.candidates.len(), 1);
    assert_eq!(peer.candidates.get(&first.remote), Some(&first));

    // seq 10 with identical bytes is idempotent: no write, no lifetime extension.
    let duplicate = signed.verify(&policy, Some(&durable)).unwrap();
    assert!(duplicate.state_to_persist().is_none());
    let second = hint(
        &peer
            .accept_verified(&duplicate, NOW + 500, 510, |_| {
                panic!("idempotent read must not require another write");
                #[allow(unreachable_code)]
                Ok::<_, ()>(())
            })
            .unwrap(),
    );
    assert_eq!(first, second);
    assert_eq!(second.expires_at_ms, first.expires_at_ms);
    assert_eq!(peer.next_id, 2, "an idempotent read allocates no new id");

    // seq 10 with different bytes is equivocation and never reaches the state.
    let (equivocating, equivocating_policy) = payload(10, &[50_010]);
    assert!(matches!(
        equivocating.verify(&equivocating_policy, Some(&durable)),
        Err(PayloadError::PeerRecord(PeerRecordReject::Equivocation {
            seq: 10
        }))
    ));
    assert_eq!(peer.highest_record_seq, Some(10));
    assert_eq!(peer.candidates.len(), 1);
    assert_eq!(peer.candidates.get(&first.remote), Some(&first));
}

/// A failed durable commit must release no hint at all: no update escapes, the
/// candidate set is untouched and no high-water state advances.
#[test]
fn commit_failure_leaks_no_update_and_leaves_candidates_untouched() {
    let mut peer = PeerPublic::new();
    let (signed, policy) = payload(10, &[50_000]);
    let verified = signed.verify(&policy, None).unwrap();
    assert_eq!(
        peer.accept_verified(&verified, NOW, 10, |_| Err("disk full")),
        Err(PublicAcceptError::Commit("disk full"))
    );
    assert!(peer.candidates.is_empty());
    assert_eq!(peer.highest_record_seq, None);
    assert_eq!(peer.record_deadline_ms, 0);
    assert_eq!(peer.next_id, 1);
    let expiry = peer.expire(10);
    assert!(expiry.updates.is_empty());
    assert_eq!(expiry.expired_request, None);

    // A rejected replacement must not remove the already released candidate.
    let updates = peer
        .accept_verified(&verified, NOW, 10, |_| Ok::<_, ()>(()))
        .unwrap();
    let first = hint(&updates);
    let (newer_signed, newer_policy) = payload(11, &[50_001]);
    let newer = newer_signed.verify(&newer_policy, None).unwrap();
    assert_eq!(
        peer.accept_verified(&newer, NOW + 10, 20, |_| Err("disk full")),
        Err(PublicAcceptError::Commit("disk full"))
    );
    assert_eq!(peer.candidates.len(), 1);
    assert_eq!(peer.candidates.get(&first.remote), Some(&first));
    assert_eq!(peer.highest_record_seq, Some(10));
    assert!(peer.expire(20).updates.is_empty());
}

/// A NAT rebinding must refresh a relationship exactly once, and an unchanged
/// node must never re-publish on a timer tick.
///
/// This is the behaviour that was lost when the node-level STUN state and the
/// per-relationship request state were split: the node knows the mappings, the
/// relationship remembers what it last advertised, and only the pair of them
/// can tell a real rebinding from an idle tick.
#[test]
fn a_node_mapping_change_refreshes_once_and_an_unchanged_node_never_does() {
    let mut peer = PeerPublic::new();
    let first = vec![(1u64, endpoint(40_001))];
    let rebound = vec![(1u64, endpoint(40_002))];

    // Seeing a mapping for the first time makes a request due.
    assert_eq!(peer.request_refresh_needed(10, &first, 0), None);
    assert!(peer.request_due(10));

    let id = RequestId::from_bytes([3; 16]);
    assert!(peer.request_started(id, NOW + 600_000, NOW, 10));

    // The same mappings and the same flags never accelerate or cancel anything.
    assert_eq!(peer.request_refresh_needed(11, &first, 0), None);
    assert_eq!(peer.pending_request().unwrap().id, id);
    assert!(!peer.request_due(11));

    // A rebinding on the same transport cancels the in-flight request and
    // makes a fresh one due at once: the record already published advertises an
    // endpoint this node no longer owns.
    assert_eq!(peer.request_refresh_needed(12, &rebound, 0), Some(id));
    assert_eq!(peer.pending_request(), None);
    assert!(peer.request_due(12));

    // A second transport appearing is a change too.
    assert!(peer.request_started(id, NOW + 600_000, NOW, 12));
    let two = vec![(1u64, endpoint(40_002)), (2u64, endpoint(40_003))];
    assert_eq!(peer.request_refresh_needed(13, &two, 0), Some(id));

    // Re-presenting the identical set changes nothing, whatever the clock says.
    assert_eq!(peer.request_refresh_needed(14, &two, 0), None);
    assert_eq!(peer.request_refresh_needed(90_000_000, &two, 0), None);
}

/// A mapping change in one relationship must not be able to cancel another
/// relationship's in-flight request through shared node state.
#[test]
fn one_relationships_mapping_refresh_does_not_cancel_another() {
    let mut a = PeerPublic::new();
    let mut b = PeerPublic::new();
    let mappings = vec![(1u64, endpoint(40_001))];
    let rebound = vec![(1u64, endpoint(40_002))];

    a.request_refresh_needed(10, &mappings, 0);
    b.request_refresh_needed(10, &mappings, 0);
    let id_a = RequestId::from_bytes([1; 16]);
    let id_b = RequestId::from_bytes([2; 16]);
    assert!(a.request_started(id_a, NOW + 600_000, NOW, 10));
    assert!(b.request_started(id_b, NOW + 600_000, NOW, 10));

    // Only A is told about the rebinding; B keeps its own correlation and its
    // own advertised set, so a caller that refreshes one relationship at a time
    // cannot silently cancel another.
    assert_eq!(a.request_refresh_needed(11, &rebound, 0), Some(id_a));
    assert_eq!(b.pending_request().unwrap().id, id_b);
    assert_eq!(b.request_refresh_needed(11, &mappings, 0), None);
    assert_eq!(b.pending_request().unwrap().id, id_b);
}
