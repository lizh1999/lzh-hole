use super::*;
use crate::{
    ContactRecord, MessageKind, PeerRecordPolicy, RecordCandidate, SignedPayload,
    candidate::CandidateSource,
    stun::{ATTR_MAPPED_ADDRESS, MAGIC_COOKIE, MSG_BINDING_SUCCESS},
};
use ed25519_dalek::SigningKey;
use lzh_hole_types::{BootId, DiscoveryPublicKey, RelationshipId};
use std::net::Ipv4Addr;

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
fn payload(seq: u64, ports: &[u16]) -> (SignedPayload, PeerRecordPolicy) {
    let sender = SigningKey::from_bytes(&[7; 32]);
    let receiver = SigningKey::from_bytes(&[8; 32]);
    let sender_key = DiscoveryPublicKey::from_bytes(sender.verifying_key().to_bytes());
    let receiver_key = DiscoveryPublicKey::from_bytes(receiver.verifying_key().to_bytes());
    let relationship = RelationshipId::from_bytes([9; 16]);
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
fn hint(updates: &[DiscoveryUpdate]) -> CandidateHint {
    match updates.last().unwrap() {
        DiscoveryUpdate::Upsert(hint) => *hint,
        _ => panic!("expected upsert"),
    }
}
#[test]
fn stun_is_socket_transaction_and_source_specific_and_bad_replies_do_not_consume_work() {
    let mut public = PublicDiscovery::new();
    assert!(public.add_transport(1, vec![server()], 0));
    assert!(public.add_transport(2, vec![server()], 0));
    let a = public.start_stun(1, [1; 12], 0).unwrap().unwrap();
    let b = public.start_stun(2, [2; 12], 0).unwrap().unwrap();
    assert_eq!(a.transport, 1);
    assert_eq!(&a.packet[8..20], &[1; 12]);
    assert_eq!(b.transport, 2);
    let data = response([1; 12], endpoint(40_001));
    assert_eq!(
        public.receive_stun(2, server(), &data, 1),
        Err(StunError::BadTransaction)
    );
    let wrong = SocketAddrV4::new(*server().ip(), 1234);
    assert!(matches!(
        public.receive_stun(1, wrong, &data, 1),
        Err(StunError::BadSource { .. })
    ));
    assert!(public.own_mappings(1).is_empty());
    let mapping = public.receive_stun(1, server(), &data, 2).unwrap().unwrap();
    assert_eq!(mapping.transport, 1);
    assert_eq!(mapping.endpoint, endpoint(40_001));
    public
        .receive_stun(2, server(), &response([2; 12], endpoint(40_002)), 3)
        .unwrap()
        .unwrap();
    assert_eq!(public.own_mappings(3).len(), 2);
    assert_eq!(public.own_mappings(120_002).len(), 1);
    public.remove_transport(2);
    assert!(public.own_mappings(120_002).is_empty());
}
#[test]
fn timeout_round_robin_send_failure_and_bounded_transport_lifecycle() {
    let mut public = PublicDiscovery::new();
    let other = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 3478);
    assert!(public.add_transport(1, vec![server(), other], 0));
    assert!(!public.add_transport(1, vec![server()], 0));
    assert_eq!(
        public.start_stun(1, [1; 12], 0).unwrap().unwrap().server,
        server()
    );
    assert!(public.start_stun(1, [2; 12], 2_999).unwrap().is_none());
    assert!(public.expire(3_000).updates.is_empty());
    assert_eq!(public.consecutive_timeouts(1), Some(1));
    assert!(public.start_stun(1, [2; 12], 7_999).unwrap().is_none());
    assert_eq!(
        public
            .start_stun(1, [2; 12], 8_000)
            .unwrap()
            .unwrap()
            .server,
        other
    );
    public.stun_send_failed(1, [1; 12], 8_001);
    assert!(public.start_stun(1, [3; 12], 8_001).unwrap().is_none());
    public.stun_send_failed(1, [2; 12], 8_001);
    assert!(public.start_stun(1, [3; 12], 13_000).unwrap().is_none());
    assert!(public.start_stun(1, [3; 12], 13_001).unwrap().is_some());
    public.remove_transport(1);
    assert_eq!(
        public.receive_stun(1, server(), &response([3; 12], endpoint(5)), 13_002),
        Ok(None)
    );
    for id in 1..=MAX_PUBLIC_TRANSPORTS as u64 {
        assert!(public.add_transport(id, vec![server()], 0));
    }
    assert!(!public.add_transport(99, vec![server()], 0));
}
#[test]
fn mappings_are_bounded_fresh_and_rejected_mappings_do_not_discard_transaction() {
    let mut public = PublicDiscovery::new();
    public.add_transport(1, vec![server()], 0);
    for i in 0..=MAX_SOCKET_MAPPINGS {
        let now = i as u64 * STUN_INTERVAL_MS;
        let tx = [i as u8; 12];
        public.start_stun(1, tx, now).unwrap().unwrap();
        if i == 0 {
            assert!(
                public
                    .receive_stun(
                        1,
                        server(),
                        &response(tx, Endpoint::new(Ipv4Addr::new(198, 18, 0, 1), 5)),
                        now
                    )
                    .is_err()
            );
        }
        public
            .receive_stun(1, server(), &response(tx, endpoint(40_000 + i as u16)), now)
            .unwrap()
            .unwrap();
    }
    assert_eq!(public.own_mappings(40_000).len(), MAX_SOCKET_MAPPINGS);
    assert!(
        !public
            .own_mappings(40_000)
            .iter()
            .any(|m| m.endpoint == endpoint(40_000))
    );
    public.expire(200_000);
    assert!(public.own_mappings(200_000).is_empty());
}
#[test]
fn public_candidates_require_successful_highwater_commit_and_replace_then_expire() {
    let mut public = PublicDiscovery::new();
    let (signed, policy) = payload(100, &[50_000]);
    let verified = signed.verify(&policy, None).unwrap();
    assert_eq!(
        public.accept_verified(&verified, NOW, 10, |_| Err("disk full")),
        Err(PublicAcceptError::Commit("disk full"))
    );
    assert!(public.expire(10).updates.is_empty());
    let mut durable = None;
    let updates = public
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
        public.accept_verified(&newer, NOW + 100, 110, |_| Err("disk full")),
        Err(PublicAcceptError::Commit("disk full"))
    );
    assert_eq!(public.candidates.get(&first.remote), Some(&first));
    let updates = public
        .accept_verified(&newer, NOW + 100, 110, |_| Ok::<_, ()>(()))
        .unwrap();
    assert_eq!(updates[0], DiscoveryUpdate::Remove(first.observation_id));
    let second = hint(&updates);
    assert_ne!(first.observation_id, second.observation_id);
    assert_eq!(
        public.accept_verified(&verified, NOW + 100, 110, |_| Ok::<_, ()>(())),
        Err(PublicAcceptError::Stale)
    );
    assert_eq!(
        public.expire(600_010).updates,
        vec![DiscoveryUpdate::Remove(second.observation_id)]
    );
}
#[test]
fn duplicate_record_does_not_extend_expiry_even_after_wallclock_regression_or_removal() {
    let mut public = PublicDiscovery::new();
    let (signed, policy) = payload(100, &[50_000]);
    let verified = signed.verify(&policy, None).unwrap();
    let durable = verified.state_to_persist().unwrap().clone();
    let first = hint(
        &public
            .accept_verified(&verified, NOW, 10, |_| Ok::<_, ()>(()))
            .unwrap(),
    );
    let duplicate = signed.verify(&policy, Some(&durable)).unwrap();
    let second = hint(
        &public
            .accept_verified(&duplicate, NOW - 10_000, 100, |_| {
                panic!("idempotent read must not require another write");
                #[allow(unreachable_code)]
                Ok::<_, ()>(())
            })
            .unwrap(),
    );
    assert_eq!(first, second);
    public.expire(600_010);
    assert_eq!(
        public.accept_verified(&duplicate, NOW - 10_000, 600_011, |_| Ok::<_, ()>(())),
        Err(PublicAcceptError::Expired)
    );
}
#[test]
fn signaling_retry_is_independent_of_stun_and_reconnect_preserves_pending_request() {
    let mut public = PublicDiscovery::new();
    let id = RequestId::from_bytes([1; 16]);
    assert!(public.request_due(0));
    assert!(public.request_started(id, NOW + 100, NOW, 0));
    assert!(!public.request_started(id, NOW + 100, NOW, 1));
    public.add_transport(1, vec![server()], 0);
    public.start_stun(1, [1; 12], 0).unwrap().unwrap();
    assert_eq!(public.expire(100).expired_request, Some(id));
    assert!(public.pending_request().is_none());
    assert!(!public.request_due(30_099));
    assert!(public.request_due(30_100));
    assert!(public.request_started(id, NOW + 600_000, NOW, 30_100));
    public.expire(33_100);
    assert_eq!(public.pending_request().unwrap().id, id);
    public.remove_transport(1);
    assert_eq!(public.pending_request().unwrap().id, id);
    public.request_matched(id, 33_101);
    assert!(!public.request_due(33_101));
    assert!(public.request_due(33_101 + REQUEST_REFRESH_MS));
}

#[test]
fn retries_retain_thirty_minute_cap_without_identical_refresh_acceleration() {
    let mut public = PublicDiscovery::new();
    for failure in 1..=20u32 {
        let now = u64::from(failure) * 10_000_000;
        public.request_queue_failed(now);
        let delay = 30_000u64
            .saturating_mul(1 << (failure - 1).min(6))
            .min(30 * 60_000);
        assert!(!public.request_due(now + delay - 1));
        assert!(public.request_due(now + delay));
        assert_eq!(public.request_refresh_needed(now + 1, 0), None);
        assert!(!public.request_due(now + delay - 1));
    }
}
#[test]
fn coordination_changes_refresh_even_when_mappings_do_not_change() {
    let mut public = PublicDiscovery::new();
    let second: SocketAddrV4 = "8.8.4.4:3478".parse().unwrap();
    public.add_transport(1, vec![server(), second], 0);
    public.start_stun(1, [1; 12], 0).unwrap();
    public
        .receive_stun(1, server(), &response([1; 12], endpoint(40_001)), 1)
        .unwrap();
    let flags = public.mapping_behavior(1).mapping.record_flags();
    assert_eq!(flags, crate::record::FLAG_MAPPING_UNKNOWN);
    public.request_refresh_needed(1, flags);
    let id = RequestId::from_bytes([1; 16]);
    assert!(public.request_started(id, NOW + 600_000, NOW, 1));
    public.request_matched(id, 2);
    public.start_stun(1, [2; 12], 5_001).unwrap();
    public
        .receive_stun(1, second, &response([2; 12], endpoint(40_001)), 5_002)
        .unwrap();
    let flags = public.mapping_behavior(1).mapping.record_flags();
    assert_eq!(flags, 0);
    public.request_refresh_needed(5_002, flags);
    assert!(
        public.request_due(5_002),
        "UNKNOWN to EIM refreshes a stable mapping"
    );
    assert!(public.request_started(id, NOW + 600_000, NOW, 5_002));
    assert_eq!(
        public.request_refresh_needed(5_003, crate::record::FLAG_PUNCH_OFFER),
        Some(id)
    );
    assert_eq!(
        public.request_refresh_needed(5_004, crate::record::FLAG_PUNCH_OFFER),
        None
    );
}

#[test]
fn actual_mapping_changes_cancel_pending_and_refresh_after_success() {
    let mut public = PublicDiscovery::new();
    public.add_transport(1, vec![server()], 0);
    public.start_stun(1, [1; 12], 0).unwrap();
    public
        .receive_stun(1, server(), &response([1; 12], endpoint(40_001)), 1)
        .unwrap();
    public.request_refresh_needed(1, 0);
    let id = RequestId::from_bytes([1; 16]);
    assert!(public.request_started(id, NOW + 600_000, NOW, 1));
    public.request_matched(id, 2);
    assert!(!public.request_due(2));
    public.start_stun(1, [2; 12], 5_001).unwrap();
    public
        .receive_stun(1, server(), &response([2; 12], endpoint(40_001)), 5_002)
        .unwrap();
    assert_eq!(public.request_refresh_needed(5_002, 0), None);
    assert!(!public.request_due(5_002));
    public.start_stun(1, [3; 12], 10_002).unwrap();
    public
        .receive_stun(1, server(), &response([3; 12], endpoint(40_002)), 10_003)
        .unwrap();
    assert_eq!(public.request_refresh_needed(10_003, 0), None);
    assert!(public.request_due(10_003));
    assert!(public.request_started(id, NOW + 600_000, NOW, 10_003));
    public.remove_transport(1);
    assert_eq!(public.request_refresh_needed(10_004, 0), Some(id));
    assert!(public.request_due(10_004));
    assert_eq!(public.request_refresh_needed(10_005, 0), None);
}
