use super::super::tests::offline_daemon;
use super::*;
use lzh_hole_discovery::record::FLAG_MAPPING_EDM;
use lzh_hole_discovery::stun::{ATTR_MAPPED_ADDRESS, MAGIC_COOKIE, MSG_BINDING_SUCCESS};

fn measured_mapping(daemon: &mut super::super::Daemon) {
    let seeds = daemon.resolved.config.stun_seeds.clone();
    daemon.public.add_transport(1, seeds, 0);
    let effect = daemon.public.start_stun(1, [1; 12], 0).unwrap().unwrap();
    let mut reply = Vec::new();
    reply.extend_from_slice(&MSG_BINDING_SUCCESS.to_be_bytes());
    reply.extend_from_slice(&12u16.to_be_bytes());
    reply.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    reply.extend_from_slice(&effect.transaction);
    reply.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
    reply.extend_from_slice(&8u16.to_be_bytes());
    reply.extend_from_slice(&[0, 1]);
    reply.extend_from_slice(&51_000u16.to_be_bytes());
    reply.extend_from_slice(&[8, 8, 4, 4]);
    daemon
        .public
        .receive_stun(1, effect.server, &reply, 0)
        .unwrap()
        .unwrap();
}

fn facts(daemon: &super::super::Daemon, flags: u8, deadline: Option<u64>) -> NodeFacts<'_> {
    NodeFacts {
        ntfy_handle: None,
        engines: None,
        state: &daemon.state,
        signing_key: &daemon.signing_key,
        public: &daemon.public,
        transports: &daemon.transports,
        boot_id: daemon.boot_id,
        generation: daemon.generation,
        self_key: daemon.self_key(),
        stun_servers: Vec::new(),
        forbidden_addresses: Vec::new(),
        monotonic_ms: 0,
        flags,
        punch_offer_deadline: deadline,
    }
}

fn verified_record(daemon: &super::super::Daemon, payload: &SignedPayload) -> ContactRecord {
    let peer = &daemon.peers[&daemon.peer_order[0]];
    let policy = PeerRecordPolicy::new(
        peer.relationship_id,
        peer.peer_key,
        daemon.self_key(),
        now_unix_ms(),
    );
    payload.verify(&policy, None).unwrap().validated.record
}

#[test]
fn offer_construction_preserves_normal_ttl_at_short_closed_and_exact_margin() {
    let now = 1_800_000_000_000;
    let flags = FLAG_MAPPING_EDM | FLAG_PUNCH_OFFER;
    let margin = lzh_hole_discovery::transport::MIN_PUNCH_OFFER_REMAINING_MS;
    for remaining in [0, 28_366, 30_000, margin] {
        assert_eq!(
            publication_validity(flags, Some(now + remaining), now),
            (FLAG_MAPPING_EDM, now + MAX_LIFETIME_MS)
        );
    }
    assert_eq!(
        publication_validity(flags, None, now),
        (FLAG_MAPPING_EDM, now + MAX_LIFETIME_MS)
    );
    assert_eq!(
        publication_validity(flags, Some(now - 1), now),
        (FLAG_MAPPING_EDM, now + MAX_LIFETIME_MS)
    );
    assert_eq!(
        publication_validity(flags, Some(now + margin + 1), now),
        (flags, now + margin + 1)
    );
    assert_eq!(
        publication_validity(FLAG_MAPPING_EDM, Some(now + margin + 1), now),
        (FLAG_MAPPING_EDM, now + MAX_LIFETIME_MS)
    );
}

#[tokio::test]
async fn durable_offer_alternatives_keep_correlation_and_discarded_sequences_never_return() {
    let (_temp, mut daemon) = offline_daemon();
    measured_mapping(&mut daemon);
    let relationship = daemon.peer_order[0];
    let peer = &daemon.peers[&relationship];
    let id = RequestId::from_hex("11111111111111111111111111111111").unwrap();
    let flags = FLAG_MAPPING_EDM | FLAG_PUNCH_OFFER;
    let before = now_unix_ms();
    let deadline = before + 120_000;
    let facts = facts(&daemon, flags, Some(deadline));
    let publication = facts
        .build_publication(peer, MessageKind::Reply, id)
        .unwrap();
    let offer = verified_record(&daemon, &publication.payload);
    let fallback = publication.fallback.as_ref().unwrap();
    let normal = verified_record(&daemon, fallback);
    assert!(offer.issued_at_unix_ms >= before);
    assert_eq!(offer.expires_at_unix_ms, deadline);
    assert_ne!(offer.flags & FLAG_PUNCH_OFFER, 0);
    assert_eq!(normal.flags, FLAG_MAPPING_EDM);
    assert_eq!(
        normal.expires_at_unix_ms - normal.issued_at_unix_ms,
        MAX_LIFETIME_MS
    );
    assert_eq!(publication.expires_at_unix_ms, normal.expires_at_unix_ms);
    assert!(normal.record_seq > offer.record_seq);
    assert_eq!(
        daemon.state.load_sequence(relationship).unwrap(),
        normal.record_seq
    );
    assert_eq!(fallback.kind(), MessageKind::Reply);
    assert_eq!(fallback.request_id(), id);
    assert_eq!(normal.candidates, offer.candidates);
    // Neither alternative is queued. The next build must skip both sequences.
    let next = facts
        .build_publication(peer, MessageKind::Request, id)
        .unwrap();
    let next_record = verified_record(&daemon, &next.payload);
    assert!(next_record.record_seq > normal.record_seq);
    assert!(daemon.state.load_sequence(relationship).unwrap() > next_record.record_seq);
}

#[tokio::test]
async fn short_offer_signs_only_a_normal_ttl_record_and_failed_signing_still_consumes_sequence() {
    let (_temp, mut daemon) = offline_daemon();
    measured_mapping(&mut daemon);
    let relationship = daemon.peer_order[0];
    let peer = &daemon.peers[&relationship];
    let id = RequestId::from_hex("11111111111111111111111111111111").unwrap();
    let mut facts = facts(
        &daemon,
        FLAG_MAPPING_EDM | FLAG_PUNCH_OFFER,
        Some(now_unix_ms() + 28_366),
    );
    let wrong = SigningKey::from_bytes(&[99; 32]);
    facts.signing_key = &wrong;
    assert!(
        facts
            .build_publication(peer, MessageKind::Request, id)
            .is_err()
    );
    let discarded = daemon.state.load_sequence(relationship).unwrap();
    facts.signing_key = &daemon.signing_key;
    let publication = facts
        .build_publication(peer, MessageKind::Request, id)
        .unwrap();
    assert!(publication.fallback.is_none());
    let normal = verified_record(&daemon, &publication.payload);
    assert_eq!(normal.flags, FLAG_MAPPING_EDM);
    assert_eq!(
        normal.expires_at_unix_ms - normal.issued_at_unix_ms,
        MAX_LIFETIME_MS
    );
    assert!(normal.record_seq > discarded);
    assert_eq!(
        daemon.state.load_sequence(relationship).unwrap(),
        normal.record_seq
    );
}
