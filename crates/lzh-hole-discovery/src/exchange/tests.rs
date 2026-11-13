use std::net::Ipv4Addr;

use lzh_hole_protocol::path::{CandidateSource, Endpoint};
use lzh_hole_types::{BootId, DiscoveryPublicKey, RelationshipId};

use super::*;
use crate::record::{ContactRecord, RecordCandidate};

fn verified(kind: MessageKind, request_id: RequestId, outcome: AcceptOutcome) -> VerifiedPayload {
    let record = ContactRecord {
        relationship_id: RelationshipId::from_bytes([0x44; 16]),
        sender: DiscoveryPublicKey::from_bytes([7; 32]),
        receiver: DiscoveryPublicKey::from_bytes([8; 32]),
        record_seq: 1,
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_000_600_000,
        boot_id: BootId::from_bytes([0x91; 16]),
        generation: 1,
        candidates: vec![RecordCandidate {
            endpoint: Endpoint::new(Ipv4Addr::new(8, 8, 8, 8), 50_000),
            source: CandidateSource::Stun,
        }],
    };
    VerifiedPayload::for_exchange_test(kind, request_id, outcome, record)
}

#[test]
fn cached_requests_do_not_reply_and_live_requests_reply_once() {
    let mut tracker = ExchangeTracker::default();
    let cached_id = RequestId::from_bytes([1; 16]);
    let cached = verified(MessageKind::Request, cached_id, AcceptOutcome::Accepted);
    assert_eq!(
        tracker.on_verified(&cached, Delivery::Cached),
        ExchangeAction::Cached
    );

    let id = RequestId::from_bytes([2; 16]);
    let request = verified(MessageKind::Request, id, AcceptOutcome::Accepted);
    assert_eq!(
        tracker.on_verified(&request, Delivery::Live),
        ExchangeAction::ReplyOnce(id)
    );
    assert_eq!(
        tracker.on_verified(&request, Delivery::Live),
        ExchangeAction::DuplicateRequest
    );

    let replayed = verified(
        MessageKind::Request,
        RequestId::from_bytes([3; 16]),
        AcceptOutcome::Idempotent,
    );
    assert_eq!(
        tracker.on_verified(&replayed, Delivery::Live),
        ExchangeAction::DuplicateRequest
    );

    let reply = verified(MessageKind::Reply, id, AcceptOutcome::Accepted);
    assert_eq!(
        tracker.on_verified(&reply, Delivery::Live),
        ExchangeAction::UnmatchedReply
    );
    tracker.register_request(id).unwrap();
    assert_eq!(
        tracker.on_verified(&reply, Delivery::Live),
        ExchangeAction::ReplyMatched(id)
    );
    assert_eq!(
        tracker.on_verified(&reply, Delivery::Live),
        ExchangeAction::UnmatchedReply
    );
    assert_eq!(
        tracker.on_verified(&reply, Delivery::Cached),
        ExchangeAction::Cached
    );
}

#[test]
fn pending_request_capacity_is_bounded() {
    let mut tracker = ExchangeTracker::default();
    for index in 0..MAX_PENDING_REQUESTS {
        tracker
            .register_request(RequestId::from_bytes([index as u8; 16]))
            .unwrap();
    }
    assert_eq!(
        tracker.register_request(RequestId::from_bytes([0xff; 16])),
        Err(ExchangeError::TooManyPending)
    );
}
