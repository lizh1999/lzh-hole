use std::net::Ipv4Addr;

use ed25519_dalek::SigningKey;
use futures_util::{StreamExt, stream};
use lzh_hole_protocol::path::{CandidateSource, Endpoint};
use lzh_hole_types::{BootId, DiscoveryPublicKey, RelationshipId};

use super::*;
use crate::record::{ContactRecord, RecordCandidate};

const NOW: u64 = 1_800_000_000_000;

fn public(signing: &SigningKey) -> DiscoveryPublicKey {
    DiscoveryPublicKey::from_bytes(signing.verifying_key().to_bytes())
}

fn signed(sequence: u64) -> SignedPayload {
    let sender = SigningKey::from_bytes(&[7; 32]);
    let receiver = SigningKey::from_bytes(&[8; 32]);
    let record = ContactRecord {
        relationship_id: RelationshipId::from_bytes([0x44; 16]),
        sender: public(&sender),
        receiver: public(&receiver),
        record_seq: sequence,
        issued_at_unix_ms: NOW,
        expires_at_unix_ms: NOW + 600_000,
        boot_id: BootId::from_bytes([0x91; 16]),
        generation: 1,
        candidates: vec![RecordCandidate {
            endpoint: Endpoint::new(Ipv4Addr::new(8, 8, 8, 8), 50_000),
            source: CandidateSource::Stun,
        }],
        flags: 0,
    };
    SignedPayload::sign(
        MessageKind::Request,
        RequestId::from_bytes([0x12; 16]),
        &record,
        &sender,
    )
    .unwrap()
}

#[tokio::test]
async fn ndjson_handles_chunk_boundaries_keepalive_and_oversize_lines() {
    let payload = signed(700);
    let wire = serde_json::json!({
        "id": "message-1",
        "time": 1_800_000_100u64,
        "event": "message",
        "topic": "topic-1",
        "message": payload.to_json().unwrap(),
    })
    .to_string();
    let input = format!("{{\"event\":\"open\"}}\n{wire}\n");
    let midpoint = input.len() / 2;
    let chunks = vec![
        Ok(Bytes::copy_from_slice(&input.as_bytes()[..midpoint])),
        Ok(Bytes::copy_from_slice(&input.as_bytes()[midpoint..])),
    ];
    let lines = ndjson_lines(stream::iter(chunks));
    tokio::pin!(lines);
    let open = lines.next().await.unwrap().unwrap();
    assert!(
        parse_ntfy_line(
            &open,
            "topic-1",
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
            false,
        )
        .is_none()
    );
    let message = lines.next().await.unwrap().unwrap();
    let event = parse_ntfy_line(
        &message,
        "topic-1",
        UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        false,
    )
    .unwrap()
    .unwrap();
    match event {
        NtfyEvent::Received {
            payload: received,
            delivery: Delivery::Live,
            ntfy_id,
        } => {
            assert_eq!(received, payload);
            assert_eq!(ntfy_id, "message-1");
        }
        _ => panic!("unexpected event"),
    }
    assert!(lines.next().await.is_none());

    let oversized = format!("{}\n", "x".repeat(MAX_NTFY_LINE_BYTES + 1));
    let lines = ndjson_lines(stream::iter(vec![Ok(Bytes::from(oversized))]));
    tokio::pin!(lines);
    assert!(matches!(
        lines.next().await,
        Some(Err(LinesCodecError::MaxLineLengthExceeded))
    ));
}

#[test]
fn cached_replay_distinguishes_old_new_and_ambiguous_messages() {
    let payload = signed(701);
    let wire = serde_json::json!({
        "id": "cached-1",
        "time": 100u64,
        "event": "message",
        "topic": "topic-1",
        "message": payload.to_json().unwrap(),
    })
    .to_string();
    let event = parse_ntfy_line(
        &wire,
        "topic-1",
        UNIX_EPOCH + Duration::from_secs(101),
        true,
    )
    .unwrap()
    .unwrap();
    assert!(matches!(
        event,
        NtfyEvent::Received {
            delivery: Delivery::Cached,
            ..
        }
    ));

    let live = wire.replace("\"time\":100", "\"time\":102");
    let event = parse_ntfy_line(
        &live,
        "topic-1",
        UNIX_EPOCH + Duration::from_secs(101),
        true,
    )
    .unwrap()
    .unwrap();
    assert!(matches!(
        event,
        NtfyEvent::Received {
            delivery: Delivery::Live,
            ..
        }
    ));

    let event = parse_ntfy_line(
        &wire,
        "topic-1",
        UNIX_EPOCH + Duration::from_millis(100_900),
        false,
    )
    .unwrap()
    .unwrap();
    assert!(matches!(
        event,
        NtfyEvent::Received {
            delivery: Delivery::Cached,
            ..
        }
    ));
}

#[test]
fn stale_signed_payload_is_refused_before_post_without_mutation() {
    let payload = signed(799);
    let expires = payload.expires_at_unix_ms().unwrap();
    assert!(check_publish_fresh(&payload, UNIX_EPOCH + Duration::from_millis(NOW)).is_ok());
    assert!(matches!(
        check_publish_fresh(&payload, UNIX_EPOCH + Duration::from_millis(expires)),
        Err(NtfyError::PublishExpired {
            kind: MessageKind::Request,
            expires_at_unix_ms,
            ..
        }) if expires_at_unix_ms == expires
    ));
    assert_eq!(payload.expires_at_unix_ms().unwrap(), expires);
}

#[test]
fn config_rejects_ambiguous_urls_and_builds_json_endpoint() {
    assert!(NtfyConfig::new("http://example.com", "topic").is_err());
    assert!(NtfyConfig::new("https://user@example.com", "topic").is_err());
    assert!(NtfyConfig::new("https://example.com", "bad topic").is_err());
    let config = NtfyConfig::new("https://example.com/base", "topic-1")
        .unwrap()
        .with_cached_replay(true);
    assert_eq!(
        config.subscribe_url().unwrap().as_str(),
        "https://example.com/base/topic-1/json?since=all"
    );
    assert_eq!(
        config.publish_url().unwrap().as_str(),
        "https://example.com/base/topic-1"
    );
}

#[test]
fn resolve_override_preserves_the_https_origin_and_public_address_policy() {
    let config = NtfyConfig::new("https://example.com/base", "topic-1")
        .unwrap()
        .with_resolve_ip(Ipv4Addr::new(159, 203, 148, 75))
        .unwrap();
    assert_eq!(config.base_url.as_str(), "https://example.com/base/");
    assert_eq!(
        config.resolve_addr,
        Some("159.203.148.75:443".parse().unwrap())
    );
    assert_eq!(
        config.subscribe_url().unwrap().as_str(),
        "https://example.com/base/topic-1/json"
    );
    assert!(
        NtfyConfig::new("https://example.com", "topic-1")
            .unwrap()
            .with_resolve_ip(Ipv4Addr::new(198, 18, 0, 1))
            .is_err()
    );
    assert!(
        NtfyConfig::new("https://8.8.8.8", "topic-1")
            .unwrap()
            .with_resolve_ip(Ipv4Addr::new(159, 203, 148, 75))
            .is_err()
    );
}
