use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use reqwest::dns::Resolve as _;

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

fn relationship(byte: u8) -> RelationshipId {
    RelationshipId::from_bytes([byte; 16])
}

fn topic_map(pairs: &[(u8, &str)]) -> BTreeMap<RelationshipId, String> {
    pairs
        .iter()
        .map(|(id, topic)| (relationship(*id), (*topic).to_owned()))
        .collect()
}

#[derive(Debug)]
struct StubResolver {
    result: Result<Vec<SocketAddr>, String>,
}

impl reqwest::dns::Resolve for StubResolver {
    fn resolve(&self, _name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let result = self.result.clone();
        Box::pin(async move {
            match result {
                Ok(addresses) => Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs),
                Err(detail) => Err(Box::new(std::io::Error::other(detail))
                    as Box<dyn std::error::Error + Send + Sync>),
            }
        })
    }
}

fn guarded(result: Result<Vec<SocketAddr>, String>) -> GuardedResolver {
    GuardedResolver {
        inner: Arc::new(StubResolver { result }),
    }
}

async fn guarded_lookup(addresses: Vec<SocketAddr>) -> Result<Vec<SocketAddr>, String> {
    let name = "ntfy.sh".parse().expect("a valid DNS name");
    match guarded(Ok(addresses)).resolve(name).await {
        Ok(addrs) => Ok(addrs.collect()),
        Err(error) => Err(error.to_string()),
    }
}

#[tokio::test]
async fn a_resolved_address_in_a_refused_range_is_never_connected_to() {
    let public = SocketAddr::from((Ipv4Addr::new(159, 203, 148, 75), 0));
    assert_eq!(
        guarded_lookup(vec![public, public]).await.unwrap(),
        vec![public]
    );

    for (ip, reason) in [
        (Ipv4Addr::new(198, 18, 0, 30), "fake_ip"),
        (Ipv4Addr::new(192, 168, 31, 1), "private"),
        (Ipv4Addr::new(127, 0, 0, 1), "loopback"),
        (Ipv4Addr::new(100, 64, 0, 1), "cgnat"),
        (Ipv4Addr::new(224, 0, 0, 1), "multicast"),
        (Ipv4Addr::new(169, 254, 1, 1), "link_local"),
    ] {
        // A single refused address refuses the whole answer: partially
        // trusting a resolver that mixes real and Fake-IP answers is exactly
        // the failure this guard exists to prevent.
        let error = guarded_lookup(vec![public, SocketAddr::from((ip, 0))])
            .await
            .unwrap_err();
        assert!(error.contains(reason), "{ip}: {error}");
        assert!(error.contains(&ip.to_string()), "{ip}: {error}");
    }

    assert!(
        guarded_lookup(Vec::new())
            .await
            .unwrap_err()
            .contains("no usable address")
    );
}

#[tokio::test]
async fn a_resolver_failure_keeps_its_own_diagnostic() {
    let name = "ntfy.sh".parse().expect("a valid DNS name");
    let error = match guarded(Err("gateway 192.168.31.1 did not answer".to_owned()))
        .resolve(name)
        .await
    {
        Ok(_) => panic!("a failing resolver must not produce addresses"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("gateway 192.168.31.1 did not answer"),
        "{error}"
    );
}

#[test]
fn a_client_can_be_built_around_an_injected_resolver() {
    let config = NtfyConfig::new("https://ntfy.sh", "topic-1")
        .unwrap()
        .with_relationship(relationship(1))
        .unwrap()
        .with_resolver(NtfyResolver::new(StubResolver {
            result: Ok(Vec::new()),
        }));
    assert!(config.resolver.is_some());
    assert!(build_client(&config).is_ok());
}

#[test]
fn a_fake_ip_failure_keeps_the_operation_that_produced_it() {
    let address: SocketAddr = "198.18.0.30:443".parse().unwrap();
    assert_eq!(
        NtfyError::FakeIp {
            operation: NtfyOperation::Publish,
            address
        }
        .operation(),
        NtfyOperation::Publish
    );
    assert_eq!(
        NtfyError::FakeIp {
            operation: NtfyOperation::Subscribe,
            address
        }
        .operation(),
        NtfyOperation::Subscribe
    );
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
            relationship(1),
            "topic-1",
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
            false,
        )
        .is_none()
    );
    let message = lines.next().await.unwrap().unwrap();
    let event = parse_ntfy_line(
        &message,
        relationship(1),
        "topic-1",
        UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        false,
    )
    .unwrap()
    .unwrap();
    match event {
        NtfyEvent::Received {
            relationship: source,
            payload: received,
            delivery: Delivery::Live,
            ntfy_id,
        } => {
            assert_eq!(source, relationship(1));
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
        relationship(1),
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
        relationship(1),
        "topic-1",
        UNIX_EPOCH + Duration::from_secs(101),
        false,
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
        relationship(1),
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
        .with_relationship(relationship(1))
        .unwrap()
        .with_cached_replay(true);
    assert_eq!(config.topic_count(), 1);
    assert_eq!(
        config.subscribe_url_for(&relationship(1)).unwrap().as_str(),
        "https://example.com/base/topic-1/json?since=all"
    );
    assert_eq!(
        config.publish_url_for(&relationship(1)).unwrap().as_str(),
        "https://example.com/base/topic-1"
    );
    assert!(config.publish_url_for(&relationship(2)).is_err());
}

#[test]
fn resolve_override_preserves_the_https_origin_and_public_address_policy() {
    let config = NtfyConfig::new("https://example.com/base", "topic-1")
        .unwrap()
        .with_relationship(relationship(1))
        .unwrap()
        .with_resolve_ip(Ipv4Addr::new(159, 203, 148, 75))
        .unwrap();
    assert_eq!(config.base_url.as_str(), "https://example.com/base/");
    assert_eq!(
        config.resolve_addr,
        Some("159.203.148.75:443".parse().unwrap())
    );
    assert_eq!(
        config.subscribe_url_for(&relationship(1)).unwrap().as_str(),
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

#[test]
fn multi_topic_configuration_is_bounded_and_refuses_shared_topics() {
    let one = topic_map(&[(1, "topic-a")]);
    let single = NtfyConfig::multi("https://example.com", &one).unwrap();
    assert_eq!(single.topic_count(), 1);
    assert_eq!(single.relationships().count(), 1);

    let eight: BTreeMap<RelationshipId, String> = (1..=8u8)
        .map(|id| (relationship(id), format!("topic-{id}")))
        .collect();
    let full = NtfyConfig::multi("https://example.com/base", &eight).unwrap();
    assert_eq!(full.topic_count(), MAX_NTFY_TOPICS);
    assert_eq!(full.relationships().count(), MAX_NTFY_TOPICS);

    let nine: BTreeMap<RelationshipId, String> = (1..=9u8)
        .map(|id| (relationship(id), format!("topic-{id}")))
        .collect();
    assert!(NtfyConfig::multi("https://example.com", &nine).is_err());

    assert!(NtfyConfig::multi("https://example.com", &BTreeMap::new()).is_err());

    assert!(NtfyConfig::multi("https://example.com", &topic_map(&[(1, "bad topic")])).is_err());
    assert!(NtfyConfig::multi("https://example.com", &topic_map(&[(1, "")])).is_err());
    let long = "x".repeat(65);
    assert!(NtfyConfig::multi("https://example.com", &topic_map(&[(1, long.as_str())])).is_err());
    let edge = "x".repeat(64);
    assert!(NtfyConfig::multi("https://example.com", &topic_map(&[(1, edge.as_str())])).is_ok());

    // Two relationships must never share one topic.
    assert!(
        NtfyConfig::multi(
            "https://example.com",
            &topic_map(&[(1, "shared"), (2, "shared")])
        )
        .is_err()
    );

    // Base URL validation is unchanged for multi-topic configurations.
    assert!(NtfyConfig::multi("http://example.com", &one).is_err());
    assert!(NtfyConfig::multi("https://user@example.com", &one).is_err());
    assert!(NtfyConfig::multi("https://example.com/base?x=1", &one).is_err());
}

#[test]
fn topic_urls_follow_the_relationship_and_refuse_unserved_ones() {
    let topics = topic_map(&[(1, "topic-a"), (2, "topic-b"), (3, "topic-c")]);
    let config = NtfyConfig::multi("https://example.com/base", &topics)
        .unwrap()
        .with_cached_replay(true);
    assert_eq!(config.topic_for(&relationship(1)), Some("topic-a"));
    assert_eq!(config.topic_for(&relationship(2)), Some("topic-b"));
    assert_eq!(config.topic_for(&relationship(9)), None);
    assert_eq!(
        config.publish_url_for(&relationship(2)).unwrap().as_str(),
        "https://example.com/base/topic-b"
    );
    assert_eq!(
        config.subscribe_url_for(&relationship(3)).unwrap().as_str(),
        "https://example.com/base/topic-c/json?since=all"
    );
    assert!(config.publish_url_for(&relationship(9)).is_err());
    assert!(config.subscribe_url_for(&relationship(9)).is_err());
}

#[test]
fn received_events_carry_the_relationship_of_their_own_topic() {
    let payload = signed(702);
    let wire = serde_json::json!({
        "id": "message-a",
        "time": 1_800_000_100u64,
        "event": "message",
        "topic": "topic-a",
        "message": payload.to_json().unwrap(),
    })
    .to_string();
    let wall = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let event = parse_ntfy_line(&wire, relationship(1), "topic-a", wall, false)
        .unwrap()
        .unwrap();
    match event {
        NtfyEvent::Received {
            relationship: source,
            ntfy_id,
            ..
        } => {
            assert_eq!(source, relationship(1));
            assert_eq!(ntfy_id, "message-a");
        }
        _ => panic!("unexpected event"),
    }

    // The same line read on another relationship's stream is refused: a message
    // may never be attributed to a topic it did not arrive on.
    assert!(matches!(
        parse_ntfy_line(&wire, relationship(2), "topic-b", wall, false),
        Some(Err(NtfyError::Protocol(_)))
    ));
}
