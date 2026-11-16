use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use ed25519_dalek::SigningKey;
use lzh_hole_protocol::path::{CandidateSource, Endpoint};
use lzh_hole_types::{BootId, DiscoveryPublicKey, RelationshipId};

use super::*;
use crate::message::{MessageKind, RequestId};
use crate::pacing::DEFAULT_OPERATION_BUDGET;
use crate::record::{ContactRecord, RecordCandidate};

fn signed() -> SignedPayload {
    let sender = SigningKey::from_bytes(&[7; 32]);
    let receiver = SigningKey::from_bytes(&[8; 32]);
    let public = |key: &SigningKey| DiscoveryPublicKey::from_bytes(key.verifying_key().to_bytes());
    let record = ContactRecord {
        relationship_id: RelationshipId::from_bytes([0x44; 16]),
        sender: public(&sender),
        receiver: public(&receiver),
        record_seq: 800,
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_000_600_000,
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

fn relationship(byte: u8) -> RelationshipId {
    RelationshipId::from_bytes([byte; 16])
}

fn single_config(relationship: RelationshipId) -> NtfyConfig {
    NtfyConfig::new("https://example.com", "topic-1")
        .unwrap()
        .with_relationship(relationship)
        .unwrap()
}

fn multi_config(count: u8) -> NtfyConfig {
    let topics: BTreeMap<RelationshipId, String> = (1..=count)
        .map(|id| (relationship(id), format!("topic-{id}")))
        .collect();
    NtfyConfig::multi("https://example.com", &topics).unwrap()
}

#[derive(Debug, Clone, Default)]
struct SharedPacingStore {
    latest: std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    history: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
}

impl SharedPacingStore {
    fn saves(&self) -> Vec<Vec<u8>> {
        self.history.lock().unwrap().clone()
    }
}

impl NtfyPacingStore for SharedPacingStore {
    fn load(&mut self) -> Result<NtfyPacingLoad, String> {
        Ok(match self.latest.lock().unwrap().clone() {
            Some(bytes) => NtfyPacingLoad::Snapshot(bytes),
            None => NtfyPacingLoad::Missing,
        })
    }

    fn save(&mut self, snapshot: &[u8]) -> Result<(), String> {
        self.latest.lock().unwrap().replace(snapshot.to_vec());
        self.history.lock().unwrap().push(snapshot.to_vec());
        Ok(())
    }
}

fn test_config() -> NtfyConfig {
    single_config(relationship(1))
}

#[tokio::test]
async fn disconnect_preserves_pending_payload_for_explicit_failure_handling() {
    let relationship = relationship(1);
    let (mut transport, handle, _events) =
        NtfyTransport::channel(single_config(relationship), 2).unwrap();
    let payload = signed();
    let request_id = payload.request_id();
    handle.try_publish(relationship, payload).unwrap();

    let mut state = ActorState::new(&transport.config, 2, Instant::now());
    transport.drain_commands(&mut state);
    assert_eq!(state.pending.len(), 1);
    // The payload is waiting for its host turn, so a disconnect cannot POST it.
    state.gate.note_start(Instant::now());
    state
        .scheduler
        .note_subscribe_started(relationship, Instant::now());
    state
        .scheduler
        .note_subscribed(relationship, Instant::now());

    let (lines_tx, mut lines_rx) = mpsc::channel::<StreamMessage>(4);
    lines_tx
        .send(StreamMessage::Closed {
            relationship,
            detail: "server closed NDJSON stream".to_owned(),
        })
        .await
        .unwrap();
    transport
        .drain_streams(&mut state, &mut lines_rx)
        .await
        .unwrap();

    assert_eq!(
        state
            .pending
            .front()
            .map(|command| command.payload.request_id()),
        Some(request_id)
    );
    assert_eq!(
        state.scheduler.state(&relationship),
        Some(SubscriptionState::Idle)
    );
    assert_eq!(state.scheduler.failures(&relationship), Some(1));
    assert!(state.scheduler.next_attempt(&relationship).unwrap() > Instant::now());
}

#[tokio::test]
async fn response_headers_alone_do_not_enable_publishing() {
    let relationship = relationship(1);
    let (mut transport, handle, mut events) =
        NtfyTransport::channel(single_config(relationship), 4).unwrap();
    handle.try_publish(relationship, signed()).unwrap();

    let mut state = ActorState::new(&transport.config, 4, Instant::now());
    transport.drain_commands(&mut state);
    state
        .scheduler
        .note_subscribe_started(relationship, Instant::now());
    state
        .scheduler
        .note_subscribed(relationship, Instant::now());

    // Headers arrived, but no NDJSON line has been read yet.
    let (_lines_tx, mut lines_rx) = mpsc::channel::<StreamMessage>(4);
    transport
        .drain_streams(&mut state, &mut lines_rx)
        .await
        .unwrap();

    assert!(!state.scheduler.publish_ready(&relationship));
    assert!(state.ready_publishes().is_empty());
    assert_eq!(
        state.pending.len(),
        1,
        "payload must not be dequeued before NDJSON"
    );
    let decision = next_host_operation(
        &state.scheduler,
        &state.gate,
        &state.ready_publishes(),
        None,
        Instant::now(),
    )
    .unwrap();
    assert!(
        !matches!(decision, NextOperation::Publish(_)),
        "headers are not subscription health"
    );
    assert!(
        events.try_recv().is_err(),
        "headers are not subscription health"
    );
}

#[tokio::test]
async fn budget_failure_keeps_a_long_gate_after_the_stream_goes_idle() {
    let relationship = relationship(1);
    let (mut transport, handle, mut events) =
        NtfyTransport::channel(single_config(relationship), 8).unwrap();
    handle.try_publish(relationship, signed()).unwrap();

    let mut state = ActorState::new(&transport.config, 8, Instant::now());
    state.budget = OperationBudget::new(1);
    state.budget.reserve(Instant::now()).unwrap();
    transport.drain_commands(&mut state);
    state
        .scheduler
        .note_subscribe_started(relationship, Instant::now());
    state
        .scheduler
        .note_subscribed(relationship, Instant::now());

    let (lines_tx, mut lines_rx) = mpsc::channel::<StreamMessage>(4);
    lines_tx
        .send(StreamMessage::Line {
            relationship,
            line: Ok("{\"event\":\"open\"}".to_owned()),
        })
        .await
        .unwrap();
    transport
        .drain_streams(&mut state, &mut lines_rx)
        .await
        .unwrap();
    assert!(state.scheduler.publish_ready(&relationship));

    let ready = state.ready_publishes();
    assert_eq!(ready, vec![relationship]);
    assert_eq!(
        next_host_operation(&state.scheduler, &state.gate, &ready, None, Instant::now()).unwrap(),
        NextOperation::Publish(relationship)
    );
    transport
        .run_publish(&mut state, relationship)
        .await
        .unwrap();

    assert!(state.pending.is_empty());
    assert!(state.gate.remaining(Instant::now()).unwrap() > Duration::from_secs(23 * 60 * 60));

    let mut saw_ready = false;
    let mut saw_budget = false;
    let mut saw_failure = false;
    while let Ok(event) = events.try_recv() {
        match event {
            NtfyEvent::Subscribed {
                relationship: source,
                ..
            } => saw_ready = source == relationship,
            NtfyEvent::Error {
                relationship: source,
                detail,
                retry_after,
                ..
            } => {
                saw_budget = source == Some(relationship)
                    && detail.contains("budget")
                    && retry_after.is_some_and(|wait| wait > Duration::from_secs(23 * 60 * 60));
            }
            NtfyEvent::PublishFailed {
                relationship: source,
                ..
            } => saw_failure = source == relationship,
            _ => {}
        }
    }
    assert!(saw_ready && saw_budget && saw_failure);

    // An idle stream ends on its own per-relationship deadline and must not
    // shorten or lengthen the shared host gate.
    assert_eq!(
        state.scheduler.expired_idle(Instant::now(), Duration::ZERO),
        Some(relationship)
    );
    transport
        .fail_stream(
            &mut state,
            relationship,
            Instant::now(),
            "no NDJSON data or keepalive".to_owned(),
        )
        .await
        .unwrap();
    assert_eq!(
        state.scheduler.state(&relationship),
        Some(SubscriptionState::Idle)
    );
    assert!(state.gate.remaining(Instant::now()).unwrap() > Duration::from_secs(23 * 60 * 60));
}

#[tokio::test]
async fn pacing_and_original_reason_survive_actor_recreation_and_smaller_idle_delay() {
    let store = SharedPacingStore::default();
    let (mut first, _handle, _events) =
        NtfyTransport::channel_with_pacing_store(test_config(), 8, Box::new(store.clone()))
            .unwrap();
    let mut gate = HostGate::default();
    let mut budget = OperationBudget::new(1);
    first
        .reserve_operation(&mut gate, &mut budget, NtfyOperation::Subscribe, None)
        .await
        .unwrap();
    first
        .defer_pacing(
            &mut gate,
            &mut budget,
            Duration::from_secs(3600),
            "server Retry-After".to_owned(),
        )
        .unwrap();

    let (mut second, _handle, mut events) =
        NtfyTransport::channel_with_pacing_store(test_config(), 8, Box::new(store.clone()))
            .unwrap();
    let mut restored_gate = HostGate::default();
    let mut restored_budget = OperationBudget::new(1);
    second
        .restore_pacing(&mut restored_gate, &mut restored_budget)
        .await
        .unwrap();
    assert!(restored_budget.reserve(Instant::now()).is_err());
    assert!(restored_gate.remaining(Instant::now()).unwrap() > Duration::from_secs(3500));
    let event = events.recv().await.unwrap();
    assert!(matches!(
        event,
        NtfyEvent::Error { detail, .. } if detail.contains("server Retry-After")
    ));
    second
        .defer_pacing(
            &mut restored_gate,
            &mut restored_budget,
            Duration::from_secs(60),
            "later idle timeout".to_owned(),
        )
        .unwrap();

    let (mut third, _handle, mut events) =
        NtfyTransport::channel_with_pacing_store(test_config(), 8, Box::new(store)).unwrap();
    let mut third_gate = HostGate::default();
    let mut third_budget = OperationBudget::new(1);
    third
        .restore_pacing(&mut third_gate, &mut third_budget)
        .await
        .unwrap();
    let event = events.recv().await.unwrap();
    assert!(matches!(
        event,
        NtfyEvent::Error { detail, .. } if detail.contains("server Retry-After")
    ));
}

#[test]
fn repeated_idle_disconnects_escalate_instead_of_resetting_reconnect_backoff() {
    let failures = failures_after_connection(1, Duration::from_secs(90));
    assert_eq!(failures, 2);
    assert_eq!(reconnect_delay(failures), Duration::from_secs(60));
    assert_eq!(
        failures_after_connection(8, HEALTHY_CONNECTION_RESET),
        1,
        "only a sustained healthy connection resets backoff"
    );
}

#[tokio::test]
async fn missing_snapshot_applies_only_a_persistent_host_cooldown_without_fake_history() {
    let store = SharedPacingStore::default();
    let (mut first, _handle, mut events) =
        NtfyTransport::channel_with_pacing_store(test_config(), 4, Box::new(store.clone()))
            .unwrap();
    let mut gate = HostGate::default();
    let mut budget = OperationBudget::new(128);
    first.restore_pacing(&mut gate, &mut budget).await.unwrap();
    let remaining = gate.remaining(Instant::now()).unwrap();
    assert!(remaining > Duration::from_secs(29));
    assert!(remaining <= MIN_HOST_INTERVAL);
    assert!(budget.reserve(Instant::now()).is_ok());
    assert!(events.try_recv().is_err());

    let (mut second, _handle, mut events) =
        NtfyTransport::channel_with_pacing_store(test_config(), 4, Box::new(store)).unwrap();
    let mut restored_gate = HostGate::default();
    let mut restored_budget = OperationBudget::new(128);
    second
        .restore_pacing(&mut restored_gate, &mut restored_budget)
        .await
        .unwrap();
    let restored = restored_gate.remaining(Instant::now()).unwrap();
    assert!(restored <= remaining);
    assert!(restored > Duration::from_secs(28));
    assert!(restored_budget.reserve(Instant::now()).is_ok());
    assert!(events.try_recv().is_err());
}

#[tokio::test]
async fn try_publish_routes_to_the_relationship_topic_and_refuses_unknown_ones() {
    let (transport, handle, _events) = NtfyTransport::channel(multi_config(3), 4).unwrap();
    let mut outgoing = transport.outgoing;

    assert!(matches!(
        handle.try_publish(relationship(9), signed()),
        Err(TryPublishError::UnknownRelationship(id)) if id == relationship(9)
    ));
    assert!(
        outgoing.try_recv().is_err(),
        "a refused publish queues nothing"
    );

    handle.try_publish(relationship(2), signed()).unwrap();
    let command = outgoing.try_recv().unwrap();
    assert_eq!(command.relationship, relationship(2));
    assert_eq!(
        transport
            .config
            .publish_url_for(&command.relationship)
            .unwrap()
            .as_str(),
        "https://example.com/topic-2"
    );
    for id in 1..=3u8 {
        assert_eq!(
            transport
                .config
                .publish_url_for(&relationship(id))
                .unwrap()
                .as_str(),
            format!("https://example.com/topic-{id}")
        );
    }
}

#[tokio::test]
async fn an_unbound_single_topic_configuration_cannot_create_an_actor() {
    let config = NtfyConfig::new("https://example.com", "topic-1").unwrap();
    assert_eq!(config.topic_count(), 1);
    assert!(matches!(
        NtfyTransport::channel(config, 4),
        Err(NtfyError::Config(_))
    ));
}

/// Model a host where every relationship always wants a host operation right
/// now: each subscribe fails and the relationship is due again immediately, so
/// only the shared gate can bound the operation count.
fn saturated_operations(relationships: u8, window: Duration) -> usize {
    let start = Instant::now();
    let ids: Vec<RelationshipId> = (1..=relationships).map(relationship).collect();
    let mut scheduler = Scheduler::new(ids.iter().copied(), start);
    let mut gate = HostGate::default();
    let mut now = start;
    let mut operations = 0usize;
    while now < start + window {
        match next_host_operation(&scheduler, &gate, &[], None, now).unwrap() {
            NextOperation::Subscribe(relationship) => {
                gate.note_start(now);
                scheduler.note_subscribe_started(relationship, now);
                scheduler
                    .schedule_reconnect(relationship, now, Duration::ZERO)
                    .unwrap();
                operations += 1;
                now += Duration::from_millis(1);
            }
            NextOperation::Wait(at) => now = at.max(now + Duration::from_millis(1)),
            NextOperation::Publish(_) | NextOperation::Idle => break,
        }
    }
    operations
}

/// Model a host whose every subscribe fails and whose per-relationship backoff
/// therefore escalates on its own.
fn simulated_operations(relationships: u8, window: Duration) -> usize {
    let start = Instant::now();
    let ids: Vec<RelationshipId> = (1..=relationships).map(relationship).collect();
    let mut scheduler = Scheduler::new(ids.iter().copied(), start);
    let mut gate = HostGate::default();
    let mut now = start;
    let mut operations = 0usize;
    while now < start + window {
        match next_host_operation(&scheduler, &gate, &[], None, now).unwrap() {
            NextOperation::Subscribe(relationship) => {
                gate.note_start(now);
                scheduler.note_subscribe_started(relationship, now);
                let failures = scheduler.bump_failures(&relationship);
                scheduler
                    .schedule_reconnect(relationship, now, reconnect_delay(failures))
                    .unwrap();
                operations += 1;
                now += Duration::from_millis(1);
            }
            NextOperation::Wait(at) => now = at.max(now + Duration::from_millis(1)),
            NextOperation::Publish(_) | NextOperation::Idle => break,
        }
    }
    operations
}

#[test]
fn one_shared_gate_caps_operations_regardless_of_relationship_count() {
    let window = Duration::from_secs(600);
    let maximum = (window.as_secs() / MIN_HOST_INTERVAL.as_secs()) as usize;

    // Saturated demand: eight relationships wanting an operation at once must
    // not produce eight times the operations of a single relationship.
    let single = saturated_operations(1, window);
    let eight = saturated_operations(8, window);
    assert_eq!(
        single, maximum,
        "one relationship is already limited by the shared gate alone"
    );
    assert_eq!(
        eight, single,
        "adding relationships must never raise the host operation rate"
    );

    // Escalating per-relationship backoff can only lower the rate further.
    let escalating = simulated_operations(8, window);
    assert!(escalating > 0);
    assert!(
        escalating <= maximum,
        "{escalating} operations in {window:?} exceeds the {maximum} the shared gate allows"
    );
}

#[test]
fn one_rolling_budget_caps_every_topic_together() {
    let start = Instant::now();
    let ids: Vec<RelationshipId> = (1..=8u8).map(relationship).collect();
    let mut scheduler = Scheduler::new(ids.iter().copied(), start);
    let mut gate = HostGate::default();
    let mut budget = OperationBudget::new(DEFAULT_OPERATION_BUDGET);
    let mut now = start;
    let mut reserved = 0usize;
    let mut touched = BTreeSet::new();
    while now < start + Duration::from_secs(48 * 60 * 60) {
        match next_host_operation(&scheduler, &gate, &[], None, now).unwrap() {
            NextOperation::Subscribe(relationship) => {
                if budget.reserve(now).is_err() {
                    break;
                }
                reserved += 1;
                touched.insert(relationship);
                gate.note_start(now);
                scheduler.note_subscribe_started(relationship, now);
                let failures = scheduler.bump_failures(&relationship);
                scheduler
                    .schedule_reconnect(relationship, now, reconnect_delay(failures))
                    .unwrap();
                now += Duration::from_millis(1);
            }
            NextOperation::Wait(at) => now = at.max(now + Duration::from_millis(1)),
            NextOperation::Publish(_) | NextOperation::Idle => break,
        }
    }
    assert_eq!(
        reserved, DEFAULT_OPERATION_BUDGET as usize,
        "eight topics must not each receive their own rolling budget"
    );
    assert!(
        touched.len() > 1,
        "the shared gate must still serve several relationships"
    );
    assert!(now - start >= MIN_HOST_INTERVAL * (DEFAULT_OPERATION_BUDGET - 1));
}

#[test]
fn one_failing_stream_does_not_raise_another_relationships_backoff() {
    let start = Instant::now();
    let (a, b, c) = (relationship(1), relationship(2), relationship(3));
    let mut scheduler = Scheduler::new([a, b, c], start);
    let mut gate = HostGate::default();

    let mut now = start;
    for expected in 1..=5u32 {
        scheduler.note_subscribe_started(a, now);
        let failures = scheduler.bump_failures(&a);
        assert_eq!(failures, expected);
        scheduler
            .schedule_reconnect(a, now, reconnect_delay(failures))
            .unwrap();
        gate.note_start(now);
        now += MIN_HOST_INTERVAL;
    }

    assert_eq!(scheduler.failures(&a), Some(5));
    assert_eq!(scheduler.failures(&b), Some(0));
    assert_eq!(scheduler.failures(&c), Some(0));
    assert_eq!(scheduler.next_attempt(&b), Some(start));
    assert_eq!(scheduler.next_attempt(&c), Some(start));
    assert_eq!(
        scheduler.next_attempt(&a),
        Some(start + MIN_HOST_INTERVAL * 4 + reconnect_delay(5))
    );

    // Only a carries the escalated backoff; b and c are still due at once.
    assert_eq!(scheduler.due_subscribe(now), Some(b));

    // They nevertheless queue behind the one shared host gate.
    let blocked = now - Duration::from_secs(1);
    gate.note_start(blocked);
    match next_host_operation(&scheduler, &gate, &[], None, blocked).unwrap() {
        NextOperation::Wait(at) => assert_eq!(at, blocked + MIN_HOST_INTERVAL),
        other => panic!("the shared gate must serialize every relationship, got {other:?}"),
    }
    let opened = blocked + MIN_HOST_INTERVAL;
    assert_eq!(
        next_host_operation(&scheduler, &gate, &[], None, opened).unwrap(),
        NextOperation::Subscribe(b),
        "exactly one relationship starts per host turn"
    );
}

#[tokio::test]
async fn multi_topic_pacing_persists_one_aggregate_snapshot() {
    let store = SharedPacingStore::default();
    let (mut transport, _handle, _events) =
        NtfyTransport::channel_with_pacing_store(multi_config(3), 4, Box::new(store.clone()))
            .unwrap();
    let mut gate = HostGate::default();
    let mut budget = OperationBudget::new(DEFAULT_OPERATION_BUDGET);
    for id in 1..=3u8 {
        transport
            .reserve_operation(
                &mut gate,
                &mut budget,
                NtfyOperation::Subscribe,
                Some(relationship(id)),
            )
            .await
            .unwrap();
    }

    let saves = store.saves();
    assert_eq!(
        saves.len(),
        3,
        "one snapshot per HTTP attempt, never one snapshot per topic"
    );
    let mut previous = 0usize;
    for bytes in &saves {
        let snapshot: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        assert_eq!(
            snapshot["version"], 1,
            "the pacing snapshot format version must not change"
        );
        assert!(
            snapshot.get("topics").is_none(),
            "the snapshot stays per host, never per topic"
        );
        assert_eq!(
            snapshot.as_object().unwrap().len(),
            4,
            "version, starts, one not_before and one reason"
        );
        let starts = snapshot["operation_starts_unix_ms"].as_array().unwrap();
        assert!(
            starts.len() > previous,
            "every topic operation is aggregated into the one snapshot"
        );
        previous = starts.len();
        let not_before = &snapshot["not_before_unix_ms"];
        assert!(not_before.is_u64() || not_before.is_null());
    }
    assert_eq!(previous, 3);
}
