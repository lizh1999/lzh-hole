use std::net::Ipv4Addr;
use std::time::UNIX_EPOCH;

use ed25519_dalek::SigningKey;
use futures_util::stream;
use lzh_hole_protocol::path::{CandidateSource, Endpoint};
use lzh_hole_types::{BootId, DiscoveryPublicKey, RelationshipId};

use super::*;
use crate::message::{MessageKind, RequestId};
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

#[tokio::test]
async fn disconnect_preserves_pending_payload_for_explicit_failure_handling() {
    let config = NtfyConfig::new("https://example.com", "topic-1").unwrap();
    let (mut transport, _handle, _events) = NtfyTransport::channel(config, 2).unwrap();
    let payload = signed();
    let request_id = payload.request_id();
    let mut pending = Some(payload);
    let mut lines = stream::iter(Vec::<Result<String, LinesCodecError>>::new());
    let mut gate = HostGate::default();
    // The payload is waiting for its host turn, so a disconnect cannot POST it.
    gate.note_start(Instant::now());
    let mut budget = OperationBudget::new(2);
    let result = transport
        .run_connected(
            &mut lines,
            &mut gate,
            &mut budget,
            UNIX_EPOCH,
            &mut pending,
            Duration::from_millis(10),
        )
        .await;
    assert!(matches!(result, Err(NtfyError::Stream(_))));
    assert_eq!(
        pending.as_ref().map(SignedPayload::request_id),
        Some(request_id)
    );
}

#[derive(Debug, Clone, Default)]
struct SharedPacingStore(std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>);

impl NtfyPacingStore for SharedPacingStore {
    fn load(&mut self) -> Result<NtfyPacingLoad, String> {
        Ok(match self.0.lock().unwrap().clone() {
            Some(bytes) => NtfyPacingLoad::Snapshot(bytes),
            None => NtfyPacingLoad::Missing,
        })
    }

    fn save(&mut self, snapshot: &[u8]) -> Result<(), String> {
        self.0.lock().unwrap().replace(snapshot.to_vec());
        Ok(())
    }
}

fn test_config() -> NtfyConfig {
    NtfyConfig::new("https://example.com", "topic-1").unwrap()
}

#[tokio::test]
async fn response_headers_alone_do_not_enable_publishing() {
    let (mut transport, _handle, mut events) = NtfyTransport::channel(test_config(), 4).unwrap();
    let mut pending = Some(signed());
    let mut lines = stream::pending::<Result<String, LinesCodecError>>();
    let mut gate = HostGate::default();
    let mut budget = OperationBudget::new(2);
    let result = transport
        .run_connected(
            &mut lines,
            &mut gate,
            &mut budget,
            UNIX_EPOCH,
            &mut pending,
            Duration::from_millis(10),
        )
        .await;
    assert!(matches!(result, Err(NtfyError::Stream(_))));
    assert!(
        pending.is_some(),
        "payload must not be dequeued before NDJSON"
    );
    assert!(
        events.try_recv().is_err(),
        "headers are not subscription health"
    );
}

#[tokio::test]
async fn budget_failure_keeps_a_long_gate_after_the_stream_goes_idle() {
    let (mut transport, _handle, mut events) = NtfyTransport::channel(test_config(), 8).unwrap();
    let mut pending = Some(signed());
    let open = Ok("{\"event\":\"open\"}".to_owned());
    let mut lines = stream::iter(vec![open]).chain(stream::pending());
    let mut gate = HostGate::default();
    let mut budget = OperationBudget::new(1);
    budget.reserve(Instant::now()).unwrap();
    let result = transport
        .run_connected(
            &mut lines,
            &mut gate,
            &mut budget,
            UNIX_EPOCH,
            &mut pending,
            Duration::from_millis(20),
        )
        .await;
    assert!(matches!(result, Err(NtfyError::Stream(_))));
    assert!(pending.is_none());
    assert!(gate.remaining(Instant::now()).unwrap() > Duration::from_secs(23 * 60 * 60));

    let mut saw_ready = false;
    let mut saw_budget = false;
    let mut saw_failure = false;
    while let Ok(event) = events.try_recv() {
        match event {
            NtfyEvent::Subscribed { .. } => saw_ready = true,
            NtfyEvent::Error {
                detail,
                retry_after,
                ..
            } => {
                saw_budget = detail.contains("budget")
                    && retry_after.is_some_and(|wait| wait > Duration::from_secs(23 * 60 * 60));
            }
            NtfyEvent::PublishFailed { .. } => saw_failure = true,
            _ => {}
        }
    }
    assert!(saw_ready && saw_budget && saw_failure);
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
        .reserve_operation(&mut gate, &mut budget, NtfyOperation::Subscribe)
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
