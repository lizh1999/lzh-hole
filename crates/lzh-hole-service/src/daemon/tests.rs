use lzh_hole_control::{ComponentState, ControlResponse, DaemonState};
use lzh_hole_store::{PAIRING_VERSION, Relationship, Role};
use lzh_hole_types::RelationshipId;

use super::*;
use crate::config::NtfyConfig as FileNtfyConfig;

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

fn relationship(seed: &[u8; 32]) -> Relationship {
    let signing = SigningKey::from_bytes(seed);
    Relationship {
        pairing_version: PAIRING_VERSION,
        pairing_id: RelationshipId::from_bytes([1; 16]),
        relationship_id: RelationshipId::from_bytes([2; 16]),
        self_public_key: DiscoveryPublicKey::from_bytes(signing.verifying_key().to_bytes()),
        peer_public_key: DiscoveryPublicKey::from_bytes([9; 32]),
        role: Role::Initiator,
        self_vip: "10.203.0.1".to_owned(),
        peer_vip: "10.203.0.2".to_owned(),
        finalised_unix_ms: 1,
    }
}

fn resolved_for_test(interface: Option<&str>) -> ResolvedConfig {
    let relationship = relationship(&[7u8; 32]);
    ServiceConfig {
        state_dir: PathBuf::from("/var/db/lzh-hole-test"),
        control_socket: PathBuf::from("/var/run/lzh-hole-test/control.sock"),
        management_uid: effective_uid(),
        interface: interface.map(str::to_owned),
        bind_ip: None,
        udp_port: 51000,
        stun_seeds: vec![SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 3478)],
        ntfy: FileNtfyConfig {
            base_url: "https://ntfy.sh".to_owned(),
            topic: topic_for_relationship(&relationship.relationship_id),
            resolve_ip: None,
        },
        mtu: 1200,
    }
    .resolve(relationship)
    .unwrap()
}

fn physical(name: &str, index: u32, ip: Ipv4Addr) -> InterfaceInfo {
    InterfaceInfo {
        name: name.to_owned(),
        index,
        ipv4: vec![ip],
        is_up: true,
        is_loopback: false,
        is_tunnel: false,
    }
}

fn offline_daemon() -> (tempfile::TempDir, Daemon) {
    let temp = tempfile::tempdir().unwrap();
    let state = StateDir::open(&temp.path().join("state")).unwrap();
    let seed = [7u8; 32];
    state.store_seed(&seed).unwrap();
    let relationship = relationship(&seed);
    state
        .finalise(&relationship, &Secret32::from_bytes([0x5a; 32]))
        .unwrap();
    let mut resolved = resolved_for_test(None);
    resolved.config.state_dir = state.path().to_path_buf();
    resolved.config.control_socket = temp.path().join("control").join("control.sock");
    let (snapshots, _) = watch::channel(ServiceSnapshot::starting(1, now_unix_ms()));
    let daemon = Daemon::new(
        resolved,
        false,
        RuntimeComponents::offline_for_test(),
        snapshots,
    )
    .unwrap();
    (temp, daemon)
}

fn contact_record_for(
    daemon: &Daemon,
    sender: DiscoveryPublicKey,
    receiver: DiscoveryPublicKey,
) -> ContactRecord {
    let now = now_unix_ms();
    ContactRecord {
        relationship_id: daemon.resolved.relationship.relationship_id,
        sender,
        receiver,
        record_seq: now_unix_us(),
        issued_at_unix_ms: now,
        expires_at_unix_ms: now + MAX_LIFETIME_MS,
        boot_id: BootId::random().unwrap(),
        generation: 1,
        candidates: vec![RecordCandidate {
            endpoint: Endpoint::new(Ipv4Addr::new(8, 8, 4, 4), 50_000),
            source: CandidateSource::Stun,
        }],
    }
}

#[tokio::test(flavor = "current_thread")]
async fn injected_offline_components_support_doctor_and_clean_shutdown() {
    let temp = tempfile::tempdir().unwrap();
    let state = StateDir::open(&temp.path().join("state")).unwrap();
    let seed = [7u8; 32];
    state.store_seed(&seed).unwrap();
    let relationship = relationship(&seed);
    state
        .finalise(&relationship, &Secret32::from_bytes([0x5a; 32]))
        .unwrap();
    let socket_path = temp.path().join("control").join("control.sock");
    let config = ServiceConfig {
        state_dir: state.path().to_path_buf(),
        control_socket: socket_path.clone(),
        management_uid: effective_uid(),
        interface: None,
        bind_ip: None,
        udp_port: 51000,
        stun_seeds: vec![SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 3478)],
        ntfy: FileNtfyConfig {
            base_url: "https://ntfy.sh".to_owned(),
            topic: topic_for_relationship(&relationship.relationship_id),
            resolve_ip: None,
        },
        mtu: 1200,
    };
    let resolved = config.resolve(relationship).unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(run_async(
        resolved,
        false,
        RuntimeComponents::offline_for_test(),
        shutdown_rx,
    ));
    let mut ready = false;
    for _ in 0..100 {
        if socket_path.exists() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(ready, "injected control socket was not created");

    let response = lzh_hole_control::doctor(&socket_path).await.unwrap();
    let ControlResponse::Doctor { report } = response else {
        panic!("expected doctor response");
    };
    assert_eq!(report.daemon.state, DaemonState::Running);
    assert_eq!(report.ntfy.state, ComponentState::NotConfigured);
    assert_eq!(report.tun.state, ComponentState::NotConfigured);
    assert_eq!(report.routes.state, ComponentState::NotConfigured);

    shutdown_tx.send(true).unwrap();
    timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!socket_path.exists());
}

#[test]
fn automatic_interface_rotation_reaches_a_third_candidate_and_respects_binding() {
    let interfaces = vec![
        physical("en0", 14, Ipv4Addr::new(192, 168, 6, 112)),
        physical("en3", 18, Ipv4Addr::new(192, 168, 7, 113)),
        physical("en7", 26, Ipv4Addr::new(192, 168, 8, 164)),
    ];
    let resolved = resolved_for_test(None);
    let routed = std::collections::BTreeSet::from([14, 18, 26]);
    let mut failures = BTreeMap::new();
    let ordered =
        lifecycle::ordered_physical_interfaces_from(&interfaces, &routed, &resolved, &failures)
            .unwrap();
    assert_eq!(
        ordered
            .iter()
            .map(|item| item.0.as_str())
            .collect::<Vec<_>>(),
        ["en0", "en3", "en7"]
    );

    failures.insert("en0".to_owned(), 1);
    let ordered =
        lifecycle::ordered_physical_interfaces_from(&interfaces, &routed, &resolved, &failures)
            .unwrap();
    assert_eq!(
        ordered
            .iter()
            .map(|item| item.0.as_str())
            .collect::<Vec<_>>(),
        ["en3", "en7", "en0"]
    );
    failures.insert("en3".to_owned(), 1);
    let ordered =
        lifecycle::ordered_physical_interfaces_from(&interfaces, &routed, &resolved, &failures)
            .unwrap();
    assert_eq!(
        ordered
            .iter()
            .map(|item| item.0.as_str())
            .collect::<Vec<_>>(),
        ["en7", "en0", "en3"]
    );

    let mut bound = resolved.clone();
    bound.config.bind_ip = Some(Ipv4Addr::new(192, 168, 8, 164));
    failures.insert("en7".to_owned(), 99);
    let ordered =
        lifecycle::ordered_physical_interfaces_from(&interfaces, &routed, &bound, &failures)
            .unwrap();
    assert_eq!(ordered.len(), 1);
    assert_eq!(ordered[0].0, "en7");

    let explicit = resolved_for_test(Some("en7"));
    let ordered = lifecycle::ordered_physical_interfaces_from(
        &interfaces,
        &std::collections::BTreeSet::new(),
        &explicit,
        &failures,
    )
    .unwrap();
    assert_eq!(ordered.len(), 1);
    assert_eq!(ordered[0].0, "en7");
}

#[test]
fn socket_open_failure_is_recorded_and_tries_the_complete_candidate_list() {
    let candidates = vec![
        ("en0".to_owned(), Ipv4Addr::new(192, 168, 6, 112)),
        ("en3".to_owned(), Ipv4Addr::new(192, 168, 7, 113)),
        ("en7".to_owned(), Ipv4Addr::new(192, 168, 8, 164)),
    ];
    let mut failures = BTreeMap::new();
    let mut attempts = Vec::new();
    let opened = lifecycle::open_in_order(&candidates, &mut failures, |name, _| {
        attempts.push(name.to_owned());
        if name == "en7" {
            Ok(name.to_owned())
        } else {
            Err(format!("simulated open failure on {name}"))
        }
    })
    .unwrap();
    assert_eq!(opened, "en7");
    assert_eq!(attempts, ["en0", "en3", "en7"]);
    assert_eq!(failures.get("en0"), Some(&1));
    assert_eq!(failures.get("en3"), Some(&1));
    assert!(!failures.contains_key("en7"));
}

#[tokio::test(flavor = "current_thread")]
async fn stun_timeout_recovers_only_after_all_servers_fail() {
    let (_temp, mut daemon) = offline_daemon();
    let first = SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 3478);
    let second = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 3478);
    daemon.network_enabled = true;
    daemon.stun = StunState::new(vec![first, second]);
    daemon.stun.in_flight = Some(stun::StunRequest {
        transaction: [1; TRANSACTION_ID_LEN],
        server: first,
        started_at: Instant::now() - STUN_TIMEOUT,
    });
    daemon.maybe_start_stun().await;
    assert_eq!(daemon.stun.consecutive_timeouts, 1);
    assert!(daemon.next_recovery.is_none());

    daemon.stun.in_flight = Some(stun::StunRequest {
        transaction: [2; TRANSACTION_ID_LEN],
        server: second,
        started_at: Instant::now() - STUN_TIMEOUT,
    });
    daemon.maybe_start_stun().await;
    assert_eq!(daemon.stun.consecutive_timeouts, 2);
    let deadline = daemon.next_recovery.expect("recovery must be scheduled");
    assert!(deadline > Instant::now());
}

#[tokio::test(flavor = "current_thread")]
async fn resubscribe_preserves_pending_request_and_retry_schedule() {
    let (_temp, mut daemon) = offline_daemon();
    let id = RequestId::from_hex("07070707070707070707070707070707").unwrap();
    daemon.exchange.register_request(id).unwrap();
    daemon.pending_request = Some(PendingRequest {
        id,
        expires_at_unix_ms: now_unix_ms() + 60_000,
    });
    let next = Instant::now() + Duration::from_secs(300);
    daemon.next_request = next;
    daemon
        .handle_ntfy(NtfyEvent::Subscribed {
            cached_replay: true,
        })
        .await;
    assert_eq!(
        daemon.pending_request.as_ref().map(|pending| pending.id),
        Some(id)
    );
    assert_eq!(daemon.next_request, next);
}

#[tokio::test(flavor = "current_thread")]
async fn budget_block_remains_visible_after_idle_and_publish_failure() {
    let (_temp, mut daemon) = offline_daemon();
    daemon
        .handle_ntfy(NtfyEvent::Error {
            operation: NtfyOperation::Subscribe,
            detail: "ntfy rolling 24 hour operation budget of 128 exhausted".to_owned(),
            retry_after: Some(Duration::from_secs(10_000)),
        })
        .await;
    let deadline = daemon.ntfy_block.as_ref().unwrap().not_before_unix_ms;
    daemon
        .handle_ntfy(NtfyEvent::Error {
            operation: NtfyOperation::Subscribe,
            detail: "ntfy subscription stream: no NDJSON data or keepalive".to_owned(),
            retry_after: Some(Duration::from_secs(9_000)),
        })
        .await;
    let detail = daemon.ntfy_status.detail.as_deref().unwrap();
    assert!(detail.contains("operation budget"), "{detail}");
    assert!(detail.contains("no NDJSON"), "{detail}");
    assert!(detail.contains(&deadline.to_string()), "{detail}");
    daemon
        .handle_ntfy(NtfyEvent::PublishFailed {
            kind: MessageKind::Reply,
            request_id: RequestId::from_hex("09090909090909090909090909090909").unwrap(),
            detail: "discarded while blocked".to_owned(),
        })
        .await;
    let detail = daemon.ntfy_status.detail.as_deref().unwrap();
    assert!(detail.contains("operation budget"), "{detail}");
    assert!(detail.contains("discarded while blocked"), "{detail}");
    assert!(detail.contains(&deadline.to_string()), "{detail}");
}

#[tokio::test(flavor = "current_thread")]
async fn matched_live_reply_schedules_refresh_instead_of_another_immediate_request() {
    let (_temp, mut daemon) = offline_daemon();
    let peer_signing = SigningKey::from_bytes(&[8u8; 32]);
    daemon.resolved.relationship.peer_public_key =
        DiscoveryPublicKey::from_bytes(peer_signing.verifying_key().to_bytes());
    let id = RequestId::from_hex("07070707070707070707070707070707").unwrap();
    daemon.exchange.register_request(id).unwrap();
    daemon.pending_request = Some(PendingRequest {
        id,
        expires_at_unix_ms: now_unix_ms() + MAX_LIFETIME_MS,
    });
    daemon.request_failures = 3;
    let record = contact_record_for(
        &daemon,
        daemon.resolved.relationship.peer_public_key,
        daemon.resolved.relationship.self_public_key,
    );
    let payload = SignedPayload::sign(MessageKind::Reply, id, &record, &peer_signing).unwrap();
    daemon
        .handle_signed_payload(payload, Delivery::Live, "reply-1")
        .await;
    assert!(daemon.pending_request.is_none());
    assert_eq!(daemon.request_failures, 0);
    assert!(daemon.next_request > Instant::now() + Duration::from_secs(44 * 60));
}

#[tokio::test(flavor = "current_thread")]
async fn received_self_reject_and_verified_payload_preserve_the_active_block() {
    let (_temp, mut daemon) = offline_daemon();
    daemon
        .handle_ntfy(NtfyEvent::Error {
            operation: NtfyOperation::Subscribe,
            detail: "ntfy rolling 24 hour operation budget of 128 exhausted".to_owned(),
            retry_after: Some(Duration::from_secs(10_000)),
        })
        .await;
    let deadline = daemon.ntfy_block.as_ref().unwrap().not_before_unix_ms;

    let own_record = contact_record_for(
        &daemon,
        daemon.resolved.relationship.self_public_key,
        daemon.resolved.relationship.peer_public_key,
    );
    let own_payload = SignedPayload::sign(
        MessageKind::Request,
        RequestId::from_hex("01010101010101010101010101010101").unwrap(),
        &own_record,
        &daemon.signing_key.clone(),
    )
    .unwrap();
    daemon
        .handle_ntfy(NtfyEvent::Received {
            payload: own_payload,
            delivery: Delivery::Live,
            ntfy_id: "self-message".to_owned(),
        })
        .await;
    let detail = daemon.ntfy_status.detail.as_deref().unwrap();
    assert!(detail.contains("operation budget"), "{detail}");
    assert!(detail.contains("signed payload rejected"), "{detail}");
    assert!(detail.contains(&deadline.to_string()), "{detail}");

    let peer_signing = SigningKey::from_bytes(&[8u8; 32]);
    daemon.resolved.relationship.peer_public_key =
        DiscoveryPublicKey::from_bytes(peer_signing.verifying_key().to_bytes());
    let peer_record = contact_record_for(
        &daemon,
        daemon.resolved.relationship.peer_public_key,
        daemon.resolved.relationship.self_public_key,
    );
    let peer_payload = SignedPayload::sign(
        MessageKind::Reply,
        RequestId::from_hex("02020202020202020202020202020202").unwrap(),
        &peer_record,
        &peer_signing,
    )
    .unwrap();
    daemon
        .handle_ntfy(NtfyEvent::Received {
            payload: peer_payload,
            delivery: Delivery::Cached,
            ntfy_id: "verified-message".to_owned(),
        })
        .await;
    let detail = daemon.ntfy_status.detail.as_deref().unwrap();
    assert!(detail.contains("operation budget"), "{detail}");
    assert!(detail.contains("verified ntfy message"), "{detail}");
    assert!(detail.contains(&deadline.to_string()), "{detail}");
    assert_eq!(
        daemon.ntfy_block.as_ref().unwrap().not_before_unix_ms,
        deadline
    );
}

#[test]
fn file_pacing_store_distinguishes_missing_and_existing_state() {
    let temp = tempfile::tempdir().unwrap();
    let state = StateDir::open(&temp.path().join("state")).unwrap();
    let path = state.file("ntfy-pacing.json");
    let mut store = FileNtfyPacingStore { path };
    assert!(matches!(store.load().unwrap(), NtfyPacingLoad::Missing));
    store.save(b"snapshot").unwrap();
    assert!(matches!(
        store.load().unwrap(),
        NtfyPacingLoad::Snapshot(bytes) if bytes == b"snapshot"
    ));
}

#[test]
fn request_backoff_is_bounded() {
    assert_eq!(request_retry_delay(1), Duration::from_secs(30));
    assert_eq!(request_retry_delay(2), Duration::from_secs(60));
    assert_eq!(request_retry_delay(16), MAX_REQUEST_RETRY);
    assert_eq!(REQUEST_REFRESH, Duration::from_secs(45 * 60));
}
