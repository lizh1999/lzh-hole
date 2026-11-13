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
        lan: crate::config::LanConfig::default(),
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
    tokio::task::LocalSet::new()
        .run_until(offline_control_roundtrip())
        .await;
}

async fn offline_control_roundtrip() {
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
        lan: crate::config::LanConfig::default(),
        mtu: 1200,
    };
    let resolved = config.resolve(relationship).unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = tokio::task::spawn_local(run_async(
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

#[tokio::test(flavor = "current_thread")]
async fn stun_timeout_does_not_rebuild_the_data_transport() {
    let (_temp, mut daemon) = offline_daemon();
    let first = SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 3478);
    let second = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 3478);
    daemon.engine = Some(
        lifecycle::make_engine(
            &daemon.resolved,
            &Secret32::from_bytes([0x5a; 32]),
            daemon.boot_id,
            daemon.generation,
        )
        .unwrap(),
    );
    daemon.public.add_transport(1, vec![first, second], 0);
    let boot = daemon.boot_id;
    let snapshot = daemon.engine.as_ref().unwrap().snapshot(0);
    daemon.public.start_stun(1, [1; 12], 0).unwrap();
    daemon.public.expire(3_000);
    assert_eq!(daemon.public.consecutive_timeouts(1), Some(1));
    daemon.public.start_stun(1, [2; 12], 8_000).unwrap();
    daemon.public.expire(11_000);
    assert_eq!(daemon.public.consecutive_timeouts(1), Some(2));
    assert_eq!(daemon.engine.as_ref().unwrap().snapshot(0), snapshot);
    assert_eq!(daemon.boot_id, boot);
}

#[test]
fn offline_lan_interfaces_keep_all_ipv4_aliases_and_explicit_limits() {
    let mut home = physical("en0", 14, Ipv4Addr::new(192, 168, 1, 2));
    home.ipv4.push(Ipv4Addr::new(192, 168, 31, 156));
    let interfaces = vec![home];
    let routes = std::collections::BTreeSet::new();
    let failures = BTreeMap::new();
    let mut resolved = resolved_for_test(None);
    let ordered =
        lifecycle::ordered_physical_interfaces_from(&interfaces, &routes, &resolved, &failures)
            .unwrap();
    assert_eq!(
        ordered,
        vec![
            ("en0".to_owned(), Ipv4Addr::new(192, 168, 1, 2)),
            ("en0".to_owned(), Ipv4Addr::new(192, 168, 31, 156)),
        ]
    );
    resolved.config.bind_ip = Some(Ipv4Addr::new(192, 168, 31, 156));
    assert_eq!(
        lifecycle::ordered_physical_interfaces_from(&interfaces, &routes, &resolved, &failures,)
            .unwrap(),
        vec![("en0".to_owned(), Ipv4Addr::new(192, 168, 31, 156))]
    );
    resolved.config.lan.enabled = false;
    assert!(
        lifecycle::ordered_physical_interfaces_from(&interfaces, &routes, &resolved, &failures,)
            .is_err()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn resubscribe_preserves_pending_request_and_retry_schedule() {
    let (_temp, mut daemon) = offline_daemon();
    let id = RequestId::from_hex("07070707070707070707070707070707").unwrap();
    daemon.exchange.register_request(id).unwrap();
    assert!(daemon.public.request_started(
        id,
        now_unix_ms() + 60_000,
        now_unix_ms(),
        daemon.monotonic_ms()
    ));
    let pending = daemon.public.pending_request();
    daemon
        .handle_ntfy(NtfyEvent::Subscribed {
            cached_replay: true,
        })
        .await;
    assert_eq!(
        daemon.public.pending_request().map(|pending| pending.id),
        Some(id)
    );
    assert_eq!(daemon.public.pending_request(), pending);
    assert!(!daemon.public.request_due(daemon.monotonic_ms()));
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
    assert!(daemon.public.request_started(
        id,
        now_unix_ms() + MAX_LIFETIME_MS,
        now_unix_ms(),
        daemon.monotonic_ms()
    ));
    let record = contact_record_for(
        &daemon,
        daemon.resolved.relationship.peer_public_key,
        daemon.resolved.relationship.self_public_key,
    );
    let payload = SignedPayload::sign(MessageKind::Reply, id, &record, &peer_signing).unwrap();
    daemon
        .handle_signed_payload(payload, Delivery::Live, "reply-1")
        .await;
    assert!(daemon.public.pending_request().is_none());
    assert!(
        !daemon
            .public
            .request_due(daemon.monotonic_ms() + 44 * 60_000)
    );
    assert!(
        daemon
            .public
            .request_due(daemon.monotonic_ms() + 46 * 60_000)
    );
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
fn no_interface_engine_remains_diagnosable_without_wan_or_lan_candidates() {
    let resolved = resolved_for_test(None);
    let engine = lifecycle::make_engine(
        &resolved,
        &Secret32::from_bytes([0x5a; 32]),
        BootId::from_bytes([1; 16]),
        1,
    )
    .unwrap();
    assert!(engine.snapshot(0).selected_path.is_none());
    assert!(!engine.snapshot(0).currently_healthy);
    assert!(
        lifecycle::ordered_physical_interfaces_from(
            &[],
            &std::collections::BTreeSet::new(),
            &resolved,
            &BTreeMap::new()
        )
        .is_err()
    );
}

/// Single-process normalized-discovery + engine simulation, not native Bonjour
/// or two-host acceptance. No socket, multicast, HTTP or privileged operation.
#[tokio::test(flavor = "current_thread")]
async fn offline_lan_cold_start_survives_stun_and_ntfy_failure_and_hint_expiry() {
    let (_temp, mut daemon) = offline_daemon();
    let psk = Secret32::from_bytes([0x5a; 32]);
    let mut peer_config = daemon.resolved.clone();
    std::mem::swap(
        &mut peer_config.relationship.self_public_key,
        &mut peer_config.relationship.peer_public_key,
    );
    std::mem::swap(&mut peer_config.self_vip, &mut peer_config.peer_vip);
    let local = Endpoint::new(Ipv4Addr::new(192, 168, 31, 156), 51000);
    let remote = Endpoint::new(Ipv4Addr::new(192, 168, 31, 7), 51000);
    let scope = LanScope {
        interface: 14,
        generation: 1,
    };
    let local_transport = CandidateTransport {
        id: TransportId(1),
        scope,
        local,
    };
    let mut local_engine =
        lifecycle::make_engine(&daemon.resolved, &psk, daemon.boot_id, 1).unwrap();
    let mut peer =
        lifecycle::make_engine(&peer_config, &psk, BootId::from_bytes([3; 16]), 1).unwrap();
    local_engine.set_transports(&[TransportPolicy {
        transport: TransportId(1),
        local_endpoint: local,
        lan_subnets: vec![LanSubnet {
            address: local.ip,
            prefix_len: 24,
        }],
    }]);
    peer.set_transports(&[TransportPolicy {
        transport: TransportId(21),
        local_endpoint: remote,
        lan_subnets: vec![LanSubnet {
            address: remote.ip,
            prefix_len: 24,
        }],
    }]);
    let ad = LanAdvertisement::new(daemon.resolved.relationship.peer_public_key, remote).unwrap();
    let updates = daemon
        .lan
        .observe(
            LanObservation {
                instance: "peer".to_owned(),
                scope,
                addresses: vec![remote.ip],
                port: ad.port,
                txt: ad.txt,
                ttl_ms: 120_000,
            },
            0,
        )
        .unwrap();
    for update in updates {
        daemon.registry.apply(update, &[local_transport]);
    }
    let paths = daemon
        .registry
        .project(&[local_transport], 0, |bound, hint| {
            LanSubnet {
                address: bound.local.ip,
                prefix_len: 24,
            }
            .contains_host(hint.remote.ip)
        });
    assert_eq!(paths.len(), 1);
    local_engine.set_paths(&paths);
    // Only one side discovers the other. The peer has no discovery hints.
    peer.set_paths(&[]);
    daemon.engine = Some(local_engine);
    daemon
        .public
        .add_transport(1, daemon.resolved.config.stun_seeds.clone(), 0);
    daemon.public.start_stun(1, [1; 12], 0).unwrap();
    let start = now_unix_ms();
    let mut now = start;
    for step in 0..200 {
        now = start + step * 250;
        daemon.engine.as_mut().unwrap().tick(now);
        peer.tick(now);
        daemon.public.expire(step * 250);
        for _ in 0..32 {
            let mut progress = false;
            while let Some(frame) = daemon.engine.as_mut().unwrap().next_udp_frame() {
                assert_eq!(frame.transport, TransportId(1));
                peer.handle_datagram_on(TransportId(21), local, &frame.bytes, now);
                progress = true;
            }
            while let Some(frame) = peer.next_udp_frame() {
                assert_eq!(frame.transport, TransportId(21));
                daemon.engine.as_mut().unwrap().handle_datagram_on(
                    TransportId(1),
                    remote,
                    &frame.bytes,
                    now,
                );
                progress = true;
            }
            if !progress {
                break;
            }
        }
        if daemon
            .engine
            .as_ref()
            .unwrap()
            .snapshot(now)
            .currently_healthy
            && peer.snapshot(now).currently_healthy
            && step >= 12
        {
            break;
        }
    }
    let healthy = daemon.engine.as_ref().unwrap().snapshot(now);
    assert!(healthy.currently_healthy);
    assert!(peer.snapshot(now).currently_healthy);
    assert_eq!(daemon.public.consecutive_timeouts(1), Some(1));
    assert!(daemon.public.own_mappings(50_000).is_empty());
    // Enable only the synchronous request decision, not network housekeeping.
    // A due request with a real decoded synthetic STUN mapping must not burn a
    // durable sequence while this established LAN path remains healthy.
    let monotonic = daemon.monotonic_ms();
    daemon
        .public
        .add_transport(2, daemon.resolved.config.stun_seeds.clone(), monotonic);
    let effect = daemon
        .public
        .start_stun(2, [2; 12], monotonic)
        .unwrap()
        .unwrap();
    let mut reply = Vec::new();
    use lzh_hole_discovery::stun::{ATTR_MAPPED_ADDRESS, MAGIC_COOKIE, MSG_BINDING_SUCCESS};
    reply.extend_from_slice(&MSG_BINDING_SUCCESS.to_be_bytes());
    reply.extend_from_slice(&12u16.to_be_bytes());
    reply.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    reply.extend_from_slice(&effect.transaction);
    reply.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
    reply.extend_from_slice(&8u16.to_be_bytes());
    reply.extend_from_slice(&[0, 1]);
    reply.extend_from_slice(&51000u16.to_be_bytes());
    reply.extend_from_slice(&[8, 8, 4, 4]);
    daemon
        .public
        .receive_stun(2, effect.server, &reply, monotonic)
        .unwrap()
        .unwrap();
    daemon.refresh_public_request();
    assert!(daemon.public.request_due(daemon.monotonic_ms()));
    assert!(!daemon.public.own_mappings(daemon.monotonic_ms()).is_empty());
    let sequence = daemon.state.load_sequence().unwrap();
    daemon.network_enabled = true;
    daemon.ntfy_subscribed = true;
    daemon.maybe_queue_request();
    assert_eq!(daemon.state.load_sequence().unwrap(), sequence);
    assert!(daemon.public.pending_request().is_none());
    assert!(
        daemon.public.request_due(daemon.monotonic_ms()),
        "health suppression must leave refresh due"
    );
    daemon.network_enabled = false;
    daemon.ntfy_subscribed = false;
    daemon
        .handle_ntfy(NtfyEvent::Error {
            operation: NtfyOperation::Subscribe,
            detail: "offline".to_owned(),
            retry_after: Some(Duration::from_secs(60)),
        })
        .await;
    assert_eq!(daemon.engine.as_ref().unwrap().snapshot(now), healthy);
    for update in daemon.lan.expire(120_000) {
        daemon.registry.apply(update, &[local_transport]);
    }
    let expired = daemon
        .registry
        .project(&[local_transport], 120_000, |_, _| true);
    assert!(expired.is_empty());
    daemon.engine.as_mut().unwrap().set_paths(&expired);
    assert!(
        daemon
            .engine
            .as_ref()
            .unwrap()
            .snapshot(now)
            .currently_healthy
    );
    assert_eq!(
        daemon.engine.as_ref().unwrap().snapshot(now).selected_path,
        healthy.selected_path
    );
    daemon
        .engine
        .as_mut()
        .unwrap()
        .remove_transport(TransportId(99));
    assert!(
        daemon
            .engine
            .as_ref()
            .unwrap()
            .snapshot(now)
            .currently_healthy
    );
    daemon
        .engine
        .as_mut()
        .unwrap()
        .remove_transport(TransportId(1));
    assert!(
        daemon
            .engine
            .as_ref()
            .unwrap()
            .snapshot(now)
            .selected_path
            .is_none()
    );
}

#[test]
fn publication_mappings_cover_transports_before_older_history_and_remain_bounded() {
    use lzh_hole_discovery::public::PublicMapping;
    let mapping = |transport, port, expires_at_ms| PublicMapping {
        transport,
        endpoint: Endpoint::new(Ipv4Addr::new(8, 8, 4, 4), port),
        expires_at_ms,
    };
    let mut mappings = (0..8)
        .map(|index| mapping(1, 40_000 + index, 100 + u64::from(index)))
        .collect::<Vec<_>>();
    mappings.push(mapping(2, 50_002, 200));
    mappings.push(mapping(3, 50_003, 300));
    let selected = discovery::publication_endpoints(mappings.clone());
    assert_eq!(selected.len(), MAX_OWN_MAPPINGS);
    for (transport, port) in [(1, 40_007), (2, 50_002), (3, 50_003)] {
        assert!(selected.contains(&mapping(transport, port, 0).endpoint));
    }
    // Add five more exits: all eight freshest representatives must fit even
    // though transport 1 alone has enough history to fill the wire record.
    for transport in 4..=8 {
        mappings.push(mapping(transport, 50_000 + transport as u16, 200));
    }
    let selected = discovery::publication_endpoints(mappings.clone());
    assert_eq!(selected.len(), MAX_OWN_MAPPINGS);
    for transport in 2..=8 {
        assert!(selected.contains(&mapping(transport, 50_000 + transport as u16, 0).endpoint));
    }
    assert!(selected.contains(&mapping(1, 40_007, 0).endpoint));
    mappings.reverse();
    assert_eq!(discovery::publication_endpoints(mappings), selected);
    // Duplicate endpoints across transports consume only one wire slot.
    let duplicate = mapping(1, 55_000, 200);
    let deduped = discovery::publication_endpoints(vec![
        duplicate,
        mapping(2, 55_000, 300),
        mapping(2, 55_001, 100),
    ]);
    assert_eq!(
        deduped,
        vec![duplicate.endpoint, mapping(2, 55_001, 0).endpoint]
    );
}
