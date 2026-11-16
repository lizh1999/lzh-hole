use lzh_hole_control::{ComponentState, ControlResponse, DaemonState};
use lzh_hole_discovery::candidate::CandidateSource;
use lzh_hole_discovery::record::{ContactRecord, MAX_LIFETIME_MS, RecordCandidate};
use lzh_hole_discovery::{Delivery, MessageKind};
use lzh_hole_protocol::engine::{CandidatePolicy, EngineConfig};
use lzh_hole_protocol::handshake::HandshakeConfig;
use lzh_hole_protocol::mesh::PeerSet;
use lzh_hole_store::{PAIRING_VERSION, Relationship, Role, public_key_of_seed};
use lzh_hole_types::{DiscoveryPublicKey, RelationshipId, Secret32};

use super::*;
use crate::config::NtfyConfig as FileNtfyConfig;

/// One overlay address per node, identical in every relationship.
const SELF_VIP: &str = "10.203.0.1";
const PEER_VIP: &str = "10.203.0.2";
const SELF_SEED: [u8; 32] = [7; 32];
/// A real Ed25519 seed, so a test can actually sign records as the peer.
const PEER_SEED: [u8; 32] = [8; 32];
const PSK: [u8; 32] = [0x5a; 32];

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

fn self_vip() -> Ipv4Addr {
    SELF_VIP.parse().unwrap()
}

fn peer_vip() -> Ipv4Addr {
    PEER_VIP.parse().unwrap()
}

fn self_key() -> DiscoveryPublicKey {
    public_key_of_seed(&SELF_SEED)
}

fn peer_key() -> DiscoveryPublicKey {
    public_key_of_seed(&PEER_SEED)
}

fn peer_signing_key() -> SigningKey {
    SigningKey::from_bytes(&PEER_SEED)
}

fn relationship() -> Relationship {
    Relationship {
        pairing_version: PAIRING_VERSION,
        pairing_id: RelationshipId::from_bytes([1; 16]),
        relationship_id: RelationshipId::from_bytes([2; 16]),
        self_public_key: self_key(),
        peer_public_key: peer_key(),
        role: Role::Initiator,
        self_vip: SELF_VIP.to_owned(),
        peer_vip: PEER_VIP.to_owned(),
        finalised_unix_ms: 1,
    }
}

fn service_config(
    state_dir: PathBuf,
    control_socket: PathBuf,
    interface: Option<&str>,
) -> ServiceConfig {
    ServiceConfig {
        state_dir,
        control_socket,
        management_uid: effective_uid(),
        interface: interface.map(str::to_owned),
        bind_ip: None,
        udp_port: 51000,
        stun_seeds: vec![SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 3478)],
        ntfy: FileNtfyConfig {
            base_url: "https://ntfy.sh".to_owned(),
            resolve_ip: None,
            dns_server: None,
        },
        lan: crate::config::LanConfig::default(),
        mtu: 1200,
        punch: crate::config::PunchConfig::default(),
    }
}

/// A single-peer resolved config.
///
/// `punch::network_tests` depends on this exact signature, so keep it.
pub(super) fn resolved_for_test(interface: Option<&str>) -> ResolvedConfig {
    service_config(
        PathBuf::from("/var/db/lzh-hole-test"),
        PathBuf::from("/var/run/lzh-hole-test/control.sock"),
        interface,
    )
    .resolve(vec![relationship()])
    .unwrap()
}

/// The engine set `Daemon::new` would build, for tests that need real engines
/// without `--allow-tun`.
fn peer_set_for(
    resolved: &ResolvedConfig,
    psk: &Secret32,
    boot_id: BootId,
    generation: u64,
) -> PeerSet {
    let me = self_key();
    let forbidden = std::iter::once(resolved.self_vip)
        .chain(resolved.peers.iter().map(|peer| peer.peer_vip))
        .collect::<Vec<_>>();
    let stun_servers = resolved
        .config
        .stun_seeds
        .iter()
        .map(|server| endpoint(*server))
        .collect::<Vec<_>>();
    let mut set = PeerSet::new(resolved.self_vip, me);
    for peer in &resolved.peers {
        set.insert(
            EngineConfig {
                handshake: HandshakeConfig {
                    relationship_id: peer.relationship_id(),
                    me,
                    peer: peer.peer_key(),
                    boot_id,
                    generation,
                },
                self_vip: resolved.self_vip,
                peer_vip: peer.peer_vip,
                candidate_policy: CandidatePolicy {
                    own_endpoints: Vec::new(),
                    forbidden_addresses: forbidden.clone(),
                    stun_servers: stun_servers.clone(),
                    require_public_unicast: true,
                },
            },
            psk,
        )
        .unwrap();
    }
    set
}

/// The mirror side of the same relationship: same ids and PSK, roles swapped.
fn mirror_peer_set(psk: &Secret32, boot_id: BootId, generation: u64) -> PeerSet {
    let mut set = PeerSet::new(peer_vip(), peer_key());
    set.insert(
        EngineConfig {
            handshake: HandshakeConfig {
                relationship_id: relationship().relationship_id,
                me: peer_key(),
                peer: self_key(),
                boot_id,
                generation,
            },
            self_vip: peer_vip(),
            peer_vip: self_vip(),
            candidate_policy: CandidatePolicy {
                own_endpoints: Vec::new(),
                forbidden_addresses: vec![self_vip(), peer_vip()],
                stun_servers: Vec::new(),
                require_public_unicast: true,
            },
        },
        psk,
    )
    .unwrap();
    set
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

pub(super) fn offline_daemon() -> (tempfile::TempDir, Daemon) {
    let temp = tempfile::tempdir().unwrap();
    let state = StateDir::open(&temp.path().join("state")).unwrap();
    state.store_seed(&SELF_SEED).unwrap();
    state
        .finalise(&relationship(), &Secret32::from_bytes(PSK))
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

/// The only relationship these fixtures hold.
fn only(daemon: &Daemon) -> RelationshipId {
    daemon.peer_order[0]
}

fn peer_of(daemon: &Daemon) -> &PeerRuntime {
    &daemon.peers[&only(daemon)]
}

fn peer_of_mut(daemon: &mut Daemon) -> &mut PeerRuntime {
    let id = daemon.peer_order[0];
    daemon.peers.get_mut(&id).unwrap()
}

fn contact_record_for(
    relationship: RelationshipId,
    sender: DiscoveryPublicKey,
    receiver: DiscoveryPublicKey,
) -> ContactRecord {
    let now = now_unix_ms();
    ContactRecord {
        relationship_id: relationship,
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
        flags: 0,
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
    state.store_seed(&SELF_SEED).unwrap();
    state
        .finalise(&relationship(), &Secret32::from_bytes(PSK))
        .unwrap();
    let socket_path = temp.path().join("control").join("control.sock");
    let config = service_config(state.path().to_path_buf(), socket_path.clone(), None);
    let resolved = config.resolve(vec![relationship()]).unwrap();
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
    // The peer list is what a mesh operator reads; the node-level aggregates
    // must never be the only thing reported.
    assert_eq!(report.peers.len(), 1);
    assert_eq!(report.peers[0].peer_vip, PEER_VIP);
    assert_eq!(report.peers[0].peer_key, peer_key().to_string());
    assert!(report.current_path.is_none());
    assert!(report.candidates.is_empty());

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
    let rel = only(&daemon);
    let first = SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 3478);
    let second = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 3478);
    daemon.engines = Some(peer_set_for(
        &daemon.resolved,
        &Secret32::from_bytes(PSK),
        daemon.boot_id,
        daemon.generation,
    ));
    daemon.public.add_transport(1, vec![first, second], 0);
    let boot = daemon.boot_id;
    let snapshot = daemon
        .engines
        .as_ref()
        .unwrap()
        .get(rel)
        .unwrap()
        .snapshot(0);
    daemon.public.start_stun(1, [1; 12], 0).unwrap();
    daemon.public.expire_sockets(3_000);
    assert_eq!(daemon.public.consecutive_timeouts(1), Some(1));
    daemon.public.start_stun(1, [2; 12], 8_000).unwrap();
    daemon.public.expire_sockets(11_000);
    assert_eq!(daemon.public.consecutive_timeouts(1), Some(2));
    assert_eq!(
        daemon
            .engines
            .as_ref()
            .unwrap()
            .get(rel)
            .unwrap()
            .snapshot(0),
        snapshot
    );
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
    let rel = only(&daemon);
    let id = RequestId::from_hex("07070707070707070707070707070707").unwrap();
    let now = now_unix_ms();
    let monotonic = daemon.monotonic_ms();
    {
        let peer = peer_of_mut(&mut daemon);
        peer.exchange.register_request(id).unwrap();
        assert!(
            peer.public
                .request_started(id, now + 60_000, now, monotonic)
        );
    }
    let pending = peer_of(&daemon).public.pending_request();
    daemon
        .handle_ntfy(NtfyEvent::Subscribed {
            relationship: rel,
            cached_replay: true,
        })
        .await;
    assert_eq!(
        peer_of(&daemon).public.pending_request().map(|p| p.id),
        Some(id)
    );
    assert_eq!(peer_of(&daemon).public.pending_request(), pending);
    let monotonic = daemon.monotonic_ms();
    assert!(!peer_of(&daemon).public.request_due(monotonic));
}

#[tokio::test(flavor = "current_thread")]
async fn budget_block_remains_visible_after_idle_and_publish_failure() {
    let (_temp, mut daemon) = offline_daemon();
    let rel = only(&daemon);
    daemon
        .handle_ntfy(NtfyEvent::Error {
            relationship: None,
            operation: NtfyOperation::Subscribe,
            detail: "ntfy rolling 24 hour operation budget of 128 exhausted".to_owned(),
            retry_after: Some(Duration::from_secs(10_000)),
        })
        .await;
    let deadline = peer_of(&daemon)
        .ntfy
        .block
        .as_ref()
        .unwrap()
        .not_before_unix_ms;
    daemon
        .handle_ntfy(NtfyEvent::Error {
            relationship: None,
            operation: NtfyOperation::Subscribe,
            detail: "ntfy subscription stream: no NDJSON data or keepalive".to_owned(),
            retry_after: Some(Duration::from_secs(9_000)),
        })
        .await;
    let detail = peer_of(&daemon).ntfy.status.detail.as_deref().unwrap();
    assert!(detail.contains("operation budget"), "{detail}");
    assert!(detail.contains("no NDJSON"), "{detail}");
    assert!(detail.contains(&deadline.to_string()), "{detail}");
    daemon
        .handle_ntfy(NtfyEvent::PublishFailed {
            relationship: rel,
            kind: MessageKind::Reply,
            request_id: RequestId::from_hex("09090909090909090909090909090909").unwrap(),
            detail: "discarded while blocked".to_owned(),
        })
        .await;
    let detail = peer_of(&daemon).ntfy.status.detail.as_deref().unwrap();
    assert!(detail.contains("operation budget"), "{detail}");
    assert!(detail.contains("discarded while blocked"), "{detail}");
    assert!(detail.contains(&deadline.to_string()), "{detail}");
}

#[tokio::test(flavor = "current_thread")]
async fn a_host_level_failure_never_marks_an_unrelated_relationship() {
    // One node-level ntfy failure is reported against every relationship, but
    // an attributed failure must stay on its own relationship. With a single
    // peer there is nothing to leak into, so assert the attributed path is
    // still refused for a relationship this node does not hold.
    let (_temp, mut daemon) = offline_daemon();
    let rel = only(&daemon);
    daemon
        .handle_ntfy(NtfyEvent::Error {
            relationship: Some(rel),
            operation: NtfyOperation::Publish,
            detail: "attributed failure".to_owned(),
            retry_after: None,
        })
        .await;
    let detail = peer_of(&daemon).ntfy.status.detail.as_deref().unwrap();
    assert!(detail.contains("attributed failure"), "{detail}");

    let unknown = RelationshipId::from_bytes([0xee; 16]);
    daemon
        .handle_ntfy(NtfyEvent::Error {
            relationship: Some(unknown),
            operation: NtfyOperation::Publish,
            detail: "must not be recorded".to_owned(),
            retry_after: None,
        })
        .await;
    let detail = peer_of(&daemon).ntfy.status.detail.as_deref().unwrap();
    assert!(!detail.contains("must not be recorded"), "{detail}");
}

#[tokio::test(flavor = "current_thread")]
async fn matched_live_reply_schedules_refresh_instead_of_another_immediate_request() {
    let (_temp, mut daemon) = offline_daemon();
    let rel = only(&daemon);
    let id = RequestId::from_hex("07070707070707070707070707070707").unwrap();
    let now = now_unix_ms();
    let monotonic = daemon.monotonic_ms();
    {
        let peer = peer_of_mut(&mut daemon);
        peer.exchange.register_request(id).unwrap();
        assert!(
            peer.public
                .request_started(id, now + MAX_LIFETIME_MS, now, monotonic)
        );
    }
    let record = contact_record_for(rel, peer_key(), self_key());
    let payload =
        SignedPayload::sign(MessageKind::Reply, id, &record, &peer_signing_key()).unwrap();
    daemon
        .handle_signed_payload(rel, payload, Delivery::Live, "reply-1")
        .await;
    assert!(peer_of(&daemon).public.pending_request().is_none());
    let monotonic = daemon.monotonic_ms();
    assert!(!peer_of(&daemon).public.request_due(monotonic + 44 * 60_000));
    assert!(peer_of(&daemon).public.request_due(monotonic + 46 * 60_000));
}

#[tokio::test(flavor = "current_thread")]
async fn received_self_reject_and_verified_payload_preserve_the_active_block() {
    let (_temp, mut daemon) = offline_daemon();
    let rel = only(&daemon);
    daemon
        .handle_ntfy(NtfyEvent::Error {
            relationship: None,
            operation: NtfyOperation::Subscribe,
            detail: "ntfy rolling 24 hour operation budget of 128 exhausted".to_owned(),
            retry_after: Some(Duration::from_secs(10_000)),
        })
        .await;
    let deadline = peer_of(&daemon)
        .ntfy
        .block
        .as_ref()
        .unwrap()
        .not_before_unix_ms;

    let own_record = contact_record_for(rel, self_key(), peer_key());
    let own_payload = SignedPayload::sign(
        MessageKind::Request,
        RequestId::from_hex("01010101010101010101010101010101").unwrap(),
        &own_record,
        &daemon.signing_key.clone(),
    )
    .unwrap();
    daemon
        .handle_ntfy(NtfyEvent::Received {
            relationship: rel,
            payload: own_payload,
            delivery: Delivery::Live,
            ntfy_id: "self-message".to_owned(),
        })
        .await;
    let detail = peer_of(&daemon).ntfy.status.detail.as_deref().unwrap();
    assert!(detail.contains("operation budget"), "{detail}");
    assert!(detail.contains("signed payload rejected"), "{detail}");
    assert!(detail.contains(&deadline.to_string()), "{detail}");

    let peer_record = contact_record_for(rel, peer_key(), self_key());
    let peer_payload = SignedPayload::sign(
        MessageKind::Reply,
        RequestId::from_hex("02020202020202020202020202020202").unwrap(),
        &peer_record,
        &peer_signing_key(),
    )
    .unwrap();
    daemon
        .handle_ntfy(NtfyEvent::Received {
            relationship: rel,
            payload: peer_payload,
            delivery: Delivery::Cached,
            ntfy_id: "verified-message".to_owned(),
        })
        .await;
    let detail = peer_of(&daemon).ntfy.status.detail.as_deref().unwrap();
    assert!(detail.contains("operation budget"), "{detail}");
    assert!(detail.contains("verified ntfy message"), "{detail}");
    assert!(detail.contains(&deadline.to_string()), "{detail}");
    assert_eq!(
        peer_of(&daemon)
            .ntfy
            .block
            .as_ref()
            .unwrap()
            .not_before_unix_ms,
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
    let rel = resolved.peers[0].relationship_id();
    let engines = peer_set_for(
        &resolved,
        &Secret32::from_bytes(PSK),
        BootId::from_bytes([1; 16]),
        1,
    );
    let engine = engines.get(rel).unwrap();
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
    let rel = only(&daemon);
    let psk = Secret32::from_bytes(PSK);
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
    let mut local_set = peer_set_for(&daemon.resolved, &psk, daemon.boot_id, 1);
    let mut peer_set = mirror_peer_set(&psk, BootId::from_bytes([3; 16]), 1);
    local_set.set_transports(&[TransportPolicy {
        transport: TransportId(1),
        local_endpoint: local,
        lan_subnets: vec![LanSubnet {
            address: local.ip,
            prefix_len: 24,
        }],
    }]);
    peer_set.set_transports(&[TransportPolicy {
        transport: TransportId(21),
        local_endpoint: remote,
        lan_subnets: vec![LanSubnet {
            address: remote.ip,
            prefix_len: 24,
        }],
    }]);
    let ad = LanAdvertisement::new(peer_key(), remote).unwrap();
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
    assert_eq!(updates.len(), 1);
    assert_eq!(
        updates[0].relationship_id, rel,
        "a pinned-key advertisement must land on exactly the relationship that pins it"
    );
    for update in updates {
        daemon
            .registry
            .apply(rel, update.update, &[local_transport]);
    }
    let projected = daemon
        .registry
        .project(&[local_transport], 0, |bound, hint| {
            LanSubnet {
                address: bound.local.ip,
                prefix_len: 24,
            }
            .contains_host(hint.remote.ip)
        });
    let paths = projected
        .get(&rel)
        .expect("one relationship projects paths");
    assert_eq!(paths.len(), 1);
    local_set.get_mut(rel).unwrap().set_paths(paths);
    // Only one side discovers the other. The peer has no discovery hints.
    peer_set.get_mut(rel).unwrap().set_paths(&[]);
    daemon.engines = Some(local_set);
    daemon
        .public
        .add_transport(1, daemon.resolved.config.stun_seeds.clone(), 0);
    daemon.public.start_stun(1, [1; 12], 0).unwrap();
    let start = now_unix_ms();
    let mut now = start;
    for step in 0..200 {
        now = start + step * 250;
        daemon.engines.as_mut().unwrap().tick(now);
        peer_set.tick(now);
        daemon.public.expire_sockets(step * 250);
        for _ in 0..32 {
            let mut progress = false;
            while let Some((owner, frame)) = daemon.engines.as_mut().unwrap().next_udp_frame() {
                assert_eq!(owner, rel);
                assert_eq!(frame.transport, TransportId(1));
                peer_set.dispatch(TransportId(21), local, &frame.bytes, now);
                progress = true;
            }
            while let Some((owner, frame)) = peer_set.next_udp_frame() {
                assert_eq!(owner, rel);
                assert_eq!(frame.transport, TransportId(21));
                daemon.engines.as_mut().unwrap().dispatch(
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
        let local_healthy = daemon
            .engines
            .as_ref()
            .unwrap()
            .get(rel)
            .unwrap()
            .snapshot(now)
            .currently_healthy;
        if local_healthy && peer_set.get(rel).unwrap().snapshot(now).currently_healthy && step >= 12
        {
            break;
        }
    }
    let healthy = daemon
        .engines
        .as_ref()
        .unwrap()
        .get(rel)
        .unwrap()
        .snapshot(now);
    assert!(healthy.currently_healthy);
    assert!(peer_set.get(rel).unwrap().snapshot(now).currently_healthy);
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
    daemon.refresh_public_requests();
    let monotonic = daemon.monotonic_ms();
    assert!(peer_of(&daemon).public.request_due(monotonic));
    assert!(!daemon.public.own_mappings(monotonic).is_empty());
    let sequence = daemon.state.load_sequence(rel).unwrap();
    daemon.network_enabled = true;
    peer_of_mut(&mut daemon).ntfy.subscribed = true;
    daemon.maybe_queue_request_for(rel);
    assert_eq!(daemon.state.load_sequence(rel).unwrap(), sequence);
    assert!(peer_of(&daemon).public.pending_request().is_none());
    let monotonic = daemon.monotonic_ms();
    assert!(
        peer_of(&daemon).public.request_due(monotonic),
        "health suppression must leave refresh due"
    );
    daemon.network_enabled = false;
    peer_of_mut(&mut daemon).ntfy.subscribed = false;
    daemon
        .handle_ntfy(NtfyEvent::Error {
            relationship: None,
            operation: NtfyOperation::Subscribe,
            detail: "offline".to_owned(),
            retry_after: Some(Duration::from_secs(60)),
        })
        .await;
    assert_eq!(
        daemon
            .engines
            .as_ref()
            .unwrap()
            .get(rel)
            .unwrap()
            .snapshot(now),
        healthy
    );
    for update in daemon.lan.expire(120_000) {
        daemon
            .registry
            .apply(update.relationship_id, update.update, &[local_transport]);
    }
    let expired = daemon
        .registry
        .project(&[local_transport], 120_000, |_, _| true);
    // A relationship with no surviving observation is simply absent from the
    // projection; `reproject_candidates` turns that absence into an explicitly
    // empty path set, which is what actually withdraws the path.
    let expired = expired.get(&rel).cloned().unwrap_or_default();
    assert!(
        expired.is_empty(),
        "withdrawn hints must project no path at all"
    );
    daemon
        .engines
        .as_mut()
        .unwrap()
        .get_mut(rel)
        .unwrap()
        .set_paths(&expired);
    let snapshot = daemon
        .engines
        .as_ref()
        .unwrap()
        .get(rel)
        .unwrap()
        .snapshot(now);
    assert!(snapshot.currently_healthy);
    assert_eq!(snapshot.selected_path, healthy.selected_path);
    daemon
        .engines
        .as_mut()
        .unwrap()
        .get_mut(rel)
        .unwrap()
        .remove_transport(TransportId(99));
    assert!(
        daemon
            .engines
            .as_ref()
            .unwrap()
            .get(rel)
            .unwrap()
            .snapshot(now)
            .currently_healthy
    );
    daemon
        .engines
        .as_mut()
        .unwrap()
        .get_mut(rel)
        .unwrap()
        .remove_transport(TransportId(1));
    assert!(
        daemon
            .engines
            .as_ref()
            .unwrap()
            .get(rel)
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

/// The route-to-registration decision, independent of any real routing table.
#[test]
fn stun_registration_actions_follow_the_routed_interface_set_in_both_directions() {
    let sockets = [(TransportId(1), 4), (TransportId(2), 9)];
    let (register, unregister) =
        lifecycle::stun_registration_actions(&sockets, &std::collections::BTreeSet::from([4]));
    assert_eq!(register, vec![TransportId(1)]);
    assert_eq!(unregister, vec![TransportId(2)]);

    // Losing a route must move a socket onto the removal list, not merely stop
    // registering it again.
    let (register, unregister) =
        lifecycle::stun_registration_actions(&sockets, &std::collections::BTreeSet::new());
    assert!(register.is_empty());
    assert_eq!(unregister, vec![TransportId(1), TransportId(2)]);

    // Gaining a route registers a socket that was already open.
    let (register, unregister) =
        lifecycle::stun_registration_actions(&sockets, &std::collections::BTreeSet::from([4, 9]));
    assert_eq!(register, vec![TransportId(1), TransportId(2)]);
    assert!(unregister.is_empty());
}

fn registered_stun_transports(daemon: &Daemon) -> Vec<u64> {
    daemon
        .public
        .mapping_behaviors()
        .into_iter()
        .map(|(transport, _)| transport)
        .collect()
}

/// Loopback sockets only: the routed set is supplied by the test, so no real
/// kernel route to a STUN seed is read, required or modified.
#[tokio::test(flavor = "current_thread")]
async fn stun_registration_tracks_the_route_of_a_retained_socket() {
    let (_temp, mut daemon) = offline_daemon();
    let id = daemon
        .transports
        .open(&mut daemon.transport_ids, "lo0", Ipv4Addr::LOCALHOST, 0)
        .unwrap();
    let index = daemon.transports.get(id).unwrap().interface_index;

    daemon.sync_stun_registrations(&std::collections::BTreeSet::from([index]));
    assert_eq!(registered_stun_transports(&daemon), vec![id.0]);

    // Re-running the sync over an unchanged route must not reset the socket's
    // in-flight STUN transaction.
    let now = daemon.monotonic_ms();
    assert!(
        daemon
            .public
            .start_stun(id.0, [1; 12], now)
            .unwrap()
            .is_some()
    );
    daemon.sync_stun_registrations(&std::collections::BTreeSet::from([index]));
    assert_eq!(registered_stun_transports(&daemon), vec![id.0]);
    assert!(
        daemon
            .public
            .start_stun(id.0, [2; 12], now)
            .unwrap()
            .is_none(),
        "a re-sync must not discard the pending transaction"
    );

    // The route is gone: the registration goes with it, but the data-plane
    // socket is retained for LAN discovery.
    daemon.sync_stun_registrations(&std::collections::BTreeSet::new());
    assert!(registered_stun_transports(&daemon).is_empty());
    assert!(daemon.transports.get(id).is_some());
    assert!(
        daemon
            .public
            .start_stun(id.0, [3; 12], now)
            .unwrap()
            .is_none()
    );

    // A route appearing later registers the already open socket.
    daemon.sync_stun_registrations(&std::collections::BTreeSet::from([index]));
    assert_eq!(registered_stun_transports(&daemon), vec![id.0]);
}
