use super::*;

/// Best-to-worst severity ladder used by the aggregate session rule.
const SEVERITY_LADDER: [ComponentState; 7] = [
    ComponentState::Healthy,
    ComponentState::NotConfigured,
    ComponentState::Stopped,
    ComponentState::Unknown,
    ComponentState::Starting,
    ComponentState::Degraded,
    ComponentState::Failed,
];

fn peer_with_state(state: ComponentState) -> PeerStatus {
    PeerStatus {
        relationship_id: "0".repeat(32),
        peer_vip: "10.99.0.2".to_owned(),
        peer_key: "ab".repeat(32),
        role: "initiator".to_owned(),
        session: ComponentStatus {
            state,
            ..ComponentStatus::default()
        },
        ..PeerStatus::default()
    }
}

fn peer_with_overlay(
    direct_reachable: Option<bool>,
    currently_healthy: Option<bool>,
) -> PeerStatus {
    PeerStatus {
        overlay: OverlayHealth {
            direct_reachable,
            currently_healthy,
            detail: None,
        },
        ..peer_with_state(ComponentState::Healthy)
    }
}

fn candidate(index: usize) -> CandidateStatus {
    CandidateStatus {
        origin: DiscoveryOrigin::Lan,
        transport_id: 7,
        remote_endpoint: format!("192.0.2.{index}:41641"),
    }
}

fn snapshot_with_peers(peers: Vec<PeerStatus>) -> ServiceSnapshot {
    let mut snapshot = ServiceSnapshot::starting(4242, 1_000);
    assert!(snapshot.set_peers(peers));
    snapshot
}

#[test]
fn partial_health_never_reports_healthy() {
    let mut snapshot = ServiceSnapshot::default();

    assert!(snapshot.set_peers(vec![
        peer_with_overlay(Some(true), Some(true)),
        peer_with_overlay(Some(true), Some(true)),
        peer_with_overlay(Some(false), Some(false)),
    ]));
    assert_eq!(snapshot.overlay.direct_reachable, Some(false));
    assert_eq!(snapshot.overlay.currently_healthy, Some(false));

    assert!(snapshot.set_peers(vec![
        peer_with_overlay(Some(true), Some(true)),
        peer_with_overlay(Some(true), Some(true)),
        peer_with_overlay(None, None),
    ]));
    assert_eq!(snapshot.overlay.direct_reachable, None);
    assert_eq!(snapshot.overlay.currently_healthy, None);

    assert!(snapshot.set_peers(vec![
        peer_with_overlay(Some(true), Some(true)),
        peer_with_overlay(Some(true), Some(true)),
        peer_with_overlay(Some(true), Some(true)),
    ]));
    assert_eq!(snapshot.overlay.direct_reachable, Some(true));
    assert_eq!(snapshot.overlay.currently_healthy, Some(true));

    // A single negative peer must dominate even when the rest are healthy.
    assert!(snapshot.set_peers(vec![
        peer_with_overlay(Some(true), Some(true)),
        peer_with_overlay(Some(false), Some(true)),
        peer_with_overlay(Some(true), None),
    ]));
    assert_eq!(snapshot.overlay.direct_reachable, Some(false));
    assert_eq!(snapshot.overlay.currently_healthy, None);
}

#[test]
fn empty_peer_list_is_refused_and_keeps_previous_aggregates() {
    let mut snapshot = snapshot_with_peers(vec![
        peer_with_overlay(Some(true), Some(true)),
        peer_with_overlay(Some(false), Some(false)),
    ]);
    let before = snapshot.clone();

    assert!(!snapshot.set_peers(Vec::new()));
    assert_eq!(snapshot, before);
    assert_eq!(snapshot.overlay.direct_reachable, Some(false));
    assert_eq!(snapshot.peers.len(), 2);

    // Refusing an empty list must never reset aggregates to a healthy-looking
    // default either.
    let mut fresh = ServiceSnapshot::default();
    assert!(!fresh.set_peers(Vec::new()));
    assert_eq!(fresh.overlay.direct_reachable, None);
    assert_eq!(fresh.overlay.currently_healthy, None);
    assert_eq!(fresh.session.state, ComponentState::Unknown);
    assert!(fresh.peers.is_empty());
}

#[test]
fn session_state_takes_the_worst_peer() {
    for (index, state) in SEVERITY_LADDER.iter().enumerate() {
        let snapshot = snapshot_with_peers(vec![
            peer_with_state(ComponentState::Healthy),
            peer_with_state(*state),
        ]);
        assert_eq!(snapshot.session.state, *state, "pair with {state:?}");

        let prefix: Vec<PeerStatus> = SEVERITY_LADDER[..=index]
            .iter()
            .map(|state| peer_with_state(*state))
            .collect();
        let snapshot = snapshot_with_peers(prefix);
        assert_eq!(snapshot.session.state, *state, "prefix ending at {state:?}");
    }

    // Unmeasured must never be laundered into healthy.
    let snapshot = snapshot_with_peers(vec![
        peer_with_state(ComponentState::Healthy),
        peer_with_state(ComponentState::Unknown),
    ]);
    assert_eq!(snapshot.session.state, ComponentState::Unknown);

    let snapshot = snapshot_with_peers(vec![
        peer_with_state(ComponentState::Healthy),
        peer_with_state(ComponentState::Failed),
    ]);
    assert_eq!(snapshot.session.state, ComponentState::Failed);

    let snapshot = snapshot_with_peers(vec![
        peer_with_state(ComponentState::Degraded),
        peer_with_state(ComponentState::Stopped),
        peer_with_state(ComponentState::NotConfigured),
    ]);
    assert_eq!(snapshot.session.state, ComponentState::Degraded);
}

#[test]
fn session_detail_reports_peer_counts_and_per_peer_path() {
    let snapshot = snapshot_with_peers(vec![
        peer_with_state(ComponentState::Healthy),
        peer_with_state(ComponentState::Degraded),
        peer_with_state(ComponentState::Healthy),
    ]);
    let detail = snapshot.session.detail.expect("aggregate detail");
    assert!(detail.contains("3 peers"), "{detail}");
    assert!(detail.contains("2/3 healthy"), "{detail}");
    assert!(detail.contains("degraded"), "{detail}");

    let overlay_detail = snapshot.overlay.detail.expect("aggregate overlay detail");
    assert!(overlay_detail.contains("3 peers"), "{overlay_detail}");
    assert!(
        overlay_detail.contains("current_path is per-peer"),
        "{overlay_detail}"
    );
}

#[test]
fn session_timestamps_take_the_maximum() {
    let mut first = peer_with_state(ComponentState::Healthy);
    first.session.last_success_unix_ms = Some(10);
    first.session.last_change_unix_ms = Some(90);
    let mut second = peer_with_state(ComponentState::Degraded);
    second.session.last_success_unix_ms = Some(50);
    second.session.last_change_unix_ms = Some(20);
    let third = peer_with_state(ComponentState::Healthy);

    let snapshot = snapshot_with_peers(vec![first, second, third]);
    assert_eq!(snapshot.session.last_success_unix_ms, Some(50));
    assert_eq!(snapshot.session.last_change_unix_ms, Some(90));

    let snapshot = snapshot_with_peers(vec![
        peer_with_state(ComponentState::Healthy),
        peer_with_state(ComponentState::Unknown),
    ]);
    assert_eq!(snapshot.session.last_success_unix_ms, None);
    assert_eq!(snapshot.session.last_change_unix_ms, None);
}

#[test]
fn node_level_path_and_candidates_stay_empty() {
    let mut snapshot = ServiceSnapshot {
        current_path: Some(CurrentPathStatus {
            transport_id: 1,
            interface: "en0".to_owned(),
            local_endpoint: "192.0.2.1:41641".to_owned(),
            remote_endpoint: "198.51.100.7:41641".to_owned(),
            kind: DiscoveryOrigin::Public,
        }),
        candidates: vec![candidate(1)],
        ..ServiceSnapshot::default()
    };

    let mut peer = peer_with_state(ComponentState::Healthy);
    peer.current_path = Some(CurrentPathStatus {
        transport_id: 2,
        interface: "en0".to_owned(),
        local_endpoint: "192.0.2.1:41642".to_owned(),
        remote_endpoint: "198.51.100.8:41641".to_owned(),
        kind: DiscoveryOrigin::Lan,
    });
    peer.candidates = vec![candidate(2), candidate(3)];

    assert!(snapshot.set_peers(vec![peer]));
    assert!(snapshot.current_path.is_none());
    assert!(snapshot.candidates.is_empty());
    assert!(snapshot.peers[0].current_path.is_some());
    assert_eq!(snapshot.peers[0].candidates.len(), 2);
}

#[test]
fn peer_and_candidate_bounds_are_enforced() {
    let mut snapshot = snapshot_with_peers(vec![
        peer_with_state(ComponentState::Healthy),
        peer_with_state(ComponentState::Degraded),
    ]);
    let before = snapshot.clone();

    let too_many: Vec<PeerStatus> = (0..=MAX_PEERS_IN_SNAPSHOT)
        .map(|_| peer_with_state(ComponentState::Healthy))
        .collect();
    assert_eq!(too_many.len(), MAX_PEERS_IN_SNAPSHOT + 1);
    assert!(!snapshot.set_peers(too_many));
    assert_eq!(snapshot, before);

    let exact: Vec<PeerStatus> = (0..MAX_PEERS_IN_SNAPSHOT)
        .map(|_| peer_with_state(ComponentState::Healthy))
        .collect();
    assert!(snapshot.set_peers(exact));
    assert_eq!(snapshot.peers.len(), MAX_PEERS_IN_SNAPSHOT);

    let mut peer = peer_with_state(ComponentState::Healthy);
    peer.candidates = (0..MAX_CANDIDATES_PER_PEER + 5).map(candidate).collect();
    assert!(snapshot.set_peers(vec![peer]));
    assert_eq!(snapshot.peers[0].candidates.len(), MAX_CANDIDATES_PER_PEER);
    assert_eq!(
        snapshot.peers[0].candidates[MAX_CANDIDATES_PER_PEER - 1].remote_endpoint,
        candidate(MAX_CANDIDATES_PER_PEER - 1).remote_endpoint,
    );
}

#[test]
fn rejected_set_peers_leaves_every_field_untouched() {
    let mut snapshot = snapshot_with_peers(vec![
        peer_with_overlay(Some(true), Some(true)),
        peer_with_overlay(Some(false), None),
    ]);
    snapshot.updated_unix_ms = 12_345;
    snapshot.daemon.state = DaemonState::Running;
    let before = snapshot.clone();

    assert!(!snapshot.set_peers(Vec::new()));
    assert!(
        !snapshot.set_peers(
            (0..=MAX_PEERS_IN_SNAPSHOT)
                .map(|_| peer_with_state(ComponentState::Healthy))
                .collect()
        )
    );

    assert_eq!(snapshot.peers, before.peers);
    assert_eq!(snapshot.session, before.session);
    assert_eq!(snapshot.overlay, before.overlay);
    assert_eq!(snapshot.current_path, before.current_path);
    assert_eq!(snapshot.candidates, before.candidates);
    assert_eq!(snapshot.daemon, before.daemon);
    assert_eq!(snapshot.updated_unix_ms, before.updated_unix_ms);
    assert_eq!(snapshot, before);
}

#[test]
fn set_peers_leaves_unrelated_node_fields_alone() {
    let mut snapshot = ServiceSnapshot::starting(99, 500);
    snapshot.mark_daemon_running(600);
    snapshot.ntfy.state = ComponentState::Healthy;
    snapshot.tun.state = ComponentState::Degraded;
    snapshot.bytes.udp_rx = 17;
    assert!(snapshot.drops.record("bad_mac", 3));
    snapshot.discovery.accepted_updates = 4;
    snapshot.punch.state = "probing".to_owned();

    assert!(snapshot.set_peers(vec![peer_with_state(ComponentState::Healthy)]));

    assert_eq!(snapshot.daemon.state, DaemonState::Running);
    assert_eq!(snapshot.daemon.pid, Some(99));
    assert_eq!(snapshot.ntfy.state, ComponentState::Healthy);
    assert_eq!(snapshot.tun.state, ComponentState::Degraded);
    assert_eq!(snapshot.bytes.udp_rx, 17);
    assert_eq!(snapshot.drops.total, 3);
    assert_eq!(snapshot.discovery.accepted_updates, 4);
    assert_eq!(snapshot.punch.state, "probing");
    assert_eq!(snapshot.updated_unix_ms, 600);
}

#[test]
fn snapshot_with_peers_round_trips_and_rejects_unknown_fields() {
    let mut peer = peer_with_state(ComponentState::Degraded);
    peer.session.last_success_unix_ms = Some(7);
    peer.ntfy.state = ComponentState::Healthy;
    peer.current_path = Some(CurrentPathStatus {
        transport_id: 3,
        interface: "en0".to_owned(),
        local_endpoint: "192.0.2.1:41641".to_owned(),
        remote_endpoint: "198.51.100.9:41641".to_owned(),
        kind: DiscoveryOrigin::Public,
    });
    peer.candidates = vec![candidate(4)];
    peer.punch.state = "probing".to_owned();
    peer.bytes.udp_tx = 11;
    assert!(peer.drops.record("route_missing", 2));

    let snapshot = snapshot_with_peers(vec![peer, peer_with_state(ComponentState::Healthy)]);
    let json = serde_json::to_string(&snapshot).unwrap();
    let decoded: ServiceSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, snapshot);

    let mut value = serde_json::to_value(&snapshot).unwrap();
    value["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ServiceSnapshot>(value).is_err());

    let mut peer_value = serde_json::to_value(&snapshot.peers[0]).unwrap();
    peer_value["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PeerStatus>(peer_value).is_err());
}

/// A saturated doctor response must still fit one bounded control line.
///
/// The frame limit, `MAX_PEERS_IN_SNAPSHOT`, `MAX_CANDIDATES_PER_PEER` and the
/// drop-reason bounds are four independent constants. Nothing but this test
/// stops them from drifting into a combination where a fully populated daemon
/// answers `doctor` with a line the server itself refuses to send, which would
/// silently degrade into a generic internal error at the worst moment.
#[test]
fn a_saturated_snapshot_fits_one_control_line() {
    fn detail() -> Option<String> {
        Some("d".repeat(256))
    }

    fn component(state: ComponentState) -> ComponentStatus {
        ComponentStatus {
            state,
            detail: detail(),
            last_success_unix_ms: Some(u64::MAX),
            last_change_unix_ms: Some(u64::MAX),
        }
    }

    fn saturated_drops() -> DropCounters {
        let mut drops = DropCounters::default();
        for index in 0..MAX_DROP_REASONS {
            let reason = format!("{index:0width$}", width = MAX_DROP_REASON_BYTES);
            assert_eq!(reason.len(), MAX_DROP_REASON_BYTES);
            assert!(drops.record(&reason, u64::MAX));
        }
        assert_eq!(drops.reasons.len(), MAX_DROP_REASONS);
        drops
    }

    fn saturated_punch() -> PunchStatus {
        PunchStatus {
            state: "s".repeat(32),
            role: Some("r".repeat(32)),
            local_mapping: "m".repeat(32),
            peer_mapping: "m".repeat(32),
            blocked_by: Some("b".repeat(64)),
            last_failure: Some("f".repeat(64)),
            probes_sent: u64::MAX,
            sockets_open: u16::MAX,
            hit_port: Some(u16::MAX),
            started_unix_ms: Some(u64::MAX),
        }
    }

    fn saturated_bytes() -> ByteCounters {
        ByteCounters {
            udp_rx: u64::MAX,
            udp_tx: u64::MAX,
            tun_rx: u64::MAX,
            tun_tx: u64::MAX,
        }
    }

    let peers: Vec<PeerStatus> = (0..MAX_PEERS_IN_SNAPSHOT)
        .map(|index| PeerStatus {
            relationship_id: format!("{index:032x}"),
            peer_vip: "255.255.255.255".to_owned(),
            peer_key: "f".repeat(64),
            role: "responder".to_owned(),
            session: component(ComponentState::Degraded),
            overlay: OverlayHealth {
                direct_reachable: Some(true),
                currently_healthy: Some(true),
                detail: detail(),
            },
            ntfy: component(ComponentState::Degraded),
            current_path: Some(CurrentPathStatus {
                transport_id: u64::MAX,
                // macOS caps an interface name at IFNAMSIZ - 1 = 15 bytes.
                interface: "i".repeat(15),
                local_endpoint: "255.255.255.255:65535".to_owned(),
                remote_endpoint: "255.255.255.255:65535".to_owned(),
                kind: DiscoveryOrigin::Public,
            }),
            candidates: (0..MAX_CANDIDATES_PER_PEER)
                .map(|_| CandidateStatus {
                    origin: DiscoveryOrigin::Public,
                    transport_id: u64::MAX,
                    remote_endpoint: "255.255.255.255:65535".to_owned(),
                })
                .collect(),
            punch: saturated_punch(),
            bytes: saturated_bytes(),
            drops: saturated_drops(),
        })
        .collect();

    let mut snapshot = ServiceSnapshot::starting(u32::MAX, u64::MAX);
    snapshot.mark_daemon_running(u64::MAX);
    snapshot.daemon.detail = detail();
    snapshot.ntfy = component(ComponentState::Degraded);
    snapshot.lan = component(ComponentState::Degraded);
    snapshot.stun = component(ComponentState::Degraded);
    snapshot.tun = component(ComponentState::Degraded);
    snapshot.routes = component(ComponentState::Degraded);
    snapshot.bytes = saturated_bytes();
    snapshot.drops = saturated_drops();
    snapshot.punch = saturated_punch();
    snapshot.discovery = DiscoveryCounters {
        accepted_updates: u64::MAX,
        rejected_updates: u64::MAX,
        withdrawals: u64::MAX,
    };
    snapshot.updated_unix_ms = u64::MAX;

    assert!(snapshot.set_peers(peers));
    assert_eq!(snapshot.peers.len(), MAX_PEERS_IN_SNAPSHOT);
    assert_eq!(snapshot.peers[0].candidates.len(), MAX_CANDIDATES_PER_PEER);

    let response = ControlResponse::Doctor {
        report: Box::new(snapshot),
    };
    let line = serde_json::to_string(&response).unwrap();
    let limit = crate::server::MAX_CONTROL_LINE_BYTES;
    assert!(
        line.len() <= limit,
        "a saturated doctor response encodes to {} bytes, over the {limit} byte control line",
        line.len()
    );
}
