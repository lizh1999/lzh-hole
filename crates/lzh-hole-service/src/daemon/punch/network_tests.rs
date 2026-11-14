//! Explicit, unprivileged single-process / two-physical-uplink experiment.
//! Uses real STUN and production sockets, punch coordinator, promotion and
//! PeerEngine. Signed records are passed in memory, NOT through public ntfy.
//! No TUN, routes, DNS, PF, VPN, launchd or existing identities are touched.

use super::*;
use lzh_hole_store::{PAIRING_VERSION, Relationship, Role};
use lzh_hole_types::RelationshipId;

fn peer(
    interface: &str,
    seed: &[u8; 32],
    other: DiscoveryPublicKey,
    psk: &Secret32,
    relationship_id: RelationshipId,
    first: bool,
) -> (tempfile::TempDir, Daemon) {
    let temp = tempfile::Builder::new()
        .prefix("lzh-hole-uplink-")
        .tempdir()
        .unwrap();
    let state = StateDir::open(&temp.path().join("state")).unwrap();
    state.store_seed(seed).unwrap();
    let local =
        DiscoveryPublicKey::from_bytes(SigningKey::from_bytes(seed).verifying_key().to_bytes());
    let relationship = Relationship {
        pairing_version: PAIRING_VERSION,
        pairing_id: relationship_id,
        relationship_id,
        self_public_key: local,
        peer_public_key: other,
        role: Role::Initiator,
        self_vip: if first { "10.203.0.1" } else { "10.203.0.2" }.to_owned(),
        peer_vip: if first { "10.203.0.2" } else { "10.203.0.1" }.to_owned(),
        finalised_unix_ms: now_unix_ms(),
    };
    state.finalise(&relationship, psk).unwrap();
    let mut config = super::super::tests::resolved_for_test(Some(interface)).config;
    config.state_dir = state.path().to_owned();
    config.control_socket = temp.path().join("control/socket");
    config.lan.enabled = false;
    config.stun_seeds = vec![
        "116.162.157.195:3478".parse().unwrap(),
        "111.206.174.3:3478".parse().unwrap(),
    ];
    config.ntfy.topic = topic_for_relationship(&relationship_id);
    let resolved = config.resolve(relationship).unwrap();
    let (snapshots, _) = watch::channel(ServiceSnapshot::starting(1, now_unix_ms()));
    let mut daemon = Daemon::new(
        resolved,
        false,
        RuntimeComponents::offline_for_test(),
        snapshots,
    )
    .unwrap();
    daemon.engine = Some(
        lifecycle::make_engine(&daemon.resolved, psk, daemon.boot_id, daemon.generation).unwrap(),
    );
    daemon.topology = enumerate_interface_prefixes().unwrap();
    let address = daemon
        .topology
        .iter()
        .find(|entry| entry.interface.name == interface)
        .and_then(|entry| entry.interface.ipv4.first())
        .copied()
        .expect("active IPv4 uplink");
    let id = daemon
        .transports
        .open(&mut daemon.transport_ids, interface, address, 0)
        .unwrap();
    daemon
        .public
        .add_transport(id.0, daemon.resolved.config.stun_seeds.clone(), 0);
    daemon.sync_engine_transports();
    // Manual pump below drives STUN only; it never runs topology refresh or ntfy.
    daemon.network_enabled = true;
    (temp, daemon)
}

fn signed_record(daemon: &mut Daemon) -> SignedPayload {
    let now = now_unix_ms();
    let seq = reserve_sequence(
        daemon.state.load_sequence().unwrap(),
        daemon.peer_cache.highest_seq().unwrap_or(0),
        now_unix_us(),
    )
    .unwrap();
    daemon.state.store_sequence(seq).unwrap();
    let candidates =
        discovery::publication_endpoints(daemon.public.own_mappings(daemon.monotonic_ms()))
            .into_iter()
            .map(|endpoint| RecordCandidate {
                endpoint,
                source: CandidateSource::Stun,
            })
            .collect();
    let record = ContactRecord {
        relationship_id: daemon.resolved.relationship.relationship_id,
        sender: daemon.resolved.relationship.self_public_key,
        receiver: daemon.resolved.relationship.peer_public_key,
        record_seq: seq,
        issued_at_unix_ms: now,
        expires_at_unix_ms: daemon
            .punch_offer_deadline()
            .unwrap_or(now + MAX_LIFETIME_MS),
        boot_id: daemon.boot_id,
        generation: daemon.generation,
        candidates,
        flags: daemon.record_flags(),
    };
    SignedPayload::sign(
        MessageKind::Request,
        RequestId::random().unwrap(),
        &record,
        &daemon.signing_key,
    )
    .unwrap()
}

async fn exchange(a: &mut Daemon, b: &mut Daemon) {
    let from_a = signed_record(a);
    let from_b = signed_record(b);
    a.handle_signed_payload(from_b, Delivery::Cached, "in-memory-test-record")
        .await;
    b.handle_signed_payload(from_a, Delivery::Cached, "in-memory-test-record")
        .await;
    assert!(
        !a.paths.is_empty() && !b.paths.is_empty(),
        "real interface routes must authorize both public candidates"
    );
    // Do not let advertised-port HELLO/PROBE shortcuts masquerade as punching.
    // Only endpoints learned from a received PUNCH can seed the handshake.
    a.engine.as_mut().unwrap().set_paths(&[]);
    b.engine.as_mut().unwrap().set_paths(&[]);
}

async fn pump(
    a: &mut Daemon,
    b: &mut Daemon,
    duration: Duration,
    until_healthy: bool,
) -> Vec<(usize, Vec<u8>)> {
    let deadline = Instant::now() + duration;
    let mut ticker = tokio::time::interval(ENGINE_TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut packets = Vec::new();
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            _ = ticker.tick() => {
                for daemon in [&mut *a, &mut *b] {
                    let now = now_unix_ms();
                    daemon.engine.as_mut().unwrap().tick(now);
                    daemon.maybe_start_punch(now);
                    daemon.drive_punch(now);
                    daemon.maybe_start_stun().await;
                }
            }
            udp = a.transports.recv() => a.handle_udp(udp).await,
            udp = b.transports.recv() => b.handle_udp(udp).await,
            punch = a.punch_sockets.recv() => a.handle_punch_udp(punch, now_unix_ms()),
            punch = b.punch_sockets.recv() => b.handle_punch_udp(punch, now_unix_ms()),
        }
        for (index, daemon) in [&mut *a, &mut *b].into_iter().enumerate() {
            while let Some(packet) = daemon.engine.as_mut().unwrap().next_ipv4_packet() {
                packets.push((index, packet));
            }
            daemon.drain_engine().await;
            daemon.drain_punch(now_unix_ms()).await;
        }
        if until_healthy
            && [a.engine.as_ref().unwrap(), b.engine.as_ref().unwrap()]
                .iter()
                .all(|engine| engine.snapshot(now_unix_ms()).currently_healthy)
        {
            break;
        }
    }
    packets
}

fn ipv4_udp(source: Ipv4Addr, destination: Ipv4Addr, marker: u8) -> Vec<u8> {
    let mut packet = vec![marker; 60];
    packet[..28].fill(0);
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&60u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    packet[20..22].copy_from_slice(&31_001u16.to_be_bytes());
    packet[22..24].copy_from_slice(&31_002u16.to_be_bytes());
    packet[24..26].copy_from_slice(&40u16.to_be_bytes());
    let mut sum: u32 = packet[..20]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    packet
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "real en0/en8 STUN and UDP punching; opt in explicitly, no TUN or public ntfy"]
async fn en0_en8_real_udp_punch() {
    let mut seed_a = [0; 32];
    getrandom::fill(&mut seed_a).unwrap();
    let mut seed_b = [0; 32];
    getrandom::fill(&mut seed_b).unwrap();
    let mut secret = [0; 32];
    getrandom::fill(&mut secret).unwrap();
    let psk = Secret32::from_bytes(secret);
    let rel = RelationshipId::from_bytes(*BootId::random().unwrap().as_bytes());
    let key_a =
        DiscoveryPublicKey::from_bytes(SigningKey::from_bytes(&seed_a).verifying_key().to_bytes());
    let key_b =
        DiscoveryPublicKey::from_bytes(SigningKey::from_bytes(&seed_b).verifying_key().to_bytes());
    let (_state_a, mut a) = peer("en0", &seed_a, key_b, &psk, rel, true);
    let (_state_b, mut b) = peer("en8", &seed_b, key_a, &psk, rel, false);
    pump(&mut a, &mut b, Duration::from_secs(20), false).await;
    println!("scope=single-process/two-real-uplinks signaling=in-memory-signed-records tun=none");
    for (name, daemon) in [("en0", &a), ("en8", &b)] {
        println!(
            "{name}: mapping={} mappings={:?}",
            daemon.local_mapping().as_str(),
            daemon.public.own_mappings(daemon.monotonic_ms())
        );
    }
    assert!(
        matches!(
            (a.local_mapping(), b.local_mapping()),
            (
                MappingBehavior::EndpointIndependent,
                MappingBehavior::EndpointDependent
            ) | (
                MappingBehavior::EndpointDependent,
                MappingBehavior::EndpointIndependent
            )
        ),
        "need one measured EIM and one measured EDM uplink"
    );
    exchange(&mut a, &mut b).await;
    pump(&mut a, &mut b, Duration::from_secs(1), false).await;
    assert!(
        a.punch_offer_active() || b.punch_offer_active(),
        "hard side must open real sockets"
    );
    // Deliberately delayed offer delivery, rather than simultaneous starts.
    exchange(&mut a, &mut b).await;
    pump(&mut a, &mut b, Duration::from_secs(45), true).await;
    for (name, daemon) in [("en0", &a), ("en8", &b)] {
        println!(
            "{name}: punch={:?} engine={:?}",
            daemon.punch_status(),
            daemon.engine.as_ref().unwrap().snapshot(now_unix_ms())
        );
    }
    for daemon in [&a, &b] {
        assert!(
            daemon
                .engine
                .as_ref()
                .unwrap()
                .snapshot(now_unix_ms())
                .currently_healthy,
            "actual reciprocal PONG evidence required"
        );
    }
    assert!(
        !a.promoted_transports.is_empty() || !b.promoted_transports.is_empty(),
        "a real hard-side socket must have been promoted"
    );
    let a_packet = ipv4_udp(a.resolved.self_vip, a.resolved.peer_vip, 0xa1);
    let b_packet = ipv4_udp(b.resolved.self_vip, b.resolved.peer_vip, 0xb2);
    a.engine
        .as_mut()
        .unwrap()
        .send_ipv4(&a_packet, now_unix_ms())
        .unwrap();
    b.engine
        .as_mut()
        .unwrap()
        .send_ipv4(&b_packet, now_unix_ms())
        .unwrap();
    a.drain_engine().await;
    b.drain_engine().await;
    let received = pump(&mut a, &mut b, Duration::from_secs(3), false).await;
    assert!(
        received.contains(&(1, a_packet)),
        "en0 -> en8 authenticated IPv4 bytes"
    );
    assert!(
        received.contains(&(0, b_packet)),
        "en8 -> en0 authenticated IPv4 bytes"
    );
    println!(
        "direct_reachable=true/true currently_healthy=true/true authenticated_ipv4_bidirectional=true functional_pass=unmeasured p0_qualified=unmeasured"
    );
    a.shutdown().await;
    b.shutdown().await;
    assert_eq!(
        a.transports.iter().count()
            + b.transports.iter().count()
            + a.punch_sockets.len()
            + b.punch_sockets.len(),
        0
    );
}
