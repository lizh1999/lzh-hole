//! Real loopback UDP sockets drive two production PeerEngine instances and an
//! in-memory TUN sink. No public service, privilege, route or OS utun is used.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lzh_hole_net::socket::AsyncPhysicalSocket;
use lzh_hole_protocol::engine::{CandidatePolicy, EngineConfig, PeerEngine};
use lzh_hole_protocol::handshake::HandshakeConfig;
use lzh_hole_types::{BootId, DiscoveryPublicKey, Endpoint, RelationshipId, Secret32};
use tokio::time::timeout;

fn endpoint(addr: SocketAddrV4) -> Endpoint {
    Endpoint::new(*addr.ip(), addr.port())
}

fn socket_addr(endpoint: Endpoint) -> SocketAddrV4 {
    SocketAddrV4::new(endpoint.ip, endpoint.port)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the test supplies every engine field explicitly"
)]
fn loopback_engine(
    me: DiscoveryPublicKey,
    peer: DiscoveryPublicKey,
    boot: [u8; 16],
    self_vip: Ipv4Addr,
    peer_vip: Ipv4Addr,
    local: Endpoint,
    remote: Endpoint,
    psk: &Secret32,
) -> PeerEngine {
    let mut engine = PeerEngine::new(
        EngineConfig {
            handshake: HandshakeConfig {
                relationship_id: RelationshipId::from_bytes([0x44; 16]),
                me,
                peer,
                boot_id: BootId::from_bytes(boot),
                generation: 1,
            },
            self_vip,
            peer_vip,
            candidate_policy: CandidatePolicy {
                own_endpoints: vec![local],
                forbidden_addresses: vec![self_vip, peer_vip],
                stun_servers: Vec::new(),
                require_public_unicast: false,
            },
        },
        psk,
    )
    .unwrap();
    assert_eq!(engine.set_candidates(&[remote]).accepted, 1);
    engine
}

async fn drain_real_udp(engine: &mut PeerEngine, socket: &AsyncPhysicalSocket) {
    while let Some(frame) = engine.next_udp_frame() {
        let written = socket
            .send_to(&frame.bytes, socket_addr(frame.target))
            .await
            .unwrap();
        assert_eq!(written, frame.bytes.len());
    }
}

async fn receive_real_udp(engine: &mut PeerEngine, socket: &AsyncPhysicalSocket, now_ms: u64) {
    let mut buffer = [0u8; 2048];
    loop {
        match timeout(Duration::from_millis(2), socket.recv_from(&mut buffer)).await {
            Ok(Ok((size, metadata))) => {
                engine.handle_datagram(endpoint(metadata.source), &buffer[..size], now_ms);
            }
            Ok(Err(error)) => panic!("loopback UDP receive failed: {error}"),
            Err(_) => return,
        }
    }
}

fn ipv4_packet(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
    let mut packet = vec![0u8; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&20u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let mut sum = 0u32;
    for chunk in packet.as_chunks::<2>().0 {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    packet
}

#[tokio::test(flavor = "current_thread")]
async fn real_loopback_udp_drives_engine_and_memory_tun() {
    let socket_a = AsyncPhysicalSocket::open("lo0", Ipv4Addr::LOCALHOST, 0).unwrap();
    let socket_b = AsyncPhysicalSocket::open("lo0", Ipv4Addr::LOCALHOST, 0).unwrap();
    let endpoint_a = endpoint(socket_a.get_ref().local_addr());
    let endpoint_b = endpoint(socket_b.get_ref().local_addr());
    let key_a = DiscoveryPublicKey::from_bytes([1; 32]);
    let key_b = DiscoveryPublicKey::from_bytes([2; 32]);
    let vip_a = Ipv4Addr::new(10, 203, 0, 1);
    let vip_b = Ipv4Addr::new(10, 203, 0, 2);
    let psk = Secret32::from_bytes([0x5a; 32]);
    let mut engine_a = loopback_engine(
        key_a, key_b, [1; 16], vip_a, vip_b, endpoint_a, endpoint_b, &psk,
    );
    let mut engine_b = loopback_engine(
        key_b, key_a, [2; 16], vip_b, vip_a, endpoint_b, endpoint_a, &psk,
    );
    let start = now_unix_ms();
    let mut established = false;
    for step in 0..100 {
        let now = start + step * 50;
        engine_a.tick(now);
        engine_b.tick(now);
        drain_real_udp(&mut engine_a, &socket_a).await;
        drain_real_udp(&mut engine_b, &socket_b).await;
        receive_real_udp(&mut engine_a, &socket_a, now).await;
        receive_real_udp(&mut engine_b, &socket_b, now).await;
        if engine_a.snapshot(now).currently_healthy && engine_b.snapshot(now).currently_healthy {
            established = true;
            break;
        }
    }
    assert!(
        established,
        "real loopback UDP did not establish bilateral PONG health"
    );

    let packet = ipv4_packet(vip_a, vip_b);
    engine_a.send_ipv4(&packet, start + 5_000).unwrap();
    drain_real_udp(&mut engine_a, &socket_a).await;
    receive_real_udp(&mut engine_b, &socket_b, start + 5_000).await;
    let memory_tun_packet = engine_b.next_ipv4_packet();
    assert_eq!(memory_tun_packet, Some(packet));
    // This is real loopback UDP plus an in-memory TUN sink, not an OS utun,
    // route installation, or transparent TCP/UDP/ICMP acceptance test.
}
