use std::collections::VecDeque;
use std::net::Ipv4Addr;

use etherparse::{IpNumber, Ipv4Header};
use lzh_hole_types::{BootId, DiscoveryPublicKey, Endpoint, RelationshipId, Secret32, TransportId};

use crate::engine::{CandidatePolicy, EngineConfig, PeerEngine};
use crate::handshake::HandshakeConfig;
use crate::mesh::{Inbound, MAX_PEERS, MeshSendError, PeerSet, PeerSetError};
use crate::path::{PathCandidate, PathEndpoint, PathKind, TransportPolicy};

#[cfg(test)]
mod tests {
    use super::*;

    const START: u64 = 1_700_000_000_000;

    // Overlay addresses and physical endpoints are all public unicast, so these
    // tests exercise the production candidate filter instead of bypassing it.
    // Nothing here is ever dialled: no socket is opened.
    const A_VIP: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 11);
    const B_VIP: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 12);
    const C_VIP: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 13);
    const A_PHY: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 1);
    const B_PHY: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 2);
    const C_PHY: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 3);

    // A sits between B and C in key order, so it is the high side of one
    // relationship and the low side of the other.
    const A_KEY: [u8; 32] = [2; 32];
    const B_KEY: [u8; 32] = [1; 32];
    const C_KEY: [u8; 32] = [3; 32];
    const AB_REL: [u8; 16] = [0xb1; 16];
    const AC_REL: [u8; 16] = [0xc1; 16];

    const A_PORT: u16 = 41_001;
    const B_PORT: u16 = 41_002;
    const C_PORT: u16 = 41_003;
    const TRANSPORT: TransportId = TransportId(1);

    fn psk_ab() -> Secret32 {
        Secret32::from_bytes([0xa1; 32])
    }

    fn psk_ac() -> Secret32 {
        Secret32::from_bytes([0xa2; 32])
    }

    fn endpoint(address: Ipv4Addr, port: u16) -> Endpoint {
        Endpoint::new(address, port)
    }

    fn config(
        me: [u8; 32],
        peer: [u8; 32],
        relationship: [u8; 16],
        self_vip: Ipv4Addr,
        peer_vip: Ipv4Addr,
    ) -> EngineConfig {
        EngineConfig {
            handshake: HandshakeConfig {
                relationship_id: RelationshipId::from_bytes(relationship),
                me: DiscoveryPublicKey::from_bytes(me),
                peer: DiscoveryPublicKey::from_bytes(peer),
                boot_id: BootId::from_bytes([7; 16]),
                generation: 1,
            },
            self_vip,
            peer_vip,
            candidate_policy: CandidatePolicy::default(),
        }
    }

    fn policy(local: Ipv4Addr, port: u16) -> TransportPolicy {
        TransportPolicy {
            transport: TRANSPORT,
            local_endpoint: endpoint(local, port),
            lan_subnets: Vec::new(),
        }
    }

    // set_candidates hard-codes the legacy TransportId(0), which a strict
    // engine refuses. Real candidates have to name the socket they were
    // observed on, exactly as the daemon does.
    fn admit(engine: &mut PeerEngine, remote: Endpoint) -> usize {
        engine
            .set_paths(&[PathCandidate {
                path: PathEndpoint {
                    transport: TRANSPORT,
                    remote,
                },
                kind: PathKind::Public,
            }])
            .accepted
    }

    fn node_a() -> PeerSet {
        let mut set = PeerSet::new(A_VIP, DiscoveryPublicKey::from_bytes(A_KEY));
        set.set_transports(&[policy(A_PHY, A_PORT)]);
        set
    }

    // A structurally valid sessionless frame with an unusable MAC. Routing
    // happens before authentication, so this is enough to prove which engine was
    // reached and, more importantly, which engines were not.
    fn sessionless_frame(relationship: [u8; 16]) -> Vec<u8> {
        let mut out = vec![0u8; 42 + 240 + 32];
        out[0..4].copy_from_slice(&0x4C5A_4831u32.to_be_bytes());
        out[4] = 1;
        out[5] = 0x01;
        out[6] = 0;
        out[7] = 0;
        out[8..24].copy_from_slice(&relationship);
        out[40..42].copy_from_slice(&240u16.to_be_bytes());
        out
    }

    fn ipv4(source: Ipv4Addr, destination: Ipv4Addr, payload_len: u16) -> Vec<u8> {
        let mut header = Ipv4Header::new(
            payload_len,
            64,
            IpNumber::UDP,
            source.octets(),
            destination.octets(),
        )
        .expect("IPv4 header");
        header.header_checksum = header.calc_header_checksum();
        let mut packet = header.to_bytes().to_vec();
        packet.resize(packet.len() + usize::from(payload_len), 0xa5);
        packet
    }

    fn source_of(packet: &[u8]) -> Ipv4Addr {
        Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15])
    }

    fn destination_of(packet: &[u8]) -> Ipv4Addr {
        Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19])
    }

    fn untouched(set: &PeerSet, relationship: RelationshipId) -> bool {
        let counters = set
            .get(relationship)
            .expect("engine")
            .snapshot(START)
            .counters;
        counters.malformed_frames == 0
            && counters.stale_frames == 0
            && counters.wrong_endpoint == 0
            && counters.handshake_rejected == 0
    }

    fn punch_config(peer_endpoint: Endpoint) -> crate::punch::PunchConfig {
        crate::punch::PunchConfig {
            role: crate::punch::PunchRole::Easy,
            peer_endpoint,
            local_key: DiscoveryPublicKey::from_bytes(A_KEY),
            peer_key: DiscoveryPublicKey::from_bytes(B_KEY),
            relationship_id: RelationshipId::from_bytes(AB_REL),
            boot_id: BootId::from_bytes([7; 16]),
            generation: 1,
            direction: crate::wire::Direction::HiToLo,
            hard_sockets: 4,
        }
    }

    #[test]
    fn inbound_demux_reaches_one_engine_and_only_one() {
        let mut set = node_a();
        let ab = set
            .insert(config(A_KEY, B_KEY, AB_REL, A_VIP, B_VIP), &psk_ab())
            .expect("b");
        let ac = set
            .insert(config(A_KEY, C_KEY, AC_REL, A_VIP, C_VIP), &psk_ac())
            .expect("c");

        assert_eq!(
            set.dispatch(
                TRANSPORT,
                endpoint(B_PHY, B_PORT),
                &sessionless_frame(AB_REL),
                START
            ),
            Inbound::Delivered(ab)
        );
        let reached = set.get(ab).expect("ab").snapshot(START).counters;
        assert!(
            reached.handshake_rejected + reached.malformed_frames + reached.bad_mac > 0,
            "the owning engine must actually have inspected the frame"
        );
        assert!(untouched(&set, ac), "B's frame must not reach C's engine");

        let unknown = [0xdd; 16];
        assert_eq!(
            set.dispatch(
                TRANSPORT,
                endpoint(B_PHY, B_PORT),
                &sessionless_frame(unknown),
                START
            ),
            Inbound::UnknownRelationship(RelationshipId::from_bytes(unknown))
        );
        assert_eq!(set.counters().unknown_relationship, 1);

        assert_eq!(
            set.dispatch(TRANSPORT, endpoint(B_PHY, B_PORT), b"not a frame", START),
            Inbound::Malformed
        );
        assert_eq!(set.counters().malformed, 1);

        // Neither refusal may have touched an engine.
        let ab_counters = set.get(ab).expect("ab").snapshot(START).counters;
        assert_eq!(ab_counters.malformed_frames, 0);
        assert_eq!(ab_counters.stale_frames, 0);
        assert!(untouched(&set, ac));
    }

    #[test]
    fn conflicting_peers_are_refused() {
        let mut set = node_a();
        set.insert(config(A_KEY, B_KEY, AB_REL, A_VIP, B_VIP), &psk_ab())
            .expect("b");

        assert!(matches!(
            set.insert(config(A_KEY, C_KEY, AB_REL, A_VIP, C_VIP), &psk_ac()),
            Err(PeerSetError::DuplicateRelationship(_))
        ));
        assert!(matches!(
            set.insert(config(A_KEY, C_KEY, AC_REL, A_VIP, B_VIP), &psk_ac()),
            Err(PeerSetError::DuplicatePeerAddress(_))
        ));
        assert!(matches!(
            set.insert(config(A_KEY, C_KEY, AC_REL, A_VIP, A_VIP), &psk_ac()),
            Err(PeerSetError::SelfAddressCollision(_))
        ));
        assert!(matches!(
            set.insert(config(A_KEY, C_KEY, AC_REL, B_VIP, C_VIP), &psk_ac()),
            Err(PeerSetError::InconsistentSelfAddress { .. })
        ));
        assert!(matches!(
            set.insert(config(C_KEY, C_KEY, AC_REL, A_VIP, C_VIP), &psk_ac()),
            Err(PeerSetError::InconsistentIdentity)
        ));
        assert!(matches!(
            set.insert(config(A_KEY, B_KEY, AC_REL, A_VIP, C_VIP), &psk_ac()),
            Err(PeerSetError::DuplicatePeerKey(_))
        ));
        assert!(matches!(
            set.insert(config(A_KEY, C_KEY, AC_REL, A_VIP, C_VIP), &psk_ab()),
            Err(PeerSetError::DuplicatePsk)
        ));

        assert_eq!(set.len(), 1);
        assert_eq!(set.peer_addresses().collect::<Vec<_>>(), vec![B_VIP]);
    }

    #[test]
    fn peer_count_is_bounded() {
        let mut set = node_a();
        for index in 1..=MAX_PEERS {
            let byte = u8::try_from(index).expect("index fits");
            set.insert(
                config(
                    A_KEY,
                    [0x40 + byte; 32],
                    [byte; 16],
                    A_VIP,
                    Ipv4Addr::new(93, 184, 217, byte),
                ),
                &Secret32::from_bytes([0x70 + byte; 32]),
            )
            .expect("peer");
        }
        assert_eq!(set.len(), MAX_PEERS);

        let overflow = u8::try_from(MAX_PEERS + 1).expect("overflow fits");
        assert!(matches!(
            set.insert(
                config(
                    A_KEY,
                    [0x40 + overflow; 32],
                    [overflow; 16],
                    A_VIP,
                    Ipv4Addr::new(93, 184, 217, overflow),
                ),
                &Secret32::from_bytes([0x70 + overflow; 32]),
            ),
            Err(PeerSetError::TooManyPeers)
        ));
    }

    #[test]
    fn a_new_overlay_address_is_purged_from_existing_peers() {
        let mut set = node_a();
        let ab = set
            .insert(config(A_KEY, B_KEY, AB_REL, A_VIP, B_VIP), &psk_ab())
            .expect("b");
        let stranger = endpoint(C_VIP, 51_000);

        let engine = set.get_mut(ab).expect("b engine");
        assert_eq!(
            admit(engine, stranger),
            1,
            "C is not an overlay address of this node yet"
        );
        assert_eq!(
            set.get(ab)
                .expect("b engine")
                .snapshot(START)
                .candidate_count,
            1
        );

        set.insert(config(A_KEY, C_KEY, AC_REL, A_VIP, C_VIP), &psk_ac())
            .expect("c");

        // No second set_candidates call: tightening the policy has to purge the
        // retained candidate, not merely refuse the next one.
        assert_eq!(
            set.get(ab)
                .expect("b engine")
                .snapshot(START)
                .candidate_count,
            0,
            "an address that just became another peer's overlay address must not stay a candidate"
        );
        let engine = set.get_mut(ab).expect("b engine");
        assert_eq!(admit(engine, stranger), 0);
    }

    #[test]
    fn a_peer_added_after_transports_is_never_in_legacy_mode() {
        let mut set = node_a();
        set.insert(config(A_KEY, B_KEY, AB_REL, A_VIP, B_VIP), &psk_ab())
            .expect("b");
        // Inserted after set_transports, so it must inherit the socket facts.
        let ac = set
            .insert(config(A_KEY, C_KEY, AC_REL, A_VIP, C_VIP), &psk_ac())
            .expect("c");

        let frame = sessionless_frame(AC_REL);
        assert_eq!(
            set.dispatch(TRANSPORT, endpoint(C_PHY, C_PORT), &frame, START),
            Inbound::Delivered(ac)
        );
        assert_eq!(
            set.get(ac)
                .expect("ac")
                .snapshot(START)
                .counters
                .wrong_endpoint,
            0,
            "the configured socket must be accepted"
        );

        // A legacy-mode engine accepts TransportId(0) instead; a strict one
        // refuses it, which is what keeps real socket identities meaningful.
        assert_eq!(
            set.dispatch(TransportId(0), endpoint(C_PHY, C_PORT), &frame, START),
            Inbound::Delivered(ac)
        );
        assert_eq!(
            set.get(ac)
                .expect("ac")
                .snapshot(START)
                .counters
                .wrong_endpoint,
            1,
            "the legacy socket identity must be refused"
        );
    }

    #[test]
    fn a_punch_never_targets_an_overlay_address() {
        let mut set = node_a();
        let ab = set
            .insert(config(A_KEY, B_KEY, AB_REL, A_VIP, B_VIP), &psk_ab())
            .expect("b");
        set.insert(config(A_KEY, C_KEY, AC_REL, A_VIP, C_VIP), &psk_ac())
            .expect("c");
        let engine = set.get_mut(ab).expect("b engine");

        for forbidden in [A_VIP, B_VIP, C_VIP] {
            assert!(
                !engine.start_punch(punch_config(endpoint(forbidden, 40_000)), START),
                "overlay address {forbidden} must never be a punch target"
            );
        }
        assert!(engine.start_punch(punch_config(endpoint(B_PHY, 40_000)), START));
    }

    #[test]
    fn a_removed_peer_stops_owning_its_address_and_can_return() {
        let mut set = node_a();
        let ab = set
            .insert(config(A_KEY, B_KEY, AB_REL, A_VIP, B_VIP), &psk_ab())
            .expect("b");
        set.insert(config(A_KEY, C_KEY, AC_REL, A_VIP, C_VIP), &psk_ac())
            .expect("c");
        assert_eq!(set.len(), 2);

        assert!(set.remove(ab).is_some());
        assert!(set.remove(ab).is_none());
        assert_eq!(set.len(), 1);
        assert!(!set.contains(ab));
        assert!(set.get(ab).is_none());
        assert_eq!(
            set.send_ipv4(&ipv4(A_VIP, B_VIP, 32), START),
            Err(MeshSendError::NoPeerForDestination(B_VIP))
        );

        let again = set
            .insert(config(A_KEY, B_KEY, AB_REL, A_VIP, B_VIP), &psk_ab())
            .expect("b again");
        assert_eq!(again, ab);
        assert_eq!(set.len(), 2);
        assert!(set.get(ab).expect("b").snapshot(START).session_id.is_none());
        // Draining must stay well defined across the changed peer count.
        assert!(set.next_udp_frame().is_none());
        assert!(set.next_ipv4_packet().is_none());
        assert!(set.next_punch_frame().is_none());
    }

    #[test]
    fn send_and_dispatch_error_paths_are_counted_and_fail_closed() {
        let mut set = node_a();
        set.insert(config(A_KEY, B_KEY, AB_REL, A_VIP, B_VIP), &psk_ab())
            .expect("b");

        assert_eq!(
            set.send_ipv4(&[0u8; 8], START),
            Err(MeshSendError::Malformed)
        );
        assert_eq!(set.counters().unparsable, 1);

        let unowned = Ipv4Addr::new(93, 184, 216, 99);
        assert_eq!(
            set.send_ipv4(&ipv4(A_VIP, unowned, 32), START),
            Err(MeshSendError::NoPeerForDestination(unowned))
        );
        assert_eq!(set.counters().unroutable, 1);

        // A foreign source is refused by the owning engine, not here.
        assert!(matches!(
            set.send_ipv4(&ipv4(B_VIP, B_VIP, 32), START),
            Err(MeshSendError::Peer(_))
        ));
        // And with no verified path yet, a well formed packet is still refused.
        assert!(matches!(
            set.send_ipv4(&ipv4(A_VIP, B_VIP, 32), START),
            Err(MeshSendError::Peer(_))
        ));

        set.close();
        assert!(matches!(
            set.send_ipv4(&ipv4(A_VIP, B_VIP, 32), START),
            Err(MeshSendError::Peer(_))
        ));
    }

    struct Datagram {
        source: Endpoint,
        target: Endpoint,
        bytes: Vec<u8>,
    }

    struct Mesh {
        a: PeerSet,
        b: PeerEngine,
        c: PeerEngine,
    }

    fn mesh() -> Mesh {
        let mut a = node_a();
        a.insert(config(A_KEY, B_KEY, AB_REL, A_VIP, B_VIP), &psk_ab())
            .expect("b");
        a.insert(config(A_KEY, C_KEY, AC_REL, A_VIP, C_VIP), &psk_ac())
            .expect("c");

        let mut b = PeerEngine::new(config(B_KEY, A_KEY, AB_REL, B_VIP, A_VIP), &psk_ab())
            .expect("b engine");
        b.set_transports(&[policy(B_PHY, B_PORT)]);
        assert_eq!(admit(&mut b, endpoint(A_PHY, A_PORT)), 1);

        let mut c = PeerEngine::new(config(C_KEY, A_KEY, AC_REL, C_VIP, A_VIP), &psk_ac())
            .expect("c engine");
        c.set_transports(&[policy(C_PHY, C_PORT)]);
        assert_eq!(admit(&mut c, endpoint(A_PHY, A_PORT)), 1);

        let ab = RelationshipId::from_bytes(AB_REL);
        let ac = RelationshipId::from_bytes(AC_REL);
        assert_eq!(
            admit(a.get_mut(ab).expect("ab"), endpoint(B_PHY, B_PORT)),
            1
        );
        assert_eq!(
            admit(a.get_mut(ac).expect("ac"), endpoint(C_PHY, C_PORT)),
            1
        );
        Mesh { a, b, c }
    }

    fn pump(mesh: &mut Mesh, now_ms: u64) {
        for _ in 0..64 {
            let mut queue = VecDeque::new();
            while let Some((_, frame)) = mesh.a.next_udp_frame() {
                queue.push_back(Datagram {
                    source: endpoint(A_PHY, A_PORT),
                    target: frame.target,
                    bytes: frame.bytes,
                });
            }
            while let Some(frame) = mesh.b.next_udp_frame() {
                queue.push_back(Datagram {
                    source: endpoint(B_PHY, B_PORT),
                    target: frame.target,
                    bytes: frame.bytes,
                });
            }
            while let Some(frame) = mesh.c.next_udp_frame() {
                queue.push_back(Datagram {
                    source: endpoint(C_PHY, C_PORT),
                    target: frame.target,
                    bytes: frame.bytes,
                });
            }
            if queue.is_empty() {
                return;
            }
            while let Some(datagram) = queue.pop_front() {
                if datagram.target == endpoint(A_PHY, A_PORT) {
                    mesh.a
                        .dispatch(TRANSPORT, datagram.source, &datagram.bytes, now_ms);
                } else if datagram.target == endpoint(B_PHY, B_PORT) {
                    mesh.b
                        .handle_datagram_on(TRANSPORT, datagram.source, &datagram.bytes, now_ms);
                } else if datagram.target == endpoint(C_PHY, C_PORT) {
                    mesh.c
                        .handle_datagram_on(TRANSPORT, datagram.source, &datagram.bytes, now_ms);
                }
            }
        }
        panic!("mock queue did not converge");
    }

    fn establish(mesh: &mut Mesh) -> u64 {
        let ab = RelationshipId::from_bytes(AB_REL);
        let ac = RelationshipId::from_bytes(AC_REL);
        for step in 0..200 {
            let now = START + step * 50;
            mesh.a.tick(now);
            mesh.b.tick(now);
            mesh.c.tick(now);
            pump(mesh, now);
            let healthy = mesh.a.get(ab).expect("ab").snapshot(now).currently_healthy
                && mesh.a.get(ac).expect("ac").snapshot(now).currently_healthy
                && mesh.b.snapshot(now).currently_healthy
                && mesh.c.snapshot(now).currently_healthy;
            if healthy {
                return now;
            }
        }
        panic!("the three node mesh did not become healthy");
    }

    #[test]
    fn three_node_mesh_carries_data_in_both_directions() {
        let mut mesh = mesh();
        let now = establish(&mut mesh);
        let ab = RelationshipId::from_bytes(AB_REL);
        let ac = RelationshipId::from_bytes(AC_REL);
        let unowned = Ipv4Addr::new(93, 184, 216, 99);

        assert_eq!(mesh.a.send_ipv4(&ipv4(A_VIP, B_VIP, 32), now), Ok(ab));
        assert_eq!(mesh.a.send_ipv4(&ipv4(A_VIP, C_VIP, 48), now), Ok(ac));
        assert_eq!(
            mesh.a.send_ipv4(&ipv4(A_VIP, unowned, 32), now),
            Err(MeshSendError::NoPeerForDestination(unowned))
        );
        assert!(
            matches!(
                mesh.a.send_ipv4(&ipv4(B_VIP, C_VIP, 32), now),
                Err(MeshSendError::Peer(_))
            ),
            "the owning engine must still refuse a foreign source address"
        );

        pump(&mut mesh, now);

        let to_b = mesh.b.next_ipv4_packet().expect("b received a packet");
        let to_c = mesh.c.next_ipv4_packet().expect("c received a packet");
        assert_eq!(destination_of(&to_b), B_VIP);
        assert_eq!(source_of(&to_b), A_VIP);
        assert_eq!(destination_of(&to_c), C_VIP);
        assert_eq!(source_of(&to_c), A_VIP);
        assert!(mesh.b.next_ipv4_packet().is_none());
        assert!(mesh.c.next_ipv4_packet().is_none());

        // Inbound: both peers reach A, and every packet is attributed to the
        // relationship it actually arrived on.
        mesh.b
            .send_ipv4(&ipv4(B_VIP, A_VIP, 24), now)
            .expect("b sends");
        mesh.c
            .send_ipv4(&ipv4(C_VIP, A_VIP, 40), now)
            .expect("c sends");
        pump(&mut mesh, now);

        let mut inbound = Vec::new();
        while let Some((relationship, packet)) = mesh.a.next_ipv4_packet() {
            inbound.push((relationship, packet));
        }
        assert_eq!(inbound.len(), 2, "both peers must be delivered");
        for (relationship, packet) in &inbound {
            let expected = if *relationship == ab { B_VIP } else { C_VIP };
            assert_eq!(destination_of(packet), A_VIP);
            assert_eq!(
                source_of(packet),
                expected,
                "a packet must be attributed to the peer it came from"
            );
        }
        assert!(inbound.iter().any(|(r, _)| *r == ab));
        assert!(inbound.iter().any(|(r, _)| *r == ac));
    }

    #[test]
    fn an_authenticated_frame_cannot_be_moved_to_another_relationship() {
        let mut mesh = mesh();
        let now = establish(&mut mesh);
        let ac = RelationshipId::from_bytes(AC_REL);

        // A real, authenticated DATA frame from B on the AB relationship.
        mesh.b
            .send_ipv4(&ipv4(B_VIP, A_VIP, 32), now)
            .expect("b sends");
        let frame = mesh.b.next_udp_frame().expect("b queued a frame");
        let mut forged = frame.bytes.clone();
        forged[8..24].copy_from_slice(&AC_REL);

        // Delivered from C's own selected endpoint, so the endpoint check cannot
        // be what stops it: only the per-relationship keys can.
        let before = mesh.a.get(ac).expect("ac").snapshot(now).counters;
        assert_eq!(
            mesh.a
                .dispatch(TRANSPORT, endpoint(C_PHY, C_PORT), &forged, now),
            Inbound::Delivered(ac)
        );
        let after = mesh.a.get(ac).expect("ac").snapshot(now).counters;

        assert!(
            mesh.a.next_ipv4_packet().is_none(),
            "a frame re-labelled into another relationship must deliver nothing"
        );
        assert_eq!(after.ipv4_rx_accepted, before.ipv4_rx_accepted);
        assert_eq!(after.sessions_installed, before.sessions_installed);
        let rejections = after.bad_mac
            + after.stale_frames
            + after.replay_rejected
            + after.wrong_endpoint
            + after.control_rejected;
        assert!(
            rejections > 0,
            "the forgery must be recorded as a rejection"
        );
        // The relationship it really belongs to is untouched by the forgery.
        let ab_counters = mesh
            .a
            .get(RelationshipId::from_bytes(AB_REL))
            .expect("ab")
            .snapshot(now)
            .counters;
        assert_eq!(ab_counters.bad_mac, 0);
    }
}
