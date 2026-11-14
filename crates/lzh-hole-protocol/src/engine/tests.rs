use std::collections::VecDeque;

use etherparse::Ipv4HeaderSlice;
use lzh_hole_types::{Endpoint, RelationshipId, Secret32};

use crate::engine::{CandidatePolicy, EngineConfig, PeerEngine, SendError};
use crate::handshake::HandshakeConfig;
use crate::session::SessionKeys;
use crate::wire::{CtrlPayload, FrameType, encode_frame, parse_frame};

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use etherparse::{IpNumber, Ipv4Header};

    use super::*;
    use lzh_hole_types::{BootId, DiscoveryPublicKey};

    const START: u64 = 1_700_000_000_000;
    const A_VIP: Ipv4Addr = Ipv4Addr::new(10, 203, 0, 1);
    const B_VIP: Ipv4Addr = Ipv4Addr::new(10, 203, 0, 2);

    fn endpoint(port: u16) -> Endpoint {
        Endpoint::new(Ipv4Addr::LOCALHOST, port)
    }

    fn engine(
        me: DiscoveryPublicKey,
        peer: DiscoveryPublicKey,
        boot: [u8; 16],
        self_vip: Ipv4Addr,
        peer_vip: Ipv4Addr,
    ) -> PeerEngine {
        let psk = Secret32::from_bytes([0x5a; 32]);
        PeerEngine::new(
            EngineConfig {
                handshake: HandshakeConfig {
                    relationship_id: RelationshipId::from_bytes([9; 16]),
                    me,
                    peer,
                    boot_id: BootId::from_bytes(boot),
                    generation: 1,
                },
                self_vip,
                peer_vip,
                candidate_policy: CandidatePolicy {
                    require_public_unicast: false,
                    ..CandidatePolicy::default()
                },
            },
            &psk,
        )
        .expect("engine")
    }

    struct Pair {
        a: PeerEngine,
        b: PeerEngine,
        a_endpoint: Endpoint,
        b_endpoint: Endpoint,
    }

    fn pair() -> Pair {
        let a_endpoint = endpoint(41_001);
        let b_endpoint = endpoint(41_002);
        let dead = endpoint(41_999);
        let mut a = engine(
            DiscoveryPublicKey::from_bytes([1; 32]),
            DiscoveryPublicKey::from_bytes([2; 32]),
            [1; 16],
            A_VIP,
            B_VIP,
        );
        let mut b = engine(
            DiscoveryPublicKey::from_bytes([2; 32]),
            DiscoveryPublicKey::from_bytes([1; 32]),
            [2; 16],
            B_VIP,
            A_VIP,
        );
        // A dead first target proves that connection establishment is not
        // accidentally hard-wired to targets.first().
        assert_eq!(a.set_candidates(&[dead, b_endpoint]).accepted, 2);
        assert_eq!(b.set_candidates(&[dead, a_endpoint]).accepted, 2);
        Pair {
            a,
            b,
            a_endpoint,
            b_endpoint,
        }
    }

    #[derive(Debug)]
    struct Datagram {
        source: Endpoint,
        target: Endpoint,
        bytes: Vec<u8>,
    }

    fn drain(pair: &mut Pair, from_a: bool, queue: &mut VecDeque<Datagram>) {
        let source = if from_a {
            pair.a_endpoint
        } else {
            pair.b_endpoint
        };
        let engine = if from_a { &mut pair.a } else { &mut pair.b };
        while let Some(frame) = engine.next_udp_frame() {
            queue.push_back(Datagram {
                source,
                target: frame.target,
                bytes: frame.bytes,
            });
        }
    }

    fn pump(pair: &mut Pair, now_ms: u64, deliver: bool) {
        for _ in 0..32 {
            let mut queue = VecDeque::new();
            drain(pair, true, &mut queue);
            drain(pair, false, &mut queue);
            if queue.is_empty() {
                return;
            }
            while let Some(datagram) = queue.pop_front() {
                if !deliver {
                    continue;
                }
                if datagram.target == pair.a_endpoint {
                    pair.a
                        .handle_datagram(datagram.source, &datagram.bytes, now_ms);
                } else if datagram.target == pair.b_endpoint {
                    pair.b
                        .handle_datagram(datagram.source, &datagram.bytes, now_ms);
                }
            }
        }
        panic!("mock queue did not converge");
    }

    fn establish(pair: &mut Pair, start_ms: u64) -> u64 {
        for step in 0..100 {
            let now = start_ms + step * 50;
            pair.a.tick(now);
            pair.b.tick(now);
            pump(pair, now, true);
            if pair.a.snapshot(now).currently_healthy && pair.b.snapshot(now).currently_healthy {
                return now;
            }
        }
        panic!(
            "engines did not become healthy: {:?} {:?}",
            pair.a.snapshot(start_ms),
            pair.b.snapshot(start_ms)
        );
    }

    fn ipv4(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        payload_len: u16,
        fragment_offset: u16,
    ) -> Vec<u8> {
        let mut header = Ipv4Header::new(
            payload_len,
            64,
            IpNumber::UDP,
            source.octets(),
            destination.octets(),
        )
        .expect("IPv4 header");
        if fragment_offset != 0 {
            header.dont_fragment = false;
            header.fragment_offset = fragment_offset.try_into().expect("fragment offset");
        }
        header.header_checksum = header.calc_header_checksum();
        let mut packet = header.to_bytes().to_vec();
        packet.resize(packet.len() + usize::from(payload_len), 0xa5);
        packet
    }

    fn forged_data(engine: &PeerEngine, packet: &[u8], sequence: u64) -> Vec<u8> {
        let session = engine.hs.session().expect("session");
        encode_frame(
            FrameType::Data,
            SessionKeys::tx_direction(engine.role),
            engine.relationship_id,
            session.keys.session_id,
            sequence,
            packet,
            session.keys.tx_key(engine.role),
        )
        .expect("forged authenticated test frame")
    }

    fn forged_ping(engine: &PeerEngine, boot_id: BootId, sequence: u64, now_ms: u64) -> Vec<u8> {
        let session = engine.hs.session().expect("session");
        let payload = CtrlPayload {
            sender: engine.self_key,
            receiver: engine.peer_key,
            nonce: [0x44; 32],
            boot_id,
            generation: engine.generation,
            issued_at_unix_ms: now_ms,
            flags: 0,
        }
        .encode();
        encode_frame(
            FrameType::CtrlPing,
            SessionKeys::tx_direction(engine.role),
            engine.relationship_id,
            session.keys.session_id,
            sequence,
            &payload,
            session.keys.tx_key(engine.role),
        )
        .expect("forged authenticated test PING")
    }

    fn forged_pong(engine: &PeerEngine, nonce: [u8; 32], sequence: u64, now_ms: u64) -> Vec<u8> {
        let session = engine.hs.session().expect("session");
        let payload = CtrlPayload {
            sender: engine.self_key,
            receiver: engine.peer_key,
            nonce,
            boot_id: engine.boot_id,
            generation: engine.generation,
            issued_at_unix_ms: now_ms,
            flags: 0,
        }
        .encode();
        encode_frame(
            FrameType::CtrlPong,
            SessionKeys::tx_direction(engine.role),
            engine.relationship_id,
            session.keys.session_id,
            sequence,
            &payload,
            session.keys.tx_key(engine.role),
        )
        .expect("forged authenticated test PONG")
    }

    #[test]
    fn queue_mock_handshake_health_ipv4_and_fragment_round_trip() {
        let mut pair = pair();
        let now = establish(&mut pair, START);
        assert_eq!(
            pair.a.snapshot(now).selected_endpoint,
            Some(pair.b_endpoint)
        );
        assert_eq!(
            pair.b.snapshot(now).selected_endpoint,
            Some(pair.a_endpoint)
        );

        let a_to_b = ipv4(A_VIP, B_VIP, 48, 0);
        pair.a.send_ipv4(&a_to_b, now).expect("queue A to B");
        pump(&mut pair, now, true);
        assert_eq!(pair.b.next_ipv4_packet(), Some(a_to_b));
        assert!(pair.b.next_ipv4_packet().is_none());

        let b_to_a = ipv4(B_VIP, A_VIP, 48, 0);
        pair.b.send_ipv4(&b_to_a, now).expect("queue B to A");
        pump(&mut pair, now, true);
        assert_eq!(pair.a.next_ipv4_packet(), Some(b_to_a));

        // A non-initial fragment need not contain a UDP/TCP header. It is an
        // independent IP packet here; reassembly belongs to the receiving OS.
        let fragment = ipv4(A_VIP, B_VIP, 4, 1);
        pair.a.send_ipv4(&fragment, now).expect("queue fragment");
        pump(&mut pair, now, true);
        assert_eq!(pair.b.next_ipv4_packet(), Some(fragment));
    }

    #[test]
    fn tamper_replay_bad_epoch_vip_and_endpoint_fail_closed() {
        let mut pair = pair();
        let now = establish(&mut pair, START);
        let packet = ipv4(A_VIP, B_VIP, 32, 0);
        pair.a.send_ipv4(&packet, now).expect("queue DATA");
        let frame = pair.a.next_udp_frame().expect("DATA frame");
        let parsed = parse_frame(&frame.bytes).expect("parse DATA");
        let sequence = parsed.header.sequence;
        let highest = pair.b.hs.session().expect("session").rx.highest();

        let mut tampered = frame.bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        pair.b.handle_datagram(pair.a_endpoint, &tampered, now);
        assert!(pair.b.next_ipv4_packet().is_none());
        assert_eq!(pair.b.hs.session().expect("session").rx.highest(), highest);

        // The same authentic frame from another actual UDP source neither
        // selects that source nor consumes its sequence before the real source.
        let wrong_source = endpoint(41_100);
        pair.b.handle_datagram(wrong_source, &frame.bytes, now);
        assert!(pair.b.next_ipv4_packet().is_none());
        assert_eq!(
            pair.b.snapshot(now).selected_endpoint,
            Some(pair.a_endpoint)
        );
        assert_eq!(pair.b.hs.session().expect("session").rx.highest(), highest);

        pair.b.handle_datagram(pair.a_endpoint, &frame.bytes, now);
        assert_eq!(pair.b.next_ipv4_packet(), Some(packet));
        assert_eq!(
            pair.b.hs.session().expect("session").rx.highest(),
            Some(sequence)
        );
        pair.b.handle_datagram(pair.a_endpoint, &frame.bytes, now);
        assert!(pair.b.next_ipv4_packet().is_none());
        assert!(pair.b.snapshot(now).counters.replay_rejected >= 1);

        let before_bad = pair.b.hs.session().expect("session").rx.highest();
        let wrong_vip = ipv4(A_VIP, Ipv4Addr::new(10, 203, 0, 99), 32, 0);
        let forged = forged_data(&pair.a, &wrong_vip, u64::MAX - 5_000);
        pair.b.handle_datagram(pair.a_endpoint, &forged, now);
        assert!(pair.b.next_ipv4_packet().is_none());
        assert_eq!(
            pair.b.hs.session().expect("session").rx.highest(),
            before_bad,
            "a semantically bad high sequence must not poison replay state"
        );

        let wrong_epoch = forged_ping(
            &pair.a,
            BootId::from_bytes([0x99; 16]),
            u64::MAX - 5_000,
            now,
        );
        pair.b.handle_datagram(pair.a_endpoint, &wrong_epoch, now);
        assert!(pair.b.next_udp_frame().is_none());
        assert_eq!(
            pair.b.hs.session().expect("session").rx.highest(),
            before_bad
        );
        assert!(pair.b.snapshot(now).counters.control_rejected >= 1);
    }

    #[test]
    fn wrong_source_pong_cannot_consume_sequence_before_path_selection() {
        let mut pair = pair();
        let now = START;
        pair.a.tick(now);
        pair.b.tick(now);

        // Drive the real handshake and path probes, but intercept the first
        // PONG headed to A instead of delivering it to A automatically.
        let mut captured = None;
        for _ in 0..32 {
            let mut queue = VecDeque::new();
            drain(&mut pair, true, &mut queue);
            drain(&mut pair, false, &mut queue);
            if queue.is_empty() {
                break;
            }
            while let Some(datagram) = queue.pop_front() {
                if datagram.target == pair.a_endpoint
                    && parse_frame(&datagram.bytes)
                        .is_ok_and(|frame| frame.header.frame_type == FrameType::CtrlPong)
                {
                    captured = Some(datagram);
                    continue;
                }
                if datagram.target == pair.a_endpoint {
                    pair.a
                        .handle_datagram(datagram.source, &datagram.bytes, now);
                } else if datagram.target == pair.b_endpoint {
                    pair.b
                        .handle_datagram(datagram.source, &datagram.bytes, now);
                }
            }
            if captured.is_some() {
                break;
            }
        }
        let pong = captured.expect("captured path PONG");
        assert_eq!(pong.source, pair.b_endpoint);
        let sequence = parse_frame(&pong.bytes)
            .expect("PONG header")
            .header
            .sequence;
        assert!(pair.a.snapshot(now).selected_endpoint.is_none());
        let highest = pair.a.hs.session().expect("session").rx.highest();
        let round_trips = pair.a.snapshot(now).round_trips;

        pair.a.handle_datagram(endpoint(41_100), &pong.bytes, now);
        assert!(pair.a.snapshot(now).selected_endpoint.is_none());
        assert_eq!(pair.a.snapshot(now).round_trips, round_trips);
        assert_eq!(pair.a.hs.session().expect("session").rx.highest(), highest);

        // Rejecting the wrong-source copy must leave both the pending nonce and
        // sequence available so the identical authentic PONG still succeeds.
        pair.a.handle_datagram(pair.b_endpoint, &pong.bytes, now);
        assert_eq!(
            pair.a.snapshot(now).selected_endpoint,
            Some(pair.b_endpoint)
        );
        assert_eq!(pair.a.snapshot(now).round_trips, round_trips + 1);
        assert_eq!(
            pair.a.hs.session().expect("session").rx.highest(),
            Some(sequence)
        );
    }

    #[test]
    fn unknown_pong_nonce_does_not_advance_replay_or_health() {
        let mut pair = pair();
        let now = establish(&mut pair, START);
        let highest = pair.b.hs.session().expect("session").rx.highest();
        let round_trips = pair.b.snapshot(now).round_trips;
        let rejected = pair.b.snapshot(now).counters.control_rejected;
        let pong = forged_pong(&pair.a, [0x77; 32], u64::MAX - 5_000, now);

        pair.b.handle_datagram(pair.a_endpoint, &pong, now);
        assert_eq!(pair.b.hs.session().expect("session").rx.highest(), highest);
        assert_eq!(pair.b.snapshot(now).round_trips, round_trips);
        assert_eq!(pair.b.snapshot(now).counters.control_rejected, rejected + 1);
    }

    #[test]
    fn offline_rebuilds_a_session_and_rejects_old_data() {
        let mut pair = pair();
        let mut now = establish(&mut pair, START);
        let old_session = pair.a.snapshot(now).session_id.expect("old session");
        pair.a
            .send_ipv4(&ipv4(A_VIP, B_VIP, 16, 0), now)
            .expect("old DATA");
        let old_frame = pair.a.next_udp_frame().expect("old DATA frame");

        // Drain every datagram without delivery while advancing only the mock
        // clock. No sockets, sleeps or privileged operations are involved.
        // Include the 30-second offline detection plus the existing handshake's
        // 90-second attempt TTL, then restore inside the fresh attempt's bounded
        // retransmission window. The proven P0 retry schedule remains intact.
        for _ in 0..125 {
            now += 1_000;
            pair.a.tick(now);
            pair.b.tick(now);
            pump(&mut pair, now, false);
        }
        assert!(pair.a.snapshot(now).selected_endpoint.is_none());
        assert!(pair.b.snapshot(now).selected_endpoint.is_none());
        assert!(pair.a.snapshot(now).counters.reconnects >= 1);
        assert!(pair.b.snapshot(now).counters.reconnects >= 1);

        now = establish(&mut pair, now + 1);
        let new_session = pair.a.snapshot(now).session_id.expect("new session");
        assert_ne!(old_session, new_session);
        pair.b
            .handle_datagram(pair.a_endpoint, &old_frame.bytes, now);
        assert!(pair.b.next_ipv4_packet().is_none());

        let new_packet = ipv4(A_VIP, B_VIP, 16, 0);
        pair.a.send_ipv4(&new_packet, now).expect("new DATA");
        pump(&mut pair, now, true);
        assert_eq!(pair.b.next_ipv4_packet(), Some(new_packet));
    }

    #[test]
    fn close_clears_pending_work_and_is_terminal() {
        let mut pair = pair();
        let now = establish(&mut pair, START);
        pair.a
            .send_ipv4(&ipv4(A_VIP, B_VIP, 16, 0), now)
            .expect("queue before close");
        pair.a.close();
        assert!(pair.a.next_udp_frame().is_none());
        assert!(pair.a.next_ipv4_packet().is_none());
        assert!(pair.a.snapshot(now).closed);
        pair.a.tick(now + 1_000);
        assert!(pair.a.next_udp_frame().is_none());
        assert_eq!(
            pair.a.send_ipv4(&ipv4(A_VIP, B_VIP, 0, 0), now),
            Err(SendError::Closed)
        );
    }

    #[test]
    fn header_length_is_exact_even_for_an_authenticated_data_frame() {
        let mut pair = pair();
        let now = establish(&mut pair, START);
        let mut packet = ipv4(A_VIP, B_VIP, 20, 0);
        let wrong_total_len = packet.len() as u16 - 1;
        packet[2..4].copy_from_slice(&wrong_total_len.to_be_bytes());
        let mut header = Ipv4HeaderSlice::from_slice(&packet)
            .expect("header")
            .to_header();
        header.header_checksum = header.calc_header_checksum();
        packet[..Ipv4Header::MIN_LEN].copy_from_slice(&header.to_bytes()[..Ipv4Header::MIN_LEN]);
        let highest = pair.b.hs.session().expect("session").rx.highest();
        let forged = forged_data(&pair.a, &packet, u64::MAX - 5_000);
        pair.b.handle_datagram(pair.a_endpoint, &forged, now);
        assert!(pair.b.next_ipv4_packet().is_none());
        assert_eq!(pair.b.hs.session().expect("session").rx.highest(), highest);
    }

    use crate::path::{LanSubnet, PathCandidate, PathEndpoint, PathKind, TransportPolicy};
    use lzh_hole_types::TransportId;

    fn lan_endpoint(host: u8) -> Endpoint {
        Endpoint::new(Ipv4Addr::new(192, 168, 7, host), 42000)
    }
    fn lan_policy(id: u64, host: u8) -> TransportPolicy {
        TransportPolicy {
            transport: TransportId(id),
            local_endpoint: lan_endpoint(host),
            lan_subnets: vec![LanSubnet {
                address: lan_endpoint(host).ip,
                prefix_len: 24,
            }],
        }
    }
    fn lan_candidate(id: u64, host: u8) -> PathCandidate {
        PathCandidate {
            path: PathEndpoint {
                transport: TransportId(id),
                remote: lan_endpoint(host),
            },
            kind: PathKind::Lan,
        }
    }
    fn lan_pair() -> Pair {
        let mut pair = pair();
        pair.a_endpoint = lan_endpoint(1);
        pair.b_endpoint = lan_endpoint(2);
        pair.a
            .set_transports(&[lan_policy(11, 1), lan_policy(12, 3)]);
        pair.b
            .set_transports(&[lan_policy(21, 2), lan_policy(22, 4)]);
        pair.a.set_paths(&[lan_candidate(11, 2)]);
        pair.b.set_paths(&[lan_candidate(21, 1)]);
        pair
    }
    fn pump_lan(pair: &mut Pair, now: u64) {
        for _ in 0..32 {
            let mut progress = false;
            while let Some(frame) = pair.a.next_udp_frame() {
                assert_eq!(frame.transport, TransportId(11));
                assert_eq!(frame.target, pair.b_endpoint);
                pair.b
                    .handle_datagram_on(TransportId(21), pair.a_endpoint, &frame.bytes, now);
                progress = true;
            }
            while let Some(frame) = pair.b.next_udp_frame() {
                assert_eq!(frame.transport, TransportId(21));
                assert_eq!(frame.target, pair.a_endpoint);
                pair.a
                    .handle_datagram_on(TransportId(11), pair.b_endpoint, &frame.bytes, now);
                progress = true;
            }
            if !progress {
                return;
            }
        }
        panic!("LAN queue did not converge");
    }
    fn establish_lan(pair: &mut Pair) -> u64 {
        for step in 0..200 {
            let now = START + step * 50;
            pair.a.tick(now);
            pair.b.tick(now);
            pump_lan(pair, now);
            if pair.a.snapshot(now).currently_healthy && pair.b.snapshot(now).currently_healthy {
                return now;
            }
        }
        panic!(
            "LAN pair not healthy: {:?} {:?}",
            pair.a.snapshot(START),
            pair.b.snapshot(START)
        );
    }

    #[test]
    fn lan_handshake_data_withdrawal_and_transport_removal() {
        let mut pair = lan_pair();
        let now = establish_lan(&mut pair);
        assert_eq!(
            pair.a.snapshot(now).selected_path,
            Some(lan_candidate(11, 2).path)
        );
        let packet = ipv4(A_VIP, B_VIP, 24, 0);
        pair.a.set_paths(&[]);
        assert!(pair.a.snapshot(now).currently_healthy);
        pair.a.send_ipv4(&packet, now).unwrap();
        pump_lan(&mut pair, now);
        assert_eq!(pair.b.next_ipv4_packet(), Some(packet));
        pair.a.set_paths(&[lan_candidate(12, 2)]);
        pair.a.remove_transport(TransportId(11));
        assert_eq!(pair.a.snapshot(now).selected_path, None);
        assert_eq!(pair.a.snapshot(now).candidate_count, 1);
        assert!(pair.a.next_udp_frame().is_none());
        pair.b.send_ipv4(&ipv4(B_VIP, A_VIP, 0, 0), now).unwrap();
        let stale = pair.b.next_udp_frame().unwrap();
        pair.a
            .handle_datagram_on(TransportId(11), pair.b_endpoint, &stale.bytes, now);
        assert!(pair.a.next_ipv4_packet().is_none());
        assert_eq!(pair.a.snapshot(now).session_id, None);
    }
    #[test]
    fn lan_policy_is_strict_even_when_legacy_test_filter_is_disabled() {
        let mut pair = lan_pair();
        let mut candidates = vec![lan_candidate(11, 2)];
        for host in [0, 1, 3, 255] {
            candidates.push(lan_candidate(11, host));
        }
        for ip in [
            "192.168.8.2",
            "10.203.0.1",
            "10.203.0.2",
            "198.18.0.1",
            "127.0.0.1",
            "8.8.8.8",
        ] {
            let mut candidate = lan_candidate(11, 2);
            candidate.path.remote.ip = ip.parse().unwrap();
            candidates.push(candidate);
        }
        candidates.push(lan_candidate(999, 2));
        let mut public = lan_candidate(11, 2);
        public.kind = PathKind::Public;
        candidates.push(public);
        let update = pair.a.set_paths(&candidates);
        assert_eq!(update.accepted, 1);
        assert_eq!(update.rejected, candidates.len() - 1);
        public.path.remote.ip = "8.8.8.8".parse().unwrap();
        assert_eq!(pair.a.set_paths(&[public]).accepted, 1);
    }
    #[test]
    fn unchanged_candidates_preserve_probe_timers() {
        let mut pair = lan_pair();
        pair.b.tick(START);
        while pair.b.next_udp_frame().is_some() {}
        assert_eq!(pair.b.candidates[0].last_probe_ms, Some(START));
        pair.b.set_paths(&[lan_candidate(21, 1)]);
        assert_eq!(pair.b.candidates[0].last_probe_ms, Some(START));
        pair.b.tick(START + 1);
        assert!(pair.b.next_udp_frame().is_none());
    }
    #[test]
    fn wrong_local_transport_cannot_accept_challenge_or_consume_pong() {
        let mut pair = lan_pair();
        pair.a.tick(START);
        let hello = pair.a.next_udp_frame().unwrap();
        pair.b
            .handle_datagram_on(TransportId(21), pair.a_endpoint, &hello.bytes, START);
        let challenge = pair.b.next_udp_frame().unwrap();
        pair.a
            .handle_datagram_on(TransportId(12), pair.b_endpoint, &challenge.bytes, START);
        assert_eq!(pair.a.snapshot(START).session_id, None);
        assert!(pair.a.next_udp_frame().is_none());
        pair.a
            .handle_datagram_on(TransportId(11), pair.b_endpoint, &challenge.bytes, START);
        pump_lan(&mut pair, START);
        let now = establish_lan(&mut pair);
        while pair.a.next_udp_frame().is_some() {}
        while pair.b.next_udp_frame().is_some() {}
        pair.a.tick(now + 6_000);
        while let Some(ping) = pair.a.next_udp_frame() {
            pair.b
                .handle_datagram_on(TransportId(21), pair.a_endpoint, &ping.bytes, now + 6_000);
        }
        let pong = std::iter::from_fn(|| pair.b.next_udp_frame())
            .find(|frame| {
                parse_frame(&frame.bytes).unwrap().header.frame_type == FrameType::CtrlPong
            })
            .expect("health PONG");
        let highest = pair.a.hs.session().unwrap().rx.highest();
        let trips = pair.a.snapshot(now + 6_000).round_trips;
        pair.a
            .handle_datagram_on(TransportId(12), pair.b_endpoint, &pong.bytes, now + 6_000);
        assert_eq!(pair.a.hs.session().unwrap().rx.highest(), highest);
        assert_eq!(pair.a.snapshot(now + 6_000).round_trips, trips);
        pair.a
            .handle_datagram_on(TransportId(11), pair.b_endpoint, &pong.bytes, now + 6_000);
        assert_eq!(pair.a.snapshot(now + 6_000).round_trips, trips + 1);
    }
    #[test]
    fn multiple_paths_choose_exactly_one_finish_transcript() {
        let mut pair = lan_pair();
        pair.a
            .set_paths(&[lan_candidate(11, 2), lan_candidate(12, 2)]);
        pair.a.tick(START);
        let first = pair.a.next_udp_frame().unwrap();
        let second = pair.a.next_udp_frame().unwrap();
        pair.b
            .handle_datagram_on(TransportId(21), pair.a_endpoint, &first.bytes, START);
        let challenge1 = pair.b.next_udp_frame().unwrap();
        pair.b
            .handle_datagram_on(TransportId(22), lan_endpoint(3), &second.bytes, START);
        let challenge2 = pair.b.next_udp_frame().unwrap();
        pair.a
            .handle_datagram_on(first.transport, pair.b_endpoint, &challenge1.bytes, START);
        let winner = pair.a.snapshot(START).session_id;
        pair.a
            .handle_datagram_on(second.transport, pair.b_endpoint, &challenge2.bytes, START);
        assert_eq!(pair.a.snapshot(START).session_id, winner);
        let mut finishes = 0;
        while let Some(frame) = pair.a.next_udp_frame() {
            if parse_frame(&frame.bytes).unwrap().header.frame_type == FrameType::Finish {
                finishes += 1;
                assert_eq!(frame.transport, first.transport);
            }
        }
        assert_eq!(finishes, 1);
        assert_eq!(pair.a.hs.shadow_len(), 0);
    }
    #[test]
    fn control_probe_budget_is_bounded_without_throttling_data() {
        let mut pair = lan_pair();
        let now = establish_lan(&mut pair) + 1_000;
        while pair.a.next_udp_frame().is_some() {}
        let path = lan_candidate(11, 2).path;
        for _ in 0..20 {
            pair.a.send_responder_probe(path, now);
        }
        assert_eq!(pair.a.snapshot(now).queued_udp_frames, 2);
        for _ in 0..12 {
            pair.a.send_ipv4(&ipv4(A_VIP, B_VIP, 0, 0), now).unwrap();
        }
        assert_eq!(pair.a.snapshot(now).queued_udp_frames, 14);
        let mut budget = super::super::ProbeBudget::default();
        for host in 2..12 {
            assert!(budget.allow(lan_candidate(11, host).path, now));
        }
        assert!(!budget.allow(lan_candidate(11, 13).path, now));
        assert!(budget.allow(path, now + 1_000));
    }
    #[test]
    fn authenticated_probe_seeds_one_sided_discovery_without_duplicates() {
        let mut pair = lan_pair();
        pair.a.set_paths(&[]);
        pair.b.tick(START);
        let probe = pair.b.next_udp_frame().unwrap();
        let mut corrupt = probe.bytes.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        pair.a
            .handle_datagram_on(TransportId(11), pair.b_endpoint, &corrupt, START);
        assert_eq!(pair.a.snapshot(START).candidate_count, 0);
        for _ in 0..20 {
            pair.a
                .handle_datagram_on(TransportId(11), pair.b_endpoint, &probe.bytes, START);
        }
        assert_eq!(pair.a.snapshot(START).candidate_count, 1);
        assert!(pair.a.next_udp_frame().is_none());
        establish_lan(&mut pair);
    }
    #[test]
    fn sessionless_policy_and_finish_are_bound_to_actual_transport() {
        let mut pair = lan_pair();
        pair.a.tick(START);
        let hello = pair.a.next_udp_frame().unwrap();
        for source in [
            lan_endpoint(0),
            lan_endpoint(255),
            lan_endpoint(2),
            Endpoint::new(A_VIP, 42),
        ] {
            pair.b
                .handle_datagram_on(TransportId(21), source, &hello.bytes, START);
            assert!(pair.b.next_udp_frame().is_none());
        }
        pair.b
            .handle_datagram_on(TransportId(999), pair.a_endpoint, &hello.bytes, START);
        assert!(pair.b.next_udp_frame().is_none());
        pair.b
            .handle_datagram_on(TransportId(21), pair.a_endpoint, &hello.bytes, START);
        let challenge = pair.b.next_udp_frame().unwrap();
        pair.a
            .handle_datagram_on(TransportId(11), pair.b_endpoint, &challenge.bytes, START);
        let finish = pair.a.next_udp_frame().unwrap();
        assert_eq!(
            parse_frame(&finish.bytes).unwrap().header.frame_type,
            FrameType::Finish
        );
        pair.b
            .handle_datagram_on(TransportId(22), pair.a_endpoint, &finish.bytes, START);
        assert_eq!(pair.b.snapshot(START).session_id, None);
        assert!(pair.b.next_udp_frame().is_none());
        pair.b
            .handle_datagram_on(TransportId(21), pair.a_endpoint, &finish.bytes, START);
        assert!(pair.b.snapshot(START).session_id.is_some());
    }
    fn public_endpoint(from_a: bool) -> Endpoint {
        Endpoint::new(
            if from_a {
                Ipv4Addr::new(8, 8, 8, 1)
            } else {
                Ipv4Addr::new(9, 9, 9, 2)
            },
            42000,
        )
    }
    fn public_candidate(from_a: bool) -> PathCandidate {
        PathCandidate {
            path: PathEndpoint {
                transport: TransportId(if from_a { 12 } else { 22 }),
                remote: public_endpoint(!from_a),
            },
            kind: PathKind::Public,
        }
    }
    fn deliver_dual(pair: &mut Pair, from_a: bool, frame: crate::engine::UdpFrame, now: u64) {
        let lan = frame.transport == TransportId(if from_a { 11 } else { 21 });
        assert_eq!(
            frame.transport,
            TransportId(if from_a {
                if lan { 11 } else { 12 }
            } else if lan {
                21
            } else {
                22
            })
        );
        let source = if lan {
            if from_a {
                pair.a_endpoint
            } else {
                pair.b_endpoint
            }
        } else {
            public_endpoint(from_a)
        };
        assert_eq!(
            frame.target,
            if lan {
                if from_a {
                    pair.b_endpoint
                } else {
                    pair.a_endpoint
                }
            } else {
                public_endpoint(!from_a)
            }
        );
        let receiver = if from_a { &mut pair.b } else { &mut pair.a };
        receiver.handle_datagram_on(
            TransportId(if from_a {
                if lan { 21 } else { 22 }
            } else if lan {
                11
            } else {
                12
            }),
            source,
            &frame.bytes,
            now,
        );
    }
    fn pump_dual(pair: &mut Pair, now: u64) {
        for _ in 0..32 {
            let mut progress = false;
            while let Some(frame) = pair.a.next_udp_frame() {
                deliver_dual(pair, true, frame, now);
                progress = true;
            }
            while let Some(frame) = pair.b.next_udp_frame() {
                deliver_dual(pair, false, frame, now);
                progress = true;
            }
            if !progress {
                return;
            }
        }
        panic!("dual-path queue did not converge");
    }
    #[test]
    fn reordered_dual_lan_public_paths_verify_only_the_reciprocal_handshake_winner() {
        for lan_wins in [true, false] {
            let mut pair = lan_pair();
            let a_lan = lan_candidate(11, 2);
            let b_lan = lan_candidate(21, 1);
            pair.a.set_paths(&[public_candidate(true), a_lan]);
            pair.b.set_paths(&[b_lan, public_candidate(false)]);
            pair.a.tick(START);
            let hellos = std::iter::from_fn(|| pair.a.next_udp_frame()).collect::<Vec<_>>();
            assert_eq!(hellos.len(), 2);
            for hello in hellos {
                deliver_dual(&mut pair, true, hello, START);
            }
            let mut challenges = std::iter::from_fn(|| pair.b.next_udp_frame()).collect::<Vec<_>>();
            assert_eq!(challenges.len(), 2);
            let winning_b = TransportId(if lan_wins { 21 } else { 22 });
            let winner_index = challenges
                .iter()
                .position(|f| f.transport == winning_b)
                .unwrap();
            let winning_challenge = challenges.remove(winner_index);
            deliver_dual(&mut pair, false, winning_challenge, START);
            deliver_dual(&mut pair, false, challenges.remove(0), START + 1);
            let a_frames = std::iter::from_fn(|| pair.a.next_udp_frame()).collect::<Vec<_>>();
            let finish = a_frames
                .iter()
                .find(|f| parse_frame(&f.bytes).unwrap().header.frame_type == FrameType::Finish)
                .unwrap()
                .clone();
            let a_ping = a_frames
                .iter()
                .find(|f| parse_frame(&f.bytes).unwrap().header.frame_type == FrameType::CtrlPing)
                .unwrap()
                .clone();
            assert_eq!(a_frames.len(), 2);
            let winning_a = TransportId(if lan_wins { 11 } else { 12 });
            assert_eq!(finish.transport, winning_a);
            assert_eq!(a_ping.transport, winning_a);
            deliver_dual(&mut pair, true, finish, START + 1);
            assert_eq!(pair.a.path_probes.len(), 1);
            assert_eq!(pair.b.path_probes.len(), 1);
            let b_frames = std::iter::from_fn(|| pair.b.next_udp_frame()).collect::<Vec<_>>();
            assert_eq!(b_frames.len(), 2);
            for frame in b_frames {
                assert_eq!(frame.transport, winning_b);
                deliver_dual(&mut pair, false, frame, START + 2);
            }
            let pong_to_b = std::iter::from_fn(|| pair.a.next_udp_frame())
                .find(|f| parse_frame(&f.bytes).unwrap().header.frame_type == FrameType::CtrlPong)
                .unwrap();
            deliver_dual(&mut pair, true, pong_to_b, START + 3);
            assert_eq!(
                pair.b.snapshot(START + 3).selected_path.unwrap().transport,
                winning_b
            );
            assert!(pair.a.snapshot(START + 3).selected_path.is_none());
            deliver_dual(&mut pair, true, a_ping, START + 4);
            let pong_to_a = std::iter::from_fn(|| pair.b.next_udp_frame())
                .find(|f| parse_frame(&f.bytes).unwrap().header.frame_type == FrameType::CtrlPong)
                .unwrap();
            let highest = pair.a.hs.session().unwrap().rx.highest();
            pair.a.handle_datagram_on(
                TransportId(if lan_wins { 12 } else { 11 }),
                if lan_wins {
                    public_endpoint(false)
                } else {
                    pair.b_endpoint
                },
                &pong_to_a.bytes,
                START + 5,
            );
            assert!(pair.a.snapshot(START + 5).selected_path.is_none());
            assert_eq!(pair.a.hs.session().unwrap().rx.highest(), highest);
            deliver_dual(&mut pair, false, pong_to_a, START + 100);
            let a_selected = if lan_wins {
                a_lan.path
            } else {
                public_candidate(true).path
            };
            let b_selected = if lan_wins {
                b_lan.path
            } else {
                public_candidate(false).path
            };
            assert_eq!(pair.a.snapshot(START + 100).selected_path, Some(a_selected));
            assert_eq!(pair.b.snapshot(START + 100).selected_path, Some(b_selected));
            assert_eq!(
                pair.a.snapshot(START).session_id,
                pair.b.snapshot(START).session_id
            );
            let mut now = START + 100;
            for _ in 0..100 {
                now += 50;
                pair.a.tick(now);
                pair.b.tick(now);
                pump_dual(&mut pair, now);
                if pair.a.snapshot(now).currently_healthy && pair.b.snapshot(now).currently_healthy
                {
                    break;
                }
            }
            assert!(pair.a.snapshot(now).currently_healthy);
            assert!(pair.b.snapshot(now).currently_healthy);
            pair.a.set_paths(&[if lan_wins {
                public_candidate(true)
            } else {
                a_lan
            }]);
            pair.b.set_paths(&[if lan_wins {
                public_candidate(false)
            } else {
                b_lan
            }]);
            let ab = ipv4(A_VIP, B_VIP, 20, 0);
            let ba = ipv4(B_VIP, A_VIP, 24, 0);
            pair.a.send_ipv4(&ab, now).unwrap();
            pair.b.send_ipv4(&ba, now).unwrap();
            pump_dual(&mut pair, now);
            assert_eq!(pair.a.next_ipv4_packet(), Some(ba));
            assert_eq!(pair.b.next_ipv4_packet(), Some(ab));
            assert_eq!(pair.a.snapshot(now).selected_path, Some(a_selected));
            assert_eq!(pair.b.snapshot(now).selected_path, Some(b_selected));
        }
    }
    fn authenticated_probe(sender: &PeerEngine, nonce: u64, now: u64) -> Vec<u8> {
        let mut probe_nonce = [0; 32];
        probe_nonce[..8].copy_from_slice(&nonce.to_be_bytes());
        encode_frame(
            FrameType::Probe,
            crate::wire::Direction::HiToLo,
            sender.relationship_id,
            0,
            0,
            &crate::wire::ProbePayload {
                sender: sender.self_key,
                receiver: sender.peer_key,
                boot_id: sender.boot_id,
                generation: sender.generation,
                issued_at_unix_ms: now,
                probe_nonce,
            }
            .encode(),
            &sender.hs.probe_key(),
        )
        .unwrap()
    }
    #[test]
    fn probe_replay_is_source_independent_and_learned_hints_survive_refresh() {
        let mut pair = lan_pair();
        pair.a.set_paths(&[]);
        let probe = authenticated_probe(&pair.b, 1, START);
        let mut bad = probe.clone();
        *bad.last_mut().unwrap() ^= 1;
        let before = pair.a.hs.state_bytes();
        pair.a
            .handle_datagram_on(TransportId(11), pair.b_endpoint, &bad, START);
        assert_eq!(pair.a.hs.state_bytes(), before);
        pair.a
            .handle_datagram_on(TransportId(11), pair.b_endpoint, &probe, START);
        let state_bytes = pair.a.hs.state_bytes();
        for host in 5..20 {
            pair.a
                .handle_datagram_on(TransportId(12), lan_endpoint(host), &probe, START + 1);
        }
        assert_eq!(pair.a.hs.state_bytes(), state_bytes);
        assert_eq!(pair.a.snapshot(START).candidate_count, 1);
        pair.a.set_paths(&[lan_candidate(11, 9)]);
        assert_eq!(pair.a.snapshot(START).candidate_count, 2);
        pair.a.set_paths(&[]);
        assert_eq!(pair.a.snapshot(START).candidate_count, 1);
        pair.a.remove_transport(TransportId(11));
        assert_eq!(pair.a.snapshot(START).candidate_count, 0);
        pair.a
            .set_transports(&[lan_policy(13, 1), lan_policy(12, 3)]);
        pair.a
            .handle_datagram_on(TransportId(13), pair.b_endpoint, &probe, START + 2);
        assert_eq!(pair.a.snapshot(START).candidate_count, 0);
        let fresh = authenticated_probe(&pair.b, 2, START + 3);
        pair.a
            .handle_datagram_on(TransportId(13), pair.b_endpoint, &fresh, START + 3);
        assert_eq!(pair.a.snapshot(START).candidate_count, 1);
        pair.a.set_paths(&[]);
        pair.a
            .tick(START + 3 + crate::handshake::CLOCK_SKEW_TOLERANCE_MS);
        assert_eq!(pair.a.snapshot(START).candidate_count, 0);
    }
    #[test]
    fn probe_dedup_cache_is_bounded_and_does_not_evict_live_nonces() {
        let mut pair = lan_pair();
        pair.a.set_paths(&[]);
        for nonce in 0..crate::handshake::MAX_SEEN_PROBES as u64 {
            let probe = authenticated_probe(&pair.b, nonce, START);
            pair.a
                .handle_datagram_on(TransportId(11), pair.b_endpoint, &probe, START);
        }
        let full = pair.a.hs.state_bytes();
        let probe = authenticated_probe(&pair.b, 999, START);
        pair.a
            .handle_datagram_on(TransportId(11), lan_endpoint(9), &probe, START);
        assert_eq!(pair.a.hs.state_bytes(), full);
        assert_eq!(pair.a.snapshot(START).candidate_count, 1);
        let original = authenticated_probe(&pair.b, 0, START);
        pair.a
            .handle_datagram_on(TransportId(12), lan_endpoint(8), &original, START);
        assert_eq!(pair.a.snapshot(START).candidate_count, 1);
        let later = START + crate::handshake::CLOCK_SKEW_TOLERANCE_MS + 1;
        pair.a.tick(later);
        pair.a
            .handle_datagram_on(TransportId(12), lan_endpoint(8), &original, later);
        assert_eq!(pair.a.snapshot(later).candidate_count, 0);
        let fresh = authenticated_probe(&pair.b, 1000, later);
        pair.a
            .handle_datagram_on(TransportId(12), lan_endpoint(8), &fresh, later);
        assert_eq!(pair.a.snapshot(later).candidate_count, 1);
    }
    #[test]
    fn initial_hellos_retries_and_probes_share_the_relationship_budget() {
        let mut pair = lan_pair();
        let paths = (5..21)
            .map(|host| lan_candidate(11, host))
            .collect::<Vec<_>>();
        assert_eq!(pair.a.set_paths(&paths).accepted, 16);
        let mut counts = std::collections::HashMap::<PathEndpoint, usize>::new();
        for second in 0..4 {
            if second == 0 {
                pair.a.send_responder_probe(paths[0].path, START);
                pair.a.send_responder_probe(paths[0].path, START);
            }
            for _ in 0..3 {
                pair.a.tick(START + second * 1_000);
            }
            let frames = std::iter::from_fn(|| pair.a.next_udp_frame()).collect::<Vec<_>>();
            assert!(frames.len() <= 10);
            let mut per_path = std::collections::HashMap::<PathEndpoint, usize>::new();
            for frame in frames {
                let path = PathEndpoint {
                    transport: frame.transport,
                    remote: frame.target,
                };
                *per_path.entry(path).or_default() += 1;
                match parse_frame(&frame.bytes).unwrap().header.frame_type {
                    FrameType::Hello => *counts.entry(path).or_default() += 1,
                    FrameType::Probe => assert_eq!(second, 0),
                    other => panic!("unexpected proactive frame {other:?}"),
                }
            }
            assert!(per_path.values().all(|count| *count <= 2));
        }
        assert_eq!(counts.len(), 16);
        assert!(counts.values().any(|count| *count > 1));
    }
    #[test]
    fn transport_prefix_refresh_invalidates_only_disallowed_paths() {
        let mut pair = lan_pair();
        let now = establish_lan(&mut pair);
        let selected = pair.a.snapshot(now).selected_path;
        let mut narrowed = lan_policy(11, 1);
        narrowed.lan_subnets[0].prefix_len = 29;
        pair.a
            .set_transports(&[narrowed.clone(), lan_policy(12, 3)]);
        assert_eq!(pair.a.snapshot(now).selected_path, selected);
        assert!(pair.a.snapshot(now).currently_healthy);
        narrowed.lan_subnets = vec![LanSubnet {
            address: Ipv4Addr::new(192, 168, 8, 1),
            prefix_len: 24,
        }];
        pair.a
            .set_paths(&[lan_candidate(11, 2), lan_candidate(12, 2)]);
        pair.a.set_transports(&[narrowed, lan_policy(12, 3)]);
        assert_eq!(pair.a.snapshot(now).selected_path, None);
        assert_eq!(pair.a.snapshot(now).session_id, None);
        assert_eq!(pair.a.snapshot(now).candidate_count, 1);
        let mut alias = lan_candidate(11, 2);
        alias.path.remote.ip = Ipv4Addr::new(192, 168, 8, 2);
        assert_eq!(pair.a.set_paths(&[alias]).accepted, 0);
    }
    #[test]
    fn changed_bound_address_requires_a_new_transport_id() {
        let mut pair = lan_pair();
        let now = establish_lan(&mut pair);
        pair.a
            .set_transports(&[lan_policy(11, 5), lan_policy(12, 3)]);
        assert!(pair.a.snapshot(now).selected_path.is_none());
        assert!(
            pair.a
                .transports
                .as_ref()
                .unwrap()
                .iter()
                .all(|p| p.transport != TransportId(11))
        );
        assert_eq!(pair.a.set_paths(&[lan_candidate(11, 2)]).accepted, 0);
    }
    #[test]
    fn narrower_same_link_prefix_clears_disallowed_selected_path() {
        let mut pair = pair();
        pair.a_endpoint = lan_endpoint(1);
        pair.b_endpoint = lan_endpoint(130);
        pair.a.set_transports(&[lan_policy(11, 1)]);
        pair.b.set_transports(&[lan_policy(21, 130)]);
        pair.a.set_paths(&[lan_candidate(11, 130)]);
        pair.b.set_paths(&[lan_candidate(21, 1)]);
        let now = establish_lan(&mut pair);
        let mut narrowed = lan_policy(11, 1);
        narrowed.lan_subnets[0].prefix_len = 25;
        pair.a.set_transports(&[narrowed]);
        assert!(pair.a.snapshot(now).session_id.is_none());
        assert!(pair.a.snapshot(now).selected_path.is_none());
        assert_eq!(pair.a.snapshot(now).candidate_count, 0);
        assert!(pair.a.next_udp_frame().is_none());
    }
    #[test]
    fn full_outbox_defers_mandatory_finish_without_spending_retries() {
        let mut pair = lan_pair();
        pair.a.tick(START);
        let hello = pair.a.next_udp_frame().unwrap();
        pair.b
            .handle_datagram_on(TransportId(21), pair.a_endpoint, &hello.bytes, START);
        let challenge = pair.b.next_udp_frame().unwrap();
        for _ in 0..crate::engine::MAX_UDP_OUTBOX {
            assert!(pair.a.queue_frame(lan_candidate(11, 2).path, vec![]));
        }
        for second in 0..20 {
            pair.a.handle_datagram_on(
                TransportId(11),
                pair.b_endpoint,
                &challenge.bytes,
                START + second * 1_000,
            );
        }
        assert!(pair.a.snapshot(START).session_id.is_none());
        while pair.a.next_udp_frame().is_some() {}
        pair.a.handle_datagram_on(
            TransportId(11),
            pair.b_endpoint,
            &challenge.bytes,
            START + 20_000,
        );
        let finish = pair.a.next_udp_frame().unwrap();
        assert_eq!(
            parse_frame(&finish.bytes).unwrap().header.frame_type,
            FrameType::Finish
        );
        assert!(pair.a.snapshot(START + 20_000).session_id.is_some());
    }
    // ---- hole punching ----

    const PUNCH_PEER: Ipv4Addr = Ipv4Addr::new(210, 22, 105, 194);

    fn punch_config(
        role: crate::punch::PunchRole,
        me: DiscoveryPublicKey,
        peer: DiscoveryPublicKey,
        boot: [u8; 16],
        direction: crate::wire::Direction,
    ) -> crate::punch::PunchConfig {
        crate::punch::PunchConfig {
            role,
            peer_endpoint: Endpoint::new(PUNCH_PEER, 40_000),
            local_key: me,
            peer_key: peer,
            relationship_id: RelationshipId::from_bytes([9; 16]),
            boot_id: BootId::from_bytes(boot),
            generation: 1,
            direction,
            hard_sockets: 4,
        }
    }

    fn punch_pair() -> (PeerEngine, PeerEngine) {
        let a = engine(
            DiscoveryPublicKey::from_bytes([1; 32]),
            DiscoveryPublicKey::from_bytes([2; 32]),
            [1; 16],
            A_VIP,
            B_VIP,
        );
        let b = engine(
            DiscoveryPublicKey::from_bytes([2; 32]),
            DiscoveryPublicKey::from_bytes([1; 32]),
            [2; 16],
            B_VIP,
            A_VIP,
        );
        (a, b)
    }

    fn nonces() -> impl FnMut() -> [u8; 32] {
        let mut n = 0u8;
        move || {
            n = n.wrapping_add(1);
            [n; 32]
        }
    }

    #[test]
    fn start_punch_refuses_a_second_attempt_and_stops_cleanly() {
        let (mut a, _b) = punch_pair();
        let config = punch_config(
            crate::punch::PunchRole::Easy,
            DiscoveryPublicKey::from_bytes([1; 32]),
            DiscoveryPublicKey::from_bytes([2; 32]),
            [1; 16],
            crate::wire::Direction::LoToHi,
        );
        assert!(a.start_punch(config.clone(), START));
        assert!(a.punch_active());
        // A second attempt while one is running is refused.
        assert!(!a.start_punch(config.clone(), START));
        a.punch_tick(START, &mut nonces());
        assert!(a.next_punch_frame().is_some());
        a.stop_punch();
        assert!(!a.punch_active());
        assert!(a.next_punch_frame().is_none());
        assert!(a.take_punch_events().is_empty());
        // And a fresh attempt is accepted again afterwards.
        assert!(a.start_punch(config, START));
    }

    #[test]
    fn a_peer_punch_frame_promotes_a_slot_and_learns_the_endpoint() {
        use crate::punch::{PunchEvent, PunchRole};
        use crate::wire::Direction;

        let (mut a, mut b) = punch_pair();
        // a is lo and easy; b is hi and hard.
        assert!(a.start_punch(
            punch_config(
                PunchRole::Easy,
                DiscoveryPublicKey::from_bytes([1; 32]),
                DiscoveryPublicKey::from_bytes([2; 32]),
                [1; 16],
                Direction::LoToHi,
            ),
            START,
        ));
        assert!(b.start_punch(
            punch_config(
                PunchRole::Hard,
                DiscoveryPublicKey::from_bytes([2; 32]),
                DiscoveryPublicKey::from_bytes([1; 32]),
                [2; 16],
                Direction::HiToLo,
            ),
            START,
        ));

        // The easy side produces a grid frame; both sides derive the same
        // static punch key from the pinned relationship.
        a.punch_tick(START, &mut nonces());
        let frame = a.next_punch_frame().expect("a grid frame");
        assert_eq!(frame.target.ip, PUNCH_PEER);

        let source = Endpoint::new(PUNCH_PEER, 45_000);
        let before = b.snapshot(START).candidate_count;
        let events = b.handle_punch_datagram(2, TransportId(7), source, &frame.bytes, START);
        assert_eq!(
            events,
            vec![PunchEvent::Promote {
                slot: 2,
                peer: source
            }]
        );
        // The punch state recorded the hit. Confirmation frames are built on
        // the next tick, which is the only place holding the caller's RNG.
        let state = b.punch_state().expect("punch running");
        assert_eq!(state.hit_port(), Some(45_000));
        assert!(state.confirm_pending());
        assert!(
            b.next_punch_frame().is_none(),
            "nothing is queued before a tick"
        );
        b.punch_tick(START, &mut nonces());
        let confirm = b.next_punch_frame().expect("a confirmation is queued");
        assert_eq!(confirm.slot, 2, "from the winning slot");
        assert_eq!(confirm.target, source, "to the observed source");
        // The daemon can read the event back out of the queue as well.
        assert_eq!(
            b.take_punch_events(),
            vec![PunchEvent::Promote {
                slot: 2,
                peer: source
            }]
        );
        let _ = before;
        // No session was created and no sequence space was touched.
        assert!(b.snapshot(START).session_id.is_none());
    }

    #[test]
    fn a_punched_path_displaces_a_hint_and_starts_handshake_at_capacity() {
        use crate::engine::MAX_ENGINE_CANDIDATES;
        use crate::punch::{PunchEvent, PunchRole};
        use crate::wire::Direction;
        let (mut a, mut b) = punch_pair();
        let old = TransportPolicy {
            transport: TransportId(1),
            local_endpoint: Endpoint::new(Ipv4Addr::new(192, 168, 1, 2), 51_000),
            lan_subnets: Vec::new(),
        };
        let winner = TransportPolicy {
            transport: TransportId(7),
            local_endpoint: Endpoint::new(Ipv4Addr::new(192, 168, 1, 2), 52_000),
            lan_subnets: Vec::new(),
        };
        a.set_transports(std::slice::from_ref(&old));
        let hints = (0..MAX_ENGINE_CANDIDATES)
            .map(|index| PathCandidate {
                path: PathEndpoint {
                    transport: old.transport,
                    remote: Endpoint::new(PUNCH_PEER, 10_000 + index as u16),
                },
                kind: PathKind::Public,
            })
            .collect::<Vec<_>>();
        assert_eq!(a.set_paths(&hints).accepted, MAX_ENGINE_CANDIDATES);
        a.tick(START);
        while a.next_udp_frame().is_some() {}
        let now = START + 1_001;
        assert!(a.start_punch(
            punch_config(
                PunchRole::Hard,
                DiscoveryPublicKey::from_bytes([1; 32]),
                DiscoveryPublicKey::from_bytes([2; 32]),
                [1; 16],
                Direction::LoToHi
            ),
            now
        ));
        assert!(b.start_punch(
            punch_config(
                PunchRole::Easy,
                DiscoveryPublicKey::from_bytes([2; 32]),
                DiscoveryPublicKey::from_bytes([1; 32]),
                [2; 16],
                Direction::HiToLo
            ),
            now
        ));
        b.punch_tick(now, &mut nonces());
        let probe = b.next_punch_frame().unwrap();
        let source = Endpoint::new(PUNCH_PEER, 45_000);
        assert_eq!(
            a.handle_punch_datagram(2, winner.transport, source, &probe.bytes, now),
            vec![PunchEvent::Promote {
                slot: 2,
                peer: source
            }]
        );
        a.set_transports(&[old, winner]);
        assert_eq!(a.snapshot(now).candidate_count, MAX_ENGINE_CANDIDATES);
        a.tick(now);
        let frames = std::iter::from_fn(|| a.next_udp_frame()).collect::<Vec<_>>();
        assert!(frames.iter().any(|frame| frame.transport == TransportId(7)
            && frame.target == source
            && parse_frame(&frame.bytes).unwrap().header.frame_type == FrameType::Hello));
        a.set_paths(&hints);
        assert_eq!(a.snapshot(now).candidate_count, MAX_ENGINE_CANDIDATES);
        assert!(
            a.candidates
                .iter()
                .any(|candidate| candidate.path.transport == TransportId(7)),
            "discovery refresh preserves learned winner"
        );
    }

    #[test]
    fn a_learned_punch_endpoint_becomes_a_bounded_candidate() {
        use crate::punch::{PunchEvent, PunchRole};
        use crate::wire::Direction;

        // The easy side learns from a frame arriving on its data socket.
        let (mut a, mut b) = punch_pair();
        assert!(a.start_punch(
            punch_config(
                PunchRole::Easy,
                DiscoveryPublicKey::from_bytes([1; 32]),
                DiscoveryPublicKey::from_bytes([2; 32]),
                [1; 16],
                Direction::LoToHi,
            ),
            START,
        ));
        assert!(b.start_punch(
            punch_config(
                PunchRole::Hard,
                DiscoveryPublicKey::from_bytes([2; 32]),
                DiscoveryPublicKey::from_bytes([1; 32]),
                [2; 16],
                Direction::HiToLo,
            ),
            START,
        ));
        b.punch_tick(START, &mut nonces());
        let frame = b.next_punch_frame().expect("a hard-side frame");

        let source = Endpoint::new(PUNCH_PEER, 51_234);
        let before = a.snapshot(START).candidate_count;
        // Delivered on the ordinary data socket, so slot 0.
        let events = a.handle_punch_datagram(0, TransportId(3), source, &frame.bytes, START);
        assert_eq!(events, vec![PunchEvent::Learned { peer: source }]);
        assert_eq!(
            a.snapshot(START).candidate_count,
            before + 1,
            "a learned punch endpoint must become a candidate"
        );
        // Learning the same endpoint again refreshes rather than duplicates.
        let mut second = frame.bytes.clone();
        let last = second.len() - 33;
        second[last] ^= 0xff;
        // (a flipped nonce byte invalidates the MAC, so this must be ignored)
        a.handle_punch_datagram(0, TransportId(3), source, &second, START);
        assert_eq!(a.snapshot(START).candidate_count, before + 1);
    }

    #[test]
    fn punch_never_reaches_the_handshake_or_the_data_path() {
        use crate::punch::PunchRole;
        use crate::wire::Direction;

        let (mut a, _b) = punch_pair();
        // A punch frame with no punch running is dropped without touching any
        // other subsystem.
        let garbage = vec![0u8; 202];
        a.handle_datagram_on(TransportId(1), endpoint(41_003), &garbage, START);
        let snapshot = a.snapshot(START);
        assert!(snapshot.session_id.is_none());
        assert_eq!(snapshot.candidate_count, 0);

        // With a punch running, a forged punch frame is still refused: the
        // static punch key is not guessable.
        assert!(a.start_punch(
            punch_config(
                PunchRole::Easy,
                DiscoveryPublicKey::from_bytes([1; 32]),
                DiscoveryPublicKey::from_bytes([2; 32]),
                [1; 16],
                Direction::LoToHi,
            ),
            START,
        ));
        let forged = {
            let payload = crate::wire::PunchPayload {
                sender: DiscoveryPublicKey::from_bytes([2; 32]),
                receiver: DiscoveryPublicKey::from_bytes([1; 32]),
                boot_id: BootId::from_bytes([2; 16]),
                generation: 1,
                issued_at_unix_ms: START,
                punch_nonce: [0x77; 32],
            };
            encode_frame(
                FrameType::Punch,
                Direction::HiToLo,
                RelationshipId::from_bytes([9; 16]),
                0,
                0,
                &payload.encode(),
                &crate::crypto::Key32::from_bytes([0xab; 32]),
            )
            .unwrap()
        };
        let events = a.handle_punch_datagram(
            0,
            TransportId(3),
            Endpoint::new(PUNCH_PEER, 51_234),
            &forged,
            START,
        );
        assert!(events.is_empty(), "a forged punch frame must be refused");
        assert_eq!(a.snapshot(START).candidate_count, 0);
        assert!(a.snapshot(START).session_id.is_none());
    }

    #[test]
    fn a_learned_punch_endpoint_is_subject_to_the_target_policy() {
        use crate::punch::PunchRole;
        use crate::wire::Direction;

        let (mut a, mut b) = punch_pair();
        assert!(a.start_punch(
            punch_config(
                PunchRole::Easy,
                DiscoveryPublicKey::from_bytes([1; 32]),
                DiscoveryPublicKey::from_bytes([2; 32]),
                [1; 16],
                Direction::LoToHi,
            ),
            START,
        ));
        assert!(b.start_punch(
            punch_config(
                PunchRole::Hard,
                DiscoveryPublicKey::from_bytes([2; 32]),
                DiscoveryPublicKey::from_bytes([1; 32]),
                [2; 16],
                Direction::HiToLo,
            ),
            START,
        ));
        b.punch_tick(START, &mut nonces());
        let frame = b.next_punch_frame().expect("a hard-side frame");

        // A punch frame whose source is in a refused range is authenticated
        // but must not become a target.
        let reserved = Endpoint::new(Ipv4Addr::new(203, 0, 113, 9), 51_234);
        let events = a.handle_punch_datagram(0, TransportId(3), reserved, &frame.bytes, START);
        // A rejected source must not create a hit or queue confirmations.
        assert!(events.is_empty());
        assert!(!a.punch_state().unwrap().confirm_pending());
        assert_eq!(
            a.snapshot(START).candidate_count,
            0,
            "a documentation-range source must never become a candidate"
        );
    }
}
