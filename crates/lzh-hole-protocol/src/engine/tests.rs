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
}
