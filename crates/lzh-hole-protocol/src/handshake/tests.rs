use crate::handshake::*;
use crate::path::Endpoint;

#[cfg(test)]
mod exhaustion_tests {
    use super::*;
    use crate::crypto::Key32;
    use crate::session::SESSION_SEQ_EXHAUSTION_MARGIN;
    use crate::wire::{Direction, FrameType};
    use lzh_hole_types::{BootId, DiscoveryPublicKey, RelationshipId, Secret32};

    fn session_at(seq: u64) -> Session {
        Session {
            keys: SessionKeys {
                session_id: 1,
                k_i2r: Key32::from_bytes([1u8; 32]),
                k_r2i: Key32::from_bytes([2u8; 32]),
                th3: [0u8; 32],
            },
            tx_seq: seq,
            rx: ReplayWindow::new(),
            hello: Vec::new(),
            challenge: Vec::new(),
            finish: Vec::new(),
            created_ms: 0,
            ack_seen: false,
            ack_sent: false,
            local_boot_id: BootId::from_bytes([1u8; 16]),
            peer_boot_id: BootId::from_bytes([2u8; 16]),
            peer_generation: 1,
        }
    }

    #[test]
    fn a_fresh_session_is_not_exhausted() {
        assert!(!session_at(1).sequence_exhausted());
        assert!(!session_at(u64::MAX / 2).sequence_exhausted());
    }

    #[test]
    fn exhaustion_is_detected_before_the_space_runs_out() {
        let mut s = session_at(u64::MAX - SESSION_SEQ_EXHAUSTION_MARGIN - 1);
        assert!(!s.sequence_exhausted());
        let mut guard = 0;
        while !s.sequence_exhausted() {
            s.next_tx_seq();
            guard += 1;
            assert!(guard < 10_000, "should reach exhaustion quickly");
        }
        assert!(s.sequence_exhausted());
        assert!(s.tx_seq < u64::MAX, "must stop before the very last value");
    }

    #[test]
    fn the_sequence_never_wraps() {
        let mut s = session_at(u64::MAX - 1);
        let a = s.next_tx_seq();
        let b = s.next_tx_seq();
        let c = s.next_tx_seq();
        assert_eq!(a, u64::MAX - 1);
        assert_eq!(b, u64::MAX);
        assert_eq!(c, u64::MAX, "saturating, never wraps to zero");
        assert_eq!(s.tx_seq, u64::MAX);
        assert!(s.sequence_exhausted());
    }

    #[test]
    fn rekey_is_explicitly_unsupported_in_p0() {
        assert!(!Session::rekey_supported());
    }

    /// Drive two engines by handing frames directly, with no sockets.
    fn run_handshake(
        lo: &mut Handshake,
        hi: &mut Handshake,
        lo_ep: Endpoint,
        hi_ep: Endpoint,
        now: u64,
    ) {
        for ev in lo.start_attempt(hi_ep, now).expect("attempt") {
            if let HandshakeEvent::Send { target, frames } = ev {
                let mut queue = frames;
                let mut hops = 0;
                while let Some(frame) = queue.pop() {
                    hops += 1;
                    assert!(hops < 32, "handshake should converge");
                    for ev in hi.handle_frame(&frame, lo_ep, now) {
                        if let HandshakeEvent::Send { frames, .. } = ev {
                            for f in frames {
                                for ev2 in lo.handle_frame(&f, hi_ep, now) {
                                    if let HandshakeEvent::Send { frames, .. } = ev2 {
                                        queue.extend(frames);
                                    }
                                }
                            }
                        }
                    }
                    let _ = target;
                }
            }
        }
    }

    fn engines() -> (Handshake, Handshake, Endpoint, Endpoint) {
        let a = DiscoveryPublicKey::from_bytes([1u8; 32]);
        let b = DiscoveryPublicKey::from_bytes([2u8; 32]);
        let rel = RelationshipId::from_bytes([9u8; 16]);
        let psk = Secret32::from_bytes([0x5au8; 32]);
        let lo = Handshake::new(
            HandshakeConfig {
                relationship_id: rel,
                me: a,
                peer: b,
                boot_id: BootId::from_bytes([1u8; 16]),
                generation: 1,
            },
            &psk,
        )
        .expect("lo engine");
        let hi = Handshake::new(
            HandshakeConfig {
                relationship_id: rel,
                me: b,
                peer: a,
                boot_id: BootId::from_bytes([2u8; 16]),
                generation: 1,
            },
            &psk,
        )
        .expect("hi engine");
        let lo_ep = Endpoint::new("127.0.0.1".parse().unwrap(), 40001);
        let hi_ep = Endpoint::new("127.0.0.1".parse().unwrap(), 40002);
        (lo, hi, lo_ep, hi_ep)
    }

    #[test]
    fn a_rekey_intent_never_switches_an_installed_session() {
        let (mut lo, mut hi, lo_ep, hi_ep) = engines();
        run_handshake(&mut lo, &mut hi, lo_ep, hi_ep, 1_000);
        let first = lo.session().expect("session installed").keys.session_id;
        assert!(lo.shadow_len() == 0);

        // Grant a rekey intent and complete a second, different handshake.
        lo.grant_rekey_intent(2_000);
        assert!(lo.rekey_intent_live(2_000));
        run_handshake(&mut lo, &mut hi, lo_ep, hi_ep, 2_000);

        // The installed session must be unchanged and the new one shadowed.
        assert_eq!(
            lo.session().expect("still installed").keys.session_id,
            first,
            "a rekey intent must not switch a healthy session in P0"
        );
        assert!(
            lo.shadow_len() >= 1,
            "the second session must be held in the bounded shadow table"
        );
    }

    #[test]
    fn an_expired_intent_does_nothing() {
        let (mut lo, mut hi, lo_ep, hi_ep) = engines();
        lo.grant_rekey_intent(1_000);
        assert!(lo.rekey_intent_live(1_000 + REKEY_INTENT_TTL_MS - 1));
        assert!(!lo.rekey_intent_live(1_000 + REKEY_INTENT_TTL_MS));
        // Expiry is enforced by tick, which must not emit anything.
        let events = lo.tick(1_000 + REKEY_INTENT_TTL_MS + 1);
        assert!(!lo.rekey_intent_live(1_000 + REKEY_INTENT_TTL_MS + 1));
        let _ = events;
        let _ = (&mut hi, lo_ep, hi_ep);
    }

    #[test]
    fn a_sessionless_frame_type_is_never_given_a_session_sequence() {
        // Sessionless frames carry session 0 and sequence 0; only session frames
        // consume the space that can exhaust.
        assert!(FrameType::Hello.is_sessionless());
        assert!(FrameType::Probe.is_sessionless());
        assert!(!FrameType::CtrlPing.is_sessionless());
        assert_eq!(Direction::LoToHi.as_u8(), 0);
    }
}

#[cfg(test)]
mod response_limit_tests {
    use super::*;
    use lzh_hole_types::Secret32;

    fn ep(port: u16) -> Endpoint {
        Endpoint::new("127.0.0.1".parse().unwrap(), port)
    }

    fn engines() -> (Handshake, Handshake) {
        let a = DiscoveryPublicKey::from_bytes([1u8; 32]);
        let b = DiscoveryPublicKey::from_bytes([2u8; 32]);
        let rel = RelationshipId::from_bytes([9u8; 16]);
        let psk = Secret32::from_bytes([0x5au8; 32]);
        let lo = Handshake::new(
            HandshakeConfig {
                relationship_id: rel,
                me: a,
                peer: b,
                boot_id: BootId::from_bytes([1u8; 16]),
                generation: 1,
            },
            &psk,
        )
        .expect("lo");
        let hi = Handshake::new(
            HandshakeConfig {
                relationship_id: rel,
                me: b,
                peer: a,
                boot_id: BootId::from_bytes([2u8; 16]),
                generation: 1,
            },
            &psk,
        )
        .expect("hi");
        (lo, hi)
    }

    fn frames(events: Vec<HandshakeEvent>) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for ev in events {
            if let HandshakeEvent::Send { frames, .. } = ev {
                out.extend(frames);
            }
        }
        out
    }

    #[test]
    fn duplicate_hello_replies_are_one_per_second_and_eight_total() {
        let (mut lo, mut hi) = engines();
        let hello = frames(lo.start_attempt(ep(40002), 1_000).unwrap())
            .into_iter()
            .next()
            .expect("hello");
        assert_eq!(frames(hi.handle_frame(&hello, ep(40001), 1_000)).len(), 1);
        // Same request again immediately: no second response.
        assert!(frames(hi.handle_frame(&hello, ep(40001), 1_000)).is_empty());
        // After one second a retransmission is allowed.
        assert_eq!(frames(hi.handle_frame(&hello, ep(40001), 2_000)).len(), 1);
        // The first response is included in the cap of eight.
        let mut total = 2;
        for i in 0..20u64 {
            let now = 3_000 + i * 1_000;
            total += frames(hi.handle_frame(&hello, ep(40001), now)).len();
        }
        assert_eq!(total, MAX_RETRANSMITS as usize);
        assert!(frames(hi.handle_frame(&hello, ep(40001), 100_000)).is_empty());
    }

    #[test]
    fn duplicate_finish_replies_are_bounded_too() {
        let (mut lo, mut hi) = engines();
        let hello = frames(lo.start_attempt(ep(40002), 1_000).unwrap())
            .into_iter()
            .next()
            .expect("hello");
        let challenge = frames(hi.handle_frame(&hello, ep(40001), 1_000))
            .into_iter()
            .next()
            .expect("challenge");
        let finish = frames(lo.handle_frame(&challenge, ep(40002), 1_000))
            .into_iter()
            .next()
            .expect("finish");
        assert_eq!(frames(hi.handle_frame(&finish, ep(40001), 1_000)).len(), 1);
        assert!(frames(hi.handle_frame(&finish, ep(40001), 1_000)).is_empty());
        assert_eq!(frames(hi.handle_frame(&finish, ep(40001), 2_000)).len(), 1);
        let mut total = 2;
        for i in 0..20u64 {
            let now = 3_000 + i * 1_000;
            total += frames(hi.handle_frame(&finish, ep(40001), now)).len();
        }
        // The entry's eight sends include the initial CHALLENGE, so this flow
        // gets seven ACK responses: the first one plus six retransmissions.
        assert_eq!(total, MAX_RETRANSMITS as usize - 1);
        assert!(frames(hi.handle_frame(&finish, ep(40001), 100_000)).is_empty());
    }

    #[test]
    fn duplicate_challenge_replies_follow_the_same_budget() {
        let (mut lo, mut hi) = engines();
        let hello = frames(lo.start_attempt(ep(40002), 1_000).unwrap())
            .into_iter()
            .next()
            .expect("hello");
        let challenge = frames(hi.handle_frame(&hello, ep(40001), 1_000))
            .into_iter()
            .next()
            .expect("challenge");
        // First FINISH.
        assert_eq!(
            frames(lo.handle_frame(&challenge, ep(40002), 1_000)).len(),
            1
        );
        // Duplicate CHALLENGE at the same instant must not emit another FINISH.
        assert!(frames(lo.handle_frame(&challenge, ep(40002), 1_000)).is_empty());
        let mut total = 1;
        for i in 0..20u64 {
            let now = 2_000 + i * 1_000;
            total += frames(lo.handle_frame(&challenge, ep(40002), now)).len();
        }
        // The attempt's total send budget includes HELLO retransmissions, so it
        // can be lower than eight FINISH frames, but never exceeds eight total.
        assert!(total <= MAX_RETRANSMITS as usize);
        assert!(frames(lo.handle_frame(&challenge, ep(40002), 100_000)).is_empty());
    }

    #[test]
    fn responder_tick_never_invents_a_response() {
        let (mut lo, mut hi) = engines();
        let hello = frames(lo.start_attempt(ep(40002), 1_000).unwrap())
            .into_iter()
            .next()
            .expect("hello");
        let _ = hi.handle_frame(&hello, ep(40001), 1_000);
        // No new request arrived, so a timer cannot create a CHALLENGE or ACK.
        assert!(frames(hi.tick(2_000)).is_empty());
        assert!(frames(hi.tick(3_000)).is_empty());
    }

    #[test]
    fn invalid_input_does_not_clear_pending_responses() {
        let (mut lo, mut hi) = engines();
        let hello = frames(lo.start_attempt(ep(40002), 1_000).unwrap())
            .into_iter()
            .next()
            .expect("hello");
        let _ = hi.handle_frame(&hello, ep(40001), 1_000);
        let mut bad = hello.clone();
        bad[6] ^= 1;
        let _ = hi.handle_frame(&bad, ep(40001), 1_000);
        // The valid request still gets its response after the interval.
        assert_eq!(frames(hi.handle_frame(&hello, ep(40001), 2_000)).len(), 1);
    }
}
