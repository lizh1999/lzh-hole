//! Cross-check: the Rust codecs must reproduce the wire v1 test vectors
//! byte for byte.
//!
//! tests/fixtures/wire-v1.json is authoritative; the format it pins is
//! described in doc/protocol.md. These assertions check the Rust codecs
//! against fixed vectors rather than a snapshot of their own output.

use lzh_hole_discovery::record::{ContactRecord, RecordCandidate};
use lzh_hole_protocol::crypto::{
    LABEL_KDF_CHALLENGE, LABEL_KDF_FINISH, LABEL_KDF_HELLO, LABEL_KDF_KEY_I2R, LABEL_KDF_KEY_R2I,
    LABEL_KDF_SESSION_ID, extract_prk, frame_mac, info, transcript_hash,
};
use lzh_hole_protocol::path::{CandidateSource, Endpoint};
use lzh_hole_protocol::wire::{
    AckPayload, ChallengePayload, CtrlPayload, Direction, FinishPayload, FrameType, HelloPayload,
    ProbePayload, encode_frame,
};
use lzh_hole_types::{BootId, DiscoveryPublicKey, RelationshipId};
use serde_json::Value;
use sha2::{Digest, Sha256};

const FIXTURE: &str = include_str!("../../../tests/fixtures/wire-v1.json");

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("fixture parses")
}

fn field<'a>(v: &'a Value, section: &str, key: &str) -> &'a Value {
    v.get(section)
        .and_then(|s| s.get(key))
        .unwrap_or_else(|| panic!("fixture is missing {section}.{key}"))
}

fn text(v: &Value, section: &str, key: &str) -> String {
    field(v, section, key)
        .as_str()
        .unwrap_or_else(|| panic!("{section}.{key} is not a string"))
        .to_owned()
}

fn num(v: &Value, section: &str, key: &str) -> u64 {
    field(v, section, key)
        .as_u64()
        .unwrap_or_else(|| panic!("{section}.{key} is not a number"))
}

fn bytes(v: &Value, section: &str, key: &str) -> Vec<u8> {
    hex::decode(text(v, section, key)).unwrap_or_else(|e| panic!("{section}.{key}: {e}"))
}

fn bytes32(v: &Value, section: &str, key: &str) -> [u8; 32] {
    bytes(v, section, key)
        .try_into()
        .unwrap_or_else(|_| panic!("{section}.{key} is not 32 bytes"))
}

fn bytes16(v: &Value, section: &str, key: &str) -> [u8; 16] {
    bytes(v, section, key)
        .try_into()
        .unwrap_or_else(|_| panic!("{section}.{key} is not 16 bytes"))
}

/// Everything derived from the fixture inputs, rebuilt with the Rust codecs.
struct Built {
    prk: lzh_hole_protocol::Prk,
    lo: DiscoveryPublicKey,
    hi: DiscoveryPublicKey,
    rel: RelationshipId,
    nonce_i: [u8; 32],
    nonce_r: [u8; 32],
    iboot: BootId,
    rboot: BootId,
    igen: u64,
    rgen: u64,
    hello: Vec<u8>,
    challenge: Vec<u8>,
    finish: Vec<u8>,
    ack: Vec<u8>,
    probe: Vec<u8>,
    ping: Vec<u8>,
    pong: Vec<u8>,
    data: Vec<u8>,
    data_payload: Vec<u8>,
    k_hello: lzh_hole_protocol::Key32,
    k_chal: lzh_hole_protocol::Key32,
    k_fin: lzh_hole_protocol::Key32,
    k_probe: lzh_hole_protocol::Key32,
    k_i2r: lzh_hole_protocol::Key32,
    k_r2i: lzh_hole_protocol::Key32,
    th1: [u8; 32],
    th2: [u8; 32],
    th3: [u8; 32],
    session_id: u64,
    rekey_ping_lo: Vec<u8>,
    rekey_pong_hi: Vec<u8>,
    rekey_ping_hi: Vec<u8>,
    rekey_pong_lo: Vec<u8>,
    record_body: Vec<u8>,
}

fn build() -> Built {
    let f = fixture();
    let rel = RelationshipId::from_bytes(bytes16(&f, "inputs", "relationship_id"));
    let lo = DiscoveryPublicKey::from_bytes(bytes32(&f, "inputs", "lo_pub"));
    let hi = DiscoveryPublicKey::from_bytes(bytes32(&f, "inputs", "hi_pub"));
    let psk = bytes32(&f, "inputs", "psk");
    let nonce_i = bytes32(&f, "inputs", "nonce_i");
    let nonce_r = bytes32(&f, "inputs", "nonce_r");
    let iboot = BootId::from_bytes(bytes16(&f, "inputs", "initiator_boot_id"));
    let rboot = BootId::from_bytes(bytes16(&f, "inputs", "responder_boot_id"));
    let igen = num(&f, "inputs", "initiator_generation");
    let rgen = num(&f, "inputs", "responder_generation");
    let probe_nonce = bytes32(&f, "inputs", "probe_nonce");
    let ping_nonce = bytes32(&f, "inputs", "ping_nonce");

    let lo_b = *lo.as_bytes();
    let hi_b = *hi.as_bytes();

    let prk = extract_prk(rel.as_bytes(), &psk);

    let k_hello = prk.expand32(&info(LABEL_KDF_HELLO, &[&lo_b, &hi_b, &nonce_i]));
    let hello = encode_frame(
        FrameType::Hello,
        Direction::LoToHi,
        rel,
        0,
        0,
        &HelloPayload {
            lo_pub: lo,
            hi_pub: hi,
            nonce_i,
            boot_id: iboot,
            generation: igen,
            issued_at_unix_ms: num(&f, "inputs", "t_hello_ms"),
        }
        .encode(),
        &k_hello,
    )
    .expect("hello encodes");
    let th1 = transcript_hash(&[&hello]);

    let k_chal = prk.expand32(&info(
        LABEL_KDF_CHALLENGE,
        &[&lo_b, &hi_b, &nonce_i, &nonce_r, &th1],
    ));
    let challenge = encode_frame(
        FrameType::Challenge,
        Direction::HiToLo,
        rel,
        0,
        0,
        &ChallengePayload {
            hi_pub: hi,
            lo_pub: lo,
            nonce_i,
            nonce_r,
            th1,
            boot_id: rboot,
            generation: rgen,
            issued_at_unix_ms: num(&f, "inputs", "t_challenge_ms"),
        }
        .encode(),
        &k_chal,
    )
    .expect("challenge encodes");
    let th2 = transcript_hash(&[&hello, &challenge]);

    let k_fin = prk.expand32(&info(
        LABEL_KDF_FINISH,
        &[&lo_b, &hi_b, &nonce_i, &nonce_r, &th1, &th2],
    ));
    let finish = encode_frame(
        FrameType::Finish,
        Direction::LoToHi,
        rel,
        0,
        0,
        &FinishPayload {
            lo_pub: lo,
            hi_pub: hi,
            nonce_i,
            nonce_r,
            th1,
            th2,
            boot_id: iboot,
            generation: igen,
            issued_at_unix_ms: num(&f, "inputs", "t_finish_ms"),
        }
        .encode(),
        &k_fin,
    )
    .expect("finish encodes");
    let th3 = transcript_hash(&[&hello, &challenge, &finish]);

    let session_id = u64::from_be_bytes(prk.expand8(&info(
        LABEL_KDF_SESSION_ID,
        &[&lo_b, &hi_b, &nonce_i, &nonce_r, &th3],
    )));
    let k_i2r = prk.expand32(&info(
        LABEL_KDF_KEY_I2R,
        &[&lo_b, &hi_b, &nonce_i, &nonce_r, &th3],
    ));
    let k_r2i = prk.expand32(&info(
        LABEL_KDF_KEY_R2I,
        &[&lo_b, &hi_b, &nonce_i, &nonce_r, &th3],
    ));

    let ack = encode_frame(
        FrameType::Ack,
        Direction::HiToLo,
        rel,
        0,
        0,
        &AckPayload {
            hi_pub: hi,
            lo_pub: lo,
            th3,
            boot_id: rboot,
            generation: rgen,
            issued_at_unix_ms: num(&f, "inputs", "t_ack_ms"),
        }
        .encode(),
        &k_r2i,
    )
    .expect("ack encodes");

    let k_probe = prk.probe_key(&lo_b, &hi_b);
    let probe = encode_frame(
        FrameType::Probe,
        Direction::HiToLo,
        rel,
        0,
        0,
        &ProbePayload {
            sender: hi,
            receiver: lo,
            boot_id: rboot,
            generation: rgen,
            issued_at_unix_ms: num(&f, "inputs", "t_probe_ms"),
            probe_nonce,
        }
        .encode(),
        &k_probe,
    )
    .expect("probe encodes");

    let ping = encode_frame(
        FrameType::CtrlPing,
        Direction::LoToHi,
        rel,
        session_id,
        num(&f, "inputs", "ping_sequence_i2r"),
        &CtrlPayload {
            sender: lo,
            receiver: hi,
            nonce: ping_nonce,
            boot_id: iboot,
            generation: igen,
            issued_at_unix_ms: num(&f, "inputs", "t_ping_ms"),
            flags: 0,
        }
        .encode(),
        &k_i2r,
    )
    .expect("ping encodes");

    let pong = encode_frame(
        FrameType::CtrlPong,
        Direction::HiToLo,
        rel,
        session_id,
        num(&f, "inputs", "pong_sequence_r2i"),
        &CtrlPayload {
            sender: hi,
            receiver: lo,
            nonce: ping_nonce,
            boot_id: rboot,
            generation: rgen,
            issued_at_unix_ms: num(&f, "inputs", "t_pong_ms"),
            flags: 0,
        }
        .encode(),
        &k_r2i,
    )
    .expect("pong encodes");

    let data_payload = bytes(&f, "expected", "DATA_payload");
    let data = encode_frame(
        FrameType::Data,
        Direction::LoToHi,
        rel,
        session_id,
        num(&f, "inputs", "data_sequence_i2r"),
        &data_payload,
        &k_i2r,
    )
    .expect("data encodes");

    // Rekey authorization frames. The nonces are SHA-256 of fixed labels, so
    // both implementations derive them identically.
    let rekey_nonce_lo: [u8; 32] = Sha256::digest(b"lzh-hole v1 rekey nonce lo").into();
    let rekey_nonce_hi: [u8; 32] = Sha256::digest(b"lzh-hole v1 rekey nonce hi").into();
    const FLAG_REKEY: u8 = 0b100;

    let rekey_ping_lo = encode_frame(
        FrameType::CtrlPing,
        Direction::LoToHi,
        rel,
        session_id,
        3,
        &CtrlPayload {
            sender: lo,
            receiver: hi,
            nonce: rekey_nonce_lo,
            boot_id: iboot,
            generation: igen,
            issued_at_unix_ms: 1_762_920_002_000,
            flags: FLAG_REKEY,
        }
        .encode(),
        &k_i2r,
    )
    .expect("rekey ping lo encodes");
    let rekey_pong_hi = encode_frame(
        FrameType::CtrlPong,
        Direction::HiToLo,
        rel,
        session_id,
        2,
        &CtrlPayload {
            sender: hi,
            receiver: lo,
            nonce: rekey_nonce_lo,
            boot_id: rboot,
            generation: rgen,
            issued_at_unix_ms: 1_762_920_002_010,
            flags: 0,
        }
        .encode(),
        &k_r2i,
    )
    .expect("rekey pong hi encodes");
    let rekey_ping_hi = encode_frame(
        FrameType::CtrlPing,
        Direction::HiToLo,
        rel,
        session_id,
        3,
        &CtrlPayload {
            sender: hi,
            receiver: lo,
            nonce: rekey_nonce_hi,
            boot_id: rboot,
            generation: rgen,
            issued_at_unix_ms: 1_762_920_003_000,
            flags: FLAG_REKEY,
        }
        .encode(),
        &k_r2i,
    )
    .expect("rekey ping hi encodes");
    let rekey_pong_lo = encode_frame(
        FrameType::CtrlPong,
        Direction::LoToHi,
        rel,
        session_id,
        4,
        &CtrlPayload {
            sender: lo,
            receiver: hi,
            nonce: rekey_nonce_hi,
            boot_id: iboot,
            generation: igen,
            issued_at_unix_ms: 1_762_920_003_010,
            flags: 0,
        }
        .encode(),
        &k_i2r,
    )
    .expect("rekey pong lo encodes");

    // The sample record is the one hi publishes and lo receives, so it carries
    // the publisher's epoch.
    let candidates: Vec<RecordCandidate> = field(&f, "inputs", "record_candidates")
        .as_array()
        .expect("record_candidates is an array")
        .iter()
        .map(|c| RecordCandidate {
            endpoint: Endpoint::new(
                c["ip"].as_str().expect("ip").parse().expect("ipv4"),
                u16::try_from(c["port"].as_u64().expect("port")).expect("port fits"),
            ),
            source: CandidateSource::from_u8(
                u8::try_from(c["source_class"].as_u64().expect("source_class")).unwrap(),
            )
            .expect("known source class"),
        })
        .collect();
    let record = ContactRecord {
        relationship_id: rel,
        sender: hi,
        receiver: lo,
        record_seq: num(&f, "inputs", "record_seq_us"),
        issued_at_unix_ms: num(&f, "inputs", "record_issued_at_ms"),
        expires_at_unix_ms: num(&f, "inputs", "record_expires_at_ms"),
        boot_id: rboot,
        generation: rgen,
        candidates,
    };
    let record_body = record.encode_body().expect("record body encodes");

    Built {
        prk,
        lo,
        hi,
        rel,
        nonce_i,
        nonce_r,
        iboot,
        rboot,
        igen,
        rgen,
        hello,
        challenge,
        finish,
        ack,
        probe,
        ping,
        pong,
        data,
        data_payload,
        k_hello,
        k_chal,
        k_fin,
        k_probe,
        k_i2r,
        k_r2i,
        th1,
        th2,
        th3,
        session_id,
        rekey_ping_lo,
        rekey_pong_hi,
        rekey_ping_hi,
        rekey_pong_lo,
        record_body,
    }
}

#[test]
fn derived_keys_match_the_fixture() {
    let f = fixture();
    let b = build();
    assert_eq!(hex::encode(b.prk.as_bytes()), text(&f, "expected", "prk"));
    for (name, key) in [
        ("k_hello", &b.k_hello),
        ("k_chal", &b.k_chal),
        ("k_fin", &b.k_fin),
        ("k_probe", &b.k_probe),
        ("k_i2r", &b.k_i2r),
        ("k_r2i", &b.k_r2i),
    ] {
        assert_eq!(
            hex::encode(key.as_bytes()),
            text(&f, "expected", name),
            "{name}"
        );
    }
    assert_eq!(hex::encode(b.th1), text(&f, "expected", "th1"));
    assert_eq!(hex::encode(b.th2), text(&f, "expected", "th2"));
    assert_eq!(hex::encode(b.th3), text(&f, "expected", "th3"));

    let expected_sid = text(&f, "expected", "session_id");
    assert_eq!(format!("0x{:016x}", b.session_id), expected_sid);
    assert_ne!(b.session_id, 0, "a zero session id must never be derived");
}

#[test]
fn every_frame_matches_the_fixture_byte_for_byte() {
    let f = fixture();
    let b = build();
    let cases: [(&str, &Vec<u8>); 12] = [
        ("HELLO", &b.hello),
        ("CHALLENGE", &b.challenge),
        ("FINISH", &b.finish),
        ("ACK", &b.ack),
        ("PROBE", &b.probe),
        ("PING", &b.ping),
        ("PONG", &b.pong),
        ("DATA", &b.data),
        ("REKEY_PING_LO", &b.rekey_ping_lo),
        ("REKEY_PONG_HI", &b.rekey_pong_hi),
        ("REKEY_PING_HI", &b.rekey_ping_hi),
        ("REKEY_PONG_LO", &b.rekey_pong_lo),
    ];
    for (name, frame) in cases {
        assert_eq!(
            hex::encode(frame),
            text(&f, "expected", name),
            "frame {name} does not match the fixture"
        );
        let expected_mac = text(&f, "expected", &format!("{name}_mac"));
        assert_eq!(
            hex::encode(&frame[frame.len() - 32..]),
            expected_mac,
            "MAC of {name} does not match the fixture"
        );
    }
    assert_eq!(
        hex::encode(&b.data_payload),
        text(&f, "expected", "DATA_payload")
    );
}

#[test]
fn frame_lengths_match_the_fixture_and_show_no_amplification() {
    let f = fixture();
    let b = build();
    let lens = field(&f, "expected", "lens");
    for (name, frame) in [
        ("HELLO", &b.hello),
        ("CHALLENGE", &b.challenge),
        ("FINISH", &b.finish),
        ("ACK", &b.ack),
        ("PROBE", &b.probe),
        ("PING", &b.ping),
        ("PONG", &b.pong),
        ("DATA", &b.data),
    ] {
        let expected = lens[name].as_u64().expect("length") as usize;
        assert_eq!(frame.len(), expected, "{name} length");
    }
    // Every handshake frame is the same size, so no response exceeds its
    // request: the worst-case amplification ratio is exactly 1.0.
    for frame in [&b.hello, &b.challenge, &b.finish, &b.ack] {
        assert_eq!(frame.len(), 314);
    }
    assert_eq!(b.challenge.len(), b.hello.len());
    assert_eq!(b.ack.len(), b.finish.len());
    // PING and PONG are equal too.
    assert_eq!(b.ping.len(), b.pong.len());
}

#[test]
fn record_matches_the_fixture() {
    let f = fixture();
    let b = build();
    assert_eq!(
        hex::encode(&b.record_body),
        text(&f, "expected", "record_body")
    );
    // The canonical ntfy contact body must round-trip through our decoder.
    let decoded = ContactRecord::decode_body(&b.record_body).expect("record decodes");
    assert_eq!(decoded.sender, b.hi, "sender is the publisher");
    assert_eq!(decoded.receiver, b.lo, "receiver is the reader's own key");
    assert_eq!(
        decoded.boot_id, b.rboot,
        "record carries the publisher epoch"
    );
    assert_eq!(decoded.generation, b.rgen);
    assert_eq!(
        decoded.expires_at_unix_ms - decoded.issued_at_unix_ms,
        600_000,
        "default lifetime is 600 s"
    );
    assert_eq!(decoded.candidates.len(), 2);
}

#[test]
fn negative_cases_match_the_fixture() {
    let f = fixture();
    let b = build();

    // Flipping the direction byte changes the MAC, so direction is covered.
    let mut flipped = b.data.clone();
    flipped[6] ^= 1;
    let recomputed = frame_mac(&b.k_i2r, &flipped[..42], &b.data_payload);
    assert_eq!(
        hex::encode(recomputed),
        text(&f, "expected", "neg_DATA_direction_flip_mac")
    );
    assert_ne!(hex::encode(recomputed), text(&f, "expected", "DATA_mac"));

    // Changing payload_len changes the MAC, so payload_len is covered.
    let mut len_flipped = b.hello.clone();
    len_flipped[40] = 0;
    len_flipped[41] = 239;
    let hello_payload = &b.hello[42..42 + 240];
    let recomputed = frame_mac(&b.k_hello, &len_flipped[..42], hello_payload);
    assert_eq!(
        hex::encode(recomputed),
        text(&f, "expected", "neg_HELLO_len_flip_mac")
    );
    assert_ne!(hex::encode(recomputed), text(&f, "expected", "HELLO_mac"));

    // A FINISH with a non-zero padding byte and a *correct* MAC must still be
    // rejected. This is the case a MAC alone cannot catch.
    let tampered =
        hex::decode(text(&f, "expected", "neg_FINISH_nonzero_padding_valid_mac")).expect("hex");
    let offset = num(&f, "expected", "neg_FINISH_nonzero_padding_payload_offset") as usize;
    let payload = &tampered[42..42 + 240];
    assert_eq!(payload[offset], 1, "the fixture tampers this padding byte");
    // The MAC is valid ...
    let valid = lzh_hole_protocol::crypto::verify_frame_mac(
        &b.k_fin,
        &tampered[..42],
        payload,
        &tampered[42 + 240..],
    );
    assert!(valid, "the fixture negative frame must carry a valid MAC");
    // ... but the canonical padding check still refuses it.
    assert!(
        FinishPayload::decode(payload).is_err(),
        "non-zero padding must be rejected even with a valid MAC"
    );
}

#[test]
fn rekey_flags_follow_the_contract() {
    let b = build();
    for (name, frame, expect_rekey) in [
        ("REKEY_PING_LO", &b.rekey_ping_lo, true),
        ("REKEY_PING_HI", &b.rekey_ping_hi, true),
        ("REKEY_PONG_HI", &b.rekey_pong_hi, false),
        ("REKEY_PONG_LO", &b.rekey_pong_lo, false),
    ] {
        let payload = &frame[42..42 + 136];
        let flags = payload[128];
        assert_eq!(flags & 0b100 != 0, expect_rekey, "{name} rekey bit");
        // Reserved bits are always clear.
        assert_eq!(flags & 0b1111_1000, 0, "{name} reserved bits");
        if expect_rekey {
            assert!(
                CtrlPayload::decode_ping(payload).is_ok(),
                "{name} parses as PING"
            );
            // A PONG parser must refuse a rekey-flagged frame.
            assert!(
                CtrlPayload::decode_pong(payload).is_err(),
                "{name} must not parse as PONG"
            );
        } else {
            assert!(
                CtrlPayload::decode_pong(payload).is_ok(),
                "{name} parses as PONG"
            );
        }
    }
}

#[test]
fn fixture_rejects_a_pong_with_the_rekey_bit() {
    let f = fixture();
    let bad = hex::decode(text(&f, "expected", "neg_PONG_bit2_set")).expect("hex");
    let payload = &bad[42..42 + 136];
    assert_eq!(payload[128] & 0b100, 0b100);
    assert!(CtrlPayload::decode_pong(payload).is_err());
    assert!(CtrlPayload::decode_ping(payload).is_ok());
}

#[test]
fn fixture_rejects_reserved_flag_bits() {
    let f = fixture();
    let bad = hex::decode(text(&f, "expected", "neg_PING_reserved_bit")).expect("hex");
    let payload = &bad[42..42 + 136];
    assert_ne!(payload[128] & 0b1111_1000, 0);
    assert!(CtrlPayload::decode_ping(payload).is_err());
}

#[test]
fn inputs_are_the_documented_synthetic_values() {
    let f = fixture();
    assert_eq!(
        text(&f, "inputs", "psk"),
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
    );
    assert_eq!(text(&f, "inputs", "lo_pub").len(), 64);
    assert_eq!(text(&f, "inputs", "hi_pub").len(), 64);
    // The fixture must keep warning that these secrets are synthetic.
    let note = f["note"].as_str().unwrap_or_default().to_lowercase();
    assert!(
        note.contains("synthetic"),
        "fixture must flag synthetic secrets"
    );
    assert!(
        note.contains("never"),
        "fixture must forbid real use of the test PSK"
    );
}

#[test]
fn roles_are_consistent_with_the_fixture_direction_bytes() {
    let b = build();
    // lo < hi by construction, so lo is the initiator and sends direction 0.
    assert!(b.lo < b.hi);
    assert_eq!(b.hello[6], 0, "HELLO travels lo to hi");
    assert_eq!(b.finish[6], 0, "FINISH travels lo to hi");
    assert_eq!(b.challenge[6], 1, "CHALLENGE travels hi to lo");
    assert_eq!(b.ack[6], 1, "ACK travels hi to lo");
    assert_eq!(b.probe[6], 1, "PROBE travels hi to lo");
    // Sessionless frames carry session 0 and sequence 0.
    for frame in [&b.hello, &b.challenge, &b.finish, &b.ack, &b.probe] {
        assert_eq!(&frame[24..32], &[0u8; 8], "session id must be zero");
        assert_eq!(&frame[32..40], &[0u8; 8], "sequence must be zero");
    }
    // Session frames carry the derived id and a non-zero sequence.
    for frame in [&b.ping, &b.pong, &b.data] {
        let sid = u64::from_be_bytes(frame[24..32].try_into().unwrap());
        let seq = u64::from_be_bytes(frame[32..40].try_into().unwrap());
        assert_eq!(sid, b.session_id);
        assert!(seq >= 1);
    }
    let _ = (
        b.rel, b.nonce_i, b.nonce_r, b.iboot, b.rboot, b.igen, b.rgen,
    );
}
