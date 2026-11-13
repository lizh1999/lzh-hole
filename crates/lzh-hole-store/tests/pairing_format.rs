//! Compatibility checks for the pre-refactor identity and pairing-v2 format.
//! Every secret-looking value below is a published synthetic test vector.

use lzh_hole_store::{
    PAIRING_VERSION, Relationship, Role, Secret32, StateDir, build_acceptance, build_offer,
    public_key_of_seed, verify_acceptance,
};
use lzh_hole_types::{DiscoveryPublicKey, RelationshipId};

const RFC8032_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

#[test]
fn existing_seed_keeps_public_key_bytes_and_text() {
    let public = public_key_of_seed(&RFC8032_SEED);
    assert_eq!(
        hex::encode(public.as_bytes()),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    assert_eq!(
        public.to_string(),
        "47pjoycnsrfmxikm95jh13y88e8qnhzu5kungjpxyepgt7a8krpy"
    );
    assert_eq!(
        public.to_string().parse::<DiscoveryPublicKey>().unwrap(),
        public
    );
}

#[test]
fn pairing_v2_transcript_and_relationship_shape_remain_compatible() {
    let responder_seed = [0x42; 32];
    let initiator = public_key_of_seed(&RFC8032_SEED);
    let responder = public_key_of_seed(&responder_seed);
    let pairing_id = RelationshipId::from_bytes([1; 16]);
    let relationship_id = RelationshipId::from_bytes([2; 16]);
    let psk = Secret32::from_bytes([0x5a; 32]);
    let offer = build_offer(
        &RFC8032_SEED,
        pairing_id,
        relationship_id,
        initiator,
        responder,
        "10.203.0.1".to_owned(),
        "10.203.0.2".to_owned(),
        &psk,
        1_800_000_000_000,
    )
    .unwrap();
    assert_eq!(offer.pairing_version, PAIRING_VERSION);
    assert_eq!(offer.kind, "offer");
    offer.verify().unwrap();

    let acceptance =
        build_acceptance(&responder_seed, &offer, responder, 1_800_000_000_001).unwrap();
    verify_acceptance(&offer, &acceptance, responder).unwrap();
    assert_eq!(acceptance.kind, "accept");
    assert_eq!(acceptance.pairing_id, pairing_id);
    assert_eq!(acceptance.relationship_id, relationship_id);

    let relationship = Relationship {
        pairing_version: PAIRING_VERSION,
        pairing_id,
        relationship_id,
        self_public_key: initiator,
        peer_public_key: responder,
        role: Role::Initiator,
        self_vip: offer.initiator_vip.clone(),
        peer_vip: offer.responder_vip.clone(),
        finalised_unix_ms: 1_800_000_000_002,
    };
    let encoded = serde_json::to_string(&relationship).unwrap();
    assert_eq!(
        encoded,
        format!(
            "{{\"pairing_version\":2,\"pairing_id\":\"{pairing_id}\",\"relationship_id\":\"{relationship_id}\",\"self_public_key\":\"{initiator}\",\"peer_public_key\":\"{responder}\",\"role\":\"initiator\",\"self_vip\":\"10.203.0.1\",\"peer_vip\":\"10.203.0.2\",\"finalised_unix_ms\":1800000000002}}"
        )
    );
    assert_eq!(
        serde_json::from_str::<Relationship>(&encoded).unwrap(),
        relationship
    );
}

#[test]
fn identity_initialization_reloads_the_same_public_key() {
    let temp = tempfile::tempdir().unwrap();
    let state = StateDir::open(&temp.path().join("state")).unwrap();
    let (created, was_created) = state.init_identity(false).unwrap();
    assert!(was_created);
    let (existing, was_created) = state.init_identity(false).unwrap();
    assert!(!was_created);
    assert_eq!(existing, created);
    assert_eq!(state.public_key().unwrap(), created);
}
