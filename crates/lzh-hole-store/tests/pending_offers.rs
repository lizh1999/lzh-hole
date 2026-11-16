//! Pending pairing offers are keyed by pairing id, so a node can be pairing
//! with a second peer while the first pairing is still waiting for its
//! acceptance. A single `offer.json` made the second `pair offer` silently
//! overwrite the first one's PSK.

use lzh_hole_store::{
    MAX_PENDING_OFFERS, Offer, PairingError, StateDir, build_offer, public_key_of_seed,
};
use lzh_hole_types::{RelationshipId, Secret32};

fn seed(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn offer(
    initiator_seed: &[u8; 32],
    pairing: [u8; 16],
    relationship: [u8; 16],
    responder_seed: &[u8; 32],
    self_vip: &str,
    peer_vip: &str,
    psk_byte: u8,
) -> Offer {
    build_offer(
        initiator_seed,
        RelationshipId::from_bytes(pairing),
        RelationshipId::from_bytes(relationship),
        public_key_of_seed(initiator_seed),
        public_key_of_seed(responder_seed),
        self_vip.to_owned(),
        peer_vip.to_owned(),
        &Secret32::from_bytes([psk_byte; 32]),
        1_700_000_000_000,
    )
    .unwrap()
}

#[test]
fn concurrent_pairings_keep_independent_offers() {
    let temp = tempfile::tempdir().unwrap();
    let state = StateDir::open(&temp.path().join("state")).unwrap();

    let first = offer(
        &seed(1),
        [0x11; 16],
        [0xb1; 16],
        &seed(2),
        "10.203.0.1",
        "10.203.0.2",
        0xa1,
    );
    let second = offer(
        &seed(1),
        [0x22; 16],
        [0xc1; 16],
        &seed(3),
        "10.203.0.1",
        "10.203.0.3",
        0xa2,
    );
    state.store_offer(&first).unwrap();
    state.store_offer(&second).unwrap();

    let ids = state.pending_offer_ids().unwrap();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&first.pairing_id) && ids.contains(&second.pairing_id));

    // The second offer never replaced the first one's PSK.
    let reloaded = state.load_offer(first.pairing_id).unwrap();
    assert_eq!(reloaded.relationship_id, first.relationship_id);
    assert_eq!(
        reloaded.psk().unwrap().expose_bytes(),
        Secret32::from_bytes([0xa1; 32]).expose_bytes()
    );
    assert_eq!(state.load_offer(second.pairing_id).unwrap(), second);

    // Finalising one pairing drops only its own pending offer.
    state.remove_offer(first.pairing_id).unwrap();
    assert_eq!(state.pending_offer_ids().unwrap(), vec![second.pairing_id]);
    assert!(state.load_offer(first.pairing_id).is_err());
    assert!(state.load_offer(second.pairing_id).is_ok());

    // Removing an offer twice is not an error: finalize may be retried after a
    // crash between the finalise rename and this cleanup.
    state.remove_offer(first.pairing_id).unwrap();
}

#[test]
fn an_offer_is_never_silently_overwritten() {
    let temp = tempfile::tempdir().unwrap();
    let state = StateDir::open(&temp.path().join("state")).unwrap();

    let original = offer(
        &seed(1),
        [0x11; 16],
        [0xb1; 16],
        &seed(2),
        "10.203.0.1",
        "10.203.0.2",
        0xa1,
    );
    state.store_offer(&original).unwrap();

    // Same pairing id, different PSK: refused, and the stored PSK is intact.
    let colliding = offer(
        &seed(1),
        [0x11; 16],
        [0xb2; 16],
        &seed(2),
        "10.203.0.1",
        "10.203.0.2",
        0xff,
    );
    assert!(matches!(
        state.store_offer(&colliding),
        Err(PairingError::DuplicateOffer(_))
    ));
    assert_eq!(
        state
            .load_offer(original.pairing_id)
            .unwrap()
            .psk()
            .unwrap()
            .expose_bytes(),
        Secret32::from_bytes([0xa1; 32]).expose_bytes()
    );
}

#[test]
fn pending_offers_are_bounded_and_a_file_name_is_not_skipped() {
    let temp = tempfile::tempdir().unwrap();
    let state = StateDir::open(&temp.path().join("state")).unwrap();

    for index in 0..MAX_PENDING_OFFERS {
        let byte = u8::try_from(index + 1).unwrap();
        let pairing = [byte; 16];
        let relationship = [byte.wrapping_add(0x80); 16];
        let peer = seed(byte.wrapping_add(0x40));
        let vip = format!("10.203.0.{}", index + 2);
        let offer = offer(
            &seed(1),
            pairing,
            relationship,
            &peer,
            "10.203.0.1",
            &vip,
            byte,
        );
        state.store_offer(&offer).unwrap();
    }
    assert_eq!(state.pending_offer_ids().unwrap().len(), MAX_PENDING_OFFERS);

    let overflow = offer(
        &seed(1),
        [0xf0; 16],
        [0xf1; 16],
        &seed(0xfe),
        "10.203.0.1",
        "10.203.0.200",
        0xf0,
    );
    assert!(matches!(
        state.store_offer(&overflow),
        Err(PairingError::TooManyPendingOffers(MAX_PENDING_OFFERS))
    ));

    // A name that is not a pairing id is refused rather than skipped.
    std::fs::write(state.offers_dir().join("not-a-pairing.json"), b"{}").unwrap();
    assert!(state.pending_offer_ids().is_err());
}

#[test]
fn an_offer_whose_relationship_is_already_finalised_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let state = StateDir::open(&temp.path().join("state")).unwrap();

    let pending = offer(
        &seed(1),
        [0x11; 16],
        [0xb1; 16],
        &seed(2),
        "10.203.0.1",
        "10.203.0.2",
        0xa1,
    );
    let relationship = lzh_hole_store::Relationship {
        pairing_version: 2,
        pairing_id: pending.pairing_id,
        relationship_id: pending.relationship_id,
        self_public_key: pending.initiator_public_key,
        peer_public_key: pending.responder_public_key,
        role: lzh_hole_store::Role::Initiator,
        self_vip: pending.initiator_vip.clone(),
        peer_vip: pending.responder_vip.clone(),
        finalised_unix_ms: 1_700_000_000_001,
    };
    state
        .finalise(&relationship, &Secret32::from_bytes([0xa1; 32]))
        .unwrap();

    let again = offer(
        &seed(1),
        [0x33; 16],
        [0xb1; 16],
        &seed(2),
        "10.203.0.1",
        "10.203.0.2",
        0xa2,
    );
    assert!(matches!(
        state.store_offer(&again),
        Err(PairingError::DuplicateRelationship(_))
    ));
}
