//! Multi-relationship state layout: isolation, duplicate refusal and the
//! invariants a node must hold across however many peers it has.

use lzh_hole_store::{Relationship, Role, StateDir};
use lzh_hole_types::{DiscoveryPublicKey, RelationshipId, Secret32};

fn key(byte: u8) -> DiscoveryPublicKey {
    DiscoveryPublicKey::from_bytes([byte; 32])
}

fn relationship(
    id: [u8; 16],
    self_key: DiscoveryPublicKey,
    peer_key: DiscoveryPublicKey,
    self_vip: &str,
    peer_vip: &str,
) -> Relationship {
    Relationship {
        pairing_version: 2,
        pairing_id: RelationshipId::from_bytes([0xaa; 16]),
        relationship_id: RelationshipId::from_bytes(id),
        self_public_key: self_key,
        peer_public_key: peer_key,
        role: Role::Initiator,
        self_vip: self_vip.to_owned(),
        peer_vip: peer_vip.to_owned(),
        finalised_unix_ms: 1_700_000_000_000,
    }
}

fn psk(byte: u8) -> Secret32 {
    Secret32::from_bytes([byte; 32])
}

#[test]
fn two_relationships_coexist_with_independent_secrets_and_sequences() {
    let temp = tempfile::tempdir().unwrap();
    let state = StateDir::open(&temp.path().join("state")).unwrap();

    let ab = relationship([0xb1; 16], key(1), key(2), "10.203.0.1", "10.203.0.2");
    let ac = relationship([0xc1; 16], key(1), key(3), "10.203.0.1", "10.203.0.3");
    state.finalise(&ab, &psk(0xa1)).unwrap();
    state.finalise(&ac, &psk(0xa2)).unwrap();

    assert!(state.is_paired());
    assert!(state.is_paired_with(ab.relationship_id));
    assert!(state.is_paired_with(ac.relationship_id));

    let ids = state.relationship_ids().unwrap();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&ab.relationship_id) && ids.contains(&ac.relationship_id));

    // Each relationship keeps its own key, record and sequence stream.
    assert_eq!(
        state.load_psk(ab.relationship_id).unwrap().expose_bytes(),
        psk(0xa1).expose_bytes()
    );
    assert_eq!(
        state.load_psk(ac.relationship_id).unwrap().expose_bytes(),
        psk(0xa2).expose_bytes()
    );
    assert_eq!(state.load_relationship(ab.relationship_id).unwrap(), ab);
    assert_eq!(state.load_relationship(ac.relationship_id).unwrap(), ac);

    state.store_sequence(ab.relationship_id, 7).unwrap();
    state.store_sequence(ac.relationship_id, 99).unwrap();
    assert_eq!(state.load_sequence(ab.relationship_id).unwrap(), 7);
    assert_eq!(state.load_sequence(ac.relationship_id).unwrap(), 99);

    assert_ne!(
        state.peer_record_path(ab.relationship_id),
        state.peer_record_path(ac.relationship_id)
    );

    // The identity-wide single writer lock stays one file for the whole node.
    assert!(
        state
            .lock_publisher()
            .unwrap()
            .path()
            .ends_with("publish.lock")
    );
}

#[test]
fn a_conflicting_relationship_is_refused_and_leaves_state_untouched() {
    let temp = tempfile::tempdir().unwrap();
    let state = StateDir::open(&temp.path().join("state")).unwrap();
    let ab = relationship([0xb1; 16], key(1), key(2), "10.203.0.1", "10.203.0.2");
    state.finalise(&ab, &psk(0xa1)).unwrap();

    // Same relationship id.
    let dup_id = relationship([0xb1; 16], key(1), key(3), "10.203.0.1", "10.203.0.3");
    assert!(state.finalise(&dup_id, &psk(0xa2)).is_err());

    // Same peer key under a different relationship.
    let dup_key = relationship([0xc1; 16], key(1), key(2), "10.203.0.1", "10.203.0.3");
    assert!(state.finalise(&dup_key, &psk(0xa2)).is_err());

    // Peer address already claimed by the first relationship.
    let dup_vip = relationship([0xc1; 16], key(1), key(3), "10.203.0.1", "10.203.0.2");
    assert!(state.finalise(&dup_vip, &psk(0xa2)).is_err());

    // A different local identity.
    let other_identity = relationship([0xc1; 16], key(9), key(3), "10.203.0.1", "10.203.0.3");
    assert!(state.finalise(&other_identity, &psk(0xa2)).is_err());

    // A different local overlay address.
    let other_self_vip = relationship([0xc1; 16], key(1), key(3), "10.203.0.9", "10.203.0.3");
    assert!(state.finalise(&other_self_vip, &psk(0xa2)).is_err());

    // A peer address equal to our own.
    let self_peer = relationship([0xc1; 16], key(1), key(3), "10.203.0.1", "10.203.0.1");
    assert!(state.finalise(&self_peer, &psk(0xa2)).is_err());

    // Nothing was admitted and the first relationship is intact.
    assert_eq!(state.relationship_ids().unwrap(), vec![ab.relationship_id]);
    assert_eq!(state.load_relationship(ab.relationship_id).unwrap(), ab);
    assert_eq!(
        state.load_psk(ab.relationship_id).unwrap().expose_bytes(),
        psk(0xa1).expose_bytes()
    );
}

#[test]
fn a_relationship_is_never_visible_half_written() {
    let temp = tempfile::tempdir().unwrap();
    let state = StateDir::open(&temp.path().join("state")).unwrap();
    let ab = relationship([0xb1; 16], key(1), key(2), "10.203.0.1", "10.203.0.2");
    state.finalise(&ab, &psk(0xa1)).unwrap();

    // A leftover staging directory from an interrupted finalise must not be
    // mistaken for a relationship, and must not hide the real ones.
    let staging = state.relationships_dir().join(".deadbeef.staging");
    std::fs::create_dir_all(&staging).unwrap();
    assert_eq!(state.relationship_ids().unwrap(), vec![ab.relationship_id]);

    // A directory that is not a relationship id is refused rather than skipped.
    let bogus = state.relationships_dir().join("not-a-relationship");
    std::fs::create_dir_all(&bogus).unwrap();
    assert!(state.relationship_ids().is_err());
}

#[test]
fn an_unknown_relationship_has_no_state() {
    let temp = tempfile::tempdir().unwrap();
    let state = StateDir::open(&temp.path().join("state")).unwrap();
    let missing = RelationshipId::from_bytes([0xee; 16]);

    assert!(!state.is_paired());
    assert!(!state.is_paired_with(missing));
    assert!(state.relationship_ids().unwrap().is_empty());
    assert!(state.load_relationships().unwrap().is_empty());
    assert!(state.load_relationship(missing).is_err());
    assert!(state.load_psk(missing).is_err());
    assert!(state.store_sequence(missing, 1).is_err());
}
