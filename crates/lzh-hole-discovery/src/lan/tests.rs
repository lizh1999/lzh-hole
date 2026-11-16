use super::*;
use lzh_hole_types::RelationshipId;

fn key() -> DiscoveryPublicKey {
    DiscoveryPublicKey::from_bytes([7; 32])
}
fn other_key() -> DiscoveryPublicKey {
    DiscoveryPublicKey::from_bytes([8; 32])
}
fn unknown_key() -> DiscoveryPublicKey {
    DiscoveryPublicKey::from_bytes([9; 32])
}
fn rel() -> RelationshipId {
    RelationshipId::from_bytes([1; 16])
}
fn other_rel() -> RelationshipId {
    RelationshipId::from_bytes([2; 16])
}
fn pinned_one() -> BTreeMap<DiscoveryPublicKey, RelationshipId> {
    BTreeMap::from([(key(), rel())])
}
fn pinned_two() -> BTreeMap<DiscoveryPublicKey, RelationshipId> {
    BTreeMap::from([(key(), rel()), (other_key(), other_rel())])
}
fn lan() -> LanDiscovery {
    LanDiscovery::new(pinned_one())
}
fn scope() -> LanScope {
    LanScope {
        interface: 4,
        generation: 2,
    }
}
fn observation_for(name: &str, key: DiscoveryPublicKey) -> LanObservation {
    let ad =
        LanAdvertisement::new(key, Endpoint::new(Ipv4Addr::new(192, 168, 1, 7), 7777)).unwrap();
    LanObservation {
        instance: name.to_owned(),
        scope: scope(),
        addresses: vec![ad.address],
        port: ad.port,
        txt: ad.txt,
        ttl_ms: 5_000,
    }
}
fn observation(name: &str) -> LanObservation {
    observation_for(name, key())
}
fn hint(updates: &[LanUpdate]) -> CandidateHint {
    match updates.last().unwrap().update {
        DiscoveryUpdate::Upsert(hint) => hint,
        _ => panic!("expected upsert"),
    }
}
fn removed(relationship_id: RelationshipId, id: ObservationId) -> LanUpdate {
    LanUpdate {
        relationship_id,
        update: DiscoveryUpdate::Remove(id),
    }
}
fn txt(fields: &[String]) -> Vec<u8> {
    fields
        .iter()
        .flat_map(|field| {
            std::iter::once(field.len() as u8).chain(field.as_bytes().iter().copied())
        })
        .collect()
}

#[test]
fn txt_roundtrip_uses_only_the_advertised_a_record_not_other_aliases() {
    assert_eq!(LAN_SERVICE_TYPE, "_lzh-hole._udp.local.");
    let mut lan = lan();
    let mut obs = observation("peer");
    obs.addresses.extend([
        Ipv4Addr::new(10, 3, 2, 1),
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::LOCALHOST,
    ]);
    let updates = lan.observe(obs, 100).unwrap();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].relationship_id, rel());
    let h = hint(&updates);
    assert_eq!(h.remote, Endpoint::new(Ipv4Addr::new(192, 168, 1, 7), 7777));
    assert_eq!(h.expires_at_ms, 5_100);
    assert_eq!(h.source, HintSource::Mdns);
    assert_eq!(h.scope, CandidateScope::Lan(scope()));
}

#[test]
fn wrong_key_version_missing_or_invalid_address_and_bad_txt_are_refused() {
    let mut lan = lan();
    let mut wrong_key = observation("peer");
    wrong_key.txt = LanAdvertisement::new(other_key(), Endpoint::new(wrong_key.addresses[0], 7777))
        .unwrap()
        .txt;
    assert_eq!(lan.observe(wrong_key, 0), Err(LanError::WrongPeer));
    for (fields, error) in [
        (
            vec![
                "v=2".to_owned(),
                format!("pk={}", key()),
                "addr=192.168.1.7".to_owned(),
            ],
            LanError::Version,
        ),
        (
            vec!["v=1".to_owned(), format!("pk={}", key())],
            LanError::Address,
        ),
        (
            vec![
                "v=1".to_owned(),
                format!("pk={}", key()),
                "addr=banana".to_owned(),
            ],
            LanError::Address,
        ),
        (
            vec![
                "v=1".to_owned(),
                format!("pk={}", key()),
                "addr=10.1.1.1".to_owned(),
            ],
            LanError::Address,
        ),
        (
            vec!["v=1".to_owned(), "v=1".to_owned()],
            LanError::Malformed,
        ),
    ] {
        let mut obs = observation("peer");
        obs.txt = txt(&fields);
        assert_eq!(lan.observe(obs, 0), Err(error));
    }
    for raw in [vec![255, b'x'], vec![0], vec![1, 255], vec![b'x'; 513]] {
        let mut obs = observation("peer");
        obs.txt = raw;
        assert_eq!(lan.observe(obs, 0), Err(LanError::Malformed));
    }
    assert_eq!(lan.observation_count(), 0);
}

#[test]
fn only_rfc1918_and_nonzero_bound_ports_are_advertised_and_accepted() {
    for address in [
        Ipv4Addr::LOCALHOST,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::new(169, 254, 1, 1),
        Ipv4Addr::new(198, 18, 0, 1),
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(224, 0, 0, 1),
    ] {
        assert_eq!(
            LanAdvertisement::new(key(), Endpoint::new(address, 5)),
            Err(LanError::Address)
        );
        let mut obs = observation("peer");
        obs.addresses = vec![address];
        obs.txt = txt(&[
            "v=1".to_owned(),
            format!("pk={}", key()),
            format!("addr={address}"),
        ]);
        assert_eq!(lan().observe(obs, 0), Err(LanError::Address));
    }
    assert!(LanAdvertisement::new(key(), Endpoint::new(Ipv4Addr::new(10, 0, 0, 1), 0)).is_err());
}

#[test]
fn refresh_preserves_identity_and_changed_endpoint_replaces_only_its_observation() {
    let mut lan = lan();
    let first = hint(&lan.observe(observation("peer"), 10).unwrap());
    let refreshed = hint(&lan.observe(observation("peer"), 50).unwrap());
    assert_eq!(first.observation_id, refreshed.observation_id);
    assert_eq!(refreshed.expires_at_ms, 5_050);
    assert!(lan.expire(5_049).is_empty());
    let alias = hint(&lan.observe(observation("alias"), 51).unwrap());
    assert_ne!(alias.observation_id, first.observation_id);
    let mut changed = observation("peer");
    changed.port += 1;
    let updates = lan.observe(changed, 100).unwrap();
    assert_eq!(updates[0], removed(rel(), first.observation_id));
    assert_ne!(hint(&updates).observation_id, first.observation_id);
    assert_eq!(
        lan.remove("alias", scope()),
        vec![removed(rel(), alias.observation_id)]
    );
    assert_eq!(lan.observation_count(), 1);
    assert_eq!(lan.observation_count_for(rel()), 1);
}

#[test]
fn goodbye_expiry_and_interface_generation_revocation_are_source_specific() {
    let mut lan = lan();
    let first = hint(&lan.observe(observation("peer"), 0).unwrap());
    let mut new_scope = observation("peer");
    new_scope.scope.generation += 1;
    let second = hint(&lan.observe(new_scope, 100).unwrap());
    assert_eq!(
        lan.revoke_interface(scope()),
        vec![removed(rel(), first.observation_id)]
    );
    assert!(lan.revoke_interface(scope()).is_empty());
    assert_eq!(lan.observation_count(), 1);
    assert_eq!(
        lan.expire(5_100),
        vec![removed(rel(), second.observation_id)]
    );
    let third = hint(&lan.observe(observation("peer"), 6_000).unwrap());
    let mut goodbye = observation("peer");
    goodbye.ttl_ms = 0;
    goodbye.txt.clear();
    goodbye.addresses.clear();
    assert_eq!(
        lan.observe(goodbye.clone(), 6_001).unwrap(),
        vec![removed(rel(), third.observation_id)]
    );
    assert!(lan.observe(goodbye, 6_002).unwrap().is_empty());
}

#[test]
fn observation_and_unique_scoped_candidate_limits_and_ttl_cap_are_enforced() {
    let mut lan = lan();
    for i in 0..MAX_LAN_OBSERVATIONS {
        lan.observe(observation(&format!("alias-{i}")), 0).unwrap();
    }
    assert_eq!(
        lan.observe(observation("overflow"), 0),
        Err(LanError::Capacity)
    );
    assert!(lan.observe(observation("alias-0"), 1).is_ok());
    lan.expire(5_001);
    for i in 0..MAX_LAN_CANDIDATES {
        let mut obs = observation(&format!("endpoint-{i}"));
        obs.port += i as u16;
        lan.observe(obs, 6_000).unwrap();
    }
    let mut overflow = observation("different-endpoint");
    overflow.port = 8_888;
    assert_eq!(lan.observe(overflow, 6_000), Err(LanError::Capacity));
    lan.expire(11_000);
    let mut obs = observation("capped");
    obs.ttl_ms = u64::MAX;
    let h = hint(&lan.observe(obs, 11_000).unwrap());
    assert_eq!(h.expires_at_ms, 11_000 + MAX_LAN_TTL_MS);
}

/// Every update names the relationship whose `pk` produced it, and a broadcast
/// from one pinned peer never produces an update for another relationship.
#[test]
fn multi_peer_broadcasts_are_tagged_with_their_own_relationship() {
    let mut lan = LanDiscovery::new(pinned_two());
    let updates = lan.observe(observation_for("a", key()), 0).unwrap();
    assert_eq!(updates.len(), 1);
    assert!(updates.iter().all(|u| u.relationship_id == rel()));
    assert!(!updates.iter().any(|u| u.relationship_id == other_rel()));
    let hint_a = hint(&updates);

    let updates = lan.observe(observation_for("b", other_key()), 0).unwrap();
    assert_eq!(updates.len(), 1);
    assert!(updates.iter().all(|u| u.relationship_id == other_rel()));
    assert!(!updates.iter().any(|u| u.relationship_id == rel()));
    let hint_b = hint(&updates);

    assert_ne!(hint_a.observation_id, hint_b.observation_id);
    assert_eq!(lan.observation_count(), 2);
    assert_eq!(lan.observation_count_for(rel()), 1);
    assert_eq!(lan.observation_count_for(other_rel()), 1);

    // An unpinned key is still refused and leaves both tables untouched.
    assert_eq!(
        lan.observe(observation_for("c", unknown_key()), 0),
        Err(LanError::WrongPeer)
    );
    assert_eq!(lan.observation_count(), 2);

    // Removal and expiry stay attributed to the owning relationship.
    assert_eq!(
        lan.remove("a", scope()),
        vec![removed(rel(), hint_a.observation_id)]
    );
    assert_eq!(
        lan.expire(5_000),
        vec![removed(other_rel(), hint_b.observation_id)]
    );
    assert_eq!(lan.observation_count(), 0);
}

/// Observation and candidate budgets are counted per relationship on purpose, so
/// one chatty peer cannot starve the other pinned relationships.
#[test]
fn per_relationship_capacity_isolation_keeps_other_relationships_usable() {
    let mut lan = LanDiscovery::new(pinned_two());
    for i in 0..MAX_LAN_OBSERVATIONS {
        lan.observe(observation_for(&format!("a-{i}"), key()), 0)
            .unwrap();
    }
    assert_eq!(lan.observation_count_for(rel()), MAX_LAN_OBSERVATIONS);
    assert_eq!(
        lan.observe(observation_for("a-overflow", key()), 0),
        Err(LanError::Capacity)
    );
    // The other relationship is unaffected by the full table.
    let updates = lan.observe(observation_for("b-0", other_key()), 0).unwrap();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].relationship_id, other_rel());
    assert_eq!(lan.observation_count_for(other_rel()), 1);
    assert_eq!(lan.observation_count(), MAX_LAN_OBSERVATIONS + 1);
    // Refreshing an existing observation of the full relationship still works.
    assert!(lan.observe(observation_for("a-0", key()), 1).is_ok());

    // The distinct-candidate budget is per relationship as well.
    let mut lan = LanDiscovery::new(pinned_two());
    for i in 0..MAX_LAN_CANDIDATES {
        let mut obs = observation_for(&format!("a-endpoint-{i}"), key());
        obs.port += i as u16;
        lan.observe(obs, 0).unwrap();
    }
    let mut overflow = observation_for("a-endpoint-overflow", key());
    overflow.port = 9_000;
    assert_eq!(lan.observe(overflow, 0), Err(LanError::Capacity));
    let mut b_obs = observation_for("b-endpoint", other_key());
    b_obs.port = 9_000;
    let updates = lan.observe(b_obs, 0).unwrap();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].relationship_id, other_rel());
    assert_eq!(lan.observation_count_for(rel()), MAX_LAN_CANDIDATES);
    assert_eq!(lan.observation_count_for(other_rel()), 1);
}

/// An observation id belongs to exactly one relationship's registry, so the same
/// instance re-advertised by a different pinned peer must get a fresh id and the
/// previous relationship must be told to remove its own id.
#[test]
fn changing_the_advertising_peer_allocates_a_new_observation_id() {
    let mut lan = LanDiscovery::new(pinned_two());
    let first = hint(&lan.observe(observation_for("peer", key()), 0).unwrap());
    // Same scope, same instance and same endpoint: only the pinned peer differs.
    let updates = lan
        .observe(observation_for("peer", other_key()), 100)
        .unwrap();
    assert_eq!(updates.len(), 2);
    assert_eq!(updates[0], removed(rel(), first.observation_id));
    assert_eq!(updates[1].relationship_id, other_rel());
    let second = hint(&updates);
    assert_ne!(second.observation_id, first.observation_id);
    assert_eq!(second.remote, first.remote);
    assert_eq!(second.scope, first.scope);
    assert_eq!(lan.observation_count(), 1);
    assert_eq!(lan.observation_count_for(rel()), 0);
    assert_eq!(lan.observation_count_for(other_rel()), 1);

    // Refreshing under the new peer keeps the new id, never the old one.
    let refreshed = hint(
        &lan.observe(observation_for("peer", other_key()), 200)
            .unwrap(),
    );
    assert_eq!(refreshed.observation_id, second.observation_id);

    // Switching back likewise allocates yet another id and removes B's.
    let updates = lan.observe(observation_for("peer", key()), 300).unwrap();
    assert_eq!(updates[0], removed(other_rel(), second.observation_id));
    let third = hint(&updates);
    assert_ne!(third.observation_id, first.observation_id);
    assert_ne!(third.observation_id, second.observation_id);
    assert_eq!(lan.observation_count_for(rel()), 1);
    assert_eq!(lan.observation_count_for(other_rel()), 0);
}
