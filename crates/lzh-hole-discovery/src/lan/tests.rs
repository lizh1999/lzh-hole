use super::*;
fn key() -> DiscoveryPublicKey {
    DiscoveryPublicKey::from_bytes([7; 32])
}
fn scope() -> LanScope {
    LanScope {
        interface: 4,
        generation: 2,
    }
}
fn observation(name: &str) -> LanObservation {
    let ad =
        LanAdvertisement::new(key(), Endpoint::new(Ipv4Addr::new(192, 168, 1, 7), 7777)).unwrap();
    LanObservation {
        instance: name.to_owned(),
        scope: scope(),
        addresses: vec![ad.address],
        port: ad.port,
        txt: ad.txt,
        ttl_ms: 5_000,
    }
}
fn hint(updates: &[DiscoveryUpdate]) -> CandidateHint {
    match updates.last().unwrap() {
        DiscoveryUpdate::Upsert(hint) => *hint,
        _ => panic!("expected upsert"),
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
    let mut lan = LanDiscovery::new(key());
    let mut obs = observation("peer");
    obs.addresses.extend([
        Ipv4Addr::new(10, 3, 2, 1),
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::LOCALHOST,
    ]);
    let updates = lan.observe(obs, 100).unwrap();
    assert_eq!(updates.len(), 1);
    let h = hint(&updates);
    assert_eq!(h.remote, Endpoint::new(Ipv4Addr::new(192, 168, 1, 7), 7777));
    assert_eq!(h.expires_at_ms, 5_100);
    assert_eq!(h.source, HintSource::Mdns);
    assert_eq!(h.scope, CandidateScope::Lan(scope()));
}
#[test]
fn wrong_key_version_missing_or_invalid_address_and_bad_txt_are_refused() {
    let mut lan = LanDiscovery::new(key());
    let mut wrong_key = observation("peer");
    wrong_key.txt = LanAdvertisement::new(
        DiscoveryPublicKey::from_bytes([8; 32]),
        Endpoint::new(wrong_key.addresses[0], 7777),
    )
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
        assert_eq!(
            LanDiscovery::new(key()).observe(obs, 0),
            Err(LanError::Address)
        );
    }
    assert!(LanAdvertisement::new(key(), Endpoint::new(Ipv4Addr::new(10, 0, 0, 1), 0)).is_err());
}
#[test]
fn refresh_preserves_identity_and_changed_endpoint_replaces_only_its_observation() {
    let mut lan = LanDiscovery::new(key());
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
    assert_eq!(updates[0], DiscoveryUpdate::Remove(first.observation_id));
    assert_ne!(hint(&updates).observation_id, first.observation_id);
    assert_eq!(
        lan.remove("alias", scope()),
        vec![DiscoveryUpdate::Remove(alias.observation_id)]
    );
    assert_eq!(lan.observation_count(), 1);
}
#[test]
fn goodbye_expiry_and_interface_generation_revocation_are_source_specific() {
    let mut lan = LanDiscovery::new(key());
    let first = hint(&lan.observe(observation("peer"), 0).unwrap());
    let mut new_scope = observation("peer");
    new_scope.scope.generation += 1;
    let second = hint(&lan.observe(new_scope, 100).unwrap());
    assert_eq!(
        lan.revoke_interface(scope()),
        vec![DiscoveryUpdate::Remove(first.observation_id)]
    );
    assert!(lan.revoke_interface(scope()).is_empty());
    assert_eq!(lan.observation_count(), 1);
    assert_eq!(
        lan.expire(5_100),
        vec![DiscoveryUpdate::Remove(second.observation_id)]
    );
    let third = hint(&lan.observe(observation("peer"), 6_000).unwrap());
    let mut goodbye = observation("peer");
    goodbye.ttl_ms = 0;
    goodbye.txt.clear();
    goodbye.addresses.clear();
    assert_eq!(
        lan.observe(goodbye.clone(), 6_001).unwrap(),
        vec![DiscoveryUpdate::Remove(third.observation_id)]
    );
    assert!(lan.observe(goodbye, 6_002).unwrap().is_empty());
}
#[test]
fn observation_and_unique_scoped_candidate_limits_and_ttl_cap_are_enforced() {
    let mut lan = LanDiscovery::new(key());
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
