//! Bounded discovery eligibility, separate from authenticated path lifetime.
//!
//! Every observation belongs to exactly one relationship, and that attribution
//! is the whole point of this layer in a mesh: a hint learned from peer A's
//! signed contact record or Bonjour advertisement may only ever be projected
//! into the engine that owns A's relationship. Routing a hint to the wrong
//! engine would make one peer's address a target for another peer's session.
//!
//! Capacity is counted per relationship on purpose. A single chatty peer must
//! not be able to exhaust the observation or projection budget that the other
//! pinned relationships depend on.

use std::collections::BTreeMap;

use lzh_hole_discovery::{
    CandidateHint, CandidateScope, DiscoveryOrigin, DiscoveryUpdate, LanScope, ObservationId,
};
use lzh_hole_protocol::path::{PathCandidate, PathEndpoint, PathKind};
use lzh_hole_types::{Endpoint, RelationshipId, TransportId};

/// Observations retained per relationship.
const MAX_OBSERVATIONS: usize = 64;
/// Paths projected per relationship, per reprojection.
const MAX_PROJECTED: usize = 16;

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct RegistryCounters {
    pub accepted_updates: u64,
    pub rejected_updates: u64,
    pub withdrawals: u64,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct CandidateTransport {
    pub id: TransportId,
    pub scope: LanScope,
    pub local: Endpoint,
}

#[derive(Debug)]
struct Observation {
    hint: CandidateHint,
    /// Capture actual socket identities when accepting a LAN observation. An
    /// old observation cannot authorize a replacement socket, even on an alias
    /// with the same interface index and address.
    lan_transports: Vec<TransportId>,
}

#[derive(Debug, Default)]
pub(super) struct CandidateRegistry {
    observations: BTreeMap<(RelationshipId, ObservationId), Observation>,
    pub counters: RegistryCounters,
}

impl CandidateRegistry {
    /// Record one update against the relationship that produced it.
    ///
    /// The relationship is supplied by the caller because it is authenticated
    /// context, not something a hint can claim: a Bonjour update carries the
    /// relationship resolved from the advertisement's pinned peer key, and a
    /// public update carries the relationship of the ntfy stream it arrived on.
    pub fn apply(
        &mut self,
        relationship_id: RelationshipId,
        update: DiscoveryUpdate,
        transports: &[CandidateTransport],
    ) {
        match update {
            DiscoveryUpdate::Remove(id) => {
                if self.observations.remove(&(relationship_id, id)).is_some() {
                    self.counters.withdrawals = self.counters.withdrawals.saturating_add(1);
                }
            }
            DiscoveryUpdate::Upsert(hint) => {
                let matching = transports
                    .iter()
                    .filter(|transport| hint.scope == CandidateScope::Lan(transport.scope))
                    .map(|transport| transport.id)
                    .collect::<Vec<_>>();
                let valid = hint.remote.port != 0
                    && match hint.scope {
                        CandidateScope::Lan(scope) => {
                            hint.observation_id.origin == DiscoveryOrigin::Lan
                                && scope.interface != 0
                                && lzh_hole_discovery::candidate::is_private(hint.remote.ip)
                                && !matching.is_empty()
                        }
                        CandidateScope::Public => {
                            hint.observation_id.origin == DiscoveryOrigin::Public
                                && lzh_hole_discovery::candidate::classify(hint.remote.ip).is_none()
                        }
                    };
                let key = (relationship_id, hint.observation_id);
                let fresh = !self.observations.contains_key(&key);
                if !valid || (fresh && self.observation_count(relationship_id) >= MAX_OBSERVATIONS)
                {
                    self.counters.rejected_updates =
                        self.counters.rejected_updates.saturating_add(1);
                    return;
                }
                self.observations.insert(
                    key,
                    Observation {
                        hint,
                        lan_transports: matching,
                    },
                );
                self.counters.accepted_updates = self.counters.accepted_updates.saturating_add(1);
            }
        }
    }

    /// Observations currently held for one relationship.
    pub fn observation_count(&self, relationship_id: RelationshipId) -> usize {
        self.observations
            .keys()
            .filter(|(owner, _)| *owner == relationship_id)
            .count()
    }

    pub fn expire(&mut self, now_ms: u64) {
        let before = self.observations.len();
        self.observations
            .retain(|_, observation| now_ms < observation.hint.expires_at_ms);
        self.counters.withdrawals = self
            .counters
            .withdrawals
            .saturating_add((before - self.observations.len()) as u64);
    }

    /// Route checks apply to BOTH origins: same-link source-specific route for
    /// LAN, actual same-interface public route for public hints.
    ///
    /// Each relationship is projected and truncated on its own, so one peer
    /// filling the projection budget cannot starve another peer's paths.
    pub fn project(
        &self,
        transports: &[CandidateTransport],
        now_ms: u64,
        mut route_allowed: impl FnMut(CandidateTransport, CandidateHint) -> bool,
    ) -> BTreeMap<RelationshipId, Vec<PathCandidate>> {
        let mut per_relationship: BTreeMap<
            RelationshipId,
            BTreeMap<(TransportId, Endpoint), PathCandidate>,
        > = BTreeMap::new();
        for ((relationship_id, _), observation) in &self.observations {
            let hint = observation.hint;
            if now_ms >= hint.expires_at_ms {
                continue;
            }
            for transport in transports {
                if hint.remote == transport.local
                    || matches!(hint.scope, CandidateScope::Lan(scope)
                        if scope != transport.scope
                            || !observation.lan_transports.contains(&transport.id))
                    || !route_allowed(*transport, hint)
                {
                    continue;
                }
                per_relationship
                    .entry(*relationship_id)
                    .or_default()
                    .entry((transport.id, hint.remote))
                    .or_insert(PathCandidate {
                        path: PathEndpoint {
                            transport: transport.id,
                            remote: hint.remote,
                        },
                        kind: match hint.scope {
                            CandidateScope::Lan(_) => PathKind::Lan,
                            CandidateScope::Public => PathKind::Public,
                        },
                    });
            }
        }
        per_relationship
            .into_iter()
            .map(|(relationship_id, candidates)| {
                let mut candidates = candidates.into_values().collect::<Vec<_>>();
                candidates.sort_by_key(|candidate| candidate.kind != PathKind::Lan);
                candidates.truncate(MAX_PROJECTED);
                (relationship_id, candidates)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use lzh_hole_discovery::HintSource;
    use std::net::Ipv4Addr;

    use super::*;

    fn relationship(byte: u8) -> RelationshipId {
        RelationshipId::from_bytes([byte; 16])
    }

    fn transport(id: u64, index: u32, generation: u64, ip: [u8; 4]) -> CandidateTransport {
        CandidateTransport {
            id: TransportId(id),
            scope: LanScope {
                interface: index,
                generation,
            },
            local: Endpoint::new(Ipv4Addr::from(ip), 51000),
        }
    }

    fn hint(serial: u64, transport: CandidateTransport) -> CandidateHint {
        CandidateHint {
            remote: Endpoint::new(Ipv4Addr::new(192, 168, 31, 7), 51000),
            scope: CandidateScope::Lan(transport.scope),
            observation_id: ObservationId {
                origin: DiscoveryOrigin::Lan,
                serial,
            },
            expires_at_ms: 100,
            source: HintSource::Mdns,
        }
    }

    fn public_hint(serial: u64, remote: [u8; 4], expires_at_ms: u64) -> CandidateHint {
        CandidateHint {
            remote: Endpoint::new(Ipv4Addr::from(remote), 51000),
            scope: CandidateScope::Public,
            observation_id: ObservationId {
                origin: DiscoveryOrigin::Public,
                serial,
            },
            expires_at_ms,
            source: HintSource::VerifiedContactRecord,
        }
    }

    #[test]
    fn withdrawal_expiry_and_transport_recreation_are_source_specific() {
        let original = transport(1, 14, 1, [192, 168, 31, 156]);
        let mut registry = CandidateRegistry::default();
        let first = hint(1, original);
        let mut second = hint(2, original);
        second.expires_at_ms = 200;
        registry.apply(relationship(1), DiscoveryUpdate::Upsert(first), &[original]);
        registry.apply(
            relationship(1),
            DiscoveryUpdate::Upsert(second),
            &[original],
        );
        registry.apply(
            relationship(1),
            DiscoveryUpdate::Remove(first.observation_id),
            &[original],
        );
        assert_eq!(
            registry
                .project(&[original], 100, |_, _| true)
                .get(&relationship(1))
                .map(Vec::len),
            Some(1)
        );
        let replacement = transport(2, 14, 1, [192, 168, 31, 156]);
        assert!(
            registry
                .project(&[replacement], 100, |_, _| true)
                .get(&relationship(1))
                .is_none_or(Vec::is_empty),
            "an old LAN observation must not authorize a replacement socket"
        );
    }

    #[test]
    fn a_hint_is_only_ever_projected_into_its_own_relationship() {
        let socket = transport(1, 14, 1, [192, 168, 31, 156]);
        let mut registry = CandidateRegistry::default();
        let a = public_hint(1, [210, 22, 105, 194], 500);
        // 203.0.113.0/24 is TEST-NET-3 and is refused as a public candidate,
        // so peer B needs a genuinely global unicast address here.
        let b = public_hint(1, [210, 22, 105, 193], 500);
        // Deliberately the same observation id under two relationships: ids are
        // allocated per discovery source, so only the pair is unique.
        registry.apply(relationship(0xa1), DiscoveryUpdate::Upsert(a), &[socket]);
        registry.apply(relationship(0xb2), DiscoveryUpdate::Upsert(b), &[socket]);

        let projected = registry.project(&[socket], 100, |_, _| true);
        assert_eq!(projected.len(), 2);
        let for_a = &projected[&relationship(0xa1)];
        let for_b = &projected[&relationship(0xb2)];
        assert_eq!(for_a.len(), 1);
        assert_eq!(for_b.len(), 1);
        assert_eq!(for_a[0].path.remote, a.remote);
        assert_eq!(for_b[0].path.remote, b.remote);
        assert!(
            !for_a.iter().any(|c| c.path.remote == b.remote),
            "peer A's engine must never see peer B's candidate"
        );

        // Removing one relationship's hint leaves the other's intact.
        registry.apply(
            relationship(0xa1),
            DiscoveryUpdate::Remove(a.observation_id),
            &[socket],
        );
        let projected = registry.project(&[socket], 100, |_, _| true);
        assert!(!projected.contains_key(&relationship(0xa1)));
        assert_eq!(projected[&relationship(0xb2)].len(), 1);
    }

    #[test]
    fn one_relationship_cannot_exhaust_another_relationships_capacity() {
        let socket = transport(1, 14, 1, [192, 168, 31, 156]);
        let mut registry = CandidateRegistry::default();
        for serial in 0..MAX_OBSERVATIONS as u64 {
            let hint = public_hint(serial, [210, 22, 105, 194], 500);
            let hint = CandidateHint {
                remote: Endpoint::new(Ipv4Addr::new(210, 22, 105, 194), 51000 + serial as u16),
                ..hint
            };
            registry.apply(relationship(0xa1), DiscoveryUpdate::Upsert(hint), &[socket]);
        }
        assert_eq!(
            registry.observation_count(relationship(0xa1)),
            MAX_OBSERVATIONS
        );

        // The full relationship refuses more.
        let overflow = public_hint(9_000, [210, 22, 105, 194], 500);
        let overflow = CandidateHint {
            remote: Endpoint::new(Ipv4Addr::new(210, 22, 105, 194), 60000),
            ..overflow
        };
        let before = registry.counters.rejected_updates;
        registry.apply(
            relationship(0xa1),
            DiscoveryUpdate::Upsert(overflow),
            &[socket],
        );
        assert_eq!(registry.counters.rejected_updates, before + 1);
        assert_eq!(
            registry.observation_count(relationship(0xa1)),
            MAX_OBSERVATIONS
        );

        // A different relationship is unaffected.
        registry.apply(
            relationship(0xb2),
            DiscoveryUpdate::Upsert(overflow),
            &[socket],
        );
        assert_eq!(registry.observation_count(relationship(0xb2)), 1);
        assert_eq!(
            registry.observation_count(relationship(0xa1)),
            MAX_OBSERVATIONS
        );
    }

    #[test]
    fn projection_is_truncated_per_relationship_not_globally() {
        let socket = transport(1, 14, 1, [192, 168, 31, 156]);
        let mut registry = CandidateRegistry::default();
        for serial in 0..(MAX_PROJECTED as u64 + 8) {
            let hint = CandidateHint {
                remote: Endpoint::new(Ipv4Addr::new(210, 22, 105, 194), 51000 + serial as u16),
                ..public_hint(serial, [210, 22, 105, 194], 500)
            };
            registry.apply(relationship(0xa1), DiscoveryUpdate::Upsert(hint), &[socket]);
        }
        let lone = public_hint(77, [210, 22, 105, 193], 500);
        registry.apply(relationship(0xb2), DiscoveryUpdate::Upsert(lone), &[socket]);

        let projected = registry.project(&[socket], 100, |_, _| true);
        assert_eq!(projected[&relationship(0xa1)].len(), MAX_PROJECTED);
        assert_eq!(
            projected[&relationship(0xb2)].len(),
            1,
            "a saturated relationship must not consume another relationship's projection budget"
        );
    }

    #[test]
    fn lan_and_public_hints_are_validated_by_their_own_rules() {
        let socket = transport(1, 14, 1, [192, 168, 31, 156]);
        let mut registry = CandidateRegistry::default();

        // A LAN hint that is not an RFC1918 address is refused.
        let mut bogus_lan = hint(1, socket);
        bogus_lan.remote = Endpoint::new(Ipv4Addr::new(210, 22, 105, 194), 51000);
        let before = registry.counters.rejected_updates;
        registry.apply(
            relationship(1),
            DiscoveryUpdate::Upsert(bogus_lan),
            &[socket],
        );
        assert_eq!(registry.counters.rejected_updates, before + 1);

        // A public hint that is not public unicast is refused.
        let mut bogus_public = public_hint(1, [192, 168, 31, 7], 500);
        bogus_public.observation_id.origin = DiscoveryOrigin::Public;
        let before = registry.counters.rejected_updates;
        registry.apply(
            relationship(1),
            DiscoveryUpdate::Upsert(bogus_public),
            &[socket],
        );
        assert_eq!(registry.counters.rejected_updates, before + 1);

        // Port zero is refused for both.
        let mut zero_port = public_hint(2, [210, 22, 105, 194], 500);
        zero_port.remote = Endpoint::new(Ipv4Addr::new(210, 22, 105, 194), 0);
        let before = registry.counters.rejected_updates;
        registry.apply(
            relationship(1),
            DiscoveryUpdate::Upsert(zero_port),
            &[socket],
        );
        assert_eq!(registry.counters.rejected_updates, before + 1);
        assert_eq!(registry.observation_count(relationship(1)), 0);
    }

    #[test]
    fn expired_hints_are_not_projected_and_are_counted_as_withdrawals() {
        let socket = transport(1, 14, 1, [192, 168, 31, 156]);
        let mut registry = CandidateRegistry::default();
        let hint = public_hint(1, [210, 22, 105, 194], 100);
        registry.apply(relationship(1), DiscoveryUpdate::Upsert(hint), &[socket]);

        assert!(
            registry
                .project(&[socket], 100, |_, _| true)
                .get(&relationship(1))
                .is_none_or(Vec::is_empty)
        );
        let before = registry.counters.withdrawals;
        registry.expire(100);
        assert_eq!(registry.counters.withdrawals, before + 1);
        assert_eq!(registry.observation_count(relationship(1)), 0);
    }
}
