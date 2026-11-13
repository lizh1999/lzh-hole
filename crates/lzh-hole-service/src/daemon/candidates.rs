//! Bounded discovery eligibility, separate from authenticated path lifetime.

use std::collections::BTreeMap;

use lzh_hole_discovery::{
    CandidateHint, CandidateScope, DiscoveryOrigin, DiscoveryUpdate, LanScope, ObservationId,
};
use lzh_hole_protocol::path::{PathCandidate, PathEndpoint, PathKind};
use lzh_hole_types::{Endpoint, TransportId};

const MAX_OBSERVATIONS: usize = 64;
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
    observations: BTreeMap<ObservationId, Observation>,
    pub counters: RegistryCounters,
}

impl CandidateRegistry {
    pub fn apply(&mut self, update: DiscoveryUpdate, transports: &[CandidateTransport]) {
        match update {
            DiscoveryUpdate::Remove(id) => {
                if self.observations.remove(&id).is_some() {
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
                if !valid
                    || (!self.observations.contains_key(&hint.observation_id)
                        && self.observations.len() >= MAX_OBSERVATIONS)
                {
                    self.counters.rejected_updates =
                        self.counters.rejected_updates.saturating_add(1);
                    return;
                }
                self.observations.insert(
                    hint.observation_id,
                    Observation {
                        hint,
                        lan_transports: matching,
                    },
                );
                self.counters.accepted_updates = self.counters.accepted_updates.saturating_add(1);
            }
        }
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
    pub fn project(
        &self,
        transports: &[CandidateTransport],
        now_ms: u64,
        mut route_allowed: impl FnMut(CandidateTransport, CandidateHint) -> bool,
    ) -> Vec<PathCandidate> {
        let mut candidates = BTreeMap::new();
        for observation in self.observations.values() {
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
                candidates
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
        let mut candidates = candidates.into_values().collect::<Vec<_>>();
        candidates.sort_by_key(|candidate| candidate.kind != PathKind::Lan);
        candidates.truncate(MAX_PROJECTED);
        candidates
    }
}

#[cfg(test)]
mod tests {
    use lzh_hole_discovery::HintSource;
    use std::net::Ipv4Addr;

    use super::*;

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

    #[test]
    fn withdrawal_expiry_and_transport_recreation_are_source_specific() {
        let original = transport(1, 14, 1, [192, 168, 31, 156]);
        let mut registry = CandidateRegistry::default();
        let first = hint(1, original);
        let mut second = hint(2, original);
        second.expires_at_ms = 200;
        registry.apply(DiscoveryUpdate::Upsert(first), &[original]);
        registry.apply(DiscoveryUpdate::Upsert(second), &[original]);
        registry.apply(DiscoveryUpdate::Remove(first.observation_id), &[original]);
        assert_eq!(registry.project(&[original], 100, |_, _| true).len(), 1);
        let replacement = transport(2, 14, 1, [192, 168, 31, 156]);
        assert!(
            registry
                .project(&[replacement], 100, |_, _| true)
                .is_empty()
        );
        let new_generation = transport(1, 14, 2, [192, 168, 31, 156]);
        assert!(
            registry
                .project(&[new_generation], 100, |_, _| true)
                .is_empty()
        );
        registry.expire(200);
        assert_eq!(registry.counters.withdrawals, 2);
    }

    #[test]
    fn both_origins_require_source_specific_actual_routes() {
        let aliases = [
            transport(1, 14, 1, [192, 168, 1, 2]),
            transport(2, 14, 1, [192, 168, 31, 156]),
            transport(3, 18, 2, [192, 168, 31, 8]),
        ];
        let mut registry = CandidateRegistry::default();
        registry.apply(DiscoveryUpdate::Upsert(hint(1, aliases[0])), &aliases);
        let projected = registry.project(&aliases, 1, |local, hint| {
            local.local.ip.octets()[..3] == hint.remote.ip.octets()[..3]
        });
        assert_eq!(projected.len(), 1);
        assert_eq!(projected[0].path.transport, TransportId(2));
        let public = CandidateHint {
            remote: Endpoint::new(Ipv4Addr::new(8, 8, 4, 4), 50000),
            scope: CandidateScope::Public,
            observation_id: ObservationId {
                origin: DiscoveryOrigin::Public,
                serial: 1,
            },
            expires_at_ms: 100,
            source: HintSource::VerifiedContactRecord,
        };
        registry.apply(DiscoveryUpdate::Upsert(public), &aliases);
        assert!(registry.project(&aliases, 1, |_, _| false).is_empty());
        assert!(registry.project(&[], 1, |_, _| true).is_empty());
    }
}
