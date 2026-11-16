//! Bounded, sans-I/O Bonjour hint validation. No DNS packet parsing or native FFI.
//!
//! The adapter supplies complete normalized resolutions. Incomplete resolutions
//! are not retained here; native resolution caches must also be bounded.
//! Subnet, own-address and route checks remain service/protocol responsibilities.
//!
//! Several pinned peers may advertise at once. Every observation is resolved to
//! exactly one relationship through its `pk` TXT field, and every update carries
//! that relationship so a hint can only ever reach the engine that owns it.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};

use lzh_hole_types::{DiscoveryPublicKey, Endpoint, RelationshipId};

use crate::observation::{
    CandidateHint, CandidateScope, DiscoveryOrigin, DiscoveryUpdate, HintSource, LanScope,
    ObservationId,
};

pub const LAN_SERVICE_TYPE: &str = "_lzh-hole._udp.local.";
pub const MAX_LAN_OBSERVATIONS: usize = 32;
pub const MAX_LAN_CANDIDATES: usize = 16;
pub const MAX_LAN_TXT_BYTES: usize = 512;
pub const MAX_LAN_TTL_MS: u64 = 120_000;
const MAX_INSTANCE_BYTES: usize = 255;
const MAX_RESOLVED_ADDRESSES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LanError {
    #[error("malformed or oversized mDNS observation")]
    Malformed,
    #[error("unsupported advertisement version")]
    Version,
    #[error("advertisement is not for the pinned peer")]
    WrongPeer,
    #[error("advertised endpoint is not an RFC1918 A-record address")]
    Address,
    #[error("LAN discovery capacity reached")]
    Capacity,
}

#[cfg(test)]
mod tests;

/// One update together with the relationship whose `pk` produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LanUpdate {
    pub relationship_id: RelationshipId,
    pub update: DiscoveryUpdate,
}

/// DNS TXT wire bytes: length-prefixed strings, not a delimiter-joined string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanAdvertisement {
    pub address: Ipv4Addr,
    pub port: u16,
    pub txt: Vec<u8>,
}

impl LanAdvertisement {
    /// Call only with an address/port actually bound on the advertised interface.
    /// This pure layer cannot inspect the socket.
    pub fn new(key: DiscoveryPublicKey, bound: Endpoint) -> Result<Self, LanError> {
        if !bound.ip.is_private() || bound.port == 0 {
            return Err(LanError::Address);
        }
        let mut txt = Vec::new();
        for field in [
            "v=1".to_owned(),
            format!("pk={key}"),
            format!("addr={}", bound.ip),
        ] {
            txt.push(field.len() as u8);
            txt.extend_from_slice(field.as_bytes());
        }
        Ok(Self {
            address: bound.ip,
            port: bound.port,
            txt,
        })
    }
}

/// One SRV/TXT/A resolution, scoped to its receiving interface, not DNS aliases.
#[derive(Debug, Clone)]
pub struct LanObservation {
    pub instance: String,
    pub scope: LanScope,
    pub addresses: Vec<Ipv4Addr>,
    pub port: u16,
    pub txt: Vec<u8>,
    /// Zero is a goodbye/removal. Other TTLs are capped locally.
    pub ttl_ms: u64,
}

/// A retained observation plus the relationship its `pk` resolved to.
#[derive(Debug, Clone, Copy)]
struct LanEntry {
    relationship_id: RelationshipId,
    hint: CandidateHint,
}

#[derive(Debug)]
pub struct LanDiscovery {
    pinned: BTreeMap<DiscoveryPublicKey, RelationshipId>,
    observations: BTreeMap<(LanScope, String), LanEntry>,
    next_id: u64,
}

impl LanDiscovery {
    pub fn new(pinned: BTreeMap<DiscoveryPublicKey, RelationshipId>) -> Self {
        Self {
            pinned,
            observations: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// `now_ms` must use the same monotonic clock for every call.
    /// Call `expire` on the service timer, even when no observations arrive.
    pub fn observe(
        &mut self,
        observation: LanObservation,
        now_ms: u64,
    ) -> Result<Vec<LanUpdate>, LanError> {
        if observation.instance.is_empty()
            || observation.instance.len() > MAX_INSTANCE_BYTES
            || observation
                .instance
                .bytes()
                .any(|b| b == 0 || b.is_ascii_control())
            || observation.scope.interface == 0
        {
            return Err(LanError::Malformed);
        }
        if observation.ttl_ms == 0 {
            return Ok(self.remove(&observation.instance, observation.scope));
        }
        let (relationship_id, remote) = self.validate(&observation)?;
        let key = (observation.scope, observation.instance);
        let existing = self.observations.get(&key).copied();
        // Capacity is counted per relationship on purpose: one chatty peer must
        // not be able to exhaust the observation or candidate budget that the
        // other pinned relationships depend on. Reaching the limit for one
        // relationship only refuses that relationship's new observations.
        if existing.is_none() && self.observation_count_for(relationship_id) >= MAX_LAN_OBSERVATIONS
        {
            return Err(LanError::Capacity);
        }
        let scope = CandidateScope::Lan(observation.scope);
        let distinct: BTreeSet<_> = self
            .observations
            .iter()
            .filter(|(k, entry)| **k != key && entry.relationship_id == relationship_id)
            .map(|(_, entry)| (entry.hint.scope, entry.hint.remote))
            .chain(std::iter::once((scope, remote)))
            .collect();
        if distinct.len() > MAX_LAN_CANDIDATES {
            return Err(LanError::Capacity);
        }
        let mut updates = Vec::new();
        let id = match existing {
            // A different endpoint or a different relationship is a different
            // path: an observation id is never handed from one relationship to
            // another, because the two engines key their registries separately.
            Some(old) if old.hint.remote == remote && old.relationship_id == relationship_id => {
                old.hint.observation_id
            }
            old => {
                let serial = self.next_id;
                self.next_id = serial.checked_add(1).ok_or(LanError::Capacity)?;
                if let Some(old) = old {
                    updates.push(LanUpdate {
                        relationship_id: old.relationship_id,
                        update: DiscoveryUpdate::Remove(old.hint.observation_id),
                    });
                }
                ObservationId {
                    origin: DiscoveryOrigin::Lan,
                    serial,
                }
            }
        };
        let hint = CandidateHint {
            remote,
            scope,
            observation_id: id,
            expires_at_ms: now_ms.saturating_add(observation.ttl_ms.min(MAX_LAN_TTL_MS)),
            source: HintSource::Mdns,
        };
        self.observations.insert(
            key,
            LanEntry {
                relationship_id,
                hint,
            },
        );
        updates.push(LanUpdate {
            relationship_id,
            update: DiscoveryUpdate::Upsert(hint),
        });
        Ok(updates)
    }

    /// Resolve the advertising key to its pinned relationship, then validate the
    /// rest of the advertisement exactly as before.
    fn validate(
        &self,
        observation: &LanObservation,
    ) -> Result<(RelationshipId, Endpoint), LanError> {
        if observation.txt.len() > MAX_LAN_TXT_BYTES
            || observation.addresses.len() > MAX_RESOLVED_ADDRESSES
            || observation.port == 0
        {
            return Err(LanError::Malformed);
        }
        let mut fields = BTreeMap::new();
        let mut remaining = observation.txt.as_slice();
        while let Some((&length, tail)) = remaining.split_first() {
            let length = usize::from(length);
            if length == 0 || tail.len() < length {
                return Err(LanError::Malformed);
            }
            let field = std::str::from_utf8(&tail[..length]).map_err(|_| LanError::Malformed)?;
            let (key, value) = field.split_once('=').ok_or(LanError::Malformed)?;
            if key.is_empty() || fields.insert(key, value).is_some() {
                return Err(LanError::Malformed);
            }
            remaining = &tail[length..];
        }
        if fields.get("v") != Some(&"1") {
            return Err(LanError::Version);
        }
        let advertised = fields.get("pk").copied().ok_or(LanError::WrongPeer)?;
        let relationship_id = self
            .pinned
            .iter()
            .find(|(key, _)| key.to_string() == advertised)
            .map(|(_, relationship_id)| *relationship_id)
            .ok_or(LanError::WrongPeer)?;
        let address = fields
            .get("addr")
            .ok_or(LanError::Address)?
            .parse::<Ipv4Addr>()
            .map_err(|_| LanError::Address)?;
        if !address.is_private() || !observation.addresses.contains(&address) {
            return Err(LanError::Address);
        }
        Ok((relationship_id, Endpoint::new(address, observation.port)))
    }

    pub fn remove(&mut self, instance: &str, scope: LanScope) -> Vec<LanUpdate> {
        self.observations
            .remove(&(scope, instance.to_owned()))
            .map(|entry| {
                vec![LanUpdate {
                    relationship_id: entry.relationship_id,
                    update: DiscoveryUpdate::Remove(entry.hint.observation_id),
                }]
            })
            .unwrap_or_default()
    }

    /// Revoke only this generation; a stale callback cannot revoke a new one.
    pub fn revoke_interface(&mut self, scope: LanScope) -> Vec<LanUpdate> {
        self.remove_where(|hint| hint.scope == CandidateScope::Lan(scope))
    }

    pub fn expire(&mut self, now_ms: u64) -> Vec<LanUpdate> {
        self.remove_where(|hint| hint.expires_at_ms <= now_ms)
    }

    fn remove_where(&mut self, predicate: impl Fn(&CandidateHint) -> bool) -> Vec<LanUpdate> {
        let mut updates = Vec::new();
        self.observations.retain(|_, entry| {
            if predicate(&entry.hint) {
                updates.push(LanUpdate {
                    relationship_id: entry.relationship_id,
                    update: DiscoveryUpdate::Remove(entry.hint.observation_id),
                });
                false
            } else {
                true
            }
        });
        updates
    }

    pub fn observation_count(&self) -> usize {
        self.observations.len()
    }

    pub fn observation_count_for(&self, relationship_id: RelationshipId) -> usize {
        self.observations
            .values()
            .filter(|entry| entry.relationship_id == relationship_id)
            .count()
    }
}
