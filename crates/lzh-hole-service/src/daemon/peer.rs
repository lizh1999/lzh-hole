//! One pinned peer's runtime state.
//!
//! Everything in here is scoped to exactly one relationship. A mesh node shares
//! its physical sockets, its STUN measurements and its identity key across every
//! peer, and shares nothing else: each peer owns its own coordination topic,
//! its own anti-rollback high-water cache, its own durable sequence stream, its
//! own request/reply correlation and its own advisory flags.
//!
//! The split is what keeps one peer from being able to affect another. A record
//! signed by peer A can only ever move A's high-water mark; a request A never
//! answered can only ever consume A's correlation table; a sequence reserved for
//! A is only ever compared against A's own stream.

use std::net::Ipv4Addr;

use ed25519_dalek::SigningKey;
use lzh_hole_control::{ByteCounters, ComponentState, ComponentStatus, DropCounters};
use lzh_hole_discovery::candidate::CandidateSource;
use lzh_hole_discovery::peer_record::PeerRecordPolicy;
use lzh_hole_discovery::record::{
    ContactRecord, FLAG_PUNCH_OFFER, MAX_LIFETIME_MS, RecordCandidate, reserve_sequence,
};
use lzh_hole_discovery::{
    Delivery, DiscoveryUpdate, ExchangeAction, ExchangeTracker, MessageKind, NtfyHandle,
    PeerPublic, PublicAcceptError, PublicDiscovery, RequestId, SignedPayload, VerifiedPayload,
};
use lzh_hole_protocol::mesh::PeerSet;
use lzh_hole_store::{PeerRecordCache, Relationship, StateDir};
use lzh_hole_types::{BootId, DiscoveryPublicKey, Endpoint, RelationshipId};

use super::discovery::NtfyBlock;
use super::status::component;
use super::transport::TransportSet;
use super::{DaemonError, now_unix_ms, now_unix_us, publication_endpoints};

/// One relationship's view of the node's single ntfy actor.
///
/// There is exactly one actor per host, serving every relationship's topic, so
/// the handle, the event stream and the task are node-level and every event
/// carries the relationship it belongs to. What stays per relationship is only
/// the observed status: whether this relationship's stream is subscribed,
/// whether a persisted Retry-After boundary currently blocks it, and the latest
/// truthful diagnostic.
///
/// Sharing one actor is what keeps the per-host 30 second operation interval and
/// the rolling 24 hour budget honest. Eight relationships served by eight actors
/// would multiply both by eight against the same host.
#[derive(Debug, Default)]
pub(super) struct PeerNtfy {
    pub subscribed: bool,
    pub block: Option<NtfyBlock>,
    pub status: ComponentStatus,
}

impl PeerNtfy {
    pub fn starting(detail: &str) -> Self {
        Self {
            status: component(ComponentState::Starting, detail, None),
            ..Self::default()
        }
    }

    pub fn not_configured(detail: &str) -> Self {
        Self {
            status: component(ComponentState::NotConfigured, detail, None),
            ..Self::default()
        }
    }

    /// Whether a persisted Retry-After boundary currently blocks this
    /// relationship's coordination.
    pub fn waiting(&self) -> bool {
        self.block
            .as_ref()
            .is_some_and(|block| block.not_before_unix_ms > now_unix_ms())
    }

    /// Fold the newest diagnostic into the status, keeping an active
    /// Retry-After boundary visible instead of letting a later message hide it.
    pub fn degraded(&self, latest: String) -> ComponentStatus {
        let now = now_unix_ms();
        if let Some(block) = self
            .block
            .as_ref()
            .filter(|block| block.not_before_unix_ms > now)
        {
            let latest = if latest == block.detail {
                String::new()
            } else {
                format!("; latest: {latest}")
            };
            return component(
                ComponentState::Degraded,
                format!(
                    "{}{latest}; ntfy operations blocked until unix ms {}",
                    block.detail, block.not_before_unix_ms
                ),
                self.status.last_success_unix_ms,
            );
        }
        component(
            ComponentState::Degraded,
            latest,
            self.status.last_success_unix_ms,
        )
    }

    pub fn write_detail(&mut self, detail: String) {
        if self.waiting() {
            self.status = self.degraded(detail);
        } else {
            self.status.detail = Some(detail);
        }
    }

    /// Record a server-supplied Retry-After without ever moving the boundary
    /// earlier than one already persisted.
    pub fn note_retry_after(&mut self, latest: String, delay: std::time::Duration) {
        if delay.is_zero() {
            return;
        }
        let now = now_unix_ms();
        let delay_ms = delay.as_millis().min(u64::MAX as u128) as u64;
        let proposed = now.saturating_add(delay_ms);
        let previous = self
            .block
            .as_ref()
            .filter(|block| block.not_before_unix_ms > now);
        let not_before_unix_ms = previous
            .map(|block| block.not_before_unix_ms.max(proposed))
            .unwrap_or(proposed);
        let detail = previous.map(|block| block.detail.clone()).unwrap_or(latest);
        self.block = Some(NtfyBlock {
            detail,
            not_before_unix_ms,
        });
    }

    pub fn clear_block(&mut self) {
        self.block = None;
    }
}

/// One pinned peer: its relationship, its coordination state and its counters.
#[derive(Debug)]
pub(super) struct PeerRuntime {
    /// Authenticated public pairing metadata, without the PSK.
    pub relationship: Relationship,
    /// Cached from `relationship`, which is read on every dispatch.
    pub relationship_id: RelationshipId,
    /// The one /32 host route this peer contributes.
    pub peer_vip: Ipv4Addr,
    /// The pinned peer discovery key.
    pub peer_key: DiscoveryPublicKey,
    /// This relationship's request/reply correlation.
    pub exchange: ExchangeTracker,
    /// This relationship's durable anti-rollback cache.
    pub peer_cache: PeerRecordCache,
    /// This relationship's slice of public coordination.
    pub public: PeerPublic,
    /// This relationship's view of the node's ntfy actor.
    pub ntfy: PeerNtfy,
    /// Coordination flags from this peer's last accepted contact record.
    pub peer_record_flags: u8,
    /// Expiry of this peer's last accepted contact record.
    pub peer_record_expires_ms: u64,
    /// Dataplane bytes attributed to this peer.
    pub bytes: ByteCounters,
    /// Dataplane drops attributed to this peer.
    pub drops: DropCounters,
    /// Last time this peer's session was actually healthy.
    pub last_healthy_unix_ms: Option<u64>,
}

impl PeerRuntime {
    pub fn new(
        state: &StateDir,
        relationship: Relationship,
        peer_vip: Ipv4Addr,
        ntfy: PeerNtfy,
    ) -> Result<Self, DaemonError> {
        let relationship_id = relationship.relationship_id;
        let peer_key = relationship.peer_public_key;
        let peer_cache = PeerRecordCache::load(&state.peer_record_path(relationship_id))?;
        Ok(Self {
            relationship,
            relationship_id,
            peer_vip,
            peer_key,
            exchange: ExchangeTracker::default(),
            peer_cache,
            public: PeerPublic::new(),
            ntfy,
            peer_record_flags: 0,
            peer_record_expires_ms: 0,
            bytes: ByteCounters::default(),
            drops: DropCounters::default(),
            last_healthy_unix_ms: None,
        })
    }

    pub fn record_drop(&mut self, reason: &str, count: u64) {
        let _ = self.drops.record(reason, count);
    }

    /// The policy a record must satisfy to be usable by this relationship.
    ///
    /// `forbidden_addresses` must contain this node's own overlay address and
    /// every peer's, not just this peer's: an overlay address is never a
    /// physical candidate target for anybody.
    pub fn record_policy(
        &self,
        self_key: DiscoveryPublicKey,
        now_unix_ms: u64,
        stun_servers: Vec<Endpoint>,
        own_endpoints: Vec<Endpoint>,
        forbidden_addresses: Vec<Ipv4Addr>,
    ) -> PeerRecordPolicy {
        let mut policy =
            PeerRecordPolicy::new(self.relationship_id, self_key, self.peer_key, now_unix_ms);
        policy.stun_servers = stun_servers;
        policy.own_endpoints = own_endpoints;
        policy.forbidden_addresses = forbidden_addresses;
        policy
    }

    /// This peer's engine snapshot, if the mesh is running.
    pub fn engine_snapshot(
        &self,
        engines: Option<&PeerSet>,
        now_unix_ms: u64,
    ) -> Option<lzh_hole_protocol::engine::EngineSnapshot> {
        engines?
            .get(self.relationship_id)
            .map(|engine| engine.snapshot(now_unix_ms))
    }
}

/// Node-level facts a relationship needs to build and publish its own record.
///
/// Passed by reference rather than reached through `Daemon` so the daemon can
/// hold `&mut` on one peer while still reading shared node state, and so the
/// per-relationship code cannot accidentally mutate node-level state.
pub(super) struct NodeFacts<'a> {
    pub ntfy_handle: Option<&'a NtfyHandle>,
    pub engines: Option<&'a PeerSet>,
    pub state: &'a StateDir,
    pub signing_key: &'a SigningKey,
    pub public: &'a PublicDiscovery,
    pub transports: &'a TransportSet,
    pub boot_id: BootId,
    pub generation: u64,
    pub self_key: DiscoveryPublicKey,
    pub stun_servers: Vec<Endpoint>,
    /// Every overlay address in the mesh: ours and every peer's.
    pub forbidden_addresses: Vec<Ipv4Addr>,
    pub monotonic_ms: u64,
    pub flags: u8,
    /// Signed-record expiry cap while THIS relationship's punch window is open.
    pub punch_offer_deadline: Option<u64>,
}

struct Publication {
    payload: SignedPayload,
    fallback: Option<SignedPayload>,
    expires_at_unix_ms: u64,
}

fn publication_validity(flags: u8, deadline: Option<u64>, now: u64) -> (u8, u64) {
    let normal_expiry = now.saturating_add(MAX_LIFETIME_MS);
    if flags & FLAG_PUNCH_OFFER != 0
        && let Some(deadline) = deadline
        && deadline
            > now.saturating_add(lzh_hole_discovery::transport::MIN_PUNCH_OFFER_REMAINING_MS)
    {
        return (flags, deadline.min(normal_expiry));
    }
    // A short/closed offer must not shorten the normal candidate advertisement.
    (flags & !FLAG_PUNCH_OFFER, normal_expiry)
}

impl NodeFacts<'_> {
    /// This node's own endpoints, which no peer's record may name as a target.
    pub fn own_endpoints(&self) -> Vec<Endpoint> {
        let mut endpoints = self
            .public
            .own_mappings(self.monotonic_ms)
            .into_iter()
            .map(|mapping| mapping.endpoint)
            .collect::<Vec<_>>();
        endpoints.extend(
            self.transports
                .iter()
                .map(|socket| super::endpoint(socket.local)),
        );
        endpoints.sort();
        endpoints.dedup();
        endpoints
    }

    /// Build, durably reserve and queue one signed payload for one relationship.
    ///
    /// Sequence persistence always precedes signing, and the sequence stream is
    /// this relationship's own: it is only ever compared against this peer's
    /// high-water mark, never against another relationship's.
    pub fn queue_payload(
        &self,
        peer: &mut PeerRuntime,
        kind: MessageKind,
        id: RequestId,
    ) -> Result<u64, String> {
        let publication = self.build_publication(peer, kind, id)?;
        let handle = self
            .ntfy_handle
            .ok_or_else(|| "ntfy transport is not running".to_owned())?;
        match publication.fallback {
            Some(fallback) => handle.try_publish_with_fallback(
                peer.relationship_id,
                publication.payload,
                fallback,
            ),
            None => handle.try_publish(peer.relationship_id, publication.payload),
        }
        .map_err(|error| error.to_string())?;
        Ok(publication.expires_at_unix_ms)
    }

    fn reserve_record_sequence(&self, peer: &PeerRuntime) -> Result<u64, String> {
        let durable = self
            .state
            .load_sequence(peer.relationship_id)
            .map_err(|error| error.to_string())?;
        let sequence = reserve_sequence(
            durable,
            peer.peer_cache.highest_seq().unwrap_or(0),
            now_unix_us(),
        )
        .map_err(|error| error.to_string())?;
        self.state
            .store_sequence(peer.relationship_id, sequence)
            .map_err(|error| error.to_string())?;
        Ok(sequence)
    }

    fn build_publication(
        &self,
        peer: &PeerRuntime,
        kind: MessageKind,
        id: RequestId,
    ) -> Result<Publication, String> {
        let candidates = publication_endpoints(self.public.own_mappings(self.monotonic_ms))
            .into_iter()
            .map(|endpoint| RecordCandidate {
                endpoint,
                source: CandidateSource::Stun,
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Err(
                "no fresh measured STUN mapping; refusing an empty contact record".to_owned(),
            );
        }
        let sequence = self.reserve_record_sequence(peer)?;
        let (flags, _) = publication_validity(self.flags, self.punch_offer_deadline, now_unix_ms());
        // A distinct higher sequence makes the alternative independently signed,
        // never a rewrite of an already signed snapshot. Reserve before signing.
        let fallback_sequence = if flags & FLAG_PUNCH_OFFER != 0 {
            Some(self.reserve_record_sequence(peer)?)
        } else {
            None
        };
        // Durable storage may block: issue time and offer admission follow it.
        let now = now_unix_ms();
        let (flags, expires_at) = publication_validity(flags, self.punch_offer_deadline, now);
        let sequence = if flags & FLAG_PUNCH_OFFER == 0 {
            fallback_sequence.unwrap_or(sequence)
        } else {
            sequence
        };
        let record = ContactRecord {
            relationship_id: peer.relationship_id,
            sender: self.self_key,
            receiver: peer.peer_key,
            record_seq: sequence,
            issued_at_unix_ms: now,
            expires_at_unix_ms: expires_at,
            boot_id: self.boot_id,
            generation: self.generation,
            candidates,
            flags,
        };
        // No publish queueing or signing happens before the durable reservation above.
        let payload = SignedPayload::sign(kind, id, &record, self.signing_key)
            .map_err(|error| error.to_string())?;
        let fallback = if flags & FLAG_PUNCH_OFFER != 0 {
            let normal = ContactRecord {
                record_seq: fallback_sequence.expect("offer alternative reserved before signing"),
                flags: flags & !FLAG_PUNCH_OFFER,
                expires_at_unix_ms: now.saturating_add(MAX_LIFETIME_MS),
                ..record
            };
            Some(
                SignedPayload::sign(kind, id, &normal, self.signing_key)
                    .map_err(|error| error.to_string())?,
            )
        } else {
            None
        };
        Ok(Publication {
            payload,
            fallback,
            // Correlation remains valid for whichever alternative the actor sends.
            expires_at_unix_ms: now.saturating_add(MAX_LIFETIME_MS),
        })
    }

    /// Verify one payload against this relationship and release its candidates.
    ///
    /// Returns the discovery updates tagged with this relationship together with
    /// the verified payload, so the caller can apply request/reply correlation
    /// without verifying twice. Nothing here can touch another relationship's
    /// state: the policy pins this relationship's id, this node's key and this
    /// peer's key, and the high-water cache and candidate set are this peer's.
    pub fn accept_payload(
        &self,
        peer: &mut PeerRuntime,
        payload: &SignedPayload,
    ) -> Result<(Vec<DiscoveryUpdate>, VerifiedPayload), String> {
        let policy = peer.record_policy(
            self.self_key,
            now_unix_ms(),
            self.stun_servers.clone(),
            self.own_endpoints(),
            self.forbidden_addresses.clone(),
        );
        // Clone the cached high-water state so the verification borrow ends
        // before the durable commit closure needs `peer_cache` mutably.
        let previous = peer.peer_cache.state().cloned();
        let verified = payload
            .verify(&policy, previous.as_ref())
            .map_err(|error| {
                format!("signed payload rejected; not used as a candidate: {error}")
            })?;
        let now = now_unix_ms();
        // Disjoint field borrows: `public` is mutated while the commit closure
        // mutably borrows `peer_cache`. Both belong to this one peer.
        let PeerRuntime {
            public, peer_cache, ..
        } = peer;
        let updates = public
            .accept_verified(&verified, now, self.monotonic_ms, |state| {
                peer_cache.commit(state)
            })
            .map_err(|error| match error {
                PublicAcceptError::Commit(error) => {
                    format!("signed payload not used: durable high-water commit failed: {error}")
                }
                other => format!("signed payload not used: {other:?}"),
            })?;
        // Advisory only: the punch coordinator refuses to act on an
        // unclassified peer, so a wrong flag cannot start a scan.
        peer.peer_record_flags = verified.validated.record.flags;
        peer.peer_record_expires_ms = verified.validated.record.expires_at_unix_ms;
        Ok((updates, verified))
    }

    /// Apply correlation after independent verification and queue at most one
    /// reply. Returns the action taken so the caller can update node state.
    pub fn apply_exchange(
        &self,
        peer: &mut PeerRuntime,
        verified: &VerifiedPayload,
        delivery: Delivery,
    ) -> ExchangeAction {
        peer.exchange.on_verified(verified, delivery)
    }

    /// Whether this relationship's engine currently reports bilateral health.
    pub fn peer_is_healthy(&self, peer: &PeerRuntime, now_unix_ms: u64) -> bool {
        peer.engine_snapshot(self.engines, now_unix_ms)
            .is_some_and(|snapshot| snapshot.currently_healthy)
    }
}

#[cfg(test)]
mod tests;
