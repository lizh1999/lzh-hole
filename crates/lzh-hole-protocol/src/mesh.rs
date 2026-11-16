//! Bounded multi-peer composition over independent per-relationship engines.
//!
//! Every peer owns its own PeerEngine: its own handshake, session keys,
//! sequence space, replay window, health state, candidate set and punch state.
//! Nothing here pools, shares or reuses per-peer cryptographic state, so adding
//! a peer cannot weaken the peers already present.
//!
//! The wire format is unchanged. The relationship id is already carried in the
//! plaintext frame header and is covered by the frame MAC, so one set of
//! physical sockets can serve every peer: an inbound datagram is routed by its
//! header before any key is selected, and the engine that owns the relationship
//! stays the only authority that authenticates and admits it.
//!
//! The routing field is not authenticated. Anyone who can observe a
//! relationship id, which appears in clear in every frame header, can aim junk
//! at that relationship's engine. Every frame type is verified before it
//! allocates state or draws a reply, so the ceiling is targeted pollution of
//! one engine's rejection counters, never replay, session or amplification.
//! What routing does guarantee is that such traffic reaches exactly one engine
//! and never perturbs another peer's protocol state.
//!
//! Routing is by destination address on the way out and by relationship on the
//! way in. Both directions fail closed: an unknown destination or an unknown
//! relationship is refused here and never reaches an engine.

use std::net::Ipv4Addr;

use sha2::{Digest, Sha256};

use crate::engine::{
    EngineBuildError, EngineConfig, EngineSnapshot, MAX_ENGINE_CANDIDATES, MAX_FORBIDDEN_ADDRESSES,
    PeerEngine, SendError, UdpFrame,
};
use crate::path::TransportPolicy;
use crate::punch::{PunchEvent, PunchFrame};
use crate::wire::Header;
use lzh_hole_types::{DiscoveryPublicKey, Endpoint, RelationshipId, Secret32, TransportId};

/// Maximum simultaneous pinned peers held by one node.
///
/// Every bound downstream is already per peer, so this only caps how many of
/// them exist at once. It also caps shared transport contention, candidate
/// fan-out and drain work per event-loop pass.
pub const MAX_PEERS: usize = 8;

/// Domain separation for the stored pre-shared key fingerprint.
const LABEL_PSK_FINGERPRINT: &[u8] = b"lzh-hole/v1/psk-fingerprint";

/// A one-way fingerprint of a relationship's pre-shared key.
///
/// Only the fingerprint is retained, never the key, and it is redacted from
/// debug output so it cannot be used to correlate relationships across logs.
#[derive(Clone, Copy, PartialEq, Eq)]
struct PskFingerprint([u8; 32]);

impl PskFingerprint {
    fn of(psk: &Secret32) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(LABEL_PSK_FINGERPRINT);
        hasher.update(psk.expose_bytes());
        Self(hasher.finalize().into())
    }
}

impl std::fmt::Debug for PskFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PskFingerprint(<redacted>)")
    }
}

/// Why a peer could not be added to a set.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PeerSetError {
    /// The set already holds MAX_PEERS peers.
    #[error("a node may hold at most {MAX_PEERS} peers")]
    TooManyPeers,
    /// The same relationship is already present.
    #[error("relationship {0:?} is already present")]
    DuplicateRelationship(RelationshipId),
    /// Two peers would claim the same overlay address.
    #[error("overlay address {0} is already claimed by another peer")]
    DuplicatePeerAddress(Ipv4Addr),
    /// A peer would claim this node's own overlay address.
    #[error("peer address {0} collides with this node's own overlay address")]
    SelfAddressCollision(Ipv4Addr),
    /// Two peers would pin the same peer public key.
    #[error("peer public key {0:?} is already pinned by another relationship")]
    DuplicatePeerKey(DiscoveryPublicKey),
    /// Two relationships would share one pre-shared key.
    ///
    /// A relationship id travels in clear in every frame header, so a peer
    /// that knows a shared key can derive every other relationship's keys and
    /// impersonate those peers. Refusing this keeps one relationship's
    /// compromise from becoming the whole mesh's.
    #[error("two relationships must not share a pre-shared key")]
    DuplicatePsk,
    /// A relationship disagrees with this node's overlay address.
    #[error("relationship declares local address {actual}, but this node holds {expected}")]
    InconsistentSelfAddress {
        /// The address every relationship of this node must share.
        expected: Ipv4Addr,
        /// The address the rejected relationship declared.
        actual: Ipv4Addr,
    },
    /// A relationship disagrees with this node's pinned discovery identity.
    #[error("relationship pins a different local discovery identity")]
    InconsistentIdentity,
    /// Admitting this peer would exceed the bounded forbidden-address list.
    #[error("admitting this peer would exceed the bounded forbidden address list")]
    ForbiddenAddressesFull,
    /// The underlying engine refused the configuration.
    #[error(transparent)]
    Engine(#[from] EngineBuildError),
}

/// What happened to one inbound datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inbound {
    /// The owning relationship's engine received the datagram. Whether it was
    /// admitted is that engine's decision, not this layer's.
    Delivered(RelationshipId),
    /// The header named a relationship this node does not hold.
    UnknownRelationship(RelationshipId),
    /// The datagram is not a structurally valid frame of this wire version.
    Malformed,
}

/// Why one local TUN packet could not be queued for a peer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MeshSendError {
    /// No pinned peer owns this destination address.
    #[error("no peer owns destination {0}")]
    NoPeerForDestination(Ipv4Addr),
    /// The buffer is not a readable IPv4 header, so no destination exists.
    #[error("packet is too short or not IPv4 to select a peer")]
    Malformed,
    /// The owning engine refused the packet.
    #[error(transparent)]
    Peer(#[from] SendError),
}

/// Node-level counters for traffic this layer refused itself.
///
/// Per-peer admission counters live in each engine's own snapshot. These cover
/// only what never reached an engine, which no engine could have counted.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MeshCounters {
    /// Datagrams that were not a structurally valid frame of this wire version.
    pub malformed: u64,
    /// Frames naming a relationship this node does not hold.
    pub unknown_relationship: u64,
    /// Local TUN packets whose destination no peer owns.
    pub unroutable: u64,
    /// Local TUN packets too short or not IPv4 to select a peer.
    pub unparsable: u64,
}

/// One pinned peer and the engine that serves it.
#[derive(Debug)]
struct PeerSlot {
    relationship_id: RelationshipId,
    peer_key: DiscoveryPublicKey,
    peer_address: Ipv4Addr,
    psk: PskFingerprint,
    engine: PeerEngine,
}

/// A bounded set of independently authenticated peers sharing one node identity.
///
/// Insertion order is preserved and lookups are linear; the set is bounded by
/// MAX_PEERS, so this is cheaper than an index at every realistic size.
#[derive(Debug)]
pub struct PeerSet {
    self_address: Ipv4Addr,
    self_key: DiscoveryPublicKey,
    peers: Vec<PeerSlot>,
    transports: Vec<TransportPolicy>,
    counters: MeshCounters,
    udp_cursor: usize,
    ipv4_cursor: usize,
    punch_cursor: usize,
}

impl PeerSet {
    /// An empty set for one node identity and its single overlay address.
    ///
    /// Every relationship added later must agree with both: a node has exactly
    /// one overlay address and one discovery identity, whatever it peers with.
    ///
    /// The set starts fail closed. No physical socket is trusted yet, so every
    /// engine is created in strict transport mode and refuses all paths until
    /// set_transports supplies real socket facts.
    pub fn new(self_address: Ipv4Addr, self_key: DiscoveryPublicKey) -> Self {
        Self {
            self_address,
            self_key,
            peers: Vec::new(),
            transports: Vec::new(),
            counters: MeshCounters::default(),
            udp_cursor: 0,
            ipv4_cursor: 0,
            punch_cursor: 0,
        }
    }

    /// This node's overlay address.
    pub fn self_address(&self) -> Ipv4Addr {
        self.self_address
    }

    /// This node's pinned discovery public key.
    pub fn self_key(&self) -> DiscoveryPublicKey {
        self.self_key
    }

    /// Number of pinned peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether the node currently holds no peer.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Traffic this layer refused itself, without reaching any engine.
    pub fn counters(&self) -> MeshCounters {
        self.counters
    }

    /// Every pinned relationship, in insertion order.
    pub fn relationship_ids(&self) -> impl Iterator<Item = RelationshipId> + '_ {
        self.peers.iter().map(|slot| slot.relationship_id)
    }

    /// Every peer overlay address, in insertion order. This is exactly the set
    /// of destinations the caller may install host routes for.
    pub fn peer_addresses(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.peers.iter().map(|slot| slot.peer_address)
    }

    /// Whether a relationship is pinned.
    pub fn contains(&self, relationship_id: RelationshipId) -> bool {
        self.slot(relationship_id).is_some()
    }

    /// Add one peer and build its engine.
    ///
    /// The candidate policy is amended before construction: no overlay address
    /// of this node, of the new peer, or of any peer already present may ever
    /// become a physical candidate target for the new engine. Peers already
    /// present learn the new overlay address for the same reason, and their
    /// existing candidates, probes, queued frames and sessions targeting it are
    /// dropped rather than left usable.
    ///
    /// Everything that can fail is checked before any engine is mutated, so a
    /// rejected peer leaves the set exactly as it was. The only exception cannot
    /// be reached after those checks, and even then a partial application only
    /// ever over-restricts a surviving engine, never relaxes one.
    pub fn insert(
        &mut self,
        mut config: EngineConfig,
        psk: &Secret32,
    ) -> Result<RelationshipId, PeerSetError> {
        if self.peers.len() >= MAX_PEERS {
            return Err(PeerSetError::TooManyPeers);
        }
        if config.self_vip != self.self_address {
            return Err(PeerSetError::InconsistentSelfAddress {
                expected: self.self_address,
                actual: config.self_vip,
            });
        }
        if config.handshake.me != self.self_key {
            return Err(PeerSetError::InconsistentIdentity);
        }
        let relationship_id = config.handshake.relationship_id;
        if self.slot(relationship_id).is_some() {
            return Err(PeerSetError::DuplicateRelationship(relationship_id));
        }
        let peer_address = config.peer_vip;
        if peer_address == self.self_address {
            return Err(PeerSetError::SelfAddressCollision(peer_address));
        }
        if self.peers.iter().any(|s| s.peer_address == peer_address) {
            return Err(PeerSetError::DuplicatePeerAddress(peer_address));
        }
        let peer_key = config.handshake.peer;
        if self.peers.iter().any(|s| s.peer_key == peer_key) {
            return Err(PeerSetError::DuplicatePeerKey(peer_key));
        }
        let fingerprint = PskFingerprint::of(psk);
        if self.peers.iter().any(|s| s.psk == fingerprint) {
            return Err(PeerSetError::DuplicatePsk);
        }

        let forbidden = &mut config.candidate_policy.forbidden_addresses;
        for address in self
            .peers
            .iter()
            .map(|slot| slot.peer_address)
            .chain([self.self_address, peer_address])
        {
            if !forbidden.contains(&address) {
                forbidden.push(address);
            }
        }
        if forbidden.len() > MAX_FORBIDDEN_ADDRESSES
            || !self
                .peers
                .iter()
                .all(|slot| slot.engine.can_forbid(&[peer_address]))
        {
            return Err(PeerSetError::ForbiddenAddressesFull);
        }

        let mut engine = PeerEngine::new(config, psk)?;
        // A newly built engine must never sit in the legacy transport mode the
        // single-peer tests rely on: it would accept TransportId(0), skip the
        // own-socket exclusion and be unusable with real socket identities.
        engine.set_transports(&self.transports);
        for slot in &mut self.peers {
            if slot.engine.forbid_addresses(&[peer_address]).is_err() {
                return Err(PeerSetError::ForbiddenAddressesFull);
            }
        }
        self.peers.push(PeerSlot {
            relationship_id,
            peer_key,
            peer_address,
            psk: fingerprint,
            engine,
        });
        self.rescale_cursors();
        Ok(relationship_id)
    }

    /// Remove one peer and hand back its engine so the caller can drain or drop
    /// it deliberately. Remaining peers keep the removed overlay address in
    /// their forbidden set, which is the conservative direction: a surviving
    /// engine must never target that address, whether or not it is still a peer.
    pub fn remove(&mut self, relationship_id: RelationshipId) -> Option<PeerEngine> {
        let index = self
            .peers
            .iter()
            .position(|slot| slot.relationship_id == relationship_id)?;
        let slot = self.peers.remove(index);
        self.rescale_cursors();
        Some(slot.engine)
    }

    /// The engine for one relationship.
    pub fn get(&self, relationship_id: RelationshipId) -> Option<&PeerEngine> {
        self.slot(relationship_id).map(|slot| &slot.engine)
    }

    /// The engine for one relationship.
    pub fn get_mut(&mut self, relationship_id: RelationshipId) -> Option<&mut PeerEngine> {
        self.peers
            .iter_mut()
            .find(|slot| slot.relationship_id == relationship_id)
            .map(|slot| &mut slot.engine)
    }

    /// The engine that owns one peer overlay address.
    pub fn get_by_address(&self, address: Ipv4Addr) -> Option<&PeerEngine> {
        self.peers
            .iter()
            .find(|slot| slot.peer_address == address)
            .map(|slot| &slot.engine)
    }

    /// The engine that owns one peer overlay address.
    pub fn get_by_address_mut(&mut self, address: Ipv4Addr) -> Option<&mut PeerEngine> {
        self.peers
            .iter_mut()
            .find(|slot| slot.peer_address == address)
            .map(|slot| &mut slot.engine)
    }

    /// Every peer and its engine, in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (RelationshipId, &PeerEngine)> {
        self.peers
            .iter()
            .map(|slot| (slot.relationship_id, &slot.engine))
    }

    /// Every peer and its engine, in insertion order.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (RelationshipId, &mut PeerEngine)> {
        self.peers
            .iter_mut()
            .map(|slot| (slot.relationship_id, &mut slot.engine))
    }

    /// Route one received datagram to the engine that owns its relationship.
    ///
    /// Only the fixed header is read here, and that is a strictly weaker check
    /// than the one the engine performs, so this can never reject a frame the
    /// engine would have admitted. A datagram for an unknown relationship is
    /// refused without touching any engine, which is what keeps one peer's
    /// traffic from perturbing another peer's replay or session state.
    pub fn dispatch(
        &mut self,
        transport: TransportId,
        remote: Endpoint,
        datagram: &[u8],
        now_ms: u64,
    ) -> Inbound {
        let Ok(header) = Header::parse(datagram) else {
            self.counters.malformed = self.counters.malformed.saturating_add(1);
            return Inbound::Malformed;
        };
        let relationship_id = header.relationship_id;
        let Some(slot) = self
            .peers
            .iter_mut()
            .find(|slot| slot.relationship_id == relationship_id)
        else {
            self.counters.unknown_relationship =
                self.counters.unknown_relationship.saturating_add(1);
            return Inbound::UnknownRelationship(relationship_id);
        };
        slot.engine
            .handle_datagram_on(transport, remote, datagram, now_ms);
        Inbound::Delivered(relationship_id)
    }

    /// Queue one local TUN packet for the peer that owns its destination.
    ///
    /// The destination is read only to select an engine; the selected engine
    /// still performs the full structural, checksum and both-addresses check,
    /// so a wrong or forged destination cannot bypass it.
    pub fn send_ipv4(
        &mut self,
        packet: &[u8],
        now_ms: u64,
    ) -> Result<RelationshipId, MeshSendError> {
        let Some(destination) = ipv4_destination(packet) else {
            self.counters.unparsable = self.counters.unparsable.saturating_add(1);
            return Err(MeshSendError::Malformed);
        };
        let Some(slot) = self
            .peers
            .iter_mut()
            .find(|slot| slot.peer_address == destination)
        else {
            self.counters.unroutable = self.counters.unroutable.saturating_add(1);
            return Err(MeshSendError::NoPeerForDestination(destination));
        };
        slot.engine.send_ipv4(packet, now_ms)?;
        Ok(slot.relationship_id)
    }

    /// Take one queued datagram, rotating between peers so a backlogged peer
    /// cannot starve the others.
    pub fn next_udp_frame(&mut self) -> Option<(RelationshipId, UdpFrame)> {
        let count = self.peers.len();
        for offset in 0..count {
            let index = (self.udp_cursor + offset) % count;
            if let Some(frame) = self.peers[index].engine.next_udp_frame() {
                self.udp_cursor = (index + 1) % count;
                return Some((self.peers[index].relationship_id, frame));
            }
        }
        None
    }

    /// Take one authenticated inbound packet for the TUN writer, rotating
    /// between peers. The relationship is returned so the caller can attribute
    /// the packet and its counters to the peer it actually came from.
    pub fn next_ipv4_packet(&mut self) -> Option<(RelationshipId, Vec<u8>)> {
        let count = self.peers.len();
        for offset in 0..count {
            let index = (self.ipv4_cursor + offset) % count;
            if let Some(packet) = self.peers[index].engine.next_ipv4_packet() {
                self.ipv4_cursor = (index + 1) % count;
                return Some((self.peers[index].relationship_id, packet));
            }
        }
        None
    }

    /// Take one queued punch frame, rotating between peers.
    pub fn next_punch_frame(&mut self) -> Option<(RelationshipId, PunchFrame)> {
        let count = self.peers.len();
        for offset in 0..count {
            let index = (self.punch_cursor + offset) % count;
            if let Some(frame) = self.peers[index].engine.next_punch_frame() {
                self.punch_cursor = (index + 1) % count;
                return Some((self.peers[index].relationship_id, frame));
            }
        }
        None
    }

    /// Drain every peer's punch events. The total is bounded by each engine's
    /// own queue times MAX_PEERS.
    pub fn take_punch_events(&mut self) -> Vec<(RelationshipId, PunchEvent)> {
        let mut events = Vec::new();
        for slot in &mut self.peers {
            for event in slot.engine.take_punch_events() {
                events.push((slot.relationship_id, event));
            }
        }
        events
    }

    /// Apply the same trusted socket facts to every peer, and remember them so
    /// a peer added later starts from the same facts instead of the legacy
    /// transport mode. Physical sockets are a node-level resource, not a
    /// per-peer one.
    ///
    /// This drops any path the new facts forbid on every peer at once, so a
    /// network change can rebuild all sessions together. That is a deliberate
    /// availability trade: the alternative is per-engine policy divergence.
    pub fn set_transports(&mut self, policies: &[TransportPolicy]) {
        self.transports = policies
            .iter()
            .take(MAX_ENGINE_CANDIDATES)
            .cloned()
            .collect();
        for slot in &mut self.peers {
            slot.engine.set_transports(policies);
        }
    }

    /// Advance every peer's timers.
    pub fn tick(&mut self, now_ms: u64) {
        for slot in &mut self.peers {
            slot.engine.tick(now_ms);
        }
    }

    /// Close every peer permanently.
    pub fn close(&mut self) {
        for slot in &mut self.peers {
            slot.engine.close();
        }
    }

    /// One snapshot per peer, in insertion order.
    pub fn snapshots(&self, now_ms: u64) -> Vec<(RelationshipId, EngineSnapshot)> {
        self.peers
            .iter()
            .map(|slot| (slot.relationship_id, slot.engine.snapshot(now_ms)))
            .collect()
    }

    fn slot(&self, relationship_id: RelationshipId) -> Option<&PeerSlot> {
        self.peers
            .iter()
            .find(|slot| slot.relationship_id == relationship_id)
    }

    fn rescale_cursors(&mut self) {
        let count = self.peers.len();
        if count == 0 {
            self.udp_cursor = 0;
            self.ipv4_cursor = 0;
            self.punch_cursor = 0;
            return;
        }
        self.udp_cursor %= count;
        self.ipv4_cursor %= count;
        self.punch_cursor %= count;
    }
}

/// Read only the destination address of a complete IPv4 packet or fragment.
///
/// This is a routing hint, never an admission check: source and destination
/// sit at fixed offsets that do not depend on IHL, so this verifies just enough
/// to index into the header, and the engine that ends up owning the packet
/// revalidates version, header length, total length, checksum and both
/// addresses before queueing anything.
fn ipv4_destination(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ))
}

#[cfg(test)]
#[path = "mesh/tests.rs"]
mod unit_tests;
