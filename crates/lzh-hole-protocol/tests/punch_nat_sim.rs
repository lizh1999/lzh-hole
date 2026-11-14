//! In-process NAT simulation proving the punch closes the hard/easy case.
//!
//! This is deliberately not a socket test. The punch state machine is sans-I/O,
//! so the interesting behaviour -- contiguous external port allocation on the
//! hard side, port-restricted filtering on the easy side -- can be modelled
//! exactly and deterministically, with no network, no timing and no flakiness.
//!
//! The model reproduces what was measured on a real carrier NAT:
//!
//! * endpoint-dependent mapping allocates a fresh external port per
//!   (internal socket, destination) pair, and successive allocations towards one
//!   destination come out contiguous;
//! * endpoint-independent mapping reuses one external port per internal socket;
//! * address-and-port-dependent filtering only admits a source the internal
//!   host has already sent to, on that exact port.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4};

use lzh_hole_protocol::crypto::Key32;
use lzh_hole_protocol::punch::{
    PUNCH_GRID_STEP, PUNCH_HARD_SOCKETS, PunchConfig, PunchEvent, PunchRole, PunchState,
};
use lzh_hole_protocol::wire::Direction;
use lzh_hole_types::{BootId, DiscoveryPublicKey, Endpoint, RelationshipId};

const HARD_PUBLIC: Ipv4Addr = Ipv4Addr::new(39, 144, 107, 79);
const EASY_PUBLIC: Ipv4Addr = Ipv4Addr::new(116, 230, 58, 111);
const T0: u64 = 1_762_920_000_000;
const REL: [u8; 16] = [7u8; 16];
/// The matched protocol constant. Anything smaller lets the fixed grid step
/// walk straight over the block, which is what the wide-step test asserts.
const HARD_SOCKETS: u16 = PUNCH_HARD_SOCKETS as u16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mapping {
    /// One external port per internal socket, whatever the destination.
    EndpointIndependent,
    /// A fresh external port per (internal socket, destination), allocated
    /// contiguously. This is what the hard side really does.
    EndpointDependent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Filtering {
    /// Anything with a mapping may send in.
    EndpointIndependent,
    /// Only an address the host has already sent to.
    AddressDependent,
    /// Only an exact address and port the host has already sent to.
    AddressAndPortDependent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum MappingKey {
    Socket(u16),
    SocketAndDestination(u16, SocketAddrV4),
}

#[derive(Debug)]
struct Nat {
    public_ip: Ipv4Addr,
    mapping: Mapping,
    filtering: Filtering,
    forward: HashMap<MappingKey, u16>,
    reverse: HashMap<u16, u16>,
    next_external: u16,
    sent_addresses: HashSet<Ipv4Addr>,
    sent_exact: HashSet<SocketAddrV4>,
}

impl Nat {
    fn new(public_ip: Ipv4Addr, mapping: Mapping, filtering: Filtering, first_port: u16) -> Self {
        Self {
            public_ip,
            mapping,
            filtering,
            forward: HashMap::new(),
            reverse: HashMap::new(),
            next_external: first_port,
            sent_addresses: HashSet::new(),
            sent_exact: HashSet::new(),
        }
    }

    fn key(&self, internal: u16, destination: SocketAddrV4) -> MappingKey {
        match self.mapping {
            Mapping::EndpointIndependent => MappingKey::Socket(internal),
            Mapping::EndpointDependent => MappingKey::SocketAndDestination(internal, destination),
        }
    }

    /// Translate one outbound datagram, returning the source the peer sees.
    fn outbound(&mut self, internal: u16, destination: SocketAddrV4) -> SocketAddrV4 {
        let key = self.key(internal, destination);
        let external = *self.forward.entry(key).or_insert_with(|| {
            // Contiguous allocation, exactly as measured.
            let port = self.next_external;
            self.next_external = self.next_external.wrapping_add(1);
            self.reverse.insert(port, internal);
            port
        });
        self.sent_addresses.insert(*destination.ip());
        self.sent_exact.insert(destination);
        SocketAddrV4::new(self.public_ip, external)
    }

    /// Whether an inbound datagram from `source` passes the filter.
    fn admits(&self, source: SocketAddrV4) -> bool {
        match self.filtering {
            Filtering::EndpointIndependent => true,
            Filtering::AddressDependent => self.sent_addresses.contains(source.ip()),
            Filtering::AddressAndPortDependent => self.sent_exact.contains(&source),
        }
    }

    /// Resolve an inbound destination port to an internal socket, if the
    /// filter admits the source and a mapping exists.
    fn inbound(&self, destination_port: u16, source: SocketAddrV4) -> Option<u16> {
        if !self.admits(source) {
            return None;
        }
        self.reverse.get(&destination_port).copied()
    }

    /// External ports currently mapped, for assertions.
    fn mapped_ports(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = self.reverse.keys().copied().collect();
        ports.sort_unstable();
        ports
    }
}

struct World {
    hard_nat: Nat,
    easy_nat: Nat,
    hard: PunchState,
    easy: PunchState,
    nonce: u8,
}

impl World {
    fn new(hard_sockets: u16, easy_filtering: Filtering, hard_mapping: Mapping) -> Self {
        let key = Key32::from_bytes([0x5a; 32]);
        let easy_endpoint = Endpoint::new(EASY_PUBLIC, 51_000);
        let hard_endpoint = Endpoint::new(HARD_PUBLIC, 51_000);
        // The easy side advertises whatever port its own NAT gave it; the hard
        // side only needs the address.
        let hard = PunchState::new(
            PunchConfig {
                role: PunchRole::Hard,
                peer_endpoint: easy_endpoint,
                local_key: DiscoveryPublicKey::from_bytes([0x20; 32]),
                peer_key: DiscoveryPublicKey::from_bytes([0x00; 32]),
                relationship_id: RelationshipId::from_bytes(REL),
                boot_id: BootId::from_bytes([0x90; 16]),
                generation: 2,
                direction: Direction::HiToLo,
                hard_sockets,
            },
            key.clone(),
            T0,
        );
        let easy = PunchState::new(
            PunchConfig {
                role: PunchRole::Easy,
                peer_endpoint: hard_endpoint,
                local_key: DiscoveryPublicKey::from_bytes([0x00; 32]),
                peer_key: DiscoveryPublicKey::from_bytes([0x20; 32]),
                relationship_id: RelationshipId::from_bytes(REL),
                boot_id: BootId::from_bytes([0x80; 16]),
                generation: 7,
                direction: Direction::LoToHi,
                hard_sockets: 0,
            },
            key,
            T0,
        );
        Self {
            // The hard side sits behind a carrier NAT that rebinds per
            // destination; the easy side sits behind a home router.
            hard_nat: Nat::new(
                HARD_PUBLIC,
                hard_mapping,
                Filtering::AddressAndPortDependent,
                26_170,
            ),
            easy_nat: Nat::new(
                EASY_PUBLIC,
                Mapping::EndpointIndependent,
                easy_filtering,
                51_000,
            ),
            hard,
            easy,
            nonce: 0,
        }
    }

    /// Push hard-side frames through the easy side's NAT.
    fn pump_hard(&mut self, now_ms: u64) -> Vec<PunchEvent> {
        let mut events = Vec::new();
        let mut nonce = [0u8; 32];
        {
            let counter = &mut self.nonce;
            let mut source = || {
                *counter = counter.wrapping_add(1);
                nonce = [*counter; 32];
                nonce
            };
            let _ = self.hard.tick(now_ms, &mut source);
        }
        let mut frames = Vec::new();
        while let Some(frame) = self.hard.next_frame() {
            frames.push(frame);
        }
        for frame in frames {
            let destination = SocketAddrV4::new(frame.target.ip, frame.target.port);
            let source = self.hard_nat.outbound(frame.slot, destination);
            // The easy side's NAT decides whether this gets in.
            let Some(internal) = self.easy_nat.inbound(destination.port(), source) else {
                continue;
            };
            let _ = internal;
            events.extend(
                self.easy
                    .handle_inbound(0, endpoint_of(source), &frame.bytes, now_ms),
            );
        }
        events
    }

    /// Push easy-side frames through the hard side's NAT.
    fn pump_easy(&mut self, now_ms: u64) -> Vec<PunchEvent> {
        let mut events = Vec::new();
        {
            let counter = &mut self.nonce;
            let mut source = || {
                *counter = counter.wrapping_add(1);
                [*counter; 32]
            };
            let _ = self.easy.tick(now_ms, &mut source);
        }
        let mut frames = Vec::new();
        while let Some(frame) = self.easy.next_frame() {
            frames.push(frame);
        }
        for frame in frames {
            let destination = SocketAddrV4::new(frame.target.ip, frame.target.port);
            let source = self.easy_nat.outbound(0, destination);
            // The hard side's NAT only has a mapping for ports one of its punch
            // sockets actually created.
            let Some(internal) = self.hard_nat.inbound(destination.port(), source) else {
                continue;
            };
            events.extend(self.hard.handle_inbound(
                internal,
                endpoint_of(source),
                &frame.bytes,
                now_ms,
            ));
        }
        events
    }
}

fn endpoint_of(addr: SocketAddrV4) -> Endpoint {
    Endpoint::new(*addr.ip(), addr.port())
}

fn run(world: &mut World, rounds: usize) -> (Vec<PunchEvent>, Vec<PunchEvent>) {
    let mut hard_events = Vec::new();
    let mut easy_events = Vec::new();
    for round in 0..rounds {
        let now = T0 + round as u64 * 100;
        easy_events.extend(world.pump_hard(now));
        hard_events.extend(world.pump_easy(now));
        if world.hard.hit_port().is_some() && world.easy.hit_port().is_some() {
            break;
        }
    }
    (hard_events, easy_events)
}

#[test]
fn a_hard_side_and_a_port_restricted_easy_side_complete_a_punch() {
    // The core case: symmetric NAT against a port-restricted cone. Neither side
    // can reach the other without the grid.
    let mut world = World::new(
        HARD_SOCKETS,
        Filtering::AddressAndPortDependent,
        Mapping::EndpointDependent,
    );
    let (hard_events, easy_events) = run(&mut world, 400);

    let promote = hard_events.iter().find_map(|event| match event {
        PunchEvent::Promote { slot, peer } => Some((*slot, *peer)),
        _ => None,
    });
    let learned = easy_events.iter().find_map(|event| match event {
        PunchEvent::Learned { peer } => Some(*peer),
        _ => None,
    });

    let (slot, peer) = promote.expect("the hard side must promote its winning socket");
    let learned = learned.expect("the easy side must learn the hard side's real port");

    // Each side records the source it actually saw, so the two are different
    // endpoints by construction: the hard side saw the easy side, and the easy
    // side saw the hard side.
    assert_eq!(peer.ip, EASY_PUBLIC, "the hard side saw the easy side");
    assert_eq!(learned.ip, HARD_PUBLIC, "the easy side saw the hard side");
    assert_eq!(world.hard.hit_port(), Some(peer.port));
    assert_eq!(world.easy.hit_port(), Some(learned.port));

    // The port the easy side learned is a real hard-side mapping, inside the
    // contiguous block the hard side opened.
    let ports = world.hard_nat.mapped_ports();
    assert!(
        ports.contains(&learned.port),
        "learned port must be a real hard-side mapping"
    );
    let block: Vec<u16> = ports
        .iter()
        .copied()
        .filter(|p| p.abs_diff(learned.port) <= PUNCH_GRID_STEP)
        .collect();
    assert!(
        block.len() >= usize::from(HARD_SOCKETS) / 2,
        "the hard side should have opened a contiguous block, saw {} ports",
        block.len()
    );
    // The winning slot is one the hard side actually opened.
    assert!(slot < HARD_SOCKETS, "slot {slot} outside the opened range");
}

#[test]
fn the_promoted_socket_can_answer_the_easy_side_directly() {
    let mut world = World::new(
        HARD_SOCKETS,
        Filtering::AddressAndPortDependent,
        Mapping::EndpointDependent,
    );
    // Pump by hand and stop the instant the hit lands, so nothing has drained
    // the confirmation frames yet.
    let mut promoted = None;
    for round in 0..400u64 {
        let now = T0 + round * 100;
        world.pump_hard(now);
        let events = world.pump_easy(now);
        if let Some(found) = events.iter().find_map(|event| match event {
            PunchEvent::Promote { slot, peer } => Some((*slot, *peer)),
            _ => None,
        }) {
            promoted = Some(found);
            break;
        }
    }
    let (slot, peer) = promoted.expect("the hard side must promote");

    // A hit records what is owed but builds nothing; frames are only ever
    // generated in `tick`, which is where the caller's randomness lives.
    assert!(world.hard.next_frame().is_none(), "nothing before a tick");
    {
        let mut n = 0u8;
        let mut source = || {
            n = n.wrapping_add(1);
            [n; 32]
        };
        world.hard.tick(T0 + 1_000, &mut source);
    }
    // The hard side queued confirmations aimed at the exact source it saw,
    // from the slot that won.
    let confirms: Vec<_> = std::iter::from_fn(|| world.hard.next_frame()).collect();
    assert!(!confirms.is_empty(), "a hit must queue confirmations");
    for confirm in &confirms {
        assert_eq!(
            confirm.slot, slot,
            "confirmations come from the winning slot"
        );
        assert_eq!(confirm.target, peer, "and target the observed source");
    }

    // And the easy side's NAT admits them, because scanning already opened
    // state for that exact endpoint.
    let source = world
        .hard_nat
        .outbound(slot, SocketAddrV4::new(peer.ip, peer.port));
    assert!(
        world.easy_nat.inbound(51_000, source).is_some(),
        "the reverse direction must be open after a hit"
    );
}

#[test]
fn an_easy_side_behind_a_relaxed_filter_still_completes() {
    for filtering in [Filtering::EndpointIndependent, Filtering::AddressDependent] {
        let mut world = World::new(HARD_SOCKETS, filtering, Mapping::EndpointDependent);
        let (hard_events, easy_events) = run(&mut world, 400);
        assert!(
            hard_events
                .iter()
                .any(|event| matches!(event, PunchEvent::Promote { .. })),
            "address-dependent filtering must still punch"
        );
        assert!(
            easy_events
                .iter()
                .any(|event| matches!(event, PunchEvent::Learned { .. })),
            "the easy side must still learn"
        );
    }
}

#[test]
fn two_hard_sides_never_complete_and_both_fail_honestly() {
    // Both sides rebind per destination, so a reply can never come from a port
    // the other side opened state for. This must fail, not half-succeed.
    let key = Key32::from_bytes([0x5a; 32]);
    let mut a = PunchState::new(
        PunchConfig {
            role: PunchRole::Hard,
            peer_endpoint: Endpoint::new(EASY_PUBLIC, 51_000),
            local_key: DiscoveryPublicKey::from_bytes([0x00; 32]),
            peer_key: DiscoveryPublicKey::from_bytes([0x20; 32]),
            relationship_id: RelationshipId::from_bytes(REL),
            boot_id: BootId::from_bytes([0x80; 16]),
            generation: 1,
            direction: Direction::LoToHi,
            hard_sockets: 32,
        },
        key.clone(),
        T0,
    );
    let mut b = PunchState::new(
        PunchConfig {
            role: PunchRole::Hard,
            peer_endpoint: Endpoint::new(HARD_PUBLIC, 51_000),
            local_key: DiscoveryPublicKey::from_bytes([0x20; 32]),
            peer_key: DiscoveryPublicKey::from_bytes([0x00; 32]),
            relationship_id: RelationshipId::from_bytes(REL),
            boot_id: BootId::from_bytes([0x90; 16]),
            generation: 1,
            direction: Direction::HiToLo,
            hard_sockets: 32,
        },
        key,
        T0,
    );
    let mut nat_a = Nat::new(
        Ipv4Addr::new(1, 1, 1, 1),
        Mapping::EndpointDependent,
        Filtering::AddressAndPortDependent,
        30_000,
    );
    let mut nat_b = Nat::new(
        Ipv4Addr::new(2, 2, 2, 2),
        Mapping::EndpointDependent,
        Filtering::AddressAndPortDependent,
        40_000,
    );

    let mut events_a = Vec::new();
    let mut events_b = Vec::new();
    for round in 0..200u64 {
        let now = T0 + round * 100;
        {
            let mut n = 0u8;
            let mut source = || {
                n = n.wrapping_add(1);
                [n; 32]
            };
            let _ = a.tick(now, &mut source);
            let _ = b.tick(now, &mut source);
        }
        let mut frames_a = Vec::new();
        while let Some(frame) = a.next_frame() {
            frames_a.push(frame);
        }
        let mut frames_b = Vec::new();
        while let Some(frame) = b.next_frame() {
            frames_b.push(frame);
        }
        for frame in frames_a {
            let destination = SocketAddrV4::new(frame.target.ip, frame.target.port);
            let source = nat_a.outbound(frame.slot, destination);
            if let Some(internal) = nat_b.inbound(destination.port(), source) {
                events_b.extend(b.handle_inbound(internal, endpoint_of(source), &frame.bytes, now));
            }
        }
        for frame in frames_b {
            let destination = SocketAddrV4::new(frame.target.ip, frame.target.port);
            let source = nat_b.outbound(frame.slot, destination);
            if let Some(internal) = nat_a.inbound(destination.port(), source) {
                events_a.extend(a.handle_inbound(internal, endpoint_of(source), &frame.bytes, now));
            }
        }
        if a.hit_port().is_some() || b.hit_port().is_some() {
            break;
        }
    }

    // Nothing may be promoted or learned: a reply always arrives from a port
    // the other side never opened state for.
    assert!(a.hit_port().is_none(), "hard/hard must not promote");
    assert!(b.hit_port().is_none(), "hard/hard must not promote");
    assert!(
        !events_a
            .iter()
            .any(|event| matches!(event, PunchEvent::Promote { .. })),
        "hard/hard must not produce a promotion event"
    );
    assert!(
        !events_b
            .iter()
            .any(|event| matches!(event, PunchEvent::Promote { .. })),
        "hard/hard must not produce a promotion event"
    );
}

#[test]
fn a_wide_grid_misses_a_narrow_block_behind_port_restricted_filtering() {
    // With relaxed filtering a hard-side keepalive can be learned directly;
    // only a port-restricted filter makes the grid intersection necessary.
    let mut world = World::new(
        8,
        Filtering::AddressAndPortDependent,
        Mapping::EndpointDependent,
    );
    // Force a step far wider than the 8-socket block.
    world
        .easy
        .set_port_sequence(Box::new(lzh_hole_protocol::punch::GridSequence::new(
            1024, 4096, 16,
        )));
    let (hard_events, _) = run(&mut world, 200);
    let promoted = hard_events
        .iter()
        .any(|event| matches!(event, PunchEvent::Promote { .. }));
    assert!(
        !promoted,
        "a grid step wider than the hard-side block must not punch"
    );
    // The default step, by contrast, is guaranteed to hit such a block; the
    // matched-pair invariant itself is pinned in the state machine's own tests.
    const { assert!(PUNCH_GRID_STEP <= 128) };
}
