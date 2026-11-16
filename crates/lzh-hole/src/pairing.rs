//! CLI pairing subcommands. Cryptographic and durable operations are delegated
//! to `lzh-hole-store`; this module only validates arguments and prints public
//! results.
//!
//! A node holds one relationship per peer. Several pairings may be in flight at
//! once: every pending offer is stored under its own pairing id, so starting a
//! second `pair offer` never overwrites the PSK a first peer may already hold.

use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use lzh_hole_protocol::MAX_PEERS;
use lzh_hole_store::{
    Acceptance, Offer, PAIRING_VERSION, PairingError, Relationship, Role, Secret32, StateDir,
    build_acceptance, build_offer, public_key_of_seed, read_pair_file, verify_acceptance,
    write_pair_file,
};
use lzh_hole_types::{DiscoveryPublicKey, RelationshipId};

use crate::args::{
    InitArgs, PairAcceptArgs, PairAction, PairFinalizeArgs, PairOfferArgs, PairRoleArg,
};

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

pub(crate) fn init(args: &InitArgs) -> Result<ExitCode, PairingError> {
    let state = StateDir::open(&args.state)?;
    let (public, created) = state.init_identity(args.force)?;
    if !created {
        println!("identity already exists in {}", args.state.display());
        println!("public_key   {public}");
        println!("short_id     {}", public.short_id());
        println!("re-run with --force to replace it");
        return Ok(ExitCode::from(2));
    }
    println!("created identity in {}", args.state.display());
    println!("public_key   {public}");
    println!("short_id     {}", public.short_id());
    println!("state_dir    mode 0700");
    println!("identity_key mode 0600");
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn run(action: PairAction) -> Result<ExitCode, PairingError> {
    match action {
        PairAction::Offer(args) => offer(&args),
        PairAction::Accept(args) => accept(&args),
        PairAction::Finalize(args) => finalize(&args),
    }
}

fn parse_key(text: &str, what: &str) -> Result<DiscoveryPublicKey, PairingError> {
    text.parse()
        .map_err(|error| PairingError::Format(format!("{what}: {error}")))
}

/// Parse an overlay address and return it with its canonical text form.
///
/// The canonical form is what gets signed into the offer and stored in the
/// relationship, so two spellings of one address can never end up disagreeing
/// between the two sides of a pairing.
fn parse_vip(text: &str, what: &str) -> Result<(Ipv4Addr, String), PairingError> {
    let ip = text
        .parse::<Ipv4Addr>()
        .map_err(|error| PairingError::Format(format!("{what}: not an IPv4 address: {error}")))?;
    Ok((ip, ip.to_string()))
}

fn stored_vip(relationship: &Relationship, field: &str) -> Result<Ipv4Addr, PairingError> {
    let text = match field {
        "self_vip" => &relationship.self_vip,
        _ => &relationship.peer_vip,
    };
    text.parse::<Ipv4Addr>().map_err(|error| {
        PairingError::Format(format!(
            "relationship {} {field}: {error}",
            relationship.relationship_id
        ))
    })
}

/// Refuse a pairing the mesh shape forbids, before any secret is created.
///
/// This repeats the checks `StateDir::finalise` performs so the operator learns
/// immediately instead of after a round trip. `finalise` remains the authority
/// and re-checks all of it.
fn check_mesh_shape(
    existing: &[Relationship],
    self_key: DiscoveryPublicKey,
    self_vip: Ipv4Addr,
    peer_key: DiscoveryPublicKey,
    peer_vip: Ipv4Addr,
) -> Result<(), PairingError> {
    if self_key == peer_key {
        return Err(PairingError::SelfPairing(self_key));
    }
    if self_vip == peer_vip {
        return Err(PairingError::State(format!(
            "the local and peer overlay addresses are both {self_vip}"
        )));
    }
    if existing.len() >= MAX_PEERS {
        return Err(PairingError::State(format!(
            "this node already holds {} relationships, the {MAX_PEERS}-peer bound",
            existing.len()
        )));
    }
    for relationship in existing {
        let id = relationship.relationship_id;
        if relationship.self_public_key != self_key {
            return Err(PairingError::InconsistentIdentity {
                relationship: id,
                actual: self_key,
                expected: relationship.self_public_key,
            });
        }
        let stored_self = stored_vip(relationship, "self_vip")?;
        if stored_self != self_vip {
            return Err(PairingError::InconsistentSelfAddress {
                relationship: id,
                actual: self_vip.to_string(),
                expected: relationship.self_vip.clone(),
            });
        }
        if relationship.peer_public_key == peer_key {
            return Err(PairingError::DuplicatePeerKey {
                peer: peer_key,
                existing: id,
            });
        }
        // Only the peer's address has to be new; our own address is required to
        // be identical across every relationship, checked above.
        if stored_self == peer_vip || stored_vip(relationship, "peer_vip")? == peer_vip {
            return Err(PairingError::DuplicateOverlayAddress {
                address: peer_vip.to_string(),
                existing: id,
            });
        }
    }
    Ok(())
}

/// Drop a pending offer once its relationship is durable.
///
/// A failure here leaves a PSK on disk but does not invalidate the pairing, so
/// it is reported loudly without turning a completed pairing into an error.
fn retire_offer(state: &StateDir, pairing: RelationshipId) {
    if let Err(error) = state.remove_offer(pairing) {
        eprintln!("warning: could not remove the pending offer for pairing {pairing}: {error}");
        eprintln!(
            "warning: it still holds the relationship PSK; delete it from the state directory by hand"
        );
    }
}

fn offer(args: &PairOfferArgs) -> Result<ExitCode, PairingError> {
    let state = StateDir::open(&args.state)?;
    if !state.has_identity() {
        return Err(PairingError::State(
            "no identity yet; run lzh-hole init first".to_owned(),
        ));
    }
    let peer_key = parse_key(&args.peer_key, "--peer-key")?;
    let (self_vip, self_vip_text) = parse_vip(&args.self_vip, "--self-vip")?;
    let (peer_vip, peer_vip_text) = parse_vip(&args.peer_vip, "--peer-vip")?;
    let seed = state.load_seed()?;
    let self_key = public_key_of_seed(seed.expose_bytes());
    let existing = state.load_relationships()?;
    check_mesh_shape(&existing, self_key, self_vip, peer_key, peer_vip)?;

    let psk = Secret32::random()?;
    let pairing_id =
        RelationshipId::random().map_err(|error| PairingError::Format(error.to_string()))?;
    let relationship_id =
        RelationshipId::random().map_err(|error| PairingError::Format(error.to_string()))?;
    let offer = build_offer(
        seed.expose_bytes(),
        pairing_id,
        relationship_id,
        self_key,
        peer_key,
        self_vip_text,
        peer_vip_text,
        &psk,
        now_unix_ms(),
    )?;
    state.store_offer(&offer)?;
    write_pair_file(&args.out, &offer)?;
    println!("wrote offer to {}", args.out.display());
    println!("pairing       {}", offer.pairing_id);
    println!("relationship  {}", offer.relationship_id);
    println!("you           {self_key}  (initiator)");
    println!("peer          {peer_key}  (responder, as declared by you)");
    println!("your_vip      {}", offer.initiator_vip);
    println!("peer_vip      {}", offer.responder_vip);
    println!(
        "peers         {} finalised, this will be number {}",
        existing.len(),
        existing.len() + 1
    );
    println!();
    println!("This file contains the relationship PSK and is signed by your identity");
    println!("key. Transfer it over a channel you already trust, keep it 0600, and");
    println!("delete it once pairing completes.");
    println!("Other pairings may run in parallel; each keeps its own PSK.");
    Ok(ExitCode::SUCCESS)
}

fn accept(args: &PairAcceptArgs) -> Result<ExitCode, PairingError> {
    let state = StateDir::open(&args.state)?;
    if !state.has_identity() {
        return Err(PairingError::State(
            "no identity yet; run lzh-hole init first".to_owned(),
        ));
    }
    let offer: Offer = read_pair_file(&args.offer)?;
    offer.verify()?;
    let seed = state.load_seed()?;
    let self_key = public_key_of_seed(seed.expose_bytes());
    if self_key == offer.initiator_public_key {
        return Err(PairingError::SelfPairing(self_key));
    }
    if self_key != offer.responder_public_key {
        return Err(PairingError::NotTheResponder {
            expected: offer.responder_public_key,
            got: self_key,
        });
    }
    // We are the responder, so the offer's responder address is ours and its
    // initiator is the peer.
    let (self_vip, _) = parse_vip(&offer.responder_vip, "offer responder_vip")?;
    let (peer_vip, _) = parse_vip(&offer.initiator_vip, "offer initiator_vip")?;
    let existing = state.load_relationships()?;
    check_mesh_shape(
        &existing,
        self_key,
        self_vip,
        offer.initiator_public_key,
        peer_vip,
    )?;

    let acceptance = build_acceptance(seed.expose_bytes(), &offer, self_key, now_unix_ms())?;
    state.store_offer(&offer)?;
    write_pair_file(&args.out, &acceptance)?;
    println!("wrote acceptance to {}", args.out.display());
    println!("pairing       {}", acceptance.pairing_id);
    println!("relationship  {}", acceptance.relationship_id);
    println!("you           {self_key}  (responder)");
    println!("peer          {}  (initiator)", offer.initiator_public_key);
    println!("your_vip      {}", offer.responder_vip);
    println!("peer_vip      {}", offer.initiator_vip);
    println!(
        "peers         {} finalised, this will be number {}",
        existing.len(),
        existing.len() + 1
    );
    println!();
    println!("Send this file back, then run pair finalize on both sides.");
    println!("This side is NOT paired yet and no data path exists.");
    Ok(ExitCode::SUCCESS)
}

fn finalize(args: &PairFinalizeArgs) -> Result<ExitCode, PairingError> {
    let state = StateDir::open(&args.state)?;
    let expected = parse_key(&args.expect_peer_key, "--expect-peer-key")?;
    let self_key = state.public_key()?;
    let now = now_unix_ms();

    let relationship = match args.role {
        PairRoleArg::Initiator => {
            let accept_path = args.accept.as_ref().ok_or_else(|| {
                PairingError::State("--accept is required when finalising as initiator".to_owned())
            })?;
            // The acceptance names the pairing, so parallel pairings stay apart.
            let acceptance: Acceptance = read_pair_file(accept_path)?;
            acceptance.check_shape()?;
            let offer = state.load_offer(acceptance.pairing_id)?;
            verify_acceptance(&offer, &acceptance, expected)?;
            if acceptance.responder_public_key == self_key {
                return Err(PairingError::SelfPairing(self_key));
            }
            if offer.initiator_public_key != self_key {
                return Err(PairingError::State(
                    "the stored offer was not created by this identity".to_owned(),
                ));
            }
            let psk = offer.psk()?;
            let relationship = Relationship {
                pairing_version: PAIRING_VERSION,
                pairing_id: offer.pairing_id,
                relationship_id: offer.relationship_id,
                self_public_key: offer.initiator_public_key,
                peer_public_key: acceptance.responder_public_key,
                role: Role::Initiator,
                self_vip: offer.initiator_vip.clone(),
                peer_vip: offer.responder_vip.clone(),
                finalised_unix_ms: now,
            };
            state.finalise(&relationship, &psk)?;
            retire_offer(&state, offer.pairing_id);
            relationship
        }
        PairRoleArg::Responder => {
            let offer_path = args.offer.as_ref().ok_or_else(|| {
                PairingError::State("--offer is required when finalising as responder".to_owned())
            })?;
            let offer: Offer = read_pair_file(offer_path)?;
            offer.verify()?;
            if offer.initiator_public_key != expected {
                return Err(PairingError::ExpectationMismatch {
                    got: offer.initiator_public_key,
                    expected,
                });
            }
            if offer.responder_public_key != self_key {
                return Err(PairingError::NotTheResponder {
                    expected: offer.responder_public_key,
                    got: self_key,
                });
            }
            if offer.initiator_public_key == self_key {
                return Err(PairingError::SelfPairing(self_key));
            }
            // Finalising an offer this node never accepted would let a file that
            // merely arrived on disk create a relationship. `pair accept` always
            // stores the offer, so require it and require it to be the same one.
            let stored = state.load_offer(offer.pairing_id)?;
            if stored != offer {
                return Err(PairingError::State(format!(
                    "the offer file does not match the offer this node accepted for pairing {}",
                    offer.pairing_id
                )));
            }
            let psk = offer.psk()?;
            let relationship = Relationship {
                pairing_version: PAIRING_VERSION,
                pairing_id: offer.pairing_id,
                relationship_id: offer.relationship_id,
                self_public_key: offer.responder_public_key,
                peer_public_key: offer.initiator_public_key,
                role: Role::Responder,
                self_vip: offer.responder_vip.clone(),
                peer_vip: offer.initiator_vip.clone(),
                finalised_unix_ms: now,
            };
            state.finalise(&relationship, &psk)?;
            retire_offer(&state, offer.pairing_id);
            relationship
        }
    };

    let total = state.relationship_ids()?.len();
    println!("paired");
    println!("pairing       {}", relationship.pairing_id);
    println!("relationship  {}", relationship.relationship_id);
    println!("role          {:?}", relationship.role);
    println!("you           {}", relationship.self_public_key);
    println!("peer          {}", relationship.peer_public_key);
    println!("your_vip      {}", relationship.self_vip);
    println!("peer_vip      {}", relationship.peer_vip);
    println!("peers         {total} finalised in this state directory");
    println!("psk_file      0600");
    println!();
    println!("The pairing role is not the wire role: on the wire the holder of the");
    println!("lexicographically smaller key is the initiator. Both sides agree on it");
    println!("without negotiation.");
    println!("Delete the offer and acceptance files now that pairing is complete.");
    Ok(ExitCode::SUCCESS)
}
