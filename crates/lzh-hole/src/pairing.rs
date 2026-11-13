//! CLI pairing subcommands. Cryptographic and durable operations are delegated
//! to `lzh-hole-store`; this module only validates arguments and prints public
//! results.

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

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

fn offer(args: &PairOfferArgs) -> Result<ExitCode, PairingError> {
    let state = StateDir::open(&args.state)?;
    if !state.has_identity() {
        return Err(PairingError::State(
            "no identity yet; run lzh-hole init first".to_owned(),
        ));
    }
    if state.is_paired() {
        return Err(PairingError::State(
            "already paired; remove the relationship files to re-pair".to_owned(),
        ));
    }
    let peer_key = parse_key(&args.peer_key, "--peer-key")?;
    let seed = state.load_seed()?;
    let self_key = public_key_of_seed(seed.expose_bytes());
    if self_key == peer_key {
        return Err(PairingError::SelfPairing(self_key));
    }
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
        args.self_vip.clone(),
        args.peer_vip.clone(),
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
    println!();
    println!("This file contains the relationship PSK and is signed by your identity");
    println!("key. Transfer it over a channel you already trust, keep it 0600, and");
    println!("delete it once pairing completes.");
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
            let offer = state.load_offer()?;
            let acceptance: Acceptance = read_pair_file(accept_path)?;
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
            relationship
        }
    };

    println!("paired");
    println!("pairing       {}", relationship.pairing_id);
    println!("relationship  {}", relationship.relationship_id);
    println!("role          {:?}", relationship.role);
    println!("you           {}", relationship.self_public_key);
    println!("peer          {}", relationship.peer_public_key);
    println!("your_vip      {}", relationship.self_vip);
    println!("peer_vip      {}", relationship.peer_vip);
    println!("psk_file      0600");
    println!();
    println!("The pairing role is not the wire role: on the wire the holder of the");
    println!("lexicographically smaller key is the initiator. Both sides agree on it");
    println!("without negotiation.");
    println!("Delete the offer and acceptance files now that pairing is complete.");
    Ok(ExitCode::SUCCESS)
}
