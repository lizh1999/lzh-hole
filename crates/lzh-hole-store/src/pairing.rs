//! Pairing material and its on-disk layout.
//!
//! Pairing happens over a channel the operator already trusts. The relationship
//! PSK travels inside the offer file, which is written 0600 inside a 0700
//! directory and never appears in argv, in the environment, in a log line or in
//! a report.
//!
//! The PSK alone is NOT an identity credential. Both sides sign the complete
//! pairing transcript with their own Ed25519 private key, so each side proves
//! it holds the private key for the public key the other side expects, and the
//! signature covers the PSK, both identities, the roles, the relationship id and
//! the pairing id. An interceptor who reads the offer but does not hold the
//! designated responder private key cannot produce an acceptance the initiator
//! will accept.
//!
//! Format version 2. Version 1 material is refused outright: it bound the
//! acceptance only with a MAC under the PSK, which let anyone who read the
//! offer impersonate the responder.

use std::path::{Path, PathBuf};

use crate::secret::{
    SecretError, ensure_private_dir, read_private_bytes, read_secret_file, write_private_bytes,
    write_secret_file,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use lzh_hole_types::{DiscoveryPublicKey, RelationshipId, Secret32};
pub use lzh_hole_types::{PairingRole as Role, Relationship};
use serde::{Deserialize, Serialize};

/// Pairing protocol version. Version 1 is refused.
pub const PAIRING_VERSION: u32 = 2;
/// Domain separation for the offer transcript.
pub const LABEL_PAIR_OFFER: &[u8] = b"lzh-hole/v2/pair/offer";
/// Domain separation for the acceptance transcript.
pub const LABEL_PAIR_ACCEPT: &[u8] = b"lzh-hole/v2/pair/accept";
/// File name of the identity seed.
pub const IDENTITY_FILE: &str = "identity.key";
/// File name of the finalised relationship.
pub const RELATIONSHIP_FILE: &str = "relationship.json";
/// File name of the relationship PSK.
pub const PSK_FILE: &str = "relationship.psk";
/// File name of the durable sequence high-water mark.
pub const SEQUENCE_FILE: &str = "publish.seq";
/// File name of the single-writer lock.
pub const LOCK_FILE: &str = "publish.lock";
/// File name of the offer the initiator keeps so finalize can verify against it.
pub const OFFER_FILE: &str = "offer.json";
/// Largest pairing file we will read.
pub const MAX_PAIR_FILE_BYTES: u64 = 16 * 1024;
/// Longest overlay address we accept.
pub const MAX_VIP_LEN: usize = 64;
/// Longest hex signature.
pub const SIGNATURE_HEX_LEN: usize = 128;

/// Why pairing failed.
#[derive(Debug, thiserror::Error)]
pub enum PairingError {
    /// The state directory is missing or unsafe.
    #[error("state directory: {0}")]
    State(String),
    /// A file could not be read or written.
    #[error("{path}: {detail}")]
    Io {
        /// Offending path.
        path: PathBuf,
        /// What went wrong.
        detail: String,
    },
    /// The pairing file was not understood.
    #[error("pairing file: {0}")]
    Format(String),
    /// The material is from the refused version 1 format.
    #[error(
        "refusing pairing version {0}: version 1 bound acceptance only with a PSK MAC, \
         which let anyone who read the offer impersonate the responder. Re-create the pairing."
    )]
    UnsupportedVersion(u32),
    /// A signature did not verify.
    #[error("{0}")]
    SignatureInvalid(&'static str),
    /// The acceptance names a different responder than the offer declared.
    #[error("acceptance names responder {got}, but the offer declared {expected}")]
    ResponderMismatch {
        /// Key in the acceptance.
        got: DiscoveryPublicKey,
        /// Key the offer declared.
        expected: DiscoveryPublicKey,
    },
    /// The acceptance names a different responder than the operator expects.
    #[error("acceptance names responder {got}, but --expect-peer-key says {expected}")]
    ExpectationMismatch {
        /// Key in the acceptance.
        got: DiscoveryPublicKey,
        /// Key the operator declared.
        expected: DiscoveryPublicKey,
    },
    /// The acceptance is for a different pairing or relationship.
    #[error("acceptance does not belong to this offer ({0})")]
    WrongPairing(&'static str),
    /// We are not the responder this offer is addressed to.
    #[error("this offer is addressed to responder {expected}, but our key is {got}")]
    NotTheResponder {
        /// Key the offer declared.
        expected: DiscoveryPublicKey,
        /// Our own key.
        got: DiscoveryPublicKey,
    },
    /// A key was paired with itself.
    #[error("refusing to pair a key with itself ({0})")]
    SelfPairing(DiscoveryPublicKey),
    /// No finalised relationship exists.
    #[error("no finalised relationship in {0}; run pair offer/accept/finalize first")]
    NotPaired(PathBuf),
    /// Secret storage refused.
    #[error(transparent)]
    Secret(#[from] SecretError),
    /// Secret value generation or decoding failed.
    #[error(transparent)]
    SecretValue(#[from] lzh_hole_types::SecretError),
}

fn io(path: &Path, detail: impl std::fmt::Display) -> PairingError {
    PairingError::Io {
        path: path.to_path_buf(),
        detail: detail.to_string(),
    }
}

/// The offer the initiator hands to the responder.
///
/// Every field except `initiator_signature` is covered by that signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    /// Pairing protocol version. Must be 2.
    pub pairing_version: u32,
    /// Always "offer".
    pub kind: String,
    /// Unique id for this pairing attempt.
    pub pairing_id: RelationshipId,
    /// Random relationship id this pairing establishes.
    pub relationship_id: RelationshipId,
    /// The initiator's discovery public key.
    pub initiator_public_key: DiscoveryPublicKey,
    /// The responder public key the initiator expects. Binding this here is
    /// what stops an interceptor substituting their own key.
    pub responder_public_key: DiscoveryPublicKey,
    /// The initiator's overlay address.
    pub initiator_vip: String,
    /// The responder's overlay address.
    pub responder_vip: String,
    /// The relationship PSK, hex. Secret, and covered by both signatures.
    pub psk_hex: String,
    /// When the offer was made.
    pub created_unix_ms: u64,
    /// Ed25519 signature by the initiator over the offer transcript, hex.
    pub initiator_signature: String,
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The exact bytes the initiator signs, and that the acceptance extends.
///
/// The argument list is deliberately flat and explicit: every field that the
/// signature must cover appears here, so a reviewer can see the whole covered
/// set in one place.
#[allow(
    clippy::too_many_arguments,
    reason = "every covered field is explicit on purpose"
)]
pub fn offer_transcript(
    pairing_version: u32,
    pairing_id: &RelationshipId,
    relationship_id: &RelationshipId,
    initiator: &DiscoveryPublicKey,
    responder: &DiscoveryPublicKey,
    initiator_vip: &str,
    responder_vip: &str,
    psk: &Secret32,
    created_unix_ms: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(LABEL_PAIR_OFFER);
    out.extend_from_slice(&pairing_version.to_be_bytes());
    out.extend_from_slice(pairing_id.as_bytes());
    out.extend_from_slice(relationship_id.as_bytes());
    out.extend_from_slice(initiator.as_bytes());
    out.extend_from_slice(responder.as_bytes());
    push_len_prefixed(&mut out, initiator_vip.as_bytes());
    push_len_prefixed(&mut out, responder_vip.as_bytes());
    out.extend_from_slice(psk.expose_bytes());
    out.extend_from_slice(&created_unix_ms.to_be_bytes());
    out
}

impl Offer {
    /// The PSK, parsed strictly.
    pub fn psk(&self) -> Result<Secret32, PairingError> {
        Secret32::from_hex(&self.psk_hex).map_err(|e| PairingError::Format(e.to_string()))
    }

    /// The initiator transcript this offer claims to sign.
    pub fn transcript(&self) -> Result<Vec<u8>, PairingError> {
        let psk = self.psk()?;
        Ok(offer_transcript(
            self.pairing_version,
            &self.pairing_id,
            &self.relationship_id,
            &self.initiator_public_key,
            &self.responder_public_key,
            &self.initiator_vip,
            &self.responder_vip,
            &psk,
            self.created_unix_ms,
        ))
    }

    /// Validate structure, bounds and the initiator signature.
    pub fn verify(&self) -> Result<(), PairingError> {
        if self.pairing_version != PAIRING_VERSION {
            return Err(PairingError::UnsupportedVersion(self.pairing_version));
        }
        if self.kind != "offer" {
            return Err(PairingError::Format(format!("kind is {:?}", self.kind)));
        }
        if self.initiator_public_key == self.responder_public_key {
            return Err(PairingError::SelfPairing(self.initiator_public_key));
        }
        if self.initiator_vip.len() > MAX_VIP_LEN || self.responder_vip.len() > MAX_VIP_LEN {
            return Err(PairingError::Format(
                "overlay address is too long".to_owned(),
            ));
        }
        if self.initiator_signature.len() != SIGNATURE_HEX_LEN {
            return Err(PairingError::Format(
                "initiator signature is not 128 hex characters".to_owned(),
            ));
        }
        let transcript = self.transcript()?;
        verify_signature(
            &self.initiator_public_key,
            &transcript,
            &self.initiator_signature,
            "the offer's initiator signature does not verify under the declared initiator key",
        )
    }
}

/// The responder's reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acceptance {
    /// Pairing protocol version. Must be 2.
    pub pairing_version: u32,
    /// Always "accept".
    pub kind: String,
    /// The pairing id from the offer.
    pub pairing_id: RelationshipId,
    /// The relationship id from the offer.
    pub relationship_id: RelationshipId,
    /// The responder's discovery public key.
    pub responder_public_key: DiscoveryPublicKey,
    /// When it was accepted.
    pub accepted_unix_ms: u64,
    /// Ed25519 signature by the responder over the acceptance transcript, hex.
    pub responder_signature: String,
}

impl Acceptance {
    /// The bytes the responder signs: the whole offer transcript, then the
    /// responder's own identity and timestamp.
    pub fn transcript(&self, offer: &Offer) -> Result<Vec<u8>, PairingError> {
        let mut out = Vec::with_capacity(320);
        out.extend_from_slice(LABEL_PAIR_ACCEPT);
        out.extend_from_slice(&offer.transcript()?);
        out.extend_from_slice(self.responder_public_key.as_bytes());
        out.extend_from_slice(&self.accepted_unix_ms.to_be_bytes());
        Ok(out)
    }

    /// Validate structure and bounds. Signature checking needs the offer.
    pub fn check_shape(&self) -> Result<(), PairingError> {
        if self.pairing_version != PAIRING_VERSION {
            return Err(PairingError::UnsupportedVersion(self.pairing_version));
        }
        if self.kind != "accept" {
            return Err(PairingError::Format(format!("kind is {:?}", self.kind)));
        }
        if self.responder_signature.len() != SIGNATURE_HEX_LEN {
            return Err(PairingError::Format(
                "responder signature is not 128 hex characters".to_owned(),
            ));
        }
        Ok(())
    }
}

fn signing_key(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

/// Derive the public identity from an existing Ed25519 seed. The byte and text
/// representation is identical to the pre-refactor implementation.
pub fn public_key_of_seed(seed: &[u8; 32]) -> DiscoveryPublicKey {
    public_key_of_signing_key(&signing_key(seed))
}

/// Derive the public identity from an Ed25519 signing key.
pub fn public_key_of_signing_key(key: &SigningKey) -> DiscoveryPublicKey {
    DiscoveryPublicKey::from_bytes(key.verifying_key().to_bytes())
}

fn sign_hex(seed: &[u8; 32], message: &[u8]) -> String {
    hex::encode(signing_key(seed).sign(message).to_bytes())
}

fn verify_signature(
    key: &DiscoveryPublicKey,
    message: &[u8],
    signature_hex: &str,
    what: &'static str,
) -> Result<(), PairingError> {
    let raw = hex::decode(signature_hex)
        .map_err(|_| PairingError::Format("signature is not hex".to_owned()))?;
    let bytes: [u8; 64] = raw
        .try_into()
        .map_err(|_| PairingError::Format("signature is not 64 bytes".to_owned()))?;
    let signature = Signature::from_bytes(&bytes);
    let verifying = VerifyingKey::from_bytes(key.as_bytes())
        .map_err(|_| PairingError::Format("public key is not a valid Ed25519 point".to_owned()))?;
    verifying
        .verify_strict(message, &signature)
        .map_err(|_| PairingError::SignatureInvalid(what))
}

/// Build an offer, signing it with the initiator's private key.
#[allow(clippy::too_many_arguments)]
pub fn build_offer(
    seed: &[u8; 32],
    pairing_id: RelationshipId,
    relationship_id: RelationshipId,
    initiator: DiscoveryPublicKey,
    responder: DiscoveryPublicKey,
    initiator_vip: String,
    responder_vip: String,
    psk: &Secret32,
    created_unix_ms: u64,
) -> Result<Offer, PairingError> {
    if initiator == responder {
        return Err(PairingError::SelfPairing(initiator));
    }
    if initiator_vip.len() > MAX_VIP_LEN || responder_vip.len() > MAX_VIP_LEN {
        return Err(PairingError::Format(
            "overlay address is too long".to_owned(),
        ));
    }
    let transcript = offer_transcript(
        PAIRING_VERSION,
        &pairing_id,
        &relationship_id,
        &initiator,
        &responder,
        &initiator_vip,
        &responder_vip,
        psk,
        created_unix_ms,
    );
    let derived = signing_key(seed).verifying_key();
    if derived.to_bytes() != *initiator.as_bytes() {
        return Err(PairingError::State(
            "the identity key on disk does not match the initiator public key".to_owned(),
        ));
    }
    Ok(Offer {
        pairing_version: PAIRING_VERSION,
        kind: "offer".to_owned(),
        pairing_id,
        relationship_id,
        initiator_public_key: initiator,
        responder_public_key: responder,
        initiator_vip,
        responder_vip,
        psk_hex: hex::encode(psk.expose_bytes()),
        created_unix_ms,
        initiator_signature: sign_hex(seed, &transcript),
    })
}

/// Build an acceptance, signing it with the responder's private key.
pub fn build_acceptance(
    seed: &[u8; 32],
    offer: &Offer,
    responder: DiscoveryPublicKey,
    accepted_unix_ms: u64,
) -> Result<Acceptance, PairingError> {
    offer.verify()?;
    if offer.responder_public_key != responder {
        return Err(PairingError::NotTheResponder {
            expected: offer.responder_public_key,
            got: responder,
        });
    }
    if offer.initiator_public_key == responder {
        return Err(PairingError::SelfPairing(responder));
    }
    let mut acceptance = Acceptance {
        pairing_version: PAIRING_VERSION,
        kind: "accept".to_owned(),
        pairing_id: offer.pairing_id,
        relationship_id: offer.relationship_id,
        responder_public_key: responder,
        accepted_unix_ms,
        responder_signature: String::new(),
    };
    let transcript = acceptance.transcript(offer)?;
    let derived = signing_key(seed).verifying_key();
    if derived.to_bytes() != *responder.as_bytes() {
        return Err(PairingError::State(
            "the identity key on disk does not match the responder public key".to_owned(),
        ));
    }
    acceptance.responder_signature = sign_hex(seed, &transcript);
    Ok(acceptance)
}

/// Verify an acceptance against the offer and the operator's expectation.
///
/// This is the only place a peer key is ever pinned. The acceptance's own claim
/// is never trusted on its own: it must match the offer, it must match what the
/// operator declared, and its signature must verify under that key over a
/// transcript that includes the PSK.
pub fn verify_acceptance(
    offer: &Offer,
    acceptance: &Acceptance,
    expected_responder: DiscoveryPublicKey,
) -> Result<(), PairingError> {
    offer.verify()?;
    acceptance.check_shape()?;
    if acceptance.pairing_id != offer.pairing_id {
        return Err(PairingError::WrongPairing("pairing id"));
    }
    if acceptance.relationship_id != offer.relationship_id {
        return Err(PairingError::WrongPairing("relationship id"));
    }
    if acceptance.responder_public_key != offer.responder_public_key {
        return Err(PairingError::ResponderMismatch {
            got: acceptance.responder_public_key,
            expected: offer.responder_public_key,
        });
    }
    if acceptance.responder_public_key != expected_responder {
        return Err(PairingError::ExpectationMismatch {
            got: acceptance.responder_public_key,
            expected: expected_responder,
        });
    }
    if acceptance.responder_public_key == offer.initiator_public_key {
        return Err(PairingError::SelfPairing(acceptance.responder_public_key));
    }
    let transcript = acceptance.transcript(offer)?;
    verify_signature(
        &acceptance.responder_public_key,
        &transcript,
        &acceptance.responder_signature,
        "the responder signature does not verify: the acceptor did not hold the expected responder private key, or the offer was altered",
    )
}

/// The on-disk state directory.
#[derive(Debug, Clone)]
pub struct StateDir {
    path: PathBuf,
}

impl StateDir {
    /// Open or create a state directory with mode 0700.
    pub fn open(path: &Path) -> Result<Self, PairingError> {
        ensure_private_dir(path)?;
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    /// Open an existing private directory without creating or modifying anything.
    pub fn open_existing(path: &Path) -> Result<Self, PairingError> {
        crate::secret::verify_private_dir(path)?;
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    /// The directory path.
    #[allow(dead_code, reason = "state-dir introspection; covered by unit tests")]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Path of one file inside the state directory.
    pub fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    /// Whether an identity already exists.
    pub fn has_identity(&self) -> bool {
        self.file(IDENTITY_FILE).exists()
    }

    /// Whether a relationship is finalised.
    pub fn is_paired(&self) -> bool {
        self.file(RELATIONSHIP_FILE).exists() && self.file(PSK_FILE).exists()
    }

    /// Load the Ed25519 seed in its redacted, zeroizing container.
    pub fn load_seed(&self) -> Result<Secret32, PairingError> {
        Ok(read_secret_file(&self.file(IDENTITY_FILE))?)
    }

    /// Load the Ed25519 signing key without retaining a separate raw seed copy.
    pub fn load_signing_key(&self) -> Result<SigningKey, PairingError> {
        let secret = self.load_seed()?;
        Ok(SigningKey::from_bytes(secret.expose_bytes()))
    }

    /// Derive this identity's public key from the stored seed.
    pub fn public_key(&self) -> Result<DiscoveryPublicKey, PairingError> {
        Ok(public_key_of_signing_key(&self.load_signing_key()?))
    }

    /// Create an identity with `ed25519-dalek` and OS randomness, or report the
    /// existing public key. Replacement requires the explicit `force` flag.
    /// Returns `(public_key, created)`.
    pub fn init_identity(&self, force: bool) -> Result<(DiscoveryPublicKey, bool), PairingError> {
        if self.has_identity() && !force {
            return Ok((self.public_key()?, false));
        }
        if self.has_identity() {
            let path = self.file(IDENTITY_FILE);
            std::fs::remove_file(&path).map_err(|error| io(&path, error))?;
        }
        let secret = Secret32::random()?;
        self.store_seed(secret.expose_bytes())?;
        Ok((public_key_of_seed(secret.expose_bytes()), true))
    }

    /// Store the Ed25519 seed.
    pub fn store_seed(&self, seed: &[u8; 32]) -> Result<(), PairingError> {
        let secret = Secret32::from_bytes(*seed);
        write_secret_file(&self.file(IDENTITY_FILE), &secret)?;
        Ok(())
    }

    /// Load the relationship PSK.
    pub fn load_psk(&self) -> Result<Secret32, PairingError> {
        Ok(read_secret_file(&self.file(PSK_FILE))?)
    }

    /// Load the finalised relationship, with owner, mode, no-follow and length
    /// checks applied by the reader.
    pub fn load_relationship(&self) -> Result<Relationship, PairingError> {
        if !self.is_paired() {
            return Err(PairingError::NotPaired(self.path.clone()));
        }
        let path = self.file(RELATIONSHIP_FILE);
        let bytes = read_private_bytes(&path, MAX_PAIR_FILE_BYTES)?;
        let text = String::from_utf8(bytes).map_err(|_| io(&path, "not valid UTF-8"))?;
        let rel: Relationship =
            serde_json::from_str(&text).map_err(|e| PairingError::Format(e.to_string()))?;
        if rel.pairing_version != PAIRING_VERSION {
            return Err(PairingError::UnsupportedVersion(rel.pairing_version));
        }
        Ok(rel)
    }

    /// Persist the finalised relationship and its PSK.
    pub fn finalise(
        &self,
        relationship: &Relationship,
        psk: &Secret32,
    ) -> Result<(), PairingError> {
        write_secret_file(&self.file(PSK_FILE), psk)?;
        let text = serde_json::to_string_pretty(relationship)
            .map_err(|e| PairingError::Format(e.to_string()))?;
        write_private_bytes(&self.file(RELATIONSHIP_FILE), text.as_bytes())?;
        Ok(())
    }

    /// Read the durable sequence high-water mark.
    pub fn load_sequence(&self) -> Result<u64, PairingError> {
        let path = self.file(SEQUENCE_FILE);
        if !path.exists() {
            return Ok(0);
        }
        let bytes = read_private_bytes(&path, 64)?;
        let text = String::from_utf8(bytes).map_err(|_| io(&path, "not valid UTF-8"))?;
        text.trim()
            .parse::<u64>()
            .map_err(|e| PairingError::Format(format!("publish.seq: {e}")))
    }

    /// Durably record a new sequence high-water mark.
    ///
    /// Uses a temp file, an atomic rename and a parent directory fsync, so a
    /// crash can never leave a mark that was never reserved.
    pub fn store_sequence(&self, seq: u64) -> Result<(), PairingError> {
        write_private_bytes(&self.file(SEQUENCE_FILE), format!("{seq}\n").as_bytes())?;
        Ok(())
    }

    /// Take the single-writer publish lock.
    pub fn lock_publisher(&self) -> Result<crate::secret::FileLock, PairingError> {
        let path = self.file(LOCK_FILE);
        crate::secret::FileLock::try_acquire(&path)?.ok_or_else(|| {
            PairingError::State(
                "another process already holds the publish lock for this identity".to_owned(),
            )
        })
    }

    /// Store the offer so finalize can verify the acceptance against it.
    pub fn store_offer(&self, offer: &Offer) -> Result<(), PairingError> {
        write_pair_file(&self.file(OFFER_FILE), offer)
    }

    /// Load the stored offer.
    pub fn load_offer(&self) -> Result<Offer, PairingError> {
        read_pair_file(&self.file(OFFER_FILE))
    }
}

/// Write an offer or acceptance file with mode 0600.
pub fn write_pair_file<T: Serialize>(path: &Path, value: &T) -> Result<(), PairingError> {
    let text =
        serde_json::to_string_pretty(value).map_err(|e| PairingError::Format(e.to_string()))?;
    if text.len() as u64 > MAX_PAIR_FILE_BYTES {
        return Err(PairingError::Format("pairing file is too large".to_owned()));
    }
    write_private_bytes(path, text.as_bytes())?;
    Ok(())
}

/// Read an offer or acceptance file with the same owner, mode, no-follow and
/// length checks used for every other state file.
pub fn read_pair_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, PairingError> {
    let bytes = read_private_bytes(path, MAX_PAIR_FILE_BYTES)?;
    let text = String::from_utf8(bytes).map_err(|_| io(path, "not valid UTF-8"))?;
    serde_json::from_str(&text).map_err(|e| PairingError::Format(e.to_string()))
}
