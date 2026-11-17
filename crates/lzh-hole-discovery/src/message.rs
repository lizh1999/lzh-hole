//! Authenticated candidate coordination over ntfy's streaming JSON endpoint.
//!
//! The transport carries only bounded, signed contact records. It never carries
//! a private key, PSK, session key or business IP packet. ntfy is not an
//! authentication or presence service: a verified record is only a candidate
//! hint, and even a live delivery does not prove that UDP is reachable.
//!
//! The daemon owns record construction and MUST durably reserve `record_seq`
//! through its `StateDir` single-writer path BEFORE calling `SignedPayload::sign`
//! or queueing a publish. This module deliberately has no clock-based sequence
//! fallback. The daemon also owns UDP state; transport events arrive on a bounded
//! Tokio channel so slow or failed HTTP never blocks the UDP socket loop.

use std::fmt;
use std::str::FromStr;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use lzh_hole_types::{PeerRecordState, RelationshipId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::peer_record::{
    PeerRecordPolicy, PeerRecordReject, ValidatedPeerRecord, evaluate_acceptance,
};
use crate::record::{AcceptOutcome, ContactRecord, MAX_CANDIDATES, RECORD_FIXED_LEN, RecordError};

/// Wire schema for the signed ntfy payload.
pub const SIGNALING_SCHEMA_VERSION: u8 = 1;
/// Domain separation for the exact signed transcript.
pub const LABEL_NTFY_PAYLOAD: &[u8] = b"lzh-hole/v1/ntfy/payload";
/// Maximum encoded signed payload accepted inside ntfy's `message` field.
pub const MAX_SIGNED_PAYLOAD_BYTES: usize = 2048;
const MAX_RECORD_BODY_BYTES: usize = RECORD_FIXED_LEN + 8 * MAX_CANDIDATES;

/// A random 128-bit identifier shared by one request and its correlated reply.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestId([u8; 16]);

impl RequestId {
    /// Generate a fresh identifier using the OS CSPRNG.
    pub fn random() -> Result<Self, PayloadError> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| PayloadError::Randomness)?;
        Ok(Self(bytes))
    }

    /// Wrap an identifier supplied by a deterministic test or restored state.
    #[cfg(test)]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw identifier.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Parse exactly 32 hexadecimal characters.
    pub fn from_hex(value: &str) -> Result<Self, PayloadError> {
        if value.len() != 32 {
            return Err(PayloadError::InvalidRequestId);
        }
        let raw = hex::decode(value).map_err(|_| PayloadError::InvalidRequestId)?;
        let bytes: [u8; 16] = raw.try_into().map_err(|_| PayloadError::InvalidRequestId)?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RequestId({self})")
    }
}

impl FromStr for RequestId {
    type Err = PayloadError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl Serialize for RequestId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for RequestId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// Signed correlation semantics. Only a request can elicit a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    /// Ask the peer for one correlated contact record.
    Request,
    /// Answer a request with the same request ID. Never auto-answer this kind.
    Reply,
}

impl MessageKind {
    fn code(self) -> u8 {
        match self {
            MessageKind::Request => 1,
            MessageKind::Reply => 2,
        }
    }
}

/// Why a signed payload could not be built or authenticated.
#[derive(Debug, thiserror::Error)]
pub enum PayloadError {
    /// The OS random source failed.
    #[error("operating system randomness unavailable")]
    Randomness,
    /// A request ID was not exactly 16 bytes encoded as hex.
    #[error("request ID must be exactly 32 hexadecimal characters")]
    InvalidRequestId,
    /// The encoded payload exceeded its hard bound.
    #[error("signed payload is {actual} bytes; maximum is {max}")]
    TooLarge {
        /// Observed size.
        actual: usize,
        /// Hard limit.
        max: usize,
    },
    /// JSON did not match the closed signed-payload schema.
    #[error("signed payload JSON: {0}")]
    Json(String),
    /// The payload schema is not supported.
    #[error("unsupported signaling schema {0}")]
    UnsupportedVersion(u8),
    /// A bounded hex field was malformed.
    #[error("invalid {0} hex")]
    InvalidHex(&'static str),
    /// The local signing key does not match the record sender.
    #[error("signing key does not match ContactRecord.sender")]
    WrongSigningKey,
    /// Ed25519 verification failed over the explicit transcript.
    #[error("signed payload signature, kind, request ID or record body was altered")]
    InvalidSignature,
    /// The canonical contact body was invalid.
    #[error(transparent)]
    Record(#[from] RecordError),
    /// Relationship, identity, validity, candidate or replay validation failed.
    #[error(transparent)]
    PeerRecord(#[from] PeerRecordReject),
}

/// A bounded JSON envelope containing a signed canonical contact body.
///
/// Use `from_json` at the transport boundary and `verify` before using any
/// candidate. Fields are private so callers cannot accidentally alter signed
/// metadata without creating a new signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPayload {
    version: u8,
    kind: MessageKind,
    request_id: RequestId,
    record_body: String,
    signature: String,
}

impl SignedPayload {
    /// Sign `ContactRecord::encode_body()` together with kind and request ID.
    ///
    /// The caller MUST have durably reserved `record.record_seq` before this
    /// call. Signing does not reserve, persist or otherwise advance a sequence.
    pub fn sign(
        kind: MessageKind,
        request_id: RequestId,
        record: &ContactRecord,
        signing_key: &SigningKey,
    ) -> Result<Self, PayloadError> {
        if signing_key.verifying_key().to_bytes() != *record.sender.as_bytes() {
            return Err(PayloadError::WrongSigningKey);
        }
        let body = record.encode_body()?;
        let transcript = signing_transcript(kind, request_id, &body);
        let signature = signing_key.sign(&transcript);
        let payload = Self {
            version: SIGNALING_SCHEMA_VERSION,
            kind,
            request_id,
            record_body: hex::encode(body),
            signature: hex::encode(signature.to_bytes()),
        };
        // Enforce the publish bound at construction, not only after receipt.
        let _ = payload.to_json()?;
        Ok(payload)
    }

    /// Parse and bound-check a payload without claiming it is authenticated.
    pub fn from_json(text: &str) -> Result<Self, PayloadError> {
        check_payload_size(text.len())?;
        let payload: Self =
            serde_json::from_str(text).map_err(|e| PayloadError::Json(e.to_string()))?;
        payload.check_shape()?;
        Ok(payload)
    }

    /// Encode the closed schema canonically enough for transport and replay identity.
    ///
    /// Signatures cover `signing_transcript`, never this JSON serialization.
    pub fn to_json(&self) -> Result<String, PayloadError> {
        self.check_shape()?;
        let text = serde_json::to_string(self).map_err(|e| PayloadError::Json(e.to_string()))?;
        check_payload_size(text.len())?;
        Ok(text)
    }

    /// The signed message kind.
    pub const fn kind(&self) -> MessageKind {
        self.kind
    }

    /// The signed request/reply correlation ID.
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Expiry inside the signed record, used to reject stale work before POST.
    /// This never extends or mutates the signed record.
    pub fn expires_at_unix_ms(&self) -> Result<u64, PayloadError> {
        Ok(self.contact_record()?.expires_at_unix_ms)
    }

    // Local publish admission only. Received candidates MUST still use verify.
    pub(crate) fn contact_record(&self) -> Result<ContactRecord, PayloadError> {
        let body = decode_hex_bounded(&self.record_body, MAX_RECORD_BODY_BYTES, "record body")?;
        Ok(ContactRecord::decode_body(&body)?)
    }

    /// Verify the signature and fully validate the record and its replay state.
    ///
    /// This function performs no I/O. For a newly accepted record the caller
    /// must commit `VerifiedPayload::state_to_persist` before using candidates.
    pub fn verify(
        &self,
        policy: &PeerRecordPolicy,
        previous: Option<&PeerRecordState>,
    ) -> Result<VerifiedPayload, PayloadError> {
        self.check_shape()?;
        let body = decode_hex_bounded(&self.record_body, MAX_RECORD_BODY_BYTES, "record body")?;
        let signature_bytes = decode_hex_bounded(&self.signature, 64, "signature")?;
        let signature_bytes: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| PayloadError::InvalidHex("signature"))?;
        let signature = Signature::from_bytes(&signature_bytes);
        let record = ContactRecord::decode_body(&body)?;
        let verifying = VerifyingKey::from_bytes(record.sender.as_bytes())
            .map_err(|_| PayloadError::InvalidSignature)?;
        verifying
            .verify_strict(
                &signing_transcript(self.kind, self.request_id, &body),
                &signature,
            )
            .map_err(|_| PayloadError::InvalidSignature)?;

        // Include signed correlation metadata in idempotency/equivocation bytes.
        // The canonical transcript, rather than arbitrary JSON/hex formatting,
        // makes reordered fields and hex case changes idempotent representations.
        let mut accepted_bytes = signing_transcript(self.kind, self.request_id, &body);
        accepted_bytes.extend_from_slice(&signature_bytes);
        let validated = crate::peer_record::validate(&record, record.record_seq, policy)?;
        let acceptance = evaluate_acceptance(&record, &accepted_bytes, previous)?;
        Ok(VerifiedPayload {
            kind: self.kind,
            request_id: self.request_id,
            validated,
            accept_outcome: acceptance.outcome,
            state_to_persist: acceptance.state_to_persist,
        })
    }

    fn check_shape(&self) -> Result<(), PayloadError> {
        if self.version != SIGNALING_SCHEMA_VERSION {
            return Err(PayloadError::UnsupportedVersion(self.version));
        }
        if self.record_body.len() > MAX_RECORD_BODY_BYTES * 2
            || !self.record_body.len().is_multiple_of(2)
            || !self.record_body.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(PayloadError::InvalidHex("record body"));
        }
        if self.signature.len() != 128 || !self.signature.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(PayloadError::InvalidHex("signature"));
        }
        Ok(())
    }
}

fn check_payload_size(actual: usize) -> Result<(), PayloadError> {
    if actual > MAX_SIGNED_PAYLOAD_BYTES {
        return Err(PayloadError::TooLarge {
            actual,
            max: MAX_SIGNED_PAYLOAD_BYTES,
        });
    }
    Ok(())
}

fn decode_hex_bounded(
    text: &str,
    maximum: usize,
    name: &'static str,
) -> Result<Vec<u8>, PayloadError> {
    if text.len() > maximum.saturating_mul(2) || !text.len().is_multiple_of(2) {
        return Err(PayloadError::InvalidHex(name));
    }
    hex::decode(text).map_err(|_| PayloadError::InvalidHex(name))
}

/// The exact signed bytes: domain || kind || request_id || canonical record body.
fn signing_transcript(kind: MessageKind, request_id: RequestId, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(LABEL_NTFY_PAYLOAD.len() + 1 + 16 + body.len());
    out.extend_from_slice(LABEL_NTFY_PAYLOAD);
    out.push(kind.code());
    out.extend_from_slice(request_id.as_bytes());
    out.extend_from_slice(body);
    out
}

/// An authenticated and policy-validated candidate message, not presence evidence.
#[derive(Debug, Clone)]
pub struct VerifiedPayload {
    /// Signed kind, used to prevent reply loops.
    pub kind: MessageKind,
    /// Signed correlation ID.
    pub request_id: RequestId,
    /// Fully checked contact record and filtered candidate targets.
    pub validated: ValidatedPeerRecord,
    /// Replay decision evaluated against the supplied durable state.
    pub accept_outcome: AcceptOutcome,
    state_to_persist: Option<PeerRecordState>,
}

impl VerifiedPayload {
    /// New state that must be committed before using the candidates. Idempotent
    /// reads return `None` and do not refresh issue/expiry times.
    pub fn state_to_persist(&self) -> Option<&PeerRecordState> {
        self.state_to_persist.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn for_exchange_test(
        kind: MessageKind,
        request_id: RequestId,
        accept_outcome: AcceptOutcome,
        record: ContactRecord,
    ) -> Self {
        let targets = record
            .candidates
            .iter()
            .map(|candidate| candidate.endpoint)
            .collect();
        Self {
            kind,
            request_id,
            validated: ValidatedPeerRecord {
                record,
                targets,
                rejected: Vec::new(),
            },
            accept_outcome,
            state_to_persist: None,
        }
    }
}

/// Derive the shared non-secret topic from the paired relationship.
pub fn topic_for_relationship(relationship_id: &RelationshipId) -> String {
    format!("lzh-hole-v1-{}", relationship_id.to_hex())
}
#[cfg(test)]
mod tests {
    use crate::record::RecordCandidate;
    use lzh_hole_protocol::path::{CandidateSource, Endpoint};
    use lzh_hole_store::PeerRecordCache;
    use lzh_hole_types::{BootId, DiscoveryPublicKey, RelationshipId};
    use std::net::Ipv4Addr;
    use tempfile::TempDir;

    use super::*;

    const NOW: u64 = 1_800_000_000_000;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn public(signing: &SigningKey) -> DiscoveryPublicKey {
        DiscoveryPublicKey::from_bytes(signing.verifying_key().to_bytes())
    }

    fn relationship() -> RelationshipId {
        RelationshipId::from_bytes([0x44; 16])
    }

    fn record(sender: &SigningKey, receiver: &SigningKey, sequence: u64) -> ContactRecord {
        ContactRecord {
            relationship_id: relationship(),
            sender: public(sender),
            receiver: public(receiver),
            record_seq: sequence,
            issued_at_unix_ms: NOW,
            expires_at_unix_ms: NOW + 600_000,
            boot_id: BootId::from_bytes([0x91; 16]),
            generation: 1,
            candidates: vec![RecordCandidate {
                endpoint: Endpoint::new(Ipv4Addr::new(8, 8, 8, 8), 50_000),
                source: CandidateSource::Stun,
            }],
            flags: 0,
        }
    }

    fn policy(sender: &SigningKey, receiver: &SigningKey) -> PeerRecordPolicy {
        PeerRecordPolicy::new(relationship(), public(receiver), public(sender), NOW)
    }

    fn cache(temp: &TempDir, name: &str) -> PeerRecordCache {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        PeerRecordCache::load(&temp.path().join(name)).unwrap()
    }

    trait TestVerify {
        fn verify_cached(
            &self,
            policy: &PeerRecordPolicy,
            cache: &mut PeerRecordCache,
        ) -> Result<VerifiedPayload, PayloadError>;
    }

    impl TestVerify for SignedPayload {
        fn verify_cached(
            &self,
            policy: &PeerRecordPolicy,
            cache: &mut PeerRecordCache,
        ) -> Result<VerifiedPayload, PayloadError> {
            let verified = self.verify(policy, cache.state())?;
            if let Some(state) = verified.state_to_persist() {
                cache.commit(state).unwrap();
            }
            Ok(verified)
        }
    }

    fn signed(sequence: u64) -> (SignedPayload, SigningKey, SigningKey) {
        let sender = key(7);
        let receiver = key(8);
        let payload = SignedPayload::sign(
            MessageKind::Request,
            RequestId::from_bytes([0x12; 16]),
            &record(&sender, &receiver, sequence),
            &sender,
        )
        .unwrap();
        (payload, sender, receiver)
    }

    #[test]
    fn signature_binds_body_kind_and_request_id() {
        let temp = TempDir::new().unwrap();
        let (payload, sender, receiver) = signed(100);
        let encoded = payload.to_json().unwrap();
        let decoded = SignedPayload::from_json(&encoded).unwrap();
        assert_eq!(decoded, payload);
        let verified = decoded
            .verify_cached(&policy(&sender, &receiver), &mut cache(&temp, "a.json"))
            .unwrap();
        assert_eq!(verified.accept_outcome, AcceptOutcome::Accepted);
        assert_eq!(verified.validated.record.record_seq, 100);

        for tamper in [0, 1, 2] {
            let mut changed = payload.clone();
            match tamper {
                0 => changed.kind = MessageKind::Reply,
                1 => changed.request_id = RequestId::from_bytes([0x13; 16]),
                _ => {
                    let mut body = record(&sender, &receiver, 100).encode_body().unwrap();
                    body[RECORD_FIXED_LEN] ^= 1;
                    changed.record_body = hex::encode(body);
                }
            }
            let result = changed.verify_cached(
                &policy(&sender, &receiver),
                &mut cache(&temp, &format!("tamper-{tamper}.json")),
            );
            assert!(matches!(result, Err(PayloadError::InvalidSignature)));
        }

        let with_unknown = encoded.trim_end_matches('}').to_owned() + ",\"extra\":1}";
        assert!(matches!(
            SignedPayload::from_json(&with_unknown),
            Err(PayloadError::Json(_))
        ));
    }

    #[test]
    fn ntfy_signed_wire_bytes_match_the_pre_refactor_vector() {
        // Generated with the original implementation before migration, using
        // only synthetic keys and the same record as `signed(100)`.
        const EXPECTED: &str = r#"{"version":1,"kind":"request","request_id":"12121212121212121212121212121212","record_body":"4c5a010144444444444444444444444444444444ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca0000000000000064000001a3185c5000000001a3186577c0919191919191919191919191919191910000000000000001010008080808c3500000","signature":"1c2a9271c7b2eb7092fdfaef0e44ad4a853c5d4eaca3b47f2a81211247f25d573e00877f09b7009c1befee3c73ff1e94cb0068299ce3795297ce2b2a48a5970d"}"#;
        let (payload, _, _) = signed(100);
        assert_eq!(payload.to_json().unwrap(), EXPECTED);
        assert_eq!(SignedPayload::from_json(EXPECTED).unwrap(), payload);
    }

    #[test]
    fn relationship_receiver_and_signer_are_checked() {
        let temp = TempDir::new().unwrap();
        let sender = key(7);
        let receiver = key(8);
        let other = key(9);
        let request_id = RequestId::from_bytes([0x20; 16]);

        assert!(matches!(
            SignedPayload::sign(
                MessageKind::Request,
                request_id,
                &record(&sender, &receiver, 1),
                &other
            ),
            Err(PayloadError::WrongSigningKey)
        ));

        let mut wrong_relationship = record(&sender, &receiver, 1);
        wrong_relationship.relationship_id = RelationshipId::from_bytes([0x45; 16]);
        let payload = SignedPayload::sign(
            MessageKind::Request,
            request_id,
            &wrong_relationship,
            &sender,
        )
        .unwrap();
        assert!(matches!(
            payload.verify_cached(&policy(&sender, &receiver), &mut cache(&temp, "rel.json")),
            Err(PayloadError::PeerRecord(
                PeerRecordReject::WrongRelationship { .. }
            ))
        ));

        let wrong_receiver = record(&sender, &other, 2);
        let payload = SignedPayload::sign(
            MessageKind::Request,
            RequestId::from_bytes([0x21; 16]),
            &wrong_receiver,
            &sender,
        )
        .unwrap();
        assert!(matches!(
            payload.verify_cached(
                &policy(&sender, &receiver),
                &mut cache(&temp, "receiver.json")
            ),
            Err(PayloadError::PeerRecord(
                PeerRecordReject::WrongReceiver { .. }
            ))
        ));

        let mut expired = record(&sender, &receiver, 3);
        expired.issued_at_unix_ms = NOW - 600_000;
        expired.expires_at_unix_ms = NOW;
        let payload = SignedPayload::sign(
            MessageKind::Request,
            RequestId::from_bytes([0x22; 16]),
            &expired,
            &sender,
        )
        .unwrap();
        assert!(matches!(
            payload.verify_cached(
                &policy(&sender, &receiver),
                &mut cache(&temp, "expired.json")
            ),
            Err(PayloadError::PeerRecord(PeerRecordReject::Expired { .. }))
        ));
    }

    #[test]
    fn replay_is_idempotent_and_same_sequence_equivocation_fails() {
        let temp = TempDir::new().unwrap();
        let (payload, sender, receiver) = signed(500);
        let mut cache = cache(&temp, "peer.json");
        let first = payload
            .verify_cached(&policy(&sender, &receiver), &mut cache)
            .unwrap();
        assert_eq!(first.accept_outcome, AcceptOutcome::Accepted);
        let second = payload
            .verify_cached(&policy(&sender, &receiver), &mut cache)
            .unwrap();
        assert_eq!(second.accept_outcome, AcceptOutcome::Idempotent);

        let mut alternate_hex = payload.clone();
        alternate_hex.record_body = alternate_hex.record_body.to_uppercase();
        alternate_hex.signature = alternate_hex.signature.to_uppercase();
        let third = alternate_hex
            .verify_cached(&policy(&sender, &receiver), &mut cache)
            .unwrap();
        assert_eq!(third.accept_outcome, AcceptOutcome::Idempotent);

        let equivocation = SignedPayload::sign(
            MessageKind::Reply,
            RequestId::from_bytes([0x99; 16]),
            &record(&sender, &receiver, 500),
            &sender,
        )
        .unwrap();
        assert!(matches!(
            equivocation.verify_cached(&policy(&sender, &receiver), &mut cache),
            Err(PayloadError::PeerRecord(PeerRecordReject::Equivocation {
                seq: 500
            }))
        ));

        let rollback = SignedPayload::sign(
            MessageKind::Request,
            RequestId::from_bytes([0x88; 16]),
            &record(&sender, &receiver, 499),
            &sender,
        )
        .unwrap();
        assert!(matches!(
            rollback.verify_cached(&policy(&sender, &receiver), &mut cache),
            Err(PayloadError::PeerRecord(PeerRecordReject::Rollback { .. }))
        ));
    }
}
