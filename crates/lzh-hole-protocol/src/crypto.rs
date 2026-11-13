//! Key derivation and frame authentication.
//!
//! Every label in this module is part of the wire v1 contract
//! (doc/protocol.md) and is pinned by `tests/fixtures/wire-v1.json`. Changing
//! one changes every derived key and therefore every test vector.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Domain separation label for the HELLO MAC key.
pub const LABEL_KDF_HELLO: &[u8] = b"lzh-hole/v1/kdf/hello";
/// Domain separation label for the CHALLENGE MAC key.
pub const LABEL_KDF_CHALLENGE: &[u8] = b"lzh-hole/v1/kdf/challenge";
/// Domain separation label for the FINISH MAC key.
pub const LABEL_KDF_FINISH: &[u8] = b"lzh-hole/v1/kdf/finish";
/// Domain separation label for the session identifier.
pub const LABEL_KDF_SESSION_ID: &[u8] = b"lzh-hole/v1/kdf/session-id";
/// Domain separation label for the lo->hi session key.
pub const LABEL_KDF_KEY_I2R: &[u8] = b"lzh-hole/v1/kdf/key/i2r";
/// Domain separation label for the hi->lo session key.
pub const LABEL_KDF_KEY_R2I: &[u8] = b"lzh-hole/v1/kdf/key/r2i";
/// Domain separation label for the static PROBE key.
pub const LABEL_KDF_PROBE: &[u8] = b"lzh-hole/v1/kdf/probe";
/// Prefix for every transcript hash.
pub const LABEL_TRANSCRIPT: &[u8] = b"lzh-hole/v1/transcript";
/// Prefix for every frame MAC input.
pub const LABEL_FRAME_MAC: &[u8] = b"lzh-hole/v1/frame-mac";

/// A 32-byte symmetric key. Not printable, not serialisable.
#[derive(Clone)]
pub struct Key32([u8; 32]);

impl Key32 {
    /// Wrap raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for Key32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key32(<redacted>)")
    }
}

impl Drop for Key32 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The root pseudo-random key for one relationship.
#[derive(Clone, Debug)]
pub struct Prk(Key32);

/// Compute `PRK = HKDF-Extract(salt = relationship_id, ikm = psk)`.
pub fn extract_prk(relationship_id: &[u8; 16], psk: &[u8; 32]) -> Prk {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(relationship_id), psk);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    Prk(Key32(out))
}

impl Prk {
    /// Raw PRK bytes, for cross-checking against the fixture.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// `HKDF-Expand(PRK, info, 32)`.
    pub fn expand32(&self, info: &[u8]) -> Key32 {
        let hk = Hkdf::<Sha256>::from_prk(self.0.as_bytes()).expect("32-byte PRK is valid");
        let mut out = [0u8; 32];
        hk.expand(info, &mut out)
            .expect("32 bytes is a valid length");
        Key32(out)
    }

    /// `HKDF-Expand(PRK, info, 8)`.
    pub fn expand8(&self, info: &[u8]) -> [u8; 8] {
        let hk = Hkdf::<Sha256>::from_prk(self.0.as_bytes()).expect("32-byte PRK is valid");
        let mut out = [0u8; 8];
        hk.expand(info, &mut out)
            .expect("8 bytes is a valid length");
        out
    }

    /// The static PROBE key. Derivable by both sides from pinned keys alone.
    pub fn probe_key(&self, lo: &[u8; 32], hi: &[u8; 32]) -> Key32 {
        let mut info = Vec::with_capacity(LABEL_KDF_PROBE.len() + 64);
        info.extend_from_slice(LABEL_KDF_PROBE);
        info.extend_from_slice(lo);
        info.extend_from_slice(hi);
        self.expand32(&info)
    }
}

/// Build a KDF info string: label followed by context parts, no separators.
pub fn info(label: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(label.len() + parts.iter().map(|p| p.len()).sum::<usize>());
    out.extend_from_slice(label);
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

/// `SHA256(LABEL_TRANSCRIPT || frames...)`.
pub fn transcript_hash(frames: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LABEL_TRANSCRIPT);
    for frame in frames {
        hasher.update(frame);
    }
    hasher.finalize().into()
}

/// `HMAC-SHA256(key, LABEL_FRAME_MAC || header || payload)`.
pub fn frame_mac(key: &Key32, header: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes())
        .expect("HMAC accepts keys of any length");
    mac.update(LABEL_FRAME_MAC);
    mac.update(header);
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

/// Verify a frame MAC in constant time.
pub fn verify_frame_mac(key: &Key32, header: &[u8], payload: &[u8], tag: &[u8]) -> bool {
    if tag.len() != 32 {
        return false;
    }
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes())
        .expect("HMAC accepts keys of any length");
    mac.update(LABEL_FRAME_MAC);
    mac.update(header);
    mac.update(payload);
    mac.verify_slice(tag).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seq(start: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = start.wrapping_add(i as u8);
        }
        out
    }

    fn fixture_prk() -> Prk {
        let rel: [u8; 16] = (0..16).collect::<Vec<u8>>().try_into().unwrap();
        extract_prk(&rel, &seq(0xa0))
    }

    #[test]
    fn prk_matches_the_fixture() {
        assert_eq!(
            hex::encode(fixture_prk().as_bytes()),
            "bfdaac2e77dc72b68b1c7bafa327f731ed72ebc40376bc6a9f4d9ac0a23ce407"
        );
    }

    #[test]
    fn hello_and_probe_keys_match_the_fixture() {
        let prk = fixture_prk();
        let lo = seq(0x00);
        let hi = seq(0x20);
        let ni = seq(0x40);
        let k_hello = prk.expand32(&info(LABEL_KDF_HELLO, &[&lo, &hi, &ni]));
        assert_eq!(
            hex::encode(k_hello.as_bytes()),
            "e9b27cfd0f37cb93684023b849a541348817dcc151652dea0e9106a234dac730"
        );
        let k_probe = prk.probe_key(&lo, &hi);
        assert_eq!(
            hex::encode(k_probe.as_bytes()),
            "e8fe0a6209c0d4b90e535c9d4fa5b08757507554e3cda7e5986e814d772b2cd2"
        );
    }

    #[test]
    fn session_id_expansion_is_eight_bytes() {
        let prk = fixture_prk();
        let out = prk.expand8(b"test");
        assert_eq!(out.len(), 8);
        // Same info must give the same 8 bytes as the first 8 of a 32-byte expand.
        let wide = prk.expand32(b"test");
        assert_eq!(&out[..], &wide.as_bytes()[..8]);
    }

    #[test]
    fn mac_covers_header_and_payload() {
        let key = Key32::from_bytes(seq(1));
        let header = [1u8; 42];
        let payload = [2u8; 16];
        let tag = frame_mac(&key, &header, &payload);
        assert!(verify_frame_mac(&key, &header, &payload, &tag));

        let mut flipped = header;
        flipped[6] ^= 1;
        assert!(!verify_frame_mac(&key, &flipped, &payload, &tag));
        assert_ne!(frame_mac(&key, &flipped, &payload), tag);

        let mut flipped_payload = payload;
        flipped_payload[0] ^= 1;
        assert!(!verify_frame_mac(&key, &header, &flipped_payload, &tag));
    }

    #[test]
    fn mac_rejects_wrong_key_and_wrong_tag_length() {
        let key = Key32::from_bytes(seq(1));
        let other = Key32::from_bytes(seq(2));
        let header = [1u8; 42];
        let payload = [2u8; 16];
        let tag = frame_mac(&key, &header, &payload);
        assert!(!verify_frame_mac(&other, &header, &payload, &tag));
        assert!(!verify_frame_mac(&key, &header, &payload, &tag[..31]));
        assert!(!verify_frame_mac(&key, &header, &payload, &[]));
    }

    #[test]
    fn transcript_hash_is_labelled_ordered_and_deterministic() {
        let a = [1u8; 8];
        let b = [2u8; 8];
        let joined = transcript_hash(&[&a, &b]);
        assert_eq!(joined, transcript_hash(&[&a, &b]));

        // The documented definition: SHA256(label || frame1 || frame2).
        let mut expected = Sha256::new();
        expected.update(LABEL_TRANSCRIPT);
        expected.update(a);
        expected.update(b);
        assert_eq!(joined, <[u8; 32]>::from(expected.finalize()));

        // Order and frame count both matter.
        assert_ne!(joined, transcript_hash(&[&b, &a]));
        assert_ne!(joined, transcript_hash(&[&a]));
        assert_ne!(joined, transcript_hash(&[]));

        // The label really is part of the input.
        let mut unlabelled = Sha256::new();
        unlabelled.update(a);
        unlabelled.update(b);
        assert_ne!(joined, <[u8; 32]>::from(unlabelled.finalize()));
    }

    #[test]
    fn keys_are_redacted_in_debug_output() {
        let key = Key32::from_bytes([0xab; 32]);
        assert_eq!(format!("{key:?}"), "Key32(<redacted>)");
        assert!(!format!("{key:?}").contains("ab"));
    }

    #[test]
    fn labels_are_exactly_as_specified() {
        assert_eq!(LABEL_KDF_HELLO, b"lzh-hole/v1/kdf/hello");
        assert_eq!(LABEL_KDF_CHALLENGE, b"lzh-hole/v1/kdf/challenge");
        assert_eq!(LABEL_KDF_FINISH, b"lzh-hole/v1/kdf/finish");
        assert_eq!(LABEL_KDF_SESSION_ID, b"lzh-hole/v1/kdf/session-id");
        assert_eq!(LABEL_KDF_KEY_I2R, b"lzh-hole/v1/kdf/key/i2r");
        assert_eq!(LABEL_KDF_KEY_R2I, b"lzh-hole/v1/kdf/key/r2i");
        assert_eq!(LABEL_KDF_PROBE, b"lzh-hole/v1/kdf/probe");
        assert_eq!(LABEL_TRANSCRIPT, b"lzh-hole/v1/transcript");
        assert_eq!(LABEL_FRAME_MAC, b"lzh-hole/v1/frame-mac");
    }
}
