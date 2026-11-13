//! Identity material that is safe to print, log and publish.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// An Ed25519 public key used to identify a paired discovery endpoint.
///
/// Rendered as z-base-32, preserving the existing identity text representation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DiscoveryPublicKey([u8; 32]);

/// A random 128-bit identifier for one process start.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BootId([u8; 16]);

/// A random 128-bit identifier for one paired relationship.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelationshipId([u8; 16]);

macro_rules! fixed_bytes {
    ($name:ident, $len:expr, $zbase:expr) => {
        impl $name {
            /// Wrap raw bytes.
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// Borrow the raw bytes.
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            /// Lowercase hex, no separators.
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }

            /// Parse from lowercase or uppercase hex of exactly the right length.
            pub fn from_hex(s: &str) -> Result<Self, IdentityError> {
                if s.len() != $len * 2 {
                    return Err(IdentityError::BadLength {
                        expected: $len * 2,
                        got: s.len(),
                    });
                }
                let raw = hex::decode(s).map_err(|_| IdentityError::NotHex)?;
                let mut out = [0u8; $len];
                out.copy_from_slice(&raw);
                Ok(Self(out))
            }

            /// Generate a fresh random value from the OS CSPRNG.
            pub fn random() -> Result<Self, IdentityError> {
                let mut out = [0u8; $len];
                getrandom::fill(&mut out).map_err(|_| IdentityError::NoRandomness)?;
                Ok(Self(out))
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

fixed_bytes!(DiscoveryPublicKey, 32, true);
fixed_bytes!(BootId, 16, false);
fixed_bytes!(RelationshipId, 16, false);

impl DiscoveryPublicKey {
    /// z-base-32 text form used by existing identity and pairing files.
    pub fn to_z_base32(&self) -> String {
        base32::encode(base32::Alphabet::Z, &self.0)
    }

    /// Parse z-base-32. Case-sensitive: the z-base-32 alphabet is lowercase.
    pub fn from_z_base32(s: &str) -> Result<Self, IdentityError> {
        if s.len() != 52 {
            return Err(IdentityError::BadLength {
                expected: 52,
                got: s.len(),
            });
        }
        let raw = base32::decode(base32::Alphabet::Z, s).ok_or(IdentityError::NotZBase32)?;
        if raw.len() != 32 {
            return Err(IdentityError::BadLength {
                expected: 32,
                got: raw.len(),
            });
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        Ok(Self(out))
    }

    /// Short, human-comparable prefix. Display aid only: it is a truncation,
    /// not a hash, so it is NOT collision resistant.
    pub fn short_id(&self) -> String {
        self.to_z_base32()[..8].to_owned()
    }
}

impl fmt::Display for DiscoveryPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_z_base32())
    }
}

impl fmt::Display for BootId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Display for RelationshipId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for DiscoveryPublicKey {
    type Err = IdentityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() == 52 {
            Self::from_z_base32(s)
        } else {
            Self::from_hex(s)
        }
    }
}

impl FromStr for BootId {
    type Err = IdentityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl FromStr for RelationshipId {
    type Err = IdentityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

/// Why an identity value could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// Wrong number of characters or bytes.
    #[error("expected {expected} characters, got {got}")]
    BadLength {
        /// Required length.
        expected: usize,
        /// Supplied length.
        got: usize,
    },
    /// Not valid hex.
    #[error("not valid hex")]
    NotHex,
    /// Not valid z-base-32.
    #[error("not valid z-base-32")]
    NotZBase32,
    /// The OS random source failed.
    #[error("operating system randomness unavailable")]
    NoRandomness,
}

/// Canonical role assignment for one relationship.
///
/// Both sides compute this identically from the two pinned public keys, with no
/// negotiation and no reliance on clocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Roles {
    /// Lexicographically smaller public key.
    pub lo: DiscoveryPublicKey,
    /// Lexicographically larger public key.
    pub hi: DiscoveryPublicKey,
}

/// Which side of the relationship a local key is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Holder of `lo`. Sends HELLO.
    Initiator,
    /// Holder of `hi`. Sends PROBE and CHALLENGE.
    Responder,
}

impl Roles {
    /// Order the two pinned keys.
    pub fn new(a: DiscoveryPublicKey, b: DiscoveryPublicKey) -> Result<Self, IdentityError> {
        if a == b {
            return Err(IdentityError::BadLength {
                expected: 2,
                got: 1,
            });
        }
        Ok(if a < b {
            Self { lo: a, hi: b }
        } else {
            Self { lo: b, hi: a }
        })
    }

    /// Which role `me` plays.
    pub fn role_of(&self, me: DiscoveryPublicKey) -> Option<Role> {
        if me == self.lo {
            Some(Role::Initiator)
        } else if me == self.hi {
            Some(Role::Responder)
        } else {
            None
        }
    }
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

    #[test]
    fn z_base32_matches_the_fixture_vectors() {
        let zero = DiscoveryPublicKey::from_bytes([0u8; 32]);
        assert_eq!(zero.to_z_base32(), "y".repeat(52));
        let s = DiscoveryPublicKey::from_bytes(seq(0));
        assert_eq!(
            s.to_z_base32(),
            "yyyoryarywdyqnyjbefoadeqbhebnrounoktcfaadrpbs8y7daxo"
        );
    }

    #[test]
    fn z_base32_round_trips_and_is_case_sensitive() {
        let key = DiscoveryPublicKey::from_bytes(seq(0x20));
        let text = key.to_z_base32();
        assert_eq!(text.len(), 52);
        assert_eq!(DiscoveryPublicKey::from_z_base32(&text).unwrap(), key);
        assert_eq!(text.parse::<DiscoveryPublicKey>().unwrap(), key);
        assert!(DiscoveryPublicKey::from_z_base32(&text.to_uppercase()).is_err());
    }

    #[test]
    fn hex_form_is_also_accepted() {
        let key = DiscoveryPublicKey::from_bytes(seq(0xa0));
        let text = key.to_hex();
        assert_eq!(text.parse::<DiscoveryPublicKey>().unwrap(), key);
        assert_eq!(
            text.to_uppercase().parse::<DiscoveryPublicKey>().unwrap(),
            key
        );
    }

    #[test]
    fn wrong_lengths_are_rejected() {
        assert!("".parse::<DiscoveryPublicKey>().is_err());
        assert!("abcd".parse::<DiscoveryPublicKey>().is_err());
        assert!("00".repeat(31).parse::<DiscoveryPublicKey>().is_err());
        assert!("zz".repeat(52).parse::<DiscoveryPublicKey>().is_err());
        assert!("00".repeat(15).parse::<BootId>().is_err());
    }

    #[test]
    fn serde_uses_the_canonical_text_form() {
        let key = DiscoveryPublicKey::from_bytes(seq(1));
        let json = serde_json::to_string(&key).unwrap();
        assert_eq!(json, format!("\"{}\"", key.to_z_base32()));
        assert_eq!(
            serde_json::from_str::<DiscoveryPublicKey>(&json).unwrap(),
            key
        );
    }

    #[test]
    fn roles_are_canonical_and_agree_on_both_sides() {
        let a = DiscoveryPublicKey::from_bytes(seq(0x00));
        let b = DiscoveryPublicKey::from_bytes(seq(0x20));
        let from_a = Roles::new(a, b).unwrap();
        let from_b = Roles::new(b, a).unwrap();
        assert_eq!(from_a, from_b);
        assert_eq!(from_a.lo, a);
        assert_eq!(from_a.hi, b);
        assert_eq!(from_a.role_of(a), Some(Role::Initiator));
        assert_eq!(from_a.role_of(b), Some(Role::Responder));
        let stranger = DiscoveryPublicKey::from_bytes(seq(0x40));
        assert_eq!(from_a.role_of(stranger), None);
    }

    #[test]
    fn a_relationship_cannot_pair_a_key_with_itself() {
        let a = DiscoveryPublicKey::from_bytes(seq(7));
        assert!(Roles::new(a, a).is_err());
    }

    #[test]
    fn ordering_is_by_raw_bytes() {
        let a = DiscoveryPublicKey::from_bytes(seq(0x00));
        let b = DiscoveryPublicKey::from_bytes(seq(0x20));
        assert!(a < b);
        let mut high_first = [0xffu8; 32];
        high_first[31] = 0x00;
        let mut low_first = [0x00u8; 32];
        low_first[31] = 0xff;
        assert!(low_first < high_first);
    }

    #[test]
    fn boot_and_relationship_ids_round_trip() {
        let boot = BootId::from_bytes(seq(0x80)[..16].try_into().unwrap());
        assert_eq!(boot.to_hex().parse::<BootId>().unwrap(), boot);
        let rel = RelationshipId::from_bytes(seq(0x90)[..16].try_into().unwrap());
        assert_eq!(rel.to_hex().parse::<RelationshipId>().unwrap(), rel);
        assert_eq!(rel.to_hex().len(), 32);
    }

    #[test]
    fn short_id_is_a_prefix_not_a_hash() {
        let key = DiscoveryPublicKey::from_bytes(seq(3));
        assert_eq!(key.short_id(), key.to_z_base32()[..8]);
        assert_eq!(key.short_id().len(), 8);
    }
}
