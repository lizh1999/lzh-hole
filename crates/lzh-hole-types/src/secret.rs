//! A deliberately small, redacted 256-bit secret container.

use std::fmt;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// A 256-bit secret. It implements neither `Serialize` nor `Deserialize`.
///
/// Cloning is explicit, byte access is named for review, and the owned buffer
/// is cleared with `zeroize` on drop.
#[derive(Clone)]
pub struct Secret32([u8; 32]);

impl Secret32 {
    /// Wrap raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes. Named to make every use site obvious in review.
    pub fn expose_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parse exactly 64 hexadecimal characters.
    pub fn from_hex(text: &str) -> Result<Self, SecretError> {
        if text.len() != 64 {
            return Err(SecretError::BadEncoding);
        }
        let raw = hex::decode(text).map_err(|_| SecretError::BadEncoding)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        Ok(Self(out))
    }

    /// Generate fresh secret material from the operating system CSPRNG.
    pub fn random() -> Result<Self, SecretError> {
        let mut out = [0u8; 32];
        getrandom::fill(&mut out).map_err(|_| SecretError::NoRandomness)?;
        Ok(Self(out))
    }
}

impl fmt::Debug for Secret32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret32(<redacted>)")
    }
}

impl fmt::Display for Secret32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl PartialEq for Secret32 {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for Secret32 {}

impl Drop for Secret32 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Secret parsing or random-generation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SecretError {
    /// Content was not exactly 32 bytes encoded as 64 hex characters.
    #[error("secret file content is not 64 hex characters")]
    BadEncoding,
    /// The operating system random source failed.
    #[error("operating system randomness unavailable")]
    NoRandomness,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_is_redacted_and_constant_time_comparable() {
        let a = Secret32::from_bytes([0xab; 32]);
        let mut changed = [0xab; 32];
        changed[31] ^= 1;
        let b = Secret32::from_bytes(changed);
        assert_eq!(a, a.clone());
        assert_ne!(a, b);
        assert_eq!(format!("{a:?}"), "Secret32(<redacted>)");
        assert_eq!(format!("{a}"), "<redacted>");
    }

    #[test]
    fn strict_hex_round_trip() {
        let value = Secret32::from_bytes([0x5a; 32]);
        let hex = hex::encode(value.expose_bytes());
        assert_eq!(Secret32::from_hex(&hex).unwrap(), value);
        assert!(Secret32::from_hex("5a").is_err());
        assert!(Secret32::from_hex(&"z".repeat(64)).is_err());
    }
}
