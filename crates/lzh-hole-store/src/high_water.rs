//! Durable peer high-water persistence, deliberately independent of record
//! decoding and validation. The caller commits only after discovery has
//! accepted a signed record, and commits before using its candidates.

use std::path::{Path, PathBuf};

use lzh_hole_types::{BootId, PeerRecordState};

use crate::secret::{read_private_bytes, write_private_bytes};

const MAX_HIGH_WATER_BYTES: u64 = 64 * 1024;

/// Persistent high-water load or commit failure.
#[derive(Debug, thiserror::Error)]
pub enum HighWaterError {
    /// The existing JSON or private file could not be read.
    #[error("peer record cache {path}: {detail}")]
    CacheIo {
        /// Offending path.
        path: PathBuf,
        /// Non-secret diagnostic.
        detail: String,
    },
}

fn io(path: &Path, detail: impl std::fmt::Display) -> HighWaterError {
    HighWaterError::CacheIo {
        path: path.to_path_buf(),
        detail: detail.to_string(),
    }
}

/// On-disk anti-rollback cache using the existing `peer-record.json` schema.
#[derive(Debug)]
pub struct PeerRecordCache {
    path: PathBuf,
    state: Option<PeerRecordState>,
}

impl PeerRecordCache {
    /// Open a cache and load any existing high-water state.
    pub fn load(path: &Path) -> Result<Self, HighWaterError> {
        let state = if path.exists() {
            let bytes =
                read_private_bytes(path, MAX_HIGH_WATER_BYTES).map_err(|error| io(path, error))?;
            let raw: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|error| io(path, error))?;
            let highest_seq = raw["highest_seq"]
                .as_u64()
                .ok_or_else(|| io(path, "missing highest_seq"))?;
            let accepted_bytes = hex::decode(raw["accepted_bytes"].as_str().unwrap_or_default())
                .map_err(|error| io(path, error))?;
            let boot_bytes = hex::decode(raw["boot_id"].as_str().unwrap_or_default())
                .map_err(|error| io(path, error))?;
            let boot_id: [u8; 16] = boot_bytes
                .try_into()
                .map_err(|_| io(path, "boot_id must contain exactly 16 bytes"))?;
            Some(PeerRecordState {
                highest_seq,
                accepted_bytes,
                boot_id: BootId::from_bytes(boot_id),
                generation: raw["generation"].as_u64().unwrap_or(0),
            })
        } else {
            None
        };
        Ok(Self {
            path: path.to_path_buf(),
            state,
        })
    }

    /// Current validated high-water state, if any.
    pub fn state(&self) -> Option<&PeerRecordState> {
        self.state.as_ref()
    }

    /// Highest accepted sequence, used when reserving a new local sequence.
    pub fn highest_seq(&self) -> Option<u64> {
        self.state.as_ref().map(|state| state.highest_seq)
    }

    /// Atomically persist a newly accepted state before the caller uses the
    /// corresponding candidates. Idempotent reads require no write.
    pub fn commit(&mut self, state: &PeerRecordState) -> Result<(), HighWaterError> {
        let body = serde_json::json!({
            "highest_seq": state.highest_seq,
            "accepted_bytes": hex::encode(&state.accepted_bytes),
            "boot_id": hex::encode(state.boot_id.as_bytes()),
            "generation": state.generation,
        });
        let text = serde_json::to_string_pretty(&body).map_err(|error| io(&self.path, error))?;
        write_private_bytes(&self.path, text.as_bytes()).map_err(|error| io(&self.path, error))?;
        self.state = Some(state.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::ensure_private_dir;

    #[test]
    fn existing_schema_round_trips_and_survives_reload() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("state");
        ensure_private_dir(&base).unwrap();
        let path = base.join("peer-record.json");
        let state = PeerRecordState {
            highest_seq: 1_800_000_000_000_000,
            accepted_bytes: b"canonical-public-transcript".to_vec(),
            boot_id: BootId::from_bytes([7; 16]),
            generation: 3,
        };
        let mut cache = PeerRecordCache::load(&path).unwrap();
        cache.commit(&state).unwrap();
        assert_eq!(cache.highest_seq(), Some(state.highest_seq));

        let cache = PeerRecordCache::load(&path).unwrap();
        assert_eq!(cache.state(), Some(&state));
        let text = std::fs::read_to_string(path).unwrap();
        let raw: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(raw.get("highest_seq").is_some());
        assert!(raw.get("accepted_bytes").is_some());
        assert!(raw.get("boot_id").is_some());
        assert!(raw.get("generation").is_some());
    }

    #[test]
    fn malformed_boot_id_does_not_silently_become_zero() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("state");
        ensure_private_dir(&base).unwrap();
        let path = base.join("peer-record.json");
        write_private_bytes(
            &path,
            br#"{"highest_seq":1,"accepted_bytes":"","boot_id":"00","generation":0}"#,
        )
        .unwrap();
        assert!(PeerRecordCache::load(&path).is_err());
    }
}
