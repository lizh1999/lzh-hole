//! Strictly read-only installation preflight: no locks, sequence reservation or network.
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use lzh_hole_discovery::topic_for_relationship;
use lzh_hole_store::StateDir;
use serde::Serialize;

use crate::{ConfigError, ServiceConfig};

/// Only non-secret facts needed by the installer; never serializes the relationship.
#[derive(Debug, Serialize)]
pub struct InstallPreflight {
    /// Existing private state directory (not created by preflight).
    pub state_dir: PathBuf,
    /// Configured private control socket.
    pub control_socket: PathBuf,
    /// Sole owned peer /32 route.
    pub peer_vip: Ipv4Addr,
}

/// Validate config, private files, pinned identity and topic without changing state.
pub fn install_preflight(path: &Path) -> Result<InstallPreflight, ConfigError> {
    let config = ServiceConfig::load(path)?;
    let state = StateDir::open_existing(&config.state_dir)?;
    let resolved = config.resolve(state.load_relationship()?)?;
    if state.public_key()? != resolved.relationship.self_public_key {
        return Err(ConfigError::Invalid(
            "identity does not match finalized pairing".into(),
        ));
    }
    drop(state.load_psk()?);
    if resolved.config.ntfy.topic != topic_for_relationship(&resolved.relationship.relationship_id)
    {
        return Err(ConfigError::Invalid(
            "ntfy topic does not match finalized pairing".into(),
        ));
    }
    Ok(InstallPreflight {
        state_dir: resolved.config.state_dir,
        control_socket: resolved.config.control_socket,
        peer_vip: resolved.peer_vip,
    })
}

#[cfg(test)]
mod tests;
