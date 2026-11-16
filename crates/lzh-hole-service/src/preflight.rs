//! Strictly read-only installation preflight: no locks, sequence reservation or network.
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use lzh_hole_discovery::{NtfyConfig, topic_for_relationship};
use lzh_hole_store::StateDir;
use serde::Serialize;

use crate::{ConfigError, ServiceConfig};

/// One pinned peer the installer may expect, without any secret material.
#[derive(Debug, Serialize)]
pub struct InstallPreflightPeer {
    /// Lowercase hex relationship id.
    pub relationship_id: String,
    /// The one /32 host route this peer may contribute.
    pub peer_vip: Ipv4Addr,
    /// The pinned peer discovery key, which is public.
    pub peer_key: String,
}

/// Only non-secret facts needed by the installer; never serializes a PSK.
#[derive(Debug, Serialize)]
pub struct InstallPreflight {
    /// Existing private state directory (not created by preflight).
    pub state_dir: PathBuf,
    /// Configured private control socket.
    pub control_socket: PathBuf,
    /// This node's single overlay address, identical in every relationship.
    pub self_vip: Ipv4Addr,
    /// Every pinned peer, in relationship-id order. One /32 host route each.
    pub peers: Vec<InstallPreflightPeer>,
}

/// Validate config, private files, pinned identity and every derived topic
/// without changing state.
///
/// Every relationship is checked, not just the first one: a mesh node whose
/// second relationship disagrees with its identity, or whose derived topic the
/// ntfy transport would refuse, must fail here rather than at daemon start.
pub fn install_preflight(path: &Path) -> Result<InstallPreflight, ConfigError> {
    let config = ServiceConfig::load(path)?;
    let state = StateDir::open_existing(&config.state_dir)?;
    let resolved = config.resolve(state.load_relationships()?)?;
    let self_key = state.public_key()?;
    if resolved
        .peers
        .iter()
        .any(|peer| peer.relationship.self_public_key != self_key)
    {
        return Err(ConfigError::Invalid(
            "identity does not match every finalized relationship".into(),
        ));
    }
    let mut peers = Vec::with_capacity(resolved.peers.len());
    for peer in &resolved.peers {
        let id = peer.relationship_id();
        // Read and immediately drop: this proves the 0600 PSK is present and
        // readable without letting it reach any output.
        drop(state.load_psk(id)?);
        // The topic is derived from the relationship, never configured, so the
        // only thing left to prove is that the transport accepts it.
        let topic = topic_for_relationship(&id);
        NtfyConfig::new(&resolved.config.ntfy.base_url, &topic).map_err(|error| {
            ConfigError::Invalid(format!(
                "ntfy coordination for relationship {} is unusable: {error}",
                id.to_hex()
            ))
        })?;
        peers.push(InstallPreflightPeer {
            relationship_id: id.to_hex(),
            peer_vip: peer.peer_vip,
            peer_key: peer.relationship.peer_public_key.to_string(),
        });
    }
    Ok(InstallPreflight {
        state_dir: resolved.config.state_dir,
        control_socket: resolved.config.control_socket,
        self_vip: resolved.self_vip,
        peers,
    })
}

#[cfg(test)]
mod tests;
