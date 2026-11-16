use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use lzh_hole_store::{PAIRING_VERSION, Relationship, Role, Secret32, StateDir, public_key_of_seed};
use lzh_hole_types::{DiscoveryPublicKey, RelationshipId};

use super::*;
use crate::{FileNtfyConfig, LanConfig};

/// One overlay address per node, identical in every relationship.
const SELF_VIP: &str = "10.203.0.1";
const LOCAL_SEED: [u8; 32] = [7; 32];

struct Fixture {
    _temp: tempfile::TempDir,
    config: ServiceConfig,
    path: PathBuf,
    relationships: Vec<Relationship>,
}

impl Fixture {
    fn new() -> Self {
        Self::with_peers(2)
    }

    /// Build a node holding `count` finalised relationships to distinct peers,
    /// all sharing one identity and one overlay address.
    fn with_peers(count: usize) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let state = StateDir::open(&temp.path().join("state")).unwrap();
        state.store_seed(&LOCAL_SEED).unwrap();
        let mut relationships = Vec::with_capacity(count);
        for index in 0..count {
            let byte = u8::try_from(index).expect("peer index fits a byte");
            let relationship = Relationship {
                pairing_version: PAIRING_VERSION,
                pairing_id: RelationshipId::from_bytes([0x10 + byte; 16]),
                relationship_id: RelationshipId::from_bytes([0x20 + byte; 16]),
                self_public_key: public_key_of_seed(&LOCAL_SEED),
                peer_public_key: DiscoveryPublicKey::from_bytes([0x40 + byte; 32]),
                role: Role::Initiator,
                self_vip: SELF_VIP.to_owned(),
                peer_vip: format!("10.203.0.{}", 2 + index),
                finalised_unix_ms: 1,
            };
            state
                .finalise(&relationship, &Secret32::from_bytes([0x5a + byte; 32]))
                .unwrap();
            relationships.push(relationship);
        }
        let config = ServiceConfig {
            state_dir: state.path().into(),
            control_socket: temp.path().join("control/control.sock"),
            management_uid: fs::metadata(temp.path()).unwrap().uid(),
            interface: None,
            bind_ip: None,
            udp_port: 51000,
            stun_seeds: vec!["8.8.8.8:3478".parse().unwrap()],
            ntfy: FileNtfyConfig {
                base_url: "https://ntfy.sh".into(),
                resolve_ip: None,
                dns_server: None,
            },
            lan: LanConfig::default(),
            mtu: 1200,
            punch: crate::config::PunchConfig::default(),
        };
        let path = temp.path().join("config.toml");
        let this = Self {
            _temp: temp,
            config,
            path,
            relationships,
        };
        this.save();
        this
    }

    fn state(&self) -> StateDir {
        StateDir::open_existing(&self.config.state_dir).unwrap()
    }

    fn save(&self) {
        fs::write(&self.path, toml::to_string(&self.config).unwrap()).unwrap();
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// Every file and directory below the state directory, with its mode.
    ///
    /// Recursive on purpose: the relationship layout nests one directory per
    /// relationship, so a flat listing would miss exactly the files a
    /// read-only preflight must not touch.
    fn snapshot(&self) -> Vec<(PathBuf, bool, u32, Vec<u8>)> {
        let mut out = Vec::new();
        collect(&self.config.state_dir, &mut out);
        out.sort();
        out
    }
}

fn collect(dir: &Path, out: &mut Vec<(PathBuf, bool, u32, Vec<u8>)>) {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    paths.sort();
    for path in paths {
        let metadata = fs::symlink_metadata(&path).unwrap();
        let mode = metadata.mode();
        if metadata.is_dir() {
            out.push((path.clone(), true, mode, Vec::new()));
            collect(&path, out);
        } else {
            out.push((path.clone(), false, mode, fs::read(&path).unwrap()));
        }
    }
}

#[test]
fn preflight_reports_every_peer_and_stays_read_only() {
    let f = Fixture::new();
    let state = f.state();
    let _writer = state.lock_publisher().unwrap();
    fs::write(
        state.file("ntfy-pacing.json"),
        b"synthetic pacing, do not touch",
    )
    .unwrap();
    let before = f.snapshot();
    let result = install_preflight(&f.path).unwrap();

    assert_eq!(result.self_vip.to_string(), SELF_VIP);
    assert_eq!(result.state_dir, f.config.state_dir);
    assert_eq!(result.peers.len(), 2);
    let vips: Vec<String> = result
        .peers
        .iter()
        .map(|peer| peer.peer_vip.to_string())
        .collect();
    assert_eq!(vips, vec!["10.203.0.2".to_owned(), "10.203.0.3".to_owned()]);
    for (peer, relationship) in result.peers.iter().zip(&f.relationships) {
        assert_eq!(peer.relationship_id, relationship.relationship_id.to_hex());
        assert_eq!(
            peer.peer_key,
            relationship.peer_public_key.to_string(),
            "the pinned peer key must be reported verbatim"
        );
    }

    assert_eq!(before, f.snapshot());
    let json = serde_json::to_string(&result).unwrap();
    assert!(
        !json.contains("psk"),
        "preflight output must not name a PSK"
    );
    assert!(
        !json.contains("seed"),
        "preflight output must not name a seed"
    );
    // The fixture PSKs are 0x5a and 0x5b repeated; neither may appear as hex.
    assert!(!json.contains("5a5a5a5a"));
    assert!(!json.contains("5b5b5b5b"));
    assert!(!f.config.control_socket.parent().unwrap().exists());
}

#[test]
fn a_single_peer_node_still_reports_one_route() {
    let f = Fixture::with_peers(1);
    let result = install_preflight(&f.path).unwrap();
    assert_eq!(result.peers.len(), 1);
    assert_eq!(result.peers[0].peer_vip.to_string(), "10.203.0.2");
}

#[test]
fn missing_state_is_not_created() {
    let mut f = Fixture::new();
    f.config.state_dir = f._temp.path().join("missing");
    f.save();
    assert!(install_preflight(&f.path).is_err());
    assert!(!f.config.state_dir.exists());
}

#[test]
fn an_identity_that_disagrees_with_a_relationship_is_rejected_without_writing() {
    let f = Fixture::new();
    let seed_path = f.config.state_dir.join(lzh_hole_store::IDENTITY_FILE);
    fs::remove_file(&seed_path).unwrap();
    f.state().store_seed(&[8; 32]).unwrap();
    let before = f.snapshot();
    assert!(install_preflight(&f.path).is_err());
    assert_eq!(before, f.snapshot());
}

#[test]
fn a_broken_psk_in_any_relationship_is_rejected() {
    // The second relationship, not the first: preflight must check every
    // relationship, otherwise a mesh node silently starts with one peer it can
    // never authenticate.
    let f = Fixture::new();
    let second = f.relationships[1].relationship_id;
    let path = f
        .state()
        .relationship_dir(second)
        .join(lzh_hole_store::PSK_FILE);
    fs::write(&path, b"invalid synthetic fixture").unwrap();
    assert!(install_preflight(&f.path).is_err());
}

#[test]
fn rejects_unsafe_permissions() {
    let f = Fixture::new();
    fs::set_permissions(&f.path, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(install_preflight(&f.path).is_err());

    let f = Fixture::new();
    fs::set_permissions(&f.config.state_dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(install_preflight(&f.path).is_err());
}

#[test]
fn a_configured_topic_is_refused_outright() {
    // `NtfyConfig` denies unknown fields, so a stale single-peer config that
    // still pins a topic fails to load instead of silently coordinating on a
    // topic the daemon would never derive.
    let f = Fixture::new();
    let text = toml::to_string(&f.config).unwrap();
    let mut lines: Vec<String> = Vec::new();
    let mut injected = false;
    for line in text.lines() {
        lines.push(line.to_owned());
        if line.trim() == "[ntfy]" {
            lines.push("topic = \"lzh-hole-v1-00112233445566778899aabbccddeeff\"".to_owned());
            injected = true;
        }
    }
    assert!(injected, "the serialized config has no [ntfy] table");
    fs::write(&f.path, lines.join("\n")).unwrap();
    fs::set_permissions(&f.path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(install_preflight(&f.path).is_err());
}
