use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

use lzh_hole_store::{PAIRING_VERSION, Relationship, Role, Secret32, StateDir, public_key_of_seed};
use lzh_hole_types::{DiscoveryPublicKey, RelationshipId};

use super::*;
use crate::{FileNtfyConfig, LanConfig};

struct Fixture {
    _temp: tempfile::TempDir,
    config: ServiceConfig,
    path: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let state = StateDir::open(&temp.path().join("state")).unwrap();
        let seed = [7; 32];
        state.store_seed(&seed).unwrap();
        let relation = Relationship {
            pairing_version: PAIRING_VERSION,
            pairing_id: RelationshipId::from_bytes([1; 16]),
            relationship_id: RelationshipId::from_bytes([2; 16]),
            self_public_key: public_key_of_seed(&seed),
            peer_public_key: DiscoveryPublicKey::from_bytes([9; 32]),
            role: Role::Initiator,
            self_vip: "10.203.0.1".into(),
            peer_vip: "10.203.0.2".into(),
            finalised_unix_ms: 1,
        };
        state
            .finalise(&relation, &Secret32::from_bytes([0x5a; 32]))
            .unwrap();
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
                topic: topic_for_relationship(&relation.relationship_id),
                resolve_ip: None,
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
        };
        this.save();
        this
    }
    fn save(&self) {
        fs::write(&self.path, toml::to_string(&self.config).unwrap()).unwrap();
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn snapshot(&self) -> Vec<(PathBuf, Vec<u8>, u32)> {
        let mut paths = fs::read_dir(&self.config.state_dir)
            .unwrap()
            .map(|p| p.unwrap().path())
            .collect::<Vec<_>>();
        paths.sort();
        paths
            .into_iter()
            .map(|p| {
                let mode = fs::metadata(&p).unwrap().mode();
                let bytes = fs::read(&p).unwrap();
                (p, bytes, mode)
            })
            .collect()
    }
}

#[test]
fn preflight_is_read_only_even_with_active_publisher() {
    let f = Fixture::new();
    let state = StateDir::open_existing(&f.config.state_dir).unwrap();
    let _writer = state.lock_publisher().unwrap();
    fs::write(
        state.file("ntfy-pacing.json"),
        b"synthetic pacing, do not touch",
    )
    .unwrap();
    let before = f.snapshot();
    let result = install_preflight(&f.path).unwrap();
    assert_eq!(result.peer_vip.to_string(), "10.203.0.2");
    assert_eq!(result.state_dir, f.config.state_dir);
    assert_eq!(before, f.snapshot());
    let json = serde_json::to_string(&result).unwrap();
    assert!(!json.contains("psk"));
    assert!(!json.contains("seed"));
    assert!(!json.contains("relationship"));
    assert!(!f.config.control_socket.parent().unwrap().exists());
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
fn rejects_wrong_topic_or_identity_without_writing_state() {
    let mut f = Fixture::new();
    f.config.ntfy.topic = "lzh-hole-v1-00000000000000000000000000000000".into();
    f.save();
    let before = f.snapshot();
    assert!(install_preflight(&f.path).is_err());
    assert_eq!(before, f.snapshot());
    f.config.ntfy.topic = topic_for_relationship(&RelationshipId::from_bytes([2; 16]));
    f.save();
    let seed = f.config.state_dir.join(lzh_hole_store::IDENTITY_FILE);
    fs::remove_file(&seed).unwrap();
    StateDir::open_existing(&f.config.state_dir)
        .unwrap()
        .store_seed(&[8; 32])
        .unwrap();
    let before = f.snapshot();
    assert!(install_preflight(&f.path).is_err());
    assert_eq!(before, f.snapshot());
}

#[test]
fn rejects_bad_psk_and_unsafe_permissions() {
    let f = Fixture::new();
    fs::write(
        f.config.state_dir.join(lzh_hole_store::PSK_FILE),
        b"invalid synthetic fixture",
    )
    .unwrap();
    assert!(install_preflight(&f.path).is_err());
    let f = Fixture::new();
    fs::set_permissions(&f.path, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(install_preflight(&f.path).is_err());
    let f = Fixture::new();
    fs::set_permissions(&f.config.state_dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(install_preflight(&f.path).is_err());
}
