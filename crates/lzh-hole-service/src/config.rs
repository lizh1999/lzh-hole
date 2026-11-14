//! Explicit, non-secret service configuration.
//!
//! Virtual addresses and peer identity deliberately do not appear in the TOML
//! schema. They are loaded from the finalized pairing relationship so a second
//! configuration source cannot disagree with the authenticated pairing state.

use std::fs::OpenOptions;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use lzh_hole_discovery::candidate::{self, EndpointReject};
use lzh_hole_net::interface::is_tunnel_name;
use serde::{Deserialize, Serialize};

use lzh_hole_store::{PAIRING_VERSION, PairingError, Relationship, StateDir};

/// Conservative tunnel MTU. Larger values are refused by the service schema.
pub const DEFAULT_MTU: u16 = 1200;
/// IPv4's minimum reassembly size; lower configured MTUs are not useful here.
pub const MIN_MTU: u16 = 576;
/// Overlay routing is host-only. No LAN, default-route or other prefix is exposed.
pub const HOST_ROUTE_PREFIX_LEN: u8 = 32;
/// Largest accepted non-secret configuration file.
pub const MAX_CONFIG_BYTES: u64 = 64 * 1024;
/// macOS sockaddr_un.sun_path has 104 bytes including the trailing NUL.
pub const MAX_CONTROL_SOCKET_PATH_BYTES: usize = 103;

const MAX_STUN_SEEDS: usize = 8;
const MAX_NTFY_BASE_URL_LEN: usize = 2048;
const MIN_NTFY_TOPIC_LEN: usize = 16;
const MAX_NTFY_TOPIC_LEN: usize = 128;

fn default_mtu() -> u16 {
    DEFAULT_MTU
}

/// Local Bonjour discovery. It never publishes secrets or business packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LanConfig {
    /// Browse and advertise successfully bound physical UDP endpoints.
    #[serde(default = "default_lan_enabled")]
    pub enabled: bool,
}

fn default_lan_enabled() -> bool {
    true
}

impl Default for LanConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// ntfy coordination settings. The topic is not an authentication secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NtfyConfig {
    /// HTTPS origin and optional path prefix, without query or fragment.
    pub base_url: String,
    /// A long, unguessable topic containing only ASCII alphanumerics, '_' and '-'.
    pub topic: String,
    /// Optional public IPv4 resolve override that preserves the HTTPS hostname.
    #[serde(default)]
    pub resolve_ip: Option<Ipv4Addr>,
}

/// Largest permitted punch transmission rate.
pub const MAX_PUNCH_RATE_PER_SECOND: u32 = 1_000;
/// Default punch transmission rate. A real carrier NAT was measured dropping
/// confirmations at roughly 20k packets per second while 400 always got
/// through, so this is deliberately far below any line rate.
pub const DEFAULT_PUNCH_RATE_PER_SECOND: u32 = 400;

fn default_punch_enabled() -> bool {
    true
}

/// Hole-punch tuning. The whole section is optional so an existing
/// configuration file keeps working unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PunchConfig {
    /// Whether hole punching may run at all. Turning this off disables the
    /// whole feature without touching any other setting.
    #[serde(default = "default_punch_enabled")]
    pub enabled: bool,
    /// Punch frames per second, `1..=MAX_PUNCH_RATE_PER_SECOND`.
    #[serde(default)]
    pub rate_per_second: Option<u32>,
}

impl Default for PunchConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rate_per_second: None,
        }
    }
}

impl PunchConfig {
    /// Effective punch transmission rate.
    pub fn rate_per_second(&self) -> u32 {
        self.rate_per_second
            .unwrap_or(DEFAULT_PUNCH_RATE_PER_SECOND)
            .clamp(1, MAX_PUNCH_RATE_PER_SECOND)
    }
}

/// Validated daemon configuration. Secrets and paired addresses are excluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    /// Finalized identity/relationship directory, protected as mode 0700.
    pub state_dir: PathBuf,
    /// Unix control socket inside a dedicated mode-0700 directory.
    pub control_socket: PathBuf,
    /// UID allowed to use the control API. UID 0 is always allowed as well.
    pub management_uid: u32,
    /// Physical interface name. None asks the platform layer to select one.
    #[serde(default)]
    pub interface: Option<String>,
    /// Optional local IPv4 on the selected physical interface.
    #[serde(default)]
    pub bind_ip: Option<Ipv4Addr>,
    /// Fixed, non-zero local UDP port for the long-lived physical socket.
    pub udp_port: u16,
    /// Numeric public IPv4 STUN endpoints, not DNS names and never peer addresses.
    pub stun_seeds: Vec<SocketAddrV4>,
    /// ntfy carries bounded signed coordination records.
    pub ntfy: NtfyConfig,
    /// Independent LAN discovery, enabled for legacy configuration files too.
    #[serde(default)]
    pub lan: LanConfig,
    /// Tunnel MTU, conservatively capped at 1200.
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Hole-punch tuning. Absent sections keep the defaults.
    #[serde(default)]
    pub punch: PunchConfig,
}

/// Configuration joined with the one authoritative pairing relationship.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    /// Non-secret service settings.
    pub config: ServiceConfig,
    /// Authenticated public pairing metadata, without the relationship PSK.
    pub relationship: Relationship,
    /// Parsed local /32 virtual address from `relationship.self_vip`.
    pub self_vip: Ipv4Addr,
    /// Parsed peer /32 virtual address from `relationship.peer_vip`.
    pub peer_vip: Ipv4Addr,
}

impl ResolvedConfig {
    /// The only peer route the later tunnel integration may request.
    pub fn peer_host_route(&self) -> (Ipv4Addr, u8) {
        (self.peer_vip, HOST_ROUTE_PREFIX_LEN)
    }
}

/// Configuration loading or validation failure.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A configuration file could not be opened or read.
    #[error("configuration {path}: {source}")]
    Io {
        /// Offending path.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Configuration files must be regular, non-symlink and not group/world writable.
    #[error("configuration {path}: {detail}")]
    UnsafeFile {
        /// Offending path.
        path: PathBuf,
        /// Failed safety property.
        detail: String,
    },
    /// The bounded file reader stopped at the configured cap.
    #[error("configuration {path}: exceeds the 65536-byte cap")]
    TooLarge {
        /// Offending path.
        path: PathBuf,
    },
    /// TOML decoding failed, including unknown fields such as a PSK or VIP override.
    #[error("configuration {path}: invalid TOML: {detail}")]
    Parse {
        /// Offending path.
        path: PathBuf,
        /// Serde/TOML diagnostic.
        detail: String,
    },
    /// A standalone TOML string was invalid.
    #[error("invalid configuration: {0}")]
    Invalid(String),
    /// Pairing metadata was missing or unsafe.
    #[error(transparent)]
    Pairing(#[from] PairingError),
}

fn io(path: &Path, source: std::io::Error) -> ConfigError {
    ConfigError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

fn validate_absolute_path(path: &Path, field: &str) -> Result<(), ConfigError> {
    if !path.is_absolute() {
        return Err(invalid(format!("{field} must be an absolute path")));
    }
    if path == Path::new("/") {
        return Err(invalid(format!("{field} must not be the filesystem root")));
    }
    if path
        .as_os_str()
        .as_encoded_bytes()
        .split(|byte| *byte == b'/')
        .any(|component| component == b"." || component == b"..")
    {
        return Err(invalid(format!(
            "{field} must not contain '.' or '..' components"
        )));
    }
    Ok(())
}

fn validate_interface(interface: &str) -> Result<(), ConfigError> {
    if interface.is_empty()
        || interface.len() > 15
        || !interface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(invalid(
            "interface must be a short macOS interface name such as en0",
        ));
    }
    if is_tunnel_name(interface)
        || interface.starts_with("lo")
        || interface.starts_with("gif")
        || interface.starts_with("stf")
    {
        return Err(invalid(format!(
            "interface {interface:?} is not an allowed physical IPv4 interface"
        )));
    }
    Ok(())
}

fn validate_local_bind_ip(ip: Ipv4Addr) -> Result<(), ConfigError> {
    match candidate::classify(ip) {
        None | Some(EndpointReject::Private | EndpointReject::Cgnat) => Ok(()),
        Some(reason) => Err(invalid(format!(
            "bind_ip {ip} is not a usable physical-interface address: {reason}"
        ))),
    }
}

fn validate_ntfy(config: &NtfyConfig) -> Result<(), ConfigError> {
    if config.base_url.is_empty() || config.base_url.len() > MAX_NTFY_BASE_URL_LEN {
        return Err(invalid("ntfy.base_url has an invalid length"));
    }
    if config
        .base_url
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(invalid("ntfy.base_url contains whitespace or controls"));
    }
    let uri = config
        .base_url
        .parse::<http::Uri>()
        .map_err(|_| invalid("ntfy.base_url is not a valid absolute URI"))?;
    if uri.scheme_str() != Some("https") {
        return Err(invalid("ntfy.base_url must use https"));
    }
    if uri.query().is_some() {
        return Err(invalid("ntfy.base_url must not contain a query"));
    }
    let authority = uri
        .authority()
        .ok_or_else(|| invalid("ntfy.base_url has no host"))?;
    if authority.as_str().contains('@') {
        return Err(invalid(
            "ntfy.base_url must not contain userinfo or embedded credentials",
        ));
    }
    if let Ok(ip) = authority.host().parse::<Ipv4Addr>()
        && matches!(
            candidate::classify(ip),
            Some(
                EndpointReject::FakeIp
                    | EndpointReject::ThisNetwork
                    | EndpointReject::Multicast
                    | EndpointReject::Reserved
                    | EndpointReject::Broadcast
            )
        )
    {
        return Err(invalid(format!(
            "ntfy.base_url contains refused numeric address {ip}"
        )));
    }
    if let Some(ip) = config.resolve_ip {
        if candidate::classify(ip).is_some() {
            return Err(invalid(format!(
                "ntfy.resolve_ip must be a public IPv4 address, not {ip}"
            )));
        }
        if authority.host().parse::<std::net::IpAddr>().is_ok() {
            return Err(invalid(
                "ntfy.resolve_ip requires a DNS hostname in ntfy.base_url",
            ));
        }
    }

    let topic_len = config.topic.len();
    if !(MIN_NTFY_TOPIC_LEN..=MAX_NTFY_TOPIC_LEN).contains(&topic_len)
        || !config
            .topic
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(invalid(format!(
            "ntfy.topic must be {MIN_NTFY_TOPIC_LEN}..={MAX_NTFY_TOPIC_LEN} ASCII alphanumerics, '_' or '-'"
        )));
    }
    Ok(())
}

impl ServiceConfig {
    /// Decode and validate a standalone TOML document.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text).map_err(|error| invalid(error.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// Load a bounded, non-symlink configuration owned by the effective UID.
    ///
    /// The file is non-secret and may be readable by others, but group/world
    /// write permission is refused. The finalized PSK remains in `state_dir`.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(|error| io(path, error))?;
        let metadata = file.metadata().map_err(|error| io(path, error))?;
        if !metadata.file_type().is_file() {
            return Err(ConfigError::UnsafeFile {
                path: path.to_path_buf(),
                detail: "not a regular file (symlinks are not followed)".to_owned(),
            });
        }
        if metadata.uid() != effective_uid() {
            return Err(ConfigError::UnsafeFile {
                path: path.to_path_buf(),
                detail: format!(
                    "owned by uid {}, expected effective uid {}",
                    metadata.uid(),
                    effective_uid()
                ),
            });
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(ConfigError::UnsafeFile {
                path: path.to_path_buf(),
                detail: format!(
                    "mode {:#o} is group/world writable",
                    metadata.mode() & 0o777
                ),
            });
        }
        if metadata.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge {
                path: path.to_path_buf(),
            });
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| io(path, error))?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge {
                path: path.to_path_buf(),
            });
        }
        let text = String::from_utf8(bytes).map_err(|_| ConfigError::UnsafeFile {
            path: path.to_path_buf(),
            detail: "not valid UTF-8".to_owned(),
        })?;
        let config: Self = toml::from_str(&text).map_err(|error| ConfigError::Parse {
            path: path.to_path_buf(),
            detail: error.to_string(),
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Check all local fields without accessing the network or changing the OS.
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_absolute_path(&self.state_dir, "state_dir")?;
        validate_absolute_path(&self.control_socket, "control_socket")?;
        if self.state_dir == self.control_socket {
            return Err(invalid("state_dir and control_socket must differ"));
        }
        if self.control_socket.file_name().is_none()
            || self.control_socket.parent() == Some(Path::new("/"))
        {
            return Err(invalid(
                "control_socket must name a socket inside a dedicated directory",
            ));
        }
        if self.control_socket.as_os_str().as_encoded_bytes().len() > MAX_CONTROL_SOCKET_PATH_BYTES
        {
            return Err(invalid(format!(
                "control_socket exceeds {MAX_CONTROL_SOCKET_PATH_BYTES} bytes on macOS"
            )));
        }
        if let Some(interface) = &self.interface {
            validate_interface(interface)?;
        }
        if let Some(ip) = self.bind_ip {
            validate_local_bind_ip(ip)?;
        }
        if self.udp_port == 0 {
            return Err(invalid("udp_port must be fixed and non-zero"));
        }
        if self.stun_seeds.is_empty() || self.stun_seeds.len() > MAX_STUN_SEEDS {
            return Err(invalid(format!(
                "stun_seeds must contain 1..={MAX_STUN_SEEDS} endpoints"
            )));
        }
        let mut unique = std::collections::BTreeSet::new();
        for endpoint in &self.stun_seeds {
            if endpoint.port() == 0 {
                return Err(invalid("STUN endpoint port must be non-zero"));
            }
            if let Some(reason) = candidate::classify(*endpoint.ip()) {
                return Err(invalid(format!(
                    "STUN endpoint {endpoint} is not a public IPv4 address: {reason}"
                )));
            }
            if !unique.insert(*endpoint) {
                return Err(invalid(format!("duplicate STUN endpoint {endpoint}")));
            }
        }
        if !(MIN_MTU..=DEFAULT_MTU).contains(&self.mtu) {
            return Err(invalid(format!(
                "mtu must be {MIN_MTU}..={DEFAULT_MTU}; broad or jumbo overlays are not configured"
            )));
        }
        validate_ntfy(&self.ntfy)
    }

    /// Join with finalized pairing metadata and validate strict host VIPs.
    pub fn resolve(self, relationship: Relationship) -> Result<ResolvedConfig, ConfigError> {
        self.validate()?;
        if relationship.pairing_version != PAIRING_VERSION {
            return Err(invalid(format!(
                "unsupported pairing version {}",
                relationship.pairing_version
            )));
        }
        if relationship.self_public_key == relationship.peer_public_key {
            return Err(invalid("paired self and peer identities must differ"));
        }
        let self_vip = parse_paired_vip("self_vip", &relationship.self_vip)?;
        let peer_vip = parse_paired_vip("peer_vip", &relationship.peer_vip)?;
        if self_vip == peer_vip {
            return Err(invalid("paired self_vip and peer_vip must differ"));
        }
        if let Some(bind_ip) = self.bind_ip
            && (bind_ip == self_vip || bind_ip == peer_vip)
        {
            return Err(invalid(
                "physical bind_ip must not collide with either overlay VIP",
            ));
        }
        Ok(ResolvedConfig {
            config: self,
            relationship,
            self_vip,
            peer_vip,
        })
    }

    /// Load this file and the finalized relationship from its configured state directory.
    pub fn load_resolved(path: &Path) -> Result<ResolvedConfig, ConfigError> {
        let config = Self::load(path)?;
        let state = StateDir::open(&config.state_dir)?;
        let relationship = state.load_relationship()?;
        config.resolve(relationship)
    }
}

fn parse_paired_vip(field: &str, text: &str) -> Result<Ipv4Addr, ConfigError> {
    let ip = text.parse::<Ipv4Addr>().map_err(|_| {
        invalid(format!(
            "paired {field} must be one bare IPv4 address, not a prefix or hostname"
        ))
    })?;
    if !candidate::is_private(ip) {
        return Err(invalid(format!(
            "paired {field} {ip} must be an RFC1918 host address; Fake-IP, public and special-use ranges are refused"
        )));
    }
    Ok(ip)
}

#[cfg(test)]
mod tests {
    use lzh_hole_types::{DiscoveryPublicKey, RelationshipId};

    use super::*;
    use lzh_hole_store::Role;

    const VALID_TOML: &str = r#"
state_dir = "/var/db/lzh-hole"
control_socket = "/var/run/lzh-hole/control.sock"
management_uid = 501
interface = "en0"
udp_port = 51000
stun_seeds = ["8.8.8.8:3478", "1.1.1.1:3478"]
mtu = 1200

[ntfy]
base_url = "https://ntfy.sh"
topic = "lzh-example-0123456789abcdef"
"#;

    fn valid_config() -> ServiceConfig {
        ServiceConfig::from_toml(VALID_TOML).unwrap()
    }

    fn relationship() -> Relationship {
        Relationship {
            pairing_version: PAIRING_VERSION,
            pairing_id: RelationshipId::from_bytes([1; 16]),
            relationship_id: RelationshipId::from_bytes([2; 16]),
            self_public_key: DiscoveryPublicKey::from_bytes([3; 32]),
            peer_public_key: DiscoveryPublicKey::from_bytes([4; 32]),
            role: Role::Initiator,
            self_vip: "10.203.0.1".to_owned(),
            peer_vip: "10.203.0.2".to_owned(),
            finalised_unix_ms: 1,
        }
    }

    #[test]
    fn explicit_config_has_no_vip_or_secret_fields() {
        let config = valid_config();
        assert_eq!(config.mtu, DEFAULT_MTU);
        assert!(
            ServiceConfig::from_toml(&VALID_TOML.replace("mtu = 1200", ""))
                .unwrap()
                .mtu
                == DEFAULT_MTU
        );
        let with_psk = VALID_TOML.replace(
            "management_uid = 501",
            "management_uid = 501\npsk_hex = \"00\"",
        );
        assert!(ServiceConfig::from_toml(&with_psk).is_err());
        let with_vip = VALID_TOML.replace(
            "management_uid = 501",
            "management_uid = 501\nself_vip = \"10.0.0.9\"",
        );
        assert!(ServiceConfig::from_toml(&with_vip).is_err());
    }

    #[test]
    fn lan_defaults_on_and_can_be_explicitly_disabled() {
        assert!(valid_config().lan.enabled);
        let disabled = format!("{VALID_TOML}\n[lan]\nenabled = false\n");
        assert!(!ServiceConfig::from_toml(&disabled).unwrap().lan.enabled);
        assert!(
            ServiceConfig::from_toml(&format!("{VALID_TOML}\n[lan]\nunknown = true\n")).is_err()
        );
    }

    #[test]
    fn rejects_broad_or_fake_network_inputs() {
        for ip in ["198.18.0.1", "127.0.0.1", "0.0.0.0", "224.0.0.1"] {
            let text = VALID_TOML.replace(
                "interface = \"en0\"",
                &format!("interface = \"en0\"\nbind_ip = \"{ip}\""),
            );
            assert!(ServiceConfig::from_toml(&text).is_err(), "bind_ip {ip}");
        }
        for endpoint in ["198.18.0.1:3478", "192.168.1.1:3478", "127.0.0.1:3478"] {
            let text = VALID_TOML.replace(
                "\"8.8.8.8:3478\", \"1.1.1.1:3478\"",
                &format!("\"{endpoint}\""),
            );
            assert!(ServiceConfig::from_toml(&text).is_err(), "STUN {endpoint}");
        }
        for vip in ["198.18.0.1", "8.8.8.8", "10.203.0.0/24"] {
            let mut relationship = relationship();
            relationship.peer_vip = vip.to_owned();
            assert!(valid_config().resolve(relationship).is_err(), "VIP {vip}");
        }
    }

    #[test]
    fn resolved_addresses_come_only_from_pairing_and_are_host_routes() {
        let resolved = valid_config().resolve(relationship()).unwrap();
        assert_eq!(resolved.self_vip, Ipv4Addr::new(10, 203, 0, 1));
        assert_eq!(
            resolved.peer_host_route(),
            (Ipv4Addr::new(10, 203, 0, 2), 32)
        );
    }

    #[test]
    fn rejects_unsafe_service_bounds() {
        let cases = [
            VALID_TOML.replace("udp_port = 51000", "udp_port = 0"),
            VALID_TOML.replace("mtu = 1200", "mtu = 1400"),
            VALID_TOML.replace("mtu = 1200", "mtu = 575"),
            VALID_TOML.replace("interface = \"en0\"", "interface = \"utun4\""),
            VALID_TOML.replace("/var/db/lzh-hole", "relative/state"),
            VALID_TOML.replace("https://ntfy.sh", "http://ntfy.sh"),
            VALID_TOML.replace("https://ntfy.sh", "https://user:pass@ntfy.sh"),
            VALID_TOML.replace("lzh-example-0123456789abcdef", "short"),
        ];
        for text in cases {
            assert!(ServiceConfig::from_toml(&text).is_err(), "{text}");
        }
    }

    #[test]
    fn ntfy_resolve_override_is_public_and_preserves_a_dns_hostname() {
        let text = VALID_TOML.replace(
            "base_url = \"https://ntfy.sh\"",
            "base_url = \"https://ntfy.sh\"\nresolve_ip = \"159.203.148.75\"",
        );
        let config = ServiceConfig::from_toml(&text).unwrap();
        assert_eq!(
            config.ntfy.resolve_ip,
            Some(Ipv4Addr::new(159, 203, 148, 75))
        );
        for ip in ["198.18.0.1", "192.168.1.1", "127.0.0.1"] {
            let text = VALID_TOML.replace(
                "base_url = \"https://ntfy.sh\"",
                &format!("base_url = \"https://ntfy.sh\"\nresolve_ip = \"{ip}\""),
            );
            assert!(ServiceConfig::from_toml(&text).is_err(), "resolve {ip}");
        }
        let numeric_origin = VALID_TOML
            .replace("https://ntfy.sh", "https://8.8.8.8")
            .replace(
                "base_url = \"https://8.8.8.8\"",
                "base_url = \"https://8.8.8.8\"\nresolve_ip = \"159.203.148.75\"",
            );
        assert!(ServiceConfig::from_toml(&numeric_origin).is_err());
    }

    #[test]
    fn physical_bind_may_be_rfc1918_but_not_a_vip() {
        let text = VALID_TOML.replace(
            "interface = \"en0\"",
            "interface = \"en0\"\nbind_ip = \"192.168.8.164\"",
        );
        let config = ServiceConfig::from_toml(&text).unwrap();
        let mut relationship = relationship();
        relationship.self_vip = "192.168.8.164".to_owned();
        assert!(config.resolve(relationship).is_err());
    }
}
