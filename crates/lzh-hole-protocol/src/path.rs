//! Candidate endpoints and the rules for publishing versus targeting.
//!
//! Publication and remote-target filtering are deliberately separate concerns:
//!
//! * Our own measured STUN mappings ARE the subject of publication, so they
//!   must never be blanket-refused by a "do not target ourselves" rule.
//! * When choosing a remote target we refuse only our own *exact* endpoints.
//!   The same public IP on a different port is a legitimate peer mapping and
//!   must not be banned wholesale.
//! * A STUN server address is a destination we query, never a peer candidate.

use std::fmt;
use std::net::Ipv4Addr;

pub use lzh_hole_types::Endpoint;
use lzh_hole_types::TransportId;
use serde::{Deserialize, Serialize};

/// A remote endpoint reached through one retained local physical socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathEndpoint {
    /// Opaque local socket identity.
    pub transport: TransportId,
    /// Actual remote UDP address.
    pub remote: Endpoint,
}

/// Discovery provenance; neither class is authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    /// Untrusted on-link RFC1918 hint.
    Lan,
    /// Existing public discovery.
    Public,
}

/// A discovery hint associated with its physical transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathCandidate {
    /// Local transport and remote endpoint.
    pub path: PathEndpoint,
    /// Address policy to apply.
    pub kind: PathKind,
}

/// An IPv4 subnet actually attached to a physical interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LanSubnet {
    /// Interface address (host bits need not be zero).
    pub address: Ipv4Addr,
    /// CIDR prefix length.
    pub prefix_len: u8,
}

impl LanSubnet {
    /// Whether this is an on-link RFC1918 host, excluding network/broadcast.
    pub fn contains_host(&self, address: Ipv4Addr) -> bool {
        if !(1..=30).contains(&self.prefix_len) || !is_private(self.address) || !is_private(address)
        {
            return false;
        }
        let mask = u32::MAX << (32 - self.prefix_len);
        let network = u32::from(self.address) & mask;
        // A broad/malformed subnet must not authorize another private block.
        if !is_private(Ipv4Addr::from(network)) || !is_private(Ipv4Addr::from(network | !mask)) {
            return false;
        }
        let host = u32::from(address);
        host & mask == network && host != network && host != network | !mask
    }
}

/// Trusted local facts supplied by the socket owner, never by discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportPolicy {
    /// Daemon-lifetime unique socket identity.
    pub transport: TransportId,
    /// Bound physical address and port.
    pub local_endpoint: Endpoint,
    /// Physical interface's attached IPv4 subnets.
    pub lan_subnets: Vec<LanSubnet>,
}

/// How a candidate was learned.
///
/// v1 has exactly two publishable classes. There is deliberately no
/// "configured" class: an operator may not hand-fill this run's peer port, and
/// a STUN server address is not a candidate at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateSource {
    /// Server-reflexive mapping measured for our own data socket.
    Stun,
    /// Source address of a frame with a correct session MAC that has also
    /// completed a return-path challenge in the current generation.
    PeerReflexiveVerified,
}

impl CandidateSource {
    /// The on-wire byte.
    pub const fn as_u8(self) -> u8 {
        match self {
            CandidateSource::Stun => 0,
            CandidateSource::PeerReflexiveVerified => 1,
        }
    }

    /// Parse a source byte. Anything else is not publishable in v1.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(CandidateSource::Stun),
            1 => Some(CandidateSource::PeerReflexiveVerified),
            _ => None,
        }
    }

    /// Both v1 classes are publishable.
    pub const fn is_publishable(self) -> bool {
        true
    }

    /// Stable snake_case identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            CandidateSource::Stun => "stun",
            CandidateSource::PeerReflexiveVerified => "peer_reflexive_verified",
        }
    }
}

/// Why an address may not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointReject {
    /// Port zero is not a destination.
    PortZero,
    /// 0.0.0.0/8.
    ThisNetwork,
    /// 127.0.0.0/8.
    Loopback,
    /// RFC 1918.
    Private,
    /// 169.254.0.0/16.
    LinkLocal,
    /// 100.64.0.0/10 carrier-grade NAT space.
    Cgnat,
    /// 192.0.0.0/24 IETF protocol assignments.
    IetfProtocol,
    /// TEST-NET-1/2/3 documentation ranges.
    Documentation,
    /// 198.18.0.0/15: RFC 2544 benchmarking, and the range Fake-IP resolvers
    /// hand out. Refused as a data candidate under either reading.
    FakeIp,
    /// 192.88.99.0/24 deprecated 6to4 relay anycast.
    #[serde(rename = "shared_6to4")]
    Shared6to4,
    /// 224.0.0.0/4.
    Multicast,
    /// 240.0.0.0/4.
    Reserved,
    /// 255.255.255.255.
    Broadcast,
    /// The endpoint is a configured STUN server, not a peer.
    StunServerAddress,
    /// Exactly one of our own endpoints, so we would be talking to ourselves.
    ForbiddenEndpoint,
    /// An address we must never target at all: a coordination gateway or an
    /// overlay address.
    ForbiddenAddress,
}

impl EndpointReject {
    /// Stable snake_case identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            EndpointReject::PortZero => "port_zero",
            EndpointReject::ThisNetwork => "this_network",
            EndpointReject::Loopback => "loopback",
            EndpointReject::Private => "private",
            EndpointReject::LinkLocal => "link_local",
            EndpointReject::Cgnat => "cgnat",
            EndpointReject::IetfProtocol => "ietf_protocol",
            EndpointReject::Documentation => "documentation",
            EndpointReject::FakeIp => "fake_ip",
            EndpointReject::Shared6to4 => "shared_6to4",
            EndpointReject::Multicast => "multicast",
            EndpointReject::Reserved => "reserved",
            EndpointReject::Broadcast => "broadcast",
            EndpointReject::StunServerAddress => "stun_server_address",
            EndpointReject::ForbiddenEndpoint => "forbidden_endpoint",
            EndpointReject::ForbiddenAddress => "forbidden_address",
        }
    }
}

impl fmt::Display for EndpointReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Every reject reason, for exhaustiveness tests.
pub const ALL_REJECTS: [EndpointReject; 16] = [
    EndpointReject::PortZero,
    EndpointReject::ThisNetwork,
    EndpointReject::Loopback,
    EndpointReject::Private,
    EndpointReject::LinkLocal,
    EndpointReject::Cgnat,
    EndpointReject::IetfProtocol,
    EndpointReject::Documentation,
    EndpointReject::FakeIp,
    EndpointReject::Shared6to4,
    EndpointReject::Multicast,
    EndpointReject::Reserved,
    EndpointReject::Broadcast,
    EndpointReject::StunServerAddress,
    EndpointReject::ForbiddenEndpoint,
    EndpointReject::ForbiddenAddress,
];

/// Classify an address. None means "not in any range we refuse".
pub fn classify(ip: Ipv4Addr) -> Option<EndpointReject> {
    let o = ip.octets();
    if ip == Ipv4Addr::BROADCAST {
        return Some(EndpointReject::Broadcast);
    }
    match o[0] {
        0 => Some(EndpointReject::ThisNetwork),
        10 => Some(EndpointReject::Private),
        127 => Some(EndpointReject::Loopback),
        100 if (64..=127).contains(&o[1]) => Some(EndpointReject::Cgnat),
        169 if o[1] == 254 => Some(EndpointReject::LinkLocal),
        172 if (16..=31).contains(&o[1]) => Some(EndpointReject::Private),
        192 if o[1] == 0 && o[2] == 0 => Some(EndpointReject::IetfProtocol),
        192 if o[1] == 0 && o[2] == 2 => Some(EndpointReject::Documentation),
        192 if o[1] == 88 && o[2] == 99 => Some(EndpointReject::Shared6to4),
        192 if o[1] == 168 => Some(EndpointReject::Private),
        198 if o[1] == 18 || o[1] == 19 => Some(EndpointReject::FakeIp),
        198 if o[1] == 51 && o[2] == 100 => Some(EndpointReject::Documentation),
        203 if o[1] == 0 && o[2] == 113 => Some(EndpointReject::Documentation),
        224..=239 => Some(EndpointReject::Multicast),
        240..=255 => Some(EndpointReject::Reserved),
        _ => None,
    }
}

/// Whether the address is in RFC 1918 space, where overlay addresses live.
pub fn is_private(ip: Ipv4Addr) -> bool {
    classify(ip) == Some(EndpointReject::Private)
}

/// A candidate endpoint with its provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    /// The address.
    pub endpoint: Endpoint,
    /// How we learned it.
    pub source: CandidateSource,
    /// Physical interface it was observed on, when known.
    pub interface: Option<String>,
    /// Milliseconds since the Unix epoch when it was observed.
    pub observed_unix_ms: u64,
}

/// A candidate that failed validation, kept for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedCandidate {
    /// The address we refused.
    pub endpoint: Endpoint,
    /// Where it came from.
    pub source: CandidateSource,
    /// Why it was refused.
    pub reject: EndpointReject,
}

/// Check an endpoint we are about to PUBLISH.
///
/// Our own measured mappings are the subject here, so they are not refused.
/// Only structurally unusable addresses and STUN server addresses are.
pub fn validate_publishable(
    endpoint: &Endpoint,
    stun_servers: &[Endpoint],
) -> Result<(), EndpointReject> {
    if endpoint.port == 0 {
        return Err(EndpointReject::PortZero);
    }
    if stun_servers.contains(endpoint) {
        return Err(EndpointReject::StunServerAddress);
    }
    classify(endpoint.ip).map_or(Ok(()), Err)
}

/// Check an endpoint we are about to TARGET as a peer.
///
/// On top of the publication rules this refuses our own exact endpoints and any
/// wholly forbidden address. A different port on the same public IP is allowed.
pub fn validate_remote_target(
    endpoint: &Endpoint,
    own_endpoints: &[Endpoint],
    forbidden_addresses: &[Ipv4Addr],
    stun_servers: &[Endpoint],
) -> Result<(), EndpointReject> {
    validate_publishable(endpoint, stun_servers)?;
    if own_endpoints.contains(endpoint) {
        return Err(EndpointReject::ForbiddenEndpoint);
    }
    if forbidden_addresses.contains(&endpoint.ip) {
        return Err(EndpointReject::ForbiddenAddress);
    }
    Ok(())
}

/// Split candidates into publishable and rejected.
pub fn partition_candidates(
    candidates: &[Candidate],
    stun_servers: &[Endpoint],
) -> (Vec<Candidate>, Vec<RejectedCandidate>) {
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    for candidate in candidates {
        match validate_publishable(&candidate.endpoint, stun_servers) {
            Ok(()) => accepted.push(candidate.clone()),
            Err(reject) => rejected.push(RejectedCandidate {
                endpoint: candidate.endpoint,
                source: candidate.source,
                reject,
            }),
        }
    }
    (accepted, rejected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn ep(s: &str, port: u16) -> Endpoint {
        Endpoint::new(ip(s), port)
    }

    #[test]
    fn real_observed_mappings_are_publishable() {
        for s in ["210.22.105.194", "38.58.103.204"] {
            assert_eq!(classify(ip(s)), None, "{s}");
            assert!(validate_publishable(&ep(s, 40000), &[]).is_ok());
        }
    }

    #[test]
    fn special_ranges_are_refused() {
        let cases = [
            ("0.0.0.0", EndpointReject::ThisNetwork),
            ("10.203.0.1", EndpointReject::Private),
            ("172.16.0.1", EndpointReject::Private),
            ("172.31.255.255", EndpointReject::Private),
            ("192.168.8.164", EndpointReject::Private),
            ("127.0.0.1", EndpointReject::Loopback),
            ("169.254.1.1", EndpointReject::LinkLocal),
            ("100.64.0.1", EndpointReject::Cgnat),
            ("100.127.255.255", EndpointReject::Cgnat),
            ("192.0.0.1", EndpointReject::IetfProtocol),
            ("192.0.2.1", EndpointReject::Documentation),
            ("198.51.100.1", EndpointReject::Documentation),
            ("203.0.113.1", EndpointReject::Documentation),
            ("192.88.99.1", EndpointReject::Shared6to4),
            ("198.18.0.241", EndpointReject::FakeIp),
            ("198.19.255.255", EndpointReject::FakeIp),
            ("224.0.0.1", EndpointReject::Multicast),
            ("239.255.255.250", EndpointReject::Multicast),
            ("240.0.0.1", EndpointReject::Reserved),
            ("255.255.255.255", EndpointReject::Broadcast),
            ("255.255.255.254", EndpointReject::Reserved),
        ];
        for (addr, expected) in cases {
            assert_eq!(classify(ip(addr)), Some(expected), "{addr}");
        }
    }

    #[test]
    fn fake_ip_range_is_named_for_diagnosis() {
        for s in ["198.18.0.241", "198.18.0.242", "198.18.0.243"] {
            assert_eq!(classify(ip(s)), Some(EndpointReject::FakeIp));
        }
    }

    #[test]
    fn boundaries_of_private_and_public_space() {
        assert_eq!(classify(ip("172.15.255.255")), None);
        assert_eq!(classify(ip("172.32.0.0")), None);
        assert_eq!(classify(ip("100.63.255.255")), None);
        assert_eq!(classify(ip("100.128.0.0")), None);
        assert_eq!(classify(ip("11.0.0.1")), None);
        assert_eq!(classify(ip("223.255.255.255")), None);
    }

    #[test]
    fn port_zero_is_refused() {
        assert_eq!(
            validate_publishable(&ep("210.22.105.194", 0), &[]),
            Err(EndpointReject::PortZero)
        );
    }

    #[test]
    fn our_own_mapping_is_publishable_but_not_a_valid_target() {
        let mine = ep("210.22.105.194", 51000);
        assert!(validate_publishable(&mine, &[]).is_ok());
        assert_eq!(
            validate_remote_target(&mine, &[mine], &[], &[]),
            Err(EndpointReject::ForbiddenEndpoint)
        );
    }

    #[test]
    fn same_public_ip_different_port_is_still_a_valid_target() {
        let mine = ep("210.22.105.194", 51000);
        let other_port = ep("210.22.105.194", 51001);
        assert!(validate_remote_target(&other_port, &[mine], &[], &[]).is_ok());
        assert!(validate_publishable(&other_port, &[]).is_ok());
    }

    #[test]
    fn forbidden_addresses_are_refused_whatever_the_port() {
        let gateway = ip("34.65.156.171");
        for port in [80u16, 443, 51000] {
            assert_eq!(
                validate_remote_target(&ep("34.65.156.171", port), &[], &[gateway], &[]),
                Err(EndpointReject::ForbiddenAddress)
            );
        }
    }

    #[test]
    fn overlay_addresses_are_never_valid_targets() {
        assert_eq!(
            validate_remote_target(&ep("10.203.0.2", 1), &[], &[], &[]),
            Err(EndpointReject::Private)
        );
        assert!(is_private(ip("10.203.0.1")));
        assert!(is_private(ip("10.203.0.2")));
        assert!(!is_private(ip("210.22.105.194")));
    }

    #[test]
    fn stun_server_addresses_are_never_peer_candidates() {
        let seeds = [ep("116.162.157.195", 3478), ep("111.206.174.3", 3478)];
        assert_eq!(
            validate_publishable(&ep("116.162.157.195", 3478), &seeds),
            Err(EndpointReject::StunServerAddress)
        );
        assert!(validate_publishable(&ep("116.162.157.195", 51000), &seeds).is_ok());
    }

    #[test]
    fn only_two_publishable_source_classes_exist() {
        assert_eq!(CandidateSource::from_u8(0), Some(CandidateSource::Stun));
        assert_eq!(
            CandidateSource::from_u8(1),
            Some(CandidateSource::PeerReflexiveVerified)
        );
        for v in 2u8..=255 {
            assert_eq!(CandidateSource::from_u8(v), None, "source class {v}");
        }
        assert!(CandidateSource::Stun.is_publishable());
        assert!(CandidateSource::PeerReflexiveVerified.is_publishable());
    }

    #[test]
    fn partition_keeps_rejected_candidates_for_diagnostics() {
        let candidates = vec![
            Candidate {
                endpoint: ep("210.22.105.194", 51000),
                source: CandidateSource::Stun,
                interface: Some("en7".to_owned()),
                observed_unix_ms: 1,
            },
            Candidate {
                endpoint: ep("192.168.8.164", 51000),
                source: CandidateSource::Stun,
                interface: Some("en7".to_owned()),
                observed_unix_ms: 1,
            },
            Candidate {
                endpoint: ep("198.18.0.241", 443),
                source: CandidateSource::PeerReflexiveVerified,
                interface: None,
                observed_unix_ms: 1,
            },
        ];
        let (accepted, rejected) = partition_candidates(&candidates, &[]);
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].endpoint.ip, ip("210.22.105.194"));
        assert_eq!(rejected.len(), 2);
        assert_eq!(rejected[0].reject, EndpointReject::Private);
        assert_eq!(rejected[1].reject, EndpointReject::FakeIp);
    }

    #[test]
    fn multiple_distinct_mappings_are_all_kept() {
        let candidates = vec![
            Candidate {
                endpoint: ep("210.22.105.194", 40001),
                source: CandidateSource::Stun,
                interface: Some("en7".to_owned()),
                observed_unix_ms: 1,
            },
            Candidate {
                endpoint: ep("38.58.103.204", 40001),
                source: CandidateSource::Stun,
                interface: Some("en7".to_owned()),
                observed_unix_ms: 1,
            },
        ];
        let (accepted, rejected) = partition_candidates(&candidates, &[]);
        assert_eq!(accepted.len(), 2);
        assert!(rejected.is_empty());
    }

    #[test]
    fn reject_codes_are_stable_snake_case() {
        for reject in ALL_REJECTS {
            let name = reject.as_str();
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{name}"
            );
            assert_eq!(
                serde_json::to_string(&reject).unwrap(),
                format!("\"{name}\"")
            );
        }
        for source in [
            CandidateSource::Stun,
            CandidateSource::PeerReflexiveVerified,
        ] {
            let name = source.as_str();
            assert_eq!(
                serde_json::to_string(&source).unwrap(),
                format!("\"{name}\"")
            );
        }
    }
}
