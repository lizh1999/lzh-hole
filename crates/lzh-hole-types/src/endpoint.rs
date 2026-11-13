//! Small, serialisable network domain types shared across crate boundaries.

use std::fmt;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// An IPv4 UDP endpoint. Validation policy lives with the protocol/discovery
/// users of this type rather than in this minimal shared crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Endpoint {
    /// IPv4 address.
    pub ip: Ipv4Addr,
    /// UDP port, never zero for a usable candidate.
    pub port: u16,
}

impl Endpoint {
    /// Build an endpoint.
    pub const fn new(ip: Ipv4Addr, port: u16) -> Self {
        Self { ip, port }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}
