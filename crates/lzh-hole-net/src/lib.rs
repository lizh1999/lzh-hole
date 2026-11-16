//! Thin macOS adapters: physical interfaces, native Bonjour, bound async UDP
//! sockets, dedicated utun and ownership-scoped peer routes.
//!
//! This crate deliberately has no protocol, discovery or service dependency.

#![allow(unsafe_code)]

pub mod dns;
pub mod interface;
pub mod mdns;
pub mod overlay;
pub mod route;
pub mod socket;
pub mod tun;

pub use dns::{
    DNS_PORT, DnsError, DnsOptions, encode_a_query, parse_a_response, query_a, query_a_with,
};
pub use interface::{
    InterfaceInfo, InterfacePrefixes, Ipv4Prefix, default_gateway_ipv4,
    enumerate_interface_prefixes, enumerate_interfaces, has_scoped_direct_route,
    has_scoped_direct_route_from, is_physical_candidate,
};
pub use overlay::{MAX_OVERLAY_ROUTES, OverlayRoutes};
pub use route::{PeerHostRoute, RouteError};
pub use socket::{AsyncPhysicalSocket, PhysicalSocket, RecvMeta};
pub use tun::{DEFAULT_MTU, MIN_MTU, TunConfig, Tunnel, TunnelError};
