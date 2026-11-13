//! Thin macOS network adapters: physical interfaces, one bound async UDP
//! socket, dedicated utun and ownership-scoped peer routes.
//!
//! This crate deliberately has no protocol, discovery or service dependency.

#![allow(unsafe_code)]

pub mod interface;
pub mod route;
pub mod socket;
pub mod tun;

pub use interface::{InterfaceInfo, enumerate_interfaces, is_physical_candidate};
pub use route::{PeerHostRoute, RouteError};
pub use socket::{AsyncPhysicalSocket, PhysicalSocket, RecvMeta};
pub use tun::{DEFAULT_MTU, MIN_MTU, TunConfig, Tunnel, TunnelError};
