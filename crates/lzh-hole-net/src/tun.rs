//! A thin macOS utun wrapper for raw IPv4-over-UDP forwarding.
//!
//! `tun-rs` owns utun creation, packet-information stripping and Tokio I/O.
//! This module adds only the lzh-hole configuration and ownership contract:
//! one local/peer IPv4 pair, one MTU, no automatic subnet/default routes, and
//! one separately owned peer `/32` route.

use std::io;
use std::net::{IpAddr, Ipv4Addr};

use tun_rs::{AsyncDevice, DeviceBuilder, Layer};

use crate::route::{PeerHostRoute, RouteError};

/// Default tunnel MTU, deliberately below common path MTUs to leave room for
/// the UDP/IPv4 and lzh-hole frame headers.
pub const DEFAULT_MTU: u16 = 1200;
/// Smallest accepted IPv4 MTU.
pub const MIN_MTU: u16 = 576;

/// Fixed addressing for one two-host tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunConfig {
    local: Ipv4Addr,
    peer: Ipv4Addr,
    mtu: u16,
}

impl TunConfig {
    /// Configure a local and peer virtual IPv4 address with [`DEFAULT_MTU`].
    pub fn new(local: Ipv4Addr, peer: Ipv4Addr) -> Self {
        Self {
            local,
            peer,
            mtu: DEFAULT_MTU,
        }
    }

    /// Override the tunnel MTU. Values below 576 are rejected on creation.
    pub fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }

    /// Local virtual IPv4 address assigned to utun.
    pub fn local(&self) -> Ipv4Addr {
        self.local
    }

    /// Peer's fixed virtual IPv4 address, also used for the `/32` host route.
    pub fn peer(&self) -> Ipv4Addr {
        self.peer
    }

    /// Configured utun MTU.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Validate configuration without creating an interface or changing routes.
    pub fn validate(&self) -> Result<(), TunnelError> {
        if self.local == self.peer {
            return Err(TunnelError::InvalidConfig(
                "local and peer addresses must differ",
            ));
        }
        if self.local.is_unspecified() || self.peer.is_unspecified() {
            return Err(TunnelError::InvalidConfig(
                "local and peer addresses must not be unspecified",
            ));
        }
        if self.local.is_multicast() || self.peer.is_multicast() {
            return Err(TunnelError::InvalidConfig(
                "local and peer addresses must not be multicast",
            ));
        }
        if self.local.is_broadcast() || self.peer.is_broadcast() {
            return Err(TunnelError::InvalidConfig(
                "local and peer addresses must not be broadcast",
            ));
        }
        if self.mtu < MIN_MTU {
            return Err(TunnelError::InvalidConfig(
                "IPv4 tunnel MTU must be at least 576",
            ));
        }
        Ok(())
    }
}

/// Failures while constructing a managed tunnel.
#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    /// Invalid addresses or MTU.
    #[error("invalid tunnel configuration: {0}")]
    InvalidConfig(&'static str),
    /// utun creation, configuration or readback failed.
    #[error("utun setup failed: {0}")]
    Device(#[from] io::Error),
    /// The device did not retain the required configuration.
    #[error("utun configuration verification failed: {0}")]
    DeviceVerification(String),
    /// Installing the peer host route failed. The newly created utun is closed.
    #[error("could not install peer host route: {0}")]
    Route(#[from] RouteError),
}

/// A live utun and its owned peer host route.
///
/// Creation must run inside a Tokio runtime with I/O enabled. The route field
/// is intentionally dropped before the device so cleanup happens while utun
/// still exists. Dropping the value performs best-effort route cleanup;
/// [`Tunnel::close`] reports route cleanup failures.
pub struct Tunnel {
    peer_route: PeerHostRoute,
    device: AsyncDevice,
    config: TunConfig,
    name: String,
    if_index: u32,
}

impl Tunnel {
    /// Create a new kernel-assigned utun, configure it and install only the
    /// peer `/32` route.
    ///
    /// No existing utun is reused. Automatic associated routes are disabled,
    /// and no default route, DNS, PF rule or physical-interface setting is
    /// touched. This is a privileged operation when actually called.
    pub fn create(config: TunConfig) -> Result<Self, TunnelError> {
        config.validate()?;
        let device = DeviceBuilder::new()
            .layer(Layer::L3)
            .mtu(config.mtu)
            // macOS creates a peer host route for a point-to-point destination.
            // Leave it unset here so PeerHostRoute remains the sole /32 owner.
            .ipv4(config.local, 32, None)
            .packet_information(false)
            .enable(true)
            .with(|options| {
                options.associate_route(false);
            })
            .build_async()?;

        if device.associate_route() {
            return Err(TunnelError::DeviceVerification(
                "associate_route remained enabled".to_owned(),
            ));
        }
        if !device.ignore_packet_info() {
            return Err(TunnelError::DeviceVerification(
                "utun packet-information stripping is disabled".to_owned(),
            ));
        }
        let actual_mtu = device.mtu()?;
        if actual_mtu != config.mtu {
            return Err(TunnelError::DeviceVerification(format!(
                "MTU is {actual_mtu}, expected {}",
                config.mtu
            )));
        }
        let addresses = device.addresses()?;
        if !addresses.contains(&IpAddr::V4(config.local)) {
            return Err(TunnelError::DeviceVerification(format!(
                "local address {} is not assigned",
                config.local
            )));
        }
        let name = device.name()?;
        if !name.starts_with("utun") {
            return Err(TunnelError::DeviceVerification(format!(
                "unexpected interface name {name}"
            )));
        }
        let if_index = device.if_index()?;
        let peer_route = PeerHostRoute::install(config.local, config.peer, if_index, &name)?;

        Ok(Self {
            peer_route,
            device,
            config,
            name,
            if_index,
        })
    }

    /// Immutable tunnel configuration.
    pub fn config(&self) -> TunConfig {
        self.config
    }

    /// Kernel-assigned utun name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Kernel interface index used by the owned peer route.
    pub fn if_index(&self) -> u32 {
        self.if_index
    }

    /// Receive one raw IPv4 packet. macOS's four-byte utun protocol header is
    /// handled by tun-rs and is never exposed to the caller.
    pub async fn recv_ipv4(&self, buf: &mut [u8]) -> io::Result<usize> {
        let size = self.device.recv(buf).await?;
        validate_ipv4_packet(&buf[..size])?;
        Ok(size)
    }

    /// Send one complete raw IPv4 packet to the kernel.
    pub async fn send_ipv4(&self, packet: &[u8]) -> io::Result<()> {
        validate_ipv4_packet(packet)?;
        let written = self.device.send(packet).await?;
        if written != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("partial IPv4 packet write: {written} of {}", packet.len()),
            ));
        }
        Ok(())
    }

    /// Remove the owned peer route and close utun.
    pub fn close(self) -> Result<(), RouteError> {
        let Self {
            peer_route, device, ..
        } = self;
        let result = peer_route.close();
        drop(device);
        result
    }
}

fn validate_ipv4_packet(packet: &[u8]) -> io::Result<()> {
    if packet.len() < 20 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "IPv4 packet is shorter than its base header",
        ));
    }
    if packet[0] >> 4 != 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "packet is not IPv4",
        ));
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || header_len > packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid IPv4 header length",
        ));
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len != packet.len() || total_len < header_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "IPv4 total length does not match the packet buffer",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local() -> Ipv4Addr {
        Ipv4Addr::new(100, 64, 0, 1)
    }

    fn peer() -> Ipv4Addr {
        Ipv4Addr::new(100, 64, 0, 2)
    }

    fn packet(payload_len: usize) -> Vec<u8> {
        let mut packet = vec![0u8; 20 + payload_len];
        packet[0] = 0x45;
        let total = (packet.len() as u16).to_be_bytes();
        packet[2] = total[0];
        packet[3] = total[1];
        packet
    }

    #[test]
    fn defaults_are_a_point_to_point_ipv4_tunnel() {
        let config = TunConfig::new(local(), peer());
        assert_eq!(config.local(), local());
        assert_eq!(config.peer(), peer());
        assert_eq!(config.mtu(), 1200);
        assert_eq!(DEFAULT_MTU, 1200);
        config.validate().unwrap();
        assert_eq!(config.with_mtu(1400).mtu(), 1400);
    }

    #[test]
    fn unsafe_or_ill_formed_configuration_is_rejected_offline() {
        for config in [
            TunConfig::new(local(), local()),
            TunConfig::new(Ipv4Addr::UNSPECIFIED, peer()),
            TunConfig::new(local(), Ipv4Addr::new(224, 0, 0, 1)),
            TunConfig::new(local(), peer()).with_mtu(MIN_MTU - 1),
        ] {
            assert!(matches!(
                config.validate(),
                Err(TunnelError::InvalidConfig(_))
            ));
        }
        TunConfig::new(local(), peer())
            .with_mtu(MIN_MTU)
            .validate()
            .unwrap();
    }

    #[test]
    fn raw_ipv4_validation_accepts_only_complete_single_packets() {
        assert!(validate_ipv4_packet(&packet(0)).is_ok());
        assert!(validate_ipv4_packet(&packet(32)).is_ok());

        let mut wrong_version = packet(0);
        wrong_version[0] = 0x65;
        assert!(validate_ipv4_packet(&wrong_version).is_err());

        let mut short_header = packet(0);
        short_header[0] = 0x44;
        assert!(validate_ipv4_packet(&short_header).is_err());

        let mut wrong_total = packet(4);
        wrong_total[3] = 0;
        assert!(validate_ipv4_packet(&wrong_total).is_err());
        assert!(validate_ipv4_packet(&packet(0)[..19]).is_err());
    }
}
