//! Physical interface enumeration.
//!
//! We never modify the routing table or any interface. This module only reads
//! what the kernel already reports, and classifies what it sees so the caller
//! can prefer a real physical adapter over an overlay tunnel.

use std::collections::BTreeSet;
use std::ffi::CStr;
use std::io;
use std::net::{IpAddr, Ipv4Addr};

use route_manager::{Route, RouteKind, RouteManager};

/// One IPv4 interface as the kernel reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceInfo {
    /// Interface name, for example "en7".
    pub name: String,
    /// Kernel interface index.
    pub index: u32,
    /// IPv4 addresses configured on it.
    pub ipv4: Vec<Ipv4Addr>,
    /// Whether the interface is administratively up.
    pub is_up: bool,
    /// Whether it is the loopback interface.
    pub is_loopback: bool,
    /// Whether the name looks like a point-to-point tunnel (utun, ppp, tap).
    pub is_tunnel: bool,
}

impl InterfaceInfo {
    /// Whether this looks like a physical adapter we may bind a data socket to.
    ///
    /// Loopback is allowed so that offline tests can run; tunnels and down
    /// interfaces are not. The caller applies its own allowlist on top.
    pub fn is_physical_candidate(&self) -> bool {
        self.is_up && !self.is_tunnel && !self.ipv4.is_empty()
    }
}

/// Whether an interface name looks like an overlay tunnel rather than hardware.
pub fn is_tunnel_name(name: &str) -> bool {
    name.starts_with("utun")
        || name.starts_with("ppp")
        || name.starts_with("tap")
        || name.starts_with("tun")
        || name.starts_with("ipsec")
}

/// Whether an interface is a plausible physical data interface.
pub fn is_physical_candidate(info: &InterfaceInfo) -> bool {
    info.is_physical_candidate()
}

/// Enumerate IPv4 interfaces.
///
/// This is a read-only snapshot. Names and indexes are never cached as
/// permanent configuration: they are re-read every time.
pub fn enumerate_interfaces() -> io::Result<Vec<InterfaceInfo>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: head is a valid out-pointer.
    let rc = unsafe { libc::getifaddrs(&mut head) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut out: Vec<InterfaceInfo> = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: cur is non-null and points into the list returned above.
        let entry = unsafe { &*cur };
        cur = entry.ifa_next;
        if entry.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: ifa_addr is non-null and we check the family before use.
        let family = unsafe { (*entry.ifa_addr).sa_family };
        if family != libc::AF_INET as libc::sa_family_t {
            continue;
        }
        // SAFETY: a non-null ifa_name is a NUL-terminated C string.
        let name = unsafe { CStr::from_ptr(entry.ifa_name) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: AF_INET sockaddr is a sockaddr_in.
        let addr = unsafe { (*(entry.ifa_addr as *const libc::sockaddr_in)).sin_addr };
        let ip = Ipv4Addr::from(u32::from_be(addr.s_addr));
        let flags = entry.ifa_flags as i32;
        let is_up = flags & libc::IFF_UP != 0;
        let is_loopback = flags & libc::IFF_LOOPBACK != 0;
        let index = if_nametoindex(&name).unwrap_or(0);

        match out.iter_mut().find(|i| i.name == name) {
            Some(existing) => {
                if !existing.ipv4.contains(&ip) {
                    existing.ipv4.push(ip);
                }
            }
            None => out.push(InterfaceInfo {
                is_tunnel: is_tunnel_name(&name),
                name,
                index,
                ipv4: vec![ip],
                is_up,
                is_loopback,
            }),
        }
    }
    // SAFETY: head is the list returned by getifaddrs and is freed once.
    unsafe { libc::freeifaddrs(head) };
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn if_nametoindex(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: c is a valid NUL-terminated string for the call.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 { None } else { Some(idx) }
}

/// Return interface indices with a usable same-interface IPv4 route to at
/// least one destination. The routing table is only read; no route is changed.
///
/// An interface-scoped `IP_BOUND_IF` socket cannot use an arbitrary default
/// route through another physical interface or a VPN. For each interface and
/// destination, the longest matching prefix must therefore be a unicast route
/// through that same interface.
pub fn interfaces_with_ipv4_route(destinations: &[Ipv4Addr]) -> io::Result<BTreeSet<u32>> {
    let mut manager = RouteManager::new()?;
    let routes = manager.list()?;
    Ok(routed_interface_indices(&routes, destinations))
}

fn routed_interface_indices(routes: &[Route], destinations: &[Ipv4Addr]) -> BTreeSet<u32> {
    let mut usable = BTreeSet::new();
    for destination in destinations {
        let destination = IpAddr::V4(*destination);
        let mut best_by_interface = std::collections::BTreeMap::<u32, &Route>::new();
        for route in routes {
            let Some(index) = route.if_index().filter(|index| *index != 0) else {
                continue;
            };
            if !route.contains(&destination) {
                continue;
            }
            best_by_interface
                .entry(index)
                .and_modify(|best| {
                    if route.prefix() > best.prefix() {
                        *best = route;
                    }
                })
                .or_insert(route);
        }
        usable.extend(
            best_by_interface
                .into_iter()
                .filter(|(_, route)| route.kind() == RouteKind::Unicast)
                .map(|(index, _)| index),
        );
    }
    usable
}

/// Resolve an interface name to its kernel index.
pub fn interface_index(name: &str) -> io::Result<u32> {
    if_nametoindex(name).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("no such interface: {name}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_names_are_recognised() {
        for name in ["utun0", "utun6", "utun12", "ppp0", "tap1", "tun3", "ipsec0"] {
            assert!(is_tunnel_name(name), "{name}");
        }
        for name in ["en0", "en7", "lo0", "bridge0", "awdl0"] {
            assert!(!is_tunnel_name(name), "{name}");
        }
    }

    #[test]
    fn physical_candidate_rules() {
        let base = InterfaceInfo {
            name: "en7".to_owned(),
            index: 26,
            ipv4: vec![Ipv4Addr::new(192, 168, 8, 164)],
            is_up: true,
            is_loopback: false,
            is_tunnel: false,
        };
        assert!(is_physical_candidate(&base));

        let down = InterfaceInfo {
            is_up: false,
            ..base.clone()
        };
        assert!(!is_physical_candidate(&down));

        let tunnel = InterfaceInfo {
            name: "utun6".to_owned(),
            is_tunnel: true,
            ..base.clone()
        };
        assert!(!is_physical_candidate(&tunnel));

        let no_addr = InterfaceInfo {
            ipv4: vec![],
            ..base
        };
        assert!(!is_physical_candidate(&no_addr));
    }

    #[test]
    fn route_selection_requires_a_same_interface_longest_prefix() {
        let destination = Ipv4Addr::new(116, 162, 157, 195);
        let routes = vec![
            Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).with_if_index(28),
            Route::new(IpAddr::V4(Ipv4Addr::new(192, 168, 4, 0)), 22).with_if_index(14),
            Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                .with_gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 8, 1)))
                .with_if_index(26),
        ];
        let routed = routed_interface_indices(&routes, &[destination]);
        assert!(routed.contains(&26));
        assert!(!routed.contains(&14));

        let rejecting = Route::new(IpAddr::V4(destination), 32)
            .with_kind(RouteKind::Unreachable)
            .with_if_index(26);
        let mut routes_with_reject = routes;
        routes_with_reject.push(rejecting);
        let routed = routed_interface_indices(&routes_with_reject, &[destination]);
        assert!(!routed.contains(&26));
        assert!(!routed.contains(&14));
    }

    #[test]
    fn enumeration_is_read_only_and_finds_loopback() {
        // This reads real kernel state. It must not modify anything, and it
        // must always find at least the loopback interface on macOS.
        let list = enumerate_interfaces().expect("getifaddrs should succeed");
        assert!(!list.is_empty());
        let lo = list.iter().find(|i| i.is_loopback);
        assert!(lo.is_some(), "expected a loopback interface");
        let lo = lo.unwrap();
        assert!(lo.ipv4.contains(&Ipv4Addr::LOCALHOST));
        assert!(lo.index > 0, "loopback must have a kernel index");
        // Names are sorted and unique.
        let mut names: Vec<&str> = list.iter().map(|i| i.name.as_str()).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count);
    }

    /// Host-specific evidence, run explicitly with --ignored --nocapture.
    /// No packets are sent and no route is changed.
    #[test]
    #[ignore = "prints the current host's read-only route snapshot"]
    fn inspect_system_route_scope_and_kind() {
        let mut manager = RouteManager::new().unwrap();
        let routes = manager.list().unwrap();
        assert!(!routes.is_empty());
        for route in routes.iter().filter(|route| {
            route.destination().is_ipv4()
                && (route.prefix() == 0 || route.kind() != RouteKind::Unicast)
        }) {
            assert!(route.if_index().is_some_and(|index| index > 0));
            assert!(route.if_name().is_some());
            println!("{route:?}");
        }
        let destination = Ipv4Addr::new(8, 8, 8, 8);
        let routed = routed_interface_indices(&routes, &[destination]);
        for interface in enumerate_interfaces()
            .unwrap()
            .into_iter()
            .filter(|interface| interface.is_physical_candidate() && !interface.is_loopback)
        {
            println!(
                "physical candidate {} index={} route_to_{}={}",
                interface.name,
                interface.index,
                destination,
                routed.contains(&interface.index)
            );
        }
    }

    #[test]
    fn unknown_interface_index_is_an_error() {
        assert!(interface_index("definitely-not-an-interface").is_err());
        assert!(interface_index("lo0").is_ok());
    }
}
