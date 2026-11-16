//! DHCP-provided resolvers for one interface.
//!
//! The host resolver configuration is deliberately never read: a Fake-IP proxy
//! replaces it, and an answer that only works while that proxy is up is not an
//! answer this project may use. A DHCP lease is different. It is what the
//! network operator handed this interface, so when the gateway itself does not
//! run a resolver, option 6 is the right place to learn one.
//!
//! Only the lease of the interface that will carry the query is read, and only
//! the DNS option of that lease. Nothing here decides whether an answer may be
//! used; that policy lives in the caller.

use std::io;
use std::net::Ipv4Addr;

use system_configuration::core_foundation::base::{CFType, TCFType};
use system_configuration::core_foundation::data::CFData;
use system_configuration::core_foundation::dictionary::CFDictionary;
use system_configuration::core_foundation::propertylist::CFPropertyList;
use system_configuration::core_foundation::string::CFString;
use system_configuration::dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder};

/// Most resolvers one lease may contribute.
pub const MAX_DHCP_DNS_SERVERS: usize = 4;

const SERVICE_INTERFACE_PATTERN: &str = "Setup:/Network/Service/.*/Interface";
const SERVICE_DHCP_PREFIX: &str = "State:/Network/Service/";
const SERVICE_DHCP_SUFFIX: &str = "/DHCP";
const KEY_DEVICE_NAME: &str = "DeviceName";
/// DHCP option 6, under the name SystemConfiguration stores it.
const KEY_DNS_OPTION: &str = "Option_6";

type StringDictionary = CFDictionary<CFString, CFType>;

/// Resolvers the DHCP lease of one interface offers, in lease order.
///
/// An interface with no lease, no DNS option or an unusable option yields an
/// empty list rather than an error: not knowing a resolver is an ordinary
/// state that the caller answers by asking the gateway instead. Only a
/// SystemConfiguration session that cannot be opened at all is an error.
pub fn dhcp_dns_servers(interface: &str) -> io::Result<Vec<Ipv4Addr>> {
    let Some(store) = SCDynamicStoreBuilder::new("lzh-hole").build() else {
        return Err(io::Error::other(
            "cannot open a SystemConfiguration dynamic store",
        ));
    };
    let Some(service) = service_for_interface(&store, interface) else {
        return Ok(Vec::new());
    };
    let key = format!("{SERVICE_DHCP_PREFIX}{service}{SERVICE_DHCP_SUFFIX}");
    let Some(lease) = store.get(key.as_str()) else {
        return Ok(Vec::new());
    };
    let Some(lease) = typed_dictionary(&lease) else {
        return Ok(Vec::new());
    };
    let Some(option) = lease
        .find(CFString::new(KEY_DNS_OPTION))
        .and_then(|value| value.downcast::<CFData>())
    else {
        return Ok(Vec::new());
    };
    Ok(parse_dns_option(option.bytes()))
}

/// The network service whose interface is the one we were asked about.
fn service_for_interface(store: &SCDynamicStore, interface: &str) -> Option<String> {
    let keys = store.get_keys(SERVICE_INTERFACE_PATTERN)?;
    for key in keys.iter() {
        let key = key.to_string();
        let Some(service) = service_id_from_key(&key) else {
            continue;
        };
        let Some(entry) = store.get(key.as_str()) else {
            continue;
        };
        let Some(entry) = typed_dictionary(&entry) else {
            continue;
        };
        let Some(device) = entry
            .find(CFString::new(KEY_DEVICE_NAME))
            .and_then(|value| value.downcast::<CFString>())
        else {
            continue;
        };
        if device == interface {
            return Some(service.to_owned());
        }
    }
    None
}

/// The service identifier inside one Setup:/Network/Service/<id>/Interface key.
fn service_id_from_key(key: &str) -> Option<&str> {
    let mut parts = key.split('/');
    match (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) {
        (
            Some("Setup:"),
            Some("Network"),
            Some("Service"),
            Some(service),
            Some("Interface"),
            None,
        ) if !service.is_empty() => Some(service),
        _ => None,
    }
}

/// A typed view of one property list already known to be a dictionary.
///
/// The untyped dictionary and the typed view share one reference; only the
/// phantom key and value types differ.
fn typed_dictionary(plist: &CFPropertyList) -> Option<StringDictionary> {
    let untyped = plist.downcast::<CFDictionary>()?;
    // SAFETY: the untyped value is a live CFDictionary, and
    // CFDictionary<CFString, CFType> has the same concrete reference type and
    // the same type ID. The view retains the dictionary under the get rule, so
    // it cannot outlive the reference it was built from.
    Some(unsafe { StringDictionary::wrap_under_get_rule(untyped.as_concrete_TypeRef()) })
}

/// IPv4 resolvers inside one DHCP option 6 payload.
///
/// Option 6 is a bare concatenation of four-byte addresses, so a length that is
/// not a multiple of four is malformed rather than fatal: the whole addresses
/// in front of the remainder are still usable.
fn parse_dns_option(bytes: &[u8]) -> Vec<Ipv4Addr> {
    let (chunks, _remainder) = bytes.as_chunks::<4>();
    let mut servers: Vec<Ipv4Addr> = Vec::new();
    for chunk in chunks {
        let address = Ipv4Addr::from(*chunk);
        if usable_resolver(address)
            && !servers.contains(&address)
            && servers.len() < MAX_DHCP_DNS_SERVERS
        {
            servers.push(address);
        }
    }
    servers
}

/// Whether a leased resolver address is one we would send a query to.
///
/// Loopback is refused because a local stub is exactly the resolver this
/// project must not depend on, and the Fake-IP range is refused because an
/// interface-bound socket cannot reach it.
fn usable_resolver(address: Ipv4Addr) -> bool {
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || address.is_broadcast()
        || is_fake_ip(address))
}

fn is_fake_ip(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    octets[0] == 198 && octets[1] & 0xfe == 18
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_six_is_a_bare_list_of_four_byte_addresses() {
        let bytes = [192, 168, 0, 252, 223, 5, 5, 5];
        assert_eq!(
            parse_dns_option(&bytes),
            vec![Ipv4Addr::new(192, 168, 0, 252), Ipv4Addr::new(223, 5, 5, 5)]
        );
        // A trailing partial address is malformed, not a reason to drop the
        // whole addresses in front of it.
        assert_eq!(
            parse_dns_option(&[192, 168, 0, 252, 223]),
            vec![Ipv4Addr::new(192, 168, 0, 252)]
        );
        assert!(parse_dns_option(&[]).is_empty());
        assert!(parse_dns_option(&[1, 2, 3]).is_empty());
    }

    #[test]
    fn duplicate_and_unusable_resolvers_are_dropped() {
        let bytes = [
            127, 0, 0, 1, // a local stub is not a resolver we may depend on
            192, 168, 0, 252, 192, 168, 0, 252, // duplicate
            0, 0, 0, 0, // unspecified
            224, 0, 0, 1, // multicast
            255, 255, 255, 255, // broadcast
            198, 18, 0, 1, // Fake-IP range
            198, 19, 0, 1, // Fake-IP range
        ];
        assert_eq!(
            parse_dns_option(&bytes),
            vec![Ipv4Addr::new(192, 168, 0, 252)]
        );
    }

    #[test]
    fn a_lease_contributes_at_most_the_documented_number_of_resolvers() {
        let mut bytes = Vec::new();
        for last in 1..=8u8 {
            bytes.extend_from_slice(&[10, 0, 0, last]);
        }
        let servers = parse_dns_option(&bytes);
        assert_eq!(servers.len(), MAX_DHCP_DNS_SERVERS);
        assert_eq!(servers[0], Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn only_a_service_interface_key_yields_an_identifier() {
        let key = "Setup:/Network/Service/5FD2AFD4-A6EF/Interface";
        assert_eq!(service_id_from_key(key), Some("5FD2AFD4-A6EF"));
        for key in [
            "",
            "Setup:/Network/Service//Interface",
            "Setup:/Network/Service/ABC",
            "Setup:/Network/Service/ABC/DNS",
            "State:/Network/Service/ABC/Interface",
            "Setup:/Network/Service/ABC/Interface/Extra",
        ] {
            assert_eq!(service_id_from_key(key), None, "{key}");
        }
    }

    #[test]
    fn a_resolver_must_be_a_unicast_address_we_could_send_to() {
        assert!(usable_resolver(Ipv4Addr::new(192, 168, 0, 252)));
        assert!(usable_resolver(Ipv4Addr::new(223, 5, 5, 5)));
        assert!(usable_resolver(Ipv4Addr::new(169, 254, 1, 1)));
        for address in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(127, 0, 0, 53),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv4Addr::new(198, 19, 255, 255),
        ] {
            assert!(!usable_resolver(address), "{address}");
        }
        // 198.20.0.0 is outside the Fake-IP range and stays usable.
        assert!(usable_resolver(Ipv4Addr::new(198, 20, 0, 1)));
    }

    /// Host-specific evidence, run explicitly with --ignored --nocapture.
    /// Only SystemConfiguration state is read; no packet is sent.
    #[test]
    #[ignore = "prints the current host's DHCP resolvers"]
    fn inspect_dhcp_resolvers() {
        for snapshot in crate::interface::enumerate_interface_prefixes().expect("getifaddrs") {
            let interface = &snapshot.interface;
            if !interface.is_physical_candidate() || interface.is_loopback {
                continue;
            }
            println!(
                "{} index={} dhcp_dns={:?}",
                interface.name,
                interface.index,
                dhcp_dns_servers(&interface.name)
            );
        }
    }
}
