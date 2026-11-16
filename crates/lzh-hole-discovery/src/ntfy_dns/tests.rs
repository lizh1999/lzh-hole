use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::str::FromStr;

use lzh_hole_net::interface::{InterfaceInfo, InterfacePrefixes, Ipv4Prefix};
use reqwest::dns::Resolve as _;

use super::*;

fn snapshot(
    name: &str,
    index: u32,
    addresses: &[(Ipv4Addr, u8)],
    is_up: bool,
    is_loopback: bool,
    is_tunnel: bool,
) -> InterfacePrefixes {
    InterfacePrefixes {
        interface: InterfaceInfo {
            name: name.to_owned(),
            index,
            ipv4: addresses.iter().map(|(ip, _)| *ip).collect(),
            is_up,
            is_loopback,
            is_tunnel,
        },
        ipv4_prefixes: addresses
            .iter()
            .map(|(ip, prefix_len)| Ipv4Prefix {
                address: *ip,
                prefix_len: *prefix_len,
            })
            .collect(),
    }
}

fn awdl() -> InterfacePrefixes {
    snapshot(
        "awdl0",
        12,
        &[(Ipv4Addr::new(169, 254, 44, 9), 16)],
        true,
        false,
        false,
    )
}

fn lan() -> InterfacePrefixes {
    snapshot(
        "en0",
        14,
        &[(Ipv4Addr::new(192, 168, 31, 10), 24)],
        true,
        false,
        false,
    )
}

fn sources(entries: &[(u32, Ipv4Addr)]) -> BTreeSet<(u32, Ipv4Addr)> {
    entries.iter().copied().collect()
}

#[test]
fn a_requested_interface_must_be_a_usable_physical_one() {
    let snapshots = vec![
        awdl(),
        lan(),
        snapshot("en5", 15, &[], true, false, false),
        snapshot("lo0", 1, &[(Ipv4Addr::LOCALHOST, 8)], true, true, false),
        snapshot(
            "utun4",
            9,
            &[(Ipv4Addr::new(10, 203, 0, 1), 32)],
            true,
            false,
            true,
        ),
        snapshot(
            "en6",
            16,
            &[(Ipv4Addr::new(192, 168, 9, 4), 24)],
            false,
            false,
            false,
        ),
    ];
    assert_eq!(
        candidate_interfaces(&snapshots, Some("en0")).unwrap()[0]
            .interface
            .name,
        "en0"
    );
    for name in ["awdl0", "en5", "lo0", "utun4", "en6", "en9"] {
        assert!(
            matches!(
                candidate_interfaces(&snapshots, Some(name)),
                Err(ResolveError::UnknownInterface(_))
            ),
            "{name} should be refused"
        );
    }

    // Without a name every usable adapter is a candidate, in snapshot order,
    // and a link-local-only adapter is never one of them.
    let names: Vec<&str> = candidate_interfaces(&snapshots, None)
        .unwrap()
        .iter()
        .map(|snapshot| snapshot.interface.name.as_str())
        .collect();
    assert_eq!(names, vec!["en0"]);
    assert!(candidate_interfaces(&[], None).unwrap().is_empty());
}

#[test]
fn a_configured_server_is_the_only_one_that_will_be_asked() {
    let configured = SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 252), 53);
    let config = GatewayDnsConfig::default().with_server(*configured.ip());
    let leased = [Ipv4Addr::new(223, 5, 5, 5)];
    // Neither the lease nor the gateway may displace an operator decision.
    assert_eq!(
        servers_for(&config, &leased, Some(Ipv4Addr::new(192, 168, 8, 1))),
        vec![configured]
    );
    // A configured port is preserved rather than forced back to 53.
    let config = GatewayDnsConfig {
        server: Some(SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 252), 5353)),
        ..GatewayDnsConfig::default()
    };
    assert_eq!(
        servers_for(&config, &leased, None),
        vec![SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 252), 5353)]
    );
}

#[test]
fn a_lease_outranks_the_gateway_and_the_list_stays_bounded() {
    let config = GatewayDnsConfig::default();
    let leased = [
        Ipv4Addr::new(192, 168, 0, 252),
        Ipv4Addr::new(192, 168, 0, 253),
    ];
    let gateway = Ipv4Addr::new(192, 168, 8, 1);
    assert_eq!(
        servers_for(&config, &leased, Some(gateway)),
        vec![
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 252), DNS_PORT),
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 253), DNS_PORT),
            SocketAddrV4::new(gateway, DNS_PORT),
        ]
    );
    // A gateway that the lease already lists is not asked twice.
    assert_eq!(
        servers_for(&config, &[gateway], Some(gateway)),
        vec![SocketAddrV4::new(gateway, DNS_PORT)]
    );
    // A network with no lease still gets the gateway.
    assert_eq!(
        servers_for(&config, &[], Some(gateway)),
        vec![SocketAddrV4::new(gateway, DNS_PORT)]
    );
    // A network with neither contributes nothing rather than inventing one.
    assert!(servers_for(&config, &[], None).is_empty());

    let many: Vec<Ipv4Addr> = (1..=8u8)
        .map(|last| Ipv4Addr::new(10, 0, 0, last))
        .collect();
    let servers = servers_for(&config, &many, Some(gateway));
    assert_eq!(servers.len(), MAX_PLAN_SERVERS);
    assert_eq!(
        servers[0],
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), DNS_PORT)
    );
}

#[test]
fn a_resolver_on_another_subnet_is_reachable_through_the_interface_route() {
    // The regression this exists for: a leased resolver on 192.168.0.0/24
    // while the interface address is on 192.168.8.0/23. A same-link rule
    // refuses it, and refusing it makes the documented escape hatch useless on
    // exactly the networks that need it.
    let interface = snapshot(
        "en7",
        26,
        &[(Ipv4Addr::new(192, 168, 8, 164), 23)],
        true,
        false,
        false,
    );
    let leased = Ipv4Addr::new(192, 168, 0, 252);
    let routed = sources(&[(26, Ipv4Addr::new(192, 168, 8, 164))]);
    assert_eq!(
        choose_source(&interface, &routed, leased, None).unwrap(),
        Ipv4Addr::new(192, 168, 8, 164)
    );
    assert_eq!(
        choose_source(
            &interface,
            &routed,
            leased,
            Some(Ipv4Addr::new(192, 168, 8, 164))
        )
        .unwrap(),
        Ipv4Addr::new(192, 168, 8, 164)
    );
    // Without a route the same address is refused, so a dead alias cannot be
    // used just because it happens to be configured.
    assert!(matches!(
        choose_source(&interface, &BTreeSet::new(), leased, None),
        Err(ResolveError::NoSource { .. })
    ));
}

#[test]
fn an_alias_on_the_server_own_link_wins_over_an_unrelated_routable_alias() {
    let gateway = Ipv4Addr::new(192, 168, 31, 1);
    let wan = Ipv4Addr::new(192, 168, 1, 2);
    let lan = Ipv4Addr::new(192, 168, 31, 10);
    let dual = snapshot("en0", 14, &[(wan, 24), (lan, 24)], true, false, false);
    let both = sources(&[(14, wan), (14, lan)]);
    // Both aliases have a route; the one that shares the server link wins.
    assert_eq!(choose_source(&dual, &both, gateway, None).unwrap(), lan);
    // An explicitly bound address that has no route is still refused.
    let only_lan = sources(&[(14, lan)]);
    assert!(matches!(
        choose_source(&dual, &only_lan, gateway, Some(wan)),
        Err(ResolveError::NoSource { .. })
    ));
    // A source on another interface never satisfies this interface.
    assert!(matches!(
        choose_source(&dual, &sources(&[(15, lan)]), gateway, None),
        Err(ResolveError::NoSource { .. })
    ));
}

#[test]
fn a_loopback_address_is_never_a_dns_source() {
    let interface = snapshot(
        "en0",
        14,
        &[
            (Ipv4Addr::LOCALHOST, 8),
            (Ipv4Addr::new(192, 168, 31, 10), 24),
        ],
        true,
        false,
        false,
    );
    let both = sources(&[
        (14, Ipv4Addr::LOCALHOST),
        (14, Ipv4Addr::new(192, 168, 31, 10)),
    ]);
    let server = Ipv4Addr::new(192, 168, 31, 1);
    assert_eq!(
        choose_source(&interface, &both, server, None).unwrap(),
        Ipv4Addr::new(192, 168, 31, 10)
    );
}

/// Host-specific evidence, run explicitly with --ignored --nocapture.
/// No packet is sent; only interfaces, routes and DHCP leases are read.
#[test]
#[ignore = "prints the current host's ntfy DNS plans"]
fn inspect_query_plans() {
    println!(
        "default: {:#?}",
        GatewayDnsResolver::new(GatewayDnsConfig::default()).plans()
    );
    for name in ["en0", "en1", "en7", "awdl0", "lo0", "utun0"] {
        let resolver = GatewayDnsResolver::new(GatewayDnsConfig {
            interface: Some(name.to_owned()),
            bind_ip: None,
            server: None,
        });
        println!("{name}: {:?}", resolver.plans());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn an_unusable_plan_fails_before_any_packet_is_sent() {
    let resolver = GatewayDnsResolver::new(GatewayDnsConfig {
        interface: Some("definitely-not-an-interface".to_owned()),
        bind_ip: None,
        server: None,
    });
    assert!(matches!(
        resolver.plans(),
        Err(ResolveError::UnknownInterface(_))
    ));
    let name = reqwest::dns::Name::from_str("ntfy.sh").unwrap();
    let error = match resolver.resolve(name).await {
        Ok(_) => panic!("an unusable plan must not produce addresses"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("not a usable physical IPv4 interface"),
        "{error}"
    );
}
