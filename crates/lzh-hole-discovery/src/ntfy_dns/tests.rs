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
fn a_candidate_without_a_way_out_is_skipped_rather_than_fatal() {
    // Two real adapters: the first cannot reach the server from any alias, so
    // planning must fall through to the second instead of failing outright.
    let first = snapshot(
        "en0",
        14,
        &[(Ipv4Addr::new(192, 168, 1, 2), 24)],
        true,
        false,
        false,
    );
    let second = snapshot(
        "en1",
        15,
        &[(Ipv4Addr::new(192, 168, 31, 156), 24)],
        true,
        false,
        false,
    );
    let server = Ipv4Addr::new(192, 168, 31, 1);
    assert!(plan_for(&first, &GatewayDnsConfig::default().with_server(server)).is_err());
    let plan = plan_for(&second, &GatewayDnsConfig::default().with_server(server)).unwrap();
    assert_eq!(plan.interface, "en1");
    assert_eq!(plan.bind_ip, Ipv4Addr::new(192, 168, 31, 156));
    assert_eq!(plan.server, SocketAddrV4::new(server, 53));
}

#[test]
fn a_source_address_must_share_a_link_with_the_server() {
    let gateway = Ipv4Addr::new(192, 168, 31, 1);
    let dual = snapshot(
        "en0",
        14,
        &[
            (Ipv4Addr::new(192, 168, 1, 2), 24),
            (Ipv4Addr::new(192, 168, 31, 10), 24),
        ],
        true,
        false,
        false,
    );
    // The alias on the gateway link wins over the unrelated alias.
    assert_eq!(
        choose_source(&dual, gateway, None).unwrap(),
        Ipv4Addr::new(192, 168, 31, 10)
    );
    assert_eq!(
        choose_source(&dual, gateway, Some(Ipv4Addr::new(192, 168, 31, 10))).unwrap(),
        Ipv4Addr::new(192, 168, 31, 10)
    );
    // An explicitly bound address that cannot reach the server is refused.
    assert!(matches!(
        choose_source(&dual, gateway, Some(Ipv4Addr::new(192, 168, 1, 2))),
        Err(ResolveError::NoSource { .. })
    ));

    let single = snapshot(
        "en0",
        14,
        &[(Ipv4Addr::new(192, 168, 1, 2), 24)],
        true,
        false,
        false,
    );
    assert!(matches!(
        choose_source(&single, gateway, None),
        Err(ResolveError::NoSource { .. })
    ));
}

/// Host-specific evidence, run explicitly with --ignored --nocapture.
/// No packet is sent; only interfaces and routes are read.
#[test]
#[ignore = "prints the current host's ntfy DNS plan"]
fn inspect_query_plan() {
    println!(
        "default: {:?}",
        GatewayDnsResolver::new(GatewayDnsConfig::default()).plan()
    );
    for name in ["en0", "en1", "awdl0", "lo0", "utun0"] {
        let resolver = GatewayDnsResolver::new(GatewayDnsConfig {
            interface: Some(name.to_owned()),
            bind_ip: None,
            server: None,
        });
        println!("{name}: {:?}", resolver.plan());
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
        resolver.plan(),
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
