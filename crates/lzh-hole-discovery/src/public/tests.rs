use super::*;
use crate::stun::{ATTR_MAPPED_ADDRESS, MAGIC_COOKIE, MSG_BINDING_SUCCESS};
use std::net::Ipv4Addr;

fn server() -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 3478)
}
fn endpoint(port: u16) -> Endpoint {
    Endpoint::new(Ipv4Addr::new(210, 22, 105, 194), port)
}
fn response(transaction: [u8; 12], mapped: Endpoint) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MSG_BINDING_SUCCESS.to_be_bytes());
    out.extend_from_slice(&12_u16.to_be_bytes());
    out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(&transaction);
    out.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
    out.extend_from_slice(&8_u16.to_be_bytes());
    out.extend_from_slice(&[0, 1]);
    out.extend_from_slice(&mapped.port.to_be_bytes());
    out.extend_from_slice(&mapped.ip.octets());
    out
}

#[test]
fn stun_is_socket_transaction_and_source_specific_and_bad_replies_do_not_consume_work() {
    let mut public = PublicDiscovery::new();
    assert!(public.add_transport(1, vec![server()], 0));
    assert!(public.add_transport(2, vec![server()], 0));
    let a = public.start_stun(1, [1; 12], 0).unwrap().unwrap();
    let b = public.start_stun(2, [2; 12], 0).unwrap().unwrap();
    assert_eq!(a.transport, 1);
    assert_eq!(&a.packet[8..20], &[1; 12]);
    assert_eq!(b.transport, 2);
    let data = response([1; 12], endpoint(40_001));
    assert_eq!(
        public.receive_stun(2, server(), &data, 1),
        Err(StunError::BadTransaction)
    );
    let wrong = SocketAddrV4::new(*server().ip(), 1234);
    assert!(matches!(
        public.receive_stun(1, wrong, &data, 1),
        Err(StunError::BadSource { .. })
    ));
    assert!(public.own_mappings(1).is_empty());
    let mapping = public.receive_stun(1, server(), &data, 2).unwrap().unwrap();
    assert_eq!(mapping.transport, 1);
    assert_eq!(mapping.endpoint, endpoint(40_001));
    public
        .receive_stun(2, server(), &response([2; 12], endpoint(40_002)), 3)
        .unwrap()
        .unwrap();
    assert_eq!(public.own_mappings(3).len(), 2);
    assert_eq!(public.own_mappings(120_002).len(), 1);
    public.remove_transport(2);
    assert!(public.own_mappings(120_002).is_empty());
}

#[test]
fn timeout_round_robin_send_failure_and_bounded_transport_lifecycle() {
    let mut public = PublicDiscovery::new();
    let other = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 3478);
    assert!(public.add_transport(1, vec![server(), other], 0));
    assert!(!public.add_transport(1, vec![server()], 0));
    assert_eq!(
        public.start_stun(1, [1; 12], 0).unwrap().unwrap().server,
        server()
    );
    assert!(public.start_stun(1, [2; 12], 2_999).unwrap().is_none());
    public.expire_sockets(3_000);
    assert_eq!(public.consecutive_timeouts(1), Some(1));
    assert!(public.start_stun(1, [2; 12], 7_999).unwrap().is_none());
    assert_eq!(
        public
            .start_stun(1, [2; 12], 8_000)
            .unwrap()
            .unwrap()
            .server,
        other
    );
    public.stun_send_failed(1, [1; 12], 8_001);
    assert!(public.start_stun(1, [3; 12], 8_001).unwrap().is_none());
    public.stun_send_failed(1, [2; 12], 8_001);
    assert!(public.start_stun(1, [3; 12], 13_000).unwrap().is_none());
    assert!(public.start_stun(1, [3; 12], 13_001).unwrap().is_some());
    public.remove_transport(1);
    assert_eq!(
        public.receive_stun(1, server(), &response([3; 12], endpoint(5)), 13_002),
        Ok(None)
    );
    for id in 1..=MAX_PUBLIC_TRANSPORTS as u64 {
        assert!(public.add_transport(id, vec![server()], 0));
    }
    assert!(!public.add_transport(99, vec![server()], 0));
}

#[test]
fn mappings_are_bounded_fresh_and_rejected_mappings_do_not_discard_transaction() {
    let mut public = PublicDiscovery::new();
    public.add_transport(1, vec![server()], 0);
    for i in 0..=MAX_SOCKET_MAPPINGS {
        let now = i as u64 * STUN_INTERVAL_MS;
        let tx = [i as u8; 12];
        public.start_stun(1, tx, now).unwrap().unwrap();
        if i == 0 {
            assert!(
                public
                    .receive_stun(
                        1,
                        server(),
                        &response(tx, Endpoint::new(Ipv4Addr::new(198, 18, 0, 1), 5)),
                        now
                    )
                    .is_err()
            );
        }
        public
            .receive_stun(1, server(), &response(tx, endpoint(40_000 + i as u16)), now)
            .unwrap()
            .unwrap();
    }
    assert_eq!(public.own_mappings(40_000).len(), MAX_SOCKET_MAPPINGS);
    assert!(
        !public
            .own_mappings(40_000)
            .iter()
            .any(|m| m.endpoint == endpoint(40_000))
    );
    public.expire_sockets(200_000);
    assert!(public.own_mappings(200_000).is_empty());
}

/// The node-level verdict is reported per socket and stays available after the
/// per-relationship split, because every relationship advertises the same
/// node-level mapping behaviour.
#[test]
fn mapping_behaviors_reports_every_registered_socket() {
    let mut public = PublicDiscovery::new();
    assert!(public.mapping_behaviors().is_empty());
    assert_eq!(public.consecutive_timeouts(1), None);
    public.add_transport(1, vec![server()], 0);
    public.add_transport(2, vec![server()], 0);
    let behaviors = public.mapping_behaviors();
    assert_eq!(behaviors.len(), 2);
    assert_eq!(behaviors[0].0, 1);
    assert_eq!(behaviors[1].0, 2);
    assert_eq!(public.mapping_behavior(1), behaviors[0].1);
    assert_eq!(public.mapping_behavior(2), behaviors[1].1);
    public.remove_transport(1);
    assert_eq!(
        public
            .mapping_behaviors()
            .iter()
            .map(|(transport, _)| *transport)
            .collect::<Vec<_>>(),
        vec![2]
    );
}
