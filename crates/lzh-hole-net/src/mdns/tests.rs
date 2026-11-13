use super::*;

fn fixture() -> (MdnsClient, OperationId, ServiceKey, ServiceKey) {
    let mut client = MdnsClient::new();
    let operation = OperationId(1);
    let root = ServiceKey {
        interface_index: 4,
        name: String::new(),
        service_type: "_test._udp".into(),
        domain: "local.".into(),
    };
    let good = ServiceKey {
        name: "good".into(),
        ..root.clone()
    };
    let bad = ServiceKey {
        name: "bad".into(),
        ..root.clone()
    };
    for key in [root, good.clone(), bad.clone()] {
        let (token, reference) = client
            .allocate(Some(operation), Some(key.clone()), false)
            .unwrap();
        client.refs.insert(token, reference);
        if key.name.is_empty() {
            continue;
        }
        client
            .watched
            .insert((operation, key.clone()), Instant::now() + REFRESH_INTERVAL);
        client.services.insert(
            (operation, key.clone()),
            Cached {
                record: ServiceRecord {
                    key,
                    port: 9,
                    txt: vec![1, b'x'],
                    addresses: vec![],
                    observed_at: Instant::now(),
                    srv_ttl: None,
                    txt_ttl: None,
                },
                expires: BTreeMap::new(),
                host: "host.local.".into(),
                srv_expires: None,
                txt_expires: None,
            },
        );
    }
    (client, operation, good, bad)
}
#[test]
fn malformed_or_unresolved_instance_never_cancels_other_instances() {
    let failures = [
        Raw::Record(ADD, 4, 0, 16, vec![3, b'x'], 120),
        Raw::Record(ADD, 4, 0, 33, vec![0; 8], 120),
        Raw::Resolved(
            4,
            0,
            "bad._test._udp.local.".into(),
            "host.local.".into(),
            0,
            vec![],
        ),
        Raw::Resolved(4, -65568, String::new(), String::new(), 0, vec![]),
        Raw::Record(0, 4, -65563, 1, vec![], 0),
    ];
    for failure in failures {
        let (mut client, operation, good, bad) = fixture();
        client.process_callback(3, failure);
        assert!(client.refs.contains_key(&1));
        assert!(client.refs.contains_key(&2));
        assert!(!client.refs.contains_key(&3));
        assert!(client.services.contains_key(&(operation, good)));
        assert!(!client.services.contains_key(&(operation, bad.clone())));
        assert!(client.watched.contains_key(&(operation, bad.clone())));
        assert_eq!(
            client.events.pop_front(),
            Some(MdnsEvent::Remove {
                operation,
                key: bad
            })
        );
        assert!(client.events.is_empty());
    }
    let (mut client, operation, good, bad) = fixture();
    client.fail_reference(3, -65568);
    assert!(client.refs.contains_key(&1));
    assert!(client.services.contains_key(&(operation, good)));
    assert!(!client.services.contains_key(&(operation, bad)));
    client.fail_reference(1, -65563);
    assert!(client.refs.is_empty());
    assert!(client.watched.is_empty());
    assert!(matches!(
        client.events.back(),
        Some(MdnsEvent::Error { .. })
    ));
}
#[test]
fn scan_deadline_is_persistent_under_high_frequency_service_events() {
    let mut client = MdnsClient::new();
    let start = client.next_scan;
    assert!(client.claim_scan(start));
    let deadline = client.next_scan;
    for offset in 0..1000 {
        assert!(!client.claim_scan(start + Duration::from_micros(offset)));
        assert_eq!(client.next_scan, deadline);
    }
    assert!(client.claim_scan(deadline));
    assert_eq!(client.next_scan, deadline + SCAN_INTERVAL);
}
#[tokio::test(flavor = "current_thread")]
async fn cancelling_recv_does_not_reset_or_run_the_scan_deadline() {
    use std::future::Future;
    let mut client = MdnsClient::new();
    client.next_scan = Instant::now() + Duration::from_secs(60);
    let deadline = client.next_scan;
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    for _ in 0..1000 {
        let mut recv = std::pin::pin!(client.recv());
        assert!(recv.as_mut().poll(&mut cx).is_pending());
    }
    assert_eq!(client.next_scan, deadline);
}
#[test]
fn identical_records_can_return_after_local_ttl_expiry_without_ptr_change() {
    let (mut client, operation, good, _) = fixture();
    let start = Instant::now();
    let address = Ipv4Addr::new(192, 168, 1, 2);
    let cached = client.services.get_mut(&(operation, good.clone())).unwrap();
    cached
        .expires
        .insert(address, start + Duration::from_secs(2));
    cached.srv_expires = Some(start + Duration::from_secs(2));
    cached.txt_expires = Some(start + Duration::from_secs(2));
    client
        .watched
        .insert((operation, good.clone()), start + REFRESH_INTERVAL);
    client.expire_records(start + Duration::from_secs(3));
    let cached = &client.services[&(operation, good.clone())];
    assert!(cached.record.addresses.is_empty());
    assert_eq!(cached.record.port, 0);
    assert!(client.watched.contains_key(&(operation, good.clone())));
    assert!(
        client
            .due_refreshes(start + Duration::from_secs(3))
            .is_empty()
    );
    let due = client.due_refreshes(start + REFRESH_INTERVAL);
    assert!(due.contains(&(operation, good.clone())));
    for _ in 0..1000 {
        assert!(client.due_refreshes(start + REFRESH_INTERVAL).is_empty());
    }
    client.process_callback(2, Raw::Record(ADD, 4, 0, 1, address.octets().to_vec(), 120));
    client.process_callback(2, Raw::Record(ADD, 4, 0, 16, vec![1, b'x'], 120));
    let mut srv = vec![0, 0, 0, 0, 0, 9];
    srv.extend_from_slice(b"\x04host\x05local\0");
    client.process_callback(2, Raw::Record(ADD, 4, 0, 33, srv, 120));
    let cached = &client.services[&(operation, good)];
    assert_eq!(cached.record.addresses[0].address, address);
    assert_eq!(cached.record.port, 9);
    assert_eq!(cached.record.txt, vec![1, b'x']);
    assert_eq!(client.refs[&1].operation, operation);
}
#[test]
fn txt_is_bounded_and_binary() {
    assert!(validate_txt(&[]).is_ok());
    assert!(validate_txt(&[2, 0xff, 0]).is_ok());
    assert!(validate_txt(&[3, 1, 2]).is_err());
    assert!(validate_txt(&vec![0; TXT_LIMIT + 1]).is_err());
}
#[test]
fn callback_queue_is_bounded() {
    let queue = Rc::default();
    let context = Context {
        token: 1,
        queue: Rc::clone(&queue),
        registration: false,
    };
    for _ in 0..LIMIT + 1 {
        context.push(Raw::Registered(
            1,
            String::new(),
            String::new(),
            String::new(),
        ));
    }
    assert_eq!(queue.borrow().items.len(), LIMIT);
    assert!(queue.borrow().overflow);
}
#[test]
fn address_add_remove_ttl_and_wrong_scope() {
    let (mut client, operation, key, _) = fixture();
    client
        .handle(2, Raw::Record(ADD, 5, 0, 1, vec![192, 168, 1, 2], 120))
        .unwrap();
    assert!(client.events.is_empty());
    client
        .handle(2, Raw::Record(ADD, 4, 0, 1, vec![192, 168, 1, 2], 120))
        .unwrap();
    assert_eq!(
        client.services[&(operation, key.clone())]
            .record
            .addresses
            .len(),
        1
    );
    client
        .handle(2, Raw::Record(ADD, 4, 0, 1, vec![192, 168, 1, 2], 0))
        .unwrap();
    assert!(
        client.services[&(operation, key.clone())]
            .record
            .addresses
            .is_empty()
    );
    let mut srv = vec![0, 0, 0, 0, 0x12, 0x34];
    srv.extend_from_slice(b"\x04host\x05local\0");
    client
        .handle(2, Raw::Record(ADD, 4, 0, 33, srv.clone(), 60))
        .unwrap();
    let cached = &client.services[&(operation, key.clone())];
    assert_eq!(cached.record.port, 0x1234);
    assert_eq!(cached.record.srv_ttl, Some(60));
    client.handle(2, Raw::Record(0, 4, 0, 33, srv, 0)).unwrap();
    assert_eq!(client.services[&(operation, key)].record.port, 0);
    client.cancel(operation);
    assert!(client.refs.is_empty());
    assert!(client.services.is_empty());
    assert!(client.events.is_empty());
    client
        .handle(2, Raw::Registered(0, "late".into(), "".into(), "".into()))
        .unwrap();
    assert!(client.events.is_empty());
}
#[test]
fn srv_wire_parser_is_bounded_and_rejects_compression() {
    let mut bytes = vec![0, 0, 0, 0, 0, 9];
    bytes.extend_from_slice(b"\x03a.b\x05local\0");
    assert_eq!(parse_srv(&bytes).unwrap(), (9, "a\\046b.local.".into()));
    assert!(parse_srv(&[0, 0, 0, 0, 0, 9, 0xc0, 0]).is_err());
    assert!(parse_srv(&[0, 0, 0, 0, 0, 9, 3, b'a']).is_err());
    assert!(parse_srv(&[0; 262]).is_err());
    bytes.push(0);
    assert!(parse_srv(&bytes).is_err());
}
#[test]
fn browse_removal_cancels_children_and_preserves_root() {
    let (mut client, operation, key, other) = fixture();
    client.remove_service(operation, &other);
    client.events.clear();
    client
        .handle(
            1,
            Raw::Browse(
                0,
                4,
                0,
                key.name.clone(),
                key.service_type.clone(),
                key.domain.clone(),
            ),
        )
        .unwrap();
    assert_eq!(client.refs.len(), 1);
    assert_eq!(
        client.events.pop_front(),
        Some(MdnsEvent::Remove { operation, key })
    );
    client
        .handle(
            1,
            Raw::Browse(0, 0, -65563, String::new(), String::new(), String::new()),
        )
        .unwrap();
    assert!(client.refs.is_empty());
    assert_eq!(
        client.events.pop_front(),
        Some(MdnsEvent::Error {
            operation,
            code: -65563
        })
    );
}
#[tokio::test(flavor = "current_thread")]
async fn overflow_is_fail_closed_without_native_calls() {
    let mut client = MdnsClient::new();
    let (token, reference) = client.allocate(None, None, false).unwrap();
    client.refs.insert(token, reference);
    client.queue.borrow_mut().overflow = true;
    assert!(client.recv().await.is_err());
    assert!(client.refs.is_empty());
    assert!(!client.queue.borrow().overflow);
}
#[test]
fn callback_context_copies_binary_data_and_retains_registration_mapping() {
    let queue = Rc::default();
    let mut context = Box::new(Context {
        token: 7,
        queue: Rc::clone(&queue),
        registration: true,
    });
    let context_ptr = (&mut *context as *mut Context).cast();
    // SAFETY: valid test-owned strings and stable boxed callback context.
    unsafe {
        registered(
            ptr::null_mut(),
            ADD,
            0,
            c"renamed (2)".as_ptr(),
            c"_test._udp".as_ptr(),
            c"local.".as_ptr(),
            context_ptr,
        );
    }
    let Some((7, Raw::Registered(0, name, _, _))) = queue.borrow_mut().items.pop_front() else {
        panic!("missing callback");
    };
    assert_eq!(name, "renamed (2)");
    let txt = [2u8, 0xff, 0];
    // SAFETY: valid boxed context, DNS strings and txt.len() readable bytes.
    unsafe {
        resolved(
            ptr::null_mut(),
            0,
            4,
            0,
            c"instance._test._udp.local.".as_ptr(),
            c"host.local.".as_ptr(),
            1234u16.to_be(),
            txt.len() as u16,
            txt.as_ptr(),
            context_ptr,
        );
    }
    let Some((7, Raw::Resolved(4, 0, _, _, port, bytes))) = queue.borrow_mut().items.pop_front()
    else {
        panic!("missing resolve");
    };
    assert_eq!(port, 1234);
    assert_eq!(bytes, txt);
}
