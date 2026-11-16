use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

use super::*;

fn push_name(out: &mut Vec<u8>, host: &str) {
    for label in host.split('.') {
        if label.is_empty() {
            continue;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

/// A response whose answer owner names are all pointers to the question.
fn build_response(id: u16, flags: u16, host: &str, answers: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    push_name(&mut out, host);
    out.extend_from_slice(&TYPE_A.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    for (rtype, rdata) in answers {
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&300u32.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
    }
    out
}

fn loopback_server_addr(socket: &UdpSocket) -> SocketAddrV4 {
    match socket.local_addr().expect("bound socket") {
        SocketAddr::V4(v4) => v4,
        SocketAddr::V6(_) => unreachable!("bound an IPv4 loopback socket"),
    }
}

#[test]
fn a_query_is_one_recursive_in_a_question() {
    let mut out = Vec::new();
    encode_a_query(0x1234, "ntfy.sh", &mut out).unwrap();
    assert_eq!(&out[..2], &[0x12, 0x34]);
    assert_eq!(&out[2..4], &[0x01, 0x00]);
    assert_eq!(&out[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);

    let mut expected = Vec::new();
    expected.push(4);
    expected.extend_from_slice(b"ntfy");
    expected.push(2);
    expected.extend_from_slice(b"sh");
    expected.extend_from_slice(&[0, 0, 1, 0, 1]);
    assert_eq!(&out[12..], expected.as_slice());
}

#[test]
fn names_outside_the_wire_format_are_refused() {
    let long_label = "a".repeat(MAX_DNS_LABEL_BYTES + 1);
    let long_name = vec!["abcdefghij"; 30].join(".");
    for host in [
        "",
        ".",
        "ntfy..sh",
        long_label.as_str(),
        long_name.as_str(),
        "café.sh",
    ] {
        let mut out = Vec::new();
        assert!(
            matches!(
                encode_a_query(1, host, &mut out),
                Err(DnsError::InvalidName)
            ),
            "{host:?} should be refused"
        );
    }
    // A trailing root dot names the same host.
    let mut out = Vec::new();
    assert!(encode_a_query(1, "ntfy.sh.", &mut out).is_ok());
}

#[test]
fn a_records_are_collected_deduplicated_and_cnames_skipped() {
    let response = build_response(
        0x4242,
        0x8180,
        "ntfy.sh",
        &[
            (5, b"alias.example".to_vec()),
            (1, vec![159, 203, 148, 75]),
            (1, vec![159, 203, 148, 75]),
            (28, vec![0; 16]),
            (1, vec![159, 203, 148, 76]),
        ],
    );
    let addresses = parse_a_response(0x4242, "ntfy.sh", &response).unwrap();
    assert_eq!(
        addresses,
        vec![
            Ipv4Addr::new(159, 203, 148, 75),
            Ipv4Addr::new(159, 203, 148, 76)
        ]
    );
    // The question name comparison is case insensitive, as DNS requires.
    assert_eq!(
        parse_a_response(0x4242, "NTFY.SH", &response).unwrap(),
        addresses
    );
}

#[test]
fn responses_that_are_not_our_answer_are_refused() {
    let good = build_response(7, 0x8180, "ntfy.sh", &[(1, vec![159, 203, 148, 75])]);

    assert!(matches!(
        parse_a_response(8, "ntfy.sh", &good),
        Err(DnsError::Malformed(_))
    ));
    assert!(matches!(
        parse_a_response(7, "other.sh", &good),
        Err(DnsError::QuestionMismatch { .. })
    ));

    let mut query = Vec::new();
    encode_a_query(7, "ntfy.sh", &mut query).unwrap();
    assert!(matches!(
        parse_a_response(7, "ntfy.sh", &query),
        Err(DnsError::Malformed(_))
    ));

    let truncated = build_response(7, 0x8380, "ntfy.sh", &[(1, vec![159, 203, 148, 75])]);
    assert!(matches!(
        parse_a_response(7, "ntfy.sh", &truncated),
        Err(DnsError::Truncated)
    ));

    let refused = build_response(7, 0x8183, "ntfy.sh", &[]);
    assert!(matches!(
        parse_a_response(7, "ntfy.sh", &refused),
        Err(DnsError::Rcode(3))
    ));

    let no_answers = build_response(7, 0x8180, "ntfy.sh", &[]);
    assert!(matches!(
        parse_a_response(7, "ntfy.sh", &no_answers),
        Err(DnsError::NoRecords(_))
    ));

    let cname_only = build_response(7, 0x8180, "ntfy.sh", &[(5, b"alias.example".to_vec())]);
    assert!(matches!(
        parse_a_response(7, "ntfy.sh", &cname_only),
        Err(DnsError::NoRecords(_))
    ));

    let short_rdata = build_response(7, 0x8180, "ntfy.sh", &[(1, vec![1, 2, 3])]);
    assert!(matches!(
        parse_a_response(7, "ntfy.sh", &short_rdata),
        Err(DnsError::Malformed(_))
    ));

    assert!(matches!(
        parse_a_response(7, "ntfy.sh", &good[..11]),
        Err(DnsError::Malformed(_))
    ));
    assert!(matches!(
        parse_a_response(7, "ntfy.sh", &good[..good.len() - 1]),
        Err(DnsError::Malformed(_))
    ));
}

#[test]
fn answer_and_address_counts_stay_bounded() {
    let too_many: Vec<(u16, Vec<u8>)> = (0..=MAX_DNS_ANSWERS)
        .map(|index| (1u16, vec![159, 203, 148, index as u8]))
        .collect();
    let response = build_response(1, 0x8180, "ntfy.sh", &too_many);
    assert!(matches!(
        parse_a_response(1, "ntfy.sh", &response),
        Err(DnsError::Malformed(_))
    ));

    let capped: Vec<(u16, Vec<u8>)> = (0..MAX_DNS_ANSWERS)
        .map(|index| (1u16, vec![159, 203, (index + 1) as u8, 1]))
        .collect();
    let response = build_response(1, 0x8180, "ntfy.sh", &capped);
    let addresses = parse_a_response(1, "ntfy.sh", &response).unwrap();
    assert_eq!(addresses.len(), MAX_DNS_ADDRESSES);
}

#[test]
fn compression_pointers_must_move_backwards() {
    let mut message = Vec::new();
    message.extend_from_slice(&3u16.to_be_bytes());
    message.extend_from_slice(&0x8180u16.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    // One answer, so parsing reaches the question name at all.
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    // A name at offset 12 that points at itself.
    message.extend_from_slice(&[0xc0, 0x0c]);
    message.extend_from_slice(&TYPE_A.to_be_bytes());
    message.extend_from_slice(&CLASS_IN.to_be_bytes());
    assert!(matches!(
        parse_a_response(3, "ntfy.sh", &message),
        Err(DnsError::Malformed(_))
    ));
}

#[test]
fn an_over_long_name_in_a_response_is_refused() {
    let host = vec!["a".repeat(MAX_DNS_LABEL_BYTES); 5].join(".");
    let response = build_response(4, 0x8180, &host, &[(1, vec![159, 203, 148, 75])]);
    assert!(matches!(
        parse_a_response(4, &host, &response),
        Err(DnsError::Malformed(_))
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn a_loopback_query_returns_the_servers_a_records() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = loopback_server_addr(&server);
    let task = tokio::spawn(async move {
        let mut buffer = [0u8; MAX_DNS_RESPONSE_BYTES];
        let (length, from) = server.recv_from(&mut buffer).await.unwrap();
        assert!(length >= 12, "a query is at least a header");
        let id = u16::from_be_bytes([buffer[0], buffer[1]]);
        let reply = build_response(id, 0x8180, "ntfy.sh", &[(1, vec![159, 203, 148, 75])]);
        server.send_to(&reply, from).await.unwrap();
    });
    let addresses = query_a("lo0", Ipv4Addr::LOCALHOST, server_addr, "ntfy.sh")
        .await
        .unwrap();
    assert_eq!(addresses, vec![Ipv4Addr::new(159, 203, 148, 75)]);
    task.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn a_silent_server_fails_within_the_bounded_budget() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = loopback_server_addr(&server);
    let options = DnsOptions {
        attempts: 2,
        attempt_timeout: Duration::from_millis(50),
    };
    let error = query_a_with("lo0", Ipv4Addr::LOCALHOST, server_addr, "ntfy.sh", options)
        .await
        .unwrap_err();
    assert!(matches!(error, DnsError::Timeout { attempts: 2, .. }));
}

#[tokio::test(flavor = "current_thread")]
async fn a_deterministic_answer_is_not_retried() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = loopback_server_addr(&server);
    let task = tokio::spawn(async move {
        let mut buffer = [0u8; MAX_DNS_RESPONSE_BYTES];
        let (length, from) = server.recv_from(&mut buffer).await.unwrap();
        assert!(length >= 12, "a query is at least a header");
        let id = u16::from_be_bytes([buffer[0], buffer[1]]);
        let reply = build_response(id, 0x8183, "ntfy.sh", &[]);
        server.send_to(&reply, from).await.unwrap();
        // A refused name is deterministic, so no second question may follow.
        tokio::time::timeout(Duration::from_millis(200), server.recv_from(&mut buffer))
            .await
            .is_ok()
    });
    let options = DnsOptions {
        attempts: 3,
        attempt_timeout: Duration::from_millis(300),
    };
    let error = query_a_with("lo0", Ipv4Addr::LOCALHOST, server_addr, "ntfy.sh", options)
        .await
        .unwrap_err();
    assert!(matches!(error, DnsError::Rcode(3)));
    assert!(!task.await.unwrap(), "a refused name must not be retried");
}
