//! Minimal STUN binding request and response handling.
//!
//! Only what a server-reflexive mapping needs: a Binding request with a random
//! transaction id, and strict parsing of the Binding success response. Nothing
//! here opens a socket; the caller sends these bytes on its own long-lived
//! data socket, which is what keeps the measured mapping valid.

use std::net::{SocketAddr, SocketAddrV4};

use lzh_hole_protocol::path::{Endpoint, EndpointReject, classify};
use stun_rs::methods::BINDING;
use stun_rs::{
    DecoderContextBuilder, MessageClass, MessageDecoderBuilder, MessageEncoder, StunAttribute,
    StunMessageBuilder, TransactionId,
};

/// The STUN magic cookie from RFC 5389.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;
/// Binding request message type.
pub const MSG_BINDING_REQUEST: u16 = 0x0001;
/// Binding success response message type.
pub const MSG_BINDING_SUCCESS: u16 = 0x0101;
/// MAPPED-ADDRESS attribute.
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
/// XOR-MAPPED-ADDRESS attribute.
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// Fixed STUN header length.
pub const HEADER_LEN: usize = 20;
/// Transaction id length.
pub const TRANSACTION_ID_LEN: usize = 12;

/// Why a STUN response was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StunError {
    /// Not a Binding success response.
    #[error("unexpected message type {0:#06x}")]
    BadMessageType(u16),
    /// Transaction id does not match the request.
    #[error("transaction id mismatch")]
    BadTransaction,
    /// Datagram did not come from the queried server.
    #[error("STUN response source {actual} does not match server {expected}")]
    BadSource {
        /// Server the request was sent to.
        expected: SocketAddrV4,
        /// Datagram's actual source.
        actual: SocketAddrV4,
    },
    /// The STUN library rejected a response attribute or message body.
    #[error("STUN decode failed: {0}")]
    Decode(String),
    /// The STUN library could not encode a request.
    #[error("STUN encode failed: {0}")]
    Encode(String),
    /// No usable IPv4 mapped address.
    #[error("no IPv4 mapped address in the response")]
    NoMappedAddress,
    /// The mapped endpoint is not a usable public candidate.
    #[error("STUN mapped endpoint is not public and usable: {0}")]
    InvalidMapping(EndpointReject),
}

/// A parsed Binding success response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StunResponse {
    /// The transaction id that was echoed.
    pub transaction_id: [u8; TRANSACTION_ID_LEN],
    /// The server-reflexive mapping.
    pub mapped: Endpoint,
    /// Whether the mapping came from XOR-MAPPED-ADDRESS.
    pub xor_mapped: bool,
}

/// Build a Binding request for the given transaction id using `stun-rs`.
pub fn build_binding_request(
    transaction_id: &[u8; TRANSACTION_ID_LEN],
) -> Result<Vec<u8>, StunError> {
    let message = StunMessageBuilder::new(BINDING, MessageClass::Request)
        .with_transaction_id(TransactionId::from(*transaction_id))
        .build();
    let mut out = vec![0u8; HEADER_LEN];
    let size = MessageEncoder::default()
        .encode(&mut out, &message)
        .map_err(|error| StunError::Encode(error.to_string()))?;
    out.truncate(size);
    Ok(out)
}

/// Parse a Binding success response.
///
/// The caller must additionally check that the packet actually came from the
/// server address it queried, or use [`parse_binding_response_from`] to perform
/// that check together with message validation.
pub fn parse_binding_response(
    data: &[u8],
    expected_transaction: &[u8; TRANSACTION_ID_LEN],
) -> Result<StunResponse, StunError> {
    // Decode exactly once. No credentials are configured because public STUN
    // Binding discovery does not use MESSAGE-INTEGRITY for peer authentication.
    let context = DecoderContextBuilder::default().not_ignore().build();
    let decoder = MessageDecoderBuilder::default()
        .with_context(context)
        .build();
    let (message, consumed) = decoder
        .decode(data)
        .map_err(|error| StunError::Decode(error.to_string()))?;
    if consumed != data.len() {
        return Err(StunError::Decode(format!(
            "decoder consumed {consumed} of {} bytes",
            data.len()
        )));
    }
    if message.method() != BINDING || message.class() != MessageClass::SuccessResponse {
        return Err(StunError::BadMessageType(u16::from_be_bytes([
            data[0], data[1],
        ])));
    }
    if message.transaction_id().as_bytes() != expected_transaction {
        return Err(StunError::BadTransaction);
    }
    let transaction_id = *message.transaction_id().as_bytes();

    let mut mapped: Option<Endpoint> = None;
    let mut xor_mapped = false;
    for attribute in message.attributes() {
        let (address, is_xor) = match attribute {
            StunAttribute::XorMappedAddress(address) => (address.socket_address(), true),
            StunAttribute::MappedAddress(address) => (address.socket_address(), false),
            _ => continue,
        };
        let SocketAddr::V4(address) = address else {
            continue;
        };
        // XOR-MAPPED-ADDRESS wins over MAPPED-ADDRESS regardless of order.
        if is_xor || mapped.is_none() {
            mapped = Some(Endpoint::new(*address.ip(), address.port()));
            xor_mapped = is_xor;
        }
    }

    let mapped = mapped.ok_or(StunError::NoMappedAddress)?;
    if mapped.port == 0 {
        return Err(StunError::InvalidMapping(EndpointReject::PortZero));
    }
    if let Some(reject) = classify(mapped.ip) {
        return Err(StunError::InvalidMapping(reject));
    }
    Ok(StunResponse {
        transaction_id,
        mapped,
        xor_mapped,
    })
}

/// Validate both the datagram source and the Binding success response.
pub fn parse_binding_response_from(
    data: &[u8],
    expected_transaction: &[u8; TRANSACTION_ID_LEN],
    expected_source: SocketAddrV4,
    actual_source: SocketAddrV4,
) -> Result<StunResponse, StunError> {
    if actual_source != expected_source {
        return Err(StunError::BadSource {
            expected: expected_source,
            actual: actual_source,
        });
    }
    parse_binding_response(data, expected_transaction)
}

/// Whether a datagram could plausibly be a STUN message.
///
/// Used only to demultiplex our own frames from STUN replies on the shared
/// socket; it is not a security check.
pub fn looks_like_stun(data: &[u8]) -> bool {
    data.len() >= HEADER_LEN
        && data[0] & 0b1100_0000 == 0
        && u32::from_be_bytes([data[4], data[5], data[6], data[7]]) == MAGIC_COOKIE
}

/// Format a STUN server specification as an endpoint, when it is an IP literal.
pub fn parse_server_literal(spec: &str) -> Option<SocketAddrV4> {
    spec.parse::<SocketAddrV4>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn tx() -> [u8; TRANSACTION_ID_LEN] {
        let mut out = [0u8; TRANSACTION_ID_LEN];
        for (i, b) in out.iter_mut().enumerate() {
            *b = i as u8;
        }
        out
    }

    fn attr(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    fn response(body: &[u8], transaction: &[u8; TRANSACTION_ID_LEN]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MSG_BINDING_SUCCESS.to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(transaction);
        out.extend_from_slice(body);
        out
    }

    fn mapped_value(ip: [u8; 4], port: u16, xor: bool) -> Vec<u8> {
        let mut ip = u32::from_be_bytes(ip);
        let mut port = port;
        if xor {
            ip ^= MAGIC_COOKIE;
            port ^= (MAGIC_COOKIE >> 16) as u16;
        }
        let mut out = vec![0u8, 1];
        out.extend_from_slice(&port.to_be_bytes());
        out.extend_from_slice(&ip.to_be_bytes());
        out
    }

    #[test]
    fn request_is_a_well_formed_20_byte_binding_request() {
        let req = build_binding_request(&tx()).unwrap();
        assert_eq!(req.len(), HEADER_LEN);
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), MSG_BINDING_REQUEST);
        assert_eq!(u16::from_be_bytes([req[2], req[3]]), 0);
        assert_eq!(
            u32::from_be_bytes([req[4], req[5], req[6], req[7]]),
            MAGIC_COOKIE
        );
        assert_eq!(&req[8..20], &tx());
    }

    #[test]
    fn xor_mapped_is_parsed() {
        let body = attr(
            ATTR_XOR_MAPPED_ADDRESS,
            &mapped_value([210, 22, 105, 194], 51000, true),
        );
        let data = response(&body, &tx());
        let parsed = parse_binding_response(&data, &tx()).unwrap();
        assert_eq!(
            parsed.mapped,
            Endpoint::new(Ipv4Addr::new(210, 22, 105, 194), 51000)
        );
        assert!(parsed.xor_mapped);
        assert_eq!(parsed.transaction_id, tx());
    }

    #[test]
    fn plain_mapped_is_a_fallback() {
        let body = attr(
            ATTR_MAPPED_ADDRESS,
            &mapped_value([38, 58, 103, 204], 40000, false),
        );
        let data = response(&body, &tx());
        let parsed = parse_binding_response(&data, &tx()).unwrap();
        assert_eq!(
            parsed.mapped,
            Endpoint::new(Ipv4Addr::new(38, 58, 103, 204), 40000)
        );
        assert!(!parsed.xor_mapped);
    }

    #[test]
    fn xor_wins_over_plain_in_either_order() {
        let plain = attr(
            ATTR_MAPPED_ADDRESS,
            &mapped_value([1, 2, 3, 4], 1111, false),
        );
        let xor = attr(
            ATTR_XOR_MAPPED_ADDRESS,
            &mapped_value([210, 22, 105, 194], 51000, true),
        );
        for body in [[plain.clone(), xor.clone()].concat(), [xor, plain].concat()] {
            let data = response(&body, &tx());
            let parsed = parse_binding_response(&data, &tx()).unwrap();
            assert_eq!(
                parsed.mapped,
                Endpoint::new(Ipv4Addr::new(210, 22, 105, 194), 51000)
            );
            assert!(parsed.xor_mapped);
        }
    }

    #[test]
    fn unknown_attributes_with_padding_are_skipped() {
        let mut body = attr(0x8022, b"hello");
        body.extend_from_slice(&attr(
            ATTR_XOR_MAPPED_ADDRESS,
            &mapped_value([210, 22, 105, 194], 51000, true),
        ));
        let data = response(&body, &tx());
        let parsed = parse_binding_response(&data, &tx()).unwrap();
        assert_eq!(parsed.mapped.port, 51000);
    }

    #[test]
    fn wrong_transaction_cookie_type_and_length_are_refused() {
        let body = attr(
            ATTR_XOR_MAPPED_ADDRESS,
            &mapped_value([210, 22, 105, 194], 51000, true),
        );
        let data = response(&body, &tx());

        let mut other = tx();
        other[0] ^= 1;
        assert_eq!(
            parse_binding_response(&data, &other),
            Err(StunError::BadTransaction)
        );

        let mut bad_cookie = data.clone();
        bad_cookie[7] ^= 1;
        assert!(matches!(
            parse_binding_response(&bad_cookie, &tx()),
            Err(StunError::Decode(_))
        ));

        let mut bad_type = data.clone();
        bad_type[1] = 0x11;
        assert!(matches!(
            parse_binding_response(&bad_type, &tx()),
            Err(StunError::BadMessageType(0x0111)) | Err(StunError::Decode(_))
        ));

        let mut bad_len = data.clone();
        bad_len[3] = 0xff;
        assert!(matches!(
            parse_binding_response(&bad_len, &tx()),
            Err(StunError::Decode(_))
        ));

        assert!(matches!(
            parse_binding_response(&data[..19], &tx()),
            Err(StunError::Decode(_))
        ));
        let mut trailing = data.clone();
        trailing.push(0);
        assert!(matches!(
            parse_binding_response(&trailing, &tx()),
            Err(StunError::Decode(_))
        ));
    }

    #[test]
    fn truncated_attribute_is_refused() {
        let mut body = attr(0x8022, b"hello");
        body.extend_from_slice(&[0x00, 0x20, 0x00, 0x40]);
        let data = response(&body, &tx());
        assert!(matches!(
            parse_binding_response(&data, &tx()),
            Err(StunError::Decode(_))
        ));
    }

    #[test]
    fn non_public_or_zero_port_mappings_are_refused() {
        for (ip, port, expected) in [
            ([127, 0, 0, 1], 51000, EndpointReject::Loopback),
            ([198, 18, 0, 241], 51000, EndpointReject::FakeIp),
            ([210, 22, 105, 194], 0, EndpointReject::PortZero),
        ] {
            let body = attr(ATTR_XOR_MAPPED_ADDRESS, &mapped_value(ip, port, true));
            let data = response(&body, &tx());
            assert_eq!(
                parse_binding_response(&data, &tx()),
                Err(StunError::InvalidMapping(expected))
            );
        }
    }

    #[test]
    fn missing_mapped_address_is_refused() {
        let body = attr(0x8022, b"hello");
        let data = response(&body, &tx());
        assert_eq!(
            parse_binding_response(&data, &tx()),
            Err(StunError::NoMappedAddress)
        );
    }

    #[test]
    fn response_source_is_checked_before_the_mapping_is_accepted() {
        let body = attr(
            ATTR_XOR_MAPPED_ADDRESS,
            &mapped_value([210, 22, 105, 194], 51000, true),
        );
        let data = response(&body, &tx());
        let server = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 3478);
        let other = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 3478);
        assert_eq!(
            parse_binding_response_from(&data, &tx(), server, other),
            Err(StunError::BadSource {
                expected: server,
                actual: other,
            })
        );
        let parsed = parse_binding_response_from(&data, &tx(), server, server).unwrap();
        assert_eq!(parsed.mapped.port, 51000);
    }

    #[test]
    fn stun_demux_does_not_match_our_own_frames() {
        // Our frames start with 0x4C5A4831, which has the top bits set and is
        // not the STUN cookie, so they can never be mistaken for STUN.
        let frame = [0x4Cu8, 0x5A, 0x48, 0x31, 1, 1, 0, 0];
        assert!(!looks_like_stun(&frame));
        let req = build_binding_request(&tx()).unwrap();
        assert!(looks_like_stun(&req));
        let response_bytes = response(
            &attr(
                ATTR_XOR_MAPPED_ADDRESS,
                &mapped_value([210, 22, 105, 194], 51000, true),
            ),
            &tx(),
        );
        assert!(looks_like_stun(&response_bytes));
        assert!(!looks_like_stun(&[0u8; 4]));
    }

    #[test]
    fn server_literals_parse() {
        assert!(parse_server_literal("116.162.157.195:3478").is_some());
        assert!(parse_server_literal("stun.example.com:3478").is_none());
    }
}
