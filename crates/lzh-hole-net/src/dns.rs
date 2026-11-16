//! Bounded DNS A-record lookups on a socket pinned to one physical interface.
//!
//! The host resolver is never consulted. A resolver that hands out Fake-IP
//! addresses from 198.18.0.0/15 produces answers whose reachability depends on
//! a proxy tunnel being up, and there is no way to tell such an answer from a
//! real one after the fact. Asking the interface own gateway over an
//! interface-bound socket keeps the question, the answer and the route on the
//! same physical path the data plane already uses.
//!
//! Only what one coordination hostname needs is implemented: a single
//! recursive IN/A question, no EDNS0, no TCP fallback and no chasing of CNAME
//! records. Every loop, buffer, retry and answer count is bounded.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use tokio::time::{Instant, timeout};

use crate::socket::AsyncPhysicalSocket;

/// Conventional DNS service port.
pub const DNS_PORT: u16 = 53;
/// Largest response we will read. Without EDNS0 a server must fit its answer
/// into 512 bytes, so a larger datagram is not something we asked for.
pub const MAX_DNS_RESPONSE_BYTES: usize = 512;
/// Longest wire-format name, including the root label.
pub const MAX_DNS_NAME_BYTES: usize = 255;
/// Longest single label.
pub const MAX_DNS_LABEL_BYTES: usize = 63;
/// Answers we will walk before refusing the response.
pub const MAX_DNS_ANSWERS: usize = 16;
/// Addresses we will return for one name.
pub const MAX_DNS_ADDRESSES: usize = 8;
/// Compression pointers we will follow while reading one name.
pub const MAX_DNS_POINTER_JUMPS: usize = 8;
/// Datagrams from someone other than the queried server we will ignore.
pub const MAX_IGNORED_DATAGRAMS: usize = 4;
/// Default transmissions attempted for one lookup.
pub const DEFAULT_DNS_ATTEMPTS: usize = 3;
/// Default wait for a single attempt.
pub const DEFAULT_DNS_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);

const FLAG_RESPONSE: u16 = 0x8000;
const FLAG_TRUNCATED: u16 = 0x0200;
const RCODE_MASK: u16 = 0x000f;
const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;

/// Why one bounded lookup did not produce addresses.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    /// The name is not a plain ASCII DNS name we will put on the wire.
    #[error("not a usable ASCII DNS name")]
    InvalidName,
    /// Randomness for the transaction ID was unavailable.
    #[error("no randomness for a DNS transaction ID")]
    NoRandomness,
    /// The operating system refused the interface-bound socket or the send.
    #[error("DNS socket on {interface}: {source}")]
    Socket {
        /// Interface the socket was pinned to.
        interface: String,
        /// Underlying I/O failure.
        source: io::Error,
    },
    /// No usable response arrived within the bounded attempt budget.
    #[error("DNS server {server} did not answer within {attempts} attempts")]
    Timeout {
        /// Server that was asked.
        server: SocketAddrV4,
        /// Attempts that were made.
        attempts: usize,
    },
    /// The response violated the wire format or one of our bounds.
    #[error("malformed DNS response: {0}")]
    Malformed(&'static str),
    /// The server answered with a non-zero RCODE.
    #[error("DNS server answered with RCODE {0}")]
    Rcode(u8),
    /// The answer did not fit in one datagram. EDNS0 and TCP are not used.
    #[error("DNS response was truncated; EDNS0 and TCP are deliberately not used")]
    Truncated,
    /// The response answered a different question.
    #[error("DNS response answered {answered:?}, not {asked:?}")]
    QuestionMismatch {
        /// Name we asked about.
        asked: String,
        /// Name the response answered.
        answered: String,
    },
    /// The name resolved but carries no A record.
    #[error("{0} has no A record")]
    NoRecords(String),
}

impl DnsError {
    /// Whether asking the same question again could plausibly help.
    ///
    /// A name that does not exist, a refused question and a truncated answer
    /// are all deterministic: repeating them only spends the attempt budget.
    fn is_retryable(&self) -> bool {
        matches!(self, DnsError::Malformed(_) | DnsError::Timeout { .. })
    }
}

/// Bounded retry budget for one lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsOptions {
    /// Transmissions attempted before giving up. Zero is treated as one.
    pub attempts: usize,
    /// Wait for a single attempt.
    pub attempt_timeout: Duration,
}

impl Default for DnsOptions {
    fn default() -> Self {
        Self {
            attempts: DEFAULT_DNS_ATTEMPTS,
            attempt_timeout: DEFAULT_DNS_ATTEMPT_TIMEOUT,
        }
    }
}

/// Append one recursive IN/A question for a host under a transaction ID.
pub fn encode_a_query(id: u16, host: &str, out: &mut Vec<u8>) -> Result<(), DnsError> {
    let host = host.trim_end_matches('.');
    if host.is_empty() || !host.is_ascii() {
        return Err(DnsError::InvalidName);
    }
    out.extend_from_slice(&id.to_be_bytes());
    // Recursion desired, everything else at its default.
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0u8; 6]);

    // One byte for the root label, then one length byte per label.
    let mut wire_len = 1usize;
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > MAX_DNS_LABEL_BYTES
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(DnsError::InvalidName);
        }
        wire_len += 1 + label.len();
        if wire_len > MAX_DNS_NAME_BYTES {
            return Err(DnsError::InvalidName);
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&TYPE_A.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(())
}

/// Collect the A records of one response to our own question.
///
/// CNAME records are skipped rather than chased: a recursive resolver puts the
/// final A records in the same answer section, and chasing a chain would add
/// a second unbounded dimension to a lookup that has to stay bounded.
pub fn parse_a_response(id: u16, host: &str, response: &[u8]) -> Result<Vec<Ipv4Addr>, DnsError> {
    let asked = host.trim_end_matches('.');
    let header = response
        .get(..12)
        .ok_or(DnsError::Malformed("shorter than a DNS header"))?;
    if u16::from_be_bytes([header[0], header[1]]) != id {
        return Err(DnsError::Malformed(
            "transaction ID does not match our query",
        ));
    }
    let flags = u16::from_be_bytes([header[2], header[3]]);
    if flags & FLAG_RESPONSE == 0 {
        return Err(DnsError::Malformed("not a response"));
    }
    if flags & FLAG_TRUNCATED != 0 {
        return Err(DnsError::Truncated);
    }
    let rcode = (flags & RCODE_MASK) as u8;
    if rcode != 0 {
        return Err(DnsError::Rcode(rcode));
    }
    let questions = u16::from_be_bytes([header[4], header[5]]) as usize;
    let answers = u16::from_be_bytes([header[6], header[7]]) as usize;
    if questions != 1 {
        return Err(DnsError::Malformed("expected exactly one question"));
    }
    if answers == 0 {
        return Err(DnsError::NoRecords(asked.to_owned()));
    }
    if answers > MAX_DNS_ANSWERS {
        return Err(DnsError::Malformed("more answers than we will walk"));
    }

    let (answered, mut cursor) = read_name(response, 12)?;
    let question = response
        .get(cursor..cursor + 4)
        .ok_or(DnsError::Malformed("question runs past the response"))?;
    if u16::from_be_bytes([question[0], question[1]]) != TYPE_A
        || u16::from_be_bytes([question[2], question[3]]) != CLASS_IN
    {
        return Err(DnsError::Malformed("question is not IN/A"));
    }
    cursor += 4;
    if !answered.eq_ignore_ascii_case(asked) {
        return Err(DnsError::QuestionMismatch {
            asked: asked.to_owned(),
            answered,
        });
    }

    let mut addresses: Vec<Ipv4Addr> = Vec::new();
    for _ in 0..answers {
        let (_, next) = read_name(response, cursor)?;
        cursor = next;
        let record = response
            .get(cursor..cursor + 10)
            .ok_or(DnsError::Malformed("answer runs past the response"))?;
        let rtype = u16::from_be_bytes([record[0], record[1]]);
        let rclass = u16::from_be_bytes([record[2], record[3]]);
        let rdlength = u16::from_be_bytes([record[8], record[9]]) as usize;
        cursor += 10;
        let rdata = response
            .get(cursor..cursor + rdlength)
            .ok_or(DnsError::Malformed("record data runs past the response"))?;
        cursor += rdlength;
        if rtype != TYPE_A || rclass != CLASS_IN {
            continue;
        }
        if rdlength != 4 {
            return Err(DnsError::Malformed("A record data is not four bytes"));
        }
        let address = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
        if !addresses.contains(&address) && addresses.len() < MAX_DNS_ADDRESSES {
            addresses.push(address);
        }
    }
    if addresses.is_empty() {
        return Err(DnsError::NoRecords(asked.to_owned()));
    }
    Ok(addresses)
}

/// Read one possibly compressed name, returning it and the offset just past it.
fn read_name(message: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut name = String::new();
    let mut cursor = start;
    let mut resume: Option<usize> = None;
    let mut jumps = 0usize;
    let mut budget = MAX_DNS_NAME_BYTES;
    loop {
        let length = *message
            .get(cursor)
            .ok_or(DnsError::Malformed("name runs past the response"))?;
        if length == 0 {
            cursor += 1;
            break;
        }
        if length & 0xc0 == 0xc0 {
            let low = *message
                .get(cursor + 1)
                .ok_or(DnsError::Malformed("compression pointer is truncated"))?;
            let target = (usize::from(length & 0x3f) << 8) | usize::from(low);
            if resume.is_none() {
                resume = Some(cursor + 2);
            }
            jumps += 1;
            if jumps > MAX_DNS_POINTER_JUMPS {
                return Err(DnsError::Malformed("too many compression pointers"));
            }
            // A pointer must move strictly backwards, which is also what makes
            // a pointer loop impossible without a separate visited set.
            if target >= cursor || target >= message.len() {
                return Err(DnsError::Malformed(
                    "compression pointer does not move back",
                ));
            }
            cursor = target;
            continue;
        }
        if length & 0xc0 != 0 {
            return Err(DnsError::Malformed("reserved label length"));
        }
        let length = usize::from(length);
        let label = message
            .get(cursor + 1..cursor + 1 + length)
            .ok_or(DnsError::Malformed("label runs past the response"))?;
        budget = budget.checked_sub(length + 1).ok_or(DnsError::Malformed(
            "name is longer than the wire format allows",
        ))?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(
            std::str::from_utf8(label).map_err(|_| DnsError::Malformed("label is not ASCII"))?,
        );
        cursor += 1 + length;
    }
    Ok((name, resume.unwrap_or(cursor)))
}

/// Look up one host on one server from a socket pinned to one interface.
///
/// The socket is a fresh, short-lived, kernel-chosen source port. It is not
/// part of the reserved physical socket pool and cannot disturb a measured
/// STUN mapping: a different source port is a different mapping.
pub async fn query_a(
    interface: &str,
    bind_ip: Ipv4Addr,
    server: SocketAddrV4,
    host: &str,
) -> Result<Vec<Ipv4Addr>, DnsError> {
    query_a_with(interface, bind_ip, server, host, DnsOptions::default()).await
}

/// The same lookup with an explicit, still bounded, attempt budget.
pub async fn query_a_with(
    interface: &str,
    bind_ip: Ipv4Addr,
    server: SocketAddrV4,
    host: &str,
    options: DnsOptions,
) -> Result<Vec<Ipv4Addr>, DnsError> {
    let mut id_bytes = [0u8; 2];
    getrandom::fill(&mut id_bytes).map_err(|_| DnsError::NoRandomness)?;
    let id = u16::from_be_bytes(id_bytes);

    let mut query = Vec::with_capacity(32 + host.len());
    encode_a_query(id, host, &mut query)?;

    let socket =
        AsyncPhysicalSocket::open(interface, bind_ip, 0).map_err(|source| DnsError::Socket {
            interface: interface.to_owned(),
            source,
        })?;

    let attempts = options.attempts.max(1);
    let mut buffer = vec![0u8; MAX_DNS_RESPONSE_BYTES];
    let mut last: Option<DnsError> = None;

    for _ in 0..attempts {
        socket
            .send_to(&query, server)
            .await
            .map_err(|source| DnsError::Socket {
                interface: interface.to_owned(),
                source,
            })?;
        let deadline = Instant::now() + options.attempt_timeout;
        let mut ignored = 0usize;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let Ok(received) = timeout(remaining, socket.recv_from(&mut buffer)).await else {
                break;
            };
            let (length, meta) = received.map_err(|source| DnsError::Socket {
                interface: interface.to_owned(),
                source,
            })?;
            if meta.source != server {
                ignored += 1;
                if ignored >= MAX_IGNORED_DATAGRAMS {
                    break;
                }
                continue;
            }
            match parse_a_response(id, host, &buffer[..length]) {
                Ok(addresses) => return Ok(addresses),
                Err(error) if error.is_retryable() => {
                    last = Some(error);
                    break;
                }
                Err(error) => return Err(error),
            }
        }
    }
    Err(last.unwrap_or(DnsError::Timeout { server, attempts }))
}

#[cfg(test)]
mod tests;
