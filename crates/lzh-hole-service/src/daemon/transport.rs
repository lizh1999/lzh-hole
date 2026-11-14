//! Concrete bounded physical socket ownership, without discovery/session policy.
//!
//! Receive futures borrow the sockets and are cancellation safe. There are no
//! detached receive tasks or descriptors that outlive removal from this set.

use std::collections::BTreeMap;
use std::future::poll_fn;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::task::Poll;

use lzh_hole_net::socket::{AsyncPhysicalSocket, RecvMeta};
use lzh_hole_types::TransportId;

pub(super) const MAX_TRANSPORTS: usize = 8;
const MAX_DATAGRAM_BYTES: usize = 64 * 1024;

/// One monotonic identifier space shared by every socket pool in the daemon.
///
/// Sharing it is what keeps "identifiers never reuse" true across the data
/// plane and the punch pool: an identifier that has escaped into a discovery
/// observation or a peer-reflexive candidate can never be handed out again by
/// the other pool.
#[derive(Debug, Default)]
pub(super) struct TransportIds {
    last: u64,
}

impl TransportIds {
    /// Zero belongs to the protocol's legacy API; real sockets start at one.
    pub(super) fn reserve(&mut self) -> io::Result<TransportId> {
        self.last = self
            .last
            .checked_add(1)
            .ok_or_else(|| io::Error::other("physical transport identifiers exhausted"))?;
        Ok(TransportId(self.last))
    }
}

pub(super) struct BoundTransport {
    pub id: TransportId,
    pub interface: String,
    pub interface_index: u32,
    pub local: SocketAddrV4,
    pub socket: AsyncPhysicalSocket,
}

pub(super) struct TransportDatagram {
    pub transport: TransportId,
    pub result: io::Result<(usize, RecvMeta)>,
    pub buffer: Vec<u8>,
}

pub(super) struct TransportSet {
    sockets: BTreeMap<TransportId, BoundTransport>,
    receive_cursor: usize,
    scratch: Vec<u8>,
}

impl Default for TransportSet {
    fn default() -> Self {
        Self {
            sockets: BTreeMap::new(),
            receive_cursor: 0,
            scratch: vec![0; MAX_DATAGRAM_BYTES],
        }
    }
}

impl TransportSet {
    /// Retain one socket per actual interface/address. Failed opens consume no
    /// capacity and cannot replace any healthy retained socket.
    pub fn open(
        &mut self,
        ids: &mut TransportIds,
        interface: &str,
        address: Ipv4Addr,
        port: u16,
    ) -> io::Result<TransportId> {
        if let Some(existing) = self.sockets.values().find(|socket| {
            socket.interface == interface
                && socket.local.ip() == &address
                && socket.local.port() == port
        }) {
            return Ok(existing.id);
        }
        if self.sockets.len() >= MAX_TRANSPORTS {
            return Err(io::Error::other("physical transport capacity reached"));
        }
        // Reserve before opening, so even subsequent setup failure never reuses
        // an ID that might have escaped into a discovery observation.
        let id = ids.reserve()?;
        let socket = AsyncPhysicalSocket::open(interface, address, port)?;
        let local = socket.get_ref().local_addr();
        let interface_index = socket.get_ref().bound_ifindex();
        self.sockets.insert(
            id,
            BoundTransport {
                id,
                interface: interface.to_owned(),
                interface_index,
                local,
                socket,
            },
        );
        Ok(id)
    }

    /// Take ownership of a socket that already exists, keeping its identifier.
    ///
    /// This is how a winning punch socket joins the data plane. Minting a fresh
    /// identifier instead would invalidate any identifier the peer may already
    /// have learned, so the original one is preserved.
    pub fn adopt(
        &mut self,
        id: TransportId,
        interface: String,
        socket: AsyncPhysicalSocket,
    ) -> io::Result<()> {
        if self.sockets.contains_key(&id) {
            return Err(io::Error::other("transport identifier already present"));
        }
        if self.sockets.len() >= MAX_TRANSPORTS {
            return Err(io::Error::other("physical transport capacity reached"));
        }
        let local = socket.get_ref().local_addr();
        let interface_index = socket.get_ref().bound_ifindex();
        if self.sockets.values().any(|existing| {
            existing.interface == interface
                && existing.local.ip() == local.ip()
                && existing.local.port() == local.port()
        }) {
            return Err(io::Error::other("transport address already bound"));
        }
        self.sockets.insert(
            id,
            BoundTransport {
                id,
                interface,
                interface_index,
                local,
                socket,
            },
        );
        Ok(())
    }

    pub fn get(&self, id: TransportId) -> Option<&BoundTransport> {
        self.sockets.get(&id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &BoundTransport> {
        self.sockets.values()
    }

    /// Drop this socket immediately. The caller then invalidates this ID in
    /// discovery and PeerEngine, never rebuilding unrelated retained sockets.
    pub fn remove(&mut self, id: TransportId) -> bool {
        self.sockets.remove(&id).is_some()
    }

    pub fn clear(&mut self) {
        self.sockets.clear();
        // Deliberately keep the allocator across complete network outages.
    }

    pub async fn recv(&mut self) -> TransportDatagram {
        let Self {
            sockets,
            receive_cursor,
            scratch,
            ..
        } = self;
        poll_fn(|context| {
            let count = sockets.len();
            if count == 0 {
                return Poll::Pending;
            }
            let start = *receive_cursor % count;
            let ordered = sockets
                .values()
                .enumerate()
                .skip(start)
                .chain(sockets.values().enumerate().take(start));
            for (index, transport) in ordered {
                if let Poll::Ready(result) = transport.socket.poll_recv_from(context, scratch) {
                    // Pending/cancelled polls do not allocate or move the
                    // cursor. A serviced socket yields to the next one.
                    *receive_cursor = (index + 1) % count;
                    let buffer = match &result {
                        Ok((size, _)) => scratch[..*size].to_vec(),
                        Err(_) => Vec::new(),
                    };
                    return Poll::Ready(TransportDatagram {
                        transport: transport.id,
                        result,
                        buffer,
                    });
                }
            }
            Poll::Pending
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_never_reuse_and_never_wrap_to_legacy_zero() {
        let mut ids = TransportIds::default();
        assert_eq!(ids.reserve().unwrap(), TransportId(1));
        assert_eq!(ids.reserve().unwrap(), TransportId(2));
        ids.last = u64::MAX - 1;
        assert_eq!(ids.reserve().unwrap(), TransportId(u64::MAX));
        assert!(ids.reserve().is_err());
        assert!(ids.reserve().is_err());
        assert_eq!(ids.last, u64::MAX);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn the_identifier_space_survives_clearing_the_set() {
        // The allocator is owned by the daemon, not the set, so emptying the
        // data plane can never hand an identifier out twice.
        let mut ids = TransportIds::default();
        let mut transports = TransportSet::default();
        assert_eq!(
            transports
                .open(&mut ids, "lo0", Ipv4Addr::LOCALHOST, 0)
                .unwrap(),
            TransportId(1)
        );
        transports.clear();
        assert_eq!(
            transports
                .open(&mut ids, "lo0", Ipv4Addr::LOCALHOST, 0)
                .unwrap(),
            TransportId(2)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn loopback_socket_set_is_bounded_fair_and_cleans_up_individually() {
        let mut ids = TransportIds::default();
        let mut transports = TransportSet::default();
        let first = transports
            .open(&mut ids, "lo0", Ipv4Addr::LOCALHOST, 0)
            .unwrap();
        let first_address = transports.get(first).unwrap().local;
        assert!(
            transports
                .open(&mut ids, "not-an-if", Ipv4Addr::LOCALHOST, 0)
                .is_err()
        );
        assert!(transports.get(first).is_some());
        let second = transports
            .open(&mut ids, "lo0", Ipv4Addr::LOCALHOST, 0)
            .unwrap();
        let second_address = transports.get(second).unwrap().local;
        transports
            .get(first)
            .unwrap()
            .socket
            .send_to(b"one", second_address)
            .await
            .unwrap();
        let datagram = tokio::time::timeout(std::time::Duration::from_secs(2), transports.recv())
            .await
            .unwrap();
        assert_eq!(datagram.transport, second);
        assert_eq!(datagram.buffer, b"one");
        assert_eq!(datagram.result.unwrap().1.source, first_address);
        assert!(transports.remove(first));
        assert!(transports.get(second).is_some());
        for _ in 1..MAX_TRANSPORTS {
            transports
                .open(&mut ids, "lo0", Ipv4Addr::LOCALHOST, 0)
                .unwrap();
        }
        assert_eq!(transports.iter().count(), MAX_TRANSPORTS);
        assert!(
            transports
                .open(&mut ids, "lo0", Ipv4Addr::LOCALHOST, 0)
                .is_err()
        );
        transports.clear();
        assert_eq!(transports.iter().count(), 0);
        let next = transports
            .open(&mut ids, "lo0", Ipv4Addr::LOCALHOST, 0)
            .unwrap();
        assert!(next > second);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn adopting_a_socket_keeps_its_identifier_and_refuses_duplicates() {
        let mut ids = TransportIds::default();
        let mut transports = TransportSet::default();
        let data = transports
            .open(&mut ids, "lo0", Ipv4Addr::LOCALHOST, 0)
            .unwrap();

        // A socket that already exists elsewhere keeps the identifier it was
        // given, so a peer that learned it is not invalidated.
        let promoted = ids.reserve().unwrap();
        let socket = AsyncPhysicalSocket::open("lo0", Ipv4Addr::LOCALHOST, 0).unwrap();
        transports
            .adopt(promoted, "lo0".to_owned(), socket)
            .unwrap();
        assert!(transports.get(promoted).is_some());
        assert_ne!(promoted, data);

        // Adopting the same identifier twice is refused.
        let socket = AsyncPhysicalSocket::open("lo0", Ipv4Addr::LOCALHOST, 0).unwrap();
        assert!(
            transports
                .adopt(promoted, "lo0".to_owned(), socket)
                .is_err()
        );

        // A new identifier is still accepted while capacity remains.
        let another = ids.reserve().unwrap();
        let socket = AsyncPhysicalSocket::open("lo0", Ipv4Addr::LOCALHOST, 0).unwrap();
        transports.adopt(another, "lo0".to_owned(), socket).unwrap();
        assert_eq!(transports.iter().count(), 3);
    }
}
