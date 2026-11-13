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

#[derive(Debug, Default)]
struct TransportIds {
    last: u64,
}

impl TransportIds {
    /// Zero belongs to the protocol's legacy API; real sockets start at one.
    fn reserve(&mut self) -> io::Result<TransportId> {
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
    ids: TransportIds,
    receive_cursor: usize,
    scratch: Vec<u8>,
}

impl Default for TransportSet {
    fn default() -> Self {
        Self {
            sockets: BTreeMap::new(),
            ids: TransportIds::default(),
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
        let id = self.ids.reserve()?;
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

    #[test]
    fn clearing_transports_preserves_identifier_generation() {
        let mut transports = TransportSet::default();
        assert_eq!(transports.ids.reserve().unwrap(), TransportId(1));
        transports.clear();
        assert_eq!(transports.ids.reserve().unwrap(), TransportId(2));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn loopback_socket_set_is_bounded_fair_and_cleans_up_individually() {
        let mut transports = TransportSet::default();
        let first = transports.open("lo0", Ipv4Addr::LOCALHOST, 0).unwrap();
        let first_address = transports.get(first).unwrap().local;
        assert!(
            transports
                .open("not-an-if", Ipv4Addr::LOCALHOST, 0)
                .is_err()
        );
        assert!(transports.get(first).is_some());
        let second = transports.open("lo0", Ipv4Addr::LOCALHOST, 0).unwrap();
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
            transports.open("lo0", Ipv4Addr::LOCALHOST, 0).unwrap();
        }
        assert_eq!(transports.iter().count(), MAX_TRANSPORTS);
        assert!(transports.open("lo0", Ipv4Addr::LOCALHOST, 0).is_err());
        transports.clear();
        assert_eq!(transports.iter().count(), 0);
        let next = transports.open("lo0", Ipv4Addr::LOCALHOST, 0).unwrap();
        assert!(next > second);
    }
}
