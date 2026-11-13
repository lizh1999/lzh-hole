//! One long-lived, interface-bound IPv4 UDP socket with receive metadata.
//!
//! This is the single socket per physical interface. STUN, authenticated
//! connectivity checks, the handshake and data frames all use it. We never open
//! a second socket to "get a fresh mapping" and then send on the old one: that
//! would invalidate the mapping we just measured.
//!
//! macOS specifics: IP_BOUND_IF (25) pins egress to one interface, and
//! IP_PKTINFO (26) reports which interface actually received a datagram.

use std::io;
use std::mem;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, RawFd};
use std::task::{Context, Poll};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

/// macOS IP_BOUND_IF socket option.
pub const IP_BOUND_IF: libc::c_int = 25;
/// macOS IP_PKTINFO socket option.
pub const IP_PKTINFO: libc::c_int = 26;
/// Size of the Darwin in_pktinfo structure.
const IN_PKTINFO_LEN: usize = 12;

/// What the kernel reported about a received datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecvMeta {
    /// Who sent it.
    pub source: SocketAddrV4,
    /// Interface index the datagram actually arrived on, when IP_PKTINFO was
    /// present. This is evidence, not a guess.
    pub ifindex: Option<u32>,
    /// Local address the datagram was addressed to, when known.
    pub dest: Option<Ipv4Addr>,
}

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

fn sockaddr_to_v4(addr: &libc::sockaddr_in) -> SocketAddrV4 {
    SocketAddrV4::new(
        Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
        u16::from_be(addr.sin_port),
    )
}

/// A bound UDP socket tied to one physical interface.
#[derive(Debug)]
pub struct PhysicalSocket {
    socket: Socket,
    local: SocketAddrV4,
    ifindex: u32,
    interface: String,
}

impl PhysicalSocket {
    /// Open a socket bound to `bind_ip:port` and pinned to `interface`.
    ///
    /// `port` may be 0 to let the kernel choose. The bound interface is read
    /// back and verified, so a silent failure cannot leave us believing we are
    /// pinned when we are not.
    pub fn open(interface: &str, bind_ip: Ipv4Addr, port: u16) -> io::Result<Self> {
        let ifindex = super::interface::interface_index(interface)?;
        let ifindex_nonzero = NonZeroU32::new(ifindex).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "interface index must not be zero")
        })?;
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.bind_device_by_index_v4(Some(ifindex_nonzero))?;

        let enable: libc::c_int = 1;
        // SAFETY: the socket is live and the option value is a valid c_int.
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                IP_PKTINFO,
                std::ptr::from_ref(&enable).cast(),
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(last_error());
        }

        let want = SocketAddrV4::new(bind_ip, port);
        socket.bind(&SockAddr::from(want))?;

        // socket2 has no IP_BOUND_IF getter. Read it back explicitly; a silent
        // failure must not leave us believing the socket is pinned.
        let mut got: libc::c_int = 0;
        let mut len = mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: got and len are valid out-parameters.
        let rc = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                IP_BOUND_IF,
                std::ptr::from_mut(&mut got).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(last_error());
        }
        if got != ifindex as libc::c_int {
            return Err(io::Error::other(format!(
                "interface binding did not stick: wanted {ifindex}, got {got}"
            )));
        }

        let local = socket.local_addr()?.as_socket_ipv4().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "bound address is not IPv4")
        })?;
        Ok(Self {
            socket,
            local,
            ifindex,
            interface: interface.to_owned(),
        })
    }

    /// The address the kernel actually bound.
    pub fn local_addr(&self) -> SocketAddrV4 {
        self.local
    }

    /// The interface index this socket is pinned to.
    pub fn bound_ifindex(&self) -> u32 {
        self.ifindex
    }

    /// The interface name this socket is pinned to.
    pub fn interface_name(&self) -> &str {
        &self.interface
    }

    /// Send a datagram.
    pub fn send_to(&self, buf: &[u8], target: SocketAddrV4) -> io::Result<usize> {
        self.socket.send_to(buf, &SockAddr::from(target))
    }

    /// Receive one datagram with its Darwin ancillary metadata.
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, RecvMeta)> {
        // SAFETY: sockaddr_in is plain old data; all-zero is a valid value.
        let mut sa: libc::sockaddr_in = unsafe { mem::zeroed() };
        let mut sa_len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let mut cmsg_buf = [0u8; 128];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        // SAFETY: msghdr is plain old data; all-zero (null pointers) is valid.
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = std::ptr::from_mut(&mut sa).cast();
        msg.msg_namelen = sa_len;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr().cast();
        msg.msg_controllen = cmsg_buf.len() as libc::socklen_t;

        // SAFETY: all pointers in msg refer to live locals for the call.
        let n = unsafe { libc::recvmsg(self.socket.as_raw_fd(), &mut msg, 0) };
        if n < 0 {
            return Err(last_error());
        }
        sa_len = msg.msg_namelen;

        let mut meta = RecvMeta {
            source: sockaddr_to_v4(&sa),
            ifindex: None,
            dest: None,
        };
        let _ = sa_len;

        // SAFETY: msg was filled by recvmsg and msg_control points at cmsg_buf.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                let hdr = &*cmsg;
                if hdr.cmsg_level == libc::IPPROTO_IP
                    && hdr.cmsg_type == IP_PKTINFO
                    && hdr.cmsg_len as usize >= libc::CMSG_LEN(IN_PKTINFO_LEN as u32) as usize
                {
                    let data = libc::CMSG_DATA(cmsg);
                    if !data.is_null() {
                        let mut ifindex: u32 = 0;
                        std::ptr::copy_nonoverlapping(
                            data,
                            std::ptr::from_mut(&mut ifindex).cast::<u8>(),
                            4,
                        );
                        let mut addr: u32 = 0;
                        std::ptr::copy_nonoverlapping(
                            data.add(8),
                            std::ptr::from_mut(&mut addr).cast::<u8>(),
                            4,
                        );
                        meta.ifindex = Some(ifindex);
                        meta.dest = Some(Ipv4Addr::from(u32::from_be(addr)));
                    }
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
        }

        Ok((n as usize, meta))
    }
}

impl AsRawFd for PhysicalSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

impl PhysicalSocket {
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.socket.set_nonblocking(nonblocking)
    }

    /// Move this socket into a Tokio adapter without duplicating or replacing
    /// its descriptor. The socket retains its interface binding, local port and
    /// `IP_PKTINFO` receive metadata.
    ///
    /// This must be called from within a Tokio runtime with I/O enabled.
    pub fn into_async(self) -> io::Result<AsyncPhysicalSocket> {
        AsyncPhysicalSocket::new(self)
    }
}

/// Tokio readiness adapter for the one physical UDP socket.
///
/// STUN requests, handshake frames, health frames and data frames are all sent
/// and received through this object. It never creates another UDP socket.
pub struct AsyncPhysicalSocket {
    io: AsyncFd<PhysicalSocket>,
}

impl AsyncPhysicalSocket {
    /// Register an existing physical socket with the current Tokio reactor.
    ///
    /// The descriptor is put into nonblocking mode. This must be called from
    /// within a Tokio runtime with I/O enabled.
    pub fn new(socket: PhysicalSocket) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        // SAFETY: PhysicalSocket owns a stable descriptor and AsyncFd takes
        // ownership of that same owner until deregistration.
        let io = unsafe { AsyncFd::register(socket)? };
        Ok(Self { io })
    }

    /// Open and register a physical socket in one step.
    pub fn open(interface: &str, bind_ip: Ipv4Addr, port: u16) -> io::Result<Self> {
        PhysicalSocket::open(interface, bind_ip, port)?.into_async()
    }

    /// Access the synchronous owner for address and interface information.
    pub fn get_ref(&self) -> &PhysicalSocket {
        self.io.get_ref()
    }

    /// Send one datagram on the shared physical socket.
    pub async fn send_to(&self, buf: &[u8], target: SocketAddrV4) -> io::Result<usize> {
        self.io
            .async_io(Interest::WRITABLE, |socket| socket.send_to(buf, target))
            .await
    }

    /// Try once on the retained nonblocking socket. WouldBlock need not stall
    /// other healthy transports; control retransmissions remain protocol-owned.
    pub fn try_send_to(&self, buf: &[u8], target: SocketAddrV4) -> io::Result<usize> {
        self.io.get_ref().send_to(buf, target)
    }

    /// Receive one datagram and the original `recvmsg` metadata.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, RecvMeta)> {
        self.io
            .async_io(Interest::READABLE, |socket| socket.recv_from(buf))
            .await
    }

    /// Allocation-free, cancellation-safe receive into caller-retained storage.
    /// Only one read waiter may use a socket at a time.
    pub fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, RecvMeta)>> {
        loop {
            let mut readiness = match self.io.poll_read_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(readiness)) => readiness,
            };
            match readiness.try_io(|io| io.get_ref().recv_from(buf)) {
                Ok(result) => return Poll::Ready(result),
                Err(_) => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn loopback_socket() -> PhysicalSocket {
        PhysicalSocket::open("lo0", Ipv4Addr::LOCALHOST, 0).expect("bind lo0")
    }

    fn async_loopback() -> AsyncPhysicalSocket {
        AsyncPhysicalSocket::open("lo0", Ipv4Addr::LOCALHOST, 0).expect("bind async lo0")
    }

    #[test]
    fn binding_pins_the_interface_and_reads_back() {
        let sock = loopback_socket();
        let expected = super::super::interface::interface_index("lo0").unwrap();
        assert_eq!(sock.bound_ifindex(), expected);
        assert_eq!(sock.interface_name(), "lo0");
        assert_eq!(*sock.local_addr().ip(), Ipv4Addr::LOCALHOST);
        assert_ne!(sock.local_addr().port(), 0);
    }

    #[test]
    fn unknown_interface_is_refused() {
        let err = PhysicalSocket::open("no-such-if", Ipv4Addr::LOCALHOST, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn polled_receive_is_cancellation_safe_and_clears_stale_readiness() {
        let sender = async_loopback();
        let receiver = async_loopback();
        let mut buffer = [0; 64];
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(receiver.poll_recv_from(&mut cx, &mut buffer).is_pending());
        sender
            .send_to(b"first", receiver.get_ref().local_addr())
            .await
            .unwrap();
        let (len, meta) = tokio::time::timeout(
            Duration::from_secs(2),
            std::future::poll_fn(|cx| receiver.poll_recv_from(cx, &mut buffer)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&buffer[..len], b"first");
        assert_eq!(meta.source, sender.get_ref().local_addr());
        assert_eq!(meta.dest, Some(Ipv4Addr::LOCALHOST));
        assert!(receiver.poll_recv_from(&mut cx, &mut buffer).is_pending());
        sender
            .send_to(b"second", receiver.get_ref().local_addr())
            .await
            .unwrap();
        let (len, _) = tokio::time::timeout(
            Duration::from_secs(2),
            std::future::poll_fn(|cx| receiver.poll_recv_from(cx, &mut buffer)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&buffer[..len], b"second");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn send_receive_and_metadata_use_the_same_socket() {
        let a = async_loopback();
        let b = async_loopback();
        let sent = a.send_to(b"hello", b.get_ref().local_addr()).await.unwrap();
        assert_eq!(sent, 5);

        let mut buf = [0u8; 64];
        let (n, meta) = tokio::time::timeout(Duration::from_secs(2), b.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(meta.source, a.get_ref().local_addr());
        assert_eq!(meta.ifindex, Some(a.get_ref().bound_ifindex()));
        assert_eq!(meta.dest, Some(Ipv4Addr::LOCALHOST));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn one_socket_keeps_one_mapping_across_many_sends() {
        let a = async_loopback();
        let b = async_loopback();
        let source_port = a.get_ref().local_addr().port();
        for i in 0..5u8 {
            a.send_to(&[i], b.get_ref().local_addr()).await.unwrap();
            let mut buf = [0u8; 8];
            let (n, meta) = tokio::time::timeout(Duration::from_secs(2), b.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(n, 1);
            assert_eq!(buf[0], i);
            assert_eq!(meta.source.port(), source_port);
        }
        assert_eq!(a.get_ref().local_addr().port(), source_port);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn oversized_datagram_is_truncated_not_panicking() {
        let a = async_loopback();
        let b = async_loopback();
        let big = vec![7u8; 2048];
        a.send_to(&big, b.get_ref().local_addr()).await.unwrap();
        let mut buf = [0u8; 512];
        let (n, _meta) = tokio::time::timeout(Duration::from_secs(2), b.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 512);
        assert!(buf.iter().all(|byte| *byte == 7));
    }
}
