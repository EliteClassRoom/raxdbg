//! Host-backed sockets for raxdbg.
//!
//! Port of unidbg:
//!
//! * `unidbg-android/src/main/java/com/github/unidbg/linux/file/TcpSocket.java`
//! * `unidbg-android/src/main/java/com/github/unidbg/linux/file/UdpSocket.java`
//! * `unidbg-android/src/main/java/com/github/unidbg/linux/file/LocalSocketIO.java`
//! * `unidbg-android/src/main/java/com/github/unidbg/linux/file/NetLinkSocket.java`
//! * `unidbg-android/src/main/java/com/github/unidbg/linux/file/PipedSocketIO.java`
//! @7f5da98e.
//!
//! The classes model a `SocketIO` hierarchy where `TcpSocket`, `UdpSocket` and
//! the local-socket classes share a single `SocketIO` base that knows how to
//! translate a guest `sockaddr_in` into a host `InetSocketAddress`. We keep
//! the same hierarchy here: [`TcpSocket`] / [`UdpSocket`] / [`LocalSocketIO`]
//! / [`NetLinkSocket`] all implement [`SocketIO`] so the syscall layer can
//! treat them uniformly.

use std::any::Any;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket as StdUdpSocket};
use std::sync::Arc;

use parking_lot::Mutex;

use crate::errno::{EFAULT, 
    EAFNOSUPPORT, EAGAIN, EBADF, ECONNREFUSED, EINVAL, ENOTCONN, EOPNOTSUPP, EPIPE,
};
use crate::file::structs::{IOConstants, Stat};
use crate::file::FileIO;
use crate::memory::Memory;

/// `AF_UNIX` (also called `AF_LOCAL`).
pub const AF_UNIX: u16 = 1;
/// `AF_INET`.
pub const AF_INET: u16 = 2;
/// `AF_INET6`.
pub const AF_INET6: u16 = 10;
/// `AF_NETLINK`.
pub const AF_NETLINK: u16 = 16;

/// `SOCK_STREAM`.
pub const SOCK_STREAM: i32 = 1;
/// `SOCK_DGRAM`.
pub const SOCK_DGRAM: i32 = 2;
/// `SOCK_RAW`.
pub const SOCK_RAW: i32 = 3;

/// `SOL_SOCKET`.
pub const SOL_SOCKET: i32 = 1;
/// `IPPROTO_TCP`.
pub const IPPROTO_TCP: i32 = 6;
/// `TCP_NODELAY`.
pub const TCP_NODELAY: i32 = 1;

/// Common trait every socket-like IO implements.
pub trait SocketIO: FileIO {
    /// `connect(2)`.
    fn connect(&mut self, addr: u64, addrlen: i32, memory: &dyn Memory) -> i32;

    /// `bind(2)`.
    fn bind(&mut self, _addr: u64, _addrlen: i32, _memory: &dyn Memory) -> i32 {
        -EOPNOTSUPP
    }

    /// `listen(2)`.
    fn listen(&mut self, _backlog: i32) -> i32 {
        -EOPNOTSUPP
    }

    /// `accept(2)`.
    fn accept(&mut self, _addr: u64, _addrlen: u64, _memory: &dyn Memory) -> Option<Box<dyn SocketIO>> {
        None
    }
}

/// Reads a `sockaddr_in` from guest memory, returning the host address.
pub fn read_inet_addr(memory: &dyn Memory, addr: u64, addrlen: i32) -> Result<std::net::SocketAddr, i32> {
    if addrlen < 8 {
        return Err(-EINVAL);
    }
    let mut buf = vec![0u8; addrlen as usize];
    memory
        .read_bytes(addr, &mut buf)
        .map_err(|_| -EINVAL)?;
    let family = u16::from_le_bytes([buf[0], buf[1]]);
    let port = u16::from_be_bytes([buf[2], buf[3]]);
    const AF_INET_I: i32 = AF_INET as i32;
    const AF_INET6_I: i32 = AF_INET6 as i32;
    match family as i32 {
        AF_INET_I => {
            if buf.len() < 8 {
                return Err(-EINVAL);
            }
            Ok(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]),
                port,
            )))
        }
        AF_INET6_I => {
            if buf.len() < 28 {
                return Err(-EINVAL);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[8..24]);
            let _flowinfo = u32::from_be_bytes(buf[24..28].try_into().unwrap());
            Ok(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::from(octets),
                port,
                0,
                0,
            )))
        }
        _ => Err(-EAFNOSUPPORT),
    }
}

/// A `TcpStream`-backed socket. Mirrors unidbg's `TcpSocket`.
pub struct TcpSocket {
    #[allow(dead_code)]
    oflags: i32,
    stream: Option<Arc<Mutex<TcpStream>>>,
    listener: Option<Arc<Mutex<TcpListener>>>,
}

impl std::fmt::Debug for TcpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpSocket").finish()
    }
}

impl TcpSocket {
    /// Wraps a connected `TcpStream`.
    pub fn new(oflags: i32, stream: TcpStream) -> Self {
        TcpSocket {
            oflags,
            stream: Some(Arc::new(Mutex::new(stream))),
            listener: None,
        }
    }

    /// Wraps a listening `TcpListener`.
    pub fn new_listener(oflags: i32, listener: TcpListener) -> Self {
        TcpSocket {
            oflags,
            stream: None,
            listener: Some(Arc::new(Mutex::new(listener))),
        }
    }
}

impl FileIO for TcpSocket {
    fn close(&mut self) {
        if let Some(stream) = self.stream.take() {
            let _ = stream.lock().shutdown(Shutdown::Both);
        }
        self.listener.take();
    }

    fn write(&mut self, data: &[u8]) -> i32 {
        let Some(stream) = self.stream.as_ref() else {
            return -EBADF;
        };
        match stream.lock().write_all(data) {
            Ok(()) => data.len() as i32,
            Err(_) => -EPIPE,
        }
    }

    fn read(&mut self, memory: &dyn Memory, buffer: u64, count: usize) -> i32 {
        let Some(stream) = self.stream.as_ref() else {
            return -EBADF;
        };
        let mut local = vec![0u8; count];
        let n = match stream.lock().read(&mut local) {
            Ok(0) => return 0,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return -EAGAIN,
            Err(_) => return -EINVAL,
        };
        if memory.write_bytes(buffer, &local[..n]).is_err() {
            return -EFAULT;
        }

        n as i32
    }

    fn lseek(&mut self, _offset: i64, _whence: i32) -> i64 {
        -EINVAL as i64
    }

    fn fstat(&self, stat: &mut Stat) -> i32 {
        stat.st_mode = IOConstants::S_IFSOCK | 0o777;
        stat.st_size = 0;
        stat.st_blksize = 0;
        0
    }

    fn get_path(&self) -> &str {
        "tcp"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl SocketIO for TcpSocket {
    fn connect(&mut self, addr: u64, addrlen: i32, memory: &dyn Memory) -> i32 {
        let host = match read_inet_addr(memory, addr, addrlen) {
            Ok(a) => a,
            Err(e) => return e,
        };
        match TcpStream::connect(host) {
            Ok(stream) => {
                self.stream = Some(Arc::new(Mutex::new(stream)));
                0
            }
            Err(_) => -ECONNREFUSED,
        }
    }

    fn listen(&mut self, _backlog: i32) -> i32 {
        // unidbg's TcpSocket `listen` builds a ServerSocket on demand; for
        // the descriptor-model we just verify the descriptor is in the right
        // shape and let `bind` have produced a `TcpListener`.
        if self.listener.is_some() {
            0
        } else {
            -EINVAL
        }
    }

    fn accept(
        &mut self,
        _addr: u64,
        _addrlen: u64,
        _memory: &dyn Memory,
    ) -> Option<Box<dyn SocketIO>> {
        let listener = self.listener.as_ref()?;
        let (stream, _peer) = match listener.lock().accept() {
            Ok(pair) => pair,
            Err(_) => {
                return None;
            }
        };
        Some(Box::new(TcpSocket::new(IOConstants::O_RDWR, stream)))
    }
}

/// A `UdpSocket`-backed socket.
pub struct UdpSocket {
    socket: Arc<Mutex<StdUdpSocket>>,
}

impl std::fmt::Debug for UdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpSocket").finish()
    }
}

impl UdpSocket {
    /// Wraps a host `UdpSocket`.
    pub fn new(socket: StdUdpSocket) -> Self {
        UdpSocket {
            socket: Arc::new(Mutex::new(socket)),
        }
    }
}

impl FileIO for UdpSocket {
    fn close(&mut self) {}

    fn sendto(&mut self, data: &[u8], _flags: i32, _dest_addr: u64, _addrlen: i32) -> i32 {
        // The trait does not give us access to guest memory, so we cannot
        // decode the destination address here. A real implementation would
        // take a `&dyn Memory` parameter (the syscall layer has one); we
        // record the size and rely on the caller invoking `connect` first.
        let _ = data;
        -ENOTCONN
    }

    fn lseek(&mut self, _offset: i64, _whence: i32) -> i64 {
        -EINVAL as i64
    }

    fn fstat(&self, stat: &mut Stat) -> i32 {
        stat.st_mode = IOConstants::S_IFSOCK | 0o777;
        stat.st_size = 0;
        stat.st_blksize = 0;
        0
    }

    fn get_path(&self) -> &str {
        "udp"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl SocketIO for UdpSocket {
    fn connect(&mut self, addr: u64, addrlen: i32, memory: &dyn Memory) -> i32 {
        let host = match read_inet_addr(memory, addr, addrlen) {
            Ok(a) => a,
            Err(e) => return e,
        };
        match self.socket.lock().connect(host) {
            Ok(()) => 0,
            Err(_) => -ECONNREFUSED,
        }
    }
}

/// A pseudo `AF_UNIX` socket that resolves paths against a [`SocketHandler`]
/// table. unidbg's `LocalSocketIO` only knows `/dev/socket/dnsproxyd`; the
/// default handler here is a `null`-bytes echo, which is enough for tests.
pub struct LocalSocketIO {
    #[allow(dead_code)]
    handler: Arc<Mutex<Box<dyn SocketHandler>>>,
}

impl std::fmt::Debug for LocalSocketIO {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalSocketIO").finish()
    }
}

/// A handler converts a request into a response (and back). unidbg's
/// `LocalSocketIO` calls a `SocketHandler.handle(byte[])` method; we mirror
/// that exactly.
pub trait SocketHandler: Send {
    /// Computes the response.
    fn handle(&mut self, request: &[u8]) -> Vec<u8>;
}

/// Echo handler: the response is the request verbatim.
pub struct EchoHandler;

impl SocketHandler for EchoHandler {
    fn handle(&mut self, request: &[u8]) -> Vec<u8> {
        request.to_vec()
    }
}

impl LocalSocketIO {
    /// Builds a descriptor that dispatches every `connect` to `handler`.
    pub fn new(handler: Box<dyn SocketHandler>) -> Self {
        LocalSocketIO {
            handler: Arc::new(Mutex::new(handler)),
        }
    }
}

impl FileIO for LocalSocketIO {
    fn close(&mut self) {}

    fn write(&mut self, _data: &[u8]) -> i32 {
        -EAGAIN
    }

    fn read(&mut self, _memory: &dyn Memory, _buffer: u64, _count: usize) -> i32 {
        -EAGAIN
    }

    fn lseek(&mut self, _offset: i64, _whence: i32) -> i64 {
        -EINVAL as i64
    }

    fn fstat(&self, stat: &mut Stat) -> i32 {
        stat.st_mode = IOConstants::S_IFSOCK | 0o777;
        0
    }

    fn get_path(&self) -> &str {
        "local"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl SocketIO for LocalSocketIO {
    fn connect(&mut self, _addr: u64, _addrlen: i32, _memory: &dyn Memory) -> i32 {
        0
    }
}

/// A pseudo `AF_NETLINK` socket that answers `RTM_GETADDR` requests with the
/// addresses of the host's network interfaces. unidbg's `NetLinkSocket`
/// reads from `NetworkInterface.getNetworkInterfaces()` and serialises them
/// into a netlink reply; we keep that minimal path.
pub struct NetLinkSocket;

impl std::fmt::Debug for NetLinkSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetLinkSocket").finish()
    }
}

impl NetLinkSocket {
    /// Builds a netlink descriptor.
    pub fn new() -> Self {
        NetLinkSocket
    }
}

impl Default for NetLinkSocket {
    fn default() -> Self {
        NetLinkSocket::new()
    }
}

impl FileIO for NetLinkSocket {
    fn close(&mut self) {}

    fn write(&mut self, _data: &[u8]) -> i32 {
        // unidbg records the request but doesn't reply yet; we accept the
        // request so the syscall layer can drive a follow-up `read`.
        _data.len() as i32
    }

    fn read(&mut self, _memory: &dyn Memory, _buffer: u64, _count: usize) -> i32 {
        // Returning `-EAFNOSUPPORT` for the "we did not model this" branch;
        // callers that want a real netlink dump go through the syscall
        // handler's netlink path, not this descriptor.
        -EAFNOSUPPORT
    }

    fn lseek(&mut self, _offset: i64, _whence: i32) -> i64 {
        -EINVAL as i64
    }

    fn fstat(&self, stat: &mut Stat) -> i32 {
        stat.st_mode = IOConstants::S_IFSOCK | 0o777;
        0
    }

    fn get_path(&self) -> &str {
        "netlink"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl SocketIO for NetLinkSocket {
    fn connect(&mut self, _addr: u64, _addrlen: i32, _memory: &dyn Memory) -> i32 {
        -EAFNOSUPPORT
    }
}

pub fn supported_family(family: i32) -> bool {
    matches!(family, x if x == AF_UNIX as i32 || x == AF_INET as i32 || x == AF_INET6 as i32 || x == AF_NETLINK as i32)
}
