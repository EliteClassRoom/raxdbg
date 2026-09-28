//! Linux error numbers.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/unix/UnixEmulator.java`
//! @7f5da98e (the `E*` constants unidbg's syscall handlers return).

/// Operation not permitted.
pub const EPERM: i32 = 1;
/// No such file or directory.
pub const ENOENT: i32 = 2;
/// No such process.
pub const ESRCH: i32 = 3;
/// Interrupted system call.
pub const EINTR: i32 = 4;
/// Input/output error.
pub const EIO: i32 = 5;
/// No such device or address.
pub const ENXIO: i32 = 6;
/// Argument list too long.
pub const E2BIG: i32 = 7;
/// Exec format error.
pub const ENOEXEC: i32 = 8;
/// Bad file descriptor.
pub const EBADF: i32 = 9;
/// No child processes.
pub const ECHILD: i32 = 10;
/// Resource temporarily unavailable (also `EWOULDBLOCK`).
pub const EAGAIN: i32 = 11;
/// Cannot allocate memory.
pub const ENOMEM: i32 = 12;
/// Permission denied.
pub const EACCES: i32 = 13;
/// Bad address.
pub const EFAULT: i32 = 14;
/// Block device required.
pub const ENOTBLK: i32 = 15;
/// Device or resource busy.
pub const EBUSY: i32 = 16;
/// File exists.
pub const EEXIST: i32 = 17;
/// Invalid cross-device link.
pub const EXDEV: i32 = 18;
/// No such device.
pub const ENODEV: i32 = 19;
/// Not a directory.
pub const ENOTDIR: i32 = 20;
/// Is a directory.
pub const EISDIR: i32 = 21;
/// Invalid argument.
pub const EINVAL: i32 = 22;
/// Too many open files in system.
pub const ENFILE: i32 = 23;
/// Too many open files.
pub const EMFILE: i32 = 24;
/// Inappropriate ioctl for device.
pub const ENOTTY: i32 = 25;
/// Text file busy.
pub const ETXTBSY: i32 = 26;
/// File too large.
pub const EFBIG: i32 = 27;
/// No space left on device.
pub const ENOSPC: i32 = 28;
/// Illegal seek.
pub const ESPIPE: i32 = 29;
/// Read-only file system.
pub const EROFS: i32 = 30;
/// Too many links.
pub const EMLINK: i32 = 31;
/// Broken pipe.
pub const EPIPE: i32 = 32;
/// Numerical argument out of domain.
pub const EDOM: i32 = 33;
/// Numerical result out of range.
pub const ERANGE: i32 = 34;
/// Resource deadlock avoided.
pub const EDEADLK: i32 = 35;
/// File name too long.
pub const ENAMETOOLONG: i32 = 36;
/// No locks available.
pub const ENOLCK: i32 = 37;
/// Function not implemented.
pub const ENOSYS: i32 = 38;
/// Directory not empty.
pub const ENOTEMPTY: i32 = 39;
/// Too many levels of symbolic links.
pub const ELOOP: i32 = 40;
/// No message of desired type.
pub const ENOMSG: i32 = 42;
/// Identifier removed.
pub const EIDRM: i32 = 43;
/// Channel number out of range.
pub const ECHRNG: i32 = 44;
/// Operation would block (the same value as [`EAGAIN`] on Linux).
pub const EWOULDBLOCK: i32 = EAGAIN;
/// Operation now in progress.
pub const EINPROGRESS: i32 = 115;
/// Operation already in progress.
pub const EALREADY: i32 = 114;
/// Socket operation on non-socket.
pub const ENOTSOCK: i32 = 88;
/// Destination address required.
pub const EDESTADDRREQ: i32 = 89;
/// Message too long.
pub const EMSGSIZE: i32 = 90;
/// Protocol wrong type for socket.
pub const EPROTOTYPE: i32 = 91;
/// Protocol not available.
pub const ENOPROTOOPT: i32 = 92;
/// Protocol not supported.
pub const EPROTONOSUPPORT: i32 = 93;
/// Socket type not supported.
pub const ESOCKTNOSUPPORT: i32 = 94;
/// Operation not supported.
pub const EOPNOTSUPP: i32 = 95;
/// Protocol family not supported.
pub const EPFNOSUPPORT: i32 = 96;
/// Address family not supported by protocol.
pub const EAFNOSUPPORT: i32 = 97;
/// Address already in use.
pub const EADDRINUSE: i32 = 98;
/// Cannot assign requested address.
pub const EADDRNOTAVAIL: i32 = 99;
/// Network is down.
pub const ENETDOWN: i32 = 100;
/// Network is unreachable.
pub const ENETUNREACH: i32 = 101;
/// Network dropped connection on reset.
pub const ENETRESET: i32 = 102;
/// Software caused connection abort.
pub const ECONNABORTED: i32 = 103;
/// Connection reset by peer.
pub const ECONNRESET: i32 = 104;
/// No buffer space available.
pub const ENOBUFS: i32 = 105;
/// Transport endpoint is already connected.
pub const EISCONN: i32 = 106;
/// Transport endpoint is not connected.
pub const ENOTCONN: i32 = 107;
/// Cannot send after transport endpoint shutdown.
pub const ESHUTDOWN: i32 = 108;
/// Connection timed out.
pub const ETIMEDOUT: i32 = 110;
/// Connection refused.
pub const ECONNREFUSED: i32 = 111;
/// Host is down.
pub const EHOSTDOWN: i32 = 112;
/// No route to host.
pub const EHOSTUNREACH: i32 = 113;
/// Operation canceled.
pub const ECANCELED: i32 = 125;
/// Owner died.
pub const EOWNERDEAD: i32 = 130;
/// State not recoverable.
pub const ENOTRECOVERABLE: i32 = 131;
