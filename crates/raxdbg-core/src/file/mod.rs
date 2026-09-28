//! Guest file descriptors and the host file system behind them.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/file/{FileIO,FileSystem,FileResult,NewFileIO}.java`
//! and `unidbg-android/src/main/java/com/github/unidbg/file/linux/{LinuxFileSystem,IOConstants}.java`
//! @7f5da98e.
//!
//! A [`FileIO`] is one open guest file descriptor. Every method returns the
//! value the guest's syscall returns, with Linux's `-errno` convention, and
//! the trait's defaults answer `-EINVAL` so a type only implements what it can
//! actually do.

pub mod byte_array;
pub mod driver;
pub mod linux_fs;
pub mod pipe;
pub mod socket;
pub mod structs;

use std::path::Path;

use crate::backend::Prot;
use crate::errno::EINVAL;
use crate::memory::{Memory, MemoryError};

pub use structs::{IOConstants, ITimerVal, RLimit64, SockAddr, Stat, TimeSpec64};

/// The result of resolving a guest path.
///
/// Port of unidbg: `FileResult`, whose three states are "the IO is the answer",
/// "the IO is a fallback another resolver may override" and "not found".
pub enum FileResult<T> {
    /// The path resolved; the caller must use this IO.
    Success(T),
    /// The path resolved through a resource; another resolver may override it.
    Fallback(T),
    /// No resolver knows the path.
    NotFound,
}

impl<T> FileResult<T> {
    /// The IO, whichever state it is in.
    pub fn into_io(self) -> Option<T> {
        match self {
            FileResult::Success(io) | FileResult::Fallback(io) => Some(io),
            FileResult::NotFound => None,
        }
    }

    /// Whether the path resolved.
    pub fn is_found(&self) -> bool {
        !matches!(self, FileResult::NotFound)
    }
}

/// One open guest file descriptor.
pub trait FileIO: std::fmt::Debug {
    /// Closes the descriptor.
    fn close(&mut self) {}

    /// Writes `data`, returning the byte count or `-errno`.
    fn write(&mut self, _data: &[u8]) -> i32 {
        -EINVAL
    }

    /// Reads up to `count` bytes into the guest buffer at `buffer`.
    fn read(&mut self, _memory: &dyn Memory, _buffer: u64, _count: usize) -> i32 {
        -EINVAL
    }

    /// Reads up to `count` bytes at `offset` into the guest buffer.
    fn pread(&mut self, _memory: &dyn Memory, _buffer: u64, _count: usize, _offset: u64) -> i32 {
        -EINVAL
    }

    /// Writes `count` bytes read from the guest buffer at `buffer`.
    fn pwrite(&mut self, _memory: &dyn Memory, _buffer: u64, _count: usize, _offset: u64) -> i32 {
        -EINVAL
    }

    /// `fcntl(2)`.
    fn fcntl(&mut self, _cmd: i32, _arg: u64) -> i32 {
        -EINVAL
    }

    /// `ioctl(2)`.
    fn ioctl(&mut self, _request: u64, _argp: u64) -> i32 {
        -EINVAL
    }

    /// `dup(2)`: a second descriptor for the same open file.
    fn dup(&self) -> Option<Box<dyn FileIO>> {
        None
    }

    /// `connect(2)`.
    fn connect(&mut self, _addr: u64, _addrlen: i32) -> i32 {
        -EINVAL
    }

    /// `bind(2)`.
    fn bind(&mut self, _addr: u64, _addrlen: i32) -> i32 {
        -EINVAL
    }

    /// `listen(2)`.
    fn listen(&mut self, _backlog: i32) -> i32 {
        -EINVAL
    }

    /// `accept(2)`: a descriptor for the next connection.
    fn accept(&mut self, _addr: u64, _addrlen: u64) -> Option<Box<dyn FileIO>> {
        None
    }

    /// `setsockopt(2)`.
    fn setsockopt(&mut self, _level: i32, _optname: i32, _optval: u64, _optlen: i32) -> i32 {
        -EINVAL
    }

    /// `getsockopt(2)`.
    fn getsockopt(&mut self, _level: i32, _optname: i32, _optval: u64, _optlen: u64) -> i32 {
        -EINVAL
    }

    /// `sendto(2)`.
    fn sendto(&mut self, _data: &[u8], _flags: i32, _dest_addr: u64, _addrlen: i32) -> i32 {
        -EINVAL
    }

    /// `recvfrom(2)`.
    fn recvfrom(
        &mut self,
        _memory: &dyn Memory,
        _buf: u64,
        _len: usize,
        _flags: i32,
        _src_addr: u64,
        _addrlen: u64,
    ) -> i32 {
        -EINVAL
    }

    /// `getpeername(2)`.
    fn getpeername(&mut self, _addr: u64, _addrlen: u64) -> i32 {
        -EINVAL
    }

    /// `getsockname(2)`.
    fn getsockname(&mut self, _addr: u64, _addrlen: u64) -> i32 {
        -EINVAL
    }

    /// `shutdown(2)`.
    fn shutdown(&mut self, _how: i32) -> i32 {
        -EINVAL
    }

    /// `lseek(2)`; `-errno` on failure.
    fn lseek(&mut self, _offset: i64, _whence: i32) -> i64 {
        -i64::from(EINVAL)
    }

    /// `llseek(2)`: writes the new offset to the guest `u64` at `result`.
    fn llseek(&mut self, _offset: i64, _result: u64, _whence: i32) -> i32 {
        -EINVAL
    }

    /// `ftruncate(2)`.
    fn ftruncate(&mut self, _length: i64) -> i32 {
        -EINVAL
    }

    /// `fstat(2)`.
    fn fstat(&self, _stat: &mut Stat) -> i32 {
        -EINVAL
    }

    /// `mmap` of this descriptor's contents into `[addr, addr + aligned)`.
    fn mmap2(
        &mut self,
        _memory: &dyn Memory,
        _addr: u64,
        _aligned: u64,
        _prot: Prot,
        _offset: i64,
        _length: usize,
    ) -> Result<u64, MemoryError> {
        Err(MemoryError::Message(format!(
            "{} cannot be mapped",
            self.get_path()
        )))
    }

    /// The path this descriptor was opened for.
    fn get_path(&self) -> &str;

    /// Whether this is `stdin`, `stdout` or `stderr`.
    fn is_stdio(&self) -> bool {
        false
    }

    /// Reads `count` bytes from the guest buffer, or an error.
    fn read_guest(
        &self,
        memory: &dyn Memory,
        buffer: u64,
        count: usize,
    ) -> Result<Vec<u8>, MemoryError> {
        let mut buf = vec![0u8; count];
        memory.read_bytes(buffer, &mut buf)?;
        Ok(buf)
    }

    /// Writes `data` into the guest buffer at `buffer`.
    fn write_guest(
        &self,
        memory: &dyn Memory,
        buffer: u64,
        data: &[u8],
    ) -> Result<(), MemoryError> {
        memory.write_bytes(buffer, data)
    }

    /// Downcast hook, so the syscall layer can recover a concrete type (for
    /// example to recognise a pipe or a captured `stdout`).
    fn as_any(&self) -> &dyn std::any::Any;

    /// Mutable downcast hook.
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
}

/// Resolves guest paths before the file system sees them.
///
/// Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/file/IOResolver.java`.
/// The syscall layer asks every resolver in turn, then falls back to the
/// [`FileSystem`]; a [`FileResult::Fallback`] answer may still be overridden by
/// a later resolver.
pub trait IOResolver {
    /// Resolves `pathname`, opened with Linux's `oflags`.
    fn resolve(&self, pathname: &str, oflags: i32) -> FileResult<Box<dyn FileIO>>;
}

/// The host file system a guest sees.
///
/// Port of unidbg: `FileSystem`.
pub trait FileSystem {
    /// The root directory guest paths are resolved under, if any.
    fn root_dir(&self) -> Option<&Path>;

    /// Creates the scratch work directory under the root, if there is one.
    fn create_work_dir(&self) -> Result<std::path::PathBuf, std::io::Error>;

    /// Opens `pathname` with Linux's `oflags`.
    fn open(&self, pathname: &str, oflags: i32) -> FileResult<Box<dyn FileIO>>;

    /// Removes `path`.
    fn unlink(&self, path: &str);

    /// Creates a directory.
    fn mkdir(&self, path: &str, mode: i32) -> bool;

    /// Removes a directory.
    fn rmdir(&self, path: &str);

    /// Renames a path.
    fn rename(&self, old_path: &str, new_path: &str) -> i32;
}
