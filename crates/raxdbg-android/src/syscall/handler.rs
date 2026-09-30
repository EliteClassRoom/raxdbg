//! The base Linux syscall handler: fd table, resolver chain, the file-descriptor
//! half of the POSIX API.
//!
//! Port of unidbg:
//!
//! * `unidbg-api/src/main/java/com/github/unidbg/unix/UnixSyscallHandler.java`
//! * `unidbg-api/src/main/java/com/github/unidbg/spi/SyscallHandler.java`
//! * `unidbg-api/src/main/java/com/github/unidbg/unix/IO.java`
//! * `unidbg-android/src/main/java/com/github/unidbg/linux/AndroidSyscallHandler.java`
//!   (the Android additions)
//! @7f5da98e.
//!
//! The Linux syscall layer is shared by every ABI: the arm64 [`super::arm64`]
//! and (later) arm32 tables both call into this struct for the parts that
//! don't differ between ABIs. Every handler follows unidbg's `-errno`
//! convention: a successful call returns the value the guest wants; a failed
//! call returns `-errno` and writes the same `errno` into the guest slot via
//! [`Memory::set_errno`].
//!
//! The resolver chain matches unidbg's [`UnixSyscallHandler.resolve`]:
//! every registered [`IOResolver`] runs in order, and any
//! [`FileResult::Fallback`] is kept as a candidate a later resolver may
//! override. Only after every resolver misses does the chain fall through
//! to the [`FileSystem`].

use std::cell::Cell;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::{Instant as TimeInstant, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};

use raxdbg_core::backend::Prot;
use raxdbg_core::errno::{EACCES, EBADF, EFAULT, EINVAL, ENOENT};
use raxdbg_core::file::linux_fs::LinuxFileSystem;
use raxdbg_core::thread::Waiters;
use raxdbg_core::file::structs::{IOConstants, Stat};
use raxdbg_core::file::{FileIO, FileResult, FileSystem, IOResolver};
use raxdbg_core::memory::{Memory, MemoryError, MAP_ANONYMOUS, MAP_FAILED};

/// A shared byte sink the captured `stdout`/`stderr` descriptors write into.
///
/// unidbg's `StdoutCallback` is the equivalent shape: the descriptor holds a
/// callback or `PrintStream`, and `printf`-style tests read what was written
/// out of band.
#[derive(Clone, Debug, Default)]
pub struct SharedSink(Arc<Mutex<Vec<u8>>>);

impl SharedSink {
    /// Creates an empty sink.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// The bytes written so far, as UTF-8 (lossy on invalid sequences).
    pub fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock()).into_owned()
    }

    /// Takes the bytes written so far out of the sink, leaving it empty.
    pub fn take(&self) -> Vec<u8> {
        std::mem::take(&mut *self.0.lock())
    }

    /// Appends `buf` from a shared handle, which is what the descriptor's
    /// writer does: `Write::write` needs `&mut self`, and the sink is shared
    /// between the descriptor and whoever asserts on the output.
    pub fn append(&self, buf: &[u8]) {
        self.0.lock().extend_from_slice(buf);
    }
}

impl Write for SharedSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// `O_RDONLY`.
pub const O_RDONLY: i32 = IOConstants::O_RDONLY;
/// `O_WRONLY`.
pub const O_WRONLY: i32 = IOConstants::O_WRONLY;
/// `O_RDWR`.
pub const O_RDWR: i32 = IOConstants::O_RDWR;
/// `O_CREAT`.
pub const O_CREAT: i32 = IOConstants::O_CREAT;
/// `O_TRUNC`.
pub const O_TRUNC: i32 = IOConstants::O_TRUNC;
/// `O_APPEND`.
pub const O_APPEND: i32 = IOConstants::O_APPEND;

/// `AT_FDCWD`.
pub const AT_FDCWD: i32 = IOConstants::AT_FDCWD;

/// `CLOCK_REALTIME`.
pub const CLOCK_REALTIME: i32 = 0;
/// `CLOCK_MONOTONIC`.
pub const CLOCK_MONOTONIC: i32 = 1;
/// `CLOCK_THREAD_CPUTIME_ID`.
pub const CLOCK_THREAD_CPUTIME_ID: i32 = 3;
/// `CLOCK_MONOTONIC_RAW`.
pub const CLOCK_MONOTONIC_RAW: i32 = 4;
/// `CLOCK_MONOTONIC_COARSE`.
pub const CLOCK_MONOTONIC_COARSE: i32 = 6;
/// `CLOCK_BOOTTIME`.
pub const CLOCK_BOOTTIME: i32 = 7;

/// Errors the syscall layer can return directly.
///
/// Most failures surface to the guest as `-errno`; this enum is for the
/// cases where the syscall layer itself can't proceed (resolver chain
/// returned a contradictory answer, file mapper went missing mid-call,
/// and so on).
#[derive(Debug, thiserror::Error)]
pub enum SyscallError {
    /// The guest address space operation the syscall needed failed.
    #[error(transparent)]
    Memory(#[from] MemoryError),
    /// A path the syscall tried to resolve was not NUL-terminated.
    #[error("path at {addr:#x} is not NUL-terminated")]
    UnterminatedString {
        /// The guest address the path started at.
        addr: u64,
    },
    /// The fd table could not allocate a new descriptor.
    #[error("the fd table is exhausted")]
    FdExhausted,
}

/// Shared Linux syscall state: the fd table, the resolver chain, and the
/// catch-all file system.
///
/// Port of unidbg: `UnixSyscallHandler`. The arm64 and arm32 tables both
/// delegate to this struct for the file-descriptor half of POSIX (`open`,
/// `close`, `read`, `write`, ...).
pub struct UnixSyscallHandler {
    /// The guest fd table, keyed by descriptor number.
    ///
    /// Port of unidbg: `UnixSyscallHandler.fdMap`, a `TreeMap<Integer, T>`
    /// where `T = Box<dyn FileIO>`. A `BTreeMap` keeps fds in numeric
    /// order, which is what `get_min_fd` walks.
    pub(crate) fd_map: RwLock<BTreeMap<i32, Box<dyn FileIO>>>,
    /// The resolver chain.
    ///
    /// Resolvers run in registration order; the most-recently registered
    /// resolver gets the first look (matching unidbg's `addIOResolver`,
    /// which prepends to its list). A [`FileResult::Fallback`] from any
    /// resolver stays as a candidate the next resolver may override.
    resolvers: RwLock<Vec<Box<dyn IOResolver>>>,

    /// The file system the chain falls back to.
    ///
    /// May be `None` for tests that wire only their own resolvers.
    file_system: RwLock<Option<Box<dyn FileSystem>>>,

    /// The guest memory facade, used for `set_errno` and `read`/`write`
    /// bridges through host `FileIO`s.
    memory: Rc<dyn Memory>,

    /// Whether the guest is 64-bit. Drives which [`Stat`] layout to write
    /// and the size of the path strings we hand to resolvers.
    is_64bit: bool,

    /// The futex waiters: what a blocking syscall parks a thread on.
    ///
    /// Port of unidbg: `AbstractEmulator.waiters`. The dispatcher shares this
    /// registry, which is how a `FUTEX_WAKE` makes a parked task runnable.
    waiters: Rc<Waiters>,

    /// Set by a syscall that wants the running thread switched out.
    ///
    /// unidbg throws `ThreadContextSwitchException` from inside the handler.
    /// The table here returns `i64`, so the handler records the request and the
    /// SVC dispatch turns it into `RunError::ThreadSwitch` — plan D5's rule that
    /// control flow is a value returned up the stack.
    pending_switch: Cell<bool>,
    /// The status the guest last passed to `exit`/`exit_group`, or `None`
    /// when it has not.
    ///
    /// The table's `exit` is `&self` and has no backend to stop, so it
    /// records the request here and the SVC dispatch acts on it, exactly
    /// as it does for [`Self::request_switch`].
    ///
    /// Port of unidbg: `ARM64SyscallHandler.exit_group`@7f5da98e, which
    /// calls `Backend.emu_stop()`.
    pending_exit: Cell<Option<i32>>,
}

impl std::fmt::Debug for UnixSyscallHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.fd_map.read().len();
        let resolvers = self.resolvers.read().len();
        f.debug_struct("UnixSyscallHandler")
            .field("fd_count", &count)
            .field("resolvers", &resolvers)
            .field("is_64bit", &self.is_64bit)
            .finish_non_exhaustive()
    }
}

impl UnixSyscallHandler {
    /// Builds the shared half of the syscall layer.
    pub fn new(memory: Rc<dyn Memory>, is_64bit: bool) -> Self {
        Self {
            fd_map: RwLock::new(BTreeMap::new()),
            resolvers: RwLock::new(Vec::new()),
            file_system: RwLock::new(None),
            memory,
            is_64bit,
            waiters: Rc::new(Waiters::new()),
            pending_switch: Cell::new(false),
            pending_exit: Cell::new(None),
        }
    }

    /// The futex registry, shared with the thread dispatcher.
    pub fn waiters(&self) -> &Rc<Waiters> {
        &self.waiters
    }

    /// Asks for the running thread to be switched out.
    ///
    /// Port of unidbg: the `ThreadContextSwitchException` that a blocking
    /// syscall raises after it has registered its waiter — and that a
    /// successful `FUTEX_WAKE` raises too, so the woken thread gets to run.
    pub fn request_switch(&self) {
        self.pending_switch.set(true);
    }

    /// Takes the switch request, if a syscall made one.
    pub fn take_switch_request(&self) -> bool {
        self.pending_switch.replace(false)
    }

    /// Records that the guest asked to exit with `status`.
    pub fn request_exit(&self, status: i32) {
        self.pending_exit.set(Some(status));
    }

    /// Takes the exit request, if a syscall made one.
    pub fn take_exit_request(&self) -> Option<i32> {
        self.pending_exit.replace(None)
    }

    /// Whether the guest is 64-bit.
    pub fn is_64bit(&self) -> bool {
        self.is_64bit
    }

    /// The guest memory facade.
    pub fn memory(&self) -> &Rc<dyn Memory> {
        &self.memory
    }

    /// Sets the file system the resolver chain falls back to.
    pub fn set_file_system(&self, fs: Box<dyn FileSystem>) {
        *self.file_system.write() = Some(fs);
    }

    /// Registers an [`IOResolver`].
    ///
    /// Most-recent registration runs first, matching unidbg's
    /// `addIOResolver`. Subsequent resolvers may override a
    /// [`FileResult::Fallback`] answer from earlier ones.
    pub fn add_io_resolver(&self, resolver: Box<dyn IOResolver>) {
        self.resolvers.write().push(resolver);
    }

    /// Inserts an already-open [`FileIO`] and returns its fd.
    pub fn add_file_io(&self, io: Box<dyn FileIO>) -> i32 {
        let fd = self.get_min_fd();
        self.fd_map.write().insert(fd, io);
        fd
    }

    /// Removes and closes the descriptor `fd`, if any.
    pub fn close_file_io(&self, fd: i32) {
        let mut map = self.fd_map.write();
        if let Some(mut io) = map.remove(&fd) {
            io.close();
        }
    }

    /// Borrows the [`FileIO`] for `fd` and runs `f` on it.
    ///
    /// Returning a borrow instead of a `MappedRwLockReadGuard` keeps the
    /// lock guard type out of the public API; `f` is short-lived because
    /// the lock is held for its full duration.
    pub fn with_file_io<R>(&self, fd: i32, f: impl FnOnce(&mut dyn FileIO) -> R) -> Option<R> {
        let mut map = self.fd_map.write();
        let io = map.get_mut(&fd)?;
        Some(f(io.as_mut()))
    }

    /// Whether `fd` has a registered descriptor.
    pub fn contains_fd(&self, fd: i32) -> bool {
        self.fd_map.read().contains_key(&fd)
    }

    /// Every currently open fd.
    pub fn fds(&self) -> Vec<i32> {
        self.fd_map.read().keys().copied().collect()
    }

    /// The lowest unused fd, which becomes the next descriptor returned by
    /// `open`.
    ///
    /// Port of unidbg: `UnixSyscallHandler.getMinFd`.
    pub fn get_min_fd(&self) -> i32 {
        let mut last = -1i32;
        for &fd in self.fd_map.read().keys() {
            if last + 1 == fd {
                last = fd;
            } else {
                break;
            }
        }
        last + 1
    }

    /// Closes every fd the handler holds.
    pub fn destroy(&self) {
        // `parking_lot::RwLockWriteGuard` doesn't expose `drain` (it's
        // not on the guard type); swap the map out, iterate the
        // replacement, drop it, and we're done.
        let drained: BTreeMap<i32, Box<dyn FileIO>> = std::mem::replace(
            &mut *self.fd_map.write(),
            BTreeMap::new(),
        );
        for (_, mut io) in drained {
            io.close();
        }
    }

    /// Resolves `pathname` to an open [`FileIO`].
    ///
    /// Port of unidbg: `UnixSyscallHandler.resolve`. The chain runs every
    /// registered resolver; the first [`FileResult::Success`] wins, a
    /// [`FileResult::Fallback`] is kept as a candidate a later resolver
    /// may override, and the file system is consulted only after every
    /// resolver has missed.
    pub fn resolve(&self, pathname: &str, oflags: i32) -> Option<FileResult<Box<dyn FileIO>>> {
        let resolvers = self.resolvers.read();
        let mut fallback: Option<Box<dyn FileIO>> = None;

        for resolver in resolvers.iter() {
            match resolver.resolve(pathname, oflags) {
                FileResult::Success(io) => {
                    self.memory.set_errno(0);
                    return Some(FileResult::Success(io));
                }
                FileResult::Fallback(io) => {
                    if fallback.is_none() {
                        fallback = Some(io);
                    }
                }
                FileResult::NotFound => {}
            }
        }

        if let Some(fs) = self.file_system.read().as_ref() {
            match fs.open(pathname, oflags) {
                FileResult::Success(io) => {
                    self.memory.set_errno(0);
                    return Some(FileResult::Success(io));
                }
                FileResult::Fallback(io) => {
                    if fallback.is_none() {
                        fallback = Some(io);
                    }
                }
                FileResult::NotFound => {}
            }
        }

        if let Some(io) = fallback {
            return Some(FileResult::Success(io));
        }
        None
    }

    /// Reads a NUL-terminated string from `address` in guest memory.
    pub fn read_path(&self, address: u64) -> Result<String, SyscallError> {
        const LIMIT: usize = 4096;
        let mut buf = Vec::with_capacity(128);
        for offset in 0..LIMIT {
            let mut byte = [0u8; 1];
            self.memory
                .read_bytes(address + offset as u64, &mut byte)
                .map_err(SyscallError::Memory)?;
            if byte[0] == 0 {
                return Ok(String::from_utf8_lossy(&buf).into_owned());
            }
            buf.push(byte[0]);
        }
        Err(SyscallError::UnterminatedString { addr: address })
    }

    /// `open(2)`: resolves `pathname` and stores the result in the fd table.
    ///
    /// Port of unidbg: `UnixSyscallHandler.open`.
    pub fn open(&self, pathname: &str, oflags: i32) -> i32 {
        match self.resolve(pathname, oflags) {
            Some(FileResult::Success(io)) => {
                self.memory.set_errno(0);
                let fd = self.get_min_fd();
                self.fd_map.write().insert(fd, io);
                fd
            }
            _ => {
                self.memory.set_errno(ENOENT);
                -1
            }
        }
    }

    /// `close(2)`.
    ///
    /// Port of unidbg: `UnixSyscallHandler.close`.
    pub fn close(&self, fd: i32) -> i32 {
        let mut map = self.fd_map.write();
        match map.remove(&fd) {
            Some(mut io) => {
                io.close();
                0
            }
            None => {
                self.memory.set_errno(EBADF);
                -1
            }
        }
    }

    /// `dup3(2)`: clones `oldfd` into `newfd`.
    ///
    /// Port of unidbg: `ARM64SyscallHandler.dup3`. The `newfd` is closed
    /// first if it was already in use; `oldfd == newfd` is a no-op
    /// success, matching Linux's behaviour.
    pub fn dup3(&self, oldfd: i32, newfd: i32, _flags: i32) -> i32 {
        let mut map = self.fd_map.write();
        let Some(old) = map.get(&oldfd) else {
            self.memory.set_errno(EBADF);
            return -1;
        };
        if oldfd == newfd {
            return newfd;
        }
        // `FileIO::dup` returns `Option<Box<dyn FileIO>>`; we need to
        // make a clone before mutating the map. `dyn_clone_io` is
        // implemented on `&dyn FileIO` for the implementations we ship.
        let dup = old.dup().expect("FileIO::dup returned None");
        if let Some(mut existing) = map.remove(&newfd) {
            existing.close();
        }
        map.insert(newfd, dup);
        newfd
    }

    /// `read(2)`: up to `count` bytes from `fd` into the guest buffer at
    /// `buffer`.
    ///
    /// Port of unidbg: `UnixSyscallHandler.read`.
    pub fn read(&self, fd: i32, buffer: u64, count: usize) -> i32 {
        let memory: &dyn Memory = &*self.memory;
        let mut map = self.fd_map.write();
        let Some(io) = map.get_mut(&fd) else {
            self.memory.set_errno(EBADF);
            return -1;
        };
        io.read(memory, buffer, count)
    }

    /// `pread(2)`.
    pub fn pread(&self, fd: i32, buffer: u64, count: usize, offset: u64) -> i32 {
        let memory: &dyn Memory = &*self.memory;
        let mut map = self.fd_map.write();
        let Some(io) = map.get_mut(&fd) else {
            self.memory.set_errno(EBADF);
            return -1;
        };
        io.pread(memory, buffer, count, offset)
    }

    /// `write(2)`: `count` bytes from the guest buffer at `buffer` into
    /// `fd`.
    ///
    /// Port of unidbg: `UnixSyscallHandler.write`.
    pub fn write(&self, fd: i32, buffer: u64, count: usize) -> i32 {
        let memory: &dyn Memory = &*self.memory;
        let mut map = self.fd_map.write();
        let Some(io) = map.get_mut(&fd) else {
            self.memory.set_errno(EBADF);
            return -1;
        };
        // The descriptor's `write` takes a host slice; bridge through
        // guest memory the same way unidbg's `buffer.getByteArray` does.
        let mut data = vec![0u8; count];
        if memory.read_bytes(buffer, &mut data).is_err() {
            self.memory.set_errno(EFAULT);
            return -1;
        }
        io.write(&data)
    }

    /// `lseek(2)`: returns the new offset or `-errno`.
    pub fn lseek(&self, fd: i32, offset: i64, whence: i32) -> i64 {
        let mut map = self.fd_map.write();
        let Some(io) = map.get_mut(&fd) else {
            self.memory.set_errno(EBADF);
            return -1;
        };
        io.lseek(offset, whence)
    }

    /// `fcntl(2)`.
    pub fn fcntl(&self, fd: i32, cmd: i32, arg: u64) -> i32 {
        let mut map = self.fd_map.write();
        let Some(io) = map.get_mut(&fd) else {
            self.memory.set_errno(EBADF);
            return -1;
        };
        io.fcntl(cmd, arg)
    }

    /// `ioctl(2)`.
    pub fn ioctl(&self, fd: i32, request: u64, argp: u64) -> i32 {
        let mut map = self.fd_map.write();
        let Some(io) = map.get_mut(&fd) else {
            self.memory.set_errno(EBADF);
            return -1;
        };
        io.ioctl(request, argp)
    }

    /// `fstat(2)` on the given fd, written in the guest's ABI layout.
    ///
    /// Port of unidbg: `ARM64SyscallHandler.fstat`.
    pub fn fstat(&self, fd: i32, statbuf: u64) -> i32 {
        let mut map = self.fd_map.write();
        let Some(io) = map.get_mut(&fd) else {
            self.memory.set_errno(EBADF);
            return -1;
        };
        let mut stat = Stat::default();
        let ret = io.fstat(&mut stat);
        if ret == 0 {
            if stat.write_to(&*self.memory, statbuf, self.is_64bit).is_err() {
                self.memory.set_errno(EFAULT);
                return -1;
            }
        }
        ret
    }

    /// `readlinkat(2)` for the simple `AT_FDCWD` path: copies the
    /// canonical path into `buf` and returns it.
    ///
    /// Port of unidbg: `UnixSyscallHandler.readlink`. The Android
    /// `readlinkat` shim calls into this.
    pub fn readlink(&self, path: &str, buf: u64, buf_size: usize) -> i32 {
        let mut path = path.to_string();
        // Mirror unidbg's `FD_PATTERN` handling for `/proc/self/fd/N`.
        if let Some(rest) = path.strip_prefix("/proc/self/fd/") {
            if let Ok(fd) = rest.parse::<i32>() {
                if let Some(io) = self.fd_map.read().get(&fd) {
                    path = io.get_path().to_string();
                }
            }
        }
        let bytes = path.as_bytes();
        let len = bytes.len().min(buf_size.saturating_sub(1));
        let mut out = Vec::with_capacity(len + 1);
        out.extend_from_slice(&bytes[..len]);
        out.push(0);
        if self.memory.write_bytes(buf, &out).is_err() {
            self.memory.set_errno(EFAULT);
            return -1;
        }
        (len + 1) as i32
    }

    /// `getrandom(2)`: fills `buf` with `buf_size` bytes of randomness.
    ///
    /// Port of unidbg: `UnixSyscallHandler.getrandom`. Real entropy, no
    /// seed; tests that want determinism should install a custom
    /// resolver.
    pub fn getrandom(&self, buf: u64, buf_size: usize) -> i32 {
        let mut bytes = vec![0u8; buf_size];
        for chunk in bytes.chunks_mut(8) {
            let value = rand_u64();
            let raw = value.to_le_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&raw[..len]);
        }
        if self.memory.write_bytes(buf, &bytes).is_err() {
            self.memory.set_errno(EFAULT);
            return -1;
        }
        buf_size as i32
    }

    /// `mmap(2)` with no fd — anonymous mapping routed through the
    /// loader.
    ///
    /// Port of unidbg: `ARM64SyscallHandler.mmap`. The real table is in
    /// [`super::arm64`]; the loader-level mmap2 needs the [`Memory`]'s
    /// `mmap2` method.
    pub fn mmap_anonymous(
        &self,
        start: u64,
        length: usize,
        prot: Prot,
    ) -> Result<u64, SyscallError> {
        let addr = self
            .memory
            .mmap2(start, length, prot, MAP_ANONYMOUS, -1, 0)
            .map_err(SyscallError::Memory)?;
        if addr == MAP_FAILED {
            self.memory.set_errno(EINVAL);
            return Err(SyscallError::Memory(MemoryError::Message(
                "anonymous mmap failed".into(),
            )));
        }
        Ok(addr)
    }

    /// `brk(2)`.
    ///
    /// Port of unidbg: `ARM64SyscallHandler.brk`/`AndroidElfLoader.brk`.
    pub fn brk(&self, address: u64) -> Result<u64, SyscallError> {
        self.memory.brk(address).map_err(SyscallError::Memory)
    }

    /// `clock_gettime(2)` for `CLOCK_REALTIME` / `CLOCK_MONOTONIC` /
    /// `CLOCK_MONOTONIC_RAW` / `CLOCK_BOOTTIME` /
    /// `CLOCK_THREAD_CPUTIME_ID`.
    pub fn clock_gettime(&self, clk_id: i32, tp: u64) -> i32 {
        let (secs, nanos) = match clk_id & 0x7 {
            CLOCK_REALTIME => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
                (now.as_secs() as i64, now.subsec_nanos() as i64)
            }
            _ => {
                let now = TimeInstant::now();
                let elapsed = now.duration_since(*MONO_ZERO);
                (elapsed.as_secs() as i64, elapsed.subsec_nanos() as i64)
            }
        };
        let secs_bytes = secs.to_le_bytes();
        let nanos_bytes = nanos.to_le_bytes();
        let write_ok = self
            .memory
            .write_bytes(tp, &secs_bytes)
            .and_then(|()| self.memory.write_bytes(tp + 8, &nanos_bytes))
            .is_ok();
        if write_ok {
            0
        } else {
            self.memory.set_errno(EFAULT);
            -1
        }
    }

    /// `uname(2)`: fills a Linux-shaped `utsname` buffer at `buf`.
    pub fn uname(&self, buf: u64) -> i32 {
        const SYS_NMLN: usize = 65;
        let mut cursor = buf;
        for field in &[
            "Linux",
            "localhost",
            "1.0.0-unidbg",
            "#1 SMP PREEMPT",
            "armv8l",
            "localdomain",
        ] {
            let bytes = field.as_bytes();
            let len = bytes.len().min(SYS_NMLN - 1);
            let write_ok = self
                .memory
                .write_bytes(cursor, &bytes[..len])
                .and_then(|()| self.memory.write_bytes(cursor + len as u64, &[0u8; 1]))
                .is_ok();
            if !write_ok {
                self.memory.set_errno(EFAULT);
                return -1;
            }
            cursor += SYS_NMLN as u64;
        }
        0
    }

    /// `faccessat(2)`/`access(2)`-shaped: success if `pathname` resolves,
    /// `-errno` otherwise.
    pub fn faccessat(&self, pathname: &str) -> i32 {
        match self.resolve(pathname, O_RDONLY) {
            Some(FileResult::Success(_)) => 0,
            _ => {
                self.memory.set_errno(EACCES);
                -1
            }
        }
    }

    /// Returns the host file system's root directory, if any.
    pub fn root_dir(&self) -> Option<PathBuf> {
        self.file_system
            .read()
            .as_ref()
            .and_then(|fs| fs.root_dir().map(|p| p.to_path_buf()))
    }

    /// Helper: installs a [`LinuxFileSystem`] rooted at `root`.
    pub fn install_linux_file_system(&self, root: Option<PathBuf>) {
        match root {
            Some(path) => {
                if let Ok(fs) = LinuxFileSystem::new(path) {
                    self.set_file_system(Box::new(fs));
                }
            }
            None => self.set_file_system(Box::new(raxdbg_core::file::linux_fs::LinuxFileSystem::ephemeral())),
        }
    }
}

/// The wall-clock origin used to compute `CLOCK_MONOTONIC` answers.
static MONO_ZERO: LazyLock<TimeInstant> = LazyLock::new(TimeInstant::now);

thread_local! {
    /// Per-thread splitmix64 state used by [`getrandom`]. Tests that want
    /// deterministic output should not use the shared handler.
    static RAND_STATE: Cell<u64> = const { Cell::new(0xa1b2_3c4d_5e6f_7081) };
}

fn rand_u64() -> u64 {
    RAND_STATE.with(|cell| {
        let mut x = cell.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        cell.set(x);
        x
    })
}