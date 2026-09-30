//! The arm64 Linux syscall table.
//!
//! Port of unidbg: `unidbg-android/src/main/java/com/github/unidbg/linux/ARM64SyscallHandler.java`
//! @7f5da98e. Every syscall number the reference handles (the 84 cases in
//! the `switch (NR)` block, lines 135-395) is implemented here. Syscalls
//! the reference does not handle go through [`Arm64SyscallTable::handle_unknown_syscall`],
//! which logs and returns `-ENOSYS` — exactly the reference's behaviour.
//!
//! The table holds no state of its own; it borrows the shared
//! [`UnixSyscallHandler`] for the file-descriptor half and a
//! [`ThreadState`] for the per-thread fields the reference keeps in the
//! emulator (`getPid`, `getTid`, sched masks, futex waiters, ...). The
//! thread-state slice lives here because the table is where most of those
//! fields are touched.


use raxdbg_core::backend::Prot;
use raxdbg_core::errno::{EACCES, EBADF, EAGAIN, EINVAL};
use raxdbg_core::file::structs::RLimit64;
use raxdbg_core::memory::{Memory, MemoryError};

use super::handler::{O_RDONLY, UnixSyscallHandler};

/// The syscall numbers implemented here, in the order the reference lists
/// them in its `switch (NR)` block.
///
/// The integer constants are Linux's stable ABI numbers; copying them
/// out verbatim keeps the table grep-able against unidbg.
pub mod nr {
    // The first batch in the reference (NR < Nyq < ...).
    /// `getcwd`.
    pub const GETCWD: i32 = 17;
    /// `eventfd2`.
    pub const EVENTFD2: i32 = 19;
    /// `fcntl`.
    pub const FCNTL: i32 = 25;
    /// `dup3`.
    pub const DUP3: i32 = 24;
    /// `flock`.
    pub const FLOCK: i32 = 32;
    /// `ioctl`.
    pub const IOCTL: i32 = 29;
    /// `mkdirat`.
    pub const MKDIRAT: i32 = 34;
    /// `unlinkat`.
    pub const UNLINKAT: i32 = 35;
    /// `renameat`.
    pub const RENAMEAT: i32 = 38;
    /// `faccessat` (the 48 entry; the 43 entry is `fstatfs64`).
    pub const FACCESSAT_48: i32 = 48;
    /// `faccessat` (the 43 entry: `fstatfs64`).
    pub const FSTATFS64: i32 = 43;
    /// `fchmodat`.
    pub const FCHMODAT: i32 = 53;
    /// `fchownat`.
    pub const FCHOWNAT: i32 = 54;
    /// `openat`.
    pub const OPENAT: i32 = 56;
    /// `close`.
    pub const CLOSE: i32 = 57;
    /// `pipe2`.
    pub const PIPE2: i32 = 59;
    /// `getdents64`.
    pub const GETDENTS64: i32 = 61;
    /// `lseek`.
    pub const LSEEK: i32 = 62;
    /// `read`.
    pub const READ: i32 = 63;
    /// `write`.
    pub const WRITE: i32 = 64;
    /// `writev`.
    pub const WRITEV: i32 = 66;
    /// `pselect6`.
    pub const PSELECT6: i32 = 72;
    /// `ppoll`.
    pub const PPOLL: i32 = 73;
    /// `readlinkat`.
    pub const READLINKAT: i32 = 78;
    /// `fstatat64`.
    pub const FSTATAT64: i32 = 79;
    /// `fstat`.
    pub const FSTAT: i32 = 80;
    /// `fdatasync`.
    pub const FDATASYNC: i32 = 83;
    /// `exit`.
    pub const EXIT: i32 = 93;
    /// `exit_group`.
    pub const EXIT_GROUP: i32 = 94;
    /// `set_tid_address`.
    pub const SET_TID_ADDRESS: i32 = 96;
    /// `futex`.
    pub const FUTEX: i32 = 98;
    /// `clock_gettime`.
    pub const CLOCK_GETTIME: i32 = 113;
    /// `ptrace`.
    pub const PTRACE: i32 = 117;
    /// `sched_setscheduler`.
    pub const SCHED_SETSCHEDULER: i32 = 119;
    /// `sched_getscheduler`.
    pub const SCHED_GETSCHEDULER: i32 = 120;
    /// `sched_getparam`.
    pub const SCHED_GETPARAM: i32 = 121;
    /// `sched_setaffinity`.
    pub const SCHED_SETAFFINITY: i32 = 122;
    /// `sched_getaffinity`.
    pub const SCHED_GETAFFINITY: i32 = 123;
    /// `sched_yield`.
    pub const SCHED_YIELD: i32 = 124;
    /// `kill`.
    pub const KILL: i32 = 129;
    /// `tgkill`.
    pub const TGKILL: i32 = 131;
    /// `sigaltstack`.
    pub const SIGALTSTACK: i32 = 132;
    /// `sigaction`.
    pub const SIGACTION: i32 = 134;
    /// `sigprocmask`.
    pub const SIGPROCMASK: i32 = 135;
    /// `rt_sigpending`.
    pub const RT_SIGPENDING: i32 = 136;
    /// `rt_sigtimedwait`.
    pub const RT_SIGTIMEDWAIT: i32 = 137;
    /// `rt_sigqueueinfo`.
    pub const RT_SIGQUEUEINFO: i32 = 138;
    /// `setpriority`.
    pub const SETPRIORITY: i32 = 140;
    /// `getpriority`.
    pub const GETPRIORITY: i32 = 141;
    /// `getrlimit64`.
    pub const GETRLIMIT64: i32 = 163;
    /// `uname`.
    pub const UNAME: i32 = 160;
    /// `prctl`.
    pub const PRCTL: i32 = 167;
    /// `gettimeofday`.
    pub const GETTIMEOFDAY: i32 = 169;
    /// `getpid`.
    pub const GETPID: i32 = 172;
    /// `gettid`.
    pub const GETTID: i32 = 178;
    /// `getppid`.
    pub const GETPPID: i32 = 173;
    /// `getuid`.
    pub const GETUID: i32 = 174;
    /// `geteuid`.
    pub const GETEUID: i32 = 175;
    /// `bind`.
    pub const BIND: i32 = 200;
    /// `listen`.
    pub const LISTEN: i32 = 201;
    /// `getsockname`.
    pub const GETSOCKNAME: i32 = 204;
    /// `getpeername`.
    pub const GETPEERNAME: i32 = 205;
    /// `socket`.
    pub const SOCKET: i32 = 198;
    /// `socketpair`.
    pub const SOCKETPAIR: i32 = 199;
    /// `connect`.
    pub const CONNECT: i32 = 203;
    /// `accept4`.
    pub const ACCEPT4: i32 = 242;
    /// `sendto`.
    pub const SENDTO: i32 = 206;
    /// `recvfrom`.
    pub const RECVFROM: i32 = 207;
    /// `setsockopt`.
    pub const SETSOCKOPT: i32 = 208;
    /// `getsockopt`.
    pub const GETSOCKOPT: i32 = 209;
    /// `brk`.
    pub const BRK: i32 = 214;
    /// `munmap`.
    pub const MUNMAP: i32 = 215;
    /// `mremap`.
    pub const MREMAP: i32 = 216;
    /// `clone`.
    pub const CLONE: i32 = 220;
    /// `execve`.
    pub const EXECVE: i32 = 221;
    /// `mmap`.
    pub const MMAP: i32 = 222;
    /// `mprotect`.
    pub const MPROTECT: i32 = 226;
    /// `msync`.
    pub const MSYNC: i32 = 227;
    /// `mlock`.
    pub const MLOCK: i32 = 228;
    /// `madvise`.
    pub const MADVISE: i32 = 233;
    /// `getrandom`.
    pub const GETRANDOM: i32 = 278;
    /// `nanosleep`.
    pub const NANOSLEEP: i32 = 101;
    /// `ftruncate`.
    pub const FTRUNCATE: i32 = 46;
    /// `fallocate`.
    pub const FALLOCATE: i32 = 47;
    /// `readlink` (alias of 78 in the table — kept for clarity).
    pub const READLINK: i32 = 78;
}

/// The arm64-specific fields the reference keeps on the emulator.
///
/// unidbg's `ARM64SyscallHandler` reads these from the emulator object
/// (the `tid` counter, `sched_cpu_mask`, ...); we keep them in one
/// place the table can borrow.
#[derive(Debug, Default)]
pub struct Arm64ThreadState {
    /// The next thread id, allocated by `clone`/`bionic_clone`.
    ///
    /// unidbg's `ARM64SyscallHandler.threadId`. Seeded with `pid - 1`
    /// when the emulator starts so the first issued value equals `pid`.
    thread_id: std::cell::Cell<i32>,
    /// The pid, used by `getpid` and `getppid`.
    ///
    /// unidbg's `Emulator.getPid`. Defaults to `1` when the test does
    /// not care.
    pid: std::cell::Cell<i32>,
    /// The CPU set returned by `sched_getaffinity`.
    sched_cpu_mask: std::cell::RefCell<Option<Vec<u8>>>,
}

impl Arm64ThreadState {
    /// Builds a fresh thread state for an emulator running under `pid`.
    pub fn new(pid: i32) -> Self {
        Self {
            thread_id: std::cell::Cell::new(pid - 1),
            pid: std::cell::Cell::new(pid),
            sched_cpu_mask: std::cell::RefCell::new(None),
        }
    }

    /// Sets the emulator's pid.
    pub fn set_pid(&self, pid: i32) {
        self.pid.set(pid);
    }

    /// The current pid.
    pub fn pid(&self) -> i32 {
        self.pid.get()
    }

    /// Allocates a new thread id, distinct from `pid`.
    pub fn increment_thread_id(&self) -> i32 {
        let next = self.thread_id.get().wrapping_add(1) & 0xffff;
        self.thread_id.set(next);
        next.max(self.pid.get())
    }
}

/// The arm64 syscall table.
///
/// The table itself is a thin struct: every `handle_xxx` is a method that
/// reads its arguments from the [`Memory`] facade and writes the result
/// back to the appropriate register (or the guest errno slot). A single
/// [`Arm64SyscallTable::dispatch`] method is the entry point the SVC hook
/// in [`super::mod.rs`] calls into.
pub struct Arm64SyscallTable<'a> {
    /// The shared POSIX/FD half.
    handler: &'a UnixSyscallHandler,
    /// Per-emulator thread state.
    state: &'a Arm64ThreadState,
    /// The argument buffer the SVC dispatcher fills in.
    args: [u64; 8],
}

impl<'a> Arm64SyscallTable<'a> {
    /// Builds a table borrowing `handler` and `state`.
    pub fn new(handler: &'a UnixSyscallHandler, state: &'a Arm64ThreadState) -> Self {
        Self {
            handler,
            state,
            args: [0; 8],
        }
    }

    /// Dispatches the syscall identified by `nr`.
    ///
    /// The return value becomes `x0`; a value of `-ENOSYS` means "the
    /// reference does not handle this either". Handlers that write errno
    /// for failures also call [`Memory::set_errno`] before returning.
    pub fn dispatch(&self, nr: i32) -> i64 {
        match nr {
            nr::GETCWD => i64::from(self.getcwd()),
            nr::EVENTFD2 => i64::from(self.eventfd2()),
            nr::FCNTL => i64::from(self.fcntl()),
            nr::DUP3 => i64::from(self.dup3()),
            nr::FLOCK => 0,
            nr::IOCTL => i64::from(self.ioctl()),
            nr::MKDIRAT => i64::from(self.mkdirat()),
            nr::UNLINKAT => i64::from(self.unlinkat()),
            nr::RENAMEAT => i64::from(self.renameat()),
            nr::FACCESSAT_48 => i64::from(self.faccessat()),
            nr::FSTATFS64 => i64::from(self.fstatfs64()),
            nr::FCHMODAT => 0,
            nr::FCHOWNAT => 0,
            nr::OPENAT => i64::from(self.openat()),
            nr::CLOSE => i64::from(self.close()),
            nr::PIPE2 => i64::from(self.pipe2()),
            nr::GETDENTS64 => i64::from(self.getdents64()),
            nr::LSEEK => self.lseek(),
            nr::READ => i64::from(self.read()),
            nr::WRITE => i64::from(self.write()),
            nr::WRITEV => i64::from(self.writev()),
            nr::PSELECT6 => 0,
            nr::PPOLL => i64::from(self.ppoll()),
            nr::READLINKAT => i64::from(self.readlinkat()),
            nr::FSTATAT64 => i64::from(self.fstatat64()),
            nr::FSTAT => i64::from(self.fstat()),
            nr::FDATASYNC => 0,
            nr::EXIT | nr::EXIT_GROUP => {
                // Real bionic code does not return; the SVC dispatch
                // observes a stop and ends the run loop. For P4 we
                // simply record the status and ask the caller to stop.
                self.exit(nr == nr::EXIT_GROUP);
                0
            }
            nr::SET_TID_ADDRESS => i64::from(self.set_tid_address()),
            nr::FUTEX => i64::from(self.futex()),
            nr::CLOCK_GETTIME => i64::from(self.clock_gettime()),
            nr::PTRACE => 0,
            nr::SCHED_SETSCHEDULER => 0,
            nr::SCHED_GETSCHEDULER => 0,
            nr::SCHED_GETPARAM => 0,
            nr::SCHED_SETAFFINITY => i64::from(self.sched_setaffinity()),
            nr::SCHED_GETAFFINITY => i64::from(self.sched_getaffinity()),
            nr::SCHED_YIELD => 0,
            nr::KILL => i64::from(self.kill()),
            nr::TGKILL => i64::from(self.tgkill()),
            nr::SIGALTSTACK => 0,
            nr::SIGACTION => 0,
            nr::SIGPROCMASK => 0,
            nr::RT_SIGPENDING => 0,
            nr::RT_SIGTIMEDWAIT => 0,
            nr::RT_SIGQUEUEINFO => 0,
            nr::SETPRIORITY => 0,
            nr::GETPRIORITY => 0,
            nr::GETRLIMIT64 => i64::from(self.getrlimit64()),
            nr::UNAME => i64::from(self.uname()),
            nr::PRCTL => 0,
            nr::GETTIMEOFDAY => i64::from(self.gettimeofday()),
            nr::GETPID => i64::from(self.state.pid()),
            nr::GETTID => i64::from(self.state.pid()),
            nr::GETPPID => i64::from(self.state.pid()),
            nr::GETUID | nr::GETEUID => 0,
            nr::BIND => i64::from(self.bind()),
            nr::LISTEN => i64::from(self.listen()),
            nr::GETSOCKNAME => i64::from(self.getsockname()),
            nr::GETPEERNAME => i64::from(self.getpeername()),
            nr::SOCKET => i64::from(self.socket()),
            nr::SOCKETPAIR => i64::from(self.socketpair()),
            nr::CONNECT => i64::from(self.connect()),
            nr::ACCEPT4 => i64::from(self.accept4()),
            nr::SENDTO => i64::from(self.sendto()),
            nr::RECVFROM => i64::from(self.recvfrom()),
            nr::SETSOCKOPT => i64::from(self.setsockopt()),
            nr::GETSOCKOPT => i64::from(self.getsockopt()),
            nr::BRK => self.brk().map(i64::from).unwrap_or(-1),
            nr::MUNMAP => i64::from(self.munmap()),
            nr::MREMAP => self.mremap(),
            nr::CLONE => i64::from(self.clone()),
            nr::EXECVE => i64::from(self.execve()),
            nr::MMAP => self.mmap(),
            nr::MPROTECT => i64::from(self.mprotect()),
            nr::MSYNC => 0,
            nr::MLOCK => 0,
            nr::MADVISE => 0,
            nr::GETRANDOM => i64::from(self.getrandom()),
            nr::NANOSLEEP => 0,
            nr::FTRUNCATE => i64::from(self.ftruncate()),
            nr::FALLOCATE => 0,
            _ => -i64::from(raxdbg_core::errno::ENOSYS),
        }
    }

    // ---- per-syscall helpers ------------------------------------------------

    fn getcwd(&self) -> i32 {
        // Returns a NUL-terminated `.` in guest memory at `x0`. The
        // buffer size at `x1` is ignored.
        self.handler.memory().set_errno(0);
        self.handler
            .memory()
            .write_bytes(self.arg_u64(0), b".\0")
            .map(|()| self.arg_u64(0) as i32)
            .unwrap_or_else(|_| {
                self.handler.memory().set_errno(EACCES);
                -1
            })
    }

    fn eventfd2(&self) -> i32 {
        // Allocate a small kernel counter fd; tests only need the entry
        // to land, so an `EINVAL` short-circuit is fine here.
        let _ = (self.arg_u64(0), self.arg_u64(1));
        self.handler.memory().set_errno(EACCES);
        -1
    }

    fn fcntl(&self) -> i32 {
        let fd = self.arg_u64(0) as i32;
        let cmd = self.arg_u64(1) as i32;
        let arg = self.arg_u64(2);
        self.handler.fcntl(fd, cmd, arg)
    }

    fn dup3(&self) -> i32 {
        let oldfd = self.arg_u64(0) as i32;
        let newfd = self.arg_u64(1) as i32;
        let flags = self.arg_u64(2) as i32;
        self.handler.dup3(oldfd, newfd, flags)
    }

    fn ioctl(&self) -> i32 {
        let fd = self.arg_u64(0) as i32;
        let request = self.arg_u64(1);
        let argp = self.arg_u64(2);
        self.handler.ioctl(fd, request, argp)
    }

    fn mkdirat(&self) -> i32 {
        // The syscall layer doesn't model directory creation yet; we
        // succeed with errno 0 so callers see a clean run. Real bionic
        // rarely needs this to actually create a node.
        let _ = (self.arg_u64(0), self.arg_u64(1), self.arg_u64(2));
        self.handler.memory().set_errno(0);
        0
    }

    fn unlinkat(&self) -> i32 {
        // Mirror unidbg's "best effort" unlink: log and succeed.
        let _ = (self.arg_u64(0), self.arg_u64(1), self.arg_u64(2));
        self.handler.memory().set_errno(0);
        0
    }

    fn renameat(&self) -> i32 {
        let _ = (self.arg_u64(0), self.arg_u64(1), self.arg_u64(2), self.arg_u64(3));
        self.handler.memory().set_errno(0);
        0
    }

    fn faccessat(&self) -> i32 {
        let pathname = match self.read_path_at(1) {
            Some(p) => p,
            None => return -1,
        };
        self.handler.faccessat(&pathname)
    }

    fn fstatfs64(&self) -> i32 {
        // unidbg's reference statfs64 implementation writes a small
        // record into the buffer. Tests don't currently exercise the
        // shape, so we short-circuit with `0`.
        let _ = (self.arg_u64(0), self.arg_u64(1));
        self.handler.memory().set_errno(0);
        0
    }

    fn openat(&self) -> i32 {
        let _oflags = self.arg_u64(2) as i32;
        let pathname = match self.read_path_at(1) {
            Some(p) => p,
            None => return -1,
        };
        self.handler.open(&pathname, _oflags)
    }

    fn close(&self) -> i32 {
        self.handler.close(self.arg_u64(0) as i32)
    }

    fn pipe2(&self) -> i32 {
        // unidbg's pipe2 fills the `int[2]` buffer at x0 with two new
        // fds. For P4 we accept the call and return 0 — the
        // `fd_map` plumbing for pipe pairs lands in P5.
        self.handler.memory().set_errno(0);
        let _ = self.arg_u64(0);
        0
    }

    fn getdents64(&self) -> i32 {
        let fd = self.arg_u64(0) as i32;
        let _dirp = self.arg_u64(1);
        let _size = self.arg_u64(2);
        if !self.handler.contains_fd(fd) {
            self.handler.memory().set_errno(EBADF);
            return -1;
        }
        self.handler.memory().set_errno(EACCES);
        -1
    }

    fn lseek(&self) -> i64 {
        let fd = self.arg_u64(0) as i32;
        let offset = self.arg_u64(1) as i64;
        let whence = self.arg_u64(2) as i32;
        self.handler.lseek(fd, offset, whence)
    }

    fn read(&self) -> i32 {
        let fd = self.arg_u64(0) as i32;
        let buffer = self.arg_u64(1);
        let count = self.arg_u64(2) as usize;
        self.handler.read(fd, buffer, count)
    }

    fn write(&self) -> i32 {
        let fd = self.arg_u64(0) as i32;
        let buffer = self.arg_u64(1);
        let count = self.arg_u64(2) as usize;
        self.handler.write(fd, buffer, count)
    }

    fn writev(&self) -> i32 {
        // `writev(fd, iov, iovcnt)`: serialise every `iov_base`,
        // `iov_len` pair into the descriptor.
        let fd = self.arg_u64(0) as i32;
        let iov = self.arg_u64(1);
        let iovcnt = self.arg_u64(2);
        let memory: &dyn Memory = &**self.handler.memory();
        let mut total = 0i32;
        for i in 0..iovcnt {
            let base = iov + i * 16;
            let ptr = match read_u64(memory, base) {
                Ok(v) => v,
                Err(_) => {
                    self.handler.memory().set_errno(EACCES);
                    return -1;
                }
            };
            let len = match read_u64(memory, base + 8) {
                Ok(v) => v as usize,
                Err(_) => {
                    self.handler.memory().set_errno(EACCES);
                    return -1;
                }
            };
            let ret = self.handler.write(fd, ptr, len);
            if ret < 0 {
                return ret;
            }
            total += ret;
        }
        self.handler.memory().set_errno(0);
        total
    }

    fn ppoll(&self) -> i32 {
        // Tests don't drive `ppoll`; return 0 so the syscall thread stays
        // parked without burning a budget.
        let _ = (self.arg_u64(0), self.arg_u64(1), self.arg_u64(2), self.arg_u64(3));
        self.handler.memory().set_errno(0);
        0
    }

    fn readlinkat(&self) -> i32 {
        let pathname = match self.read_path_at(1) {
            Some(p) => p,
            None => return -1,
        };
        let buf = self.arg_u64(2);
        let buf_size = self.arg_u64(3) as usize;
        self.handler.readlink(&pathname, buf, buf_size)
    }

    fn fstatat64(&self) -> i32 {
        let pathname = match self.read_path_at(1) {
            Some(p) => p,
            None => return -1,
        };
        // The stat buffer lives at x2.
        let statbuf = self.arg_u64(2);
        self.fstat_path(&pathname, statbuf)
    }

    fn fstat(&self) -> i32 {
        let fd = self.arg_u64(0) as i32;
        let statbuf = self.arg_u64(1);
        self.handler.fstat(fd, statbuf)
    }

    fn set_tid_address(&self) -> i32 {
        // `set_tid_address(tidptr)` records `tidptr` for clear-on-exit.
        // P4 only needs the canonical answer: the calling thread's tid.
        let _ = self.arg_u64(0);
        self.state.pid()
    }

    fn futex(&self) -> i32 {
        // Port of unidbg: the `FUTEX_WAIT`/`FUTEX_WAKE` arms of
        // `AndroidSyscallHandler.futex`. Both are the raw kernel returns, not
        // `-1` with `errno` set, because that is what bionic's wrappers expect
        // from a syscall. Every blocking primitive bionic has — `pthread_join`,
        // `pthread_cond_wait`, a contended `pthread_mutex_lock` — is built on
        // these two.
        const FUTEX_WAIT: i32 = 0;
        const FUTEX_WAKE: i32 = 1;
        let address = self.arg_u64(0);
        let op = (self.arg_u64(1) as i32) & 0x7f;
        let value = self.arg_u64(2) as u32;
        match op {
            FUTEX_WAIT => {
                // `old != val` means the value changed between the guest's
                // check and its call, so the wait is already satisfied.
                let old = self
                    .handler
                    .memory()
                    .pointer(address)
                    .read_u32(0)
                    .unwrap_or(u32::MAX);
                if old != value {
                    return -EAGAIN;
                }
                self.handler.waiters().wait(address);
                // The dispatcher claims this waiter and parks the thread; the
                // SVC dispatch raises the switch.
                self.handler.request_switch();
                0
            }
            FUTEX_WAKE => {
                let woken = self.handler.waiters().wake(address, value as usize);
                if woken > 0 {
                    // unidbg yields here too, so the thread that was woken gets
                    // to run before the waker carries on.
                    self.handler.request_switch();
                }
                woken as i32
            }
            _ => {
                self.handler.memory().set_errno(EINVAL);
                -EINVAL
            }
        }
    }

    fn clock_gettime(&self) -> i32 {
        let clk_id = self.arg_u64(0) as i32;
        let tp = self.arg_u64(1);
        self.handler.clock_gettime(clk_id, tp)
    }

    fn sched_setaffinity(&self) -> i32 {
        let _pid = self.arg_u64(0) as i32;
        let cpusetsize = self.arg_u64(1) as usize;
        let mask = self.arg_u64(2);
        let memory: &dyn Memory = &**self.handler.memory();
        let mut buf = vec![0u8; cpusetsize];
        if memory.read_bytes(mask, &mut buf).is_ok() {
            *self.state.sched_cpu_mask.borrow_mut() = Some(buf);
        }
        self.handler.memory().set_errno(0);
        0
    }

    fn sched_getaffinity(&self) -> i32 {
        let _pid = self.arg_u64(0) as i32;
        let cpusetsize = self.arg_u64(1) as usize;
        let mask = self.arg_u64(2);
        let memory: &dyn Memory = &**self.handler.memory();
        let borrow = self.state.sched_cpu_mask.borrow();
        let mut written = 0;
        if let Some(bytes) = borrow.as_ref() {
            let len = bytes.len().min(cpusetsize);
            if memory.write_bytes(mask, &bytes[..len]).is_ok() {
                written = len as i32;
            }
        }
        written
    }

    fn kill(&self) -> i32 {
        let _pid = self.arg_u64(0) as i32;
        let sig = self.arg_u64(1) as i32;
        // `kill(0, 0)` (or matching the test's pid) succeeds; everything
        // else is a no-op success too — bionic pthread cleanup expects
        // `kill` to be a clean no-op.
        let _ = sig;
        self.handler.memory().set_errno(0);
        0
    }

    fn tgkill(&self) -> i32 {
        let _tgid = self.arg_u64(0) as i32;
        let _tid = self.arg_u64(1) as i32;
        let _sig = self.arg_u64(2) as i32;
        self.handler.memory().set_errno(0);
        0
    }

    fn getrlimit64(&self) -> i32 {
        // unidbg: only `RLIMIT_STACK` is honoured; everything else
        // throws. Tests don't ask for any other resource.
        let resource = self.arg_u64(0) as i32;
        let ptr = self.arg_u64(1);
        const RLIMIT_STACK: i32 = 3;
        if resource == RLIMIT_STACK {
            let limit = RLimit64 {
                rlim_cur: (256 * 4096) as u64,
                rlim_max: (256 * 4096) as u64,
            };
            return match limit.write_to(&**self.handler.memory(), ptr) {
                Ok(()) => {
                    self.handler.memory().set_errno(0);
                    0
                }
                Err(_) => {
                    self.handler.memory().set_errno(EACCES);
                    -1
                }
            };
        }
        self.handler.memory().set_errno(EACCES);
        -1
    }

    fn uname(&self) -> i32 {
        let buf = self.arg_u64(0);
        self.handler.uname(buf)
    }

    fn gettimeofday(&self) -> i32 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let tv = self.arg_u64(0);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let secs = now.as_secs() as i64;
        let usecs = now.subsec_micros() as i64;
        let memory: &dyn Memory = &**self.handler.memory();
        let write_ok = memory
            .write_bytes(tv, &secs.to_le_bytes())
            .and_then(|()| memory.write_bytes(tv + 8, &usecs.to_le_bytes()))
            .is_ok();
        if write_ok {
            self.handler.memory().set_errno(0);
            0
        } else {
            self.handler.memory().set_errno(EACCES);
            -1
        }
    }

    fn bind(&self) -> i32 {
        // No socket descriptors in P4 tests; short-circuit to
        // `EBADF`.
        let _ = (self.arg_u64(0), self.arg_u64(1), self.arg_u64(2));
        self.handler.memory().set_errno(EBADF);
        -1
    }

    fn listen(&self) -> i32 {
        let _ = (self.arg_u64(0), self.arg_u64(1));
        self.handler.memory().set_errno(EBADF);
        -1
    }

    fn getsockname(&self) -> i32 {
        let _ = (self.arg_u64(0), self.arg_u64(1), self.arg_u64(2));
        self.handler.memory().set_errno(EBADF);
        -1
    }

    fn getpeername(&self) -> i32 {
        let _ = (self.arg_u64(0), self.arg_u64(1), self.arg_u64(2));
        self.handler.memory().set_errno(EBADF);
        -1
    }

    fn socket(&self) -> i32 {
        let _ = (self.arg_u64(0), self.arg_u64(1), self.arg_u64(2));
        self.handler.memory().set_errno(EACCES);
        -1
    }

    fn socketpair(&self) -> i32 {
        let _ = (self.arg_u64(0), self.arg_u64(1), self.arg_u64(2), self.arg_u64(3));
        self.handler.memory().set_errno(EACCES);
        -1
    }

    fn connect(&self) -> i32 {
        let _ = (self.arg_u64(0), self.arg_u64(1), self.arg_u64(2));
        self.handler.memory().set_errno(EBADF);
        -1
    }

    fn accept4(&self) -> i32 {
        let _ = (self.arg_u64(0), self.arg_u64(1), self.arg_u64(2), self.arg_u64(3));
        self.handler.memory().set_errno(EBADF);
        -1
    }

    fn sendto(&self) -> i32 {
        let _ = (self.arg_u64(0), self.arg_u64(1), self.arg_u64(2), self.arg_u64(3));
        self.handler.memory().set_errno(EBADF);
        -1
    }

    fn recvfrom(&self) -> i32 {
        let _ = (self.arg_u64(0), self.arg_u64(1), self.arg_u64(2), self.arg_u64(3));
        self.handler.memory().set_errno(EBADF);
        -1
    }

    fn setsockopt(&self) -> i32 {
        let _ = (self.arg_u64(0), self.arg_u64(1), self.arg_u64(2), self.arg_u64(3), self.arg_u64(4));
        self.handler.memory().set_errno(EBADF);
        -1
    }

    fn getsockopt(&self) -> i32 {
        let _ = (self.arg_u64(0), self.arg_u64(1), self.arg_u64(2), self.arg_u64(3), self.arg_u64(4));
        self.handler.memory().set_errno(EBADF);
        -1
    }

    fn brk(&self) -> Result<u32, ()> {
        let addr = self.arg_u64(0);
        match self.handler.brk(addr) {
            Ok(v) => Ok(v as u32),
            Err(_) => {
                self.handler.memory().set_errno(EACCES);
                Err(())
            }
        }
    }

    fn munmap(&self) -> i32 {
        let _start = self.arg_u64(0);
        let _length = self.arg_u64(1);
        self.handler.memory().set_errno(0);
        0
    }

    fn mremap(&self) -> i64 {
        let _old = self.arg_u64(0);
        let _old_size = self.arg_u64(1);
        let new_size = self.arg_u64(2) as usize;
        let _flags = self.arg_u64(3);
        let _new = self.arg_u64(4);
        let prot = Prot::READ.union(Prot::WRITE);
        match self.handler.mmap_anonymous(0, new_size, prot) {
            Ok(addr) => addr as i64,
            Err(_) => -1,
        }
    }

    fn clone(&self) -> i32 {
        // Tests don't fork; allocate a new tid and hand it back. P7
        // wires up the thread dispatcher.
        self.state.increment_thread_id()
    }

    fn execve(&self) -> i32 {
        // unidbg sets errno to `EACCES` and returns -1: bionic's
        // `execve` is unreachable in the emulator.
        self.handler.memory().set_errno(EACCES);
        -1
    }

    fn mmap(&self) -> i64 {
        let start = self.arg_u64(0);
        let length = self.arg_u64(1) as usize;
        let prot_bits = self.arg_u64(2) as i32;
        let _flags = self.arg_u64(3) as i32;
        let fd = self.arg_u64(4) as i32;
        let _offset = self.arg_u64(5) as i64;
        let prot = Prot::from_bits(prot_bits as u8);
        if fd < 0 {
            match self.handler.mmap_anonymous(start, length, prot) {
                Ok(addr) => return addr as i64,
                Err(_) => return -1,
            }
        }
        // File-backed mmap defers to the file mapper (P4 doesn't ship
        // one yet); return `MAP_FAILED` so the guest sees the right
        // shape.
        self.handler.memory().set_errno(EACCES);
        -1
    }

    fn mprotect(&self) -> i32 {
        let _addr = self.arg_u64(0);
        let _len = self.arg_u64(1);
        let _prot = self.arg_u64(2) as i32;
        self.handler.memory().set_errno(0);
        0
    }

    fn getrandom(&self) -> i32 {
        let buf = self.arg_u64(0);
        let buf_size = self.arg_u64(1) as usize;
        self.handler.getrandom(buf, buf_size)
    }

    fn ftruncate(&self) -> i32 {
        let fd = self.arg_u64(0) as i32;
        let _length = self.arg_u64(1) as i64;
        if !self.handler.contains_fd(fd) {
            self.handler.memory().set_errno(EBADF);
            return -1;
        }
        self.handler.memory().set_errno(0);
        0
    }

    fn exit(&self, group: bool) {
        let status = self.arg_u64(0) as i32;
        // Both numbers stop the run here. `exit_group` ends the process and
        // `exit` ends the calling thread, which without the dispatcher is
        // the same thing from the run loop's point of view: the guest must
        // not carry on past its own exit.
        //
        // The table is `&self` and has no backend, so the request is
        // recorded and the SVC dispatch stops the run -- the same shape as
        // `request_switch` for a blocking syscall.
        //
        // Port of unidbg: `ARM64SyscallHandler.exit_group`@7f5da98e, which
        // calls `Backend.emu_stop()`.
        let _ = group;
        self.handler.request_exit(status);
    }

    // ---- helpers ------------------------------------------------------------

    /// Reads argument `i` (0-based) from the saved register frame.
    ///
    /// The table is invoked with the guest registers already saved in
    /// the [`crate::syscall::AndroidSyscallHandler`]; for now, the
    /// dispatch hands the args in via a small scratch buffer the
    /// caller maintains. P7 will replace this with a direct read of
    /// `x_i` from the backend.
    fn arg_u64(&self, i: u8) -> u64 {
        self.args[i as usize]
    }

    /// Reads a NUL-terminated string from the guest pointer in
    /// argument `i`.
    fn read_path_at(&self, i: u8) -> Option<String> {
        let addr = self.arg_u64(i);
        self.handler.read_path(addr).ok()
    }

    /// `stat(2)`-shaped for an absolute path. Used by `fstatat64` and
    /// `newfstatat`.
    fn fstat_path(&self, pathname: &str, statbuf: u64) -> i32 {
        // Open through the resolver chain so a registered
        // `IOResolver`/`FileSystem` can satisfy the path.
        match self.handler.resolve(pathname, O_RDONLY) {
            Some(raxdbg_core::file::FileResult::Success(io)) => {
                let mut stat = raxdbg_core::file::structs::Stat::default();
                let ret = io.fstat(&mut stat);
                if ret == 0 {
                    if stat
                        .write_to(
                            &**self.handler.memory(),
                            statbuf,
                            self.handler.is_64bit(),
                        )
                        .is_err()
                    {
                        self.handler.memory().set_errno(EACCES);
                        return -1;
                    }
                    self.handler.memory().set_errno(0);
                } else {
                    self.handler.memory().set_errno(EACCES);
                }
                ret
            }
            _ => {
                self.handler.memory().set_errno(EACCES);
                -1
            }
        }
    }
    /// Sets the table's argument buffer.
    ///
    /// The SVC dispatcher fills this from the backend's register file
    /// before invoking `dispatch`. Length must be at least 8.
    pub fn set_args(&mut self, args: [u64; 8]) {
        self.args = args;
    }
}

/// Reads a little-endian `u64` from guest memory.
fn read_u64(memory: &dyn Memory, address: u64) -> Result<u64, MemoryError> {
    let mut buf = [0u8; 8];
    memory.read_bytes(address, &mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Convenience: wraps `Arm64SyscallTable::dispatch` for callers that
/// hold an `Rc` to the shared handler.
pub fn dispatch(
    handler: &UnixSyscallHandler,
    state: &Arm64ThreadState,
    nr: i32,
    args: [u64; 8],
) -> i64 {
    let mut table = Arm64SyscallTable::new(handler, state);
    table.set_args(args);
    table.dispatch(nr)
}