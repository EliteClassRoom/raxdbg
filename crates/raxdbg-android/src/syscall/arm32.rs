//! The AArch32 (EABI) syscall numbers, and their translation to the arm64 table.
//!
//! Port of unidbg: `unidbg-android/src/main/java/com/github/unidbg/linux/ARM32SyscallHandler.java`@7f5da98e.
//!
//! The arm32 numbers are a different table from the arm64 ones — arm32 `write`
//! is 4 and arm64 `write` is 64 — so dispatching an arm32 `svc #0` into the
//! arm64 table silently runs the wrong handler. Everything else about the two
//! handlers is the same: the arguments have already been read out of `r0..r6`
//! by the SVC dispatch, the handler methods are ISA-independent, and the errno
//! convention is identical. So the arm32 handler is a *translation* onto the
//! shared table, plus the two places where the argument order differs.

/// `AT_FDCWD`, which arm32's `open` has no argument for.
pub const AT_FDCWD: u64 = 0xffff_ff9c;

/// The arm32 EABI syscall numbers this port knows.
///
/// Port of unidbg: the `case` labels in `ARM32SyscallHandler.handleSyscall`.
pub mod nr {
    /// `exit`.
    pub const EXIT: i32 = 1;
    /// `read`.
    pub const READ: i32 = 3;
    /// `write`.
    pub const WRITE: i32 = 4;
    /// `open`.
    pub const OPEN: i32 = 5;
    /// `close`.
    pub const CLOSE: i32 = 6;
    /// `lseek`.
    pub const LSEEK: i32 = 19;
    /// `getpid`.
    pub const GETPID: i32 = 20;
    /// `getuid`.
    pub const GETUID: i32 = 24;
    /// `access`.
    pub const ACCESS: i32 = 33;
    /// `kill`.
    pub const KILL: i32 = 37;
    /// `dup`.
    pub const DUP: i32 = 41;
    /// `brk`.
    pub const BRK: i32 = 45;
    /// `geteuid`.
    pub const GETEUID: i32 = 49;
    /// `ioctl`.
    pub const IOCTL: i32 = 54;
    /// `fcntl`.
    pub const FCNTL: i32 = 55;
    /// `dup2`.
    pub const DUP2: i32 = 63;
    /// `getppid`.
    pub const GETPPID: i32 = 64;
    /// `gettimeofday`.
    pub const GETTIMEOFDAY: i32 = 78;
    /// `munmap`.
    pub const MUNMAP: i32 = 91;
    /// `fstat`.
    pub const FSTAT: i32 = 107;
    /// `uname`.
    pub const UNAME: i32 = 122;
    /// `mprotect`.
    pub const MPROTECT: i32 = 125;
    /// `sigprocmask`.
    pub const SIGPROCMASK: i32 = 126;
    /// `_llseek`.
    pub const LLSEEK: i32 = 140;
    /// `readv`.
    pub const READV: i32 = 145;
    /// `writev`.
    pub const WRITEV: i32 = 146;
    /// `fdatasync`.
    pub const FDATASYNC: i32 = 148;
    /// `nanosleep`.
    pub const NANOSLEEP: i32 = 162;
    /// `mremap`.
    pub const MREMAP: i32 = 163;
    /// `poll`.
    pub const POLL: i32 = 168;
    /// `prctl`.
    pub const PRCTL: i32 = 172;
    /// `rt_sigaction`.
    pub const RT_SIGACTION: i32 = 174;
    /// `rt_sigprocmask`.
    pub const RT_SIGPROCMASK: i32 = 175;
    /// `rt_sigpending`.
    pub const RT_SIGPENDING: i32 = 176;
    /// `pread64`.
    pub const PREAD64: i32 = 180;
    /// `getcwd`.
    pub const GETCWD: i32 = 183;
    /// `sigaltstack`.
    pub const SIGALTSTACK: i32 = 186;
    /// `mmap2`.
    pub const MMAP2: i32 = 192;
    /// `stat64`.
    pub const STAT64: i32 = 196;
    /// `fstat64`.
    pub const FSTAT64: i32 = 197;
    /// `getdents64`.
    pub const GETDENTS64: i32 = 217;
    /// `fcntl64`.
    pub const FCNTL64: i32 = 221;
    /// `gettid`.
    pub const GETTID: i32 = 224;
    /// `futex`.
    pub const FUTEX: i32 = 240;
    /// `sched_setaffinity`.
    pub const SCHED_SETAFFINITY: i32 = 241;
    /// `sched_getaffinity`.
    pub const SCHED_GETAFFINITY: i32 = 242;
    /// `exit_group`.
    pub const EXIT_GROUP: i32 = 248;
    /// `set_tid_address`.
    pub const SET_TID_ADDRESS: i32 = 256;
    /// `clock_gettime`.
    pub const CLOCK_GETTIME: i32 = 263;
    /// `clock_getres`.
    pub const CLOCK_GETRES: i32 = 264;
    /// `clock_nanosleep`.
    pub const CLOCK_NANOSLEEP: i32 = 265;
    /// `tgkill`.
    pub const TGKILL: i32 = 268;
    /// `openat`.
    pub const OPENAT: i32 = 322;
    /// `mkdirat`.
    pub const MKDIRAT: i32 = 323;
    /// `fstatat64`.
    pub const FSTATAT64: i32 = 327;
    /// `unlinkat`.
    pub const UNLINKAT: i32 = 328;
    /// `renameat`.
    pub const RENAMEAT: i32 = 329;
    /// `readlinkat`.
    pub const READLINKAT: i32 = 332;
    /// `faccessat`.
    pub const FACCESSAT: i32 = 334;
    /// `ppoll`.
    pub const PPOLL: i32 = 336;
    /// `eventfd2`.
    pub const EVENTFD2: i32 = 356;
    /// `dup3`.
    pub const DUP3: i32 = 358;
    /// `pipe2`.
    pub const PIPE2: i32 = 359;
    /// `prlimit64`.
    pub const PRLIMIT64: i32 = 369;
    /// `getrandom`.
    pub const GETRANDOM: i32 = 384;
}

/// The kuser "syscalls", which the arm32 kernel answers on the same `svc`.
///
/// Port of unidbg: `ARM32SyscallHandler.handleInterrupt`'s `case 0xf0002` and
/// `case 0xf0005`. They are not syscalls -- there is no such call in the ABI --
/// but bionic issues them, so a loader that does not answer them sees a guest
/// that crashes in `__set_tls` on an old SDK.
pub mod kuser {
    /// `__ARM_NR_cacheflush`: flush the instruction cache over a range.
    pub const CACHEFLUSH: i32 = 0xf0002;
    /// `__ARM_NR_set_tls`: write the thread pointer.
    pub const SET_TLS: i32 = 0xf0005;

    /// The OABI base an arm32 `svc` immediate carries: `0x900000 + nr`.
    ///
    /// A non-OABI `svc` puts the call number in the immediate directly, which is
    /// what a syscall wrapper does; an OABI one adds the base, which is what
    /// bionic's own kuser wrappers do. Both have to be recognised, or the
    /// number arrives as `0x5f005` rather than `0xf0005`.
    pub const OABI_BASE: i32 = 0x900000;

    /// The call number an `svc` immediate stands for, whichever form it takes.
    pub fn number(swi: i32) -> i32 {
        if swi & OABI_BASE != 0 {
            swi - OABI_BASE
        } else {
            swi
        }
    }
}

/// The arm64 numbers the shared table dispatches on, for the translation.
///
/// These mirror `syscall::arm64::nr`; they are repeated here so the translation
/// reads as a table rather than as a chain of imports.
mod arm64_nr {
    pub const EXIT: i32 = 93;
    pub const EXIT_GROUP: i32 = 94;
    pub const FUTEX: i32 = 98;
    pub const NANOSLEEP: i32 = 101;
    pub const CLOCK_GETTIME: i32 = 113;
    pub const CLOCK_GETRES: i32 = 114;
    pub const CLOCK_NANOSLEEP: i32 = 115;
    pub const SCHED_SETAFFINITY: i32 = 122;
    pub const SCHED_GETAFFINITY: i32 = 123;
    pub const GETPID: i32 = 172;
    pub const GETPPID: i32 = 173;
    pub const GETUID: i32 = 174;
    pub const GETEUID: i32 = 175;
    pub const GETTID: i32 = 178;
    pub const UNAME: i32 = 160;
    pub const GETTIMEOFDAY: i32 = 169;
    pub const GETCWD: i32 = 17;
    pub const KILL: i32 = 129;
    pub const TGKILL: i32 = 131;
    pub const GETRANDOM: i32 = 278;
    pub const SET_TID_ADDRESS: i32 = 96;
    pub const MKDIRAT: i32 = 34;
    pub const UNLINKAT: i32 = 35;
    pub const RENAMEAT: i32 = 38;
    pub const OPENAT: i32 = 56;
    pub const CLOSE: i32 = 57;
    pub const PIPE2: i32 = 59;
    pub const GETDENTS64: i32 = 61;
    pub const LSEEK: i32 = 62;
    pub const READ: i32 = 63;
    pub const WRITE: i32 = 64;
    pub const READV: i32 = 65;
    pub const WRITEV: i32 = 66;
    pub const PREAD64: i32 = 67;
    pub const PPOLL: i32 = 73;
    pub const READLINKAT: i32 = 78;
    pub const FSTATAT: i32 = 79;
    pub const FSTAT: i32 = 80;
    pub const FDATASYNC: i32 = 83;
    pub const FACCESSAT: i32 = 48;
    pub const DUP: i32 = 23;
    pub const DUP3: i32 = 24;
    pub const FCNTL: i32 = 25;
    pub const IOCTL: i32 = 29;
    pub const FLOCK: i32 = 32;
    pub const MUNMAP: i32 = 215;
    pub const MPROTECT: i32 = 226;
    pub const MREMAP: i32 = 216;
    pub const BRK: i32 = 214;
    pub const MMAP: i32 = 222;
    pub const EVENTFD2: i32 = 19;
    pub const PRCTL: i32 = 167;
    pub const PRLIMIT64: i32 = 261;
    pub const POLL: i32 = 7;
    pub const SIGALTSTACK: i32 = 132;
    pub const RT_SIGACTION: i32 = 134;
    pub const RT_SIGPROCMASK: i32 = 135;
    pub const RT_SIGPENDING: i32 = 136;
    pub const STAT64: i32 = 79;
}

/// Translates an arm32 syscall into the arm64 one the shared table handles,
/// rewriting the arguments where the calling convention differs.
///
/// Returns `None` for a number this port does not implement, which the caller
/// answers with `-ENOSYS` — the same thing unidbg's `handleUnknownSyscall`
/// does, and what real bionic does when it meets a kernel without the call.
pub fn translate(nr: i32, args: &mut [u64; 8]) -> Option<i32> {
    let mapped = match nr {
        nr::EXIT => arm64_nr::EXIT,
        nr::EXIT_GROUP => arm64_nr::EXIT_GROUP,
        nr::READ => arm64_nr::READ,
        nr::WRITE => arm64_nr::WRITE,
        nr::CLOSE => arm64_nr::CLOSE,
        nr::LSEEK => arm64_nr::LSEEK,
        nr::GETPID => arm64_nr::GETPID,
        nr::GETPPID => arm64_nr::GETPPID,
        nr::GETUID => arm64_nr::GETUID,
        nr::GETEUID => arm64_nr::GETEUID,
        nr::GETTID => arm64_nr::GETTID,
        nr::UNAME => arm64_nr::UNAME,
        nr::KILL => arm64_nr::KILL,
        nr::TGKILL => arm64_nr::TGKILL,
        nr::GETRANDOM => arm64_nr::GETRANDOM,
        nr::SET_TID_ADDRESS => arm64_nr::SET_TID_ADDRESS,
        nr::GETCWD => arm64_nr::GETCWD,
        nr::IOCTL => arm64_nr::IOCTL,
        nr::FCNTL | nr::FCNTL64 => arm64_nr::FCNTL,
        nr::DUP => arm64_nr::DUP,
        nr::DUP2 | nr::DUP3 => arm64_nr::DUP3,
        nr::BRK => arm64_nr::BRK,
        nr::MMAP2 => arm64_nr::MMAP,
        nr::MUNMAP => arm64_nr::MUNMAP,
        nr::MPROTECT => arm64_nr::MPROTECT,
        nr::MREMAP => arm64_nr::MREMAP,
        nr::EVENTFD2 => arm64_nr::EVENTFD2,
        nr::PIPE2 => arm64_nr::PIPE2,
        nr::FUTEX => arm64_nr::FUTEX,
        nr::NANOSLEEP => arm64_nr::NANOSLEEP,
        nr::CLOCK_GETTIME => arm64_nr::CLOCK_GETTIME,
        nr::CLOCK_GETRES => arm64_nr::CLOCK_GETRES,
        nr::CLOCK_NANOSLEEP => arm64_nr::CLOCK_NANOSLEEP,
        nr::GETTIMEOFDAY => arm64_nr::GETTIMEOFDAY,
        nr::POLL => arm64_nr::POLL,
        nr::PPOLL => arm64_nr::PPOLL,
        nr::READV => arm64_nr::READV,
        nr::WRITEV => arm64_nr::WRITEV,
        nr::PREAD64 => arm64_nr::PREAD64,
        nr::FDATASYNC => arm64_nr::FDATASYNC,
        nr::GETDENTS64 => arm64_nr::GETDENTS64,
        nr::FSTAT | nr::FSTAT64 | nr::STAT64 => arm64_nr::FSTAT,
        nr::FSTATAT64 => arm64_nr::FSTATAT,
        nr::ACCESS => arm64_nr::FACCESSAT,
        nr::MKDIRAT => arm64_nr::MKDIRAT,
        nr::UNLINKAT => arm64_nr::UNLINKAT,
        nr::RENAMEAT => arm64_nr::RENAMEAT,
        nr::READLINKAT => arm64_nr::READLINKAT,
        nr::OPENAT => arm64_nr::OPENAT,
        nr::SCHED_SETAFFINITY => arm64_nr::SCHED_SETAFFINITY,
        nr::SCHED_GETAFFINITY => arm64_nr::SCHED_GETAFFINITY,
        nr::PRCTL => arm64_nr::PRCTL,
        nr::PRLIMIT64 => arm64_nr::PRLIMIT64,
        nr::SIGALTSTACK => arm64_nr::SIGALTSTACK,
        nr::RT_SIGACTION => arm64_nr::RT_SIGACTION,
        nr::RT_SIGPROCMASK => arm64_nr::RT_SIGPROCMASK,
        nr::RT_SIGPENDING => arm64_nr::RT_SIGPENDING,
        nr::SIGPROCMASK => arm64_nr::RT_SIGPROCMASK,
        nr::OPEN => {
            // arm32 `open(path, flags, mode)` is arm64
            // `openat(AT_FDCWD, path, flags, mode)`: the directory fd goes in
            // front and everything shifts one register.
            let [path, flags, mode, rest @ ..] = *args;
            args[0] = AT_FDCWD;
            args[1] = path;
            args[2] = flags;
            args[3] = mode;
            args[4..].copy_from_slice(&rest[..4]);
            arm64_nr::OPENAT
        }
        nr::ACCESS => arm64_nr::FACCESSAT,
        nr::LLSEEK => {
            // `_llseek(fd, offset_high, offset_low, result, whence)` becomes
            // `lseek(fd, (high << 32) | low, whence)`.
            let [fd, high, low, result, whence, rest @ ..] = *args;
            let offset = (high << 32) | (low & 0xffff_ffff);
            args[0] = fd;
            args[1] = offset;
            args[2] = whence;
            args[3] = result;
            args[4..4 + rest.len()].copy_from_slice(&rest);
            arm64_nr::LSEEK
        }
        _ => return None,
    };
    Some(mapped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_numbers_that_differ_between_the_two_abis_are_translated() {
        let mut args = [0u64; 8];
        // arm32 write is 4; arm64 write is 64.
        assert_eq!(translate(nr::WRITE, &mut args), Some(64));
        // arm32 read is 3; arm64 read is 63.
        assert_eq!(translate(nr::READ, &mut args), Some(63));
        // arm32 mmap2 is 192; the arm64 table has one mmap at 222.
        assert_eq!(translate(nr::MMAP2, &mut args), Some(222));
        // arm32 futex is 240; arm64 futex is 98.
        assert_eq!(translate(nr::FUTEX, &mut args), Some(98));
        // arm32 gettimeofday is 78; arm64 gettimeofday is 169.
        assert_eq!(translate(nr::GETTIMEOFDAY, &mut args), Some(169));
    }

    #[test]
    fn open_shifts_its_arguments_to_make_room_for_the_directory_fd() {
        let mut args = [0x1000, 0o2, 0o600, 0, 0, 0, 0, 0];
        assert_eq!(translate(nr::OPEN, &mut args), Some(56));
        assert_eq!(args[0], AT_FDCWD, "the directory fd is inserted in front");
        assert_eq!(args[1], 0x1000, "the path moved to slot 1");
        assert_eq!(args[2], 0o2, "the flags moved to slot 2");
        assert_eq!(args[3], 0o600, "the mode moved to slot 3");
    }

    #[test]
    fn llseek_becomes_a_64_bit_lseek() {
        let mut args = [7, 0x0000_0001, 0x0000_0000, 0x2000, 0, 0, 0, 0];
        assert_eq!(translate(nr::LLSEEK, &mut args), Some(62));
        assert_eq!(args[0], 7);
        assert_eq!(args[1], 0x1_0000_0000, "high and low are joined");
        assert_eq!(args[2], 0, "whence");
    }

    #[test]
    fn an_unknown_number_is_not_guessed() {
        let mut args = [0u64; 8];
        assert_eq!(translate(9999, &mut args), None);
    }
}
