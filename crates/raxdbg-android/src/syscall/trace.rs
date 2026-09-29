//! Syscall tracing and protection (anti-debug) detection.
//!
//! The tracer is a *listener*, not a second dispatch path: it is notified
//! from the single SVC choke point ([`crate::syscall::AndroidSyscallHandler::dispatch_swi`])
//! before the table runs and again after it has written the return value,
//! so every syscall the guest makes is recorded with the arguments it was
//! given and the value it got back. Nothing about the emulated behaviour
//! changes: a run with the tracer installed produces the same state as one
//! without it.
//!
//! The second half of this module reads the trace and reports what a
//! packer or a protection wrapper was looking for. unidbg has no
//! counterpart for that — it is the analysis the trace exists to feed.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use raxdbg_core::memory::Memory;

use super::arm64::nr;
use super::handler::UnixSyscallHandler;

/// The arm64 syscall number → name map.
///
/// Only the numbers this crate's table defines are named, so the map stays
/// in lockstep with [`nr`](super::arm64::nr) rather than drifting into a
/// second, hand-maintained list. A number the table does not name is
/// reported as its raw value, which is what the guest would see anyway.
fn name_arm64(number: i32) -> Option<&'static str> {
    // `READLINK` is an alias of `READLINKAT`; the first arm wins.
    Some(match number {
        nr::GETCWD => "getcwd",
        nr::EVENTFD2 => "eventfd2",
        nr::FCNTL => "fcntl",
        nr::DUP3 => "dup3",
        nr::FLOCK => "flock",
        nr::IOCTL => "ioctl",
        nr::MKDIRAT => "mkdirat",
        nr::UNLINKAT => "unlinkat",
        nr::RENAMEAT => "renameat",
        nr::FACCESSAT_48 => "faccessat",
        nr::FSTATFS64 => "fstatfs64",
        nr::FCHMODAT => "fchmodat",
        nr::FCHOWNAT => "fchownat",
        nr::OPENAT => "openat",
        nr::CLOSE => "close",
        nr::PIPE2 => "pipe2",
        nr::GETDENTS64 => "getdents64",
        nr::LSEEK => "lseek",
        nr::READ => "read",
        nr::WRITE => "write",
        nr::WRITEV => "writev",
        nr::PSELECT6 => "pselect6",
        nr::PPOLL => "ppoll",
        nr::READLINKAT => "readlinkat",
        nr::FSTATAT64 => "fstatat64",
        nr::FSTAT => "fstat",
        nr::FDATASYNC => "fdatasync",
        nr::EXIT => "exit",
        nr::EXIT_GROUP => "exit_group",
        nr::SET_TID_ADDRESS => "set_tid_address",
        nr::FUTEX => "futex",
        nr::CLOCK_GETTIME => "clock_gettime",
        nr::PTRACE => "ptrace",
        nr::SCHED_SETSCHEDULER => "sched_setscheduler",
        nr::SCHED_GETSCHEDULER => "sched_getscheduler",
        nr::SCHED_GETPARAM => "sched_getparam",
        nr::SCHED_SETAFFINITY => "sched_setaffinity",
        nr::SCHED_GETAFFINITY => "sched_getaffinity",
        nr::SCHED_YIELD => "sched_yield",
        nr::KILL => "kill",
        nr::TGKILL => "tgkill",
        nr::SIGALTSTACK => "sigaltstack",
        nr::SIGACTION => "sigaction",
        nr::SIGPROCMASK => "sigprocmask",
        nr::RT_SIGPENDING => "rt_sigpending",
        nr::RT_SIGTIMEDWAIT => "rt_sigtimedwait",
        nr::RT_SIGQUEUEINFO => "rt_sigqueueinfo",
        nr::SETPRIORITY => "setpriority",
        nr::GETPRIORITY => "getpriority",
        nr::GETRLIMIT64 => "getrlimit64",
        nr::UNAME => "uname",
        nr::PRCTL => "prctl",
        nr::GETTIMEOFDAY => "gettimeofday",
        nr::GETPID => "getpid",
        nr::GETTID => "gettid",
        nr::GETPPID => "getppid",
        nr::GETUID => "getuid",
        nr::GETEUID => "geteuid",
        nr::BIND => "bind",
        nr::LISTEN => "listen",
        nr::GETSOCKNAME => "getsockname",
        nr::GETPEERNAME => "getpeername",
        nr::SOCKET => "socket",
        nr::SOCKETPAIR => "socketpair",
        nr::CONNECT => "connect",
        nr::ACCEPT4 => "accept4",
        nr::SENDTO => "sendto",
        nr::RECVFROM => "recvfrom",
        nr::SETSOCKOPT => "setsockopt",
        nr::GETSOCKOPT => "getsockopt",
        nr::BRK => "brk",
        nr::MUNMAP => "munmap",
        nr::MREMAP => "mremap",
        nr::CLONE => "clone",
        nr::EXECVE => "execve",
        nr::MMAP => "mmap",
        nr::MPROTECT => "mprotect",
        nr::MSYNC => "msync",
        nr::MLOCK => "mlock",
        nr::MADVISE => "madvise",
        nr::GETRANDOM => "getrandom",
        nr::NANOSLEEP => "nanosleep",
        nr::FTRUNCATE => "ftruncate",
        nr::FALLOCATE => "fallocate",
        _ => return None,
    })
}

/// The arm32 syscall number → name map, for the numbers
/// [`super::arm32::translate`] forwards to the shared handlers.
///
/// arm32's numbers are a different table from arm64's, so an arm32 trace
/// needs its own names; reusing the arm64 ones would print the wrong
/// syscall for the number, which is worse than printing none.
fn name_arm32(number: i32) -> Option<&'static str> {
    Some(match number {
        1 => "exit",
        3 => "read",
        4 => "write",
        5 => "open",
        6 => "close",
        9 => "link",
        10 => "unlink",
        11 => "execve",
        12 => "chdir",
        19 => "lseek",
        20 => "getpid",
        33 => "access",
        36 => "sync",
        37 => "kill",
        38 => "rename",
        39 => "mkdir",
        41 => "dup",
        42 => "pipe",
        45 => "brk",
        54 => "ioctl",
        55 => "fcntl",
        60 => "umask",
        63 => "dup2",
        64 => "getppid",
        65 => "getpgrp",
        66 => "setsid",
        78 => "gettimeofday",
        85 => "readlink",
        91 => "munmap",
        102 => "socketcall",
        114 => "wait4",
        120 => "clone",
        122 => "uname",
        125 => "mprotect",
        140 => "_llseek",
        142 => "select",
        145 => "readv",
        146 => "writev",
        162 => "nanosleep",
        168 => "poll",
        172 => "prctl",
        174 => "rt_sigaction",
        175 => "rt_sigprocmask",
        177 => "rt_sigtimedwait",
        178 => "rt_sigqueueinfo",
        180 => "pread64",
        181 => "pwrite64",
        183 => "getcwd",
        190 => "vfork",
        191 => "getrlimit",
        192 => "mmap2",
        195 => "stat64",
        196 => "lstat64",
        197 => "fstat64",
        199 => "getuid32",
        200 => "getgid32",
        201 => "geteuid32",
        202 => "getegid32",
        208 => "setresuid32",
        213 => "setuid32",
        220 => "madvise",
        221 => "getdents64",
        224 => "gettid",
        238 => "tkill",
        240 => "futex",
        248 => "exit_group",
        252 => "epoll_wait",
        256 => "epoll_ctl",
        268 => "tgkill",
        269 => "utimes",
        281 => "socket",
        282 => "bind",
        283 => "connect",
        284 => "listen",
        285 => "accept",
        286 => "getsockname",
        287 => "getpeername",
        288 => "socketpair",
        289 => "send",
        290 => "sendto",
        291 => "recv",
        292 => "recvfrom",
        293 => "shutdown",
        294 => "setsockopt",
        295 => "getsockopt",
        296 => "sendmsg",
        297 => "recvmsg",
        322 => "openat",
        323 => "mkdirat",
        324 => "mknodat",
        325 => "fchownat",
        326 => "fchmodat",
        327 => "faccessat",
        328 => "pselect6",
        329 => "unlinkat",
        330 => "renameat",
        331 => "linkat",
        332 => "symlinkat",
        340 => "readlinkat",
        341 => "fstatat64",
        342 => "fstat64",
        345 => "sendmmsg",
        355 => "getrandom",
        _ => return None,
    })
}

/// Whether the guest is 64-bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Abi {
    /// AArch64.
    Arm64,
    /// AArch32.
    Arm32,
}

impl Abi {
    /// Whether this is AArch64.
    pub fn is_64bit(self) -> bool {
        self == Abi::Arm64
    }
}

/// One recorded syscall, as the guest issued it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyscallEvent {
    /// A 1-based counter, so a trace line can be referred to by number.
    pub index: u64,
    /// The syscall number (`x8`/`r7`).
    pub number: i32,
    /// Its name, or `None` when this build's table does not name it.
    pub name: Option<&'static str>,
    /// The six argument registers, as handed to the table.
    pub args: [u64; 6],
    /// What `x0`/`r0` held afterwards. `None` when the dispatch did not
    /// reach the write-back (an error aborted it).
    pub result: Option<i64>,
    /// The guest's `errno` afterwards.
    pub errno: i32,
    /// The instruction pointer of the `svc`.
    pub pc: u64,
    /// The link register, i.e. the instruction after the `svc`.
    pub lr: u64,
    /// The guest's pid, as the syscall layer reports it.
    pub pid: i32,
    /// The strings read out of the arguments that point at a path.
    pub paths: BTreeMap<usize, String>,
    /// The bytes read out of the arguments that point at a buffer.
    pub buffers: BTreeMap<usize, Vec<u8>>,
    /// The guest module that owns `pc`, for a readable trace.
    pub module: Option<String>,
}

impl SyscallEvent {
    /// The syscall's name, falling back to its raw number.
    pub fn label(&self) -> String {
        match self.name {
            Some(name) => name.to_string(),
            None => format!("syscall_{}", self.number),
        }
    }
}

/// Where one syscall was made from, and what the guest could see.
pub(crate) struct CallSite<'a> {
    /// The `svc` instruction's address.
    pub pc: u64,
    /// The link register: the instruction after the `svc`.
    pub lr: u64,
    /// The pid the syscall layer reports.
    pub pid: i32,
    /// The POSIX half, for reading path arguments.
    pub handler: &'a UnixSyscallHandler,
    /// Guest memory, for capturing buffer arguments.
    pub memory: &'a dyn Memory,
}

/// Records every syscall the guest makes.
///
/// Installed on the handler with [`super::AndroidSyscallHandler::set_trace`].
/// A `None` slot means "do not record", so a run without a trace pays
/// nothing beyond one branch per syscall.
pub struct SyscallTrace {
    abi: Abi,
    events: Vec<SyscallEvent>,
    /// The path arguments to resolve, by argument index. `openat`'s
    /// pathname is `x1`, the direct `open`'s is `x0`, and so on.
    path_args: &'static [(i32, usize)],
    /// The buffers to snapshot before the call.
    buffer_in: &'static [(i32, usize, usize)],
    /// The buffers to snapshot after the call.
    buffer_out: &'static [(i32, usize, usize)],
}

impl SyscallTrace {
    /// Builds a tracer for `abi` that resolves the given path and buffer
    /// arguments.
    pub fn new(
        abi: Abi,
        path_args: &'static [(i32, usize)],
        buffer_in: &'static [(i32, usize, usize)],
        buffer_out: &'static [(i32, usize, usize)],
    ) -> Self {
        Self {
            abi,
            events: Vec::new(),
            path_args,
            buffer_in,
            buffer_out,
        }
    }

    /// The ABI the trace was built for.
    pub fn abi(&self) -> Abi {
        self.abi
    }

    /// The syscalls recorded so far, in order.
    pub fn events(&self) -> &[SyscallEvent] {
        &self.events
    }

    /// The number of syscalls recorded.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether no syscall has been recorded.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// How many times each named syscall was made, most frequent first.
    pub fn counts(&self) -> Vec<(String, usize)> {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for event in &self.events {
            *counts.entry(event.label()).or_default() += 1;
        }
        let mut out: Vec<(String, usize)> = counts.into_iter().collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        out
    }

    /// Records a syscall's entry state, before the table runs.
    ///
    /// Returns the slot the event was stored in, which [`Self::on_exit`]
    /// takes to fill in the result.
    pub(crate) fn on_enter(
        &mut self,
        number: i32,
        args: [u64; 8],
        call: &CallSite<'_>,
    ) -> u64 {
        let paths = read_paths(number, &args, self.path_args, call.handler);
        let mut buffers = BTreeMap::new();
        for (wanted, index, length) in self.buffer_in {
            if *wanted != number {
                continue;
            }
            if let Some(bytes) = read_buffer(call.memory, args[*index], args[*length]) {
                buffers.insert(*index, bytes);
            }
        }
        let index = self.events.len() as u64 + 1;
        self.events.push(SyscallEvent {
            index,
            number,
            name: name(self.abi, number),
            args: [args[0], args[1], args[2], args[3], args[4], args[5]],
            result: None,
            errno: 0,
            pc: call.pc,
            lr: call.lr,
            pid: call.pid,
            paths,
            buffers,
            module: None,
        });
        index - 1
    }

    /// Fills in the return state of the syscall at `slot`.
    ///
    /// `result` is what the table returned, which is the count for a
    /// `read`/`write` and the byte count bounds the captured output.
    pub(crate) fn on_exit(
        &mut self,
        slot: u64,
        result: i64,
        errno: i32,
        memory: &dyn Memory,
    ) {
        let Some(event) = self.events.get_mut(slot as usize) else {
            return;
        };
        event.result = Some(result);
        event.errno = errno;
        if result <= 0 {
            return;
        }
        // Re-read the buffers now: for a `read` this is the payload the
        // guest actually got, which the entry state could not know.
        let out = self.buffer_out;
        let number = event.number;
        let args = event.args;
        let mut captured = BTreeMap::new();
        for (wanted, index, length) in out {
            if *wanted != number {
                continue;
            }
            // The table returned a byte count, which is the real length; the
            // register is only an upper bound.
            let length = args[*length].min(result as u64);
            if let Some(bytes) = read_buffer(memory, args[*index], length) {
                captured.insert(*index, bytes);
            }
        }
        event.buffers.extend(captured);
    }

    /// Attaches the module name for each event's `pc`.
    ///
    /// Done in one pass after the run: attributing inside the SVC hook
    /// would mean walking the module table on every syscall.
    pub fn attribute_modules(&mut self, mut owner: impl FnMut(u64) -> Option<String>) {
        for event in &mut self.events {
            event.module = owner(event.pc);
        }
    }

    /// The protection/anti-debug findings, see [`ProtectionReport`].
    pub fn protection(&self) -> ProtectionReport {
        ProtectionReport::analyse(self)
    }
}

/// The syscall name for `number` on `abi`.
fn name(abi: Abi, number: i32) -> Option<&'static str> {
    match abi {
        Abi::Arm64 => name_arm64(number),
        Abi::Arm32 => name_arm32(number),
    }
}

/// The path-taking syscalls and which argument carries the path.
///
/// The first entry per number wins, so a number the table does not know
/// about simply resolves nothing.
pub(crate) const PATH_ARGS: &[(i32, usize)] = &[
    (nr::OPENAT, 1),
    (nr::MKDIRAT, 1),
    (nr::UNLINKAT, 1),
    (nr::RENAMEAT, 2),
    (nr::READLINKAT, 1),
    (nr::FSTATAT64, 1),
];

/// The buffers whose contents the trace snapshots on the way **in**.
///
/// `(number, buffer argument, length argument)`. A `write` payload is
/// what the guest says; it is captured before the call, because after it
/// the buffer may have been recycled.
pub(crate) const BUFFER_IN: &[(i32, usize, usize)] = &[(nr::WRITE, 1, 2), (nr::READ, 1, 2)];

/// The buffers whose contents the trace snapshots on the way **out**.
///
/// `(number, buffer argument, length argument)`. A `read` payload is the
/// answer the guest got — this is how a `/proc/self/status` probe's
/// reply, including any `TracerPid` line, becomes visible.
pub(crate) const BUFFER_OUT: &[(i32, usize, usize)] = &[(nr::READ, 1, 2)];

/// The most bytes captured from one buffer.
///
/// A trace is a record, not a memory dump: the head of a `/proc/self/status`
/// or a `write` payload is what identifies the call, and an unbounded read
/// would make the tracer the reason a run goes slow.
pub const BUFFER_CAPTURE_LIMIT: usize = 512;

/// Reads a bounded slice of guest memory for the trace.
///
/// A failure is recorded as an empty buffer rather than dropped, so the
/// trace still shows the call was made. Reading guest memory cannot
/// change what the guest sees, so a tracer that fails here is harmless.
fn read_buffer(
    memory: &dyn Memory,
    address: u64,
    length: u64,
) -> Option<Vec<u8>> {
    if address == 0 || address > 0x0000_7fff_ffff_ffff {
        return None;
    }
    let length = length.min(BUFFER_CAPTURE_LIMIT as u64) as usize;
    if length == 0 {
        return None;
    }
    let mut buf = vec![0u8; length];
    match memory.read_bytes(address, &mut buf) {
        Ok(()) => Some(buf),
        Err(_) => None,
    }
}

/// Reads the path arguments a syscall was given.
///
/// A read failure is not an error: the argument may simply not be a
/// pointer, and a trace must not change the guest's behaviour because of
/// it. A path that fails to read is recorded as `?` so the trace still
/// shows the call was made.
fn read_paths(
    number: i32,
    args: &[u64; 8],
    path_args: &[(i32, usize)],
    handler: &UnixSyscallHandler,
) -> BTreeMap<usize, String> {
    let mut out = BTreeMap::new();
    for (wanted, index) in path_args {
        if *wanted != number || *index >= args.len() {
            continue;
        }
        let address = args[*index];
        if address == 0 || address > 0x0000_7fff_ffff_ffff {
            continue;
        }
        match handler.read_path(address) {
            Ok(path) if !path.is_empty() => {
                out.insert(*index, path);
            }
            Ok(_) => {
                out.insert(*index, String::new());
            }
            Err(_) => {
                out.insert(*index, "<unreadable>".to_string());
            }
        }
    }
    out
}

/// One class of protection check, and whether the guest's answers defeat it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informational: the guest asked, and the answer was harmless.
    Info,
    /// A check the emulation does not yet answer correctly.
    Gap,
    /// A check that would terminate or misbehave the guest.
    Risk,
}

/// One protection-relevant observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// The class of check, e.g. `ptrace self-attach`.
    pub kind: String,
    /// How much it matters.
    pub severity: Severity,
    /// What the guest did, in syscall terms.
    pub evidence: String,
    /// What it means for the run.
    pub detail: String,
}

/// The result of reading a [`SyscallTrace`] for protection checks.
#[derive(Clone, Debug, Default)]
pub struct ProtectionReport {
    /// Every finding, most severe first.
    pub findings: Vec<Finding>,
    /// The number of syscalls the analysis read.
    pub inspected: usize,
    /// The `/proc` and `/system` paths the guest asked for, in order.
    pub probe_paths: Vec<String>,
}

impl ProtectionReport {
    /// Reads `trace` for protection-relevant behaviour.
    pub fn analyse(trace: &SyscallTrace) -> Self {
        Self::from_events(trace.events(), trace.len())
    }

    /// Reads a sequence of events for protection-relevant behaviour.
    ///
    /// The event sequence is the whole input, so a caller that assembled its
    /// own — from a fixture, a recorded run, or a replay — gets the same
    /// analysis the live trace does.
    pub fn from_events(events: &[SyscallEvent], inspected: usize) -> Self {
        let mut report = Self {
            inspected,
            ..Self::default()
        };
        for event in events {
            let label = event.label();
            match event.number {
                nr::PTRACE => report.on_ptrace(event, &label),
                nr::PRCTL => report.on_prctl(event, &label),
                nr::KILL | nr::TGKILL => report.on_kill(event, &label),
                nr::OPENAT => report.on_open(event, &label),
                nr::READ => report.on_read(event, &label),
                nr::GETDENTS64 => report.on_getdents(event, &label),
                _ => {}
            }
        }
        report
            .findings
            .sort_by_key(|finding| std::cmp::Reverse(finding.severity));
        report
    }

    fn push(&mut self, kind: &str, severity: Severity, evidence: String, detail: impl Into<String>) {
        self.findings.push(Finding {
            kind: kind.to_string(),
            severity,
            evidence,
            detail: detail.into(),
        });
    }

    fn on_ptrace(&mut self, event: &SyscallEvent, label: &str) {
        // `PTRACE_TRACEME` (0) is the self-attach a protection uses to make
        // a later `ptrace(PTRACE_ATTACH)` fail: once traced, `/proc/self/status`
        // carries a `TracerPid`. The table answers every request with 0,
        // which is exactly the "not being traced" answer a real device
        // gives an untraced process.
        let request = event.args[0] as i32;
        let request = match request {
            0 => "PTRACE_TRACEME",
            1 => "PTRACE_PEEKTEXT",
            12 => "PTRACE_ATTACH",
            16 => "PTRACE_ATTACH_NR",
            17 => "PTRACE_DETACH",
            other => {
                return self.push(
                    "ptrace",
                    Severity::Info,
                    format!("{label} request={other}"),
                    "an unmodelled ptrace request; the table answers 0 (success)",
                );
            }
        };
        if request == "PTRACE_TRACEME" {
            self.push(
                "ptrace self-attach",
                Severity::Gap,
                format!("{label}(PTRACE_TRACEME) -> 0"),
                "the table answers 0, so the guest believes it is being traced; \
                 a real untraced process is unaffected, but a protection that \
                 expects the attach to *succeed* and then reads TracerPid will \
                 not see one",
            );
        } else {
            self.push(
                "ptrace",
                Severity::Info,
                format!("{label}({request}) -> {:?}", event.result),
                "answered from the table, no guest-visible debugger state changes",
            );
        }
    }

    /// bionic's `PR_SET_VMA` magic (`"SVMA"`), which its `prctl` wrapper
    /// puts in the option slot to tag an anonymous mapping.
    ///
    /// Port of unidbg: `ARM32SyscallHandler.BIONIC_PR_SET_VMA@7f5da98e`. The
    /// wrapper does not shift the arguments for the kernel, so the syscall
    /// really does carry the magic as its option; reading `x0` as the
    /// option without this check yields a nonsense number.
    const BIONIC_PR_SET_VMA: i32 = 0x5356_4d41;
    /// bionic's `PR_SET_PTRACER` magic, which names the process allowed to
    /// `ptrace` this one.
    ///
    /// Port of unidbg: `ARM32SyscallHandler.PR_SET_PTRACER@7f5da98e`.
    const PR_SET_PTRACER: i32 = 0x5961_6d61;

    fn on_prctl(&mut self, event: &SyscallEvent, label: &str) {
        let option = event.args[0] as i32;
        match option {
            Self::BIONIC_PR_SET_VMA => {
                // Tags an anonymous VMA with a name; the kernel takes the
                // address, length and name in x2..x4, and the option slot
                // only carries the tag.
                self.push(
                    "prctl",
                    Severity::Info,
                    format!(
                        "{label}(PR_SET_VMA, addr=0x{:x}, len={}) -> {:?}",
                        event.args[2], event.args[3], event.result
                    ),
                    "bionic tagging an anonymous mapping; not a protection check",
                );
            }
            Self::PR_SET_PTRACER => {
                let pid = event.args[1] as i32;
                // Naming a ptracer is the counterpart of `PTRACE_TRACEME`:
                // a process that sets a ptracer expects a debugger to
                // attach, and one that clears it expects none.
                let (severity, detail) = if pid == 0 {
                    (
                        Severity::Gap,
                        "the ptracer is cleared, which is the state an untraced \
                         process is in; the table has no tracer model either way",
                    )
                } else {
                    (
                        Severity::Info,
                        "a ptracer is named; the table records no tracer, so the \
                         guest's expectation is not observable here",
                    )
                };
                self.push(
                    "ptracer",
                    severity,
                    format!("{label}(PR_SET_PTRACER, pid={pid}) -> {:?}", event.result),
                    detail,
                );
            }
            _ => {
                let name = match option {
                    3 => "PR_GET_DUMPABLE",
                    4 => "PR_SET_DUMPABLE",
                    15 => "PR_SET_NAME",
                    16 => "PR_GET_NAME",
                    38 => "PR_SET_NO_NEW_PRIVS",
                    other => {
                        return self.push(
                            "prctl",
                            Severity::Info,
                            format!("{label}(0x{other:x})"),
                            "an unmodelled prctl option; the table answers 0",
                        );
                    }
                };
                let severity = match option {
                    4 => Severity::Gap,
                    _ => Severity::Info,
                };
                self.push(
                    "prctl",
                    severity,
                    format!("{label}({name}, 0x{:x}) -> {:?}", event.args[1], event.result),
                    if option == 4 {
                        "the table always answers 0, so a guest that clears dumpable \
                         keeps a readable /proc/self/* here while a real device would \
                         have removed it"
                    } else {
                        "answered from the table"
                    },
                );
            }
        }
    }

    fn on_kill(&mut self, event: &SyscallEvent, label: &str) {
        let signal = event.args[1] as i32;
        let target = event.args[0] as i32;
        // SIGTRAP (5) is the self-kill a protection uses to die when it
        // finds a debugger; SIGKILL (9) is the blunt version.
        if signal == 5 || signal == 9 {
            self.push(
                "self-termination",
                Severity::Risk,
                format!("{label}(pid={target}, sig={signal}) -> {:?}", event.result),
                "a protection that reached this point is about to end the \
                 process; the signal itself is not delivered by the table",
            );
        } else {
            self.push(
                "signal",
                Severity::Info,
                format!("{label}(pid={target}, sig={signal}) -> {:?}", event.result),
                "an ordinary signal send",
            );
        }
    }

    fn on_open(&mut self, event: &SyscallEvent, label: &str) {
        let Some(path) = event.paths.get(&1).or_else(|| event.paths.get(&0)) else {
            return;
        };
        if !is_probe_path(path) {
            return;
        }
        self.remember_probe(path);
        let result = event.result.unwrap_or(0);
        // `-ENOENT` is a clean "not being traced"; a success means the guest
        // will read whatever the emulator put there.
        let (severity, verdict) = if result >= 0 {
            (
                Severity::Gap,
                "the file opened: the guest can read whatever the emulator put \
                 there, so the answer reflects this emulator rather than a device",
            )
        } else if result == -2 {
            (
                Severity::Info,
                "-ENOENT: the guest is told the file does not exist, which is the \
                 answer a process that is not being traced gets on a build \
                 without /proc access",
            )
        } else {
            (
                Severity::Info,
                "the open failed for another reason; the guest sees an error",
            )
        };
        self.push(
            "proc probe",
            severity,
            format!("{label}({path}) -> {result}"),
            verdict,
        );
    }

    /// Inspects a `read` payload for the markers a protection looks for.
    fn on_read(&mut self, event: &SyscallEvent, label: &str) {
        if event.result.is_none_or(|count| count <= 0) {
            return;
        }
        let Some(bytes) = event.buffers.get(&1) else {
            return;
        };
        if bytes.is_empty() {
            return;
        }
        let text = String::from_utf8_lossy(bytes);
        let mut markers: Vec<&str> = Vec::new();
        if text.contains("TracerPid:") {
            markers.push("TracerPid");
        }
        for needle in ["frida", "xposed", "magisk", "gdb", "gdbserver", "substrate"] {
            if text.to_ascii_lowercase().contains(needle) {
                markers.push(needle);
            }
        }
        if markers.is_empty() {
            return;
        }
        // `TracerPid: 0` means "nobody is tracing me", which is what an
        // untraced process sees; any other value gives the tracer away.
        let traced = text
            .split("TracerPid:")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .is_some_and(|pid| pid != "0");
        let (severity, detail) = if traced {
            (
                Severity::Risk,
                "the payload names a non-zero TracerPid: a protection reading \
                 this concludes it is being debugged",
            )
        } else {
            (
                Severity::Gap,
                "the payload mentions the marker but reports no tracer; the \
                 check passes here only because the emulator supplies the file",
            )
        };
        self.push(
            "proc payload",
            severity,
            format!(
                "{label}(fd={}, {} bytes) contains {}",
                event.args[0],
                bytes.len(),
                markers.join(", ")
            ),
            detail,
        );
    }

    /// Records a probe path, in first-seen order.
    fn remember_probe(&mut self, path: &str) {
        if !self.probe_paths.iter().any(|seen| seen == path) {
            self.probe_paths.push(path.to_string());
        }
    }

    fn on_getdents(&mut self, event: &SyscallEvent, label: &str) {
        // Enumerating `/proc/self/maps` is the other half of the probe.
        let Some(path) = event.paths.get(&1) else {
            return;
        };
        if !is_probe_path(path) {
            return;
        }
        self.remember_probe(path);
        self.push(
            "proc probe",
            Severity::Info,
            format!("{label}({path}) -> {:?}", event.result),
            "the guest enumerated a /proc path; the entries come from the \
             emulator's own region tree, not a device's",
        );
    }
}

/// Whether `path` is one of the files a protection reads.
fn is_probe_path(path: &str) -> bool {
    const PROBES: &[&str] = &[
        "/proc/self/status",
        "/proc/self/maps",
        "/proc/self/mem",
        "/proc/self/cmdline",
        "/proc/self/exe",
        "/proc/self/attr/current",
        "/proc/self/task",
        "/proc/net/tcp",
        "/proc/version",
        "/proc/mounts",
        "/system/xbin/su",
        "/system/bin/su",
        "/sbin/su",
    ];
    PROBES.iter().any(|probe| path.starts_with(probe))
}

/// How much of a trace to print.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verbosity {
    /// One line per syscall, with the arguments and the result.
    Full,
    /// Only the syscalls that carry a path or a captured buffer.
    Interesting,
    /// No per-syscall lines; the summary and the report only.
    Summary,
}

/// Escapes a buffer for a one-line trace: printable ASCII stays, the rest
/// becomes `\xNN`, and a NUL ends the string the way it would in C.
fn escape(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for byte in bytes.iter().take(96) {
        match byte {
            0 => break,
            b' '..=b'~' => out.push(*byte as char),
            b'\n' => out.push_str("\\n"),
            b'\t' => out.push_str("\\t"),
            other => {
                let _ = write!(out, "\\x{other:02x}");
            }
        }
    }
    if out.len() >= 96 {
        out.push_str("...");
    }
    out
}

/// Formats one syscall as a trace line.
pub fn format_event(event: &SyscallEvent) -> String {
    let mut line = format!("#{:<5} pid={:<6} ", event.index, event.pid);
    let module = event.module.as_deref().unwrap_or("-");
    let _ = write!(
        line,
        "{:>10}@0x{:x} in {module}(",
        event.label(),
        event.pc
    );
    for (index, arg) in event.args.iter().enumerate() {
        if index > 0 {
            line.push_str(", ");
        }
        match event.paths.get(&index) {
            Some(path) => {
                let _ = write!(line, "{path:?}");
            }
            None => {
                let _ = write!(line, "0x{arg:x}");
            }
        }
    }
    line.push(')');
    match event.result {
        Some(result) => {
            let _ = write!(line, " = {result}");
            if event.errno != 0 {
                let _ = write!(line, " errno={}", event.errno);
            }
        }
        None => line.push_str(" = <not returned>"),
    }
    line
}

/// Writes the per-syscall trace lines for `trace` at `verbosity`.
pub fn render(trace: &SyscallTrace, verbosity: Verbosity) -> String {
    if verbosity == Verbosity::Summary || trace.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    for event in trace.events() {
        if verbosity == Verbosity::Interesting
            && event.paths.is_empty()
            && event.buffers.is_empty()
        {
            continue;
        }
        out.push_str(&format_event(event));
        out.push('\n');
        // The captured payloads go on their own lines, indented, so a long
        // string does not push the result off the line.
        for (index, bytes) in &event.buffers {
            if bytes.is_empty() {
                continue;
            }
            let _ = writeln!(out, "         x{index} = \"{}\"", escape(bytes));
        }
    }
    out
}

impl ProtectionReport {
    /// The one-line-per-finding report, or a note that nothing was found.
    pub fn render(&self) -> String {
        if self.findings.is_empty() {
            return "no protection checks observed in this trace\n".to_string();
        }
        let mut out = String::new();
        for finding in &self.findings {
            let tag = match finding.severity {
                Severity::Risk => "RISK",
                Severity::Gap => "GAP ",
                Severity::Info => "info",
            };
            let _ = writeln!(out, "[{tag}] {}: {}", finding.kind, finding.evidence);
            let _ = writeln!(out, "       {}", finding.detail);
        }
        out
    }

    /// The findings that would end or derail a run, most severe first.
    pub fn risks(&self) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|finding| finding.severity == Severity::Risk)
            .collect()
    }
}

