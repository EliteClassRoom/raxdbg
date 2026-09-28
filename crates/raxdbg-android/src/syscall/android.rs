//! Android-specific additions to the syscall layer.
//!
//! Port of unidbg: `unidbg-android/src/main/java/com/github/unidbg/linux/AndroidSyscallHandler.java`
//! @7f5da98e. The arm64 table (`super::arm64`) delegates here for the
//! syscalls the Android reference handles (thread ids, sched masks,
//! `set_tid_address`, `futex` and `nanosleep` returning through waiters).
//!
//! For P4, `futex` answers `-EAGAIN` when no waiter machinery is installed
//! and `FUTEX_WAKE` returns the number of waiters woken (zero in P4
//! because the waiters land in P7). `nanosleep` similarly returns
//! immediately — no dispatcher for P4.
//!
//! This module also exposes the public constructor the plan calls out:
//! [`AndroidSyscallHandler::new`] builds the SVC page, opens the standard
//! fds, and installs the `FileMapper` used by file-backed `mmap2`.

use std::cell::{Cell, RefCell};
use std::io::{Read, Write};
use std::rc::{Rc, Weak as RcWeak};
use std::sync::Arc;

use raxdbg_core::backend::{
    Backend, BackendError, RunError, EXCP_BKPT, EXCP_SWI, EXCP_UDEF,
};
use raxdbg_core::file::driver::StdoutFileIO;
use raxdbg_core::memory::loader::FileMapper;
use raxdbg_core::memory::MemoryError;
use raxdbg_core::reg::RegId;
use raxdbg_core::svc::{
    ARM64_SVC_MAX, ARM_SVC_MAX, Svc, SvcKind, SvcMemory, THUMB_SVC_MAX,
};

use super::arm64::Arm64ThreadState;
use super::handler::{SharedSink, SyscallError, UnixSyscallHandler};
use crate::elf::AndroidElfLoader;

/// The PRE-callback `swi` marker used by arm64 stubs.
const PRE_CALLBACK_SYSCALL_NUMBER: u64 = 0x8866;
/// The POST-callback `swi` marker used by arm64 stubs.
const POST_CALLBACK_SYSCALL_NUMBER: u64 = 0x8888;

/// Errors raised by [`AndroidSyscallHandler::new`].
#[derive(Debug, thiserror::Error)]
pub enum AndroidSyscallError {
    /// The guest memory operation the constructor needed failed.
    #[error(transparent)]
    Memory(#[from] MemoryError),
    /// Registering a stub on the SVC page failed.
    #[error("cannot register svc stub {name}: {source}")]
    RegisterSvc {
        /// The SVC's display name.
        name: String,
        /// The underlying memory error.
        #[source]
        source: MemoryError,
    },
}

/// A file-backed `mmap2` routed through the syscall layer's fd table.
///
/// unidbg routes `MMAP_FILE` through the `FileIO` of the descriptor; we
/// do the same so e.g. `ByteArrayFileIO::mmap2` populates the new
/// mapping from its in-memory bytes, and other descriptors fall back to
/// an empty buffer.
///
/// The mapper holds a weak reference to the active syscall layer;
/// upgrades fail when the handler has been dropped, which is exactly the
/// right behaviour because by that point the loader is dropping too.
pub(crate) struct FdFileMapper {
    /// Weak handle to the `UnixSyscallHandler` whose fd table we look
    /// `fd` up in.
    handler: RcWeak<RefCell<UnixSyscallHandler>>,
}

impl std::fmt::Debug for FdFileMapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FdFileMapper").finish_non_exhaustive()
    }
}

impl FileMapper for FdFileMapper {
    fn mmap_file(
        &self,
        fd: i32,
        addr: u64,
        length: u64,
        prot: raxdbg_core::backend::Prot,
        offset: i64,
    ) -> Result<u64, MemoryError> {
        let handler = self.handler.upgrade().ok_or_else(|| {
            MemoryError::Message("the syscall handler has been dropped".into())
        })?;
        let memory = handler.borrow().memory().clone();
        let result = handler.borrow().with_file_io(fd, |io| {
            io.mmap2(memory.as_ref(), addr, length, prot, offset, length as usize)
        });
        match result {
            Some(Ok(addr)) => Ok(addr),
            Some(Err(err)) => Err(err),
            None => Err(MemoryError::Message(format!(
                "no fd {fd} in the syscall layer"
            ))),
        }
    }
}

/// `Rc<RefCell<UnixSyscallHandler>>` alias used at module boundaries.
pub type SharedUnixHandler = Rc<RefCell<UnixSyscallHandler>>;

/// The Android-side syscall state: shared POSIX half + the SVC page +
/// the arm64 thread fields + the standard fd layout.
///
/// The handler is the SVC trampoline the emulator's interrupt hook
/// installs. Every call into [`AndroidSyscallHandler::dispatch`] answers
/// one `SVC`/`BRK`/`UDEF` trap, so the public surface stays small.
pub struct AndroidSyscallHandler {
    /// The shared POSIX/FD half.
    pub handler: SharedUnixHandler,
    /// The SVC page.
    pub svc_memory: Rc<SvcMemory>,
    /// The Android emulator's per-thread state (tid counter, sched masks).
    pub state: Arm64ThreadState,
    /// Whether the guest is 64-bit.
    is_64bit: bool,
    /// The shared sink the captured `stdout` (fd 1) and `stderr` (fd 2)
    /// write into.
    stdout_sink: Arc<SharedSink>,
    /// The guest `errno` after the last handler ran. Cached so handlers
    /// that return `-errno` without writing errno (e.g. anonymous mmap
    /// failing) can still report a consistent number.
    last_errno: Cell<i32>,
}

impl std::fmt::Debug for AndroidSyscallHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AndroidSyscallHandler")
            .field("is_64bit", &self.is_64bit)
            .field("fd_count", &self.handler.borrow().fds())
            .field("last_errno", &self.last_errno.get())
            .finish_non_exhaustive()
    }
}

impl AndroidSyscallHandler {
    /// Builds the SVC page, opens fds 0/1/2, and installs the
    /// `FileMapper` used by file-backed `mmap2`.
    ///
    /// Port of unidbg:
    /// * `ARM64SyscallHandler` constructor — creates the SVC page.
    /// * `AndroidElfLoader.setLibraryResolver` side effect — opens
    ///   `stdin`/`stdout`/`stderr` before any user code runs.
    /// * `Memory.setFileMapper` — wires file-backed `mmap2` to the
    ///   syscall layer's fd table.
    pub fn new(
        loader: Rc<AndroidElfLoader>,
        is_64bit: bool,
        stdout_sink: Option<Arc<SharedSink>>,
    ) -> Result<Rc<RefCell<Self>>, AndroidSyscallError> {
        let memory = loader.memory();
        let svc_memory = Rc::new(SvcMemory::new(memory.as_ref(), is_64bit)?);
        loader.set_svc_memory(Rc::clone(&svc_memory));

        let sink = stdout_sink.unwrap_or_else(SharedSink::new);
        let handler: SharedUnixHandler = Rc::new_cyclic(|weak| {
            let inner = UnixSyscallHandler::new(memory.clone(), is_64bit);
            install_standard_descriptors(&inner, sink.clone());
            // Wire the file mapper after the handler is anchored; this
            // lets `mmap_file` upgrade the weak reference safely.
            memory.set_file_mapper(Box::new(FdFileMapper {
                handler: weak.clone(),
            }));
            RefCell::new(inner)
        });

        let syscall_handler = Rc::new(RefCell::new(Self {
            handler,
            svc_memory,
            state: Arm64ThreadState::new(1),
            is_64bit,
            stdout_sink: sink,
            last_errno: Cell::new(0),
        }));
        Ok(syscall_handler)
    }

    /// The SVC page.
    pub fn svc_memory(&self) -> Rc<SvcMemory> {
        Rc::clone(&self.svc_memory)
    }

    /// The shared stdout sink, used by tests to assert `printf` output.
    pub fn stdout_sink(&self) -> Arc<SharedSink> {
        Arc::clone(&self.stdout_sink)
    }

    /// Whether the guest is 64-bit.
    pub fn is_64bit(&self) -> bool {
        self.is_64bit
    }

    /// The shared POSIX handler.
    pub fn unix_handler(&self) -> std::cell::Ref<'_, UnixSyscallHandler> {
        self.handler.borrow()
    }

    /// The arm64 thread state.
    pub fn thread_state(&self) -> &Arm64ThreadState {
        &self.state
    }

    /// Registers an SVC stub, allocating both the encoding in the SVC
    /// page and the bookkeeping slot.
    pub fn register_svc(&self, svc: Box<dyn Svc>) -> Result<u64, AndroidSyscallError> {
        let handler = self.handler.borrow();
        self.svc_memory
            .register_svc(&**handler.memory(), svc)
            .map_err(|source| AndroidSyscallError::RegisterSvc {
                name: "<svc>".into(),
                source,
            })
    }

    /// `open(2)` against the resolver chain.
    pub fn open(&self, path: &str, oflags: i32) -> i32 {
        self.handler.borrow().open(path, oflags)
    }

    /// Reads a NUL-terminated path from the guest at `address`.
    pub fn read_path(&self, address: u64) -> Result<String, SyscallError> {
        self.handler.borrow().read_path(address)
    }

    /// Dispatches a single SVC/BRK/UDEF trap.
    ///
    /// Matches the plan P4.2 contract exactly:
    ///
    /// * `intno == EXCP_SWI && swi != 0` looks the stub up on the SVC
    ///   page; if found, calls `svc.handle(backend)`, writes the result
    ///   to `x0` (arm64) or `r0` (arm32), and **does not touch the PC**
    ///   (the stub's own `ret`/`bx lr` returns to the caller).
    /// * `swi == ARM64_SVC_MAX` (resp. `ARM_SVC_MAX`, `THUMB_SVC_MAX`)
    ///   raises `RunError::PopContext`; `swi == SVC_MAX - 1` raises
    ///   `RunError::ThreadSwitch`.
    /// * `swi == 0` routes a real syscall through the arm64 table.
    /// * `EXCP_BKPT`/`EXCP_UDEF` return a `BackendError::Other` that
    ///   names the PC and the reason.
    pub fn dispatch(
        &mut self,
        backend: &mut dyn Backend,
        intno: i32,
        swi: i32,
    ) -> Result<(), RunError> {
        match intno {
            EXCP_SWI => self.dispatch_swi(backend, swi),
            EXCP_BKPT => Err(RunError::Backend(BackendError::Other(format!(
                "BRK trap at pc={:#x}; the console debugger hooks these in P11",
                backend.reg_read(RegId::Pc).unwrap_or(0)
            )))),
            EXCP_UDEF => Err(RunError::Backend(BackendError::Other(format!(
                "undefined instruction at pc={:#x}",
                backend.reg_read(RegId::Pc).unwrap_or(0)
            )))),
            other => Err(RunError::Backend(BackendError::Other(format!(
                "unexpected intno={other}"
            )))),
        }
    }

    fn dispatch_swi(&mut self, backend: &mut dyn Backend, swi: i32) -> Result<(), RunError> {
        // Reserved numbers: pop context / thread switch.
        let max = if self.is_64bit {
            ARM64_SVC_MAX
        } else {
            // We don't differentiate ARM/Thumb in this prototype; the
            // arm32 table will refine this.
            ARM_SVC_MAX.max(THUMB_SVC_MAX)
        };
        if swi == max {
            return Err(RunError::PopContext);
        }
        if swi == max - 1 {
            return Err(RunError::ThreadSwitch);
        }
        if swi != 0 {
            // Look up the stub's SVC. We `take` it out for the
            // duration of the call to break the aliasing between the
            // SVC page and the backend the handler is handed; we
            // `put` it back before returning.
            let svc = self.svc_memory.take_svc(swi);
            let Some(mut svc) = svc else {
                let pc = backend.reg_read(RegId::Pc).unwrap_or(0);
                return Err(RunError::Backend(BackendError::Other(format!(
                    "no SVC stub registered for swi={swi:#x} (pc={pc:#x})"
                ))));
            };
            let result = svc.handle(backend)?;
            // Write the result to x0 (arm64) or r0 (arm32). The kind
            // already encodes which; we look it up to drive the right
            // RegId.
            let target = match svc.kind() {
                SvcKind::Arm64 => RegId::X(0),
                _ => RegId::R(0),
            };
            backend.reg_write(target, result as u64)?;
            self.svc_memory.put_svc(swi, svc);
            // Crucially: do **not** touch PC. The stub's trailing
            // `ret`/`bx lr` returns to the caller.
            return Ok(());
        }

        // `swi == 0`: real syscall. The number comes from `x8` on
        // arm64 or `r7` on arm32; the args come from `x0..x6` /
        // `r0..r6`. We save them into a buffer for the table.
        let (nr, args) = if self.is_64bit {
            let nr = backend.reg_read(RegId::X(8))? as i32;
            let args = [
                backend.reg_read(RegId::X(0))?,
                backend.reg_read(RegId::X(1))?,
                backend.reg_read(RegId::X(2))?,
                backend.reg_read(RegId::X(3))?,
                backend.reg_read(RegId::X(4))?,
                backend.reg_read(RegId::X(5))?,
                backend.reg_read(RegId::X(6))?,
                0,
            ];
            (nr, args)
        } else {
            let nr = backend.reg_read(RegId::R(7))? as i32;
            let args = [
                backend.reg_read(RegId::R(0))?,
                backend.reg_read(RegId::R(1))?,
                backend.reg_read(RegId::R(2))?,
                backend.reg_read(RegId::R(3))?,
                backend.reg_read(RegId::R(4))?,
                backend.reg_read(RegId::R(5))?,
                backend.reg_read(RegId::R(6))?,
                0,
            ];
            (nr, args)
        };

        // Handle PRE/POST callbacks. unidbg dispatches these as a
        // separate code path: when `swi == 0` AND `NR == 0` AND
        // `x16 == 0x8866 | 0x8888`, the stub number is in `x12`.
        if nr == 0 && self.is_64bit {
            let marker = backend.reg_read(RegId::X(16))?;
            if marker == PRE_CALLBACK_SYSCALL_NUMBER
                || marker == POST_CALLBACK_SYSCALL_NUMBER
            {
                let number = backend.reg_read(RegId::X(12))? as i32;
                let svc = self.svc_memory.take_svc(number);
                if let Some(mut svc) = svc {
                    if marker == PRE_CALLBACK_SYSCALL_NUMBER {
                        svc.handle_pre_callback(backend);
                    } else {
                        svc.handle_post_callback(backend);
                    }
                    self.svc_memory.put_svc(number, svc);
                    return Ok(());
                }
                return Err(RunError::Backend(BackendError::Other(format!(
                    "PRE/POST callback for swi={number:#x} but no SVC registered"
                ))));
            }
        }

        let handler = self.handler.borrow();
        let result = super::arm64::dispatch(&handler, &self.state, nr, args);
        let target = if self.is_64bit {
            RegId::X(0)
        } else {
            RegId::R(0)
        };
        backend.reg_write(target, result as u64)?;
        Ok(())
    }
}

/// An empty `Read` source used for the captured `stdin`.
struct StdinReader;

impl Read for StdinReader {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Ok(0)
    }
}

/// A `Write` adapter over an `Arc<SharedSink>` so `StdoutFileIO::new`
/// can take it as a `Box<dyn Write + Send>` even when other owners of
/// the `Arc` are still around (the test that asserts on the bytes
/// typically holds the other handle).
struct SharedSinkWriter(Arc<SharedSink>);
impl Write for SharedSinkWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.append(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
/// resolver is installed; we keep a public helper so callers and tests
/// can also re-run the side effect (e.g. when they want a different
/// `SharedSink`).
pub fn install_standard_descriptors(handler: &UnixSyscallHandler, sink: Arc<SharedSink>) {
    let mut map = handler.fd_map.write();
    map.insert(
        0,
        Box::new(raxdbg_core::file::driver::StdinFileIO::new(
            "stdin",
            Box::new(StdinReader),
        )),
    );
    // `StdoutFileIO::new` takes a `Box<dyn Write + Send>`. `SharedSink`
    // implements `Write` and is `Send` (it owns its inner buffer
    // through an `Arc<Mutex<...>>`), so we wrap it in the
    // `SharedSinkWriter` adapter and box that.
    map.insert(
        1,
        Box::new(StdoutFileIO::new(
            "stdout",
            Box::new(SharedSinkWriter(sink.clone())),
        )),
    );
    map.insert(
        2,
        Box::new(StdoutFileIO::new(
            "stderr",
            Box::new(SharedSinkWriter(sink)),
        )),
    );
}

/// `Rc<RefCell<AndroidSyscallHandler>>` alias for readability.
pub type RefCellAndroidSyscallHandler = RefCell<AndroidSyscallHandler>;

/// A struct that implements [`InterruptHook`], wrapping an
/// `AndroidSyscallHandler` and bridging into the dispatch.
pub struct SyscallHook {
    /// The handler to dispatch into.
    pub handler: Rc<RefCellAndroidSyscallHandler>,
}

impl SyscallHook {
    /// Wraps `handler` for installation as an `InterruptHook`.
    pub fn new(handler: Rc<RefCellAndroidSyscallHandler>) -> Self {
        Self { handler }
    }
}

impl raxdbg_core::backend::InterruptHook for SyscallHook {
    fn hook(&mut self, backend: &mut dyn Backend, intno: i32, swi: i32) {
        let mut handler = self.handler.borrow_mut();
        if let Err(err) = handler.dispatch(backend, intno, swi) {
            // Convert control-flow errors into a backend stop; the run
            // loop surfaces it as `RunOutcome::Stopped` or the matching
            // `RunError`.
            backend.set_pending_error(err);
            backend.emu_stop();
        }
    }
}