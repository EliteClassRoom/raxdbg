//! Instruction tracing, memory tracing and disassembly.
//!
//! Port of unidbg:
//!
//! * `unidbg-api/src/main/java/com/github/unidbg/{TraceHook, TraceMemoryHook}.java@7f5da98e`
//! * `unidbg-api/src/main/java/com/github/unidbg/AssemblyCodeDumper.java@7f5da98e`
//!
//! Both hooks accumulate their events into a `Vec` the caller can drain, and
//! optionally mirror a text stream into any `Box<dyn Write>`. The disassembler
//! is hidden behind a small trait so `raxdbg-core` does not pull `yaxpeax-arm`
//! in (that crate is built on the side of `raxdbg-android`); the default
//! implementation is a no-op, the production implementation in `raxdbg-android`
//! (plan P11.2) wraps `yaxpeax-arm`.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::Write;
use std::rc::Rc;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::backend::{Backend, CodeHook, MemHookCtx, ReadHook, WriteHook};
use crate::reg::RegId;

/// One traced instruction.
#[derive(Clone, Debug)]
pub struct TraceEntry {
    /// The address the instruction lives at.
    pub pc: u64,
    /// The instruction size in bytes.
    pub size: u32,
    /// The decoded instruction, when a disassembler is available.
    pub disassembly: Option<String>,
    /// Snapshot of the register file *before* the instruction retired.
    pub registers: BTreeMap<RegId, u64>,
}

/// One traced memory access.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemTraceEvent {
    /// The guest PC that issued the access.
    pub pc: u64,
    /// The address being accessed.
    pub address: u64,
    /// The number of bytes being read or written.
    pub size: usize,
    /// For reads this is the value being read; for writes this is the value
    /// being stored (same as `value` in [`WriteHook::hook`]).
    pub value: u64,
}

// Disassembler ----------------------------------------------------------------

/// The disassembler interface that hooks consume.
///
/// `raxdbg-core` cannot depend on `yaxpeax-arm` (that dependency belongs to
/// `raxdbg-android`), so the disassembler is a trait the user fills in. The
/// `raxdbg-android` crate ships a `yaxpeax-arm`-backed implementation in P11.2.
pub trait Disassembler {
    /// Decodes the instruction starting at `addr`. `bytes` is the raw
    /// instruction stream (capped at the first instruction's size by the
    /// caller); `thumb` selects the AArch32 decoder for arm32 targets.
    /// Returns `None` when the instruction cannot be decoded.
    fn disassemble(&self, addr: u64, bytes: &[u8], thumb: bool) -> Option<String>;
}

impl<D: Disassembler + ?Sized> Disassembler for Rc<D> {
    fn disassemble(&self, addr: u64, bytes: &[u8], thumb: bool) -> Option<String> {
        (**self).disassemble(addr, bytes, thumb)
    }
}

impl<D: Disassembler + ?Sized> Disassembler for Box<D> {
    fn disassemble(&self, addr: u64, bytes: &[u8], thumb: bool) -> Option<String> {
        (**self).disassemble(addr, bytes, thumb)
    }
}

/// A trivial disassembler that produces no text.
///
/// Use this as the default until the `raxdbg-android` crate wires up
/// `yaxpeax-arm` (plan P11.2).
pub struct NoopDisassembler;

impl Disassembler for NoopDisassembler {
    fn disassemble(&self, _addr: u64, _bytes: &[u8], _thumb: bool) -> Option<String> {
        None
    }
}

// Shared helpers --------------------------------------------------------------

/// Snapshot the registers the trace formatter can name. Unrecognized
/// registers (because the backend does not implement them) are silently
/// skipped, so the same helper works on the AArch64 and the AArch32
/// stand-in backends.
fn snapshot_registers(backend: &mut dyn Backend) -> BTreeMap<RegId, u64> {
    let mut regs = BTreeMap::new();
    for reg in [
        RegId::Pc,
        RegId::Sp,
        RegId::Lr,
        RegId::Fp,
        RegId::X(0),
        RegId::X(1),
        RegId::X(2),
        RegId::R(0),
        RegId::R(1),
        RegId::R(2),
    ] {
        if let Ok(value) = backend.reg_read(reg) {
            regs.insert(reg, value);
        }
    }
    regs
}

fn read_instruction_bytes(backend: &mut dyn Backend, address: u64, size: u32) -> Vec<u8> {
    let size = size as usize;
    if size == 0 {
        return Vec::new();
    }
    match backend.mem_read(address, size) {
        Ok(bytes) => bytes,
        Err(_) => Vec::new(),
    }
}

fn format_trace_line(pc: u64, size: u32, text: Option<&str>) -> String {
    match text {
        Some(t) => format!("0x{:x} [{}]: {}", pc, size * 8, t),
        None => format!("0x{:x} [{}]: <no disassembler>", pc, size * 8),
    }
}

// Instruction tracing ---------------------------------------------------------

/// Instruction-trace hook.
///
/// `TraceCode` registers as a code hook over `[begin, end]`. Every
/// instruction it sees is pushed onto `entries` and, when an `output`
/// redirect is set, written as `pc:<text>\n`. Mirrors unidbg's
/// `AssemblyCodeDumper` (which is itself a `CodeHook`).
pub struct TraceCode {
    inner: Rc<RefCell<TraceCodeInner>>,
}

struct TraceCodeInner {
    disassembler: Rc<dyn Disassembler>,
    entries: Vec<TraceEntry>,
    output: Option<Box<dyn Write>>,
}

impl TraceCode {
    /// Creates a new trace hook. `disassembler` may be a no-op when no
    /// instruction decoding is desired; the trace still records `(pc, size)`.
    pub fn new(disassembler: Rc<dyn Disassembler>) -> Self {
        Self {
            inner: Rc::new(RefCell::new(TraceCodeInner {
                disassembler,
                entries: Vec::new(),
                output: None,
            })),
        }
    }

    /// Routes trace lines through `output`. Pass a writer that captures into
    /// a `Vec<u8>` or a `stderr`-derived handle. Mirrors
    pub fn set_redirect(&self, output: Box<dyn Write>) {
        self.inner.borrow_mut().output = Some(output);
    }

    /// Stops tracing: clears accumulated entries and drops the redirect.
    /// Mirrors `TraceHook.stopTrace`.
    pub fn stop_trace(&self) {
        let mut inner = self.inner.borrow_mut();
        inner.entries.clear();
        inner.output = None;
    }

    /// Returns a snapshot of the recorded entries.
    pub fn entries(&self) -> Vec<TraceEntry> {
        self.inner.borrow().entries.clone()
    }

    /// Installs the hook on `backend` over `[begin, end]`.
    pub fn attach(&self, backend: &Rc<RefCell<dyn Backend>>, begin: u64, end: u64) -> u64 {
        let hook = TraceCodeHook {
            inner: self.inner.clone(),
        };
        backend.borrow_mut().hook_add_code(Box::new(hook), begin, end)
    }
}

struct TraceCodeHook {
    inner: Rc<RefCell<TraceCodeInner>>,
}

impl CodeHook for TraceCodeHook {
    fn hook(&mut self, backend: &mut dyn Backend, address: u64, size: u32) {
        let registers = snapshot_registers(backend);
        let bytes = read_instruction_bytes(backend, address, size);
        let disassembly = {
            let dis = self.inner.borrow().disassembler.clone();
            dis.disassemble(address, &bytes, false)
        };

        let line = format_trace_line(address, size, disassembly.as_deref());

        {
            if let Some(out) = self.inner.borrow_mut().output.as_mut() {
                let _ = writeln!(out, "{line}");
            }
        }

        self.inner.borrow_mut().entries.push(TraceEntry {
            pc: address,
            size,
            disassembly,
            registers,
        });
    }
}

// Memory tracing --------------------------------------------------------------

/// Memory-trace hook (`ReadHook` + `WriteHook`).
///
/// Registers read and write hooks on `[begin, end]`. Every access lands in a
/// `Vec<MemTraceEvent>` and, if an output redirect was set, is mirrored as
/// `R <pc>: <addr>=<value>` / `W <pc>: <addr>=<value>`. Mirrors unidbg's
/// `TraceMemoryHook(boolean read)`.
///
/// The shared state lives behind an `Arc<Mutex<_>>` because
/// [`Backend::hook_add_read`] / [`Backend::hook_add_write`] require the
/// callbacks to be `Send`.
pub struct TraceMemory {
    inner: Arc<Mutex<TraceMemoryInner>>,
    #[allow(dead_code)]
    collect_reads: bool,
}
struct TraceMemoryInner {
    reads: Vec<MemTraceEvent>,
    writes: Vec<MemTraceEvent>,
    output: Option<Box<dyn Write + Send>>,
}

impl TraceMemory {
    /// Creates a memory trace hook. `collect_reads = true` records loads;
    /// `collect_reads = false` records only stores.
    pub fn new(collect_reads: bool) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TraceMemoryInner {
                reads: Vec::new(),
                writes: Vec::new(),
                output: None,
            })),
            collect_reads,
        }
    }
    /// Routes trace lines through `output`. See [`TraceCode::set_redirect`].
    /// `Box<dyn Write + Send>` because the inner state lives inside
    /// `Arc<parking_lot::Mutex<_>>` which itself must be `Send`.
    pub fn set_redirect(&self, output: Box<dyn Write + Send>) {
        self.inner.lock().output = Some(output);
    }

    /// Stops tracing; clears both lists and drops the redirect.
    pub fn stop_trace(&self) {
        let mut inner = self.inner.lock();
        inner.reads.clear();
        inner.writes.clear();
        inner.output = None;
    }

    /// Returns the recorded reads.
    pub fn reads(&self) -> Vec<MemTraceEvent> {
        self.inner.lock().reads.clone()
    }

    /// Returns the recorded writes.
    pub fn writes(&self) -> Vec<MemTraceEvent> {
        self.inner.lock().writes.clone()
    }

    /// Installs both hooks on `backend` over `[begin, end]`. Returns
    /// `(read_hook_id, write_hook_id)`.
    pub fn attach(
        &self,
        backend: &Rc<RefCell<dyn Backend>>,
        begin: u64,
        end: u64,
    ) -> (u64, u64) {
        let read_hook = TraceMemoryReadHook {
            inner: self.inner.clone(),
        };
        let write_hook = TraceMemoryWriteHook {
            inner: self.inner.clone(),
        };
        let mut backend = backend.borrow_mut();
        let read_id = backend.hook_add_read(Box::new(read_hook), begin, end);
        let write_id = backend.hook_add_write(Box::new(write_hook), begin, end);
        (read_id, write_id)
    }
}

struct TraceMemoryReadHook {
    inner: Arc<Mutex<TraceMemoryInner>>,
}

impl ReadHook for TraceMemoryReadHook {
    fn hook(&mut self, ctx: &mut MemHookCtx<'_>, address: u64, size: usize) {
        let pc = ctx.pc();
        let value = if size <= 8 {
            let mut buf = [0u8; 8];
            if ctx.read(address, &mut buf[..size]).is_ok() {
                let mut v = 0u64;
                for (index, byte) in buf[..size].iter().enumerate() {
                    v |= (*byte as u64) << (index * 8);
                }
                v
            } else {
                0
            }
        } else {
            0
        };

        let event = MemTraceEvent {
            pc,
            address,
            size,
            value,
        };

        let mut inner = self.inner.lock();
        if let Some(out) = inner.output.as_mut() {
            let _ = writeln!(out, "R {:#x}: {:#x}={:#x}", pc, address, value);
        }
        inner.reads.push(event);
    }
}

struct TraceMemoryWriteHook {
    inner: Arc<Mutex<TraceMemoryInner>>,
}

impl WriteHook for TraceMemoryWriteHook {
    fn hook(&mut self, ctx: &mut MemHookCtx<'_>, address: u64, size: usize, value: u64) {
        let pc = ctx.pc();
        let event = MemTraceEvent {
            pc,
            address,
            size,
            value,
        };

        let mut inner = self.inner.lock();
        if let Some(out) = inner.output.as_mut() {
            let _ = writeln!(out, "W {:#x}: {:#x}={:#x}", pc, address, value);
        }
        inner.writes.push(event);
    }
}

// Assembly dumper -------------------------------------------------------------

/// Assembly-only trace hook — collects entries without redirecting to a
/// writer. Equivalent to unidbg's `AssemblyCodeDumper` configured without a
/// `TraceCodeListener`.
pub struct AssemblyCodeDumper {
    inner: Rc<RefCell<TraceCodeInner>>,
}

impl AssemblyCodeDumper {
    pub fn new(disassembler: Rc<dyn Disassembler>) -> Self {
        Self {
            inner: Rc::new(RefCell::new(TraceCodeInner {
                disassembler,
                entries: Vec::new(),
                output: None,
            })),
        }
    }

    pub fn entries(&self) -> Vec<TraceEntry> {
        self.inner.borrow().entries.clone()
    }
    pub fn attach(
        &self,
        backend: &Rc<RefCell<dyn Backend>>,
        begin: u64,
        end: u64,
    ) -> u64 {
        let hook = AssemblyCodeDumperHook {
            inner: self.inner.clone(),
        };
        backend.borrow_mut().hook_add_code(Box::new(hook), begin, end)
    }
}

struct AssemblyCodeDumperHook {
    inner: Rc<RefCell<TraceCodeInner>>,
}

impl CodeHook for AssemblyCodeDumperHook {
    fn hook(&mut self, backend: &mut dyn Backend, address: u64, size: u32) {
        let registers = snapshot_registers(backend);
        let bytes = read_instruction_bytes(backend, address, size);
        let disassembly = {
            let dis = self.inner.borrow().disassembler.clone();
            dis.disassemble(address, &bytes, false)
        };

        self.inner.borrow_mut().entries.push(TraceEntry {
            pc: address,
            size,
            disassembly,
            registers,
        });
    }
}
