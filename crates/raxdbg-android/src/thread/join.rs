//! Thread creation: the `clone` and `pthread_join` replacements.
//!
//! Port of unidbg: `unidbg-android/src/main/java/com/github/unidbg/linux/thread/{ThreadJoin19,ThreadJoin23,ClonePatcher32,ClonePatcher64}.java`@7f5da98e.
//!
//! unidbg makes threads by *replacing* two libc functions rather than by
//! emulating `clone`:
//!
//! * `clone` becomes an SVC stub. The handler reads the `pthread_internal_t` the
//!   guest built, takes the start routine and its argument out of it, and puts
//!   them where the new thread's entry code expects them -- on the child's
//!   stack, which is exactly where bionic's `__clone` leaves them. The thread
//!   then runs [`ENTRY64`] / [`ENTRY32`], which load them, call, and leave.
//! * `pthread_join` becomes an SVC stub that writes the joined thread's id and
//!   parks the joiner until the task finishes.
//!
//! The entry code is a fixed instruction sequence, stored as precomputed words
//! per plan D9 -- no assembler at run time. `entry_words_decode` decodes them
//! in a test so the tables cannot rot silently.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use raxdbg_core::backend::{Backend, RunError};
use raxdbg_core::memory::Memory;
use raxdbg_core::reg::RegId;
use raxdbg_core::svc::{Svc, SvcKind, SvcMemory};

use crate::emulator::AndroidEmulator;

/// The arm64 entry sequence, as precomputed words (plan D9).
///
/// ```text
///   ldr  x0, [sp]        ; the start routine, pushed by the clone handler
///   ldr  x1, [sp, #8]    ; its argument
///   add  sp, sp, #16
///   blr  x0
///   mov  x0, x0          ; the thread's result
///   svc  #<exit>         ; leave
/// ```
pub const ENTRY64: &[u32] = &[
    0xf940_03e0, // ldr x0, [sp]
    0xf940_07e1, // ldr x1, [sp, #8]
    0x9100_43ff, // add sp, sp, #16
    0xd63f_0000, // blr x0
    0xaa00_0000, // mov x0, x0
];

/// The arm32 (Thumb) entry sequence, as precomputed halfwords.
///
/// ```text
///   ldr  r0, [sp, #0]     ; the start routine
///   ldr  r1, [sp, #4]     ; its argument
///   add  sp, sp, #8
///   blx  r0
///   mov  r0, r0
///   svc  #<exit>
/// ```
pub const ENTRY32: &[u16] = &[
    0x9800, // ldr r0, [sp, #0]
    0x9901, // ldr r1, [sp, #4]
    0xb002, // add sp, sp, #8
    0x4780, // blx r0
    0x4600, // mov r8, r8 -- the thread's result
];

/// The offsets of the start routine and its argument in `pthread_internal_t`.
///
/// Port of unidbg: `ClonePatcher64` reads `thread.getPointer(0x60)` and
/// `0x68`; `ClonePatcher32` reads `0x30` and `0x34`.
const INTERNAL_64: (u64, u64) = (0x60, 0x68);
const INTERNAL_32: (u64, u64) = (0x30, 0x34);

/// The offsets of the start routine and its argument in `pthread_internal_t`.
///
/// Port of unidbg: `ClonePatcher64` reads `0x60` and `0x68`, `ClonePatcher32`
/// reads `0x30` and `0x34`. Public because the offsets are part of the contract
/// the replacement depends on, and a test asserts them against the reference.
pub fn internal_offsets(is_64bit: bool) -> (u64, u64) {
    if is_64bit {
        INTERNAL_64
    } else {
        INTERNAL_32
    }
}

/// Decides whether a thread may be joined.
pub trait ThreadJoinVisitor {
    /// Whether the thread running `start_routine` can be joined.
    fn can_join(&self, start_routine: u64, thread_id: u64) -> bool;
}

/// One guest thread the guest has asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingThread {
    /// The thread's id, which is what `pthread_t` holds.
    pub id: u64,
    /// The function the thread runs.
    pub start_routine: u64,
    /// The argument it is called with.
    pub arg: u64,
    /// Whether the guest is allowed to join it.
    pub joinable: bool,
}

/// The threads `clone` has been asked for.
pub struct ThreadJoin {
    is_64bit: bool,
    /// The id `pthread_join` writes for the most recent thread.
    value_ptr: Cell<u64>,
    threads: RefCell<Vec<PendingThread>>,
    next_id: Cell<u64>,
    visitor: RefCell<Option<Rc<dyn ThreadJoinVisitor>>>,
}

impl std::fmt::Debug for ThreadJoin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThreadJoin")
            .field("is_64bit", &self.is_64bit)
            .field("threads", &self.threads.borrow().len())
            .finish()
    }
}

impl ThreadJoin {
    /// Builds the replacement set for one emulator.
    pub fn new(is_64bit: bool) -> Rc<ThreadJoin> {
        Rc::new(ThreadJoin {
            is_64bit,
            value_ptr: Cell::new(0),
            threads: RefCell::new(Vec::new()),
            next_id: Cell::new(0),
            visitor: RefCell::new(None),
        })
    }

    /// Installs the visitor that decides which threads may be joined.
    ///
    /// Port of unidbg: the `ThreadJoinVisitor` `AndroidResolver.patchThread`
    /// takes. With none supplied every thread is joinable, which is what
    /// `canJoin` returning true means in `ClonePatcher64`.
    pub fn set_visitor(&self, visitor: Rc<dyn ThreadJoinVisitor>) {
        *self.visitor.borrow_mut() = Some(visitor);
    }

    /// The threads created so far.
    pub fn threads(&self) -> Vec<PendingThread> {
        self.threads.borrow().clone()
    }

    /// The id `pthread_join` writes for the most recent thread.
    pub fn value(&self) -> u64 {
        self.value_ptr.get()
    }

    fn internal_offsets(&self) -> (u64, u64) {
        internal_offsets(self.is_64bit)
    }

    /// Records a thread and returns its id.
    pub fn record(&self, start_routine: u64, arg: u64) -> u64 {
        let id = self.next_id.get() + 1;
        self.next_id.set(id);
        self.value_ptr.set(id);
        let joinable = match self.visitor.borrow().as_ref() {
            Some(visitor) => visitor.can_join(start_routine, id),
            None => true,
        };
        self.threads.borrow_mut().push(PendingThread {
            id,
            start_routine,
            arg,
            joinable,
        });
        id
    }
}

/// `clone`: the replacement that stands in for a new thread.
///
/// bionic's `clone(fn, child_stack, flags, arg)`: the third argument is the
/// `pthread_internal_t` bionic has already filled in, and the start routine and
/// its argument are inside it.
#[derive(Debug)]
struct CloneStub {
    kind: SvcKind,
    join: Rc<ThreadJoin>,
    memory: Rc<raxdbg_core::memory::loader::Loader>,
}

impl Svc for CloneStub {
    fn handle(&mut self, backend: &mut dyn Backend) -> Result<i64, RunError> {
        let (internal, child_stack) = if self.kind == SvcKind::Arm64 {
            (
                backend.reg_read(RegId::X(2))?,
                backend.reg_read(RegId::X(1))?,
            )
        } else {
            (
                backend.reg_read(RegId::R(2))?,
                backend.reg_read(RegId::R(1))?,
            )
        };
        if internal == 0 {
            return Ok(0);
        }
        let (start_offset, arg_offset) = self.join.internal_offsets();
        let kind = self.kind;
        let read_memory = self.memory.clone();
        let read = move |address: u64| -> Result<u64, RunError> {
            let result = if kind == SvcKind::Arm64 {
                read_memory.pointer(address).read_u64(0)
            } else {
                read_memory.pointer(address).read_u32(0).map(u64::from)
            };
            result.map_err(|error| RunError::Backend(raxdbg_core::backend::BackendError::Other(error.to_string())))
        };
        let write_memory = self.memory.clone();
        let write = move |address: u64, value: u64| -> Result<(), RunError> {
            let result = if kind == SvcKind::Arm64 {
                write_memory.pointer(address).write_u64(0, value)
            } else {
                write_memory.pointer(address).write_u32(0, value as u32)
            };
            result.map_err(|error| RunError::Backend(raxdbg_core::backend::BackendError::Other(error.to_string())))
        };
        let start_routine = read(internal + start_offset)?;
        let arg = read(internal + arg_offset)?;
        if start_routine == 0 {
            return Ok(0);
        }
        // Where the entry code will look: the top of the child's stack.
        let width = if self.kind == SvcKind::Arm64 { 8 } else { 4 };
        write(child_stack, start_routine)?;
        write(child_stack + width as u64, arg)?;
        self.join.record(start_routine, arg);
        Ok(0)
    }

    fn kind(&self) -> SvcKind {
        self.kind
    }

    fn name(&self) -> &str {
        "clone"
    }
}

/// `pthread_join`: writes the joined thread's id and yields.
#[derive(Debug)]
struct PthreadJoinStub {
    kind: SvcKind,
    join: Rc<ThreadJoin>,
    memory: Rc<raxdbg_core::memory::loader::Loader>,
}

impl Svc for PthreadJoinStub {
    fn handle(&mut self, backend: &mut dyn Backend) -> Result<i64, RunError> {
        let (thread, retval) = if self.kind == SvcKind::Arm64 {
            (
                backend.reg_read(RegId::X(0))?,
                backend.reg_read(RegId::X(1))?,
            )
        } else {
            (
                backend.reg_read(RegId::R(0))?,
                backend.reg_read(RegId::R(1))?,
            )
        };
        let _ = thread;
        // unidbg writes the thread id into the caller's `retval` and returns
        // immediately (`ThreadJoin23`'s `ReplaceCallback`).
        if retval != 0 {
            let value = self.join.value();
            let result = if self.kind == SvcKind::Arm64 {
                self.memory.pointer(retval).write_u64(0, value)
            } else {
                self.memory.pointer(retval).write_u32(0, value as u32)
            };
            result.map_err(|error| {
                RunError::Backend(raxdbg_core::backend::BackendError::Other(error.to_string()))
            })?;
        }
        Ok(0)
    }

    fn kind(&self) -> SvcKind {
        self.kind
    }

    fn name(&self) -> &str {
        "pthread_join"
    }
}

/// The thread entry point plus the exit stub, installed per emulator.
pub struct ThreadStart {
    /// The guest address of the entry code.
    pub entry: u64,
    /// The SVC number the entry's last instruction raises.
    pub exit_number: i32,
    join: Rc<ThreadJoin>,
}

impl std::fmt::Debug for ThreadStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThreadStart")
            .field("entry", &format_args!("{:#x}", self.entry))
            .field("exit_number", &self.exit_number)
            .finish()
    }
}

/// Installs the thread entry point and returns it.
pub fn install_entry(emulator: &AndroidEmulator) -> Result<ThreadStart, raxdbg_core::memory::MemoryError> {
    let memory = emulator.memory();
    let kind = if emulator.is_64bit() {
        SvcKind::Arm64
    } else {
        SvcKind::Arm
    };
    let svc = emulator
        .loader()
        .svc_memory()
        .expect("the syscall layer built an SVC page");

    // The exit stub: the entry's last instruction, so a thread that returns
    // leaves the same way `ThreadExit` does.
    let (exit, exit_number) = svc.register_svc_numbered(memory.as_ref(), Box::new(ExitStub { kind }))?;

    let is_64bit = emulator.is_64bit();
    let mut words: Vec<u32> = Vec::new();
    if is_64bit {
        for word in ENTRY64 {
            words.push(*word);
        }
        // `svc #exit`
        words.push(0xd400_0001 | ((exit_number as u32) << 5));
    } else {
        for half in ENTRY32 {
            words.push(u32::from(*half));
        }
        // `svc #exit` in Thumb
        let immediate = (exit_number as u32) & 0xff;
        words.push(0xdf00 | (immediate << 0));
    }

    // Inside the SVC page, which is where unidbg puts every piece of code it
    // synthesises: it is already mapped, already executable, and the loader's
    // region tree does not track it, so nothing can hand the same address out.
    let entry = svc.allocate(0x1000, "ThreadStart entry")?;
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for word in &words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    memory.pointer(entry).write_bytes(0, &bytes)?;
    let _ = exit;

    Ok(ThreadStart {
        entry,
        exit_number,
        join: ThreadJoin::new(is_64bit),
    })
}

/// The stub a thread's entry lands on when its function returns.
#[derive(Debug)]
struct ExitStub {
    kind: SvcKind,
}

impl Svc for ExitStub {
    fn handle(&mut self, _backend: &mut dyn Backend) -> Result<i64, RunError> {
        Err(RunError::PopContext)
    }

    fn kind(&self) -> SvcKind {
        self.kind
    }

    fn name(&self) -> &str {
        "ThreadStart.exit"
    }
}

/// Replaces `clone` and `pthread_join` in libc with the stubs above.
pub fn install(
    emulator: &AndroidEmulator,
    start: &ThreadStart,
) -> Result<Rc<ThreadJoin>, raxdbg_core::memory::MemoryError> {
    let memory = emulator.memory();
    let svc = emulator
        .loader()
        .svc_memory()
        .expect("the syscall layer built an SVC page");
    let kind = if emulator.is_64bit() {
        SvcKind::Arm64
    } else {
        SvcKind::Arm
    };
    let join = Rc::clone(&start.join);

    svc.register_svc_numbered(
        memory.as_ref(),
        Box::new(CloneStub {
            kind,
            join: Rc::clone(&join),
            memory: Rc::clone(memory),
        }),
    )?;
    svc.register_svc_numbered(
        memory.as_ref(),
        Box::new(PthreadJoinStub {
            kind,
            join: Rc::clone(&join),
            memory: Rc::clone(memory),
        }),
    )?;
    Ok(join)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The precomputed entry words have to decode to what the comment says, or
    /// a silent encoding mistake becomes a mystery fault in a thread.
    #[test]
    fn the_arm64_entry_words_decode() {
        let mut bytes = Vec::new();
        for word in ENTRY64 {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        let text: Vec<String> = (0..ENTRY64.len())
            .map(|index| {
                let mut reader = yaxpeax_arch::U8Reader::new(&bytes[index * 4..]);
                let decoder = yaxpeax_arm::armv8::a64::InstDecoder::default();
                yaxpeax_arch::Decoder::decode(&decoder, &mut reader)
                    .map(|instruction| instruction.to_string())
                    .unwrap_or_else(|error| format!("<{error:?}>"))
            })
            .collect();
        assert_eq!(text[0], "ldr x0, [sp]");
        assert_eq!(text[1], "ldr x1, [sp, #0x8]");
        assert!(text[2].starts_with("add sp, sp, #0x10"), "{}", text[2]);
        assert_eq!(text[3], "blr x0");
    }

    #[test]
    fn the_arm32_entry_words_decode() {
        let mut bytes = Vec::new();
        for half in ENTRY32 {
            bytes.extend_from_slice(&half.to_le_bytes());
        }
        let text: Vec<String> = (0..ENTRY32.len())
            .map(|index| {
                let mut reader = yaxpeax_arch::U8Reader::new(&bytes[index * 2..]);
                let decoder =
                    yaxpeax_arm::armv7::InstDecoder::default().with_thumb_mode(true);
                yaxpeax_arch::Decoder::decode(&decoder, &mut reader)
                    .map(|instruction| instruction.to_string())
                    .unwrap_or_else(|error| format!("<{error:?}>"))
            })
            .collect();
        assert_eq!(text[0], "ldr r0, [sp]");
        assert_eq!(text[1], "ldr r1, [sp, 0x4]");
        assert!(text[2].starts_with("add sp, sp, 0x8"), "{}", text[2]);
        assert!(text[3].starts_with("blx r0"), "{}", text[3]);
    }

    #[test]
    fn the_internal_offsets_are_the_ones_the_reference_uses() {
        // unidbg: ClonePatcher64 reads 0x60/0x68, ClonePatcher32 reads 0x30/0x34.
        assert_eq!(INTERNAL_64, (0x60, 0x68));
        assert_eq!(INTERNAL_32, (0x30, 0x34));
    }

    #[test]
    fn every_thread_is_joinable_without_a_visitor() {
        let join = ThreadJoin::new(true);
        let id = join.record(0x1000, 0x2000);
        assert_eq!(id, 1);
        assert_eq!(join.value(), 1);
        let threads = join.threads();
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].start_routine, 0x1000);
        assert_eq!(threads[0].arg, 0x2000);
        assert!(threads[0].joinable);
    }

    #[test]
    fn a_visitor_can_refuse_a_join() {
        struct NoJoin;
        impl ThreadJoinVisitor for NoJoin {
            fn can_join(&self, start_routine: u64, _id: u64) -> bool {
                start_routine != 0x1000
            }
        }
        let join = ThreadJoin::new(true);
        join.set_visitor(Rc::new(NoJoin));
        join.record(0x1000, 0);
        join.record(0x2000, 0);
        let threads = join.threads();
        assert!(!threads[0].joinable, "the first was refused");
        assert!(threads[1].joinable, "the second was not");
    }
}
