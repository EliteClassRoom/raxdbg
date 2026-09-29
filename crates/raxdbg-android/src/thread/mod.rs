//! The Android side of guest threads: the exit stub and the thread stacks.
//!
//! Port of unidbg: `unidbg-android/src/main/java/com/github/unidbg/linux/thread/ThreadTask.java`
//! and `unidbg-android/src/main/java/com/github/unidbg/linux/android/AndroidEmulator.java`'s
//! thread-stack allocation@7f5da98e.
//!
//! [`ThreadDispatcher`] owns the scheduling; this is what it needs from the
//! emulator. A task's `lr` is the *exit stub*, an SVC stub whose handler returns
//! [`raxdbg_core::backend::RunError::PopContext`], so a thread function that
//! simply returns retires its task; and a task's stack comes from the loader's
//! thread-stack area, which is what keeps `pthread_internal_t` and the TLS block
//! on the thread's own memory.

use std::cell::RefCell;
use std::rc::Rc;

use raxdbg_core::backend::{Backend, RunError};
use raxdbg_core::memory::{Memory, MemoryError};
use raxdbg_core::memory::loader::Loader;
use raxdbg_core::svc::{Svc, SvcKind, SvcMemory};
use raxdbg_core::thread::ThreadDispatcher;

pub mod join;

pub use join::{PendingThread, ThreadJoin, ThreadJoinVisitor, ThreadStart};

use crate::emulator::AndroidEmulator;

/// The exit stub: what a thread function returns to.
#[derive(Debug)]
struct ThreadExitStub {
    kind: SvcKind,
}

impl Svc for ThreadExitStub {
    fn handle(&mut self, _backend: &mut dyn Backend) -> Result<i64, RunError> {
        // unidbg's `ThreadExit` path: the thread is done, so the dispatcher
        // retires the task and picks the next one.
        Err(RunError::PopContext)
    }

    fn kind(&self) -> SvcKind {
        self.kind
    }

    fn name(&self) -> &str {
        "ThreadExit"
    }
}

/// The exit stub's address and the loader's thread-stack allocator.
#[derive(Debug)]
pub struct ThreadRuntime {
    allocated: RefCell<Vec<(usize, Rc<Loader>)>>,
    is_64bit: bool,
    exit_stub: u64,
    number: i32,
    svc: Rc<SvcMemory>,
    /// The syscall handler's futex registry.
    ///
    /// The dispatcher needs the *same* registry the handler parks threads in: a
    /// `FUTEX_WAIT` registers a waiter there and asks for a switch, and the
    /// dispatcher claims that waiter to park the task. A dispatcher without it
    /// would re-run the parked task's `svc` forever instead of blocking it, so
    /// [`ThreadRuntime::dispatcher`] wires it in rather than leaving it to the
    /// caller.
    waiters: Rc<raxdbg_core::thread::Waiters>,
}

impl ThreadRuntime {
    /// Installs the exit stub in the emulator's SVC page.
    pub fn install(emulator: &Rc<AndroidEmulator>) -> Result<ThreadRuntime, MemoryError> {
        let svc = emulator
            .loader()
            .svc_memory()
            .expect("the emulator builds an SVC page during boot");
        let kind = if emulator.is_64bit() {
            SvcKind::Arm64
        } else {
            SvcKind::Arm
        };
        let (exit_stub, number) = svc.register_svc_numbered(
            emulator.memory().as_ref(),
            Box::new(ThreadExitStub { kind }),
        )?;
        Ok(ThreadRuntime {
            allocated: RefCell::new(Vec::new()),
            is_64bit: emulator.is_64bit(),
            exit_stub,
            number,
            svc,
            waiters: emulator.syscall().borrow().unix_handler().waiters().clone(),
        })
    }

    /// The address a task's `lr` must hold.
    pub fn exit_stub(&self) -> u64 {
        self.exit_stub
    }

    /// The SVC number the exit stub uses.
    pub fn exit_number(&self) -> i32 {
        self.number
    }

    /// Releases every stack this runtime handed out.
    ///
    /// The loader caps threads at `MAX_THREADS`, and a host-driven call that
    /// parks and resumes allocates a stack per attempt, so they have to go back
    /// or the sixteenth join is the last one that works.
    pub fn free_all_stacks(&self) {
        let taken = std::mem::take(&mut *self.allocated.borrow_mut());
        for (index, memory) in taken {
            memory.free_thread_index_impl(index);
        }
    }

    /// The thread-stack indices this runtime has taken out.
    pub fn allocated_indices(&self) -> Vec<usize> {
        self.allocated.borrow().iter().map(|(index, _)| *index).collect()
    }

    /// The guest's pointer size, which is how far apart the entry code's two
    /// operands sit on a thread's stack.
    pub fn word_size(&self) -> u64 {
        if self.is_64bit {
            8
        } else {
            4
        }
    }

    /// A dispatcher whose tasks return through this runtime's exit stub, with
    /// the futex registry already installed.
    pub fn dispatcher(&self, emulator: &Rc<AndroidEmulator>) -> ThreadDispatcher {
        let mut dispatcher = ThreadDispatcher::new(self.exit_stub, emulator.is_64bit());
        dispatcher.set_waiters(Rc::clone(&self.waiters));
        dispatcher
    }

    /// The futex registry the dispatcher and the syscall handler share.
    pub fn waiters(&self) -> &Rc<raxdbg_core::thread::Waiters> {
        &self.waiters
    }

    /// A thread's `pthread_internal_t`, on the thread's own stack.
    ///
    /// Port of unidbg: `AndroidElfLoader.initializeTLS` builds one for the main
    /// thread (`allocateStack(0x400)`, `next` and `prev` null, `tid` the pid).
    /// A created thread needs the same thing, or bionic's own bookkeeping --
    /// `__gettid`, the TLS destructor list, `pthread_getattr_np` -- has nothing
    /// to read. The struct is three words: `next`, `prev` and `tid`.
    ///
    /// The block is *linked into* the running thread's rather than standing
    /// alone. bionic's `pthread_getattr_np` walks the list from the calling
    /// thread's TLS looking for the calling thread's own entry, and a list where
    /// every node is unreachable from the head makes that walk run forever -- a
    /// loop a hook engine's own size calculation falls into, because Dobby asks
    /// for a function's extent. So the new node goes after the head, with the
    /// head's `next` pointing at it and its `prev` pointing back.
    pub fn pthread_internal(
        &self,
        emulator: &Rc<AndroidEmulator>,
        tid: u64,
    ) -> Result<(u64, u64), MemoryError> {
        let memory = emulator.memory();
        let word = self.word_size();
        let block = memory.allocate_stack(0x400)?.peer();
        let pointer = memory.pointer(block);
        // The head is the running thread's own block, read out of its TLS.
        let head = {
            let register = if emulator.is_64bit() {
                raxdbg_core::reg::RegId::X(18)
            } else {
                raxdbg_core::reg::RegId::C13C0_3
            };
            emulator
                .backend()
                .borrow()
                .reg_read(register)
                .unwrap_or(block)
        };
        // A fresh node links after the head: `next` is whatever followed it,
        // `prev` is the head, and the head's `next` is this node.
        let following = memory.pointer(head).read_pointer(0).unwrap_or(0);
        pointer.write_pointer(0, following)?;
        pointer.write_pointer(word, head)?;
        memory
            .pointer(block + word * 2)
            .write_u32(0, tid as u32)?;
        memory.pointer(head).write_pointer(0, block)?;
        if following != 0 {
            memory.pointer(following).write_pointer(word, block)?;
        }
        Ok((block, block + word * 2))
    }

    /// A stack for a new task, from the loader's thread-stack area.
    ///
    /// Port of unidbg: `AbstractLoader.allocateThreadIndex` +
    /// `allocateThreadStack`, which reserve an index and hand back the stack
    /// that goes with it.
    pub fn allocate_stack(&self, emulator: &Rc<AndroidEmulator>) -> Result<u64, MemoryError> {
        let index = emulator.memory().allocate_thread_index_impl()?;
        let stack = emulator.memory().allocate_thread_stack_impl(index)?;
        // The thread-stack pointer is the *top* of the thread's area, and the
        // ABI wants it 16-byte aligned at a call boundary.
        let sp = stack.peer() & !0xf;
        self.allocated
            .borrow_mut()
            .push((index, emulator.memory().clone()));
        Ok(sp)
    }

    /// Releases the runtime's stub.
    pub fn uninstall(&self) {
        self.svc.take_svc(self.number);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_exit_stub_is_installed_in_the_svc_page() {
        let emulator = crate::emulator::AndroidEmulatorBuilder::for_64bit()
            .process_name("raxdbg-thread-unit")
            .build()
            .expect("emulator");
        let runtime = ThreadRuntime::install(&emulator).expect("install");
        let svc = emulator.loader().svc_memory().expect("svc page");
        assert_ne!(runtime.exit_stub(), 0);
        assert!(
            runtime.exit_stub() >= svc.base() && runtime.exit_stub() < svc.base() + svc.size(),
            "the stub is inside the SVC page"
        );
        assert!(svc.take_svc(runtime.exit_number()).is_some());
        runtime.uninstall();
    }
}
