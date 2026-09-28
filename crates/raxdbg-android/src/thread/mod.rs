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

use std::rc::Rc;

use raxdbg_core::backend::{Backend, RunError};
use raxdbg_core::memory::MemoryError;
use raxdbg_core::svc::{Svc, SvcKind, SvcMemory};
use raxdbg_core::thread::ThreadDispatcher;

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
    exit_stub: u64,
    number: i32,
    svc: Rc<SvcMemory>,
    next_index: std::cell::Cell<usize>,
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
            exit_stub,
            number,
            svc,
            next_index: std::cell::Cell::new(0),
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

    /// A dispatcher whose tasks return through this runtime's exit stub.
    pub fn dispatcher(&self, emulator: &Rc<AndroidEmulator>) -> ThreadDispatcher {
        ThreadDispatcher::new(self.exit_stub, emulator.is_64bit())
    }

    /// A stack for a new task, from the loader's thread-stack area.
    ///
    /// Port of unidbg: `AbstractLoader.allocateThreadIndex` +
    /// `allocateThreadStack`, which reserve an index and hand back the stack
    /// that goes with it.
    pub fn allocate_stack(&self, emulator: &Rc<AndroidEmulator>) -> Result<u64, MemoryError> {
        let index = emulator.memory().allocate_thread_index_impl()?;
        self.next_index.set(index + 1);
        let stack = emulator.memory().allocate_thread_stack_impl(index)?;
        // The thread-stack pointer is the *top* of the thread's area, and the
        // ABI wants it 16-byte aligned at a call boundary.
        let sp = stack.peer() & !0xf;
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
