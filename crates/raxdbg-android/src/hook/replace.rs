//! Replacing a guest function with a host callback.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/hook/{BaseHook,HookCallback,ReplaceCallback,InvocationContext}.java`
//! and `unidbg-api/src/main/java/com/github/unidbg/arm/{Arm64Hook,ArmHook}.java`
//! @7f5da98e.
//!
//! unidbg's `Dobby`/`HookZz`/`xHook` patch the *code* of the target, which needs
//! an in-guest engine. This module is the engine-independent half those three
//! share: the callback contract, the argument/return view, and the trampolines.
//! A replacement is a code hook on the target's entry that moves the PC to an
//! SVC stub, so the guest reaches the stub instead of the original and the
//! stub's trailing `ret` returns to the caller — no code patching, and it works
//! for any target in any module.
//!
//! With `enable_post_call` the handler links the original call to a second stub
//! before running it, so `post_call` observes the original's result and decides
//! what the caller finally sees.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use raxdbg_core::backend::{Backend, CodeHook, HookId, RunError};
use raxdbg_core::memory::MemoryError;
use raxdbg_core::reg::RegId;
use raxdbg_core::svc::{Svc, SvcKind, SvcMemory};

use crate::emulator::AndroidEmulator;

/// Why a replacement could not be installed.
#[derive(Debug, thiserror::Error)]
pub enum HookError {
    /// The SVC stub could not be allocated.
    #[error(transparent)]
    Memory(#[from] MemoryError),
    /// The target address is not in a loaded module.
    #[error("{address:#x} is not inside a loaded module")]
    NotInModule {
        /// The target address.
        address: u64,
    },
    /// The emulator has no SVC page.
    #[error("the emulator has no SVC page; the syscall layer builds one")]
    NoSvcPage,
}

/// What a hook callback may inspect and change.
///
/// Port of unidbg: `InvocationContext` and the `Arm64HookContext`/`Arm32HookContext`
/// implementations, which capture the argument registers when the hook fires.
pub struct InvocationContext {
    /// The argument values, as they were on entry (`x1..` on arm64, `r1..` on
    /// arm32; index 0 is the first argument).
    args: Vec<u64>,
    /// The value the caller will see in `x0`/`r0`.
    ret: i64,
    /// Whether the callback asked to skip the original.
    skip_original: bool,
    /// The address the hook fired at.
    address: u64,
    /// The stack pointer at entry.
    sp: u64,
    /// The return address at entry.
    lr: u64,
    /// Whether the guest is 64-bit.
    is_64bit: bool,
}

impl InvocationContext {
    /// The address the hooked function was entered at.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// The stack pointer when the hook fired.
    pub fn sp(&self) -> u64 {
        self.sp
    }

    /// The link register when the hook fired: the caller's return address.
    pub fn lr(&self) -> u64 {
        self.lr
    }

    /// Whether the guest is 64-bit.
    pub fn is_64bit(&self) -> bool {
        self.is_64bit
    }

    /// The `index`th argument as an integer.
    pub fn get_int_arg(&self, index: usize) -> i32 {
        self.args.get(index).copied().unwrap_or(0) as i32
    }

    /// The `index`th argument as a long.
    pub fn get_long_arg(&self, index: usize) -> i64 {
        self.args.get(index).copied().unwrap_or(0) as i64
    }

    /// The `index`th argument as a guest pointer.
    pub fn get_pointer_arg(&self, index: usize) -> u64 {
        self.args.get(index).copied().unwrap_or(0)
    }

    /// The `index`th argument as a boolean.
    pub fn get_bool_arg(&self, index: usize) -> bool {
        self.get_int_arg(index) != 0
    }

    /// Replaces the `index`th argument, which the original then sees.
    pub fn set_int_arg(&mut self, index: usize, value: i32) {
        self.set_arg(index, value as u64);
    }

    /// Replaces the `index`th argument, which the original then sees.
    pub fn set_arg(&mut self, index: usize, value: u64) {
        if index < self.args.len() {
            self.args[index] = value;
        }
    }

    /// The value the caller will see.
    pub fn get_ret(&self) -> i64 {
        self.ret
    }

    /// Sets the value the caller will see.
    pub fn set_ret(&mut self, value: i64) {
        self.ret = value;
    }

    /// Skips the original: only the callback's return value reaches the caller.
    pub fn skip_original(&mut self) {
        self.skip_original = true;
    }

    /// Whether the original was skipped.
    pub fn is_original_skipped(&self) -> bool {
        self.skip_original
    }

    /// Every argument, for a callback that forwards them.
    pub fn args(&self) -> &[u64] {
        &self.args
    }
}

/// The host side of a replacement.
pub struct ReplaceCallback {
    /// Runs instead of the original. Its return value is the caller's, unless
    /// [`InvocationContext::skip_original`] was called from `post_call`'s
    /// absence.
    pub on_call: Box<dyn FnMut(&mut InvocationContext) -> i64>,
    /// Runs after the original returned, with the original's result in
    /// [`InvocationContext::get_ret`]. `Some` enables the post-call path.
    pub post_call: Option<Box<dyn FnMut(&mut InvocationContext)>>,
}

impl std::fmt::Debug for ReplaceCallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplaceCallback")
            .field("post_call", &self.post_call.is_some())
            .finish()
    }
}

/// A replacement registered on a guest address.
pub struct ReplaceHook {
    target: u64,
    stub: u64,
    post_stub: u64,
    hook_id: HookId,
    state: Rc<RefCell<HookState>>,
    svc: Rc<SvcMemory>,
    numbers: (i32, i32),
}

struct HookState {
    callback: RefCell<ReplaceCallback>,
    context: RefCell<InvocationContext>,
    /// Set while the original is running on the post-call path.
    in_original: Cell<bool>,
    /// The arguments the original was entered with.
    entry_args: RefCell<Vec<u64>>,
    /// The post stub's address, which the entry stub links the original to.
    post: Cell<u64>,
}

impl std::fmt::Debug for ReplaceHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplaceHook")
            .field("target", &format_args!("{:#x}", self.target))
            .field("stub", &format_args!("{:#x}", self.stub))
            .finish()
    }
}

impl ReplaceHook {
    /// Replaces the function at `address` with `callback`.
    ///
    /// Port of unidbg: `BaseHook.replace` plus `Arm64Hook`/`ArmHook`, minus the
    /// code patch a hook engine would do.
    pub fn replace(
        emulator: &Rc<AndroidEmulator>,
        address: u64,
        callback: ReplaceCallback,
    ) -> Result<Self, HookError> {
        let svc = emulator
            .loader()
            .svc_memory()
            .ok_or(HookError::NoSvcPage)?;
        if emulator.loader().find_module_by_address(address).is_none() {
            return Err(HookError::NotInModule { address });
        }
        let kind = if emulator.is_64bit() {
            SvcKind::Arm64
        } else {
            SvcKind::Arm
        };
        let state = Rc::new(RefCell::new(HookState {
            callback: RefCell::new(callback),
            context: RefCell::new(InvocationContext {
                args: Vec::new(),
                ret: 0,
                skip_original: false,
                address,
                sp: 0,
                lr: 0,
                is_64bit: emulator.is_64bit(),
            }),
            in_original: Cell::new(false),
            entry_args: RefCell::new(Vec::new()),
            post: Cell::new(0),
        }));

        // The stub the target's entry is redirected to.
        let entry_state = Rc::clone(&state);
        let entry_stub = svc.register_svc_numbered(
            emulator.memory().as_ref(),
            Box::new(EntryStub {
                kind,
                state: entry_state,
            }),
        )?;
        let post_state = Rc::clone(&state);
        let post_stub = svc.register_svc_numbered(
            emulator.memory().as_ref(),
            Box::new(PostStub {
                kind,
                state: post_state,
            }),
        )?;

        let hook_id = {
            let mut backend = emulator.backend().borrow_mut();
            backend.hook_add_code(
                Box::new(Redirect {
                    stub: entry_stub.0,
                    is_64bit: emulator.is_64bit(),
                    state: Rc::clone(&state),
                }),
                address,
                address,
            )
        };

        state.borrow().post.set(post_stub.0);
        Ok(ReplaceHook {
            target: address,
            stub: entry_stub.0,
            post_stub: post_stub.0,
            hook_id,
            state,
            svc: Rc::clone(&svc),
            numbers: (entry_stub.1, post_stub.1),
        })
    }

    /// The address that was replaced.
    pub fn address(&self) -> u64 {
        self.target
    }

    /// The SVC stub the target's entry now reaches.
    pub fn stub(&self) -> u64 {
        self.stub
    }

    /// The stub the original returns to when `post_call` is enabled.
    pub fn post_stub(&self) -> u64 {
        self.post_stub
    }

    /// How many times the callback ran.
    pub fn invocation_count(&self) -> usize {
        self.state.borrow().context.borrow().args.len()
    }

    /// Removes the replacement.
    pub fn uninstall(&self, emulator: &Rc<AndroidEmulator>) {
        emulator.backend().borrow_mut().hook_del(self.hook_id);
        self.svc.take_svc(self.numbers.0);
        self.svc.take_svc(self.numbers.1);
    }
}

/// The code hook that diverts the target's entry to the stub.
struct Redirect {
    stub: u64,
    is_64bit: bool,
    state: Rc<RefCell<HookState>>,
}

impl CodeHook for Redirect {
    fn hook(&mut self, backend: &mut dyn Backend, address: u64, _size: u32) {
        if self.state.borrow().in_original.get() {
            // The original is running; its own entry hook must not fire again.
            return;
        }
        // Capture the arguments and the caller's return address, then jump to
        // the stub. The stub's `ret` returns straight to the caller.
        let pointer_size = if self.is_64bit { 8 } else { 4 };
        let mut args = Vec::with_capacity(7);
        for index in 1..8u64 {
            let register = if self.is_64bit {
                RegId::X(index as u8)
            } else {
                RegId::R(index as u8)
            };
            if let Ok(value) = backend.reg_read(register) {
                args.push(value);
            }
        }
        let sp = backend.reg_read(RegId::Sp).unwrap_or(0);
        let lr = backend.reg_read(RegId::Lr).unwrap_or(0);
        {
            let mut state = self.state.borrow_mut();
            let mut context = state.context.borrow_mut();
            context.args = args.clone();
            context.ret = 0;
            context.skip_original = false;
            context.address = address;
            context.sp = sp;
            context.lr = lr;
            *state.entry_args.borrow_mut() = args;
        }
        let _ = pointer_size;
        let _ = backend.reg_write(RegId::Pc, self.stub);
    }
}

/// The stub the target's entry reaches.
struct EntryStub {
    kind: SvcKind,
    state: Rc<RefCell<HookState>>,
}

impl Svc for EntryStub {
    fn handle(&mut self, backend: &mut dyn Backend) -> Result<i64, RunError> {
        let state = self.state.borrow();
        let mut callback = state.callback.borrow_mut();
        let has_post = callback.post_call.is_some();
        let result = {
            let mut context = state.context.borrow_mut();
            let result = (callback.on_call)(&mut context);
            if context.skip_original || !has_post {
                context.set_ret(result);
                Some(result)
            } else {
                None
            }
        };
        drop(callback);

        match result {
            Some(value) => {
                write_return(backend, state.context.borrow().is_64bit, value)?;
                Ok(value)
            }
            None => {
                // Run the original with the post stub as its return address.
                // The stub's own `ret` never executes: the original's does, and
                // it lands in the post stub, whose `ret` returns to the caller.
                let args = state.entry_args.borrow().clone();
                let is_64bit = state.context.borrow().is_64bit;
                let original = state.context.borrow().address;
                let post = state.post.get();
                state.in_original.set(true);
                for (index, value) in args.iter().enumerate() {
                    let register = if is_64bit {
                        RegId::X((index + 1) as u8)
                    } else {
                        RegId::R((index + 1) as u8)
                    };
                    let _ = backend.reg_write(register, *value);
                }
                backend.reg_write(RegId::Lr, post)?;
                backend.reg_write(RegId::Pc, original)?;
                Ok(0)
            }
        }
    }

    fn kind(&self) -> SvcKind {
        self.kind
    }

    fn name(&self) -> &str {
        "ReplaceHook.entry"
    }
}

/// The stub the original returns to when `post_call` is enabled.
struct PostStub {
    kind: SvcKind,
    state: Rc<RefCell<HookState>>,
}

impl Svc for PostStub {
    fn handle(&mut self, backend: &mut dyn Backend) -> Result<i64, RunError> {
        let state = self.state.borrow();
        state.in_original.set(false);
        let mut context = state.context.borrow_mut();
        let is_64bit = context.is_64bit;
        context.set_ret(read_return(backend, is_64bit)?);
        let mut callback = state.callback.borrow_mut();
        if let Some(post) = callback.post_call.as_mut() {
            post(&mut context);
        }
        let value = context.get_ret();
        drop(callback);
        drop(context);
        write_return(backend, is_64bit, value)?;
        Ok(value)
    }

    fn kind(&self) -> SvcKind {
        self.kind
    }

    fn name(&self) -> &str {
        "ReplaceHook.post"
    }
}

fn write_return(backend: &mut dyn Backend, is_64bit: bool, value: i64) -> Result<(), RunError> {
    let register = if is_64bit { RegId::X(0) } else { RegId::R(0) };
    backend
        .reg_write(register, value as u64)
        .map_err(RunError::Backend)
}

fn read_return(backend: &mut dyn Backend, is_64bit: bool) -> Result<i64, RunError> {
    let register = if is_64bit { RegId::X(0) } else { RegId::R(0) };
    backend
        .reg_read(register)
        .map(|value| value as i64)
        .map_err(RunError::Backend)
}
