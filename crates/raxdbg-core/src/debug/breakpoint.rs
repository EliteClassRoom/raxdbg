//! Breakpoints, single-step and the `Breaker` trait.
//!
//! Port of unidbg:
//! `unidbg-api/src/main/java/com/github/unidbg/debugger/{Debugger, Breaker, BreakPoint,
//! BreakPointCallback, DebuggerType}.java@7f5da98e` and
//! `unidbg-api/src/main/java/com/github/unidbg/arm/AbstractARMDebugger.java@7f5da98e`.
//!
//! The contract is split into three pieces:
//!
//! * [`BreakPoint`] — the public handle a caller manipulates after adding one
//!   (read its address, mark it temporary, replace the callback).
//! * [`Breaker`] — the trait `Debugger` consumes: the host code only needs to
//!   install/remove breakpoints and request single-step.
//! * [`BreakerImpl`] — the production implementation that wires those calls
//!   through [`Backend::hook_add_code`](crate::backend::Backend::hook_add_code).
//!
//! A breakpoint is a one-instruction code hook installed at exactly
//! `[address, address]`; the optional user callback is invoked before the run
//! loop is asked to stop, mirroring unidbg's `BreakPointCallback.onHit`
//! returning `false` to actually pause. Temporary breakpoints remove their own
//! hook on the first hit, exactly like `setTemporary(true)` in unidbg.
//! Single-step is one global code hook covering the whole address space that
//! decrements an instruction counter and stops the run when it reaches zero.

use std::cell::Cell;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use crate::backend::{Backend, HookId};

/// What a breakpoint callback returns: whether the run should actually stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakControl {
    /// Breakpoint fires: ask the run loop to stop.
    Stop,
    /// Breakpoint is skipped for this hit; execution continues.
    Continue,
}

/// User-supplied callback for a breakpoint.
///
/// Returns [`BreakControl::Stop`] to stop the run, [`BreakControl::Continue`]
/// to skip the hit. Mirrors unidbg's `BreakPointCallback.onHit`, where a
/// `false` return value means the breakpoint triggered successfully and a
/// `true` return value skips it. The `address` argument is the breakpoint
/// address (thumb bit already stripped, exactly as unidbg does in
/// `AbstractARMDebugger.addBreakPoint`).
pub type BreakCallback = Box<dyn FnMut(u64) -> BreakControl>;

/// A breakpoint handle returned by [`Breaker::add_break_point`].
///
/// `BreakPoint` carries only the metadata the caller can manipulate plus a
/// reference back to the breaker's state, so toggling [`BreakPoint::temporary`]
/// from the caller's side actually affects the registered code hook (a
/// `temporary` breakpoint is removed on its first hit; an unmarked one stays
/// installed until [`Breaker::remove_break_point`]).
#[derive(Clone)]
pub struct BreakPoint {
    address: u64,
    thumb: bool,
    state: Rc<RefCell<BreakPointState>>,
}
struct BreakPointState {
    hook_id: HookId,
    temporary: Cell<bool>,
    callback: Option<BreakCallback>,
}
impl BreakPoint {
    /// The breakpoint address (with the thumb bit already stripped).
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Whether the breakpoint targets a Thumb instruction (the original
    /// `address & 1` was non-zero, matching unidbg's
    /// `address &= (~1)` / `thumb = (address & 1) != 0`).
    pub fn thumb(&self) -> bool {
        self.thumb
    }

    /// Whether the breakpoint will remove itself on the next hit.
    pub fn temporary(&self) -> bool {
        self.state.borrow().temporary.get()
    }

    /// Switches the breakpoint between persistent and self-removing.
    pub fn set_temporary(&self, temporary: bool) {
        self.state.borrow().temporary.set(temporary);
    }

    /// Replaces the user callback. Pass `None` to fall back to the default
    /// "always stop" behaviour, matching unidbg's `BreakPointCallback`.
    pub fn set_callback(&mut self, callback: Option<BreakCallback>) {
        self.state.borrow_mut().callback = callback;
    }
}

/// The host-side half of the debugger contract consumed by every backend.
///
/// The production implementation is [`BreakerImpl`]; tests usually substitute
/// a mock that records the calls.
pub trait Breaker {
    /// Installs a breakpoint at `address` (odd → thumb) with `callback`.
    ///
    /// `callback == None` means "always stop, no user hook", matching
    /// unidbg's `addBreakPoint(long)` without a callback.
    fn add_break_point(
        &mut self,
        address: u64,
        callback: Option<BreakCallback>,
    ) -> BreakPoint;

    /// Removes a breakpoint previously installed at `address` (thumb-stripped).
    /// Returns `true` if a hook was actually removed.
    fn remove_break_point(&mut self, address: u64) -> bool;

    /// Requests single-step: stop after the next `n` instructions.
    ///
    /// `n == 0` clears any pending single-step, equivalent to unidbg's
    /// `setSingleStep(0)`. Passing a positive `n` registers (or updates) one
    /// global code hook that decrements a counter and stops the run when it
    /// reaches zero.
    fn set_single_step(&mut self, n: u64);

    /// The number of instructions left in the pending single-step, or
    /// `None` if no single-step is active.
    fn single_step_remaining(&self) -> Option<u64>;

    /// Enables or disables fast-debug mode.
    ///
    /// Fast-debug skips user-supplied breakpoint callbacks and goes straight
    /// to stopping, matching unidbg's `fastDebug = true` (`AbstractARMDebugger`
    /// uses it to avoid an extra `BreakPointCallback` round-trip when the user
    /// has not asked for anything else).
    fn set_fast_debug(&mut self, on: bool);

    /// The current fast-debug state.
    fn fast_debug(&self) -> bool;
}

/// Reference-counted shared view used by the production [`BreakerImpl`].
///
/// A `Breaker` is usually held as `Rc<RefCell<BreakerImpl>>` because the
/// breakpoints are accessed from host code (loader, syscall handler, console
/// debugger) and from inside code-hook callbacks; both routes need an
/// `Rc`-friendly handle.
#[derive(Clone)]
pub struct BreakerImpl {
    backend: Rc<RefCell<dyn Backend>>,
    state: Rc<RefCell<BreakerState>>,
}

#[derive(Default)]
struct BreakerState {
    /// Breakpoints keyed by thumb-stripped address.
    breakpoints: BTreeMap<u64, Rc<RefCell<BreakPointState>>>,
    /// Hook id of the installed single-step hook, if any.
    step_hook: Option<HookId>,
    /// Instructions remaining in the active single-step.
    step_remaining: Option<u64>,
    /// Fast-debug flag (skips user callbacks, always stops).
    fast: bool,
}

impl BreakerImpl {
    /// Wraps a backend in a breaker. The backend must already be initialized.
    pub fn new(backend: Rc<RefCell<dyn Backend>>) -> Self {
        Self {
            backend,
            state: Rc::new(RefCell::new(BreakerState::default())),
        }
    }

    /// Borrows the backend directly (debugger code that needs it).
    pub fn backend(&self) -> Rc<RefCell<dyn Backend>> {
        self.backend.clone()
    }
}

// Thin wrapper so `&mut dyn Backend` from inside a code hook can run our
// breakpoint logic and remove its own hook when the breakpoint is temporary.
struct BreakPointHook {
    state: Rc<RefCell<BreakPointState>>,
    state_map: Rc<RefCell<BreakerState>>,
}

impl crate::backend::CodeHook for BreakPointHook {
    fn hook(&mut self, backend: &mut dyn Backend, address: u64, _size: u32) {
        // Read fast-debug live from the breaker state so toggles after
        // installation take effect on the very next hit.
        let fast = self.state_map.borrow().fast;
        let decision = if fast {
            BreakControl::Stop
        } else {
            let mut state = self.state.borrow_mut();
            match state.callback.as_mut() {
                Some(cb) => cb(address),
                None => BreakControl::Stop,
            }
        };

        let temporary = self.state.borrow().temporary.get();
        let hook_id = self.state.borrow().hook_id;

        if matches!(decision, BreakControl::Stop) {
            backend.emu_stop();
        }

        if temporary {
            backend.hook_del(hook_id);
            self.state_map.borrow_mut().breakpoints.remove(&address);
        }
    }
}

// Single-step: a single hook spanning the whole address space. On every
// instruction it decrements a counter; when the counter reaches zero, the
// run is asked to stop and the hook removes itself.
struct SingleStepHook {
    remaining: Rc<Cell<u64>>,
    state_map: Rc<RefCell<BreakerState>>,
}

impl crate::backend::CodeHook for SingleStepHook {
    fn hook(&mut self, backend: &mut dyn Backend, _address: u64, _size: u32) {
        let current = self.remaining.get();
        if current == 0 {
            // Already done: clear the hook and stop.
            let hook_id = self.state_map.borrow_mut().step_hook.take();
            if let Some(id) = hook_id {
                backend.hook_del(id);
            }
            backend.emu_stop();
            return;
        }
        if current == 1 {
            self.remaining.set(0);
            let hook_id = self.state_map.borrow_mut().step_hook.take();
            if let Some(id) = hook_id {
                backend.hook_del(id);
            }
            self.state_map.borrow_mut().step_remaining = None;
            backend.emu_stop();
        } else {
            self.remaining.set(current - 1);
            self.state_map.borrow_mut().step_remaining = Some(current - 1);
        }
    }
}

impl Breaker for BreakerImpl {
    fn add_break_point(
        &mut self,
        address: u64,
        callback: Option<BreakCallback>,
    ) -> BreakPoint {
        let thumb = (address & 1) != 0;
        let aligned = address & !1;

        let state = Rc::new(RefCell::new(BreakPointState {
            hook_id: 0,
            temporary: Cell::new(false),
            callback,
        }));

        let hook = BreakPointHook {
            state: state.clone(),
            state_map: self.state.clone(),
        };

        let hook_id = self
            .backend
            .borrow_mut()
            .hook_add_code(Box::new(hook), aligned, aligned);
        state.borrow_mut().hook_id = hook_id;
        self.state
            .borrow_mut()
            .breakpoints
            .insert(aligned, state.clone());

        BreakPoint {
            address: aligned,
            thumb,
            state,
        }
    }

    fn remove_break_point(&mut self, address: u64) -> bool {
        let aligned = address & !1;
        let Some(state) = self.state.borrow_mut().breakpoints.remove(&aligned) else {
            return false;
        };
        let hook_id = state.borrow().hook_id;
        self.backend.borrow_mut().hook_del(hook_id);
        true
    }

    fn set_single_step(&mut self, n: u64) {
        // Clear any existing step hook.
        if let Some(prev) = self.state.borrow_mut().step_hook.take() {
            self.backend.borrow_mut().hook_del(prev);
        }

        if n == 0 {
            self.state.borrow_mut().step_remaining = None;
            return;
        }

        let counter = Rc::new(Cell::new(n));
        let hook = SingleStepHook {
            remaining: counter.clone(),
            state_map: self.state.clone(),
        };

        let hook_id = self
            .backend
            .borrow_mut()
            .hook_add_code(Box::new(hook), 0, u64::MAX);

        self.state.borrow_mut().step_hook = Some(hook_id);
        self.state.borrow_mut().step_remaining = Some(n);
    }

    fn single_step_remaining(&self) -> Option<u64> {
        self.state.borrow().step_remaining
    }

    fn set_fast_debug(&mut self, on: bool) {
        self.state.borrow_mut().fast = on;
    }

    fn fast_debug(&self) -> bool {
        self.state.borrow().fast
    }
}
