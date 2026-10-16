//! Function-call tracing.
//!
//! Port of unidbg:
//!
//! * `unidbg-api/src/main/java/com/github/unidbg/arm/TraceFunctionCall.java@7f5da98e`
//! * `unidbg-api/src/main/java/com/github/unidbg/arm/TraceFunctionCall32.java@7f5da98e`
//! * `unidbg-api/src/main/java/com/github/unidbg/arm/TraceFunctionCall64.java@7f5da98e`
//!
//! The hook is a [`CodeHook`] over `[begin, end]`. Every branch-with-link
//! instruction it sees (`bl`, `blr`, `blx`) is reported to the listener
//! together with the address it targets, as is a tail call — a `br`/`bx`
//! through a register — that *leaves* the attached range. A tail call that
//! stays inside is an ordinary jump and is not reported: a protection that
//! flattens its control flow is nearly all jumps, and logging them would bury
//! the calls.
//!
//! Reporting the out-of-range tail calls is a deviation from unidbg, whose
//! hook watches `postCall` and never sees one. A JNI `JNIEnv` dispatch through
//! a function pointer is reached exactly that way — the register holds the
//! stub — so a protection that tail-calls its JNI functions would otherwise
//! trace as silent.
//!
//! Deviation from unidbg: `TraceFunctionCall` there pushes a `RunnableTask`
//! per call so it can name the call stack and report the return in `postCall`.
//! raxdbg has no call-stack tracking, so this hook reports the call at the
//! branch and does not track returns.

use std::cell::RefCell;
use std::rc::Rc;

use crate::backend::{Backend, CodeHook, HookId};
use crate::reg::RegId;

/// One call: the branch instruction and the address it targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FunctionCall {
    /// The address of the `bl`/`blr`/`blx` instruction.
    pub caller: u64,
    /// The address the branch targets.
    pub callee: u64,
}

/// Notified for every call the traced range makes.
pub trait FunctionCallListener {
    /// `backend` is the backend the hook was handed, so a listener can read
    /// registers and memory (unidbg hands its listener the emulator).
    fn on_call(&mut self, backend: &mut dyn Backend, call: &FunctionCall);

    /// Flushes buffered output; the default does nothing.
    fn flush(&mut self) {}
}

/// Function-call trace hook.
///
/// Reports every `bl`/`blr`/`blx` executed inside the range it is attached to,
/// which is what makes "which functions does this library call?" answerable:
/// attach over the module's own range and the log holds the calls it makes.
pub struct TraceFunctionCall {
    inner: Rc<RefCell<TraceFunctionCallInner>>,
}

struct TraceFunctionCallInner {
    is_64bit: bool,
    listener: Option<Box<dyn FunctionCallListener>>,
    calls: u64,
}

impl TraceFunctionCall {
    /// Creates a hook that decodes AArch64 (`true`) or AArch32 (`false`).
    pub fn new(is_64bit: bool) -> Self {
        Self {
            inner: Rc::new(RefCell::new(TraceFunctionCallInner {
                is_64bit,
                listener: None,
                calls: 0,
            })),
        }
    }

    /// Routes calls through `listener`.
    pub fn set_listener(&self, listener: Box<dyn FunctionCallListener>) {
        self.inner.borrow_mut().listener = Some(listener);
    }

    /// How many calls the hook reported.
    pub fn count(&self) -> u64 {
        self.inner.borrow().calls
    }

    /// Flushes the listener's output, if it buffers.
    pub fn flush(&self) {
        if let Some(listener) = self.inner.borrow_mut().listener.as_mut() {
            listener.flush();
        }
    }

    /// Installs the hook over `[begin, end]` (both ends inclusive).
    pub fn attach(&self, backend: &Rc<RefCell<dyn Backend>>, begin: u64, end: u64) -> HookId {
        let hook = TraceFunctionCallHook {
            inner: self.inner.clone(),
            begin,
            end,
        };
        backend
            .borrow_mut()
            .hook_add_code(Box::new(hook), begin, end)
    }
}

struct TraceFunctionCallHook {
    inner: Rc<RefCell<TraceFunctionCallInner>>,
    /// The range this hook covers, inclusive.
    ///
    /// A tail call counts only when it *leaves* it: that is a call out of the
    /// traced code, which is what the log is for. One that stays inside is an
    /// ordinary jump, and a control-flow-flattened function makes thousands.
    begin: u64,
    end: u64,
}

impl CodeHook for TraceFunctionCallHook {
    fn hook(&mut self, backend: &mut dyn Backend, address: u64, _size: u32) {
        // `_size` is ignored: the run loop always passes 4
        // (`raxdbg-backend-rax/src/run.rs`, `dispatch_step_hooks`), so the
        // instruction bytes are read here and tell the real width.
        let is_64bit = self.inner.borrow().is_64bit;
        let call = if is_64bit {
            decode_arm64(backend, address, self.begin, self.end)
        } else {
            decode_arm32(backend, address, self.begin, self.end)
        };
        let Some(call) = call else { return };

        let mut inner = self.inner.borrow_mut();
        inner.calls += 1;
        if let Some(listener) = inner.listener.as_mut() {
            listener.on_call(backend, &call);
        }
    }
}

// Decoding --------------------------------------------------------------------

/// Sign-extends the low `bits` of `value` and returns it as a `u64` whose
/// value is the signed offset in two's complement.
///
/// unidbg's `Utils.signExtend(int value, int bits)`; `bits` is always in
/// `1..=32` here, and every caller feeds the result to a wrapping add, so the
/// two's-complement form is what is wanted.
fn sign_extend(value: u32, bits: u32) -> u64 {
    let shift = 32 - bits;
    (((value << shift) as i32) >> shift) as i64 as u64
}

/// Reads one 32-bit little-endian word, or `None` when the read fails.
fn read_word32(backend: &mut dyn Backend, address: u64) -> Option<u32> {
    let bytes = backend.mem_read(address, 4).ok()?;
    (bytes.len() == 4).then(|| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Reads one 16-bit little-endian halfword, or `None` when the read fails.
fn read_halfword(backend: &mut dyn Backend, address: u64) -> Option<u16> {
    let bytes = backend.mem_read(address, 2).ok()?;
    (bytes.len() == 2).then(|| u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// AArch64 `bl`/`blr`, and a `br` that leaves the traced range.
///
/// Port of unidbg's `TraceFunctionCall64`, with one addition: unidbg watches
/// `postCall` and so never sees a tail call, while a JNI `JNIEnv` dispatch
/// through a function pointer is *reached* by a plain `br` — the register
/// holds the stub. A protection that tail-calls every JNI function would
/// otherwise trace as silent.
fn decode_arm64(
    backend: &mut dyn Backend,
    address: u64,
    begin: u64,
    end: u64,
) -> Option<FunctionCall> {
    let word = read_word32(backend, address)?;
    let callee = if word & 0xFC00_0000 == 0x9400_0000 {
        // BL: imm26, scaled by 4, relative to the branch itself.
        address.wrapping_add(sign_extend(word & 0x03FF_FFFF, 26) << 2)
    } else if word & 0xFFFF_FC1F == 0xD63F_0000 {
        // BLR Xn: the target is in Xn, whose low bit selects the state.
        let register = ((word >> 5) & 0x1F) as u8;
        backend.reg_read(RegId::X(register)).ok()?
    } else if word & 0xFFFF_FC1F == 0xD61F_0000 {
        // BR Xn: a tail call. Reported only when it leaves the traced range,
        // which is what separates a call out of the module from an ordinary
        // jump inside it — a flattened control flow is nearly all the latter.
        let register = ((word >> 5) & 0x1F) as u8;
        let target = backend.reg_read(RegId::X(register)).ok()?;
        if (begin..=end).contains(&target) {
            return None;
        }
        target
    } else {
        return None;
    };
    Some(FunctionCall {
        caller: address,
        callee,
    })
}

/// AArch32 `bl`/`blx` in ARM and Thumb state, port of unidbg's
/// `TraceFunctionCall32`.
fn decode_arm32(
    backend: &mut dyn Backend,
    address: u64,
    begin: u64,
    end: u64,
) -> Option<FunctionCall> {
    // The T bit of CPSR: 0 is ARM state, 1 is Thumb state.
    let thumb = backend.reg_read(RegId::Cpsr).ok()? & (1 << 5) != 0;
    let callee = if thumb {
        decode_thumb(backend, address, begin, end)?
    } else {
        decode_arm(backend, address, begin, end)?
    };
    Some(FunctionCall {
        caller: address,
        callee,
    })
}

/// The 32-bit ARM encodings. The ARM `PC` reads as `address + 8`.
fn decode_arm(backend: &mut dyn Backend, address: u64, begin: u64, end: u64) -> Option<u64> {
    let word = read_word32(backend, address)?;
    if word & 0x0F00_0000 == 0x0B00_0000 {
        // BL: imm24, scaled by 4, relative to `address + 8`.
        Some(
            address
                .wrapping_add(8)
                .wrapping_add(sign_extend(word & 0x00FF_FFFF, 24) << 2),
        )
    } else if word & 0xFE00_0000 == 0xFA00_0000 {
        // BLX (immediate): imm24H:imm24L, scaled by 2, halfword-aligned.
        let imm: u32 = ((word & 0x00FF_FFFF) << 1) | ((word >> 24) & 1);
        Some(
            address
                .wrapping_add(8)
                .wrapping_add(sign_extend(imm, 25) << 1)
                & !1,
        )
    } else if word & 0x0FFF_FFF0 == 0x012F_FF30 {
        // BLX Rm: the target is in Rm (bits 3:0), whose low bit selects the
        // state. unidbg's `ARM_BL_REG_MASK = ~0xf000000f`.
        let register = (word & 0xF) as u8;
        Some(backend.reg_read(RegId::R(register)).ok()? & !1)
    } else if word & 0x0FFF_FF10 == 0x012F_FF10 {
        // BX Rm: a tail call. Reported only when it leaves the traced range,
        // for the same reason as `br` on AArch64.
        let register = (word & 0xF) as u8;
        let target = backend.reg_read(RegId::R(register)).ok()? & !1;
        if (begin..=end).contains(&target) {
            return None;
        }
        Some(target)
    } else {
        None
    }
}

/// The Thumb encodings: 32-bit `bl`/`blx` immediate, 16-bit `blx Rm`.
fn decode_thumb(backend: &mut dyn Backend, address: u64, begin: u64, end: u64) -> Option<u64> {
    let h1 = read_halfword(backend, address)?;
    if h1 & 0xF800 == 0xF000 || h1 & 0xF800 == 0xF800 {
        let h2 = read_halfword(backend, address.wrapping_add(2))?;
        if h1 & 0xF800 == 0xF000 && h2 & 0xC000 == 0xC000 {
            // BL (T1) and BLX (T2) share the imm32 layout; only the base and
            // the target alignment differ.
            let s = u32::from((h1 >> 10) & 1);
            let j1 = u32::from((h2 >> 13) & 1);
            let j2 = u32::from((h2 >> 11) & 1);
            let i1 = !(j1 ^ s) & 1;
            let i2 = !(j2 ^ s) & 1;
            let imm10 = u32::from(h1 & 0x3FF);
            return Some(if (h2 >> 12) & 1 == 1 {
                let imm32 = (s << 24)
                    | (i1 << 23)
                    | (i2 << 22)
                    | (imm10 << 12)
                    | (u32::from(h2 & 0x7FF) << 1);
                address.wrapping_add(4).wrapping_add(sign_extend(imm32, 25))
            } else {
                // BLX (T2) targets a word-aligned address, so the halfword
                // offset is dropped and the base is aligned down.
                let imm32 = (s << 24)
                    | (i1 << 23)
                    | (i2 << 22)
                    | (imm10 << 12)
                    | (u32::from(h2 & 0x7FE) << 1);
                (address.wrapping_add(4) & !3).wrapping_add(sign_extend(imm32, 25))
            });
        }
        return None;
    }
    if h1 & 0xFF87 == 0x4780 {
        // BLX Rm: the target is in Rm, whose low bit selects the state.
        let register = ((h1 >> 3) & 0xF) as u8;
        return Some(backend.reg_read(RegId::R(register)).ok()? & !1);
    }
    if h1 & 0xFF87 == 0x4700 {
        // BX Rm: a tail call. Reported only when it leaves the traced range,
        // for the same reason as `br` on AArch64.
        let register = ((h1 >> 3) & 0xF) as u8;
        let target = backend.reg_read(RegId::R(register)).ok()? & !1;
        if (begin..=end).contains(&target) {
            return None;
        }
        return Some(target);
    }
    None
}
