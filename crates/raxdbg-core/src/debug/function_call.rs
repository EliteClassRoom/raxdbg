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
//! together with the address it targets. Only branch-with-link instructions
//! count: a tail call — a plain `b` to a PLT stub — is *not* reported, exactly
//! as in unidbg, whose hook watches `postCall` and never sees one.
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
        };
        backend.borrow_mut().hook_add_code(Box::new(hook), begin, end)
    }
}

struct TraceFunctionCallHook {
    inner: Rc<RefCell<TraceFunctionCallInner>>,
}

impl CodeHook for TraceFunctionCallHook {
    fn hook(&mut self, backend: &mut dyn Backend, address: u64, _size: u32) {
        // `_size` is ignored: the run loop always passes 4
        // (`raxdbg-backend-rax/src/run.rs`, `dispatch_step_hooks`), so the
        // instruction bytes are read here and tell the real width.
        let is_64bit = self.inner.borrow().is_64bit;
        let call = if is_64bit {
            decode_arm64(backend, address)
        } else {
            decode_arm32(backend, address)
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

/// AArch64 `bl`/`blr`, port of unidbg's `TraceFunctionCall64`.
fn decode_arm64(backend: &mut dyn Backend, address: u64) -> Option<FunctionCall> {
    let word = read_word32(backend, address)?;
    let callee = if word & 0xFC00_0000 == 0x9400_0000 {
        // BL: imm26, scaled by 4, relative to the branch itself.
        address.wrapping_add(sign_extend(word & 0x03FF_FFFF, 26) << 2)
    } else if word & 0xFFFF_FC1F == 0xD63F_0000 {
        // BLR Xn: the target is in Xn, whose low bit selects the state.
        let register = ((word >> 5) & 0x1F) as u8;
        backend.reg_read(RegId::X(register)).ok()?
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
fn decode_arm32(backend: &mut dyn Backend, address: u64) -> Option<FunctionCall> {
    // The T bit of CPSR: 0 is ARM state, 1 is Thumb state.
    let thumb = backend.reg_read(RegId::Cpsr).ok()? & (1 << 5) != 0;
    let callee = if thumb {
        decode_thumb(backend, address)?
    } else {
        decode_arm(backend, address)?
    };
    Some(FunctionCall {
        caller: address,
        callee,
    })
}

/// The 32-bit ARM encodings. The ARM `PC` reads as `address + 8`.
fn decode_arm(backend: &mut dyn Backend, address: u64) -> Option<u64> {
    let word = read_word32(backend, address)?;
    if word & 0x0F00_0000 == 0x0B00_0000 {
        // BL: imm24, scaled by 4, relative to `address + 8`.
        Some(address.wrapping_add(8).wrapping_add(sign_extend(word & 0x00FF_FFFF, 24) << 2))
    } else if word & 0xFE00_0000 == 0xFA00_0000 {
        // BLX (immediate): imm24H:imm24L, scaled by 2, halfword-aligned.
        let imm: u32 = ((word & 0x00FF_FFFF) << 1) | ((word >> 24) & 1);
        Some(address.wrapping_add(8).wrapping_add(sign_extend(imm, 25) << 1) & !1)
    } else if word & 0x0FFF_FFF0 == 0x012F_FF30 {
        // BLX Rm: the target is in Rm (bits 3:0), whose low bit selects the
        // state. unidbg's `ARM_BL_REG_MASK = ~0xf000000f`.
        let register = (word & 0xF) as u8;
        Some(backend.reg_read(RegId::R(register)).ok()? & !1)
    } else {
        None
    }
}

/// The Thumb encodings: 32-bit `bl`/`blx` immediate, 16-bit `blx Rm`.
fn decode_thumb(backend: &mut dyn Backend, address: u64) -> Option<u64> {
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
                let imm32 = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (u32::from(h2 & 0x7FF) << 1);
                address.wrapping_add(4).wrapping_add(sign_extend(imm32, 25))
            } else {
                // BLX (T2) targets a word-aligned address, so the halfword
                // offset is dropped and the base is aligned down.
                let imm32 = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (u32::from(h2 & 0x7FE) << 1);
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
    None
}
