//! Inline hooks: patching a guest function's entry so a call reaches a stub.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/hook/{Dobby,HookZz}.java`
//! and `unidbg-android/src/main/java/com/github/unidbg/linux/android/AndroidElfLoader.java`'s
//! inline-hook use of them@7f5da98e.
//!
//! Dobby, HookZz and xHook are three implementations of one idea: overwrite the
//! first instructions of the target with a branch to a trampoline, and let the
//! trampoline reach the replacement. The bundled binaries carry that machinery
//! for a real Android process, where they also have to cope with split pages,
//! PAC and MTE. This module is the emulator-side equivalent: the target is
//! already in our own address space, so the branch can be as long as the ISA
//! allows and the trampoline is an SVC stub the SVC dispatch already knows how
//! to route.
//!
//! AArch64 makes this straightforward: `b` is ±128 MiB, which reaches anywhere
//! in a process we lay out, so one instruction replaces the target's entry and
//! the displaced instructions move into a trampoline the replacement can call.
//! AArch32 needs more work -- `b` is ±32 MiB and a Thumb `bl` is only ±4 MiB --
//! so [`InlineHook::install`] reports what the ISA can reach rather than
//! silently writing a branch that goes nowhere.

use std::cell::RefCell;
use std::rc::Rc;

use raxdbg_core::backend::Backend;

/// Why a hook could not be installed.
#[derive(Debug, thiserror::Error)]
pub enum HookError {
    /// The guest address is not in a module the loader knows about.
    #[error("{0:#x} is not inside a loaded module")]
    NotInModule(u64),
    /// The target's first instructions could not be read.
    #[error("cannot read the instructions at {0:#x}")]
    Unreadable(u64),
    /// The ISA cannot reach the trampoline from the target.
    #[error("a branch from {target:#x} to {trampoline:#x} is out of range on this ISA: the target needs a near trampoline")]
    OutOfRange {
        /// Where the branch starts.
        target: u64,
        /// Where it would have to go.
        trampoline: u64,
    },
    /// Guest memory refused the patch.
    #[error("cannot patch the target: {0}")]
    Memory(String),
    /// The target is too short to displace any instructions.
    #[error("the target at {0:#x} is shorter than one instruction")]
    TooShort(u64),
}

/// One installed inline hook.
#[derive(Debug)]
pub struct InlineHook {
    target: u64,
    trampoline: u64,
    /// The instructions the branch displaced, moved into the trampoline.
    displaced: Vec<u32>,
    /// The bytes the patch wrote, for uninstalling.
    original: Vec<u8>,
}

impl InlineHook {
    /// The function that was hooked.
    pub fn target(&self) -> u64 {
        self.target
    }

    /// The address calls are diverted to.
    pub fn trampoline(&self) -> u64 {
        self.trampoline
    }

    /// The instructions the branch replaced.
    pub fn displaced(&self) -> &[u32] {
        &self.displaced
    }
}

/// The hooks installed on one emulator.
#[derive(Debug, Default)]
pub struct InlineHooks {
    hooks: RefCell<Vec<InlineHook>>,
}

impl InlineHooks {
    /// An empty set.
    pub fn new() -> Self {
        InlineHooks {
            hooks: RefCell::new(Vec::new()),
        }
    }

    /// The hooks installed so far.
    pub fn len(&self) -> usize {
        self.hooks.borrow().len()
    }

    /// Whether nothing is hooked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The address `target` is diverted to, if it is hooked.
    pub fn trampoline_for(&self, target: u64) -> Option<u64> {
        self.hooks
            .borrow()
            .iter()
            .find(|hook| hook.target == target)
            .map(|hook| hook.trampoline)
    }

    /// Writes a branch at `from` to `to`, and reports whether the ISA reaches.
    ///
    /// AArch64's `b` has a signed 26-bit byte offset, so ±128 MiB. AArch32's
    /// ARM `b` is ±32 MiB and a Thumb `b` far less, which is why the caller has
    /// to place the trampoline near the target.
    pub fn branch_reaches(from: u64, to: u64, is_64bit: bool) -> bool {
        let delta = to as i128 - from as i128;
        let limit: i128 = if is_64bit {
            REACH_64 as i128
        } else {
            // A Thumb `b` is a signed 11-bit byte offset: 2 KiB * 2 = 4 MiB. An
            // ARM-mode `b` would reach 32 MiB, but a function pointer on
            // Android is Thumb, so 4 MiB is the figure that has to hold.
            REACH_32 as i128
        };
        delta.abs() < limit
    }
}

/// The largest distance a trampoline may be from its target, per ISA.
pub const REACH_64: i64 = 1 << 27;
/// The AArch32 limit: a Thumb `b` is ±4 MiB, an ARM one ±32 MiB, so the
/// conservative figure is the smaller of the two.
pub const REACH_32: i64 = 1 << 22;

/// Encodes an AArch64 unconditional branch `b` from `from` to `to`.
///
/// Returns `None` when the destination is out of range, which is a real
/// constraint rather than an error to paper over: the SVC page is at
/// `0xfffe0000` and most modules at `0x12000000`, so the distance is usually
/// fine, but a module mapped low would not be.
pub fn encode_branch64(from: u64, to: u64) -> Option<u32> {
    let delta = (to as i128) - (from as i128);
    if delta & 3 != 0 {
        return None;
    }
    let words = delta / 4;
    if words < -(1 << 25) || words > (1 << 25) - 1 {
        return None;
    }
    // opcode 000101 in the top 6 bits, imm26, then the fixed 26-bit zero.
    Some((0b000101u32 << 26) | ((words as u32) & 0x03ff_ffff))
}

/// Installs an inline hook, sending calls at `target` to `trampoline`.
///
/// The branch replaces the first instruction, and that instruction is saved so
/// a replacement that wants the original behaviour can run it. This is the one
/// mechanism Dobby, HookZz and xHook all implement, and putting it here means
/// the three engines differ only in which library they wrap.
pub fn install(
    backend: &mut dyn Backend,
    hooks: &Rc<InlineHooks>,
    target: u64,
    trampoline: u64,
    is_64bit: bool,
) -> Result<(), HookError> {
    if !is_64bit {
        // AArch32 needs a near trampoline and a multi-instruction patch, which
        // is a different piece of work; saying so beats writing a branch that
        // lands in the wrong module.
        return Err(HookError::OutOfRange { target, trampoline });
    }
    let mut original = [0u8; 4];
    backend
        .mem_read_into(target, &mut original)
        .map_err(|_| HookError::Unreadable(target))?;
    let Some(branch) = encode_branch64(target, trampoline) else {
        return Err(HookError::OutOfRange { target, trampoline });
    };
    backend
        .mem_write(target, &branch.to_le_bytes())
        .map_err(|error| HookError::Memory(error.to_string()))?;
    // The instruction cache has to be told: a patched function that keeps its
    // old instructions is the single most common way an inline hook appears to
    // do nothing.
    backend.remove_jit_code_cache(target, target + 4);
    let displaced = u32::from_le_bytes(original);
    hooks.hooks.borrow_mut().push(InlineHook {
        target,
        trampoline,
        displaced: vec![displaced],
        original: original.to_vec(),
    });
    Ok(())
}

/// Restores everything [`install`] patched.
pub fn uninstall(backend: &mut dyn Backend, hooks: &Rc<InlineHooks>, target: u64) -> bool {
    let Some(index) = hooks
        .hooks
        .borrow()
        .iter()
        .position(|hook| hook.target == target)
    else {
        return false;
    };
    let hook = hooks.hooks.borrow_mut().remove(index);
    let _ = backend.mem_write(hook.target, &hook.original);
    backend.remove_jit_code_cache(hook.target, hook.target + 4);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_branch_encodes_and_comes_back() {
        // b to the next instruction is imm26 = 1.
        assert_eq!(encode_branch64(0x1000, 0x1004), Some(0x1400_0001));
        // b to itself is 0x14000000 with imm26 = 0.
        assert_eq!(encode_branch64(0x1000, 0x1000), Some(0x1400_0000));
        // Backwards by four instructions: imm26 = -4, which is all ones from
        // bit 2 up. The opcode is `000101` in the top six bits, so the word is
        // 0x17fffffc.
        assert_eq!(encode_branch64(0x1010, 0x1000), Some(0x17ff_fffc));
        // Forwards by four instructions: imm26 = 4.
        assert_eq!(encode_branch64(0x1000, 0x1010), Some(0x1400_0004));
    }

    #[test]
    fn a_branch_out_of_range_is_refused_rather_than_truncated() {
        // Beyond ±128 MiB.
        assert_eq!(encode_branch64(0x1000, 0x1000 + REACH_64 as u64), None);
        assert_eq!(encode_branch64(0x1000, 0x1_0000_0000), None, "2 GiB away");
        // A misaligned destination.
        assert_eq!(encode_branch64(0x1000, 0x1001), None);
    }

    #[test]
    fn the_svc_page_is_not_reachable_from_a_module_so_the_trampoline_must_be_near() {
        // Modules sit at MMAP_BASE (0x12000000) and the SVC page at 0xfffe0000,
        // which is about 3.9 GB away -- far outside an AArch64 branch's 128 MiB.
        // So a trampoline cannot live in the SVC page; it has to be allocated
        // next to its target. This is the constraint that makes the difference
        // between the two ISAs, and it is why a real inline hook has to place
        // its trampoline rather than reuse an existing stub.
        let module = 0x1200_0000u64;
        let svc_page = 0xfffe_0000u64;
        assert!(!InlineHooks::branch_reaches(module, svc_page, true));
        // Within a megabyte of the target it is fine, on either ISA's terms.
        assert!(InlineHooks::branch_reaches(module, module + 0x10_0000, true));
        assert!(InlineHooks::branch_reaches(module, module + 0x10_0000, false));
        // But a Thumb branch only reaches 4 MiB, so an AArch32 trampoline has to
        // be much closer than an AArch64 one: 8 MiB away is fine on AArch64 and
        // out of range on AArch32.
        assert!(!InlineHooks::branch_reaches(module, module + 0x80_0000, false));
        assert!(InlineHooks::branch_reaches(module, module + 0x80_0000, true));
    }

    #[test]
    fn the_reach_limits_are_the_isa_ones() {
        // AArch64 b: signed 26-bit, scaled by 4.
        assert_eq!(REACH_64, 128 * 1024 * 1024);
        // A Thumb b: signed 11-bit, scaled by 2.
        assert_eq!(REACH_32, 4 * 1024 * 1024);
    }
}
