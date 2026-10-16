//! Reading the arguments a `CallStatic*MethodV` call packed behind its `va_list`.
//!
//! Port of unidbg: `unidbg-android/src/main/java/com/github/unidbg/linux/android/dvm/{VaList,VaList32,VaList64}.java`
//! @7f5da98e.
//!
//! A `V`-suffixed JNI call is the `va_list` form: the arguments are not in
//! `x3..` but behind the pointer in `x3`, laid out by the caller's own
//! `va_start`. The layout is the ABI's, not JNI's, so this is the one place the
//! port models `va_arg` instead of a register file.

use raxdbg_core::memory::{Memory, MemoryError};

use super::object::ArgType;

/// Reads every argument of `args` from the `va_list` at `va_list`.
///
/// Each value is widened to a `u64` the way the corresponding register would
/// hold it, so a host recovers a `jint`, `jboolean`, `jbyte`, `jchar` or
/// `jshort` with `args[i] as i32`, a reference with `args[i] as i32`, a
/// `jdouble` with `f64::from_bits(args[i])` and a `jfloat` with
/// `f32::from_bits(args[i] as u32)`.
pub fn read_va_list(
    memory: &dyn Memory,
    va_list: u64,
    args: &[ArgType],
    is_64bit: bool,
) -> Result<Vec<u64>, MemoryError> {
    if is_64bit {
        read_va_list_64(memory, va_list, args)
    } else {
        read_va_list_32(memory, va_list, args)
    }
}

/// The arm64 layout: the 32-byte `struct __va_list` AAPCS64 defines.
///
/// |offset|field|meaning|
/// |---|---|---|
/// |+0|`__stack`|where the stack-passed arguments start|
/// |+8|`__gr_top`|top of the GP register save area|
/// |+16|`__vr_top`|top of the FP register save area|
/// |+24|`__gr_offs`|negative byte offset into the GP save area|
/// |+28|`__vr_offs`|negative byte offset into the FP save area|
fn read_va_list_64(
    memory: &dyn Memory,
    va_list: u64,
    args: &[ArgType],
) -> Result<Vec<u64>, MemoryError> {
    /// Takes the next argument's slot out of a register bank.
    ///
    /// Port of unidbg: the body of `VaList64`'s per-shorty loop. A negative
    /// offset that still leaves `width` bytes of save area reads from
    /// `top + offset` and advances the offset; otherwise the argument comes off
    /// the stack, and `bias` is unidbg's own arithmetic -- 11 for a
    /// `jint`-wide argument and 15 for a wider one, both masked to an
    /// eight-byte boundary, so the stack cursor moves to the next boundary
    /// rather than by the argument's width.
    fn slot(top: u64, offs: &mut i32, stack: &mut u64, width: i32, bias: u64) -> u64 {
        if *offs < 0 {
            if *offs + width <= 0 {
                let address = top.wrapping_add(*offs as i64 as u64);
                *offs += width;
                return address;
            }
            // The save area cannot hold another slot: every remaining argument
            // is on the stack. The offset keeps advancing, and the mask test
            // can no longer come out negative, which is what makes the stack
            // path sticky.
            *offs += width;
        }
        let address = *stack;
        *stack = (*stack + bias) & !7;
        address
    }

    let pointer = memory.pointer(va_list);
    let mut stack = pointer.read_u64(0)?;
    let gr_top = pointer.read_u64(8)?;
    let vr_top = pointer.read_u64(16)?;
    // Signed, and negative while the save area still holds arguments.
    let mut gr_offs = pointer.read_u32(24)? as i32;
    let mut vr_offs = pointer.read_u32(28)? as i32;

    let mut values = Vec::with_capacity(args.len());
    for arg in args {
        values.push(match arg {
            ArgType::Int => {
                let address = slot(gr_top, &mut gr_offs, &mut stack, 8, 11);
                // A `jint`-wide argument arrives as a sign-extended register
                // would, so a negative `jint` reads back through `as i32`.
                memory.pointer(address).read_u32(0)? as i32 as i64 as u64
            }
            ArgType::Object => {
                // unidbg reads a reference as an `int` but advances the stack
                // cursor like a full slot: `'L'` takes the `15` bias, not the
                // `11` the `jint`-wide shorties take. Sharing the arm above
                // would shift every argument after the first spilled reference.
                let address = slot(gr_top, &mut gr_offs, &mut stack, 8, 15);
                memory.pointer(address).read_u32(0)? as i32 as i64 as u64
            }
            ArgType::Long => {
                let address = slot(gr_top, &mut gr_offs, &mut stack, 8, 15);
                memory.pointer(address).read_u64(0)?
            }
            ArgType::Double => {
                let address = slot(vr_top, &mut vr_offs, &mut stack, 16, 15);
                memory.pointer(address).read_u64(0)?
            }
            ArgType::Float => {
                let address = slot(vr_top, &mut vr_offs, &mut stack, 16, 15);
                // unidbg reads a `double` for `'F'` and casts it to `float`;
                // keep the parity rather than guess the width the guest meant.
                let value = f64::from_bits(memory.pointer(address).read_u64(0)?);
                u64::from((value as f32).to_bits())
            }
        });
    }
    Ok(values)
}

/// Port of unidbg: `VaList32`, which reads `va_list` as a plain pointer into the
/// spilled arguments rather than as AAPCS32's `__va_list` struct. That is what a
/// caller's own `va_start` leaves behind, and it is what unidbg reads.
fn read_va_list_32(
    memory: &dyn Memory,
    va_list: u64,
    args: &[ArgType],
) -> Result<Vec<u64>, MemoryError> {
    let mut cursor = va_list;
    let mut values = Vec::with_capacity(args.len());
    for arg in args {
        values.push(match arg {
            ArgType::Int | ArgType::Object => {
                let value = memory.pointer(cursor).read_u32(0)? as i32 as i64 as u64;
                cursor += 4;
                value
            }
            ArgType::Long => {
                cursor = (cursor + 7) & !7;
                let value = memory.pointer(cursor).read_u64(0)?;
                cursor += 8;
                value
            }
            ArgType::Double => {
                cursor = (cursor + 7) & !7;
                let value = memory.pointer(cursor).read_u64(0)?;
                cursor += 8;
                value
            }
            ArgType::Float => {
                cursor = (cursor + 7) & !7;
                let value = f64::from_bits(memory.pointer(cursor).read_u64(0)?);
                cursor += 8;
                u64::from((value as f32).to_bits())
            }
        });
    }
    Ok(values)
}
