//! Module initialisers.
//!
//! Port of unidbg: `unidbg-android/src/main/java/com/github/unidbg/linux/{AbsoluteInitFunction,LinuxInitFunction}.java`
//! and `unidbg-api/src/main/java/com/github/unidbg/spi/InitFunction.java`@7f5da98e.
//!
//! An initialiser is data: the loader collects them while mapping a module and
//! the emulator runs them after relocation (plan P5). `Absolute` reads its
//! target out of the `init_array` slot at call time, because a relocation may
//! have rewritten the slot since the module was mapped.

use raxdbg_core::memory::{Memory, MemoryError};

/// Adds a module's load base to an initialiser address that is still relative.
///
/// `slot` is the guest address of the `init_array` entry being read. A slot's
/// owner is the module it sits in, so a value below the slot that is not already
/// a guest address is a link-time offset: every module here is mapped above
/// `MMAP_BASE` (0x12000000) and runs with the load base nowhere near zero, so a
/// slot value that is *smaller than the slot itself* cannot be a real address.
/// That test is sharper than a range check, which would also catch a genuine
/// unrelocated address and silently repair it.
fn rebase(load_base: u64, slot: u64, value: u64) -> u64 {
    // Every module is mapped above `MMAP_BASE`, so a slot value that is *below*
    // the base was never a guest address: it is a link-time offset, and adding
    // the base to it is the only way it can become one. The comparison is
    // against the load base rather than against the slot, because a slot's own
    // address says nothing about the module's own size -- a `DT_INIT` entry
    // routinely lives in a segment the module's load base sits below.
    if value == 0 {
        return 0;
    }
    if value < load_base {
        load_base.wrapping_add(value)
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::rebase;

    const BASE: u64 = 0x1214_9000;
    const SLOT: u64 = BASE + 0x8efd0;

    #[test]
    fn a_link_time_offset_gets_the_load_base() {
        // libc++'s init_array entry: a bare offset, never relocated.
        assert_eq!(rebase(BASE, SLOT, 0x8efd1), BASE + 0x8efd0 | 1);
    }

    #[test]
    fn an_already_relocated_pointer_is_left_alone() {
        assert_eq!(rebase(BASE, SLOT, BASE + 0x8efd0), BASE + 0x8efd0);
        assert_eq!(rebase(BASE, SLOT, BASE + 0x8efd1), BASE + 0x8efd1);
    }

    #[test]
    fn zero_stays_zero_so_the_caller_can_skip_it() {
        assert_eq!(rebase(BASE, SLOT, 0), 0);
    }

    #[test]
    fn a_forward_or_higher_value_is_never_rebased() {
        // At or above the base means it is already a guest address.
        assert_eq!(rebase(BASE, SLOT, BASE), BASE);
        assert_eq!(rebase(BASE, SLOT, SLOT + 0x40), SLOT + 0x40);
    }

    #[test]
    fn the_low_bit_survives_the_rebase() {
        // Thumb sets the low bit as a flag rather than as part of the address,
        // and the module's own code sits on odd addresses.
        assert_eq!(rebase(BASE, SLOT, 0x8efd1), BASE + 0x8efd1);
    }
}

/// One module initialiser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InitFunction {
    /// An `init_array`/`preinit_array` slot holding the function's address.
    Absolute {
        /// The module's load base.
        load_base: u64,
        /// The module's name.
        lib_name: String,
        /// The guest address of the array slot.
        ptr: u64,
        /// The address read from the slot when the module was mapped.
        address: u64,
    },
    /// `DT_INIT`, an offset from the module's load base.
    Linux {
        /// The module's load base.
        load_base: u64,
        /// The module's name.
        lib_name: String,
        /// The offset from the load base.
        address: u64,
    },
}

impl InitFunction {
    /// The module the initialiser belongs to.
    pub fn so_name(&self) -> &str {
        match self {
            InitFunction::Absolute { lib_name, .. } | InitFunction::Linux { lib_name, .. } => {
                lib_name
            }
        }
    }

    /// The address the initialiser was mapped with, before relocation.
    pub fn declared_address(&self) -> u64 {
        match self {
            InitFunction::Absolute { address, .. } => *address,
            InitFunction::Linux {
                load_base, address, ..
            } => load_base.wrapping_add(*address),
        }
    }

    /// The address to call now.
    ///
    /// Port of unidbg: `AbsoluteInitFunction.call`, which re-reads the slot and
    /// falls back to the address recorded when the module was mapped when the
    /// slot reads zero.
    ///
    /// The catch is a slot that holds a *link-time* address. A library built
    /// with `--pack-dyn-relocs` may leave `init_array` unrelocated -- its entry
    /// is a plain offset, not an `R_*_RELATIVE` -- and then the slot reads a
    /// plausible-looking value in the module's own low addresses. Taking that as
    /// a guest address calls something around address 8, which faults reading
    /// whatever instruction bytes are stored there. So a value that lies inside
    /// the module's own address range is an offset and gets the load base added.
    pub fn address(&self, memory: &dyn Memory) -> Result<u64, MemoryError> {
        match self {
            InitFunction::Absolute {
                load_base,
                ptr,
                address,
                ..
            } => {
                let current = if memory.pointer_size() == 4 {
                    let mut buf = [0u8; 4];
                    memory.read_bytes(*ptr, &mut buf)?;
                    u64::from(u32::from_le_bytes(buf))
                } else {
                    let mut buf = [0u8; 8];
                    memory.read_bytes(*ptr, &mut buf)?;
                    u64::from_le_bytes(buf)
                };
                let value = if current == 0 { *address } else { current };
                Ok(rebase(*load_base, *ptr, value))
            }
            InitFunction::Linux {
                load_base, address, ..
            } => Ok(load_base.wrapping_add(*address)),
        }
    }
}
