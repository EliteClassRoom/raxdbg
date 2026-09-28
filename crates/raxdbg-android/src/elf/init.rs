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
    /// Port of unidbg: `AbsoluteInitFunction.getFuncAddress`, which re-reads
    /// the slot; a slot that relocation has zeroed falls back to the address
    /// recorded at load time.
    pub fn address(&self, memory: &dyn Memory) -> Result<u64, MemoryError> {
        match self {
            InitFunction::Absolute { ptr, address, .. } => {
                let current = if memory.pointer_size() == 4 {
                    let mut buf = [0u8; 4];
                    memory.read_bytes(*ptr, &mut buf)?;
                    u64::from(u32::from_le_bytes(buf))
                } else {
                    let mut buf = [0u8; 8];
                    memory.read_bytes(*ptr, &mut buf)?;
                    u64::from_le_bytes(buf)
                };
                Ok(if current == 0 { *address } else { current })
            }
            InitFunction::Linux {
                load_base, address, ..
            } => Ok(load_base.wrapping_add(*address)),
        }
    }
}
