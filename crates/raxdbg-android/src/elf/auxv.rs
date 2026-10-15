//! The guest's auxiliary vector.
//!
//! Port of unidbg: the `AT_*` array `AndroidElfLoader.initializeTLS` builds,
//! and the `app_process` main program it describes, @7f5da98e.
//!
//! A Linux process always has a *main program*: the `app_process` executable
//! the runtime was launched from. Its `AT_BASE`, `AT_PHDR`, `AT_PHNUM`,
//! `AT_PHENT` and `AT_ENTRY` all describe that image, and protected code
//! walks them to locate the real linker — `linker64`'s own `AT_BASE` is what
//! tells it where the linker's `PT_LOAD` segments start.
//!
//! unidbg ships a stub `app_process`; raxdbg builds a minimal ELF here
//! instead, so the auxv values point at a real image with a real program
//! header table rather than at zeroes. A guest that reads the magic at
//! `AT_PHDR` gets `0x7fELF`, and one that walks the phdrs gets a loadable
//! `PT_LOAD` covering the base plus a `PT_PHDR` locating the table.

use raxdbg_core::memory::{Memory, MemoryError, PAGE_SIZE};

/// The auxv type tags raxdbg writes, from Linux's `elf.h`.
///
/// Port of unidbg: the `AT_*` constants bionic's `getauxval` compares against.
pub mod tag {
    /// `AT_PHDR` — address of the main program's program headers.
    pub const PHDR: u64 = 3;
    /// `AT_PHENT` — size of one program header.
    pub const PHENT: u64 = 4;
    /// `AT_PHNUM` — how many program headers there are.
    pub const PHNUM: u64 = 5;
    /// `AT_PAGESZ` — the system page size.
    pub const PAGESZ: u64 = 6;
    /// `AT_BASE` — the load bias of the main program.
    pub const BASE: u64 = 7;
    /// `AT_FLAGS` — the kernel's flags word; bionic only checks the randomize bit.
    pub const FLAGS: u64 = 8;
    /// `AT_ENTRY` — the main program's entry point.
    pub const ENTRY: u64 = 9;
    /// `AT_UID` — the real user id.
    pub const UID: u64 = 11;
    /// `AT_EUID` — the effective user id.
    pub const EUID: u64 = 12;
    /// `AT_GID` — the real group id.
    pub const GID: u64 = 13;
    /// `AT_EGID` — the effective group id.
    pub const EGID: u64 = 14;
    /// `AT_PLATFORM` — a pointer to the platform string, e.g. `aarch64`.
    pub const PLATFORM: u64 = 15;
    /// `AT_HWCAP` — the hardware capability word.
    pub const HWCAP: u64 = 16;
    /// `AT_CLKTCK` — the clock ticks per second.
    pub const CLKTCK: u64 = 17;
    /// `AT_SECURE` — set when the process is running setuid/setgid.
    pub const SECURE: u64 = 23;
    /// `AT_RANDOM` — a pointer to 16 bytes of kernel-supplied randomness.
    pub const RANDOM: u64 = 25;
    /// `AT_NULL` — the terminating tag, which must be followed by a zero word.
    pub const NULL: u64 = 0;
}

/// The `AT_FLAGS` bit that says the address space is randomized. raxdbg maps
/// where it likes and never relocates, so the bit stays clear.
const AT_FLAGS_0: u64 = 0;

/// `AT_CLKTCK` on every Linux kernel: 100 ticks per second.
const CLKTCK: u64 = 100;

/// The ids a non-setuid Android process runs with. `AT_SECURE` stays 0 for
/// the same reason.
const UNPRIVILEGED: u64 = 1000;

/// The platform string `AT_PLATFORM` points at, per guest width.
const PLATFORM_AARCH64: &str = "aarch64\0";
/// The platform string `AT_PLATFORM` points at for a 32-bit guest.
const PLATFORM_ARM: &str = "armv7l\0";

/// `AT_HWCAP` for AArch64: the baseline `FEAT_*` word (`FP`, `ASIMD`, `EVTSTRM`,
/// `AES`, `PMULL`, `SHA1`, `SHA2`, `CRC32`). raxdbg offers all of them; a
/// guest that gates a codepath on one must not read a zero here.
const AARCH64_HWCAP: u64 = 0xff;

/// The ARM32 equivalent of the same baseline feature word.
const ARM_HWCAP: u64 = 0x0f;

/// Where the main program is mapped.
///
/// The address is fixed and sits between the heap ([`HEAP_BASE`]) and the
/// `mmap` arena ([`MMAP_BASE`]), so mapping it neither consumes the first
/// `mmap` slot nor lands on the stack. raxdbg is the kernel here, and the
/// kernel is what picks a main program's load bias.
const MAIN_PROGRAM_BASE: u64 = 0x0805_0000;

/// A minimal AArch64/ARM ELF image standing in for `app_process`.
///
/// Only the fields the auxv and a phdr walk can reach are filled in: the
/// header, one `PT_LOAD` covering the whole image, and one `PT_PHDR` pointing
/// back at the table. A `PT_DYNAMIC` is not needed because the guest never
/// opens this image as a shared object — it only reads its base and headers
/// to work out where the real linker sits.
pub struct MainProgram {
    /// The load bias the guest sees, which is also `AT_BASE`.
    base: u64,
    /// The address of the program header table, which is also `AT_PHDR`.
    phdr: u64,
    /// The image's entry point, which is also `AT_ENTRY`.
    entry: u64,
    /// The size of one program header, which is also `AT_PHENT`.
    phent: u64,
    /// How many program headers, which is also `AT_PHNUM`.
    phnum: u64,
    /// `AT_PLATFORM`'s string.
    platform: &'static str,
    /// `AT_HWCAP`'s word.
    hwcap: u64,
}

impl MainProgram {
    /// Maps a minimal main-program image into the guest and returns it.
    ///
    /// The image is placed at [`MAIN_PROGRAM_BASE`], a fixed address, rather
    /// than through [`Memory::mmap`]. A Linux process's main program is loaded
    /// by the kernel at a fixed bias and does not come out of the `mmap`
    /// arena; mapping it through `mmap` would hand it the arena's first slot
    /// and shift every library up by a page, changing where a packed binary
    /// ends up and breaking the offsets it baked into its own data.
    ///
    /// `is_64bit` selects the AArch64 class (`ELFCLASS64`, `EM_AARCH64`) over
    /// the 32-bit one (`ELFCLASS32`, `EM_ARM`), because a guest reading the
    /// magic checks the class byte against its own pointer width.
    pub fn map(memory: &dyn Memory, is_64bit: bool) -> Result<Self, MemoryError> {
        // Two program headers (`PT_LOAD` and `PT_PHDR`) and a 64-byte ELF
        // header, rounded up to a page: the whole thing is one `PT_LOAD`.
        let phent: u64 = if is_64bit { 56 } else { 32 };
        let phnum: u64 = 2;
        let size = (64 + phent * phnum).next_multiple_of(PAGE_SIZE);

        let base = memory.mmap2(
            MAIN_PROGRAM_BASE,
            size as usize,
            raxdbg_core::backend::Prot::READ,
            // MAP_FIXED is what makes `mmap2` honour `start`; without it the
            // address is a hint and the arena hands out its own first slot,
            // which is `MMAP_BASE` -- exactly where the first library goes.
            raxdbg_core::memory::MAP_ANONYMOUS | raxdbg_core::memory::MAP_FIXED,
            -1,
            0,
        )?;
        let phdr = base + 64;
        let program = Self {
            base,
            phdr,
            entry: base + 64 + phent * phnum,
            phent,
            phnum,
            platform: if is_64bit {
                PLATFORM_AARCH64
            } else {
                PLATFORM_ARM
            },
            hwcap: if is_64bit { AARCH64_HWCAP } else { ARM_HWCAP },
        };
        program.write(memory, base, is_64bit)?;
        Ok(program)
    }

    /// Writes the ELF header and the two program headers into the guest.
    ///
    /// A fresh mapping reads as zero, so only the bytes that carry meaning
    /// are written: the identification bytes, the class and machine, the
    /// program-header offset and count, and the two `Elf64_Phdr`/`Elf32_Phdr`
    /// records.
    ///
    /// The image is a well-formed `ET_DYN` object, which means every address
    /// it carries is *relative* to the load bias: `e_phoff` and `p_offset`
    /// are file offsets, and `p_vaddr` is a link-time address the loader
    /// adds the bias to. Writing an absolute address into any of them makes
    /// a guest that relocates the image -- which is what a linker does --
    /// compute `bias + bias + offset` and walk off into unmapped memory.
    fn write(&self, memory: &dyn Memory, base: u64, is_64bit: bool) -> Result<(), MemoryError> {
        let image = memory.pointer(base);
        // The header is 64 bytes on both classes, so the table starts right
        // after it; that file offset is what `e_phoff` and `PT_PHDR` record.
        const PHDR_OFFSET: u64 = 64;
        // `e_entry` and the two `p_vaddr`s are relative to the bias.
        let entry_offset = self.entry - self.base;
        let table_size = self.phent * self.phnum;

        // e_ident: magic, class, data (little endian), version; the OSABI and
        // ABI version stay zero (`ELFOSABI_NONE`, `EV_CURRENT`).
        image.write_bytes(0, &[0x7f, b'E', b'L', b'F'])?;
        image.write_byte(4, if is_64bit { 2 } else { 1 })?; // EI_CLASS
        image.write_byte(5, 1)?; // EI_DATA: ELFDATA2LSB
        image.write_byte(6, 1)?; // EI_VERSION: EV_CURRENT

        image.write_u16(16, 3)?; // e_type = ET_DYN
        image.write_u16(18, if is_64bit { 183 } else { 40 })?; // EM_AARCH64 / EM_ARM
        image.write_u32(20, 1)?; // e_version
        if is_64bit {
            image.write_u64(24, entry_offset)?; // e_entry
            image.write_u64(32, PHDR_OFFSET)?; // e_phoff
            image.write_u64(40, 0)?; // e_shoff
            image.write_u32(48, 0)?; // e_flags
            image.write_u16(52, 64)?; // e_ehsize
            image.write_u16(54, self.phent as u16)?; // e_phentsize
            image.write_u16(56, self.phnum as u16)?; // e_phnum
        } else {
            image.write_u32(24, entry_offset as u32)?; // e_entry
            image.write_u32(28, PHDR_OFFSET as u32)?; // e_phoff
            image.write_u32(32, 0)?; // e_shoff
            image.write_u32(36, 0)?; // e_flags
            image.write_u16(40, 52)?; // e_ehsize
            image.write_u16(42, self.phent as u16)?; // e_phentsize
            image.write_u16(44, self.phnum as u16)?; // e_phnum
        }

        // PT_LOAD covers the whole image, so a phdr walk that computes
        // `p_vaddr + bias` lands on the header it started from. That is what
        // `dl_iterate_phdr` and the phdr checks in the protected stub want.
        let load = image.share(PHDR_OFFSET, 0);
        if is_64bit {
            load.write_u32(0, 1)?; // p_type = PT_LOAD
            load.write_u32(4, 5)?; // p_flags = R|X
            load.write_u64(8, 0)?; // p_offset
            load.write_u64(16, 0)?; // p_vaddr
            load.write_u64(24, 0)?; // p_paddr
            load.write_u64(32, PAGE_SIZE)?; // p_filesz
            load.write_u64(40, PAGE_SIZE)?; // p_memsz
            load.write_u64(48, PAGE_SIZE)?; // p_align

            // PT_PHDR tells a guest where the header table lives inside the
            // image, which is what `dl_phdr_info` reads to fill its
            // `dlpi_phdr`.
            let phdr_entry = load.share(self.phent, 0);
            phdr_entry.write_u32(0, 6)?; // p_type = PT_PHDR
            phdr_entry.write_u32(4, 4)?; // p_flags = R
            phdr_entry.write_u64(8, PHDR_OFFSET)?; // p_offset
            phdr_entry.write_u64(16, PHDR_OFFSET)?; // p_vaddr
            phdr_entry.write_u64(24, PHDR_OFFSET)?; // p_paddr
            phdr_entry.write_u64(32, table_size)?; // p_filesz
            phdr_entry.write_u64(40, table_size)?; // p_memsz
            phdr_entry.write_u64(48, 8)?; // p_align
        } else {
            load.write_u32(0, 1)?; // p_type = PT_LOAD
            load.write_u32(4, 0)?; // p_offset
            load.write_u32(8, 0)?; // p_vaddr
            load.write_u32(12, 0)?; // p_paddr
            load.write_u32(16, PAGE_SIZE as u32)?; // p_filesz
            load.write_u32(20, PAGE_SIZE as u32)?; // p_memsz
            load.write_u32(24, 5)?; // p_flags = R|X
            load.write_u32(28, PAGE_SIZE as u32)?; // p_align

            let phdr_entry = load.share(self.phent, 0);
            phdr_entry.write_u32(0, 6)?; // p_type = PT_PHDR
            phdr_entry.write_u32(4, PHDR_OFFSET as u32)?; // p_offset
            phdr_entry.write_u32(8, PHDR_OFFSET as u32)?; // p_vaddr
            phdr_entry.write_u32(12, PHDR_OFFSET as u32)?; // p_paddr
            phdr_entry.write_u32(16, table_size as u32)?; // p_filesz
            phdr_entry.write_u32(20, table_size as u32)?; // p_memsz
            phdr_entry.write_u32(24, 4)?; // p_flags = R
            phdr_entry.write_u32(28, 4)?; // p_align
        }
        Ok(())
    }

    /// `AT_BASE`: the load bias of the main program.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// `AT_ENTRY`: where the main program starts executing.
    pub fn entry(&self) -> u64 {
        self.entry
    }

    /// `AT_PHDR`: the address of the program header table.
    pub fn phdr(&self) -> u64 {
        self.phdr
    }

    /// `AT_PHENT`: the size of one program header.
    pub fn phent(&self) -> u64 {
        self.phent
    }

    /// `AT_PHNUM`: how many program headers the table holds.
    pub fn phnum(&self) -> u64 {
        self.phnum
    }

    /// `AT_PLATFORM`'s string, NUL-terminated.
    pub fn platform(&self) -> &'static str {
        self.platform
    }

    /// `AT_HWCAP`'s word.
    pub fn hwcap(&self) -> u64 {
        self.hwcap
    }

    /// `AT_FLAGS`'s word.
    pub fn flags(&self) -> u64 {
        AT_FLAGS_0
    }

    /// The `(tag, value)` pairs the auxv carries, in the order the kernel
    /// writes them, before the terminating `AT_NULL`.
    ///
    /// `random` is the address of the 16 bytes `AT_RANDOM` points at; the
    /// caller owns that buffer because it is the stack canary slot.
    pub fn entries(&self, random: u64, platform_pointer: u64) -> Vec<(u64, u64)> {
        vec![
            (tag::PHDR, self.phdr),
            (tag::PHENT, self.phent),
            (tag::PHNUM, self.phnum),
            (tag::PAGESZ, PAGE_SIZE),
            (tag::BASE, self.base),
            (tag::FLAGS, self.flags()),
            (tag::ENTRY, self.entry),
            (tag::UID, UNPRIVILEGED),
            (tag::EUID, UNPRIVILEGED),
            (tag::GID, UNPRIVILEGED),
            (tag::EGID, UNPRIVILEGED),
            (tag::PLATFORM, platform_pointer),
            (tag::HWCAP, self.hwcap),
            (tag::CLKTCK, CLKTCK),
            (tag::SECURE, 0),
            (tag::RANDOM, random),
        ]
    }
}

/// The tags every process has, whether or not a main program was mapped.
///
/// `AT_RANDOM` and `AT_PAGESZ` are the two bionic reads unconditionally:
/// `__libc_init_common` dereferences `getauxval(AT_RANDOM)` with no null
/// check, and `AT_PAGESZ` is what the allocator and the `getpagesize` fast
/// path consult. A loader without a main program still has to publish both,
/// or the guest faults on its first instruction after `__libc_init`.
pub fn baseline_entries(random: u64) -> Vec<(u64, u64)> {
    vec![(tag::PAGESZ, PAGE_SIZE), (tag::RANDOM, random)]
}
