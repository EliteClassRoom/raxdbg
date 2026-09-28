//! A minimal AArch64 shared object, assembled byte by byte.
#![allow(dead_code)]

//!
//! The plan asks for synthetic ELF fixtures built at test time. `object`'s
//! writer does not emit a dynamic table (`DT_NEEDED`, `DT_INIT_ARRAY`, dynamic
//! relocations), which is exactly what these tests must exercise, so the file
//! is laid out here instead: one `PT_LOAD` covering the whole file from virtual
//! address 0 (so a `DT_*` pointer is both a file offset and a virtual address,
//! as in a real shared object), plus a `PT_DYNAMIC`.

/// A symbol the test's synthetic library defines or imports.
pub struct SyntheticSymbol {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub info: u8,
    pub shndx: u16,
}

/// One `R_AARCH64_*` relocation to emit.
pub struct SyntheticRelocation {
    pub offset: u64,
    pub sym: usize,
    pub r_type: u32,
    pub addend: i64,
}

/// A relocation type the builder can emit.
pub mod reloc {
    /// `R_AARCH64_ABS64`.
    pub const ABS64: u32 = 257;
    /// `R_AARCH64_GLOB_DAT`.
    pub const GLOB_DAT: u32 = 1025;
    /// `R_AARCH64_JUMP_SLOT`.
    pub const JUMP_SLOT: u32 = 1026;
    /// `R_AARCH64_RELATIVE`.
    pub const RELATIVE: u32 = 1027;
}

/// `STB_GLOBAL`.
pub const BINDING_GLOBAL: u8 = 1;
/// `STB_WEAK`.
pub const BINDING_WEAK: u8 = 2;
/// `STT_FUNC`.
pub const TYPE_FUNC: u8 = 2;
/// `STT_OBJECT`.
pub const TYPE_OBJECT: u8 = 1;
/// `SHN_UNDEF`.
pub const SHN_UNDEF: u16 = 0;
/// `SHN_ABS`.
pub const SHN_ABS: u16 = 0xfff1;

const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;
const DYNAMIC_ENTRY: u64 = 16;
const SYM_SIZE: usize = 24;
const RELA_SIZE: usize = 24;

/// Fixed file offsets (which are also virtual addresses) of each table.
const OFF_PHDR: usize = EHDR_SIZE;
const OFF_CODE: usize = 0x100;
const OFF_INIT_ARRAY: usize = 0x180;
const OFF_RELATIVE_WORD: usize = 0x188;
const OFF_GLOB_DAT_SLOT: usize = 0x190;
// goblin sizes the dynamic symbol table from the gap between `DT_SYMTAB` and
// `DT_STRTAB`, so the string table must follow the symbols, as in a real file.
const OFF_DYNSYM: usize = 0x200;
const OFF_DYNSTR: usize = 0x300;
const OFF_HASH: usize = 0x380;
const OFF_RELA: usize = 0x400;
const OFF_DYNAMIC: usize = 0x500;

/// The address the initialiser's code lives at.
pub const MARKER_ADDRESS: u64 = OFF_CODE as u64;
/// The address of the first `init_array` slot.
pub const INIT_ARRAY_SLOT: u64 = OFF_INIT_ARRAY as u64;
/// The address of the word the `R_AARCH64_RELATIVE` relocation rewrites.
pub const RELATIVE_WORD: u64 = OFF_RELATIVE_WORD as u64;
/// The address of the slot the `R_AARCH64_GLOB_DAT` relocation rewrites.
pub const GLOB_DAT_SLOT: u64 = OFF_GLOB_DAT_SLOT as u64;
/// The `R_AARCH64_RELATIVE` addend.
pub const RELATIVE_ADDEND: i64 = 0x1234;

/// Builds a shared object with the requested symbols and relocations.
pub struct SyntheticLibrary {
    pub name: String,
    pub needed: Vec<String>,
    pub symbols: Vec<SyntheticSymbol>,
    pub relocations: Vec<SyntheticRelocation>,
    pub init_array: Vec<u64>,
    pub code: Vec<u32>,
}

impl SyntheticLibrary {
    /// A library named `name` with a two-instruction body and one initialiser.
    pub fn new(name: &str) -> Self {
        SyntheticLibrary {
            name: name.to_string(),
            needed: Vec::new(),
            symbols: Vec::new(),
            relocations: Vec::new(),
            init_array: vec![MARKER_ADDRESS],
            // `ret`, then padding; the marker's address is the first word.
            code: vec![0xd65f_03c0, 0xd503_201f],
        }
    }

    /// Assembles the file.
    pub fn build(&self) -> Vec<u8> {
        let dynstr = self.build_dynstr();
        let dynamic_len = (self.dynamic_entries(&dynstr).len() as u64) * DYNAMIC_ENTRY;
        let file_size = OFF_DYNAMIC + dynamic_len as usize;
        let mut file = vec![0u8; file_size];

        // ---- ELF header ----
        file[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        file[4] = 2; // ELFCLASS64
        file[5] = 1; // ELFDATA2LSB
        file[6] = 1; // EV_CURRENT
        put_u16(&mut file, 16, 3); // ET_DYN
        put_u16(&mut file, 18, 183); // EM_AARCH64
        put_u32(&mut file, 20, 1); // EV_CURRENT
        put_u64(&mut file, 24, 0); // e_entry
        put_u64(&mut file, 32, OFF_PHDR as u64); // e_phoff
        put_u64(&mut file, 40, 0); // e_shoff
        put_u32(&mut file, 48, 0); // e_flags
        put_u16(&mut file, 52, EHDR_SIZE as u16);
        put_u16(&mut file, 54, PHDR_SIZE as u16);
        put_u16(&mut file, 56, 2); // e_phnum
        put_u16(&mut file, 58, 64);
        put_u16(&mut file, 60, 0);
        put_u16(&mut file, 62, 0);

        // ---- program headers ----
        // PT_LOAD covering the whole file, readable, writable and executable so
        // the test can watch every kind of write.
        put_u32(&mut file, OFF_PHDR, 1);
        put_u32(&mut file, OFF_PHDR + 4, 7);
        put_u64(&mut file, OFF_PHDR + 8, 0);
        put_u64(&mut file, OFF_PHDR + 16, 0);
        put_u64(&mut file, OFF_PHDR + 24, 0);
        put_u64(&mut file, OFF_PHDR + 32, file_size as u64);
        put_u64(&mut file, OFF_PHDR + 40, file_size as u64);
        put_u64(&mut file, OFF_PHDR + 48, 0x1000);

        // PT_DYNAMIC
        let phdr1 = OFF_PHDR + PHDR_SIZE;
        put_u32(&mut file, phdr1, 2);
        put_u32(&mut file, phdr1 + 4, 6);
        put_u64(&mut file, phdr1 + 8, OFF_DYNAMIC as u64);
        put_u64(&mut file, phdr1 + 16, OFF_DYNAMIC as u64);
        put_u64(&mut file, phdr1 + 24, OFF_DYNAMIC as u64);
        put_u64(&mut file, phdr1 + 32, dynamic_len);
        put_u64(&mut file, phdr1 + 40, dynamic_len);
        put_u64(&mut file, phdr1 + 48, 8);

        // ---- code, init array, data ----
        for (index, word) in self.code.iter().enumerate() {
            put_u32(&mut file, OFF_CODE + index * 4, *word);
        }
        for (index, address) in self.init_array.iter().enumerate() {
            put_u64(&mut file, OFF_INIT_ARRAY + index * 8, *address);
        }
        put_u64(&mut file, OFF_RELATIVE_WORD, RELATIVE_ADDEND as u64);

        // ---- dynamic string table ----
        file[OFF_DYNSTR..OFF_DYNSTR + dynstr.len()].copy_from_slice(&dynstr);

        // ---- dynamic symbol table ----
        // Index 0 is the reserved null symbol, as the ELF spec requires and as
        // every relocation against section 0 assumes.
        let mut sym_index = OFF_DYNSYM + SYM_SIZE;
        for symbol in self.symbols.iter() {
            let name_offset = self.name_offset(&dynstr, &symbol.name);
            put_u32(&mut file, sym_index, name_offset);
            file[sym_index + 4] = symbol.info;
            file[sym_index + 5] = 0;
            put_u16(&mut file, sym_index + 6, symbol.shndx);
            put_u64(&mut file, sym_index + 8, symbol.value);
            put_u64(&mut file, sym_index + 16, symbol.size);
            sym_index += SYM_SIZE;
        }

        // ---- SYSV hash table ----
        // goblin sizes the dynamic symbol table from `DT_GNU_HASH` or
        // `DT_HASH`, so a file without one would report no symbols at all.
        let symbol_count = self.symbols.len() as u32 + 1;
        put_u32(&mut file, OFF_HASH, 1); // nbucket
        put_u32(&mut file, OFF_HASH + 4, symbol_count); // nchain
        // One bucket, then one chain entry per symbol, all zero: the table is
        // only here to declare the symbol count.
        for index in 0..(1 + symbol_count as usize) {
            put_u32(&mut file, OFF_HASH + 8 + index * 4, 0);
        }

        // ---- relocations ----
        let mut rela = OFF_RELA;
        for relocation in &self.relocations {
            put_u64(&mut file, rela, relocation.offset);
            let info = ((relocation.sym as u64) << 32) | u64::from(relocation.r_type);
            put_u64(&mut file, rela + 8, info);
            put_u64(&mut file, rela + 16, relocation.addend as u64);
            rela += RELA_SIZE;
        }

        // ---- dynamic table ----
        let mut entry = OFF_DYNAMIC;
        for (tag, value) in self.dynamic_entries(&dynstr) {
            put_u64(&mut file, entry, tag);
            put_u64(&mut file, entry + 8, value);
            entry += DYNAMIC_ENTRY as usize;
        }

        file
    }

    fn build_dynstr(&self) -> Vec<u8> {
        let mut table = vec![0u8];
        for name in self
            .symbols
            .iter()
            .map(|symbol| symbol.name.as_str())
            .chain(self.needed.iter().map(String::as_str))
            .chain(std::iter::once(self.name.as_str()))
        {
            table.extend_from_slice(name.as_bytes());
            table.push(0);
        }
        table
    }

    fn name_offset(&self, table: &[u8], name: &str) -> u32 {
        let needle = name.as_bytes();
        for start in 0..table.len() {
            if table[start..].starts_with(needle)
                && table.get(start + needle.len()) == Some(&0)
                && (start == 0 || table[start - 1] == 0)
            {
                return start as u32;
            }
        }
        0
    }

    fn soname_offset(&self, table: &[u8]) -> u64 {
        u64::from(self.name_offset(table, &self.name))
    }

    fn dynamic_entries(&self, table: &[u8]) -> Vec<(u64, u64)> {
        let mut entries = Vec::new();
        for needed in &self.needed {
            entries.push((1, u64::from(self.name_offset(table, needed))));
        }
        entries.push((14, self.soname_offset(table))); // DT_SONAME
        entries.push((5, OFF_DYNSTR as u64)); // DT_STRTAB
        entries.push((10, table.len() as u64)); // DT_STRSZ
        entries.push((6, OFF_DYNSYM as u64)); // DT_SYMTAB
        entries.push((11, SYM_SIZE as u64)); // DT_SYMENT
        entries.push((4, OFF_HASH as u64)); // DT_HASH
        if !self.relocations.is_empty() {
            entries.push((7, OFF_RELA as u64)); // DT_RELA
            entries.push((8, (self.relocations.len() * RELA_SIZE) as u64)); // DT_RELASZ
            entries.push((9, RELA_SIZE as u64)); // DT_RELAENT
        }
        if !self.init_array.is_empty() {
            entries.push((25, OFF_INIT_ARRAY as u64)); // DT_INIT_ARRAY
            entries.push((27, (self.init_array.len() * 8) as u64)); // DT_INIT_ARRAYSZ
        }
        entries.push((0, 0)); // DT_NULL
        entries
    }
}

fn put_u16(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
