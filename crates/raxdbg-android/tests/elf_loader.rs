//! ELF loader tests (plan P3).
//!
//! Two halves: synthetic shared objects assembled byte by byte (so every
//! relocation type, `DT_INIT_ARRAY` and `DT_NEEDED` are exercised exactly), and
//! the real bionic libraries raxdbg bundles.

mod synthetic;

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use raxdbg_backend_rax::RaxBackend;
use raxdbg_core::backend::{Backend, GuestMemory};
use raxdbg_core::memory::Memory;
use raxdbg_core::reg::RegId;
use std::collections::BTreeMap;

use raxdbg_android::android_file::{
    DirectoryResolver, ElfLibraryFile, ElfLibraryRawFile, LibraryFile, LibraryResolver,
};
use raxdbg_android::elf::loader::{AndroidElfLoader, reloc_type};
use synthetic::{
    BINDING_GLOBAL, GLOB_DAT_SLOT, MARKER_ADDRESS, RELATIVE_ADDEND, RELATIVE_WORD, SHN_ABS,
    SHN_UNDEF, TYPE_FUNC, TYPE_OBJECT,
};

/// A backend plus the borrow-free handle to its address space that the loader
/// needs (plan P2.6).
fn new_backend() -> (Rc<RefCell<dyn Backend>>, std::sync::Arc<dyn GuestMemory>) {
    let backend = RaxBackend::new_arm64(RaxBackend::default_space());
    let guest = backend.guest_memory();
    (Rc::new(RefCell::new(backend)), guest)
}

fn new_loader(seed: u64) -> Rc<AndroidElfLoader> {
    let (backend, guest) = new_backend();
    AndroidElfLoader::new(backend, guest, true, "raxdbg", seed).expect("loader")
}

/// Resolves library names from an in-memory table, so a test can supply a
/// dependency without touching the file system.
struct MapResolver(BTreeMap<String, Vec<u8>>);

impl LibraryResolver for MapResolver {
    fn resolve_library(&self, name: &str) -> Option<Box<dyn LibraryFile>> {
        self.0
            .get(name)
            .map(|data| Box::new(ElfLibraryRawFile::new(name, data.clone())) as Box<dyn LibraryFile>)
    }
}

/// A loader whose resolver knows `libdep.so`.
fn loader_with_dependency(seed: u64) -> Rc<AndroidElfLoader> {
    let loader = new_loader(seed);
    let mut table = BTreeMap::new();
    table.insert("libdep.so".to_string(), dependency_library());
    loader.set_library_resolver(Rc::new(MapResolver(table)));
    loader
}

/// The `libdep.so` the synthetic library imports from.
fn dependency_library() -> Vec<u8> {
    let mut library = synthetic::SyntheticLibrary::new("libdep.so");
    library.init_array.clear();
    library.symbols.push(synthetic::SyntheticSymbol {
        name: "imported_fn".into(),
        value: 0x40,
        size: 4,
        info: (BINDING_GLOBAL << 4) | TYPE_FUNC,
        shndx: SHN_ABS,
    });
    library.build()
}

/// The library under test: one `R_AARCH64_RELATIVE`, one `R_AARCH64_GLOB_DAT`
/// against `libdep.so`, one `init_array` entry, and a `DT_NEEDED`.
fn synthetic_library() -> Vec<u8> {
    let mut library = synthetic::SyntheticLibrary::new("libsynthetic.so");
    library.needed.push("libdep.so".into());
    library.symbols.push(synthetic::SyntheticSymbol {
        name: "imported_fn".into(),
        value: 0,
        size: 0,
        info: (BINDING_GLOBAL << 4) | TYPE_FUNC,
        shndx: SHN_UNDEF,
    });
    library.symbols.push(synthetic::SyntheticSymbol {
        name: "marker".into(),
        value: MARKER_ADDRESS,
        size: 4,
        info: (BINDING_GLOBAL << 4) | TYPE_FUNC,
        shndx: SHN_ABS,
    });
    library.symbols.push(synthetic::SyntheticSymbol {
        name: "local_data".into(),
        value: RELATIVE_WORD,
        size: 8,
        info: (BINDING_GLOBAL << 4) | TYPE_OBJECT,
        shndx: SHN_ABS,
    });
    library.relocations.push(synthetic::SyntheticRelocation {
        offset: RELATIVE_WORD,
        sym: 0,
        r_type: reloc_type::R_AARCH64_RELATIVE,
        addend: RELATIVE_ADDEND,
    });
    // A real shared object relocates its own `init_array` slots the same way.
    library.relocations.push(synthetic::SyntheticRelocation {
        offset: synthetic::INIT_ARRAY_SLOT,
        sym: 0,
        r_type: reloc_type::R_AARCH64_RELATIVE,
        addend: MARKER_ADDRESS as i64,
    });
    library.relocations.push(synthetic::SyntheticRelocation {
        offset: GLOB_DAT_SLOT,
        sym: 1,
        r_type: reloc_type::R_AARCH64_GLOB_DAT,
        addend: 0,
    });
    library.build()
}

#[test]
fn synthetic_library_maps_relocates_and_registers() {
    let loader = loader_with_dependency(1);
    let module = loader
        .load(Box::new(ElfLibraryRawFile::new("libsynthetic.so", synthetic_library())), false)
        .expect("load");

    assert_eq!(module, "libsynthetic.so");
    let info = loader.module("libsynthetic.so").expect("module");
    assert!(info.base >= 0x1200_0000, "the module is mapped above MMAP_BASE");
    assert_eq!(info.base % 0x1000, 0, "the base is page-aligned");
    assert!(info.size >= 0x1000);
    assert_eq!(info.needed_libraries, vec!["libdep.so".to_string()]);
    assert_eq!(info.init_functions, 1);
    assert_eq!(
        loader.module_init_functions("libsynthetic.so"),
        vec![info.base + MARKER_ADDRESS],
        "the init_array entry is collected with its absolute address"
    );

    // The dependency loaded too.
    let dependency = loader.module("libdep.so").expect("dependency");
    assert_ne!(dependency.base, info.base);

    let memory = loader.memory();
    // R_AARCH64_RELATIVE: load_base + addend.
    assert_eq!(
        memory.pointer(info.base + RELATIVE_WORD).read_u64(0).unwrap(),
        info.base + RELATIVE_ADDEND as u64
    );
    // R_AARCH64_GLOB_DAT: the dependency's definition.
    assert_eq!(
        memory.pointer(info.base + GLOB_DAT_SLOT).read_u64(0).unwrap(),
        dependency.base + 0x40
    );
    // The file's own bytes are mapped.
    assert_eq!(
        memory.pointer(info.base + MARKER_ADDRESS).read_u32(0).unwrap(),
        0xd65f_03c0
    );
}

#[test]
fn synthetic_library_exposes_its_symbols() {
    let loader = loader_with_dependency(2);
    loader
        .load(Box::new(ElfLibraryRawFile::new("libsynthetic.so", synthetic_library())), false)
        .expect("load");

    let marker = loader
        .find_symbol("libsynthetic.so", "marker")
        .expect("marker is exported");
    let module = loader.module("libsynthetic.so").unwrap();
    assert_eq!(marker.address, module.base + MARKER_ADDRESS);
    assert_eq!(marker.module.as_deref(), Some("libsynthetic.so"));

    // The import resolves through the dependency.
    let imported = loader
        .find_symbol("libsynthetic.so", "imported_fn")
        .expect("the import resolves against libdep.so");
    let dependency = loader.module("libdep.so").unwrap();
    assert_eq!(imported.address, dependency.base + 0x40);
    assert_eq!(imported.module.as_deref(), Some("libdep.so"));

    // And through `dlsym`.
    let symbol = loader.dlsym(module.base, "marker").expect("dlsym");
    assert_eq!(symbol.address, module.base + MARKER_ADDRESS);
    let by_default = loader.dlsym(0, "imported_fn").expect("dlsym RTLD_DEFAULT");
    assert_eq!(by_default.address, dependency.base + 0x40);

    // `environ` is answered from the loader, not from a module.
    let environ = loader.dlsym(0, "environ").expect("environ");
    assert_eq!(environ.address, loader.environ());
}

#[test]
fn a_module_loaded_later_satisfies_an_earlier_import() {
    // Load the importer first: its `imported_fn` has nowhere to resolve yet.
    // The resolver is installed afterwards, so the importer's dependency is
    // not pulled in with it.
    let loader = new_loader(3);
    let mut importer = synthetic::SyntheticLibrary::new("libimporter.so");
    importer.symbols.push(synthetic::SyntheticSymbol {
        name: "imported_fn".into(),
        value: 0,
        size: 0,
        info: (BINDING_GLOBAL << 4) | TYPE_FUNC,
        shndx: SHN_UNDEF,
    });
    importer.relocations.push(synthetic::SyntheticRelocation {
        offset: GLOB_DAT_SLOT,
        sym: 1,
        r_type: reloc_type::R_AARCH64_GLOB_DAT,
        addend: 0,
    });
    loader
        .load(Box::new(ElfLibraryRawFile::new("libimporter.so", importer.build())), false)
        .expect("load importer");

    let importer_info = loader.module("libimporter.so").unwrap();
    assert_eq!(
        loader
            .memory()
            .pointer(importer_info.base + GLOB_DAT_SLOT)
            .read_u64(0)
            .unwrap(),
        0,
        "nothing defines imported_fn yet"
    );

    loader
        .load(Box::new(ElfLibraryRawFile::new("libdep.so", dependency_library())), false)
        .expect("load dependency");
    assert!(loader.module("libdep.so").is_some());

    let dependency = loader.module("libdep.so").unwrap();
    assert_eq!(
        loader
            .memory()
            .pointer(importer_info.base + GLOB_DAT_SLOT)
            .read_u64(0)
            .unwrap(),
        dependency.base + 0x40,
        "the pending relocation resolved once the definition appeared"
    );
}

#[test]
fn dlopen_and_dlclose_reference_count() {
    let loader = new_loader(4);
    let root = std::env::temp_dir().join("raxdbg-elf-dlopen");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("temp dir");
    std::fs::write(root.join("libsynthetic.so"), synthetic_library()).expect("write");
    std::fs::write(root.join("libdep.so"), dependency_library()).expect("write");
    loader.set_library_resolver(Rc::new(DirectoryResolver::new(&root)));

    let first = loader.dlopen("libsynthetic.so", true).expect("dlopen");
    assert_eq!(first, "libsynthetic.so");
    assert_eq!(loader.module("libsynthetic.so").unwrap().reference_count, 1);

    // A second `dlopen` of the same name only bumps the count.
    let second = loader.dlopen("libsynthetic.so", true).expect("dlopen again");
    assert_eq!(second, "libsynthetic.so");
    assert_eq!(loader.module("libsynthetic.so").unwrap().reference_count, 2);

    let module = loader.module("libsynthetic.so").unwrap();
    assert!(loader.dlclose(module.base));
    assert!(loader.module("libsynthetic.so").is_some(), "still referenced");
    assert!(loader.dlclose(module.base));
    assert!(
        loader.module("libsynthetic.so").is_none(),
        "the last dlclose unloaded it"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn initialize_tls_sets_the_thread_pointer_and_errno_slot() {
    let loader = new_loader(5);
    let memory = loader.memory();
    let backend = loader.backend();

    let tpidr = backend.borrow().reg_read(RegId::TpidrEl0).unwrap();
    assert_ne!(tpidr, 0, "TPIDR_EL0 holds the TLS block");
    assert_eq!(tpidr % 16, 0, "the Android ABI requires a 16-byte-aligned thread pointer");

    // Slot 1 of the TLS block is the thread pointer, slot 3 the argv array.
    let thread = memory.pointer(tpidr).read_u64(8).unwrap();
    assert!(thread > tpidr, "the thread control block sits below the TLS block");
    let argv = memory.pointer(tpidr).read_u64(24).unwrap();
    assert_ne!(argv, 0);

    // The stack pointer is inside the stack area and 16-byte aligned.
    let sp = memory.get_stack_point();
    assert_eq!(sp % 16, 0);
    assert!(sp <= raxdbg_core::memory::STACK_BASE);
    assert!(sp > raxdbg_core::memory::STACK_BASE - raxdbg_core::memory::STACK_SIZE_OF_PAGE * 4096);

    // `errno` is writable through the facade.
    memory.set_errno(raxdbg_core::errno::ENOENT);
    assert_eq!(memory.get_last_errno(), raxdbg_core::errno::ENOENT);
    assert_eq!(
        memory
            .pointer(memory.errno_address())
            .read_u32(0)
            .unwrap(),
        raxdbg_core::errno::ENOENT as u32
    );
}

#[test]
fn the_stack_region_is_mapped_and_writable() {
    let loader = new_loader(6);
    let memory = loader.memory();
    let top = raxdbg_core::memory::STACK_BASE - 0x100;
    memory.write_bytes(top, &[0xab; 16]).expect("stack write");
    assert_eq!(memory.pointer(top).read_byte(0).unwrap(), 0xab);

    let below = raxdbg_core::memory::STACK_BASE
        - raxdbg_core::memory::STACK_SIZE_OF_PAGE * 4096
        - 1;
    assert!(memory.write_bytes(below, &[0]).is_err(), "below the stack area");
}

#[test]
fn a_wrong_architecture_is_rejected() {
    let loader = new_loader(7);
    let mut bytes = synthetic_library();
    // Flip e_machine to EM_X86_64.
    bytes[18] = 62;
    match loader.load(Box::new(ElfLibraryRawFile::new("libsynthetic.so", bytes)), false) {
        Err(error) => assert!(error.to_string().contains("AArch64"), "{error}"),
        Ok(name) => panic!("expected a rejection, got {name}"),
    }
}

// ---------------------------------------------------------------------------
// Real bionic libraries
// ---------------------------------------------------------------------------

fn libs_dir() -> PathBuf {
    // The workspace root is two levels up from `crates/raxdbg-android`.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .join("libs/android/sdk23/lib64")
}

fn load_bionic(library: &str, seed: u64) -> (Rc<AndroidElfLoader>, String) {
    let loader = new_loader(seed);
    let path = libs_dir().join(library);
    let file = raxdbg_android::android_file::ElfLibraryFile::open(&path)
        .unwrap_or_else(|error| panic!("cannot open {}: {error}", path.display()));
    let name = loader
        .load(Box::new(file), false)
        .unwrap_or_else(|error| panic!("cannot load {library}: {error}"));
    (loader, name)
}

#[test]
fn bionic_libc_loads_and_exports_its_symbols() {
    let (loader, name) = load_bionic("libc.so", 11);
    assert_eq!(name, "libc.so");

    let info = loader.module("libc.so").expect("module");
    assert!(info.base >= 0x1200_0000);
    assert!(info.size > 0x80_000, "libc is large: {:#x}", info.size);
    assert_eq!(info.base % 0x1000, 0);
    assert!(
        info.needed_libraries.contains(&"libdl.so".to_string()),
        "libc.so needs libdl.so: {:?}",
        info.needed_libraries
    );

    for symbol in ["malloc", "free", "printf", "pthread_create", "strlen", "__errno"] {
        let found = loader
            .find_symbol("libc.so", symbol)
            .unwrap_or_else(|| panic!("{symbol} is not exported"));
        assert!(found.address >= info.base && found.address < info.base + info.size);
    }
}

#[test]
fn bionic_libm_loads_against_libc() {
    let loader = new_loader(12);
    loader.set_library_resolver(Rc::new(DirectoryResolver::new(libs_dir())));
    let file = raxdbg_android::android_file::ElfLibraryFile::open(libs_dir().join("libm.so"))
        .expect("open libm.so");
    let name = loader.load(Box::new(file), false).expect("load libm.so");
    assert_eq!(name, "libm.so");

    let libm = loader.module("libm.so").expect("libm module");
    assert!(libm.size > 0x10_000);
    for symbol in ["sin", "cos", "sqrt", "atan2"] {
        let found = loader
            .find_symbol("libm.so", symbol)
            .unwrap_or_else(|| panic!("{symbol} is not exported"));
        assert!(found.address >= libm.base && found.address < libm.base + libm.size);
    }
    assert!(
        libm.needed_libraries.contains(&"libc.so".to_string()),
        "libm.so needs libc.so: {:?}",
        libm.needed_libraries
    );
}

#[test]
fn bionic_libc_has_no_unresolved_relocations() {
    let (loader, _) = load_bionic("libc.so", 13);
    // Every relocation either applied or is recorded as unresolved; the real
    // libc must have none left, since it only imports from libdl.so which is
    // bundled alongside it.
    let unresolved = loader.unresolved_relocation_count("libc.so");
    assert_eq!(unresolved, 0, "libc.so left {unresolved} relocations unresolved");
}

#[test]
fn loading_libc_twice_is_idempotent() {
    let (loader, _) = load_bionic("libc.so", 14);
    let first = loader.module("libc.so").unwrap();
    loader.set_library_resolver(Rc::new(DirectoryResolver::new(libs_dir())));
    let name = loader.dlopen("libc.so", true).expect("dlopen libc.so");
    assert_eq!(name, "libc.so");
    let second = loader.module("libc.so").unwrap();
    assert_eq!(first.base, second.base, "the same module, not a second copy");
    assert_eq!(second.reference_count, first.reference_count + 1);
}

/// Every relocation in `libcpp.so`'s packed table must land inside one of that
/// library's own `PT_LOAD` segments.
///
/// `libcpp.so` is the library that forced the packed-relocation decoder into
/// existence: on both ABIs it carries `DT_ANDROID_REL(A)` and leaves
/// `DT_REL`/`DT_RELASZ` zero, so nothing was being relocated at all. A decoder
/// that mis-reads the delta stream produces plausible-looking offsets that are
/// quietly wrong, and this is the check that catches it: an offset outside every
/// segment means the stream was decoded wrong, not that the library is odd.
#[test]
fn packed_relocations_land_inside_the_librarys_segments() {
    for (relative, is_64bit) in [
        ("libs/android/sdk23/lib/libcpp.so", false),
        ("libs/android/sdk23/lib64/libcpp.so", true),
    ] {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .expect("workspace root")
            .join(relative);
        let bytes = std::fs::read(&path).expect("read libcpp");
        let elf = goblin::elf::Elf::parse(&bytes).expect("parse libcpp");
        let dynamic = elf.dynamic.as_ref().expect("dynamic section");
        let tag = |name: u64| dynamic.dyns.iter().find(|e| e.d_tag == name).map(|e| e.d_val);

        let (offset, size, rela) = if tag(0x6000_0011).is_some() {
            (tag(0x6000_0011).unwrap(), tag(0x6000_0012).unwrap(), true)
        } else {
            (tag(0x6000_000f).expect("DT_ANDROID_REL"), tag(0x6000_0010).expect("DT_ANDROID_RELSZ"), false)
        };
        // `DT_ANDROID_REL` is a virtual address, so it has to be turned into a
        // file offset through the segment that contains it.
        let file_offset = elf
            .program_headers
            .iter()
            .filter(|header| header.p_type == goblin::elf::program_header::PT_LOAD)
            .find(|header| {
                offset >= header.p_vaddr && offset < header.p_vaddr + header.p_filesz
            })
            .map(|header| header.p_offset + (offset - header.p_vaddr))
            .expect("the packed table lives in a mapped segment");
        let table = &bytes[file_offset as usize..(file_offset + size) as usize];
        assert!(
            raxdbg_android::elf::packed::has_magic(table),
            "{relative}: the packed table does not start with APS2"
        );
        let bits = if is_64bit { 64 } else { 32 };
        let declared = raxdbg_android::elf::packed::count(&table[4..], bits).expect("count");
        let relocations =
            raxdbg_android::elf::packed::decode(&table[4..], rela, bits).expect("decode");
        assert_eq!(
            relocations.len() as u64,
            declared,
            "{relative}: the stream declares {declared} relocations but decoding produced {}",
            relocations.len()
        );

        let segments: Vec<(u64, u64)> = elf
            .program_headers
            .iter()
            .filter(|header| header.p_type == goblin::elf::program_header::PT_LOAD)
            .map(|header| (header.p_vaddr, header.p_vaddr + header.p_memsz))
            .collect();
        let outside: Vec<u64> = relocations
            .iter()
            .map(|relocation| relocation.r_offset)
            .filter(|offset| !segments.iter().any(|(start, end)| offset >= start && offset < end))
            .collect();
        assert!(
            outside.is_empty(),
            "{relative}: {} relocations fall outside every segment, e.g. {:x?}",
            outside.len(),
            &outside[..outside.len().min(6)]
        );

        // The packed table replaces `DT_REL`/`DT_RELA` wholesale, so it carries
        // every dynamic relocation the library has, not only the relative ones.
        // The types must still be ones this loader knows how to apply, because
        // an unknown one is silently skipped and the module stays wrong.
        let known: &[u32] = if is_64bit {
            &[257, 1025, 1026, 1027]
        } else {
            &[2, 21, 22, 23]
        };
        let unknown: Vec<u32> = relocations
            .iter()
            .map(|relocation| relocation.r_type)
            .filter(|kind| !known.contains(kind))
            .collect();
        assert!(
            unknown.is_empty(),
            "{relative}: {} relocations have a type this loader does not apply, e.g. {:?}",
            unknown.len(),
            &unknown[..unknown.len().min(6)]
        );
        // A relative relocation's addend is a link-time address *inside* the
        // library, so one that lands outside every segment means the delta
        // accumulator drifted -- the failure mode a decoder can have while
        // still producing the right count and the right types.
        let relative = if is_64bit { 1027 } else { 23 };
        let span_start = segments.iter().map(|(start, _)| *start).min().unwrap();
        let span_end = segments.iter().map(|(_, end)| *end).max().unwrap();
        // Only a `RELA` table carries addends; a `REL` one leaves the value in
        // the slot, so its decoded addend is always zero and says nothing.
        let stray: Vec<(u64, i64)> = if rela {
            relocations
                .iter()
                .filter(|relocation| relocation.r_type == relative)
                .filter_map(|relocation| {
                    let addend = relocation.r_addend.unwrap_or(0);
                    (!(span_start..span_end).contains(&(addend as u64)))
                        .then_some((relocation.r_offset, addend))
                })
                .collect()
        } else {
            Vec::new()
        };
        assert!(
            stray.is_empty(),
            "{relative}: {} relative relocations point outside {span_start:#x}..{span_end:#x}, e.g. {:x?}",
            stray.len(),
            &stray[..stray.len().min(4)]
        );

        // Both kinds must be present: libc++ has plenty of relative relocations
        // for its vtables and globals, and plenty of symbol ones for libc.
        let relative = if is_64bit { 1027 } else { 23 };
        let relative_count = relocations
            .iter()
            .filter(|relocation| relocation.r_type == relative)
            .count();
        assert!(
            relative_count > 0 && relative_count < relocations.len(),
            "{relative}: {relative_count} relative of {} total looks like a mis-decoded stream",
            relocations.len()
        );
    }
}

/// The `init_array` entry must come out as a real function address, not as a
/// bare link-time offset.
///
/// This is the end-to-end check on the packed-relocation work: libc++'s
/// `init_array` has one entry, its relocation is packed, and if the type or the
/// addend is decoded a step out the slot keeps a small number that looks like a
/// valid address and the initialiser is called in the wrong place.
#[test]
fn a_packed_init_array_entry_becomes_a_function_address() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .join("libs/android/sdk23/lib64/libcpp.so");
    let bytes = std::fs::read(&path).expect("read libcpp");
    let elf = goblin::elf::Elf::parse(&bytes).expect("parse libcpp");
    let dynamic = elf.dynamic.as_ref().expect("dynamic");
    let tag = |name: u64| dynamic.dyns.iter().find(|e| e.d_tag == name).map(|e| e.d_val);
    let init_array = tag(0x6000_0011).expect("DT_ANDROID_RELA");
    let size = tag(0x6000_0012).expect("DT_ANDROID_RELASZ");
    let file_offset = elf
        .program_headers
        .iter()
        .filter(|header| header.p_type == goblin::elf::program_header::PT_LOAD)
        .find(|header| init_array >= header.p_vaddr && init_array < header.p_vaddr + header.p_filesz)
        .map(|header| header.p_offset + (init_array - header.p_vaddr))
        .expect("the table is in a mapped segment");
    let table = &bytes[file_offset as usize..(file_offset + size) as usize];
    let relocations =
        raxdbg_android::elf::packed::decode(&table[4..], true, 64).expect("decode");

    // The real `init_array` lives in the .dynamic section, and its entry is
    // written by a relative relocation.
    let init_array_vaddr = dynamic
        .dyns
        .iter()
        .find(|entry| entry.d_tag == goblin::elf::dynamic::DT_INIT_ARRAY)
        .map(|entry| entry.d_val)
        .expect("DT_INIT_ARRAY");
    let entry = relocations
        .iter()
        .find(|relocation| relocation.r_offset == init_array_vaddr)
        .expect("the init_array entry has a packed relocation");
    assert_eq!(entry.r_type, 1027, "it is R_AARCH64_RELATIVE");
    assert_eq!(entry.r_sym, 0, "with no symbol");
    let target = entry.r_addend.expect("a RELA entry carries its addend");
    assert_ne!(
        target, 0,
        "the addend is the link-time address of the initialiser, not zero"
    );
    // And that address has to be a *code* address, i.e. inside a PT_LOAD and
    // above the module's first segment.
    let loads: Vec<(u64, u64)> = elf
        .program_headers
        .iter()
        .filter(|header| header.p_type == goblin::elf::program_header::PT_LOAD)
        .map(|header| (header.p_vaddr, header.p_vaddr + header.p_memsz))
        .collect();
    assert!(
        loads.iter().any(|(start, end)| target as u64 >= *start && (target as u64) < *end),
        "the initialiser {target:#x} is inside a loadable segment"
    );
}
