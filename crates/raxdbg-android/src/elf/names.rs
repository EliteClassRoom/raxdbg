//! Naming guest addresses for a trace or a fault report.
//!
//! Port of unidbg: the `module`/`symbol` half of
//! `unidbg-api/src/main/java/com/github/unidbg/debugger/Debugger.java` and the
//! call-site naming in `AbstractARM64Emulator`'s trace hooks, @7f5da98e.
//!
//! A raw address says nothing on its own: the interesting half of a call log is
//! *which* API the guest reached for, and the interesting half of a fault is
//! which function it died in. Three kinds of address need three different
//! answers, and getting them the wrong way round produces a plausible lie:
//!
//! * a **host service** lives on the SVC page and belongs to no ELF, so only
//!   the label the stub page recorded names it (`JNIEnv!GetMethodID.305`);
//! * a **branch target** is a function entry, so only an exact symbol may name
//!   it -- a nearest-symbol name would point at the wrong function;
//! * a **branch instruction** sits inside a function, so the nearest symbol
//!   below it is exactly right.
//!
//! [`name_callee`] and [`name_caller`] encode that split.

use raxdbg_core::backend::Backend;

use crate::elf::loader::AndroidElfLoader;

/// A module's file name, for a label a reader can match to a path.
///
/// The module table is keyed by `DT_SONAME`, which for a renamed library is not
/// the file it came from -- `libapk_android_a64.so` is `l1296851e_a64.so` on
/// disk. Printing the file name is what makes a log traceable back to a path.
pub fn display_name(loader: &AndroidElfLoader, name: &str) -> String {
    loader
        .module_infos()
        .into_iter()
        .find(|info| info.name == name)
        .map(|info| info.file)
        .unwrap_or_else(|| name.to_string())
}

/// A stub's label without its dispatch number.
///
/// The label is `<table>!<function>.<number>`, and the number says nothing to
/// a reader. Only a trailing `.<digits>` is removed, because a name may itself
/// contain a dot -- `JNIEnv!<unimplemented>` does.
pub fn stub_name(label: &str) -> &str {
    match label.rsplit_once('.') {
        Some((head, tail)) if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) => head,
        _ => label,
    }
}

/// Names the address of a branch instruction, which sits *inside* a function
/// and so is named by the nearest symbol below it.
pub fn name_caller(loader: &AndroidElfLoader, address: u64) -> String {
    // A branch inside a host service has no ELF symbol either, but the stub
    // page still knows which service it is in.
    if let Some(svc) = loader.svc_memory() {
        if let Some(region) = svc.find_region(address) {
            let name = stub_name(&region.label);
            if !name.is_empty() && name.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
                return format!("{name}+0x{:x}", address.wrapping_sub(region.begin));
            }
        }
    }
    // A branch the symbol table does not name is a branch in a stripped
    // function, and its RVA is already printed in the address column; adding
    // the absolute address back would only repeat the same information in
    // a longer form.
    match loader.find_closest_symbol(address) {
        Some(symbol) => match symbol.module {
            Some(module) => format!(
                "{}!{}+0x{:x}",
                display_name(loader, &module),
                symbol.name,
                address.wrapping_sub(symbol.address)
            ),
            None => "?".to_string(),
        },
        None => "?".to_string(),
    }
}

/// Names a branch target, which *is* a function entry.
///
/// A nearest-symbol name would be a lie here -- a call lands in the middle of
/// nothing -- so an exact symbol is required, then a PLT stub's GOT slot, and
/// only then the containing module.
pub fn name_callee(
    loader: &AndroidElfLoader,
    is_64bit: bool,
    backend: &mut dyn Backend,
    address: u64,
) -> String {
    // A host service on the SVC page -- a JNIEnv or JavaVM function, a libdl
    // trampoline, a system-property getter -- is not part of any ELF, so the
    // loader cannot name it. But the stub page labels every allocation, and
    // the label is the function's real name: `GetJavaVM`, `AAsset_close`.
    // This comes before the module lookup because a stub can fall inside a
    // virtual module's page-aligned span and be misattributed to it.
    if let Some(svc) = loader.svc_memory() {
        if let Some(region) = svc.find_region(address) {
            // `JNIEnv!FindClass` / `JavaVM!GetEnv`: the table a stub belongs to
            // is what tells the two apart, since both have the same shape.
            let name = stub_name(&region.label);
            if !name.is_empty() && name.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
                return name.to_string();
            }
        }
    }
    if let Some(symbol) = loader.find_closest_symbol(address) {
        if symbol.address == address {
            if let Some(module) = &symbol.module {
                return format!("{}!{}", display_name(loader, module), symbol.name);
            }
        }
    }
    if is_64bit {
        if let Some(slot) = plt_got_slot(backend, address) {
            if let Some(symbol) = loader.relocation_symbol(slot) {
                return match &symbol.module {
                    Some(module) => format!("{}!{}", display_name(loader, module), symbol.name),
                    None => symbol.name,
                };
            }
        }
    }
    // Nothing named it: the address column already carries the RVA, so say
    // only that there is no name here rather than repeating the offset.
    "?".to_string()
}

/// The GOT slot an AArch64 PLT stub loads its target from, if `address` is one.
///
/// The shape is what `lld` and the Android NDK emit: `adrp x16, page`,
/// `ldr x17, [x16, #imm]`, `add x16, x16, #imm`, `br x17`. Any other
/// instruction sequence is not a stub this can name.
fn plt_got_slot(backend: &mut dyn Backend, address: u64) -> Option<u64> {
    let bytes = backend.mem_read(address, 16).ok()?;
    if bytes.len() != 16 {
        return None;
    }
    let word = |index: usize| u32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap());
    let adrp = word(0);
    let ldr = word(1);
    let br = word(3);
    if adrp & 0x9F00_001F != 0x9000_0010 {
        return None;
    }
    if ldr & 0xFFC0_0000 != 0xF940_0000 || (ldr >> 5) & 0x1F != 16 || ldr & 0x1F != 17 {
        return None;
    }
    if br != 0xD61F_0220 {
        return None;
    }
    // ADRP's immediate is 21 bits of halfwords scaled by 2 and 4KB.
    let imm21 = (((adrp >> 5) & 0x7FFFF) << 2) | ((adrp >> 29) & 3);
    let page = (address & !0xFFF).wrapping_add(sign_extend(imm21, 21) << 12);
    Some(page.wrapping_add(u64::from((ldr >> 10) & 0xFFF) * 8))
}

/// Sign-extends the low `bits` of `value`, for an address displacement.
fn sign_extend(value: u32, bits: u32) -> u64 {
    let shift = 32 - bits;
    (((value << shift) as i32) >> shift) as i64 as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_names_drop_only_a_trailing_number() {
        assert_eq!(stub_name("JNIEnv!GetMethodID.305"), "JNIEnv!GetMethodID");
        assert_eq!(stub_name("JavaVM!GetEnv.530"), "JavaVM!GetEnv");
        // A name that is itself dotted keeps everything: only digits are a
        // dispatch number.
        assert_eq!(stub_name("JNIEnv!<unimplemented>"), "JNIEnv!<unimplemented>");
        assert_eq!(stub_name("libc.so!printf"), "libc.so!printf");
    }

    #[test]
    fn sign_extension_round_trips_a_negative_displacement() {
        assert_eq!(sign_extend(0x7ffff, 21), 0x7ffff);
        assert_eq!(sign_extend(0x1fffff, 21), u64::MAX);
    }
}
