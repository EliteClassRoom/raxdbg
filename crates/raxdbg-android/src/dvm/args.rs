//! Decoding the arguments of a `JNIEnv` or `JavaVM` call.
//!
//! Port of unidbg:
//! `unidbg-android/src/main/java/com/github/unidbg/linux/android/dvm/`'s
//! per-slot handlers, which read their arguments in `x1..x7` and describe them
//! by name, @7f5da98e.
//!
//! A call log that names the callee answers "what did it call?"; one that also
//! prints the arguments answers "what did it ask for?". For a protection that
//! is the whole difference: `FindClass` is opaque on its own, while
//! `FindClass(env, "java/io/FileInputStream")` names the asset reader the
//! packer is about to reach for.
//!
//! Every JNI function's first argument is the `JNIEnv*` (or `JavaVM*`) itself,
//! so the real arguments start at `x1`. Which of those are pointers to
//! strings, references, out-pointers or plain integers is fixed by the JNI
//! calling convention, and this module encodes that per slot.

use raxdbg_core::backend::Backend;
use raxdbg_core::memory::Memory;

use crate::elf::names::stub_name;

use super::vm::JniFunc;

/// How many characters of a guest string to print before truncating.
///
/// A class or method name is tens of characters; a packer passing a
/// megabyte-sized blob is not asking a question the reader can answer, and
/// printing it would bury the rest of the line.
const MAX_STRING: usize = 96;

/// Formats the arguments of a `JNIEnv` or `JavaVM` stub call.
///
/// `label` is the stub page's label for the stub -- `JNIEnv!FindClass.306` or
/// `JavaVM!GetEnv.530`. Returns `None` for a label that names no function this
/// module knows how to describe, which is the caller's cue to print nothing
/// rather than a line of raw registers nobody asked for.
///
/// The arguments are read *before* the `bl` retires, which is when
/// [`FunctionCallListener::on_call`] fires, so `x1..x7` still hold them.
pub fn format_jni_args(
    label: &str,
    backend: &mut dyn Backend,
    memory: &dyn Memory,
    is_64bit: bool,
) -> Option<String> {
    let (table, name) = split_label(label)?;
    match table {
        "JNIEnv" => format_env_call(name, backend, memory, is_64bit),
        "JavaVM" => format_vm_call(name, backend, is_64bit),
        _ => None,
    }
}

/// Formats a `JNIEnv` call.
fn format_env_call(
    name: &str,
    backend: &mut dyn Backend,
    memory: &dyn Memory,
    is_64bit: bool,
) -> Option<String> {
    let function = JniFunc::ALL
        .into_iter()
        .find(|function| function.name() == name)?;
    let arg = |backend: &mut dyn Backend, register: u8| register_value(backend, is_64bit, register);
    let reference = |backend: &mut dyn Backend, register: u8| {
        format!("ref={:#x}", arg(backend, register) as u32 as i32)
    };
    let string =
        |backend: &mut dyn Backend, register: u8| format_string(memory, arg(backend, register));
    let word = |backend: &mut dyn Backend, register: u8| format!("{:#x}", arg(backend, register));

    Some(match function {
        // `x0` is the JNIEnv itself, so these have nothing to describe.
        JniFunc::GetVersion | JniFunc::ExceptionCheck | JniFunc::GetJavaVM => String::new(),

        // `FindClass(JNIEnv*, const char* name)`
        JniFunc::FindClass => string(backend, 1),

        // `GetMethodID(JNIEnv*, jclass, const char* name, const char* sig)`,
        // and the static twin, share this shape.
        JniFunc::GetMethodID | JniFunc::GetStaticMethodID => format!(
            "env, {}, {}, {}",
            reference(backend, 1),
            string(backend, 2),
            string(backend, 3),
        ),

        // `NewStringUTF(JNIEnv*, const char*)`
        JniFunc::NewStringUTF => string(backend, 1),

        // `GetStringUTFChars(JNIEnv*, jstring, jboolean* isCopy)` -- the
        // out-pointer is null in practice, and saying so tells a reader the
        // result is shared rather than copied.
        JniFunc::GetStringUTFChars => format!(
            "env, {}, isCopy={}",
            reference(backend, 1),
            word(backend, 2),
        ),
        JniFunc::ReleaseStringUTFChars => {
            format!("env, {}, {}", reference(backend, 1), string(backend, 2))
        }

        // `ThrowNew(JNIEnv*, jclass, const char* msg)`
        JniFunc::ThrowNew => {
            format!("env, {}, {}", reference(backend, 1), string(backend, 2))
        }

        // `NewGlobalRef`/`DeleteLocalRef(JNIEnv*, jobject)`
        JniFunc::NewGlobalRef | JniFunc::DeleteLocalRef => reference(backend, 1),

        // `GetObjectClass(JNIEnv*, jobject)`
        JniFunc::GetObjectClass => reference(backend, 1),

        // `NewObject(JNIEnv*, jclass, jmethodID, ...)`
        JniFunc::NewObject => {
            format!(
                "env, {}, mid={}",
                reference(backend, 1),
                reference(backend, 2)
            )
        }

        // `CallIntMethod` and its static twin: env, object-or-class, method,
        // then `jvalue*` varargs the trace cannot type without a signature
        // table the VM does not keep.
        JniFunc::CallIntMethod | JniFunc::CallStaticIntMethod => {
            format!(
                "env, {}, mid={}",
                reference(backend, 1),
                reference(backend, 2)
            )
        }

        // `GetStaticFieldID(JNIEnv*, jclass, const char* name, const char* sig)`,
        // the field twin of `GetStaticMethodID`.
        JniFunc::GetStaticFieldID => format!(
            "env, {}, {}, {}",
            reference(backend, 1),
            string(backend, 2),
            string(backend, 3),
        ),

        // `GetStaticIntField(JNIEnv*, jclass, jfieldID)`
        JniFunc::GetStaticIntField => {
            format!(
                "env, {}, fid={}",
                reference(backend, 1),
                reference(backend, 2)
            )
        }

        // `CallStaticObjectMethodV(JNIEnv*, jclass, jmethodID, va_list)` -- the
        // `va_list` is a pointer into the caller's arguments, and typing it
        // needs the method's signature, which the stub does not have. The
        // instance twins share the shape: only the second argument differs, a
        // `jobject` rather than a `jclass`.
        JniFunc::CallStaticObjectMethodV
        | JniFunc::CallObjectMethod
        | JniFunc::CallObjectMethodV => {
            format!(
                "env, {}, mid={}",
                reference(backend, 1),
                reference(backend, 2)
            )
        }

        JniFunc::GetArrayLength => reference(backend, 1),
        JniFunc::GetIntArrayElements => format!(
            "env, {}, isCopy={}",
            reference(backend, 1),
            word(backend, 2),
        ),
        JniFunc::ReleaseIntArrayElements => {
            format!("env, {}, mode={}", reference(backend, 1), word(backend, 2))
        }

        // `RegisterNatives(JNIEnv*, jclass, JNINativeMethod* methods,
        // jint count)` -- the table *is* the payload, and it is the answer to
        // "what does this library bind into the VM?". The class and the count
        // alone say nothing; the entries name every method and point at the
        // code behind it.
        JniFunc::RegisterNatives => format!(
            "env, {}, count={}, natives={}",
            reference(backend, 1),
            arg(backend, 3) as i32,
            format_native_methods(memory, arg(backend, 2), arg(backend, 3) as i32, is_64bit,),
        ),
    })
}

/// How many `JNINativeMethod` entries one line will print.
///
/// A protection registers a handful; a corrupt or hostile `count` must not turn
/// a trace into a million-line dump, so the list is capped and says so.
const MAX_NATIVE_METHODS: usize = 32;

/// Reads the `JNINativeMethod` array a `RegisterNatives` call is handing over.
///
/// Each entry is `{const char* name, const char* signature, void* fnPtr}`, so
/// the walk is three pointer-sized reads per entry and stops at the first one
/// that is not readable -- a table the guest built is in its own memory, and an
/// unreadable entry is where the trace can no longer tell the truth.
fn format_native_methods(memory: &dyn Memory, table: u64, count: i32, is_64bit: bool) -> String {
    if table == 0 || count <= 0 {
        return "[]".to_string();
    }
    let stride = if is_64bit { 8u64 } else { 4u64 };
    let mut entries = Vec::new();
    for index in 0..count as usize {
        if entries.len() == MAX_NATIVE_METHODS {
            entries.push("...".to_string());
            break;
        }
        let entry = memory.pointer(table + index as u64 * stride * 3);
        let (Ok(name), Ok(signature), Ok(function)) = (
            entry.read_pointer(0),
            entry.read_pointer(stride),
            entry.read_pointer(stride * 2),
        ) else {
            // The table ends before `count` claims it does. Printing what was
            // read, without padding, is honest; guessing the rest is not.
            break;
        };
        if name == 0 || function == 0 {
            break;
        }
        entries.push(format!(
            "{} {} fn={function:#x}",
            format_string(memory, name),
            format_string(memory, signature),
        ));
    }
    format!("[{}]", entries.join(", "))
}

/// Formats a `JavaVM` call.
///
/// The `JavaVM` table is six functions wide and only `GetEnv` and the two
/// attach calls carry arguments worth naming, so this is a small match rather
/// than one arm per slot.
fn format_vm_call(name: &str, backend: &mut dyn Backend, is_64bit: bool) -> Option<String> {
    Some(match name {
        // `GetEnv(JavaVM*, void** p_env, jint version)` -- the version is what
        // a library is deciding, and a mismatch is what `__libc_init_common`
        // and a packer's SDK probe both key off.
        "GetEnv" => {
            let env_out = register_value(backend, is_64bit, 1);
            let version = register_value(backend, is_64bit, 2) as i32;
            format!("vm, env_out={env_out:#x}, version={version:#x}")
        }
        // `AttachCurrentThread(JavaVM*, JNIEnv** p_env, void* args)`
        "AttachCurrentThread" | "AttachCurrentThreadAsDaemon" => {
            let env_out = register_value(backend, is_64bit, 1);
            let args = register_value(backend, is_64bit, 2);
            format!("vm, env_out={env_out:#x}, args={args:#x}")
        }
        _ => return None,
    })
}

/// Reads `x(index)`, the register a JNI argument arrived in.
///
/// `x0` carries the `JNIEnv*`/`JavaVM*` itself, so the first real argument is
/// `x1` and this takes the register number as it appears in the ABI rather than
/// a zero-based argument index. The dispatcher in [`super::vm`] reads the other
/// way round -- its `arg(backend, _, 0)` is `x1` -- which is why this names the
/// register directly: an index that matches neither convention is a silent
/// off-by-one, and reading `x2` as a class name prints a plausible pointer.
fn register_value(backend: &mut dyn Backend, is_64bit: bool, index: u8) -> u64 {
    let register = if is_64bit {
        raxdbg_core::reg::RegId::X(index)
    } else {
        raxdbg_core::reg::RegId::R(index)
    };
    backend.reg_read(register).unwrap_or(0)
}

/// Splits a stub label into its table and its function name.
///
/// The label is `JNIEnv!FindClass.306`: the table says which vtable the stub
/// belongs to, and the trailing number is the dispatch number, which says
/// nothing to a reader.
fn split_label(label: &str) -> Option<(&str, &str)> {
    let (table, rest) = label.split_once('!')?;
    Some((table, stub_name(rest)))
}

/// Reads a NUL-terminated guest string, quoted and truncated.
///
/// A null pointer prints as `null` rather than failing: JNI spells a missing
/// optional argument that way, and a trace must not turn it into an error the
/// reader has to reason about.
fn format_string(memory: &dyn Memory, address: u64) -> String {
    if address == 0 {
        return "null".to_string();
    }
    let pointer = memory.pointer(address);
    let mut bytes = Vec::new();
    for offset in 0..MAX_STRING as u64 {
        match pointer.read_byte(offset) {
            Ok(0) => break,
            Ok(byte) => bytes.push(byte),
            // The pointer is not readable, so there is nothing to print. The
            // address is still the useful part of the answer.
            Err(_) => return format!("{address:#x}"),
        }
    }
    let text = String::from_utf8_lossy(&bytes);
    if bytes.len() == MAX_STRING {
        return format!("\"{text}...\"");
    }
    format!("\"{text}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The label split the formatter does, spelled out so a change to the
    /// stub page's naming convention fails here rather than silently printing
    /// nothing for every JNI call.
    #[test]
    fn a_stub_label_splits_into_its_table_and_function() {
        assert_eq!(
            split_label("JNIEnv!FindClass.306"),
            Some(("JNIEnv", "FindClass"))
        );
        assert_eq!(split_label("JavaVM!GetEnv.530"), Some(("JavaVM", "GetEnv")));
    }

    /// A label naming no JNI function this port implements has no arguments to
    /// describe, and the formatter must say so rather than invent a shape.
    #[test]
    fn a_function_this_port_does_not_implement_has_no_arguments_to_show() {
        assert!(
            JniFunc::ALL
                .into_iter()
                .all(|function| function.name() != "<unimplemented>")
        );
    }
}
