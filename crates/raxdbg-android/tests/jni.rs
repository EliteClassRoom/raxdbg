//! JNI tests (plan P6) against the fixture built from `fixtures/src/jnitest.c`.
//!
//! The fixture is a real Android `.so` built against bionic. It runs
//! `JNI_OnLoad`, registers `add` through `RegisterNatives`, exports ten
//! `Java_com_raxdbg_test_JniTest_*` entry points, and calls back into "Java"
//! through the `JNIEnv` table — so every test below exercises the guest's own
//! code reaching our table, not a host-side shortcut.

#[path = "synthetic/mod.rs"]
mod synthetic;

use std::cell::RefCell;
use std::rc::Rc;

use raxdbg_android::android_file::ElfLibraryFile;
use raxdbg_android::dvm::vm::JniError;
use raxdbg_android::dvm::{
    DvmClass, DvmMethod, DvmObject, JNI_OK, JNI_VERSION_1_6, Jni, Vm, format_jni_args,
};
use raxdbg_android::emulator::{AndroidEmulator, AndroidEmulatorBuilder};
use raxdbg_core::backend::Prot;
use raxdbg_core::memory::{MAP_ANONYMOUS, Memory};
use raxdbg_core::reg::RegId;

/// The fixture's class, as the guest names it.
const CLASS: &str = "com/raxdbg/test/JniTest";

/// The Java side the fixture talks to.
///
/// `seedPlusOne` calls `JniTest.getSeed()` and `callInstance` calls
/// `JniTest.value()`, so those two are the whole model the tests need.
struct TestJni;

impl Jni for TestJni {
    fn call_static_int_method(
        &self,
        _vm: &mut Vm,
        _class: &Rc<DvmClass>,
        method: &Rc<DvmMethod>,
        _args: &[u64],
    ) -> i32 {
        match method.description().as_str() {
            "getSeed()I" => 7,
            _ => 0,
        }
    }

    fn call_int_method(
        &self,
        _vm: &mut Vm,
        _object: &Rc<dyn DvmObject>,
        method: &Rc<DvmMethod>,
        _args: &[u64],
    ) -> i32 {
        match method.description().as_str() {
            "value()I" => 42,
            _ => 0,
        }
    }
}

struct Fixture {
    emulator: Rc<AndroidEmulator>,
    vm: Rc<std::cell::RefCell<Vm>>,
}

impl Fixture {
    fn boot() -> Fixture {
        let fixture = Fixture::boot_with_default_jni();
        fixture.vm.borrow().set_jni(Box::new(TestJni));
        fixture
    }

    /// Boots with whatever `Vm::create` installed, so a test can exercise the
    /// default host model rather than one the harness supplies.
    fn boot_with_default_jni() -> Fixture {
        let emulator = AndroidEmulatorBuilder::for_64bit()
            .process_name("raxdbg-jni")
            .seed(11)
            .build()
            .expect("emulator");
        emulator.load_library("libc.so").expect("libc.so");
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .expect("workspace root")
            .join("fixtures/prebuilt/arm64-v8a/libjnitest.so");
        let file = ElfLibraryFile::open(&path).expect("open fixture");
        emulator.load(Box::new(file), false).expect("load fixture");
        let vm = Vm::create(&emulator).expect("vm");
        Fixture { emulator, vm }
    }

    fn on_load(&self) -> Result<i32, JniError> {
        Vm::call_jni_on_load(&self.emulator, &self.vm, "libjnitest.so")
    }

    fn call(&self, name: &str, signature: &str, args: &[u64]) -> i64 {
        Vm::call_static_jni_method(&self.emulator, &self.vm, CLASS, name, signature, args)
            .unwrap_or_else(|error| panic!("{name}{signature}: {error}"))
    }

    fn class(&self) -> Rc<DvmClass> {
        self.vm.borrow_mut().resolve_class(CLASS)
    }
}

#[test]
fn the_vm_builds_a_jni_env_and_java_vm() {
    let fixture = Fixture::boot();
    let vm = fixture.vm.borrow();
    assert_ne!(vm.jni_env(), 0, "the JNIEnv table is allocated");
    assert_ne!(vm.java_vm(), 0, "the JavaVM table is allocated");
    assert_eq!(vm.jni_version(), JNI_VERSION_1_6);
    // The tables are distinct and inside the SVC page.
    assert_ne!(vm.jni_env(), vm.java_vm());
    let svc_base = fixture
        .emulator
        .loader()
        .svc_memory()
        .expect("svc page")
        .base();
    let svc_end = svc_base + 0x10000;
    assert!(
        vm.jni_env() >= svc_base && vm.jni_env() < svc_end,
        "JNIEnv {:#x} is not in the SVC page",
        vm.jni_env()
    );
}

/// `GetJavaVM` is JNIEnv slot 219 (`(*env)->GetJavaVM(env, &vm)`), and it is
/// the first call a packed library makes. This reads the slot straight out of
/// the table the way the guest does, so it fails if the slot is ever left as
/// the unmapped placeholder again.
#[test]
fn get_java_vm_answers_through_the_jni_env_table() {
    let fixture = Fixture::boot();
    let vm = fixture.vm.borrow();

    let table = fixture
        .emulator
        .memory()
        .pointer(vm.jni_env())
        .read_pointer(0)
        .expect("the JNIEnv handle points at its table");
    // Slot 219 * pointer_size is `GetJavaVM`; a 64-bit table is 8 bytes wide.
    let entry = fixture
        .emulator
        .memory()
        .pointer(table + 219 * 8)
        .read_pointer(0)
        .expect("read GetJavaVM slot");
    assert_ne!(
        entry,
        219 * 8,
        "GetJavaVM must not be the unmapped placeholder the table is filled with"
    );
    let svc_base = fixture
        .emulator
        .loader()
        .svc_memory()
        .expect("svc page")
        .base();
    assert!(
        entry >= svc_base,
        "GetJavaVM {entry:#x} must be a stub in the SVC page"
    );
}

/// Calling `GetJavaVM` through the table writes the `JavaVM*` the caller
/// asked for, which is the whole point of the call.
#[test]
fn get_java_vm_writes_the_handle_to_the_out_pointer() {
    let fixture = Fixture::boot();
    let java_vm = fixture.vm.borrow().java_vm();
    let table = fixture
        .emulator
        .memory()
        .pointer(fixture.vm.borrow().jni_env())
        .read_pointer(0)
        .expect("the JNIEnv handle points at its table");
    let entry = fixture
        .emulator
        .memory()
        .pointer(table + 219 * 8)
        .read_pointer(0)
        .expect("read GetJavaVM slot");

    // The out-pointer has to live somewhere `call_function`'s own stack
    // realignment will not disturb, so it comes from a mapping of its own
    // rather than from the stack.
    let out = fixture
        .emulator
        .memory()
        .mmap2(
            0,
            0x1000,
            Prot::READ.union(Prot::WRITE),
            MAP_ANONYMOUS,
            -1,
            0,
        )
        .expect("scratch page");
    fixture
        .emulator
        .memory()
        .pointer(out)
        .write_u64(0, 0)
        .expect("clear");

    // A `JNIEnv` call is `(*env)->GetJavaVM(env, &out)`: `x0` is the env the
    // table was read from and the arguments start at `x1`, which is what
    // `arg(.., 0)` returns.
    let env = fixture.vm.borrow().jni_env();
    let result = fixture
        .emulator
        .call_function(entry, &[env, out])
        .expect("GetJavaVM runs");

    assert_eq!(result as i32, JNI_OK, "GetJavaVM reports JNI_OK");
    let written = fixture
        .emulator
        .memory()
        .pointer(out)
        .read_u64(0)
        .expect("read the out-pointer");
    assert_eq!(
        written, java_vm,
        "GetJavaVM must hand back the JavaVM* it was called through"
    );
}

/// A `JNIEnv` function's arguments start at `x1`: `x0` is the environment the
/// table was read from, and `x2` onward belongs to whatever the guest happened
/// to leave there. A dispatch that reads the wrong register here writes
/// through garbage and faults, which is how a packed library that calls
/// `GetJavaVM` first dies before it reaches anything else.
///
/// This pins the convention by leaving a poison value in the registers the
/// call does *not* use.
#[test]
fn a_jni_env_call_ignores_the_registers_after_its_arguments() {
    let fixture = Fixture::boot();
    let env = fixture.vm.borrow().jni_env();
    let table = fixture
        .emulator
        .memory()
        .pointer(env)
        .read_pointer(0)
        .expect("the JNIEnv handle points at its table");
    let entry = fixture
        .emulator
        .memory()
        .pointer(table + 219 * 8)
        .read_pointer(0)
        .expect("read GetJavaVM slot");

    let out = fixture
        .emulator
        .memory()
        .mmap2(
            0,
            0x1000,
            Prot::READ.union(Prot::WRITE),
            MAP_ANONYMOUS,
            -1,
            0,
        )
        .expect("scratch page");
    fixture
        .emulator
        .memory()
        .pointer(out)
        .write_u64(0, 0)
        .expect("clear");

    // `x2` is a poison address: a dispatch that mistook it for the
    // out-pointer would fault here rather than answer.
    let poison = 0x10_0006u64;
    let result = fixture
        .emulator
        .call_function(entry, &[env, out, poison])
        .expect("GetJavaVM runs and does not write through x2");
    assert_eq!(result as i32, JNI_OK);
}

/// Each `JavaVM` function gets its own stub, so a call log names the function
/// the guest called. A single shared stub reports as the generic "JavaVM",
/// which tells a reader nothing about which entry point was reached.
#[test]
fn every_java_vm_slot_holds_its_own_named_stub() {
    let fixture = Fixture::boot();
    let java_vm = fixture.vm.borrow().java_vm();
    let table = fixture
        .emulator
        .memory()
        .pointer(java_vm)
        .read_pointer(0)
        .expect("the JavaVM handle points at its table");

    let mut named: Vec<String> = Vec::new();
    for slot in 0..=7usize {
        let entry = fixture
            .emulator
            .memory()
            .pointer(table + (slot * 8) as u64)
            .read_pointer(0)
            .expect("read a JavaVM slot");
        let label = fixture
            .emulator
            .loader()
            .svc_memory()
            .expect("svc page")
            .find_region(entry)
            .map(|region| region.label)
            .unwrap_or_default();
        named.push(label);
    }
    println!("JavaVM slots: {named:?}");

    // `GetEnv` is what a JNI library calls first; it must be nameable, and
    // the table it belongs to must be in the name so it can be told apart
    // from the identically-shaped `JNIEnv` entry points.
    assert!(
        named[6].starts_with("JavaVM!GetEnv."),
        "slot 6 is JavaVM!GetEnv, got {}",
        named[6]
    );
    // No two slots may share a stub, or the name would be ambiguous.
    assert_ne!(
        named[4], named[6],
        "AttachCurrentThread and GetEnv must not share one stub"
    );
    let unique: std::collections::BTreeSet<&String> = named.iter().collect();
    assert!(
        unique.len() >= 5,
        "each named JavaVM function needs its own stub, got {named:?}"
    );
}

#[test]
fn jni_on_load_returns_version_1_6_and_registers_its_native() {
    let fixture = Fixture::boot();
    let version = fixture.on_load().expect("JNI_OnLoad");
    assert_eq!(version, JNI_VERSION_1_6);
    assert!(fixture.vm.borrow().on_load_ran());

    // `RegisterNatives` ran inside the guest, so the class now has the entry.
    let class = fixture.class();
    assert_eq!(class.native_count(), 1, "natives: {:?}", class.natives());
    let registered = class
        .native_address("add", "(II)I")
        .expect("RegisterNatives stored add(II)I");
    // And it points at the fixture's own `native_add`.
    let expected = fixture
        .emulator
        .loader()
        .find_symbol("libjnitest.so", "Java_com_raxdbg_test_JniTest_add2")
        .expect("add2");
    let module_base = fixture
        .emulator
        .loader()
        .module("libjnitest.so")
        .expect("module")
        .base;
    assert!(
        registered >= module_base && registered < module_base + 0x10000,
        "the registered pointer {registered:#x} is not inside the fixture (base {module_base:#x}, add2 {:#x})",
        expected.address
    );
}

#[test]
fn a_registered_native_is_found_through_the_natives_map() {
    let fixture = Fixture::boot();
    fixture.on_load().expect("JNI_OnLoad");
    // `add` has no `Java_` symbol: it exists only because RegisterNatives ran.
    assert_eq!(fixture.call("add", "(II)I", &[2, 40]), 42);
}

#[test]
fn a_java_symbol_is_found_by_mangling() {
    let fixture = Fixture::boot();
    fixture.on_load().expect("JNI_OnLoad");
    assert_eq!(fixture.call("add2", "(II)I", &[2, 40]), 42);
    assert_eq!(fixture.call("add2", "(II)I", &[1000, 337]), 1337);
}

#[test]
fn get_version_answers_through_the_jni_env_table() {
    let fixture = Fixture::boot();
    fixture.on_load().expect("JNI_OnLoad");
    assert_eq!(
        fixture.call("getVersion", "()I", &[]),
        JNI_VERSION_1_6 as i64
    );
}

#[test]
fn a_string_round_trips_through_get_and_new_string_utf() {
    let fixture = Fixture::boot();
    fixture.on_load().expect("JNI_OnLoad");
    let hash = fixture.vm.borrow().new_string("abc");
    let returned = fixture.call(
        "echo",
        "(Ljava/lang/String;)Ljava/lang/String;",
        &[hash as u64],
    );
    assert_ne!(returned, 0, "echo returned a string");
    let object = fixture
        .vm
        .borrow()
        .object(returned as i32)
        .expect("the returned reference is registered");
    let string = object
        .as_any()
        .downcast_ref::<raxdbg_android::dvm::StringObject>()
        .expect("echo returns a java.lang.String");
    assert_eq!(string.value(), "abc");
}

#[test]
fn a_string_with_a_nul_terminator_survives_the_round_trip() {
    let fixture = Fixture::boot();
    fixture.on_load().expect("JNI_OnLoad");
    // `GetStringUTFChars` must hand the guest a NUL-terminated buffer.
    let hash = fixture.vm.borrow().new_string("hello from the host");
    let returned = fixture.call(
        "echo",
        "(Ljava/lang/String;)Ljava/lang/String;",
        &[hash as u64],
    );
    let object = fixture.vm.borrow().object(returned as i32).expect("object");
    let string = object
        .as_any()
        .downcast_ref::<raxdbg_android::dvm::StringObject>()
        .expect("string");
    assert_eq!(string.value(), "hello from the host");
}

#[test]
fn new_string_utf_builds_a_string_the_host_can_read() {
    let fixture = Fixture::boot();
    fixture.on_load().expect("JNI_OnLoad");
    let returned = fixture.call("newString", "()Ljava/lang/String;", &[]);
    let object = fixture.vm.borrow().object(returned as i32).expect("object");
    let string = object
        .as_any()
        .downcast_ref::<raxdbg_android::dvm::StringObject>()
        .expect("string");
    assert_eq!(string.value(), "hello from native");
}

#[test]
fn a_native_calls_back_into_java() {
    let fixture = Fixture::boot();
    fixture.on_load().expect("JNI_OnLoad");
    // The fixture does FindClass + GetStaticMethodID("getSeed","()I") +
    // CallStaticIntMethod, and our TestJni answers 7, so it returns 8.
    assert_eq!(fixture.call("seedPlusOne", "()I", &[]), 8);

    // The callback really went through the method id, not around it.
    let method = fixture
        .vm
        .borrow()
        .method_by_hash(fixture.vm.borrow().hash_method(CLASS, "getSeed", "()I"))
        .expect("getSeed()I has an id");
    assert_eq!(method.invocations(), 1);
}

#[test]
fn an_int_array_arrives_through_get_int_array_elements() {
    let fixture = Fixture::boot();
    fixture.on_load().expect("JNI_OnLoad");
    let hash = fixture.vm.borrow().new_int_array(vec![1, 2, 3, 4]);
    assert_eq!(fixture.call("sumArray", "([I)I", &[hash as u64]), 10);
}

#[test]
fn get_int_array_elements_hands_the_guest_writable_storage() {
    let fixture = Fixture::boot();
    fixture.on_load().expect("JNI_OnLoad");
    let hash = fixture.vm.borrow().new_int_array(vec![5, 5, 5]);
    assert_eq!(fixture.call("sumArray", "([I)I", &[hash as u64]), 15);
    // A second call reuses the same elements buffer, and the values are intact.
    assert_eq!(fixture.call("sumArray", "([I)I", &[hash as u64]), 15);
}

#[test]
fn a_native_throw_sets_a_pending_exception() {
    let fixture = Fixture::boot();
    fixture.on_load().expect("JNI_OnLoad");
    assert!(!fixture.vm.borrow().has_exception());
    fixture.call("throwIt", "()V", &[]);
    let exception = fixture
        .vm
        .borrow()
        .exception()
        .expect("ThrowNew raised a throwable");
    assert!(
        format!("{exception:?}").contains("IllegalStateException"),
        "the throwable names its class: {exception:?}"
    );
    assert!(
        format!("{exception:?}").contains("boom"),
        "the throwable carries the message: {exception:?}"
    );
}

#[test]
fn a_global_reference_outlives_the_local_it_came_from() {
    let fixture = Fixture::boot();
    fixture.on_load().expect("JNI_OnLoad");
    let hash = fixture.vm.borrow().new_string("keep me");
    let returned = fixture.call(
        "globalRef",
        "(Ljava/lang/Object;)Ljava/lang/Object;",
        &[hash as u64],
    );
    assert_eq!(returned as i32, hash, "the reference keeps its identity");
    {
        let vm = fixture.vm.borrow();
        assert_eq!(vm.global_ref_count(), 1, "it is a global reference now");
        // The guest deleted the local reference it was handed; only the class
        // reference from `JNI_OnLoad` is still held.
        assert_eq!(vm.local_ref_count(), 1, "the local it came from is gone");
        assert!(vm.class_by_hash(vm.hash_class(CLASS)).is_some());
        let object = vm.object(hash).expect("the global reference resolves");
        let string = object
            .as_any()
            .downcast_ref::<raxdbg_android::dvm::StringObject>()
            .expect("string");
        assert_eq!(string.value(), "keep me");
    }
}

#[test]
fn new_object_and_call_int_method_reach_the_instance() {
    let fixture = Fixture::boot();
    fixture.on_load().expect("JNI_OnLoad");
    // The fixture does GetMethodID("<init>","()V"), NewObject, then
    // GetMethodID("value","()I") and CallIntMethod; TestJni answers 42.
    assert_eq!(fixture.call("callInstance", "()I", &[]), 42);
    let ctor = fixture.vm.borrow().hash_method(CLASS, "<init>", "()V");
    let value = fixture.vm.borrow().hash_method(CLASS, "value", "()I");
    let vm = fixture.vm.borrow();
    assert!(vm.method_by_hash(ctor).is_some(), "<init>()V has an id");
    assert_eq!(
        vm.method_by_hash(value).expect("value()I").invocations(),
        1,
        "CallIntMethod went through the method id"
    );
}

#[test]
fn local_references_are_dropped_after_a_host_driven_call() {
    let fixture = Fixture::boot();
    fixture.on_load().expect("JNI_OnLoad");
    let before = fixture.vm.borrow().local_ref_count();
    // `seedPlusOne` does a FindClass and a GetStaticMethodID inside the guest,
    // so it creates local references; unidbg frees them when the call returns.
    fixture.call("seedPlusOne", "()I", &[]);
    assert_eq!(
        fixture.vm.borrow().local_ref_count(),
        before,
        "the references the call created are dropped"
    );
    // ...while a reference the call *returns* is the caller's, and survives.
    fixture.call("newString", "()Ljava/lang/String;", &[]);
    assert_eq!(
        fixture.vm.borrow().local_ref_count(),
        before + 1,
        "the returned reference is kept"
    );
}

#[test]
fn an_unknown_native_is_reported_not_guessed() {
    let fixture = Fixture::boot();
    fixture.on_load().expect("JNI_OnLoad");
    let error = Vm::call_static_jni_method(
        &fixture.emulator,
        &fixture.vm,
        CLASS,
        "notThere",
        "()I",
        &[],
    )
    .expect_err("an unknown native is an error");
    assert!(
        matches!(&error, JniError::NoNative(name) if name.contains("notThere")),
        "{error}"
    );
}

#[test]
fn the_hasher_decides_the_method_ids() {
    let fixture = Fixture::boot();
    let vm = fixture.vm.borrow();
    // unidbg's default hasher is Java's String.hashCode over
    // "L<Class>;-><name><signature>".
    let expected =
        raxdbg_android::dvm::hash::java_string_hash("Lcom/raxdbg/test/JniTest;->getSeed()I");
    assert_eq!(vm.hash_method(CLASS, "getSeed", "()I"), expected);
}

/// `JNI_OnLoad` runs after the module's constructors, the way a device does.
///
/// The library here is assembled byte by byte so the two functions are the
/// whole program: `.init` writes a magic word, and `JNI_OnLoad` reads it back
/// and returns it. The value can only come back if the constructor ran first --
/// without it the word is zero, `0` is neither a version nor `JNI_OK`, and
/// the call fails as `OnLoadFailed(0)`.
#[test]
fn jni_on_load_runs_after_the_librarys_initialisers() {
    use raxdbg_android::android_file::ElfLibraryRawFile;
    use synthetic::{BINDING_GLOBAL, SHN_ABS, TYPE_FUNC};

    let emulator = AndroidEmulatorBuilder::for_64bit()
        .process_name("raxdbg-jni-constructors")
        .seed(31)
        .build()
        .expect("emulator");
    // The load is asked not to run initialisers; `JNI_OnLoad` has to bring
    // them up itself, which is the case a `--jni-on-load` run creates.
    emulator.loader().set_call_init_function(false);

    let mut library = synthetic::SyntheticLibrary::new("libjnionload.so");
    library.init_array.clear();
    library.dt_init = Some(synthetic::MARKER_ADDRESS);
    library.symbols.push(synthetic::SyntheticSymbol {
        name: "JNI_OnLoad".into(),
        value: 0x120,
        size: 4,
        info: (BINDING_GLOBAL << 4) | TYPE_FUNC,
        shndx: SHN_ABS,
    });
    library.code = vec![
        // .init: adr x1, #0x40 ; movz w2, #6 ; movk w2, #1, lsl #16 ;
        //         str w2, [x1] ; ret
        0x1000_0201,
        0x5280_00c2,
        0x72a0_0022,
        0xb900_0022,
        0xd65f_03c0,
        // padding to 0x120
        0xd503_201f,
        0xd503_201f,
        0xd503_201f,
        // JNI_OnLoad: adr x1, #0x20 ; ldr w0, [x1] ; ret
        0x1000_0101,
        0xb940_0020,
        0xd65f_03c0,
    ];
    let name = emulator
        .load(
            Box::new(ElfLibraryRawFile::new("libjnionload.so", library.build())),
            false,
        )
        .expect("load");
    emulator.loader().set_call_init_function(true);
    assert_eq!(name, "libjnionload.so");

    let vm = Vm::create(&emulator).expect("vm");
    assert_eq!(
        Vm::call_jni_on_load(&emulator, &vm, "libjnionload.so").expect("JNI_OnLoad"),
        JNI_VERSION_1_6,
        "the constructor's word came back, so it ran first"
    );
}

/// The stub address in the `JNIEnv` table's `slot`.
///
/// Slots 115, 144 and 150 are what a packed library reaches for once
/// `GetStaticMethodID` has handed it a method id -- the `va_list` call that
/// resolves `ActivityThread.currentActivityThread()`, and the two static-field
/// slots behind it. Before they were implemented every one of them was the
/// shared `UnimplementedJniFunction` stub, so a run recorded the slot and
/// answered zero.
fn slot_address(fixture: &Fixture, slot: u64) -> u64 {
    let vm = fixture.vm.borrow();
    let table = fixture
        .emulator
        .memory()
        .pointer(vm.jni_env())
        .read_pointer(0)
        .expect("the JNIEnv handle points at its table");
    fixture
        .emulator
        .memory()
        .pointer(table + slot * 8)
        .read_pointer(0)
        .expect("read the slot")
}

/// A NUL-terminated guest string, as a JNI name or signature argument.
fn guest_string(fixture: &Fixture, value: &str) -> u64 {
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(0);
    let address = fixture
        .emulator
        .memory()
        .mmap(bytes.len(), Prot::READ)
        .expect("string buffer")
        .peer();
    fixture
        .emulator
        .memory()
        .pointer(address)
        .write_bytes(0, &bytes)
        .expect("write the string");
    address
}

/// A zeroed 32-byte arm64 `struct __va_list` in guest memory.
///
/// The header is read before any argument is, so even a call whose signature
/// takes nothing needs a real one -- a null `va_list` faults in the reader
/// rather than in the slot being tested.
fn guest_va_list(fixture: &Fixture) -> u64 {
    guest_va_list_with_arguments(fixture, &[])
}

/// The same, with `arguments` laid out in the GP register save area.
///
/// One eight-byte slot follows the 32-byte header per argument, `__gr_top`
/// sits a slot above the last of them and `__gr_offs` counts back down, which
/// is the shape the caller's own `va_start` leaves behind.
fn guest_va_list_with_arguments(fixture: &Fixture, arguments: &[u64]) -> u64 {
    const SLOT: usize = 8;
    let slots = arguments.len() as u64;
    let address = fixture
        .emulator
        .memory()
        .mmap(32 + SLOT * arguments.len(), Prot::READ)
        .expect("va_list page")
        .peer();
    let save_area = address + 32;
    let list = fixture.emulator.memory().pointer(address);
    list.write_bytes(0, &[0u8; 32]).expect("zero the header");
    for (index, value) in arguments.iter().enumerate() {
        list.write_u64(SLOT as u64 * index as u64 + 32, *value)
            .expect("the argument in the save area");
    }
    list.write_u64(0, save_area).expect("__stack");
    list.write_u64(8, save_area + SLOT as u64 * slots)
        .expect("__gr_top");
    list.write_u64(16, 0).expect("__vr_top");
    let gr_offs = -(SLOT as i32) * arguments.len() as i32;
    list.write_u32(24, gr_offs as u32).expect("__gr_offs");
    list.write_u32(28, 0).expect("__vr_offs");
    address
}

/// All three slots are reached through the table rather than a host shortcut,
/// so this asserts the only thing that matters about them: a call that used to
/// be recorded as missing now is not.
///
/// It also covers the reverse failure -- a slot that answered but recorded
/// itself unimplemented on the way -- because `unimplemented()` is what the CLI
/// prints as "JNI functions this port lacks".
#[test]
fn the_three_missing_slots_are_no_longer_unimplemented() {
    let fixture = Fixture::boot();
    let class = fixture.class();
    let class_hash = class.hash_code() as i64 as u64;
    let env = fixture.vm.borrow().jni_env();

    // Slot 115 takes a `va_list`; this method takes no arguments, so the
    // reader walks nothing and the slot's own dispatch is what is under test.
    let method_hash = fixture
        .vm
        .borrow_mut()
        .create_method(&class, "noArgs", "()Ljava/lang/Object;", true, 0)
        .hash_code() as i64 as u64;
    let va_list = guest_va_list(&fixture);
    fixture
        .emulator
        .call_function(
            slot_address(&fixture, 115),
            &[env, class_hash, method_hash, va_list],
        )
        .expect("CallStaticObjectMethodV runs");

    let name_ptr = guest_string(&fixture, "PADDED");
    let type_ptr = guest_string(&fixture, "I");
    let field = fixture
        .emulator
        .call_function(
            slot_address(&fixture, 144),
            &[env, class_hash, name_ptr, type_ptr],
        )
        .expect("GetStaticFieldID runs") as i64 as u64;
    fixture
        .emulator
        .call_function(slot_address(&fixture, 150), &[env, class_hash, field])
        .expect("GetStaticIntField runs");

    assert!(
        fixture.vm.borrow().unimplemented().is_empty(),
        "115, 144 and 150 are implemented, so nothing should be recorded: {:?}",
        fixture.vm.borrow().unimplemented()
    );
}

/// A `Jni` that keeps what slot 115 decoded out of the `va_list`.
///
/// It answers `currentActivityThread()` the way unidbg's `AbstractJni` does --
/// a fresh instance of the class -- rather than the test inventing a reference
/// hash that no other code path could produce.
struct RecordingJni {
    calls: Rc<RefCell<Vec<Vec<u64>>>>,
}

impl Jni for RecordingJni {
    fn call_static_object_method_v(
        &self,
        vm: &mut Vm,
        class: &Rc<DvmClass>,
        _method: &Rc<DvmMethod>,
        args: &[u64],
    ) -> Option<Rc<dyn DvmObject>> {
        self.calls.borrow_mut().push(args.to_vec());
        Some(vm.new_instance(class))
    }
}

/// The arm64 `va_list` is the ABI's own `struct __va_list`, not a JNI concept:
/// a stack cursor, the *tops* of the two register save areas, and a signed
/// offset into each that is negative while that save area still has room -- the
/// next slot is at `top + offset`, which is below the top, since a save area
/// fills downward from it. Nothing else in the port models that layout, so a
/// reader that took the wrong branch here would hand a host a
/// plausible-looking wrong number and no test would notice.
///
/// The save area is given a *different* value from the stack cursor's, so a
/// reader that skips the save area while a register slot is still available
/// fails rather than coincidentally agreeing.
#[test]
fn call_static_object_method_v_decodes_its_va_list() {
    const ARGUMENT: u32 = 0x1234_5678;
    const ON_THE_STACK: u32 = 0x7fff_ffff;

    let fixture = Fixture::boot();
    let class = fixture.class();
    // Built directly rather than through slot 113, so this test is about the
    // `va_list` reader and not about method-id resolution.
    let method_hash = fixture
        .vm
        .borrow_mut()
        .create_method(&class, "takeInt", "(I)Ljava/lang/Object;", true, 0)
        .hash_code();

    // 32 bytes of `__va_list`, then the eight-byte GP save area, then a
    // separate eight-byte stack area.
    let page = fixture
        .emulator
        .memory()
        .mmap(56, Prot::READ)
        .expect("va_list page")
        .peer();
    let save_area = page + 32;
    let stack_area = page + 48;
    fixture
        .emulator
        .memory()
        .pointer(save_area)
        .write_u32(0, ARGUMENT)
        .expect("the argument in the save area");
    fixture
        .emulator
        .memory()
        .pointer(stack_area)
        .write_u32(0, ON_THE_STACK)
        .expect("the poison argument on the stack");

    let list = fixture.emulator.memory().pointer(page);
    list.write_u64(0, stack_area).expect("__stack");
    // The top of the save area is one slot above the argument it holds.
    list.write_u64(8, save_area + 8).expect("__gr_top");
    list.write_u64(16, 0).expect("__vr_top");
    // One eight-byte slot left in the save area.
    list.write_u32(24, (-8i32) as u32).expect("__gr_offs");
    list.write_u32(28, 0).expect("__vr_offs");

    let calls = Rc::new(RefCell::new(Vec::new()));
    fixture.vm.borrow().set_jni(Box::new(RecordingJni {
        calls: Rc::clone(&calls),
    }));

    let env = fixture.vm.borrow().jni_env();
    let reference = fixture
        .emulator
        .call_function(
            slot_address(&fixture, 115),
            &[
                env,
                class.hash_code() as i64 as u64,
                method_hash as i64 as u64,
                page,
            ],
        )
        .expect("CallStaticObjectMethodV runs");

    assert_ne!(reference, 0, "a modelled static call answers a reference");
    let object = fixture
        .vm
        .borrow()
        .object(reference as i32)
        .expect("the returned reference names an object");
    assert_eq!(
        object.object_type(),
        class.name(),
        "the host's object is an instance of the class it was called on"
    );
    assert_eq!(
        calls.borrow().as_slice(),
        [vec![ARGUMENT as u64]],
        "the argument came off the register save area, not the stack"
    );
}

/// The other branch of the reader: once the register save area is exhausted,
/// the arguments are on the stack, which is where a call with more arguments
/// than the save area holds puts them.
///
/// The save area's offsets start non-negative here, so nothing can look like a
/// remaining register slot. Each argument is a full eight-byte stack slot and
/// so each advances the cursor to the next boundary -- a reader that advanced
/// by the argument's own width would hand the second argument the first one's
/// padding, and a reader that kept taking from the save area would fault.
#[test]
fn call_static_object_method_v_reads_arguments_off_the_stack() {
    const FIRST: i32 = 0x1122_3344;
    const SECOND: i32 = 0x5566_7788;

    let fixture = Fixture::boot();
    let class = fixture.class();
    let method_hash = fixture
        .vm
        .borrow_mut()
        .create_method(&class, "twoInts", "(II)Ljava/lang/Object;", true, 0)
        .hash_code();

    let page = fixture
        .emulator
        .memory()
        .mmap(32 + 32, Prot::READ)
        .expect("va_list page")
        .peer();
    let stack_area = page + 32;
    let memory = fixture.emulator.memory();
    // Two eight-byte slots, each holding its argument in the low four bytes
    // and zero above. A reader that advanced the cursor by four would find the
    // padding, and report zero.
    memory
        .pointer(stack_area)
        .write_u64(0, FIRST as u32 as u64)
        .expect("the first argument");
    memory
        .pointer(stack_area + 8)
        .write_u64(0, SECOND as u32 as u64)
        .expect("the second argument");

    let list = memory.pointer(page);
    list.write_u64(0, stack_area).expect("__stack");
    list.write_u64(8, 0).expect("__gr_top");
    list.write_u64(16, 0).expect("__vr_top");
    // Both save areas are spent: no argument may come from them.
    list.write_u32(24, 0).expect("__gr_offs");
    list.write_u32(28, 0).expect("__vr_offs");

    let calls = Rc::new(RefCell::new(Vec::new()));
    fixture.vm.borrow().set_jni(Box::new(RecordingJni {
        calls: Rc::clone(&calls),
    }));

    let env = fixture.vm.borrow().jni_env();
    fixture
        .emulator
        .call_function(
            slot_address(&fixture, 115),
            &[
                env,
                class.hash_code() as i64 as u64,
                method_hash as i64 as u64,
                page,
            ],
        )
        .expect("CallStaticObjectMethodV runs");

    assert_eq!(
        calls.borrow().as_slice(),
        [vec![FIRST as i64 as u64, SECOND as i64 as u64]],
        "both arguments came off the stack, eight bytes apart"
    );
}

/// The static-field path end to end: a name and a signature go in as guest
/// strings, an id comes out, and that id is what the read slot takes. The id
/// is a hash of `L<Class>;-><name>:<type>` rather than an invention, so the
/// guest can hold it across calls and the host can look it up again.
#[test]
fn a_static_field_id_resolves_and_reads_its_value() {
    const VALUE: i32 = 0x40;

    let fixture = Fixture::boot();
    let class = fixture.class();
    let env = fixture.vm.borrow().jni_env();
    let class_hash = class.hash_code() as i64 as u64;
    let name_ptr = guest_string(&fixture, "GET_SIGNATURES");
    let type_ptr = guest_string(&fixture, "I");

    let id = fixture
        .emulator
        .call_function(
            slot_address(&fixture, 144),
            &[env, class_hash, name_ptr, type_ptr],
        )
        .expect("GetStaticFieldID runs") as i32;
    let expected = fixture
        .vm
        .borrow()
        .hash_field(class.name(), "GET_SIGNATURES", "I");
    assert_eq!(id, expected, "the id is the field's hash");
    let field = fixture
        .vm
        .borrow()
        .field_by_hash(id)
        .expect("the id names a field");
    assert_eq!(field.name(), "GET_SIGNATURES");
    assert_eq!(field.field_type(), "I");

    // The value is the host's, published through the field rather than chosen
    // by the dispatch, which is the whole reason the field object exists.
    field.set_value(VALUE as i64);
    let value = fixture
        .emulator
        .call_function(
            slot_address(&fixture, 150),
            &[env, class_hash, id as i64 as u64],
        )
        .expect("GetStaticIntField runs");
    assert_eq!(
        value as i32, VALUE,
        "the read slot answers the host's value"
    );
}

/// A `jfieldID` the host never handed out is not a field. Answering with a
/// plausible-looking number here is how a caller would go on to branch on
/// garbage, so the slot answers zero like every other unresolved reference.
#[test]
fn an_unknown_field_answers_zero() {
    let fixture = Fixture::boot();
    let class = fixture.class();
    let env = fixture.vm.borrow().jni_env();

    let value = fixture
        .emulator
        .call_function(
            slot_address(&fixture, 150),
            &[env, class.hash_code() as i64 as u64, 0x0bad_f00d],
        )
        .expect("GetStaticIntField runs");
    assert_eq!(value, 0, "an id that was never registered reads as zero");
}

/// Slot 31 is what a packer calls on an object it has just been handed, to
/// reach the class it will look a method up on. Answering null here is what
/// made the guest's own ClassLoader bootstrap give up.
#[test]
fn get_object_class_answers_the_objects_type() {
    let fixture = Fixture::boot();
    let class = fixture.class();
    let instance = fixture.vm.borrow().new_instance(&class);
    let object_type = instance.object_type().to_string();
    let reference = fixture.vm.borrow().add_local(instance) as i64 as u64;
    let env = fixture.vm.borrow().jni_env();

    let answer = fixture
        .emulator
        .call_function(slot_address(&fixture, 31), &[env, reference])
        .expect("GetObjectClass runs") as i32;

    assert_ne!(answer, 0, "a live object has a type");
    assert_eq!(
        fixture
            .vm
            .borrow()
            .object(answer)
            .expect("the answer is a local reference")
            .object_type(),
        "Ljava/lang/Class;",
        "a jclass is a java.lang.Class"
    );
    assert_eq!(
        fixture
            .vm
            .borrow()
            .class_by_hash(answer)
            .expect("the answer names the class it was asked about")
            .name(),
        object_type,
        "and it is the object's own type, so the guest can ask it for methods"
    );
}

/// The whole point of the default model: with no `Jni` installed, a
/// `findClass` on a ClassLoader answers the class the guest named, instead of
/// the null that made the guest bail out of its own unpack path.
#[test]
fn the_default_model_finds_a_class_by_name() {
    const NAME: &str = "java/lang/Object";

    let fixture = Fixture::boot_with_default_jni();
    let env = fixture.vm.borrow().jni_env();
    // A `jstring` local reference, which is how the class name reaches the
    // host -- not a bare C string in guest memory.
    let name = fixture.vm.borrow().new_string(NAME) as i64 as u64;
    let loader = fixture
        .vm
        .borrow_mut()
        .resolve_class("java/lang/ClassLoader");
    // The receiver has to be a ClassLoader for the model to match the
    // signature at all -- that is how unidbg decides which call this is.
    let loader_ref = fixture.vm.borrow().new_instance(&loader);
    let receiver = fixture.vm.borrow().add_local(loader_ref) as i64 as u64;
    let method_hash = fixture
        .vm
        .borrow_mut()
        .create_method(
            &loader,
            "findClass",
            "(Ljava/lang/String;)Ljava/lang/Class;",
            false,
            0,
        )
        .hash_code() as i64 as u64;

    let answer = fixture
        .emulator
        .call_function(
            slot_address(&fixture, 35),
            &[
                env,
                receiver,
                method_hash,
                guest_va_list_with_arguments(&fixture, &[name]),
            ],
        )
        .expect("CallObjectMethodV runs") as i32;

    assert_ne!(answer, 0, "a modelled findClass answers a class, not null");
    assert_eq!(
        fixture
            .vm
            .borrow()
            .class_by_hash(answer)
            .expect("the answer is a jclass for the named class")
            .name(),
        "Ljava/lang/Object;",
        "and it is the class the guest asked for"
    );
}

/// The call the guest's ClassLoader bootstrap hangs off. A null here is not a
/// fault the guest reports -- it is a silent early return, which is why the
/// default model answers an instance rather than nothing.
#[test]
fn the_default_model_answers_current_activity_thread() {
    let fixture = Fixture::boot_with_default_jni();
    let env = fixture.vm.borrow().jni_env();
    let class = fixture
        .vm
        .borrow_mut()
        .resolve_class("android/app/ActivityThread");
    let class_hash = class.hash_code() as i64 as u64;
    let method_hash = fixture
        .vm
        .borrow_mut()
        .create_method(
            &class,
            "currentActivityThread",
            "()Landroid/app/ActivityThread;",
            true,
            0,
        )
        .hash_code() as i64 as u64;

    let answer = fixture
        .emulator
        .call_function(
            slot_address(&fixture, 115),
            &[
                env,
                class_hash,
                method_hash,
                guest_va_list_with_arguments(&fixture, &[]),
            ],
        )
        .expect("CallStaticObjectMethodV runs") as i32;

    assert_ne!(answer, 0, "currentActivityThread answers an object");
    assert_eq!(
        fixture
            .vm
            .borrow()
            .object(answer)
            .expect("the answer is a local reference")
            .object_type(),
        "Landroid/app/ActivityThread;",
        "the object is an ActivityThread, so the guest proceeds past its null check"
    );
}

/// A `Jni` that keeps what slot 34 handed it, and answers nothing -- the
/// minimum needed to tell the register-reading path apart from the `V` one.
struct RecordingObjectJni {
    calls: Rc<RefCell<Vec<Vec<u64>>>>,
}

impl Jni for RecordingObjectJni {
    fn call_object_method_v(
        &self,
        _vm: &mut Vm,
        _object: &Rc<dyn DvmObject>,
        _method: &Rc<DvmMethod>,
        args: &[u64],
    ) -> Option<Rc<dyn DvmObject>> {
        self.calls.borrow_mut().push(args.to_vec());
        None
    }
}

/// Slot 34 takes its arguments in registers, not behind a pointer, and a model
/// with no answer is a null return rather than a fault -- both are what the
/// guest sees for a method the host does not model.
#[test]
fn call_object_method_reads_its_arguments_from_the_registers() {
    const FIRST: u64 = 0x1122_3344_5566_7788;
    const SECOND: u64 = 0x0000_0000_9abc_def0;

    let fixture = Fixture::boot();
    let class = fixture.class();
    let instance = fixture.vm.borrow().new_instance(&class);
    let reference = fixture.vm.borrow().add_local(instance) as i64 as u64;
    let method_hash = fixture
        .vm
        .borrow_mut()
        .create_method(
            &class,
            "twoArgs",
            "(ILjava/lang/String;)Ljava/lang/Class;",
            false,
            0,
        )
        .hash_code() as i64 as u64;
    let calls = Rc::new(RefCell::new(Vec::new()));
    fixture.vm.borrow().set_jni(Box::new(RecordingObjectJni {
        calls: Rc::clone(&calls),
    }));
    let env = fixture.vm.borrow().jni_env();

    // The slot reads x3..x8 -- six registers, as `CallIntMethod` does -- so all
    // six are supplied here rather than left as whatever the previous call
    // happened to leave behind.
    let answer = fixture
        .emulator
        .call_function(
            slot_address(&fixture, 34),
            &[env, reference, method_hash, FIRST, SECOND, 0, 0, 0, 0],
        )
        .expect("CallObjectMethod runs");

    assert_eq!(answer, 0, "a model that answers nothing is a null return");
    assert_eq!(
        calls.borrow().as_slice(),
        [vec![FIRST, SECOND, 0, 0, 0, 0]],
        "the arguments came from x3..x7, ahead of the method's own signature"
    );
}

/// Builds a `JNINativeMethod` table in guest memory and returns its address.
///
/// The array is `{const char* name, const char* signature, void* fnPtr}` per
/// entry, three pointers wide, so the caller only has to say which methods it
/// is registering.
fn guest_native_methods(fixture: &Fixture, entries: &[(&str, &str, u64)]) -> u64 {
    const STRIDE: u64 = 24;
    let table = fixture
        .emulator
        .memory()
        .mmap((entries.len() as u64 * STRIDE) as usize, Prot::READ)
        .expect("native method table")
        .peer();
    let strings = fixture
        .emulator
        .memory()
        .mmap(entries.len() * 48, Prot::READ)
        .expect("native method strings")
        .peer();
    for (index, (name, signature, function)) in entries.iter().enumerate() {
        let name_at = guest_string(fixture, name);
        let signature_at = guest_string(fixture, signature);
        let entry = fixture
            .emulator
            .memory()
            .pointer(table + index as u64 * STRIDE);
        entry.write_pointer(0, name_at).expect("name pointer");
        entry
            .write_pointer(8, signature_at)
            .expect("signature pointer");
        entry.write_pointer(16, *function).expect("fnPtr");
        let _ = strings;
    }
    table
}

/// `RegisterNatives`' payload is the `JNINativeMethod` array, and a trace that
/// printed only `count=3` still could not answer "what does this library bind
/// into the VM?". Every field of every entry has to appear on the line.
#[test]
fn register_natives_prints_every_method_it_binds() {
    let fixture = Fixture::boot();
    let class = fixture.class();
    let env = fixture.vm.borrow().jni_env();
    let table = guest_native_methods(
        &fixture,
        &[
            ("load", "()V", 0x1200_1000),
            ("unload", "(I)Z", 0x1200_2000),
            ("check", "(Ljava/lang/String;)I", 0x1200_3000),
        ],
    );

    let line = jni_arguments(
        &fixture,
        "JNIEnv!RegisterNatives",
        &[env, class.hash_code() as i64 as u64, table, 3],
    );

    assert!(
        line.contains("count=3"),
        "the count is still part of the answer: {line}"
    );
    for (name, signature, function) in [
        ("load", "()V", 0x1200_1000u64),
        ("unload", "(I)Z", 0x1200_2000),
        ("check", "(Ljava/lang/String;)I", 0x1200_3000),
    ] {
        assert!(
            line.contains(&format!("\"{name}\" \"{signature}\" fn={function:#x}")),
            "the entry for `{name}` is missing from: {line}"
        );
    }
}

/// A `count` larger than the table really is must print the entries that exist,
/// not padding to match the number the guest claimed. A fabricated binding is
/// worse than a short line.
#[test]
fn a_register_natives_count_past_the_table_stops_at_the_last_entry() {
    let fixture = Fixture::boot();
    let class = fixture.class();
    let env = fixture.vm.borrow().jni_env();
    let table = guest_native_methods(&fixture, &[("only", "()V", 0x1200_1000)]);

    // Claims eight entries; the table holds one, and the rest is unmapped.
    let line = jni_arguments(
        &fixture,
        "JNIEnv!RegisterNatives",
        &[env, class.hash_code() as i64 as u64, table, 8],
    );

    assert!(
        line.contains("\"only\""),
        "the one real entry is shown: {line}"
    );
    assert_eq!(
        line.matches("fn=").count(),
        1,
        "no entry is invented to fill the count: {line}"
    );
}

/// The trace line for a JNI call, through the same seam the tracer uses.
fn jni_arguments(fixture: &Fixture, label: &str, args: &[u64]) -> String {
    let mut backend = fixture.emulator.backend().borrow_mut();
    for (index, value) in args.iter().enumerate() {
        backend
            .reg_write(RegId::X(index as u8), *value)
            .expect("write the argument register");
    }
    let memory = Rc::clone(fixture.emulator.loader().memory());
    format_jni_args(label, &mut *backend, memory.as_ref(), true)
        .expect("the label names a JNI function")
}
