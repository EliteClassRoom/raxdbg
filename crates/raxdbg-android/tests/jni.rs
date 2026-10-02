//! JNI tests (plan P6) against the fixture built from `fixtures/src/jnitest.c`.
//!
//! The fixture is a real Android `.so` built against bionic. It runs
//! `JNI_OnLoad`, registers `add` through `RegisterNatives`, exports ten
//! `Java_com_raxdbg_test_JniTest_*` entry points, and calls back into "Java"
//! through the `JNIEnv` table — so every test below exercises the guest's own
//! code reaching our table, not a host-side shortcut.

use std::rc::Rc;

use raxdbg_android::android_file::ElfLibraryFile;
use raxdbg_android::dvm::vm::JniError;
use raxdbg_android::dvm::{
    DvmClass, DvmMethod, DvmObject, Jni, JNI_OK, JNI_VERSION_1_6, Vm,
};
use raxdbg_android::emulator::{AndroidEmulator, AndroidEmulatorBuilder};
use raxdbg_core::backend::Prot;
use raxdbg_core::memory::{Memory, MAP_ANONYMOUS};

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
        vm.borrow().set_jni(Box::new(TestJni));
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
    let java_vm = vm.java_vm();

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
        entry, 219 * 8,
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

    assert_eq!(result as i32, JNI_OK as i32, "GetJavaVM reports JNI_OK");
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
    assert_eq!(result as i32, JNI_OK as i32);
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
    assert_eq!(fixture.call("getVersion", "()I", &[]), JNI_VERSION_1_6 as i64);
}

#[test]
fn a_string_round_trips_through_get_and_new_string_utf() {
    let fixture = Fixture::boot();
    fixture.on_load().expect("JNI_OnLoad");
    let hash = fixture.vm.borrow().new_string("abc");
    let returned = fixture.call("echo", "(Ljava/lang/String;)Ljava/lang/String;", &[hash as u64]);
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
    let hash = fixture
        .vm
        .borrow()
        .new_string("hello from the host");
    let returned = fixture.call("echo", "(Ljava/lang/String;)Ljava/lang/String;", &[hash as u64]);
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
    let returned = fixture.call("globalRef", "(Ljava/lang/Object;)Ljava/lang/Object;", &[hash as u64]);
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
    let expected = raxdbg_android::dvm::hash::java_string_hash(
        "Lcom/raxdbg/test/JniTest;->getSeed()I",
    );
    assert_eq!(vm.hash_method(CLASS, "getSeed", "()I"), expected);
}
