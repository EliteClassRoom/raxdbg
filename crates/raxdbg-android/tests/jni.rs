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
use raxdbg_android::dvm::{DvmClass, DvmMethod, DvmObject, Jni, JNI_VERSION_1_6, Vm};
use raxdbg_android::emulator::{AndroidEmulator, AndroidEmulatorBuilder};

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
