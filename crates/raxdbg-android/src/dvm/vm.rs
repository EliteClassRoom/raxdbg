//! The Java VM: reference maps, the `JNIEnv`/`JavaVM` tables, and dispatch.
//!
//! Port of unidbg: `unidbg-android/src/main/java/com/github/unidbg/linux/android/dvm/{BaseVM,DalvikVM,DalvikVM64,DalvikModule}.java`
//! @7f5da98e.
//!
//! unidbg has no DEX interpreter. What stands in for a JVM is a table of SVC
//! stubs: `JNIEnv` is 234 pointer-sized slots in the SVC page, slot `i` holds
//! the address of a stub whose `svc` number maps back to JNI function `i`, and
//! a native's `(*env)->FindClass(env, ...)` therefore lands in
//! [`JniFunction::handle`] with the arguments still in the registers. The
//! *semantics* of each function come from the [`Jni`] trait, which is what a
//! user overrides to model their Java side — exactly as unidbg's `AbstractJni`
//! is overridable.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::{Rc, Weak};

use raxdbg_core::backend::{Backend, RunError};
use raxdbg_core::memory::{Memory, MemoryError};
use raxdbg_core::reg::RegId;
use raxdbg_core::svc::{Svc, SvcKind, SvcMemory};

use crate::dvm::hash::Hasher;
use crate::dvm::object::{
    normalize_class_name, DvmClass, DvmField, DvmMethod, DvmObject, InstanceObject,
    IntArrayObject, NumberObject, StringObject,
};
use crate::emulator::AndroidEmulator;

/// `JNI_VERSION_1_6`, what bionic and the fixtures expect.
pub const JNI_VERSION_1_6: i32 = 0x0001_0006;
/// `JNI_VERSION_1_8`, the other version a library may accept.
pub const JNI_VERSION_1_8: i32 = 0x0001_0008;
/// `JNI_ERR`, what a library returns to refuse a load.
pub const JNI_ERR: i32 = -1;
/// `JNI_OK`.
pub const JNI_OK: i32 = 0;
/// `JNI_ABORT`: free the buffer without copying changes back.
pub const JNI_ABORT: i32 = 2;
/// The last `JNIEnv` slot, `GetModule`. `DalvikVM`'s `last` is `0x3a4` in
/// 32-bit terms, which is `4 * 233`.
pub const JNI_TABLE_LAST: usize = 233;
/// The last `JavaVM` slot.
///
/// The `JNIInvokeInterface_` has eight entries: 0-2 reserved, 3
/// `DestroyJavaVM`, 4 `AttachCurrentThread`, 5 `DetachCurrentThread`, 6
/// `GetEnv` and 7 `AttachCurrentThreadAsDaemon` (JDK 21 invocation spec).
/// 7 is the last, and nothing beyond it exists.
pub const JAVA_VM_TABLE_LAST: usize = 7;

/// The `JavaVM` functions this port names a stub for, by slot.
///
/// Each is `name`, `slot`. A guest that calls one lands on a stub rather than
/// on the `index * 8` placeholder the table is filled with, and the call log
/// prints the name instead of an offset.
const JAVA_VM_SLOTS: &[(usize, &str)] = &[
    (3, "DestroyJavaVM"),
    (4, "AttachCurrentThread"),
    (5, "DetachCurrentThread"),
    (6, "GetEnv"),
    (7, "AttachCurrentThreadAsDaemon"),
];

/// The JNI functions this port implements, and the slot each occupies.
///
/// The numbering is the classic `JNINativeInterface` order, which is what
/// `DalvikVM`'s `_GetVersion = 0x10`, `_FindClass = 0x18` and so on encode for
/// 32-bit pointers; for 64-bit pointers the slot is the same and the byte
/// offset doubles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(usize)]
pub enum JniFunc {
    /// `GetVersion` — slot 4.
    GetVersion = 4,
    /// `FindClass` — slot 6.
    FindClass = 6,
    /// `ThrowNew` — slot 14.
    ThrowNew = 14,
    /// `NewGlobalRef` — slot 21.
    NewGlobalRef = 21,
    /// `DeleteLocalRef` — slot 23.
    DeleteLocalRef = 23,
    /// `NewObject` — slot 28.
    NewObject = 28,
    /// `GetMethodID` — slot 33.
    GetMethodID = 33,
    /// `CallIntMethod` — slot 49.
    CallIntMethod = 49,
    /// `GetStaticMethodID` — slot 113.
    GetStaticMethodID = 113,
    /// `CallStaticIntMethod` — slot 129.
    CallStaticIntMethod = 129,
    /// `NewStringUTF` — slot 167.
    NewStringUTF = 167,
    /// `GetStringUTFChars` — slot 169.
    GetStringUTFChars = 169,
    /// `ReleaseStringUTFChars` — slot 170.
    ReleaseStringUTFChars = 170,
    /// `GetArrayLength` — slot 171.
    GetArrayLength = 171,
    /// `GetIntArrayElements` — slot 187.
    GetIntArrayElements = 187,
    /// `ReleaseIntArrayElements` — slot 195.
    ReleaseIntArrayElements = 195,
    /// `RegisterNatives` — slot 215.
    RegisterNatives = 215,
    /// `GetJavaVM` — slot 219.
    ///
    /// Port of unidbg: `DalvikVM`'s `_GetJavaVM@0x36c`@7f5da98e, which
    /// writes the `JavaVM` handle through the caller's out-pointer and
    /// answers `JNI_OK`. A protection reads this to get a second handle on
    /// the VM and can then attach further threads through it.
    GetJavaVM = 219,
    /// `ExceptionCheck` — slot 228.
    ExceptionCheck = 228,
}

impl JniFunc {
    /// Every implemented function, in slot order.
    pub const ALL: [JniFunc; 19] = [
        JniFunc::GetVersion,
        JniFunc::FindClass,
        JniFunc::ThrowNew,
        JniFunc::NewGlobalRef,
        JniFunc::DeleteLocalRef,
        JniFunc::NewObject,
        JniFunc::GetMethodID,
        JniFunc::CallIntMethod,
        JniFunc::GetStaticMethodID,
        JniFunc::CallStaticIntMethod,
        JniFunc::NewStringUTF,
        JniFunc::GetStringUTFChars,
        JniFunc::ReleaseStringUTFChars,
        JniFunc::GetArrayLength,
        JniFunc::GetIntArrayElements,
        JniFunc::ReleaseIntArrayElements,
        JniFunc::RegisterNatives,
        JniFunc::GetJavaVM,
        JniFunc::ExceptionCheck,
    ];

    /// The slot.
    pub fn slot(self) -> usize {
        self as usize
    }

    /// The function's name, for diagnostics.
    pub fn name(self) -> &'static str {
        match self {
            JniFunc::GetVersion => "GetVersion",
            JniFunc::FindClass => "FindClass",
            JniFunc::ThrowNew => "ThrowNew",
            JniFunc::NewGlobalRef => "NewGlobalRef",
            JniFunc::DeleteLocalRef => "DeleteLocalRef",
            JniFunc::NewObject => "NewObject",
            JniFunc::GetMethodID => "GetMethodID",
            JniFunc::CallIntMethod => "CallIntMethod",
            JniFunc::GetStaticMethodID => "GetStaticMethodID",
            JniFunc::CallStaticIntMethod => "CallStaticIntMethod",
            JniFunc::NewStringUTF => "NewStringUTF",
            JniFunc::GetStringUTFChars => "GetStringUTFChars",
            JniFunc::ReleaseStringUTFChars => "ReleaseStringUTFChars",
            JniFunc::GetArrayLength => "GetArrayLength",
            JniFunc::GetIntArrayElements => "GetIntArrayElements",
            JniFunc::ReleaseIntArrayElements => "ReleaseIntArrayElements",
            JniFunc::RegisterNatives => "RegisterNatives",
            JniFunc::GetJavaVM => "GetJavaVM",
            JniFunc::ExceptionCheck => "ExceptionCheck",
        }
    }
}

/// What the host answers for the Java side.
///
/// Port of unidbg: `Jni.java` and `AbstractJni.java`, reduced to the methods
/// this port dispatches. The defaults are `AbstractJni`'s where it has one: a
/// class is a name, a method is a name and a signature, and a call with no host
/// model answers zero. A caller that needs real Java behaviour implements this
/// trait and hands it to [`Vm::set_jni`].
pub trait Jni {
    /// Resolves a class by name.
    fn find_class(&self, vm: &mut Vm, name: &str) -> Option<Rc<DvmClass>> {
        Some(vm.resolve_class(name))
    }

    /// Resolves a static method.
    fn get_static_method_id(
        &self,
        vm: &mut Vm,
        class: &Rc<DvmClass>,
        name: &str,
        signature: &str,
    ) -> Option<Rc<DvmMethod>> {
        Some(vm.create_method(class, name, signature, true, 0))
    }

    /// Resolves an instance method or constructor.
    fn get_method_id(
        &self,
        vm: &mut Vm,
        class: &Rc<DvmClass>,
        name: &str,
        signature: &str,
    ) -> Option<Rc<DvmMethod>> {
        Some(vm.create_method(class, name, signature, false, 0))
    }

    /// Calls a static method returning an `int`.
    fn call_static_int_method(
        &self,
        _vm: &mut Vm,
        _class: &Rc<DvmClass>,
        _method: &Rc<DvmMethod>,
        _args: &[u64],
    ) -> i32 {
        0
    }

    /// Calls an instance method returning an `int`.
    fn call_int_method(
        &self,
        _vm: &mut Vm,
        _object: &Rc<dyn DvmObject>,
        _method: &Rc<DvmMethod>,
        _args: &[u64],
    ) -> i32 {
        0
    }

    /// Constructs an instance.
    fn new_object(
        &self,
        vm: &mut Vm,
        class: &Rc<DvmClass>,
        _ctor: &Rc<DvmMethod>,
        _args: &[u64],
    ) -> Option<Rc<dyn DvmObject>> {
        Some(vm.new_instance(class))
    }
}

/// A `Jni` that answers nothing: the starting point for a caller that only
/// wants the native side to run.
#[derive(Debug, Default)]
pub struct NoJni;

impl Jni for NoJni {}

/// Why a JNI operation failed.
#[derive(Debug, thiserror::Error)]
pub enum JniError {
    /// Guest memory refused the access.
    #[error(transparent)]
    Memory(#[from] MemoryError),
    /// The module does not export `JNI_OnLoad`.
    #[error("{0} does not export JNI_OnLoad")]
    NoOnLoad(String),
    /// `JNI_OnLoad` returned something other than a version or `JNI_OK`.
    #[error("JNI_OnLoad returned {0:#x}, which is neither a version nor JNI_OK")]
    OnLoadFailed(i32),
    /// The guest call failed.
    #[error(transparent)]
    Emulator(#[from] crate::emulator::EmulatorError),
    /// The emulator has no SVC page, so it has no JNI.
    #[error("the emulator has no SVC page")]
    NoSvcPage,
    /// No module exports the native for this method.
    #[error("no loaded module exports the native for {0}")]
    NoNative(String),
}

/// The Java VM.
pub struct Vm {
    hasher: Hasher,
    is_64bit: bool,
    pointer_size: u64,
    memory: Rc<raxdbg_core::memory::loader::Loader>,
    svc: Rc<SvcMemory>,
    jni: RefCell<Box<dyn Jni>>,
    classes_by_name: RefCell<BTreeMap<String, Rc<DvmClass>>>,
    classes_by_hash: RefCell<BTreeMap<i32, Rc<DvmClass>>>,
    methods: RefCell<BTreeMap<i32, Rc<DvmMethod>>>,
    fields: RefCell<BTreeMap<i32, Rc<DvmField>>>,
    local: RefCell<BTreeMap<i32, Rc<dyn DvmObject>>>,
    global: RefCell<BTreeMap<i32, Rc<dyn DvmObject>>>,
    weak: RefCell<BTreeMap<i32, Rc<dyn DvmObject>>>,
    next_hash: Cell<i32>,
    exception: RefCell<Option<Rc<dyn DvmObject>>>,
    jni_env: Cell<u64>,
    java_vm: Cell<u64>,
    jni_version: i32,
    /// Whether `JNI_OnLoad` has run.
    on_load_ran: Cell<bool>,
    /// The `JNIEnv` slots the guest called that this port does not
    /// implement, in the order it first called them.
    unimplemented: RefCell<Vec<usize>>,
}

impl std::fmt::Debug for Vm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vm")
            .field("is_64bit", &self.is_64bit)
            .field("hasher", &self.hasher)
            .field("classes", &self.classes_by_name.borrow().len())
            .field("local_refs", &self.local.borrow().len())
            .field("global_refs", &self.global.borrow().len())
            .finish()
    }
}

impl Vm {
    /// Creates a VM and builds its `JNIEnv` and `JavaVM` tables.
    pub fn create(emulator: &Rc<AndroidEmulator>) -> Result<Rc<RefCell<Vm>>, JniError> {
        let svc = emulator
            .loader()
            .svc_memory()
            .ok_or(JniError::NoSvcPage)?;
        let vm = Rc::new(RefCell::new(Vm {
            hasher: Hasher::Default,
            is_64bit: emulator.is_64bit(),
            pointer_size: if emulator.is_64bit() { 8 } else { 4 },
            memory: Rc::clone(emulator.memory()),
            svc,
            jni: RefCell::new(Box::new(NoJni)),
            classes_by_name: RefCell::new(BTreeMap::new()),
            classes_by_hash: RefCell::new(BTreeMap::new()),
            methods: RefCell::new(BTreeMap::new()),
            fields: RefCell::new(BTreeMap::new()),
            local: RefCell::new(BTreeMap::new()),
            global: RefCell::new(BTreeMap::new()),
            weak: RefCell::new(BTreeMap::new()),
            next_hash: Cell::new(0x1000),
            exception: RefCell::new(None),
            jni_env: Cell::new(0),
            java_vm: Cell::new(0),
            jni_version: JNI_VERSION_1_6,
            on_load_ran: Cell::new(false),
            unimplemented: RefCell::new(Vec::new()),
        }));
        Vm::build_tables(&vm)?;
        Ok(vm)
    }

    /// The hasher this VM keys references on.
    pub fn hasher(&self) -> Hasher {
        self.hasher
    }

    /// Replaces the hasher. Must be called before any class is resolved.
    pub fn set_hasher(&mut self, hasher: Hasher) {
        self.hasher = hasher;
    }

    /// The JNI version reported by `GetVersion`.
    pub fn jni_version(&self) -> i32 {
        self.jni_version
    }

    /// Installs the host's Java model.
    pub fn set_jni(&self, jni: Box<dyn Jni>) {
        *self.jni.borrow_mut() = jni;
    }

    /// The `JNIEnv` pointer a native receives.
    pub fn jni_env(&self) -> u64 {
        self.jni_env.get()
    }

    /// The `JavaVM` pointer `JNI_OnLoad` receives.
    pub fn java_vm(&self) -> u64 {
        self.java_vm.get()
    }

    /// The `JNIEnv` slots the guest called that this port does not
    /// implement, in first-call order.
    ///
    /// A library that needs one of these keeps running and returns 0 for
    /// the call, so the list is the honest answer to "what is missing
    /// before this library runs correctly".
    pub fn unimplemented(&self) -> Vec<usize> {
        self.unimplemented.borrow().clone()
    }

    /// Notes that the guest called the unimplemented JNI function at `slot`.
    fn record_unimplemented(&self, slot: usize) {
        let mut recorded = self.unimplemented.borrow_mut();
        if !recorded.contains(&slot) {
            recorded.push(slot);
        }
    }

    /// Whether the guest is 64-bit.
    pub fn is_64bit(&self) -> bool {
        self.is_64bit
    }

    /// The guest memory.
    pub fn memory(&self) -> &Rc<raxdbg_core::memory::loader::Loader> {
        &self.memory
    }

    /// The reference hasher's view of a class descriptor.
    pub fn hash_class(&self, name: &str) -> i32 {
        self.hasher.hash(&normalize_class_name(name))
    }

    /// The id for a method of `class`.
    ///
    /// Port of unidbg: `DvmClass.getMethodID`, which hashes
    /// `L<Class>;-><name><signature>`.
    pub fn hash_method(&self, class: &str, name: &str, signature: &str) -> i32 {
        self.hasher
            .hash(&format!("{}->{}{}", normalize_class_name(class), name, signature))
    }

    /// The id for a field of `class`.
    ///
    /// Port of unidbg: `DvmClass.getFieldID`, which hashes
    /// `L<Class>;-><name>:<type>`.
    pub fn hash_field(&self, class: &str, name: &str, field_type: &str) -> i32 {
        self.hasher
            .hash(&format!("{}->{}:{}", normalize_class_name(class), name, field_type))
    }

    /// Resolves a class, creating it on first use.
    pub fn resolve_class(&mut self, name: &str) -> Rc<DvmClass> {
        let descriptor = normalize_class_name(name);
        if let Some(class) = self.classes_by_name.borrow().get(&descriptor) {
            return Rc::clone(class);
        }
        let hash = self.hash_class(&descriptor);
        let class = Rc::new(DvmClass::new(descriptor.clone(), hash));
        self.classes_by_name
            .borrow_mut()
            .insert(descriptor, Rc::clone(&class));
        self.classes_by_hash
            .borrow_mut()
            .insert(hash, Rc::clone(&class));
        class
    }

    /// The class a `jclass` refers to.
    pub fn class_by_hash(&self, hash: i32) -> Option<Rc<DvmClass>> {
        self.classes_by_hash.borrow().get(&hash).cloned()
    }

    /// Creates and registers a method id.
    pub fn create_method(
        &mut self,
        class: &Rc<DvmClass>,
        name: &str,
        signature: &str,
        is_static: bool,
        address: u64,
    ) -> Rc<DvmMethod> {
        let hash = self.hash_method(class.name(), name, signature);
        if let Some(method) = self.methods.borrow().get(&hash) {
            return Rc::clone(method);
        }
        let method = Rc::new(DvmMethod::new(
            class.name(),
            name,
            signature,
            address,
            is_static,
            hash,
        ));
        self.methods.borrow_mut().insert(hash, Rc::clone(&method));
        method
    }

    /// The method a `jmethodID` refers to.
    pub fn method_by_hash(&self, hash: i32) -> Option<Rc<DvmMethod>> {
        self.methods.borrow().get(&hash).cloned()
    }

    /// Creates and registers a field id.
    pub fn create_field(
        &mut self,
        class: &Rc<DvmClass>,
        name: &str,
        field_type: &str,
    ) -> Rc<DvmField> {
        let hash = self.hash_field(class.name(), name, field_type);
        if let Some(field) = self.fields.borrow().get(&hash) {
            return Rc::clone(field);
        }
        let field = Rc::new(DvmField::new(class.name(), name, field_type, hash));
        self.fields.borrow_mut().insert(hash, Rc::clone(&field));
        field
    }

    /// The field a `jfieldID` refers to.
    pub fn field_by_hash(&self, hash: i32) -> Option<Rc<DvmField>> {
        self.fields.borrow().get(&hash).cloned()
    }

    /// The next identity hash.
    fn next_identity(&self) -> i32 {
        let hash = self.next_hash.get();
        self.next_hash.set(hash.wrapping_add(1));
        hash
    }

    /// Adds an object as a local reference and returns the reference.
    pub fn add_local(&self, object: Rc<dyn DvmObject>) -> i32 {
        let hash = object.hash_code();
        self.local.borrow_mut().insert(hash, object);
        hash
    }

    /// Wraps a string as a local reference.
    pub fn new_string(&self, value: impl Into<String>) -> i32 {
        let hash = self.next_identity();
        self.add_local(Rc::new(StringObject::new(value, hash)))
    }

    /// Wraps an `int[]` as a local reference.
    pub fn new_int_array(&self, values: Vec<i32>) -> i32 {
        let hash = self.next_identity();
        self.add_local(Rc::new(IntArrayObject::new(values, hash)))
    }

    /// A fresh instance of `class`, as a local reference.
    pub fn new_instance(&self, class: &Rc<DvmClass>) -> Rc<dyn DvmObject> {
        let hash = self.next_identity();
        Rc::new(InstanceObject::new(class.name(), hash))
    }

    /// The object a reference names, looking in locals then globals.
    pub fn object(&self, hash: i32) -> Option<Rc<dyn DvmObject>> {
        if let Some(object) = self.local.borrow().get(&hash) {
            return Some(Rc::clone(object));
        }
        if let Some(object) = self.global.borrow().get(&hash) {
            return Some(Rc::clone(object));
        }
        self.weak.borrow().get(&hash).cloned()
    }

    /// Promotes a reference to a global one, as `NewGlobalRef` does.
    pub fn new_global_ref(&self, hash: i32) -> Option<i32> {
        let object = self.object(hash)?;
        self.local.borrow_mut().remove(&hash);
        self.global.borrow_mut().insert(hash, object);
        Some(hash)
    }

    /// Drops a local reference.
    pub fn delete_local_ref(&self, hash: i32) {
        self.local.borrow_mut().remove(&hash);
    }

    /// Drops every local reference.
    pub fn delete_local_refs(&self) {
        self.local.borrow_mut().clear();
    }

    /// The references that are live now, for [`Vm::drop_locals_created_since`].
    pub fn local_keys(&self) -> Vec<i32> {
        self.local.borrow().keys().copied().collect()
    }

    /// Drops the local references created since `before`, keeping `keep`.
    ///
    /// This is unidbg's `deleteLocalRefs` as a host-driven call uses it: the
    /// references the *call* created are freed, while the caller's own and the
    /// one it returns survive — the caller is holding them.
    pub fn drop_locals_created_since(&self, before: &[i32], keep: i32) {
        self.local
            .borrow_mut()
            .retain(|hash, _| before.contains(hash) || *hash == keep);
    }

    /// Drops a global reference.
    pub fn delete_global_ref(&self, hash: i32) {
        self.global.borrow_mut().remove(&hash);
    }

    /// How many local references are live.
    pub fn local_ref_count(&self) -> usize {
        self.local.borrow().len()
    }

    /// How many global references are live.
    pub fn global_ref_count(&self) -> usize {
        self.global.borrow().len()
    }

    /// Whether a throwable is pending.
    pub fn has_exception(&self) -> bool {
        self.exception.borrow().is_some()
    }

    /// The pending throwable.
    pub fn exception(&self) -> Option<Rc<dyn DvmObject>> {
        self.exception.borrow().clone()
    }

    /// Raises a throwable, as `ThrowNew` does.
    pub fn set_exception(&self, object: Rc<dyn DvmObject>) {
        *self.exception.borrow_mut() = Some(object);
    }

    /// Clears the pending throwable.
    pub fn clear_exception(&self) -> Option<Rc<dyn DvmObject>> {
        self.exception.borrow_mut().take()
    }

    /// Whether `JNI_OnLoad` has run.
    pub fn on_load_ran(&self) -> bool {
        self.on_load_ran.get()
    }

    /// Reads a NUL-terminated string from guest memory.
    ///
    /// Port of unidbg: `BaseVM.readCString`, which is also what
    /// `GetStringUTFChars` hands back.
    pub fn read_cstring(&self, address: u64) -> Result<String, MemoryError> {
        let mut bytes = Vec::new();
        let pointer = self.memory.pointer(address);
        let mut offset = 0u64;
        loop {
            let chunk = pointer.get_bytes(offset, 64)?;
            let end = chunk.iter().position(|byte| *byte == 0);
            match end {
                Some(index) => {
                    bytes.extend_from_slice(&chunk[..index]);
                    break;
                }
                None => {
                    bytes.extend_from_slice(&chunk);
                    offset += 64;
                    if bytes.len() > 1 << 20 {
                        break;
                    }
                }
            }
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Allocates `len` bytes of guest memory the guest may read and write.
    fn allocate_buffer(&self, len: usize) -> Result<raxdbg_core::alloc::MemoryBlock, MemoryError> {
        self.memory.malloc_impl(len.max(8), false)
    }

    /// Builds the `JNIEnv` and `JavaVM` tables.
    ///
    /// Port of unidbg: `DalvikVM`'s constructor, which fills every slot with
    /// its own byte offset as a bogus pointer and then overwrites the slots it
    /// implements with the address of the stub `registerSvc` returns.
    fn build_tables(this: &Rc<RefCell<Vm>>) -> Result<(), JniError> {
        let this_weak = Rc::downgrade(this);
        let vm = this.borrow();
        let pointer_size = vm.pointer_size;
        // `JNIEnv` and `JavaVM` are handles: what a native receives is the
        // address of a word holding the table, because the guest writes
        // `(*env)->FindClass(env, ...)` — `(*env)` is the table and the `env` it
        // passes on is the handle. unidbg's `DalvikVM` allocates both the same
        // way, and getting this wrong shows up as a fault at `slot * 8`.
        let env_size = (JNI_TABLE_LAST + 1) as u64 * pointer_size;
        let env_table = vm.svc.allocate(env_size as usize, "JNIEnv table")?;
        let jni_env = vm.svc.allocate(pointer_size as usize, "JNIEnv")?;
        vm.write_pointer(jni_env, 0, env_table)?;
        vm.jni_env.set(jni_env);

        let java_vm_size = (JAVA_VM_TABLE_LAST + 1) as u64 * pointer_size;
        let vm_table = vm.svc.allocate(java_vm_size as usize, "JavaVM table")?;
        let java_vm = vm.svc.allocate(pointer_size as usize, "JavaVM")?;
        vm.write_pointer(java_vm, 0, vm_table)?;
        vm.java_vm.set(java_vm);

        for index in 0..=JNI_TABLE_LAST {
            vm.write_pointer(env_table, index, index as u64 * pointer_size)?;
        }
        for index in 0..=JAVA_VM_TABLE_LAST {
            vm.write_pointer(vm_table, index, index as u64 * pointer_size)?;
        }

        for function in JniFunc::ALL {
            let stub = JniFunction::new(
                function,
                this_weak.clone(),
                Rc::clone(&vm.memory),
                vm.is_64bit,
            );
            let (address, _number) = vm
                .svc
                .register_svc_numbered(vm.memory.as_ref(), Box::new(stub))?;
            vm.write_pointer(env_table, function.slot(), address)?;
        }

        // Every slot the table does not implement gets a stub of its own. The
        // placeholder `index * 8` the loop above writes is an *unmapped*
        // address that a guest may well branch to, so a call that reaches an
        // unimplemented function faults on the jump rather than on the work;
        // the stub records the slot and answers 0 instead, which turns "this
        // library needs a JNI function this port lacks" into a report rather
        // than a crash.
        for index in 0..=JNI_TABLE_LAST {
            if JniFunc::ALL.iter().any(|function| function.slot() == index) {
                continue;
            }
            let stub = UnimplementedJniFunction {
                vm: this_weak.clone(),
                slot: index,
                is_64bit: vm.is_64bit,
            };
            let (address, _number) = vm
                .svc
                .register_svc_numbered(vm.memory.as_ref(), Box::new(stub))?;
            vm.write_pointer(env_table, index, address)?;
        }

        // Every named `JavaVM` function gets a stub of its own. A shared stub
        // would report as the generic "JavaVM" in a call log, which tells a
        // reader nothing; naming each one is what makes the log say `GetEnv`.
        // They all answer `JNI_OK` and, for the two that take an out-pointer,
        // hand back the `JNIEnv`.
        for (slot, name) in JAVA_VM_SLOTS {
            let stub = JavaVmFunction {
                vm: this_weak.clone(),
                is_64bit: vm.is_64bit,
                label: format!("JavaVM!{name}"),
            };
            let (address, _number) = vm
                .svc
                .register_svc_numbered(vm.memory.as_ref(), Box::new(stub))?;
            vm.write_pointer(vm_table, *slot, address)?;
        }
        Ok(())
    }

    fn write_pointer(&self, table: u64, index: usize, value: u64) -> Result<(), MemoryError> {
        let offset = index as u64 * self.pointer_size;
        let pointer = self.memory.pointer(table + offset);
        if self.pointer_size == 8 {
            pointer.write_u64(0, value)
        } else {
            pointer.write_u32(0, value as u32)
        }
    }

    /// Calls a static native method by name and signature.
    ///
    /// Port of unidbg: `DvmClass.callStaticJniMethod`, which resolves the
    /// native (`natives_map` first, then `Java_<mangled>`), puts the environment
    /// and the class in front of the arguments, and calls it. Local references
    /// are dropped afterwards, as unidbg does in a `finally`.
    pub fn call_static_jni_method(
        emulator: &Rc<AndroidEmulator>,
        vm: &Rc<RefCell<Vm>>,
        class_name: &str,
        name: &str,
        signature: &str,
        args: &[u64],
    ) -> Result<i64, JniError> {
        let (jni_env, class_hash, address) = {
            let mut vm = vm.borrow_mut();
            let class = vm.resolve_class(class_name);
            let address = class
                .find_native_function(name, signature, |symbol| {
                    emulator.loader().dlsym(0, symbol).map(|symbol| symbol.address)
                })
                .ok_or_else(|| JniError::NoNative(format!("{class_name}->{name}{signature}")))?;
            (vm.jni_env(), class.hash_code(), address)
        };
        let mut full = Vec::with_capacity(args.len() + 2);
        full.push(jni_env);
        full.push(class_hash as u64);
        full.extend_from_slice(args);
        let before = vm.borrow().local_keys();
        let result = emulator.call_function(address, &full)?;
        vm.borrow()
            .drop_locals_created_since(&before, result as i32);
        Ok(result as i64)
    }

    /// Runs `JNI_OnLoad` in `module`, if it has one.
    ///
    /// Port of unidbg: `DalvikModule.callJNI_OnLoad`, which passes the
    /// `JavaVM`, accepts `JNI_VERSION_1_6`/`1_8`/`JNI_OK` and refuses
    /// `JNI_ERR`.
    pub fn call_jni_on_load(
        emulator: &Rc<AndroidEmulator>,
        vm: &Rc<RefCell<Vm>>,
        module: &str,
    ) -> Result<i32, JniError> {
        let java_vm = vm.borrow().java_vm();
        let Some(symbol) = emulator.loader().find_symbol(module, "JNI_OnLoad") else {
            return Err(JniError::NoOnLoad(module.to_string()));
        };
        let result = emulator.call_function(symbol.address, &[java_vm])? as i32;
        if result == JNI_ERR {
            return Err(JniError::OnLoadFailed(result));
        }
        if result != JNI_VERSION_1_6 && result != JNI_VERSION_1_8 && result != JNI_OK {
            return Err(JniError::OnLoadFailed(result));
        }
        vm.borrow().on_load_ran.set(true);
        Ok(result)
    }
}

/// The `JNIEnv` slot stub: every JNI function is one of these.
///
/// The stub is named `JNIEnv!<function>` so a call log distinguishes it from
/// the `JavaVM` entry points, which have the same signatures and different
/// behaviour.
struct JniFunction {
    function: JniFunc,
    vm: Weak<RefCell<Vm>>,
    memory: Rc<raxdbg_core::memory::loader::Loader>,
    is_64bit: bool,
    /// `<table>!<function>`, owned because it is built once at registration.
    label: String,
}

impl JniFunction {
    fn new(function: JniFunc, vm: Weak<RefCell<Vm>>, memory: Rc<raxdbg_core::memory::loader::Loader>, is_64bit: bool) -> Self {
        let label = format!("JNIEnv!{}", function.name());
        Self {
            function,
            vm,
            memory,
            is_64bit,
            label,
        }
    }
}

impl Svc for JniFunction {
    fn handle(&mut self, backend: &mut dyn Backend) -> Result<i64, RunError> {
        let Some(vm) = self.vm.upgrade() else {
            return Ok(0);
        };
        let mut vm = vm.borrow_mut();
        let memory = Rc::clone(&self.memory);
        let is_64bit = self.is_64bit;
        dispatch(&mut vm, self.function, backend, &memory, is_64bit)
    }

    fn kind(&self) -> SvcKind {
        if self.is_64bit {
            SvcKind::Arm64
        } else {
            SvcKind::Arm
        }
    }

    fn name(&self) -> &str {
        &self.label
    }
}

/// The `JavaVM` slot stub: `DestroyJavaVM`, `AttachCurrentThread`,
/// `DetachCurrentThread`, `GetEnv` and `AttachCurrentThreadAsDaemon`.
///
/// One stub per slot rather than one shared, so that a call log names the
/// function the guest called instead of the table it called through.
struct JavaVmFunction {
    vm: Weak<RefCell<Vm>>,
    is_64bit: bool,
    /// `JavaVM!<function>`, owned because it is built once at registration.
    label: String,
}

impl JavaVmFunction {
    /// Whether this entry point takes no out-pointer.
    ///
    /// `DetachCurrentThread` and `DestroyJavaVM` return a status and nothing
    /// else; the other three hand back a `JNIEnv`.
    fn is_terminal(&self) -> bool {
        matches!(
            self.label.as_str(),
            "JavaVM!DetachCurrentThread" | "JavaVM!DestroyJavaVM"
        )
    }
}

impl Svc for JavaVmFunction {
    fn handle(&mut self, backend: &mut dyn Backend) -> Result<i64, RunError> {
        if self.is_terminal() {
            // Neither takes an out-pointer: detaching reports success, and
            // destroying the emulated VM is not something a guest may do --
            // it would end the run the caller is in the middle of.
            return Ok(JNI_OK as i64);
        }
        let Some(vm) = self.vm.upgrade() else {
            return Ok(0);
        };
        let vm = vm.borrow();
        // `GetEnv(vm, void **p_env, jint version)` and
        // `AttachCurrentThread(vm, void **p_env, void *args)` share a shape:
        // x1 is the out-pointer, x2 the requested version for `GetEnv`.
        let out = arg(backend, self.is_64bit, 0);
        let requested = arg(backend, self.is_64bit, 1) as i32;
        if out != 0 {
            write_word(backend, self.is_64bit, out, vm.jni_env(), vm.pointer_size)
                .map_err(RunError::Backend)?;
        }
        // A version the VM does not provide is `JNI_EVERSION` (-3).
        if self.label == "JavaVM!GetEnv" && requested != 0 && requested != vm.jni_version() {
            return Ok(-3);
        }
        Ok(JNI_OK as i64)
    }

    fn kind(&self) -> SvcKind {
        if self.is_64bit {
            SvcKind::Arm64
        } else {
            SvcKind::Arm
        }
    }

    fn name(&self) -> &str {
        &self.label
    }
}

/// Runs `f` with the host's `Jni`, handing it `&mut Vm`.
///
/// The host implementation is moved out for the duration so it can borrow the
/// VM mutably: a `Jni` method takes both, and unidbg's Java side does the same
/// through its own indirection.
fn with_jni<T>(vm: &mut Vm, f: impl FnOnce(&dyn Jni, &mut Vm) -> T) -> T {
    let jni = std::mem::replace(&mut *vm.jni.borrow_mut(), Box::new(NoJni));
    let result = f(&*jni, vm);
    *vm.jni.borrow_mut() = jni;
    result
}

fn arg(backend: &mut dyn Backend, is_64bit: bool, index: u64) -> u64 {
    let register = if is_64bit {
        RegId::X((index + 1) as u8)
    } else {
        RegId::R((index + 1) as u8)
    };
    backend.reg_read(register).unwrap_or(0)
}

fn write_word(
    backend: &mut dyn Backend,
    is_64bit: bool,
    address: u64,
    value: u64,
    pointer_size: u64,
) -> Result<(), raxdbg_core::backend::BackendError> {
    let bytes = if pointer_size == 8 {
        value.to_le_bytes().to_vec()
    } else {
        (value as u32).to_le_bytes().to_vec()
    };
    backend.mem_write(address, &bytes)
}

fn dispatch(
    vm: &mut Vm,
    function: JniFunc,
    backend: &mut dyn Backend,
    memory: &Rc<raxdbg_core::memory::loader::Loader>,
    is_64bit: bool,
) -> Result<i64, RunError> {
    let pointer_size = vm.pointer_size;
    match function {
        JniFunc::GetVersion => Ok(vm.jni_version() as i64),
        JniFunc::FindClass => {
            let address = arg(backend, is_64bit, 0);
            let name = vm.read_cstring(address).map_err(|error| RunError::Backend(raxdbg_core::backend::BackendError::Other(error.to_string())))?;
            let class = with_jni(vm, |jni, vm| jni.find_class(vm, &name));
            Ok(match class {
                Some(class) => {
                    let hash = class.hash_code();
                    vm.classes_by_name
                        .borrow_mut()
                        .insert(class.name().to_string(), Rc::clone(&class));
                    vm.classes_by_hash.borrow_mut().insert(hash, class);
                    vm.add_local(Rc::new(ClassObject::new(hash)));
                    hash as i64
                }
                None => 0,
            })
        }
        JniFunc::RegisterNatives => {
            let class_hash = arg(backend, is_64bit, 0) as i32;
            let methods = arg(backend, is_64bit, 1);
            let count = arg(backend, is_64bit, 2) as usize;
            let Some(class) = vm.class_by_hash(class_hash) else {
                return Ok(-1);
            };
            let stride = 3 * pointer_size;
            for index in 0..count {
                let entry = methods + index as u64 * stride;
                let name_ptr = read_pointer(memory, entry, pointer_size)?;
                let signature_ptr = read_pointer(memory, entry + pointer_size, pointer_size)?;
                let function_ptr =
                    read_pointer(memory, entry + 2 * pointer_size, pointer_size)?;
                let name = vm.read_cstring(name_ptr).map_err(|error| RunError::Backend(raxdbg_core::backend::BackendError::Other(error.to_string())))?;
                let signature = vm.read_cstring(signature_ptr).map_err(|error| RunError::Backend(raxdbg_core::backend::BackendError::Other(error.to_string())))?;
                class.register_native(&name, &signature, function_ptr);
            }
            Ok(JNI_OK as i64)
        }
        JniFunc::GetStaticMethodID | JniFunc::GetMethodID => {
            let class_hash = arg(backend, is_64bit, 0) as i32;
            let name_ptr = arg(backend, is_64bit, 1);
            let signature_ptr = arg(backend, is_64bit, 2);
            let Some(class) = vm.class_by_hash(class_hash) else {
                return Ok(0);
            };
            let name = vm.read_cstring(name_ptr).map_err(|error| RunError::Backend(raxdbg_core::backend::BackendError::Other(error.to_string())))?;
            let signature = vm.read_cstring(signature_ptr).map_err(|error| RunError::Backend(raxdbg_core::backend::BackendError::Other(error.to_string())))?;
            let is_static = function == JniFunc::GetStaticMethodID;
            let method = with_jni(vm, |jni, vm| {
                if is_static {
                    jni.get_static_method_id(vm, &class, &name, &signature)
                } else {
                    jni.get_method_id(vm, &class, &name, &signature)
                }
            });
            Ok(match method {
                Some(method) => {
                    let hash = method.hash_code();
                    vm.methods.borrow_mut().insert(hash, method);
                    hash as i64
                }
                None => 0,
            })
        }
        JniFunc::CallStaticIntMethod => {
            let class_hash = arg(backend, is_64bit, 0) as i32;
            let method_hash = arg(backend, is_64bit, 1) as i32;
            let args: Vec<u64> = (2..8).map(|i| arg(backend, is_64bit, i)).collect();
            let (Some(class), Some(method)) =
                (vm.class_by_hash(class_hash), vm.method_by_hash(method_hash))
            else {
                return Ok(0);
            };
            method.note_invocation();
            let value = with_jni(vm, |jni, vm| {
                jni.call_static_int_method(vm, &class, &method, &args)
            });
            Ok(value as i64)
        }
        JniFunc::CallIntMethod => {
            let object_hash = arg(backend, is_64bit, 0) as i32;
            let method_hash = arg(backend, is_64bit, 1) as i32;
            let args: Vec<u64> = (2..8).map(|i| arg(backend, is_64bit, i)).collect();
            let (Some(object), Some(method)) = (vm.object(object_hash), vm.method_by_hash(method_hash))
            else {
                return Ok(0);
            };
            method.note_invocation();
            let value = with_jni(vm, |jni, vm| jni.call_int_method(vm, &object, &method, &args));
            Ok(value as i64)
        }
        JniFunc::NewObject => {
            let class_hash = arg(backend, is_64bit, 0) as i32;
            let ctor_hash = arg(backend, is_64bit, 1) as i32;
            let args: Vec<u64> = (2..8).map(|i| arg(backend, is_64bit, i)).collect();
            let Some(class) = vm.class_by_hash(class_hash) else {
                return Ok(0);
            };
            let ctor = vm.method_by_hash(ctor_hash);
            let object = with_jni(vm, |jni, vm| match &ctor {
                Some(ctor) => jni.new_object(vm, &class, ctor, &args),
                None => Some(vm.new_instance(&class)),
            });
            Ok(match object {
                Some(object) => vm.add_local(object) as i64,
                None => 0,
            })
        }
        JniFunc::NewStringUTF => {
            let address = arg(backend, is_64bit, 0);
            if address == 0 {
                return Ok(0);
            }
            let value = vm.read_cstring(address).map_err(|error| RunError::Backend(raxdbg_core::backend::BackendError::Other(error.to_string())))?;
            let hash = vm.new_string(value);
            Ok(hash as i64)
        }
        JniFunc::GetStringUTFChars => {
            let hash = arg(backend, is_64bit, 0) as i32;
            let Some(object) = vm.object(hash) else {
                return Ok(0);
            };
            let Some(string) = object.as_any().downcast_ref::<StringObject>() else {
                return Ok(0);
            };
            if let Some((pointer, _)) = string.buffer.borrow().as_ref() {
                return Ok(*pointer as i64);
            }
            let mut bytes = string.value().as_bytes().to_vec();
            bytes.push(0);
            let block = vm.allocate_buffer(bytes.len()).map_err(|error| RunError::Backend(raxdbg_core::backend::BackendError::Other(error.to_string())))?;
            block
                .pointer()
                .write_bytes(0, &bytes)
                .map_err(|error| RunError::Backend(raxdbg_core::backend::BackendError::Other(error.to_string())))?;
            let pointer = block.pointer().peer();
            *string.buffer.borrow_mut() = Some((pointer, block));
            Ok(pointer as i64)
        }
        JniFunc::ReleaseStringUTFChars => {
            let hash = arg(backend, is_64bit, 0) as i32;
            if let Some(object) = vm.object(hash) {
                if let Some(string) = object.as_any().downcast_ref::<StringObject>() {
                    if let Some((_, block)) = string.buffer.borrow_mut().take() {
                        let _ = block.free();
                    }
                }
            }
            Ok(0)
        }
        JniFunc::GetArrayLength => {
            let hash = arg(backend, is_64bit, 0) as i32;
            let Some(object) = vm.object(hash) else {
                return Ok(0);
            };
            match object.as_any().downcast_ref::<IntArrayObject>() {
                Some(array) => Ok(array.len() as i64),
                None => Ok(0),
            }
        }
        JniFunc::GetIntArrayElements => {
            let hash = arg(backend, is_64bit, 0) as i32;
            let Some(object) = vm.object(hash) else {
                return Ok(0);
            };
            let Some(array) = object.as_any().downcast_ref::<IntArrayObject>() else {
                return Ok(0);
            };
            let memory = Rc::clone(memory);
            let pointer = array.elements_pointer(|len| memory.malloc_impl(len, false).ok());
            Ok(pointer.unwrap_or(0) as i64)
        }
        JniFunc::ReleaseIntArrayElements => {
            let hash = arg(backend, is_64bit, 0) as i32;
            let mode = arg(backend, is_64bit, 2) as i32;
            if mode != JNI_ABORT {
                if let Some(object) = vm.object(hash) {
                    if let Some(array) = object.as_any().downcast_ref::<IntArrayObject>() {
                        array.sync_from_guest();
                    }
                }
            }
            Ok(0)
        }
        JniFunc::ExceptionCheck => Ok(i64::from(vm.has_exception())),
        JniFunc::GetJavaVM => {
            // `(*env)->GetJavaVM(JNIEnv **vm)`. A `JNIEnv` function's arguments
            // start at `x1` -- `x0` is the environment the table was read from,
            // which is what `arg(0)` returns -- so the out-pointer is `arg(0)`.
            let out = arg(backend, is_64bit, 0);
            if out != 0 {
                write_word(backend, is_64bit, out, vm.java_vm(), pointer_size)
                    .map_err(RunError::Backend)?;
            }
            Ok(i64::from(JNI_OK))
        }
        JniFunc::ThrowNew => {
            let class_hash = arg(backend, is_64bit, 0) as i32;
            let message_ptr = arg(backend, is_64bit, 1);
            let class = vm
                .class_by_hash(class_hash)
                .unwrap_or_else(|| vm.resolve_class("java/lang/Throwable"));
            let message = if message_ptr == 0 {
                String::new()
            } else {
                vm.read_cstring(message_ptr).map_err(|error| RunError::Backend(raxdbg_core::backend::BackendError::Other(error.to_string())))?
            };
            let hash = vm.next_identity();
            vm.set_exception(Rc::new(InstanceObject::new(
                format!("{}: {message}", class.name()),
                hash,
            )));
            Ok(0)
        }
        JniFunc::NewGlobalRef => {
            let hash = arg(backend, is_64bit, 0) as i32;
            Ok(vm.new_global_ref(hash).unwrap_or(0) as i64)
        }
        JniFunc::DeleteLocalRef => {
            let hash = arg(backend, is_64bit, 0) as i32;
            vm.delete_local_ref(hash);
            Ok(0)
        }
    }
}

/// The `JNIEnv` slot every function this port does not implement points at.
///
/// A real `JNIEnv` is a 234-entry table and most libraries touch a handful
/// of entries. Answering an unimplemented call with a logged 0 is what
/// unidbg does for a function it has not ported, and it turns a hard fault
/// at an unmapped slot address into a line in
/// [`Vm::unimplemented`], which is the list of JNI functions a library
/// needs before it can be emulated.
struct UnimplementedJniFunction {
    vm: std::rc::Weak<RefCell<Vm>>,
    slot: usize,
    is_64bit: bool,
}

impl Svc for UnimplementedJniFunction {
    fn handle(&mut self, _backend: &mut dyn Backend) -> Result<i64, RunError> {
        if let Some(vm) = self.vm.upgrade() {
            vm.borrow_mut().record_unimplemented(self.slot);
        }
        Ok(0)
    }

    fn kind(&self) -> SvcKind {
        if self.is_64bit {
            SvcKind::Arm64
        } else {
            SvcKind::Arm
        }
    }

    fn name(&self) -> &str {
        "JNIEnv!<unimplemented>"
    }
}

/// A `jclass` reference: a `DvmObject` view of a class.
#[derive(Debug)]
struct ClassObject {
    hash: i32,
}

impl ClassObject {
    fn new(hash: i32) -> Self {
        ClassObject { hash }
    }
}

impl DvmObject for ClassObject {
    fn object_type(&self) -> &str {
        "Ljava/lang/Class;"
    }

    fn hash_code(&self) -> i32 {
        self.hash
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn read_pointer(
    memory: &Rc<raxdbg_core::memory::loader::Loader>,
    address: u64,
    pointer_size: u64,
) -> Result<u64, RunError> {
    let pointer = memory.pointer(address);
    if pointer_size == 8 {
        pointer
            .read_u64(0)
            .map_err(|error| RunError::Backend(raxdbg_core::backend::BackendError::Other(error.to_string())))
    } else {
        pointer
            .read_u32(0)
            .map(|value| value as u64)
            .map_err(|error| RunError::Backend(raxdbg_core::backend::BackendError::Other(error.to_string())))
    }
}
