//! The Java side of JNI: references, classes, and the `JNIEnv` table.
//!
//! Port of unidbg: `unidbg-android/src/main/java/com/github/unidbg/linux/android/dvm/`@7f5da98e.
//!
//! unidbg has no DEX interpreter and no host JVM. The `dvm` module is therefore
//! the whole Java side of this port: a `jobject` is a 32-bit identity hash, a
//! `jmethodID` is a hash of the class, name and signature, and the `JNIEnv` the
//! guest calls through is a table of SVC stubs that land in [`vm::dispatch`].

pub mod hash;
pub mod object;
pub mod vm;

pub use hash::{Hashable, Hasher};
pub use object::{
    mangle_for_jni, normalize_class_name, DvmClass, DvmField, DvmMethod, DvmObject,
    InstanceObject, IntArrayObject, NumberObject, StringObject,
};
pub use vm::{
    Jni, JniError, JniFunc, NoJni, Vm, JAVA_VM_TABLE_LAST, JNI_ABORT, JNI_ERR, JNI_OK,
    JNI_TABLE_LAST, JNI_VERSION_1_6, JNI_VERSION_1_8,
};
