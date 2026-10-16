//! The default host model for the Java side.
//!
//! Port of unidbg: `AbstractJni.java` @7f5da98e, reduced to the signatures the
//! Android bootstrap a packed library performs. unidbg's `BaseVM` installs an
//! `AbstractJni` when a caller sets none; this port does the same, because a
//! `currentActivityThread()` that answers null makes a packer's own code bail
//! out silently -- the failure mode this model exists to remove.

use std::rc::Rc;

use super::object::{DvmClass, DvmMethod, DvmObject, StringObject};
use super::vm::{Jni, Vm};

/// unidbg's `AbstractJni` match key: `Class->method(signature)`.
///
/// [`DvmClass::name`] is the `L...;` descriptor; unidbg's key uses the binary
/// name, so the `L` and `;` come off.
fn key(class: &DvmClass, method: &DvmMethod) -> String {
    format!(
        "{}->{}",
        class.name().trim_start_matches('L').trim_end_matches(';'),
        method.description()
    )
}

/// The text a `jstring` reference holds, or `None` if it names no string.
///
/// unidbg's `AbstractJni` reads the name straight out of the argument's
/// `StringObject`; anything else is not a name and leaves the call unmodelled.
fn string_argument(vm: &Vm, reference: u64) -> Option<String> {
    let object = vm.object(reference as i32)?;
    let string = object.as_any().downcast_ref::<StringObject>()?;
    Some(string.value().to_string())
}

/// The Android bootstrap model. See the module docs.
#[derive(Debug, Default)]
pub struct AbstractJni;

impl Jni for AbstractJni {
    fn call_static_object_method_v(
        &self,
        vm: &mut Vm,
        class: &Rc<DvmClass>,
        method: &Rc<DvmMethod>,
        _args: &[u64],
    ) -> Option<Rc<dyn DvmObject>> {
        match key(class, method).as_str() {
            // AbstractJni.java:446 -- the handle a ClassLoader bootstrap hangs
            // off. A null here is not a crash but a silent early return in the
            // guest, which is why it is modelled rather than left null.
            "android/app/ActivityThread->currentActivityThread()Landroid/app/ActivityThread;" => {
                Some(vm.new_instance(class))
            }
            // AbstractJni.java:448.
            "android/app/ActivityThread->currentApplication()Landroid/app/Application;" => {
                let application = vm.resolve_class("android/app/Application");
                Some(vm.new_instance(&application))
            }
            _ => None,
        }
    }

    fn call_object_method_v(
        &self,
        vm: &mut Vm,
        object: &Rc<dyn DvmObject>,
        method: &Rc<DvmMethod>,
        args: &[u64],
    ) -> Option<Rc<dyn DvmObject>> {
        // `findClass`/`loadClass(String)` take the class name as a local
        // reference in argument 0; unidbg's ProxyMethod.java:58 treats the two
        // names as the same call.
        //
        // The key is bound before the match so the `resolve_class` borrow
        // behind it ends there rather than reaching into every arm.
        let key = key(&vm.resolve_class(object.object_type()), method);
        match key.as_str() {
            // The guest asks the ActivityThread it just received for the
            // Application, then that Application for its ClassLoader. unidbg's
            // `AbstractJni` models the *static* `currentApplication()` twin,
            // not this instance method; a null here routed the guest into its
            // own fallback path, which dies in its varargs setup.
            "android/app/ActivityThread->getApplication()Landroid/app/Application;" => {
                let application = vm.resolve_class("android/app/Application");
                Some(vm.new_instance(&application))
            }
            "java/lang/ClassLoader->findClass(Ljava/lang/String;)Ljava/lang/Class;"
            | "java/lang/ClassLoader->loadClass(Ljava/lang/String;)Ljava/lang/Class;" => {
                let name = string_argument(vm, args.first().copied()?)?;
                let class = vm.resolve_class(&name);
                Some(vm.new_class_ref(&class))
            }
            // AbstractJni.java:270/929 -- the classloader of anything is a
            // classloader.
            "android/app/ActivityThread->getClassLoader()Ljava/lang/ClassLoader;"
            | "android/app/Application->getClassLoader()Ljava/lang/ClassLoader;"
            | "java/lang/Class->getClassLoader()Ljava/lang/ClassLoader;" => {
                let class_loader = vm.resolve_class("java/lang/ClassLoader");
                Some(vm.new_instance(&class_loader))
            }
            _ => None,
        }
    }
}
