//! The Java-side reference model: objects, classes, methods and fields.
//!
//! Port of unidbg: `unidbg-android/src/main/java/com/github/unidbg/linux/android/dvm/{DvmObject,DvmClass,DvmMethod,DvmField,StringObject,array/IntArray}.java`
//! @7f5da98e.
//!
//! There is no DEX interpreter and no host JVM: a `jobject` is a 32-bit
//! identity hash, a `jclass` is the hash of its descriptor, and a
//! `jmethodID`/`jfieldID` is a hash of the class, name and type. Everything the
//! guest can observe about "Java" is one of these integers plus the maps in
//! [`crate::dvm::vm::Vm`] that hold the objects they stand for.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use raxdbg_core::alloc::MemoryBlock;

/// A reference the guest holds.
pub trait DvmObject: std::fmt::Debug {
    /// The JNI type descriptor, e.g. `Ljava/lang/String;`.
    fn object_type(&self) -> &str;

    /// The value the guest sees as this reference.
    fn hash_code(&self) -> i32;

    /// For downcasting.
    fn as_any(&self) -> &dyn Any;
}

/// A `java.lang.String`.
#[derive(Debug)]
pub struct StringObject {
    value: String,
    hash: i32,
    /// The UTF-8 bytes `GetStringUTFChars` handed out, kept so
    /// `ReleaseStringUTFChars` can free them.
    pub(crate) buffer: RefCell<Option<(u64, MemoryBlock)>>,
}

impl StringObject {
    /// Wraps `value` with the reference `hash`.
    pub fn new(value: impl Into<String>, hash: i32) -> Self {
        StringObject {
            value: value.into(),
            hash,
            buffer: RefCell::new(None),
        }
    }

    /// The text.
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl DvmObject for StringObject {
    fn object_type(&self) -> &str {
        "Ljava/lang/String;"
    }

    fn hash_code(&self) -> i32 {
        self.hash
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A boxed primitive, e.g. a `java.lang.Integer`.
#[derive(Debug)]
pub struct NumberObject {
    value: i64,
    object_type: String,
    hash: i32,
}

impl NumberObject {
    /// Wraps `value` as an object of type `object_type`.
    pub fn new(object_type: impl Into<String>, value: i64, hash: i32) -> Self {
        NumberObject {
            value,
            object_type: object_type.into(),
            hash,
        }
    }

    /// The value.
    pub fn value(&self) -> i64 {
        self.value
    }
}

impl DvmObject for NumberObject {
    fn object_type(&self) -> &str {
        &self.object_type
    }

    fn hash_code(&self) -> i32 {
        self.hash
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// An instance of a class we have no host model for: what `NewObject` returns.
#[derive(Debug)]
pub struct InstanceObject {
    class: String,
    hash: i32,
    /// Fields set through `Set*Field`, keyed by `name:type`.
    fields: RefCell<BTreeMap<String, i64>>,
}

impl InstanceObject {
    /// A fresh instance of `class`.
    pub fn new(class: impl Into<String>, hash: i32) -> Self {
        InstanceObject {
            class: class.into(),
            hash,
            fields: RefCell::new(BTreeMap::new()),
        }
    }

    /// The class descriptor.
    pub fn class(&self) -> &str {
        &self.class
    }

    /// Reads a field.
    pub fn get_field(&self, name: &str) -> Option<i64> {
        self.fields.borrow().get(name).copied()
    }

    /// Writes a field.
    pub fn set_field(&self, name: &str, value: i64) {
        self.fields.borrow_mut().insert(name.to_string(), value);
    }
}

impl DvmObject for InstanceObject {
    fn object_type(&self) -> &str {
        &self.class
    }

    fn hash_code(&self) -> i32 {
        self.hash
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// An `int[]`.
///
/// `GetIntArrayElements` must hand the guest a pointer it can read and write,
/// so the values live in a guest allocation from the moment they are first
/// asked for; `ReleaseIntArrayElements` copies back unless the caller passed
/// `JNI_ABORT`.
#[derive(Debug)]
pub struct IntArrayObject {
    values: RefCell<Vec<i32>>,
    elements: RefCell<Option<MemoryBlock>>,
    hash: i32,
}

impl IntArrayObject {
    /// An array of `values`.
    pub fn new(values: Vec<i32>, hash: i32) -> Self {
        IntArrayObject {
            values: RefCell::new(values),
            elements: RefCell::new(None),
            hash,
        }
    }

    /// The number of elements.
    pub fn len(&self) -> usize {
        self.values.borrow().len()
    }

    /// Whether the array is empty.
    pub fn is_empty(&self) -> bool {
        self.values.borrow().is_empty()
    }

    /// The elements.
    pub fn values(&self) -> Vec<i32> {
        self.values.borrow().clone()
    }

    /// The guest pointer the elements live at, allocating it on first use and
    /// refreshing it from `values`.
    pub fn elements_pointer(&self, allocate: impl FnOnce(usize) -> Option<MemoryBlock>) -> Option<u64> {
        let mut elements = self.elements.borrow_mut();
        if elements.is_none() {
            let values = self.values.borrow();
            let block = allocate(values.len() * 4)?;
            for (index, value) in values.iter().enumerate() {
                block
                    .pointer()
                    .write_u32(index as u64 * 4, *value as u32)
                    .ok()?;
            }
            *elements = Some(block);
        }
        elements.as_ref().map(|block| block.pointer().peer())
    }

    /// Copies the guest's edits back.
    pub fn sync_from_guest(&self) {
        if let Some(block) = self.elements.borrow().as_ref() {
            let count = self.values.borrow().len();
            let mut values = self.values.borrow_mut();
            for (index, slot) in values.iter_mut().enumerate().take(count) {
                if let Ok(value) = block.pointer().read_u32(index as u64 * 4) {
                    *slot = value as i32;
                }
            }
        }
    }
}

impl DvmObject for IntArrayObject {
    fn object_type(&self) -> &str {
        "[I"
    }

    fn hash_code(&self) -> i32 {
        self.hash
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A class the guest can name.
///
/// `natives_map` is what `RegisterNatives` fills and what
/// `find_native_function` consults before it looks for a `Java_<mangled>`
/// symbol.
#[derive(Debug)]
pub struct DvmClass {
    name: String,
    hash: i32,
    natives: RefCell<BTreeMap<String, u64>>,
}

impl DvmClass {
    /// A class named `name` (either `com/raxdbg/test/JniTest` or
    /// `Lcom/raxdbg/test/JniTest;`) with reference `hash`.
    pub fn new(name: impl Into<String>, hash: i32) -> Self {
        DvmClass {
            name: normalize_class_name(&name.into()),
            hash,
            natives: RefCell::new(BTreeMap::new()),
        }
    }

    /// The descriptor, always in `L...;` form.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The class's reference.
    pub fn hash_code(&self) -> i32 {
        self.hash
    }

    /// Records a `RegisterNatives` entry.
    pub fn register_native(&self, name: &str, signature: &str, address: u64) {
        self.natives
            .borrow_mut()
            .insert(format!("{name}{signature}"), address);
    }

    /// A `RegisterNatives` entry, if the class has one for `name(signature)`.
    pub fn native_address(&self, name: &str, signature: &str) -> Option<u64> {
        self.natives.borrow().get(&format!("{name}{signature}")).copied()
    }

    /// Every `RegisterNatives` entry, as `name(signature)` → address.
    pub fn natives(&self) -> BTreeMap<String, u64> {
        self.natives.borrow().clone()
    }

    /// How many entries `RegisterNatives` has added.
    pub fn native_count(&self) -> usize {
        self.natives.borrow().len()
    }

    /// The `Java_<mangled>` symbol name for a static native method.
    ///
    /// Port of unidbg: `DvmClass.mangleForJni`.
    pub fn mangled_symbol(&self, name: &str, is_static: bool) -> String {
        let class = self
            .name
            .trim_start_matches('L')
            .trim_end_matches(';');
        let mut symbol = String::from("Java_");
        symbol.push_str(&mangle_for_jni(class));
        symbol.push('_');
        symbol.push_str(&mangle_for_jni(name));
        if !is_static {
            symbol.push_str("__");
            symbol.push_str(&mangle_for_jni("")); // the class argument is part of the overload set
        }
        symbol
    }

    /// Resolves a native method: `natives_map` first, then `Java_<mangled>`.
    pub fn find_native_function(
        &self,
        name: &str,
        signature: &str,
        lookup: impl Fn(&str) -> Option<u64>,
    ) -> Option<u64> {
        if let Some(address) = self.native_address(name, signature) {
            return Some(address);
        }
        for is_static in [true, false] {
            if let Some(address) = lookup(&self.mangled_symbol(name, is_static)) {
                return Some(address);
            }
        }
        None
    }
}

/// Turns a class name into its `L...;` descriptor.
pub fn normalize_class_name(name: &str) -> String {
    if name.starts_with('L') && name.ends_with(';') {
        name.to_string()
    } else {
        format!("L{name};")
    }
}

/// JNI's name mangling.
///
/// Port of unidbg: `DvmClass.mangleForJni` — `_` becomes `_1`, `/` and `.`
/// become `_`, `;` becomes `_2`, `[` becomes `_3`, and every other character
/// outside the identifier set becomes `_0` followed by four hex digits.
pub fn mangle_for_jni(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '_' => out.push_str("_1"),
            '/' | '.' => out.push('_'),
            ';' => out.push_str("_2"),
            '[' => out.push_str("_3"),
            'a'..='z' | 'A'..='Z' | '0'..='9' => out.push(ch),
            other => {
                let code = other as u32;
                if code <= 0xffff {
                    out.push_str(&format!("_0{code:04x}"));
                } else {
                    out.push_str(&format!("_0{code:08x}"));
                }
            }
        }
    }
    out
}

/// A method the guest has an id for.
#[derive(Debug)]
pub struct DvmMethod {
    class: String,
    name: String,
    signature: String,
    address: u64,
    is_static: bool,
    hash: i32,
    /// How many times a host callback has run this method, for tests.
    invocations: Cell<usize>,
}

impl DvmMethod {
    /// A method of `class` with the given name and signature.
    pub fn new(
        class: impl Into<String>,
        name: impl Into<String>,
        signature: impl Into<String>,
        address: u64,
        is_static: bool,
        hash: i32,
    ) -> Self {
        DvmMethod {
            class: normalize_class_name(&class.into()),
            name: name.into(),
            signature: signature.into(),
            address,
            is_static,
            hash,
            invocations: Cell::new(0),
        }
    }

    /// The declaring class.
    pub fn class(&self) -> &str {
        &self.class
    }

    /// The method name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The signature.
    pub fn signature(&self) -> &str {
        &self.signature
    }

    /// The guest address, or 0 when the host answers for this method.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Whether the method is static.
    pub fn is_static(&self) -> bool {
        self.is_static
    }

    /// The method's id.
    pub fn hash_code(&self) -> i32 {
        self.hash
    }

    /// `name(signature)`, the form unidbg's `Jni` methods match on.
    pub fn description(&self) -> String {
        format!("{}{}", self.name, self.signature)
    }

    /// Records a host callback.
    pub fn note_invocation(&self) {
        self.invocations.set(self.invocations.get() + 1);
    }

    /// How many host callbacks have run.
    pub fn invocations(&self) -> usize {
        self.invocations.get()
    }
}

/// A field the guest has an id for.
#[derive(Debug)]
pub struct DvmField {
    class: String,
    name: String,
    field_type: String,
    hash: i32,
    /// The value `Get*Field` answers with, when the host owns the field.
    value: Cell<i64>,
}

impl DvmField {
    /// A field of `class` with the given name and type.
    pub fn new(
        class: impl Into<String>,
        name: impl Into<String>,
        field_type: impl Into<String>,
        hash: i32,
    ) -> Self {
        DvmField {
            class: normalize_class_name(&class.into()),
            name: name.into(),
            field_type: field_type.into(),
            hash,
            value: Cell::new(0),
        }
    }

    /// The declaring class.
    pub fn class(&self) -> &str {
        &self.class
    }

    /// The field name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The field type.
    pub fn field_type(&self) -> &str {
        &self.field_type
    }

    /// The field's id.
    pub fn hash_code(&self) -> i32 {
        self.hash
    }

    /// The host value.
    pub fn value(&self) -> i64 {
        self.value.get()
    }

    /// Sets the host value.
    pub fn set_value(&self, value: i64) {
        self.value.set(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jni_mangling_matches_the_specification() {
        // JNI's "name mangling" table.
        assert_eq!(mangle_for_jni("com/raxdbg/test/JniTest"), "com_raxdbg_test_JniTest");
        assert_eq!(mangle_for_jni("add"), "add");
        assert_eq!(mangle_for_jni("a_b"), "a_1b");
        assert_eq!(mangle_for_jni("a.b"), "a_b");
        assert_eq!(mangle_for_jni("Lcom/x/Y;"), "Lcom_x_Y_2");
        assert_eq!(mangle_for_jni("[I"), "_3I");
        assert_eq!(mangle_for_jni("a-b"), "a_0002db"); // '-' is 0x2d, 4 hex digits
    }

    #[test]
    fn a_class_knows_its_java_symbol_name() {
        let class = DvmClass::new("com/raxdbg/test/JniTest", 1);
        assert_eq!(class.name(), "Lcom/raxdbg/test/JniTest;");
        assert_eq!(
            class.mangled_symbol("add2", true),
            "Java_com_raxdbg_test_JniTest_add2"
        );
    }

    #[test]
    fn register_natives_fills_the_map_and_wins_over_the_symbol() {
        let class = DvmClass::new("com/raxdbg/test/JniTest", 1);
        class.register_native("add", "(II)I", 0x1234);
        assert_eq!(class.native_count(), 1);
        assert_eq!(class.native_address("add", "(II)I"), Some(0x1234));
        // The map is consulted first...
        assert_eq!(
            class.find_native_function("add", "(II)I", |_| Some(0xdead)),
            Some(0x1234)
        );
        // ...and a name the map does not have falls through to the symbol.
        assert_eq!(
            class.find_native_function("add2", "(II)I", |symbol| {
                (symbol == "Java_com_raxdbg_test_JniTest_add2").then_some(0xbeef)
            }),
            Some(0xbeef)
        );
    }

    #[test]
    fn a_methods_description_is_what_the_jni_trait_matches_on() {
        let method = DvmMethod::new("com/raxdbg/test/JniTest", "getSeed", "()I", 0, true, 7);
        assert_eq!(method.description(), "getSeed()I");
        assert_eq!(method.class(), "Lcom/raxdbg/test/JniTest;");
        assert_eq!(method.invocations(), 0);
        method.note_invocation();
        assert_eq!(method.invocations(), 1);
    }
}
