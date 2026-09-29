//! Android-specific host services.
//!
//! Port of unidbg: `unidbg-android/src/main/java/com/github/unidbg/linux/android/`@7f5da98e.

pub mod arm_ld;
pub mod atexit;
pub mod resolver;
pub mod system_property;
pub mod virtual_module;

pub use arm_ld::{ArmLd, ArmLd64};
pub use resolver::{AndroidResolver, LOG_PATH_PREFIX, ResolverError, default_libs_dir};
pub use system_property::{PROP_VALUE_MAX, SystemPropertyHook, SystemPropertyProvider};
pub use virtual_module::{
    AndroidModule, JniGraphics, MediaNdkModule, SystemProperties, register_virtual_module,
};
