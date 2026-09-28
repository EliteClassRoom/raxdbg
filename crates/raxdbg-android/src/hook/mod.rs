//! Hook engines and the replace/intercept machinery.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/hook/`@7f5da98e.

pub mod replace;

pub use replace::{HookError, InvocationContext, ReplaceCallback, ReplaceHook};
