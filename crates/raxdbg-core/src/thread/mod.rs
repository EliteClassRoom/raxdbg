//! Guest threads: the cooperative dispatcher and its tasks.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/arm/UniThreadDispatcher.java`
//! and `unidbg-android/src/main/java/com/github/unidbg/linux/thread/`@7f5da98e.

pub mod dispatcher;
pub mod waiter;

pub use dispatcher::{TaskState, ThreadDispatcher, ThreadTask};
pub use waiter::{Waiter, Waiters};
