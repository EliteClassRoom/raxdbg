//! Debugger core (plan P11).
//!
//! Port of unidbg's `com.github.unidbg.debugger` package: the breakpoint
//! infrastructure, code-history ring buffer and instruction/memory tracing.
//! The console debugger (P11.4) lives in `raxdbg-android`; GDB stub and
//! IDA `android_server` protocol are out of scope (plan D10), so this
//! module carries the host-side pieces every debugger variant shares.
//!
//! See:
//!
//! * `unidbg-api/.../debugger/{Debugger, Breaker, BreakPoint, BreakPointCallback, DebuggerType}.java@7f5da98e`
//! * `unidbg-api/.../arm/{SimpleARM64Debugger, SimpleARMDebugger, AbstractARMDebugger}.java@7f5da98e`
//! * `unidbg-api/.../arm/CodeHistory.java@7f5da98e`
//! * `unidbg-api/.../{TraceHook, TraceMemoryHook}.java@7f5da98e`
//! * `unidbg-api/.../AssemblyCodeDumper.java@7f5da98e`

pub mod breakpoint;
pub mod history;
pub mod trace;

pub use breakpoint::{BreakCallback, BreakControl, BreakPoint, Breaker, BreakerImpl};
pub use history::{CodeHistory, HistoryEntry};
pub use trace::{
    AssemblyCodeDumper, Disassembler, MemTraceEvent, NoopDisassembler, TraceCode, TraceMemory,
};
