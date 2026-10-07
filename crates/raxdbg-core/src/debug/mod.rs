//! Debugger core (plan P11).
//!
//! Port of unidbg's `com.github.unidbg.debugger` package: the breakpoint
//! infrastructure, code-history ring buffer and instruction/memory tracing.
//! These are the host-side pieces every debugger transport shares. The console
//! debugger (P11.4) lives in `raxdbg-cli`, and so does the GDB remote
//! protocol server, which `raxdbg-cli` reaches with `debug --gdb <port>`; the
//! IDA `android_server` protocol remains out of scope (plan D10).
//!
//! See:
//!
//! * `unidbg-api/.../debugger/{Debugger, Breaker, BreakPoint, BreakPointCallback, DebuggerType}.java@7f5da98e`
//! * `unidbg-api/.../arm/{SimpleARM64Debugger, SimpleARMDebugger, AbstractARMDebugger}.java@7f5da98e`
//! * `unidbg-api/.../arm/CodeHistory.java@7f5da98e`
//! * `unidbg-api/.../{TraceHook, TraceMemoryHook}.java@7f5da98e`
//! * `unidbg-api/.../AssemblyCodeDumper.java@7f5da98e`
//! * `unidbg-api/.../arm/TraceFunctionCall{,32,64}.java@7f5da98e`

pub mod breakpoint;
pub mod function_call;
pub mod history;
pub mod trace;

pub use breakpoint::{BreakCallback, BreakControl, BreakPoint, Breaker, BreakerImpl};
pub use function_call::{FunctionCall, FunctionCallListener, TraceFunctionCall};
pub use history::{CodeHistory, HistoryEntry};
pub use trace::{
    AssemblyCodeDumper, Disassembler, MemTraceEvent, NoopDisassembler, TraceCode, TraceMemory,
};
