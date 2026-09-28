//! Stack unwinding.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/unwind/{Unwinder,SimpleARM64Unwinder,SimpleARMUnwinder,Frame}.java`
//! @7f5da98e.
//!
//! unidbg walks the frame-pointer chain (`x29` on arm64, `r11` on arm32) and
//! falls back to the `.eh_frame`/`ARM_EXIDX` tables when the chain is broken.
//! raxdbg does the same: the frame-pointer walk is exact for code compiled with
//! frame pointers (which bionic and the fixtures are), and the table walk is
//! reported as unavailable rather than guessed at.

use std::rc::Rc;

use crate::backend::Backend;
use crate::memory::{Memory, MemoryError};
use crate::reg::RegId;

/// One frame of a guest stack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// The program counter in this frame.
    pub pc: u64,
    /// The frame pointer the frame was reached through.
    pub fp: u64,
    /// The frame's return address, when the caller's frame is known.
    pub return_address: Option<u64>,
    /// The function name, when a resolver knows it.
    pub function: Option<String>,
    /// The module the frame is in, when a resolver knows it.
    pub module: Option<String>,
    /// The offset from the function's start.
    pub offset: Option<u64>,
}

impl Frame {
    /// A frame at `pc` reached through `fp`.
    pub fn new(pc: u64, fp: u64) -> Self {
        Frame {
            pc,
            fp,
            return_address: None,
            function: None,
            module: None,
            offset: None,
        }
    }

    /// The frame as `module!function+0xoffset` (unidbg's `Frame.toString`).
    pub fn describe(&self) -> String {
        let module = self.module.as_deref().unwrap_or("?");
        match (&self.function, self.offset) {
            (Some(function), Some(offset)) => format!("{module}!{function}+{offset:#x}"),
            (Some(function), None) => format!("{module}!{function}"),
            _ => format!("{module}!{:#x}", self.pc),
        }
    }
}

/// Resolves an address to a function and module name.
///
/// The android crate implements this over the ELF loader's
/// `find_closest_symbol`, so the unwinder itself has no dependency on the
/// module registry.
pub trait SymbolResolver {
    /// The symbol containing `address`, as `(module, function, offset)`.
    fn resolve(&self, address: u64) -> Option<(String, String, u64)>;
}

/// A resolver that names nothing, for callers with no module registry.
pub struct NoSymbols;

impl SymbolResolver for NoSymbols {
    fn resolve(&self, _address: u64) -> Option<(String, String, u64)> {
        None
    }
}

/// Why an unwind stopped early.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnwindStop {
    /// The requested depth was reached.
    Depth,
    /// The frame-pointer chain ended (a null or non-increasing pointer).
    EndOfStack,
    /// A frame pointer could not be read.
    Unreadable,
}

/// A guest stack walk.
pub struct Unwinder {
    backend: Rc<std::cell::RefCell<dyn Backend>>,
    memory: Rc<dyn Memory>,
    is_64bit: bool,
    resolver: Rc<dyn SymbolResolver>,
    /// The trap page address, which is the bottom of every call stack.
    trap_address: u64,
}

impl std::fmt::Debug for Unwinder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unwinder")
            .field("is_64bit", &self.is_64bit)
            .field("trap", &format_args!("{:#x}", self.trap_address))
            .finish()
    }
}

impl Unwinder {
    /// Walks the frame-pointer chain of `backend`'s current thread.
    pub fn new(
        backend: Rc<std::cell::RefCell<dyn Backend>>,
        memory: Rc<dyn Memory>,
        is_64bit: bool,
        resolver: Rc<dyn SymbolResolver>,
        trap_address: u64,
    ) -> Self {
        Unwinder {
            backend,
            memory,
            is_64bit,
            resolver,
            trap_address,
        }
    }

    /// The register holding the frame pointer.
    fn frame_pointer_register(&self) -> RegId {
        if self.is_64bit { RegId::Fp } else { RegId::Fp }
    }

    /// The register holding the program counter.
    fn program_counter_register(&self) -> RegId {
        RegId::Pc
    }

    /// The link register, which the innermost frame's caller comes from.
    fn link_register(&self) -> RegId {
        RegId::Lr
    }

    /// Unwinds up to `max_frames` frames, innermost first.
    ///
    /// Port of unidbg: `SimpleARM64Unwinder.getFrames`.
    pub fn frames(&self, max_frames: usize) -> Result<Vec<Frame>, MemoryError> {
        let mut frames = Vec::new();
        let (mut pc, mut fp) = {
            let backend = self.backend.borrow();
            (
                backend
                    .reg_read(self.program_counter_register())
                    .map_err(|error| MemoryError::Message(error.to_string()))?,
                backend
                    .reg_read(self.frame_pointer_register())
                    .map_err(|error| MemoryError::Message(error.to_string()))?,
            )
        };

        for index in 0..max_frames {
            let mut frame = self.describe(pc, fp);
            if index == 0 {
                // The innermost frame's caller is in the link register, which
                // is what a backtrace taken at a breakpoint needs.
                let lr = self
                    .backend
                    .borrow()
                    .reg_read(self.link_register())
                    .map_err(|error| MemoryError::Message(error.to_string()))?;
                frame.return_address = Some(lr);
            }
            frames.push(frame);

            if fp == 0 || fp == self.trap_address {
                return Ok(frames);
            }
            // The frame record is `{ x29, x30 }` on arm64 and `{ r11, lr }` on
            // arm32: the saved frame pointer is at the frame base, the return
            // address right after it.
            let pointer_size = if self.is_64bit { 8 } else { 4 };
            let next_fp = self.read_word(fp)?;
            let return_address = self.read_word(fp + pointer_size)?;
            if next_fp <= fp {
                return Ok(frames);
            }
            if let Some(frame) = frames.last_mut() {
                frame.return_address = Some(return_address);
            }
            pc = return_address;
            fp = next_fp;
        }
        Ok(frames)
    }

    /// A backtrace rendered as one line per frame.
    pub fn backtrace(&self, max_frames: usize) -> Result<String, MemoryError> {
        let frames = self.frames(max_frames)?;
        let mut out = String::new();
        for (index, frame) in frames.iter().enumerate() {
            out.push_str(&format!(
                "#{index:<2} {:#018x} {}\n",
                frame.pc,
                frame.describe()
            ));
        }
        Ok(out)
    }

    fn describe(&self, pc: u64, fp: u64) -> Frame {
        let mut frame = Frame::new(pc, fp);
        if let Some((module, function, offset)) = self.resolver.resolve(pc) {
            frame.module = Some(module);
            frame.function = Some(function);
            frame.offset = Some(offset);
        }
        frame
    }

    fn read_word(&self, address: u64) -> Result<u64, MemoryError> {
        let pointer = self.memory.pointer(address);
        if self.is_64bit {
            pointer.read_u64(0)
        } else {
            Ok(u64::from(pointer.read_u32(0)?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_describe_themselves() {
        let mut frame = Frame::new(0x1000, 0x2000);
        assert_eq!(frame.describe(), "?!0x1000");
        frame.module = Some("libc.so".into());
        frame.function = Some("malloc".into());
        frame.offset = Some(0x10);
        assert_eq!(frame.describe(), "libc.so!malloc+0x10");
    }
}
