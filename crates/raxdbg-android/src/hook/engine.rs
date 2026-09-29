//! The three bundled hook engines, as one interface.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/hook/{Dobby,HookZz,xhook}.java`
//! and the bundled binaries under
//! `unidbg-android/src/main/resources/android/lib/<abi>/{libdobby,libhookzz,libxhook}.so`@7f5da98e.
//!
//! All three export one function with the same shape -- `DobbyHook`,
//! `ZzReplace`, or xHook's Java-side `NativeHandler` -- that patches a guest
//! function so calls land in a replacement, and all three do it by rewriting
//! the first instructions of the target. They differ in how they cope with a
//! real process: split pages, PAC, MTE, and the fact that the target may be
//! anywhere in a 64-bit address space.
//!
//! Here the target is in an address space we lay out, so [`inline`] can place
//! the trampoline next to its target and the engines only have to supply the
//! replacement. That is what [`HookEngine`] is: the three bundled libraries are
//! loadable and their entry points are resolved, so a caller can drive whichever
//! one they want, and the shared mechanism underneath is the same one Dobby
//! itself would use.

use std::cell::RefCell;
use std::rc::Rc;

use raxdbg_core::backend::Backend;

use crate::emulator::AndroidEmulator;
use crate::elf::loader::AndroidElfLoader;

/// Which bundled engine a caller wants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    /// `libdobby.so`: `DobbyHook(address, replacement, original)`.
    Dobby,
    /// `libhookzz.so`: `ZzReplace(address, replacement)`.
    HookZz,
    /// `libxhook.so`: driven through `Java_com_qiyi_xhook_NativeHandler_refresh`.
    XHook,
}

impl Engine {
    /// Every engine, in the order the resolver tries them.
    pub const ALL: [Engine; 3] = [Engine::Dobby, Engine::HookZz, Engine::XHook];

    /// The library file, as unidbg's `AndroidResolver.hookLibrary` names it.
    pub fn library(self) -> &'static str {
        match self {
            Engine::Dobby => "libdobby.so",
            Engine::HookZz => "libhookzz.so",
            Engine::XHook => "libxhook.so",
        }
    }

    /// The entry point that installs a hook.
    pub fn entry_point(self) -> &'static str {
        match self {
            Engine::Dobby => "DobbyHook",
            Engine::HookZz => "ZzReplace",
            // xHook has no plain C entry point: its Java class calls
            // `NativeHandler.refresh` after `xhook_refresh` has been told where
            // the patterns are. The C side is reached through the JNI symbol.
            Engine::XHook => "Java_com_qiyi_xhook_NativeHandler_refresh",
        }
    }

    /// Whether the engine's entry point is a plain C function the guest can
    /// call, or a JNI symbol that needs the VM.
    pub fn needs_vm(self) -> bool {
        match self {
            Engine::Dobby | Engine::HookZz => false,
            Engine::XHook => true,
        }
    }
}

/// A loaded hook engine and the address of its entry point.
#[derive(Debug)]
pub struct HookEngine {
    engine: Engine,
    /// The module the engine was loaded as.
    module: String,
    entry: u64,
    library: Rc<AndroidElfLoader>,
    is_64bit: bool,
}

impl HookEngine {
    /// Which engine this is.
    pub fn engine(&self) -> Engine {
        self.engine
    }

    /// The module it was loaded as.
    pub fn module(&self) -> &str {
        &self.module
    }

    /// The address of its hook entry point.
    pub fn entry(&self) -> u64 {
        self.entry
    }

    /// Loads the engine and resolves its entry point.
    ///
    /// Port of unidbg: `AndroidResolver.hookLibrary(name)`, which fetches the
    /// bundled binary for the current ABI.
    pub fn load(emulator: &Rc<AndroidEmulator>, engine: Engine) -> Result<HookEngine, EngineError> {
        let file = emulator
            .resolver()
            .hook_library(engine.library())
            .ok_or_else(|| EngineError::NotBundled(engine.library().to_string()))?;
        let module = emulator
            .load(Box::new(file), false)
            .map_err(|error| EngineError::Load(error.to_string()))?;
        let entry = emulator
            .loader()
            .find_symbol(&module, engine.entry_point())
            .map(|symbol| symbol.address)
            .ok_or_else(|| EngineError::NoEntryPoint {
                library: engine.library().to_string(),
                symbol: engine.entry_point().to_string(),
            })?;
        Ok(HookEngine {
            engine,
            module,
            entry,
            library: Rc::clone(emulator.loader()),
            is_64bit: emulator.is_64bit(),
        })
    }

    /// Loads every engine, skipping the ones that are not bundled.
    ///
    /// Port of unidbg: a caller that wants "whatever inline hooking is
    /// available" and should not care which.
    pub fn load_all(emulator: &Rc<AndroidEmulator>) -> Vec<HookEngine> {
        Engine::ALL
            .iter()
            .filter_map(|engine| HookEngine::load(emulator, *engine).ok())
            .collect()
    }

    /// Calls the engine's entry point with a target and a replacement.
    ///
    /// `original` is where the engine writes the address of the unhooked
    /// function when it keeps one: Dobby takes a third pointer for it, the
    /// other two do not.
    pub fn install(
        &self,
        backend: &Rc<RefCell<dyn Backend>>,
        target: u64,
        replacement: u64,
        original: u64,
    ) -> Result<u64, EngineError> {
        let is_64bit = self.is_64bit;
        let number = match self.engine {
            Engine::Dobby => {
                // DobbyHook(void* address, void* replace_call, void** origin_call)
                let mut backend = backend.borrow_mut();
                backend
                    .reg_write(raxdbg_core::reg::RegId::X(0), target)
                    .map_err(|error| EngineError::Register(error.to_string()))?;
                backend
                    .reg_write(raxdbg_core::reg::RegId::X(1), replacement)
                    .map_err(|error| EngineError::Register(error.to_string()))?;
                backend
                    .reg_write(raxdbg_core::reg::RegId::X(2), original)
                    .map_err(|error| EngineError::Register(error.to_string()))?;
                3
            }
            Engine::HookZz => {
                // ZzReplace(void* address, void* replace_call)
                let mut backend = backend.borrow_mut();
                backend
                    .reg_write(raxdbg_core::reg::RegId::X(0), target)
                    .map_err(|error| EngineError::Register(error.to_string()))?;
                backend
                    .reg_write(raxdbg_core::reg::RegId::X(1), replacement)
                    .map_err(|error| EngineError::Register(error.to_string()))?;
                2
            }
            Engine::XHook => {
                // Its entry point is a JNI method: the Java class refreshes the
                // hook list, it does not take a target. There is nothing to call
                // here without a VM, which is what needs_vm reports.
                return Err(EngineError::NeedsVm);
            }
        };
        let _ = number;
        // Call the engine through the emulator so the call is set up the same
        // way any other is, with the arguments the stub just read still live.
        let trap = if is_64bit {
            crate::emulator::ARM64_TRAP_ADDRESS
        } else {
            crate::emulator::ARM32_TRAP_ADDRESS
        };
        let result = crate::emulator::AndroidEmulator::call_function_on(
            backend,
            self.library.memory(),
            trap,
            is_64bit,
            self.entry,
            &[],
        )
        .map_err(|error| EngineError::Call(error.to_string()))?;
        Ok(result)
    }
}

/// Why an engine could not be used.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// The bundled library is not present for this ABI.
    #[error("{0} is not bundled for this ABI; run tools/fetch-libs.ps1")]
    NotBundled(String),
    /// The library would not load.
    #[error("{0} would not load")]
    Load(String),
    /// The library has no entry point of that name.
    #[error("{library} does not export {symbol}")]
    NoEntryPoint {
        /// The library.
        library: String,
        /// The symbol.
        symbol: String,
    },
    /// The engine's entry point is reached through the VM, not called directly.
    #[error("this engine is driven through the Java side, so it needs a VM")]
    NeedsVm,
    /// Calling the engine failed.
    #[error("the engine's call failed: {0}")]
    Call(String),
    /// A register write failed.
    #[error("cannot set up the engine's arguments: {0}")]
    Register(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_engine_names_its_own_library_and_entry_point() {
        assert_eq!(Engine::Dobby.library(), "libdobby.so");
        assert_eq!(Engine::Dobby.entry_point(), "DobbyHook");
        assert_eq!(Engine::HookZz.library(), "libhookzz.so");
        assert_eq!(Engine::HookZz.entry_point(), "ZzReplace");
        assert_eq!(Engine::XHook.library(), "libxhook.so");
    }

    #[test]
    fn only_xhook_goes_through_the_java_side() {
        // Dobby and HookZz are plain C entry points a caller can invoke;
        // xHook's C entry point is a JNI method, so it needs a VM.
        assert!(!Engine::Dobby.needs_vm());
        assert!(!Engine::HookZz.needs_vm());
        assert!(Engine::XHook.needs_vm());
    }

    #[test]
    fn every_engine_is_offered() {
        assert_eq!(Engine::ALL.len(), 3);
    }
}
