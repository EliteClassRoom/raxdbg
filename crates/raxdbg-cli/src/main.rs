//! `raxdbg`: run an Android shared object on the rax CPU engine.
//!
//! Port of unidbg's command-line surface: `unidbg-android`'s test drivers and
//! `com.github.unidbg.debugger.Debugger`'s console@7f5da98e.

use std::cell::RefCell;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::rc::Rc;

use raxdbg_android::debug::ArmDisassembler;
use raxdbg_android::emulator::{AndroidEmulator, AndroidEmulatorBuilder};
use raxdbg_core::alloc::MemoryTracker;
use raxdbg_core::backend::Backend;
use raxdbg_core::debug::{TraceCode, TraceMemory};
use raxdbg_core::memory::Memory;
use raxdbg_core::reg::RegId;
use raxdbg_core::unwind::{NoSymbols, SymbolResolver, Unwinder};

mod console;
mod options;

use options::{Command, Options};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let options = match Options::parse(&args) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("raxdbg: {message}");
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    };

    if let Some(filter) = &options.log {
        let mut builder = env_logger::Builder::new();
        builder.parse_filters(filter);
        let _ = builder.try_init();
    }

    let code = match run(&options) {
        Ok(()) => 0,
        Err(message) => {
            eprintln!("raxdbg: {message}");
            1
        }
    };
    std::process::exit(code);
}

const USAGE: &str = "\
usage: raxdbg <command> <lib.so> [options]

commands:
  run    <lib.so>   load the library, run its initialisers, optionally call a function
  info   <lib.so>   print the modules, their exports and their dependencies
  trace  <lib.so>   trace instructions or memory accesses while calling a function
  debug  <lib.so>   open the console debugger

options:
  --abi arm64|arm32     guest ABI (default: arm64)
  --sdk <level>         bundled bionic SDK level (default: 23)
  --libs-dir <dir>      the `libs/` tree (default: $RAXDBG_LIBS_DIR or the workspace)
  --root <dir>          the directory guest paths resolve under
  --call <name(args)>   the function to call, then its arguments
  --code|--read|--write which trace to run (trace)
  --leak-check          report live allocations when the run finishes
  --seed <n>            seed the random source, for reproducibility
  --stdout <file>       write the guest's stdout there instead of this terminal
  --log <filter>        env_logger filter, e.g. raxdbg=debug";

fn run(options: &Options) -> Result<(), String> {
    match &options.command {
        Command::Info { library } => info(options, library),
        Command::Run { library } => execute(options, library),
        Command::Trace { library } => execute(options, library),
        Command::Debug { library } => console::debug_session(options, library),
    }
}

/// Boots an emulator for `library` and loads it.
fn boot(options: &Options, library: &str) -> Result<Rc<AndroidEmulator>, String> {
    let mut builder = if options.is_64bit() {
        AndroidEmulatorBuilder::for_64bit()
    } else {
        AndroidEmulatorBuilder::for_32bit()
    }
    .sdk(options.sdk())
    .seed(options.seed)
    .process_name(
        PathBuf::from(library)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "raxdbg".into()),
    );
    if let Some(root) = &options.root {
        builder = builder.root_dir(root);
    }
    if let Some(dir) = &options.libs_dir {
        builder = builder.libs_dir(dir);
    }
    let emulator = builder.build().map_err(|error| error.to_string())?;
    // The tracker is an `MMapListener`, so it has to be installed before the
    // libraries are mapped to see them.
    if options.leak_check {
        let tracker = Rc::new(MemoryTracker::new());
        // The backtrace is captured where the mapping happens, which is the
        // only place the guest's stack still holds the allocation site.
        tracker.set_backtrace_provider(Box::new(GuestFrames {
            backend: Rc::clone(emulator.backend()),
            memory: emulator.memory().clone(),
            is_64bit: emulator.is_64bit(),
            trap: emulator.trap_address(),
        }));
        MemoryTracker::install(&tracker, emulator.memory().as_ref());
        emulator.memory().set_tracker(tracker);
    }
    // A path on disk loads directly; a bare name goes through the resolver,
    // which is what unidbg's `load(File)` and `loadLibrary(name)` do.
    let path = PathBuf::from(library);
    if path.is_file() {
        let file = raxdbg_android::android_file::ElfLibraryFile::open(&path)
            .map_err(|error| format!("cannot open {library}: {error}"))?;
        emulator
            .load(Box::new(file), false)
            .map_err(|error| format!("cannot load {library}: {error}"))?;
    } else {
        emulator
            .load_library(library)
            .map_err(|error| format!("cannot load {library}: {error}"))?;
    }
    emulator.register_libc_allocator();
    Ok(emulator)
}

/// `info`: the modules, their dependencies and their exports.
fn info(options: &Options, library: &str) -> Result<(), String> {
    let emulator = boot(options, library)?;
    let loader = emulator.loader();
    for module in loader.module_infos() {
        println!(
            "{} base=0x{:x} size=0x{:x} entry=0x{:x} init={} refs={}",
            module.name,
            module.base,
            module.size,
            module.entry_point,
            module.init_functions,
            module.reference_count
        );
        if !module.needed_libraries.is_empty() {
            println!("  needs: {}", module.needed_libraries.join(", "));
        }
        let mut exported: Vec<String> = loader
            .exported_symbols()
            .into_iter()
            .filter(|symbol| symbol.module.as_deref() == Some(module.name.as_str()))
            .map(|symbol| format!("{}@0x{:x}", symbol.name, symbol.address))
            .collect();
        exported.sort();
        if exported.is_empty() {
            continue;
        }
        println!("  exports ({}):", exported.len());
        for symbol in exported {
            println!("    {symbol}");
        }
        let unresolved = loader.unresolved_relocations(&module.name);
        if !unresolved.is_empty() {
            println!("  unresolved relocations ({}): {unresolved:?}", unresolved.len());
        }
    }
    Ok(())
}

/// `run` and `trace`: load, optionally call, and report.
fn execute(options: &Options, library: &str) -> Result<(), String> {
    let emulator = boot(options, library)?;

    let tracker = emulator.memory().tracker();

    let result = match &options.call {
        Some(call) => {
            let address = resolve_callable(&emulator, call)?;
            let trace = Trace::attach(options, &emulator)?;
            let value = emulator
                .call_function(address, &options.call_arguments)
                .map_err(|error| format!("calling {}: {error}", call.name))?;
            if let Some(trace) = trace {
                trace.report();
            }
            Some(value)
        }
        None => None,
    };

    let stdout = emulator.stdout().contents();
    match &options.stdout_file {
        Some(path) => {
            std::fs::write(path, stdout.as_bytes())
                .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
        }
        None => print!("{stdout}"),
    }

    if let Some(value) = result {
        println!("{}() = 0x{value:x} ({value})", options.call.as_ref().unwrap().name);
    }

    if let Some(tracker) = tracker {
        report_leaks(&emulator, &tracker);
    }
    Ok(())
}

/// Resolves a `--call` name to a guest address.
///
/// A plain symbol goes through the loader's `dlsym` (so a hook listener's
/// replacement wins, exactly as it does for the guest); a JNI signature
/// (`name(Ljava/lang/String;)Ljava/lang/String;`) needs the `dvm` runtime,
/// which is not ported yet.
fn resolve_callable(emulator: &Rc<AndroidEmulator>, call: &options::Call) -> Result<u64, String> {
    // A C symbol is tried first: `hello()V` and `hello` both name the fixture's
    // `hello`. Only when nothing defines the name does a parenthesised
    // signature mean a JNI method, which needs the `dvm` runtime.
    if let Some(symbol) = emulator.loader().dlsym(0, &call.name) {
        return Ok(symbol.address);
    }
    if call.signature.contains('(') {
        return Err(format!(
            "the JNI method {} needs the dvm runtime, which is not ported yet; \
             pass a plain C symbol name instead",
            call.signature
        ));
    }
    Err(format!("cannot resolve {}", call.name))
}

/// The instruction or memory trace a `trace` run asked for.
enum Trace {
    Code {
        hook: TraceCode,
        backend: Rc<RefCell<dyn Backend>>,
    },
    Memory {
        hook: TraceMemory,
        backend: Rc<RefCell<dyn Backend>>,
        reads: bool,
        writes: bool,
    },
}

impl Trace {
    fn attach(options: &Options, emulator: &Rc<AndroidEmulator>) -> Result<Option<Self>, String> {
        if !matches!(options.command, Command::Trace { .. }) {
            return Ok(None);
        }
        let backend = Rc::clone(emulator.backend());
        let (begin, end) = (0u64, u64::MAX);
        match options.trace_kind() {
            options::TraceKind::Memory => {
                let reads = options.trace_reads;
                let writes = options.trace_writes;
                let hook = TraceMemory::new(reads);
                hook.attach(&backend, begin, end);
                Ok(Some(Trace::Memory {
                    hook,
                    backend,
                    reads,
                    writes,
                }))
            }
            options::TraceKind::Code => {
                let hook = TraceCode::new(Rc::new(ArmDisassembler::arm64()));
                hook.attach(&backend, begin, end);
                Ok(Some(Trace::Code { hook, backend }))
            }
        }
    }

    fn report(&self) {
        match self {
            Trace::Code { hook, .. } => {
                let entries = hook.entries();
                println!("-- {} instructions --", entries.len());
                for entry in entries {
                    match &entry.disassembly {
                        Some(text) => println!("0x{:x}: {text}", entry.pc),
                        None => println!("0x{:x}: (undecoded)", entry.pc),
                    }
                }
            }
            Trace::Memory {
                hook,
                reads,
                writes,
                ..
            } => {
                if *reads {
                    for event in hook.reads() {
                        println!(
                            "read  0x{:x} <- [0x{:x}] size {} from 0x{:x}",
                            event.value, event.address, event.size, event.pc
                        );
                    }
                }
                if *writes {
                    for event in hook.writes() {
                        println!(
                            "write 0x{:x} -> [0x{:x}] size {} from 0x{:x}",
                            event.value, event.address, event.size, event.pc
                        );
                    }
                }
            }
        }
    }
}

/// Prints the live allocations, with a guest backtrace for each.
fn report_leaks(emulator: &Rc<AndroidEmulator>, tracker: &Rc<MemoryTracker>) {
    let allocations = tracker.allocations();
    println!("-- {} live allocation(s) --", allocations.len());
    let unwinder = Unwinder::new(
        Rc::clone(emulator.backend()),
        emulator.memory().clone(),
        emulator.is_64bit(),
        Rc::new(ModuleSymbols {
            loader: Rc::clone(emulator.loader()),
        }),
        emulator.trap_address(),
    );
    for record in allocations {
        println!(
            "0x{:x} size 0x{:x} prot {}",
            record.address, record.size, record.prot
        );
        if record.guest_backtrace.is_empty() {
            println!("    (no guest frames recorded)");
            continue;
        }
        let symbols = ModuleSymbols {
            loader: Rc::clone(emulator.loader()),
        };
        for pc in &record.guest_backtrace {
            match symbols.resolve(*pc) {
                Some((module, function, offset)) => {
                    println!("    {module}!{function}+{offset:#x} ({pc:#x})")
                }
                None => println!("    {pc:#x}"),
            }
        }
    }
}

/// Captures the guest stack at an allocation, for the leak report.
struct GuestFrames {
    backend: Rc<RefCell<dyn Backend>>,
    memory: Rc<raxdbg_core::memory::loader::Loader>,
    is_64bit: bool,
    trap: u64,
}

impl raxdbg_core::alloc::BacktraceProvider for GuestFrames {
    fn capture(&self, max: usize) -> Vec<u64> {
        // `capture` runs inside a syscall handler, which the run loop has
        // already entered with the backend mutably borrowed (plan P2.6); when
        // that borrow is held there are no registers to walk, so the report
        // falls back to listing the regions alone.
        if self.backend.try_borrow().is_err() {
            return Vec::new();
        }
        let unwinder = Unwinder::new(
            Rc::clone(&self.backend),
            self.memory.clone(),
            self.is_64bit,
            Rc::new(NoSymbols),
            self.trap,
        );
        unwinder
            .frames(max)
            .map(|frames| frames.into_iter().map(|frame| frame.pc).collect())
            .unwrap_or_default()
    }
}

/// Names guest addresses through the ELF loader's symbol table.
pub struct ModuleSymbols {
    loader: Rc<raxdbg_android::elf::AndroidElfLoader>,
}

impl SymbolResolver for ModuleSymbols {
    fn resolve(&self, address: u64) -> Option<(String, String, u64)> {
        let symbol = self.loader.find_closest_symbol(address)?;
        let module = symbol.module.clone()?;
        let offset = address.wrapping_sub(symbol.address);
        Some((module, symbol.name, offset))
    }
}

/// The register names the console prints, in the order unidbg's `show_regs` does.
pub fn register_names(is_64bit: bool) -> Vec<RegId> {
    if is_64bit {
        (0..31).map(RegId::X).chain([RegId::Sp, RegId::Pc]).collect()
    } else {
        (0..13)
            .map(RegId::R)
            .chain([RegId::Sp, RegId::Lr, RegId::Pc])
            .collect()
    }
}

/// Reads a line from `input`, or `None` at end of input.
pub fn read_line(input: &mut impl BufRead) -> Option<String> {
    let mut line = String::new();
    match input.read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim().to_string()),
    }
}

/// A console session's prompt, so a scripted run and a terminal look the same.
pub fn prompt(out: &mut impl Write) {
    let _ = write!(out, "raxdbg> ");
    let _ = out.flush();
}
