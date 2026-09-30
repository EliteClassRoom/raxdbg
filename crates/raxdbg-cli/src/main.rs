//! `raxdbg`: run an Android shared object on the rax CPU engine.
//!
//! Port of unidbg's command-line surface: `unidbg-android`'s test drivers and
//! `com.github.unidbg.debugger.Debugger`'s console@7f5da98e.

use std::cell::RefCell;
use std::fs::File;
use std::io::{BufRead, BufWriter, Write};
use std::path::PathBuf;
use std::rc::Rc;

use raxdbg_android::debug::ArmDisassembler;
use raxdbg_android::dvm::Vm;
use raxdbg_android::emulator::{AndroidEmulator, AndroidEmulatorBuilder, EmulatorError};
use raxdbg_android::syscall::trace::Verbosity;
use raxdbg_core::alloc::MemoryTracker;
use raxdbg_core::backend::{Backend, RunError};
use raxdbg_core::debug::{
    FunctionCall, FunctionCallListener, TraceCode, TraceFunctionCall, TraceMemory,
};
use raxdbg_core::memory::Memory;
use raxdbg_core::reg::RegId;
use raxdbg_core::unwind::{NoSymbols, SymbolResolver, Unwinder};

mod console;
mod options;

use options::{Command, Options, SyscallDetail};

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
  run       <lib.so>   load the library, run its initialisers, optionally call a function
  info      <lib.so>   print the modules, their exports and their dependencies
  trace     <lib.so>   trace instructions, memory accesses or function calls while calling a function
  syscalls  <lib.so>   log every syscall, then report the protection checks seen
  debug     <lib.so>   open the console debugger

options:
  --abi arm64|arm32     guest ABI (default: arm64)
  --sdk <level>         bundled bionic SDK level (default: 23)
  --libs-dir <dir>      the `libs/` tree (default: $RAXDBG_LIBS_DIR or the workspace)
  --root <dir>          the directory guest paths resolve under
  --call <name(args)>   the function to call, then its arguments
  --code|--read|--write|--functions which trace to run (trace)
  --out <file>           (trace) write the trace lines there instead of this terminal
  -v                     (syscalls) also print the syscalls that carry a path
  -vv                    (syscalls) print every syscall
  --jni-on-load          (syscalls) run the library's JNI_OnLoad first
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
        Command::Syscalls { library } => syscalls(options, library),
    }
}

/// `syscalls`: trace every syscall the run makes, then report what the
/// guest was checking for.
///
/// The trace is installed *before* the library is loaded, so the load's own
/// syscalls — relocation, `mmap`, the initialisers — are part of the record.
/// Tracing after the load would miss exactly the calls a packer makes while
/// it is still setting itself up.
fn syscalls(options: &Options, library: &str) -> Result<(), String> {
    let emulator = boot_traced(options, library)?;
    let handle = emulator.syscall().borrow_mut().set_trace();
    // `boot_traced` boots the emulator only; the library is loaded here so
    // the trace is on for the load itself.
    load_into(&emulator, library)?;

    // A JNI library does nothing interesting until the VM hands it an
    // environment, and `JNI_OnLoad` is where a protection wrapper runs most
    // of its setup. Run it first, so the trace covers it.
    let on_load = if options.jni_on_load {
        run_jni_on_load(&emulator, library)
    } else {
        None
    };

    let result = match &options.call {
        Some(call) => {
            let address = resolve_callable(&emulator, call)?;
            // A guest `exit` is a clean end of the run, so it is reported
            // rather than turned into a failure. It still ends the run, so
            // the trace and the report below are still produced.
            match emulator.call_function(address, &options.call_arguments) {
                Ok(value) => Some(format!("{}() = 0x{value:x} ({value})", call.name)),
                Err(EmulatorError::Run(RunError::StopEmulator)) => {
                    Some(format!("{}() called exit()", call.name))
                }
                Err(error) => return Err(format!("calling {}: {error}", call.name)),
            }
        }
        None => None,
    };

    // Attribute each syscall to the module that made it, now that every
    // module is mapped.
    let loader = emulator.loader();
    let mut trace = handle.borrow_mut();
    let modules = loader.module_infos();
    trace.attribute_modules(|pc| {
        modules
            .iter()
            .find(|module| pc >= module.base && pc < module.base + module.size)
            .map(|module| module.name.clone())
    });

    let verbosity = match options.syscall_detail {
        SyscallDetail::Summary => Verbosity::Summary,
        SyscallDetail::Interesting => Verbosity::Interesting,
        SyscallDetail::Full => Verbosity::Full,
    };
    let lines = raxdbg_android::syscall::trace::render(&trace, verbosity);
    if !lines.is_empty() {
        println!("-- syscalls --");
        print!("{lines}");
    }
    if let Some(line) = result {
        println!("{line}");
    }
    if let Some(outcome) = on_load {
        println!("JNI_OnLoad: {outcome}");
    }

    let report = trace.protection();
    println!(
        "-- protection --\n{} syscalls inspected, {} finding(s)",
        report.inspected,
        report.findings.len()
    );
    if !report.probe_paths.is_empty() {
        println!("probed: {}", report.probe_paths.join(", "));
    }
    print!("{}", report.render());
    Ok(())
}

/// Runs `library`'s `JNI_OnLoad` against a fresh VM, reporting the outcome.
///
/// A failure is a reported string rather than an `Err`: the interesting
/// part of a protection analysis is *where* it got to, and an error thrown
/// out of this function would skip the trace and the report entirely.
fn run_jni_on_load(emulator: &Rc<AndroidEmulator>, library: &str) -> Option<String> {
    let vm = match Vm::create(emulator) {
        Ok(vm) => vm,
        Err(error) => return Some(format!("could not create the VM: {error}")),
    };
    let report = |outcome: String| {
        let missing = vm.borrow().unimplemented();
        if missing.is_empty() {
            return outcome;
        }
        let slots: Vec<String> = missing.iter().map(|slot| slot.to_string()).collect();
        format!("{outcome}\n  JNI functions this port lacks: slot {}", slots.join(", "))
    };
    // Pick the module by what it actually exports rather than by guessing
    // from the file name: the loader records a library under its SONAME,
    // which for a packed binary bears no relation to the file on disk
    // (`libapk_android_a64.so` is loaded from `l1296851e_a64.so`), and
    // several system modules are mapped by then.
    let module = emulator
        .loader()
        .module_infos()
        .into_iter()
        .find_map(|info| {
            let has_on_load = emulator
                .loader()
                .find_symbol(&info.name, "JNI_OnLoad")
                .is_some();
            has_on_load.then_some(info.name)
        })
        .or_else(|| {
            PathBuf::from(library)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })?;
    match Vm::call_jni_on_load(emulator, &vm, &module) {
        Ok(version) => Some(report(format!("{module} returned 0x{version:x} (JNI version)"))),
        Err(error) => Some(report(format!("{module}: {error}"))),
    }
}

/// Boots an emulator for `library`, loads it, and returns the emulator with
/// the name the library was loaded under.
fn boot(
    options: &Options,
    library: &str,
) -> Result<(Rc<AndroidEmulator>, String), String> {
    let emulator = boot_traced(options, library)?;
    let name = load_into(&emulator, library)?;
    Ok((emulator, name))
}

/// Boots the emulator without loading `library`.
///
/// Split out from [`boot`] so `syscalls` can install a trace *before* the
/// load: a library's initialisers are ordinary guest code and make
/// syscalls of their own, so tracing has to be running first to see them.
/// `library` still names the process the guest sees, as [`boot`] does.
fn boot_traced(options: &Options, library: &str) -> Result<Rc<AndroidEmulator>, String> {
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
    Ok(emulator)
}

/// Loads `library` into `emulator` and returns the name it was loaded under.
///
/// A path on disk loads directly; a bare name goes through the resolver,
/// which is what unidbg's `load(File)` and `loadLibrary(name)` do. The name
/// is the one the loader's module table uses, which is what a trace over
/// "this module" has to look up.
fn load_into(emulator: &Rc<AndroidEmulator>, library: &str) -> Result<String, String> {
    let path = PathBuf::from(library);
    let name = if path.is_file() {
        let file = raxdbg_android::android_file::ElfLibraryFile::open(&path)
            .map_err(|error| format!("cannot open {library}: {error}"))?;
        emulator
            .load(Box::new(file), false)
            .map_err(|error| format!("cannot load {library}: {error}"))?
    } else {
        emulator
            .load_library(library)
            .map_err(|error| format!("cannot load {library}: {error}"))?
    };
    emulator.register_libc_allocator();
    Ok(name)
}

/// `info`: the modules, their dependencies and their exports.
fn info(options: &Options, library: &str) -> Result<(), String> {
    let (emulator, _) = boot(options, library)?;
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
    let (emulator, module) = boot(options, library)?;

    let tracker = emulator.memory().tracker();

    let result = match &options.call {
        Some(call) => {
            let address = resolve_callable(&emulator, call)?;
            let trace = Trace::attach(options, &emulator, &module)?;
            // A guest that called `exit` ended on purpose. That is a normal
            // end of a run, not a failure, and reporting it as an error
            // would say the emulation broke when it worked.
            let outcome = match emulator.call_function(address, &options.call_arguments) {
                Ok(value) => Some(format!("{name}() = 0x{value:x} ({value})", name = call.name)),
                Err(EmulatorError::Run(RunError::StopEmulator)) => {
                    Some(format!("{}() called exit()", call.name))
                }
                Err(error) => return Err(format!("calling {}: {error}", call.name)),
            };
            if let Some(trace) = trace {
                trace.report();
            }
            outcome
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

    if let Some(line) = result {
        println!("{line}");
    }

    if let Some(tracker) = tracker {
        report_leaks(&emulator, &tracker);
    }
    Ok(())
}

/// Resolves a `--call` name to a guest address.
///
/// A plain symbol goes through the loader's `dlsym` (so a hook listener's
/// replacement wins, exactly as it does for the guest); a bare address is
/// taken as one, which is how a packed library with no usable exports is
/// driven (`raxdbg info` prints the base it was mapped at); a JNI signature
/// (`name(Ljava/lang/String;)Ljava/lang/String;`) needs the `dvm` runtime,
/// which is not ported yet.
fn resolve_callable(emulator: &Rc<AndroidEmulator>, call: &options::Call) -> Result<u64, String> {
    // A C symbol is tried first: `hello()V` and `hello` both name the fixture's
    // `hello`. Only when nothing defines the name does a parenthesised
    // signature mean a JNI method, which needs the `dvm` runtime.
    if let Some(symbol) = emulator.loader().dlsym(0, &call.name) {
        return Ok(symbol.address);
    }
    if let Ok(address) = options::parse_number(&call.name) {
        return Ok(address);
    }
    if call.signature.contains('(') {
        return Err(format!(
            "the JNI method {} needs the dvm runtime, which is not ported yet; \
             pass a plain C symbol name or a guest address instead",
            call.signature
        ));
    }
    Err(format!("cannot resolve {}", call.name))
}

/// Where a trace's lines go: `--out <file>`, or the terminal.
fn trace_writer(options: &Options) -> Result<Box<dyn Write + Send>, String> {
    match &options.out {
        Some(path) => Ok(Box::new(BufWriter::new(File::create(path).map_err(
            |error| format!("cannot write {}: {error}", path.display()),
        )?))),
        None => Ok(Box::new(std::io::stdout())),
    }
}

/// The trace a `trace` run asked for, and the file its lines went to.
struct Trace {
    hook: TraceHook,
    /// The `--out` file the lines were streamed to, if any.
    redirect: Option<PathBuf>,
}

enum TraceHook {
    Code { hook: TraceCode },
    Memory {
        hook: TraceMemory,
        reads: bool,
        writes: bool,
    },
    Functions { hook: TraceFunctionCall },
}

impl Trace {
    fn attach(
        options: &Options,
        emulator: &Rc<AndroidEmulator>,
        module: &str,
    ) -> Result<Option<Self>, String> {
        if !matches!(options.command, Command::Trace { .. }) {
            return Ok(None);
        }
        let backend = Rc::clone(emulator.backend());
        let (begin, end) = (0u64, u64::MAX);
        let redirect = options.out.clone();
        let hook = match options.trace_kind() {
            options::TraceKind::Memory => {
                let reads = options.trace_reads;
                let writes = options.trace_writes;
                let hook = TraceMemory::new(reads);
                // `--out` streams: the lines are written as the run goes, so
                // the vectors never grow to the size of a whole trace.
                if redirect.is_some() {
                    hook.set_collect(false);
                    hook.set_redirect(trace_writer(options)?);
                }
                hook.attach(&backend, begin, end);
                TraceHook::Memory {
                    hook,
                    reads,
                    writes,
                }
            }
            options::TraceKind::Code => {
                let hook = TraceCode::new(Rc::new(ArmDisassembler::arm64()));
                if redirect.is_some() {
                    hook.set_collect(false);
                    hook.set_redirect(trace_writer(options)?);
                }
                hook.attach(&backend, begin, end);
                TraceHook::Code { hook }
            }
            options::TraceKind::Functions => {
                let info = emulator
                    .loader()
                    .module(module)
                    .ok_or_else(|| format!("cannot find the loaded module `{module}`"))?;
                let hook = TraceFunctionCall::new(options.is_64bit());
                hook.set_listener(Box::new(CallLog {
                    loader: Rc::clone(emulator.loader()),
                    is_64bit: options.is_64bit(),
                    out: trace_writer(options)?,
                }));
                // The module's own range is the point of this trace: only
                // branch instructions executed inside the library are
                // reported, not the ones libc makes on its own.
                hook.attach(&backend, info.base, info.base + info.size - 1);
                TraceHook::Functions { hook }
            }
        };
        Ok(Some(Trace { hook, redirect }))
    }

    fn report(&self) {
        let streamed = self.redirect.as_ref().map(|path| path.display().to_string());
        match &self.hook {
            TraceHook::Code { hook } => {
                hook.flush();
                match &streamed {
                    Some(path) => println!(
                        "-- {} instructions (written to {path}) --",
                        hook.count()
                    ),
                    None => {
                        let entries = hook.entries();
                        println!("-- {} instructions --", entries.len());
                        for entry in entries {
                            match &entry.disassembly {
                                Some(text) => println!("0x{:x}: {text}", entry.pc),
                                None => println!("0x{:x}: (undecoded)", entry.pc),
                            }
                        }
                    }
                }
            }
            TraceHook::Memory {
                hook,
                reads,
                writes,
            } => {
                hook.flush();
                match &streamed {
                    Some(path) => {
                        let (read_count, write_count) = hook.counts();
                        println!(
                            "-- {read_count} reads, {write_count} writes (written to {path}) --"
                        );
                    }
                    None => {
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
            TraceHook::Functions { hook } => {
                hook.flush();
                match &streamed {
                    Some(path) => println!("-- {} calls (written to {path}) --", hook.count()),
                    None => println!("-- {} calls --", hook.count()),
                }
            }
        }
    }
}

/// Streams the calls the library made, naming each through the loader.
struct CallLog {
    loader: Rc<raxdbg_android::elf::AndroidElfLoader>,
    is_64bit: bool,
    out: Box<dyn Write>,
}

impl FunctionCallListener for CallLog {
    fn on_call(&mut self, backend: &mut dyn Backend, call: &FunctionCall) {
        let _ = writeln!(
            self.out,
            "call 0x{:x} {} -> 0x{:x} {}",
            call.caller,
            name_caller(&self.loader, call.caller),
            call.callee,
            name_callee(&self.loader, self.is_64bit, backend, call.callee),
        );
    }

    fn flush(&mut self) {
        let _ = self.out.flush();
    }
}

/// Names the address of a branch instruction, which sits *inside* a function
/// and so is named by the nearest symbol below it.
fn name_caller(loader: &raxdbg_android::elf::AndroidElfLoader, address: u64) -> String {
    match loader.find_closest_symbol(address) {
        Some(symbol) => match symbol.module {
            Some(module) => format!(
                "{module}!{}+0x{:x}",
                symbol.name,
                address.wrapping_sub(symbol.address)
            ),
            None => format!("0x{address:x}"),
        },
        None => format!("0x{address:x}"),
    }
}

/// Names a branch target, which *is* a function entry.
///
/// A nearest-symbol name would be a lie here — a call lands in the middle of
/// nothing — so an exact symbol is required, then a PLT stub's GOT slot, and
/// only then the containing module.
fn name_callee(
    loader: &raxdbg_android::elf::AndroidElfLoader,
    is_64bit: bool,
    backend: &mut dyn Backend,
    address: u64,
) -> String {
    if let Some(symbol) = loader.find_closest_symbol(address) {
        if symbol.address == address {
            if let Some(module) = &symbol.module {
                return format!("{module}!{}", symbol.name);
            }
        }
    }
    if is_64bit {
        if let Some(slot) = plt_got_slot(backend, address) {
            if let Some(symbol) = loader.relocation_symbol(slot) {
                return match &symbol.module {
                    Some(module) => format!("{module}!{}", symbol.name),
                    None => symbol.name,
                };
            }
        }
    }
    match loader.find_module_by_address(address) {
        Some(info) => format!("{}+0x{:x}", info.name, address.wrapping_sub(info.base)),
        None => format!("0x{address:x}"),
    }
}

/// The GOT slot an AArch64 PLT stub loads its target from, if `address` is one.
///
/// The shape is what `lld` and the Android NDK emit: `adrp x16, page`,
/// `ldr x17, [x16, #imm]`, `add x16, x16, #imm`, `br x17`. Any other
/// instruction sequence is not a stub this can name.
fn plt_got_slot(backend: &mut dyn Backend, address: u64) -> Option<u64> {
    let bytes = backend.mem_read(address, 16).ok()?;
    if bytes.len() != 16 {
        return None;
    }
    let word = |index: usize| u32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap());
    let adrp = word(0);
    let ldr = word(1);
    let br = word(3);
    if adrp & 0x9F00_001F != 0x9000_0010 {
        return None;
    }
    if ldr & 0xFFC0_0000 != 0xF940_0000 || (ldr >> 5) & 0x1F != 16 || ldr & 0x1F != 17 {
        return None;
    }
    if br != 0xD61F_0220 {
        return None;
    }
    // ADRP's immediate is 21 bits of halfwords scaled by 2 and 4KB.
    let imm21 = (((adrp >> 5) & 0x7FFFF) << 2) | ((adrp >> 29) & 3);
    let page = (address & !0xFFF).wrapping_add(sign_extend(imm21, 21) << 12);
    Some(page.wrapping_add(u64::from((ldr >> 10) & 0xFFF) * 8))
}

/// Sign-extends the low `bits` of `value`, for an address displacement.
fn sign_extend(value: u32, bits: u32) -> u64 {
    let shift = 32 - bits;
    (((value << shift) as i32) >> shift) as i64 as u64
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
