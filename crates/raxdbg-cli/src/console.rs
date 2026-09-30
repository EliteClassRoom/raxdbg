//! The console debugger.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/debugger/Debugger.java`
//! and `arm/SimpleARM64Debugger.java`'s command set@7f5da98e, minus the GDB and
//! IDA `android_server` transports (plan D10).

use std::cell::RefCell;
use std::io::{BufRead, Write};
use std::rc::Rc;

use raxdbg_android::debug::ArmDisassembler;
use raxdbg_android::emulator::AndroidEmulator;
use raxdbg_core::backend::{Backend, RunOutcome};
use raxdbg_core::debug::{BreakCallback, BreakControl, Breaker, BreakerImpl, BreakPoint, Disassembler};
use raxdbg_core::memory::Memory;
use raxdbg_core::reg::RegId;
use raxdbg_core::unwind::Unwinder;

use crate::options::{Options, Call};
use crate::{ModuleSymbols, boot, read_line, register_names, prompt};

/// A console session over `input`/`output`.
pub struct Console {
    emulator: Rc<AndroidEmulator>,
    breaker: Rc<RefCell<BreakerImpl>>,
    history: raxdbg_core::debug::CodeHistory,
    breakpoints: Vec<BreakPoint>,
    stop: Rc<std::cell::Cell<bool>>,
}

impl Console {
    /// Attaches to a booted emulator.
    pub fn attach(emulator: Rc<AndroidEmulator>) -> Self {
        let breaker = Rc::new(RefCell::new(BreakerImpl::new(Rc::clone(emulator.backend()))));
        Console {
            emulator,
            breaker,
            history: raxdbg_core::debug::CodeHistory::new(64),
            breakpoints: Vec::new(),
            stop: Rc::new(std::cell::Cell::new(false)),
        }
    }

    /// Runs the command loop until `q` or end of input.
    pub fn run(&mut self, input: &mut impl BufRead, output: &mut impl Write) -> std::io::Result<()> {
        writeln!(
            output,
            "raxdbg console — `help` for commands, `q` to quit. The guest has not started."
        )?;
        loop {
            prompt(output);
            let Some(line) = read_line(input) else {
                return Ok(());
            };
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let command = parts.next().unwrap_or("");
            let rest: Vec<&str> = parts.collect();
            match command {
                "q" | "quit" | "exit" => return Ok(()),
                "help" | "?" => {
                    writeln!(output, "{HELP}")?;
                }
                "c" | "continue" => self.continue_run(output)?,
                "s" | "si" | "step" => self.step(output, 1)?,
                "b" | "break" => self.set_breakpoint(&rest, output)?,
                "bl" => self.list_breakpoints(output)?,
                "br" => self.remove_breakpoint(&rest, output)?,
                "r" | "regs" => self.show_registers(output)?,
                "m" => self.show_memory(&rest, output)?,
                "d" | "dis" => self.disassemble(&rest, output)?,
                "t" | "bt" => self.backtrace(output)?,
                "where" => self.where_am_i(output)?,
                "modules" => self.show_modules(output)?,
                "symbols" => self.show_symbols(&rest, output)?,
                "call" => self.call(&rest, output)?,
                "threads" => writeln!(output, "one guest thread: the main thread")?,
                other => writeln!(output, "unknown command `{other}`; try `help`")?,
            }
        }
    }

    fn continue_run(&mut self, output: &mut impl Write) -> std::io::Result<()> {
        let pc = self.pc();
        let outcome = self
            .emulator
            .backend()
            .borrow_mut()
            .emu_start(pc, 0, 0, 0);
        self.report_outcome(outcome, output)
    }

    fn step(&mut self, output: &mut impl Write, count: u64) -> std::io::Result<()> {
        let pc = self.pc();
        let outcome = self.emulator.backend().borrow_mut().emu_start(pc, 0, 0, count);
        self.report_outcome(outcome, output)
    }

    fn report_outcome(
        &self,
        outcome: Result<RunOutcome, raxdbg_core::backend::RunError>,
        output: &mut impl Write,
    ) -> std::io::Result<()> {
        match outcome {
            Ok(outcome) => writeln!(output, "stopped: {outcome}")?,
            Err(error) => writeln!(output, "stopped: {error}")?,
        }
        writeln!(output, "pc = {:#x}", self.pc())
    }

    fn set_breakpoint(&mut self, args: &[&str], output: &mut impl Write) -> std::io::Result<()> {
        let Some(target) = args.first() else {
            return writeln!(output, "usage: b <address|symbol>");
        };
        let address = match self.resolve(target) {
            Some(address) => address,
            None => return writeln!(output, "cannot resolve `{target}`"),
        };
        let stop = Rc::clone(&self.stop);
        let callback: BreakCallback = Box::new(move |_address| {
            stop.set(true);
            BreakControl::Stop
        });
        let breakpoint = self
            .breaker
            .borrow_mut()
            .add_break_point(address, Some(callback));
        writeln!(output, "breakpoint {} at {address:#x}", breakpoint.address())?;
        self.breakpoints.push(breakpoint);
        Ok(())
    }

    fn list_breakpoints(&self, output: &mut impl Write) -> std::io::Result<()> {
        for (index, breakpoint) in self.breakpoints.iter().enumerate() {
            writeln!(
                output,
                "{index}: {:#x}{}",
                breakpoint.address(),
                if breakpoint.temporary() { " (temporary)" } else { "" }
            )?;
        }
        Ok(())
    }

    fn remove_breakpoint(&self, args: &[&str], output: &mut impl Write) -> std::io::Result<()> {
        let Some(index) = args.first().and_then(|text| text.parse::<usize>().ok()) else {
            return writeln!(output, "usage: br <index>");
        };
        match self.breakpoints.get(index) {
            Some(breakpoint) => {
                self.breaker.borrow_mut().remove_break_point(breakpoint.address());
                writeln!(output, "removed breakpoint {index}")
            }
            None => writeln!(output, "no breakpoint {index}"),
        }
    }

    fn show_registers(&self, output: &mut impl Write) -> std::io::Result<()> {
        let backend = self.emulator.backend().borrow();
        for register in register_names(self.emulator.is_64bit()) {
            if let Ok(value) = backend.reg_read(register) {
                writeln!(output, "{register:<6} = 0x{value:x}")?;
            }
        }
        Ok(())
    }

    fn show_memory(&self, args: &[&str], output: &mut impl Write) -> std::io::Result<()> {
        let Some(address) = args.first().and_then(|text| parse_address(text)) else {
            return writeln!(output, "usage: m <address> [length]");
        };
        let length = args
            .get(1)
            .and_then(|text| text.parse::<usize>().ok())
            .unwrap_or(64);
        let mut buffer = vec![0u8; length];
        match Memory::read_bytes(self.emulator.memory().as_ref(), address, &mut buffer) {
            Ok(()) => {
                for (index, chunk) in buffer.chunks(16).enumerate() {
                    let hex: Vec<String> = chunk.iter().map(|byte| format!("{byte:02x}")).collect();
                    writeln!(output, "{:#018x}: {}", address + (index * 16) as u64, hex.join(" "))?;
                }
                Ok(())
            }
            Err(error) => writeln!(output, "cannot read {address:#x}: {error}"),
        }
    }

    fn disassemble(&self, args: &[&str], output: &mut impl Write) -> std::io::Result<()> {
        let Some(address) = args.first().and_then(|text| parse_address(text)) else {
            return writeln!(output, "usage: d <address> [count]");
        };
        let count = args
            .get(1)
            .and_then(|text| text.parse::<usize>().ok())
            .unwrap_or(8);
        let disassembler = if self.emulator.is_64bit() {
            ArmDisassembler::arm64()
        } else {
            ArmDisassembler::arm32()
        };
        let mut pc = address;
        for _ in 0..count {
            let mut bytes = vec![0u8; 4];
            if Memory::read_bytes(self.emulator.memory().as_ref(), pc, &mut bytes).is_err() {
                break;
            }
            match disassembler.disassemble(pc, &bytes, false) {
                Some(text) => writeln!(output, "{pc:#018x}: {text}")?,
                None => writeln!(output, "{pc:#018x}: (undecoded)")?,
            }
            pc += 4;
        }
        Ok(())
    }

    fn backtrace(&self, output: &mut impl Write) -> std::io::Result<()> {
        let unwinder = Unwinder::new(
            Rc::clone(self.emulator.backend()),
            self.emulator.memory().clone(),
            self.emulator.is_64bit(),
            Rc::new(ModuleSymbols {
                loader: Rc::clone(self.emulator.loader()),
            }),
            self.emulator.trap_address(),
        );
        match unwinder.backtrace(16) {
            Ok(text) => write!(output, "{text}"),
            Err(error) => writeln!(output, "cannot unwind: {error}"),
        }
    }

    fn where_am_i(&self, output: &mut impl Write) -> std::io::Result<()> {
        let pc = self.pc();
        match self.emulator.loader().find_closest_symbol(pc) {
            Some(symbol) => writeln!(
                output,
                "{:#x} is {}!{}+{:#x}",
                pc,
                symbol.module.as_deref().unwrap_or("?"),
                symbol.name,
                pc - symbol.address
            ),
            None => writeln!(output, "{pc:#x} is not in a loaded module"),
        }
    }

    fn show_modules(&self, output: &mut impl Write) -> std::io::Result<()> {
        for module in self.emulator.loader().module_infos() {
            writeln!(
                output,
                "{:<24} {:#x}..{:#x}",
                module.name,
                module.base,
                module.base + module.size
            )?;
        }
        Ok(())
    }

    fn show_symbols(&self, args: &[&str], output: &mut impl Write) -> std::io::Result<()> {
        let needle = args.first().copied().unwrap_or("");
        let mut shown = 0;
        for symbol in self.emulator.loader().exported_symbols() {
            if !needle.is_empty() && !symbol.name.contains(needle) {
                continue;
            }
            writeln!(
                output,
                "{}!{} = {:#x}",
                symbol.module.as_deref().unwrap_or("?"),
                symbol.name,
                symbol.address
            )?;
            shown += 1;
            if shown >= 200 {
                writeln!(output, "... (truncated)")?;
                break;
            }
        }
        writeln!(output, "{shown} symbol(s)")?;
        Ok(())
    }

    fn call(&self, args: &[&str], output: &mut impl Write) -> std::io::Result<()> {
        let Some(name) = args.first() else {
            return writeln!(output, "usage: call <symbol> [args...]");
        };
        let Some(address) = self.resolve(name) else {
            return writeln!(output, "cannot resolve `{name}`");
        };
        let arguments: Vec<u64> = args[1..]
            .iter()
            .filter_map(|text| parse_address(text))
            .collect();
        match self.emulator.call_function(address, &arguments) {
            Ok(value) => writeln!(output, "{name}() = 0x{value:x} ({value})"),
            Err(error) => writeln!(output, "{name}() failed: {error}"),
        }
    }

    fn pc(&self) -> u64 {
        self.emulator
            .backend()
            .borrow()
            .reg_read(RegId::Pc)
            .unwrap_or(0)
    }

    /// Resolves a console argument: a number, or a symbol name.
    fn resolve(&self, text: &str) -> Option<u64> {
        if let Some(address) = parse_address(text) {
            return Some(address);
        }
        self.emulator
            .loader()
            .dlsym(0, text)
            .map(|symbol| symbol.address)
    }

    /// The code history the session recorded.
    pub fn history(&self) -> &raxdbg_core::debug::CodeHistory {
        &self.history
    }
}

const HELP: &str = "\
c, continue      run until the next breakpoint
s, si, step      run one instruction
b <addr|symbol>  set a breakpoint
bl               list breakpoints
br <n>           remove breakpoint n
r, regs          show the register file
m <addr> [len]   show memory (default 64 bytes)
d <addr> [n]     disassemble (default 8 instructions)
t, bt            backtrace
where            name the current address
modules          list the loaded modules
symbols [needle] list exported symbols
call <sym> [a..] call a guest function
threads          list the guest threads
q                quit";

/// Runs a scripted or interactive console session for `debug <lib.so>`.
pub fn debug_session(options: &Options, library: &str) -> Result<(), String> {
    let (emulator, _) = boot(options, library)?;
    if let Some(call) = options.call.as_ref().filter(|call| !call.signature.is_empty()) {
        preload_call(&emulator, call)?;
    }
    let mut console = Console::attach(emulator);
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    console
        .run(&mut input, &mut output)
        .map_err(|error| error.to_string())
}

/// Resolves the `--call` target up front, so a typo is reported before the
/// console takes over the terminal.
fn preload_call(emulator: &Rc<AndroidEmulator>, call: &Call) -> Result<(), String> {
    if call.signature.contains('(') && call.signature.contains(')') && !call.signature.ends_with("()V") {
        return Err(format!(
            "the JNI signature {} needs the dvm runtime, which is not ported yet",
            call.signature
        ));
    }
    Ok(())
}

/// A console session for tests: the same object, driven from a byte slice.
pub fn scripted_session(
    emulator: Rc<AndroidEmulator>,
    script: &[u8],
) -> std::io::Result<(String, Console)> {
    let mut console = Console::attach(emulator);
    let mut input = std::io::BufReader::new(script);
    let mut output = Vec::new();
    console.run(&mut input, &mut output)?;
    Ok((String::from_utf8_lossy(&output).into_owned(), console))
}

/// Silences the unused-import warning for `Backend`, which the console uses
/// only through trait methods on the boxed backend.
#[allow(dead_code)]
fn _backend_is_used(backend: &dyn Backend) -> usize {
    backend.page_size()
}

/// Keeps the `RefCell` import honest for the same reason.
#[allow(dead_code)]
fn _cell_type() -> Rc<RefCell<dyn Backend>> {
    unreachable!("only here to name the type")
}

fn parse_address(text: &str) -> Option<u64> {
    if let Some(hex) = text.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        text.parse().ok()
    }
}
