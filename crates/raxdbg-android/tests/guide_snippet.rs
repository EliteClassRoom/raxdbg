//! The snippet from `docs/syscalls-and-protection.md` §9, compiled and run.
//!
//! A guide that does not compile is worse than no guide, and a snippet
//! cannot be checked by reading: the API moves, the example does not. This
//! is the same code the guide shows, so a change to the tracer's surface
//! breaks this test rather than silently making the documentation wrong.

#![allow(dead_code)]

use raxdbg_android::emulator::AndroidEmulatorBuilder;

#[test]
fn the_documented_snippet_works() {
    let library = "fixtures/prebuilt/arm64-v8a/libctest.so";
    if !std::path::Path::new(library).is_file() {
        eprintln!("skipping: {library} is not built");
        return;
    }
    let run = || -> Result<(), Box<dyn std::error::Error>> {
        let emulator = AndroidEmulatorBuilder::for_64bit().sdk(23).build()?;

        // Before the load: the initialisers' own syscalls are part of the record.
        let trace = emulator.syscall().borrow_mut().set_trace();

        let file = raxdbg_android::android_file::ElfLibraryFile::open("fixtures/prebuilt/arm64-v8a/libctest.so")?;
        emulator.load(Box::new(file), false)?;

        let address = emulator.loader().dlsym(0, "hello").map(|s| s.address).unwrap_or(0);
        let _result = emulator.call_function(address, &[])?;

        // One pass, after the run, to name the module behind each `pc`.
        let modules = emulator.loader().module_infos();
        let mut trace = trace.borrow_mut();
        trace.attribute_modules(|pc| {
            modules
                .iter()
                .find(|m| pc >= m.base && pc < m.base + m.size)
                .map(|m| m.name.clone())
        });

        let mut seen = 0usize;
        for event in trace.events() {
            let _ = format!("{} {} -> {:?}", event.label(), event.args[0], event.result);
            seen += 1;
        }
        let findings = trace.protection().findings;
        for finding in &findings {
            let _ = format!("{:?} {}: {}", finding.severity, finding.kind, finding.evidence);
        }
        assert!(seen > 0, "the documented snippet must see the load's syscalls");
        Ok(())
    };
    run().expect("the documented snippet runs");
}
