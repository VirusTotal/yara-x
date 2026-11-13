#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = yara_x::mods::invoke::<yara_x::mods::Vba>(data);
    let _ = yara_x::Extractor::new().extract(data, |_, _, _| {
        std::ops::ControlFlow::<()>::Continue(())
    });
});
