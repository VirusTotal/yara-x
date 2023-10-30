#![no_main]
use libfuzzer_sys::fuzz_target;
use yara_x::modules::elf::parser::ElfParser;

fuzz_target!(|data: &[u8]| {
    let _ = ElfParser::new().parse(data);
});
