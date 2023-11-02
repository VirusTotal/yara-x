#![no_main]
use libfuzzer_sys::fuzz_target;
use yara_x::modules::pe::parser::PEParser;

fuzz_target!(|data: &[u8]| {
    let _ = PEParser::new().parse(data);
});
