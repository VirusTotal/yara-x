#![no_main]
use libfuzzer_sys::fuzz_target;
use yara_x::modules::lnk::parser::LnkParser;

fuzz_target!(|data: &[u8]| {
    let _ = LnkParser::new().parse(data);
});
