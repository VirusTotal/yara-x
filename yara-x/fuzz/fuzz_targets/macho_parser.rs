#![no_main]
use libfuzzer_sys::fuzz_target;
use yara_x::modules::macho::parse_macho_file;

fuzz_target!(|data: &[u8]| {
    let _ = parse_macho_file(data);
});
