#![no_main]
use libfuzzer_sys::fuzz_target;
use yara_x::pub_parse_macho_file;

fuzz_target!(|data: &[u8]| {
    let _ = pub_parse_macho_file(data);
});
