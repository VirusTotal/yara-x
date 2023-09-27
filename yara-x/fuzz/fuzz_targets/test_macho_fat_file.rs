#![no_main]
use libfuzzer_sys::fuzz_target;
use yara_x::pub_parse_fat_macho_file;
use yara_x::Macho;

fuzz_target!(|data: &[u8]| {
    let mut macho_proto = Macho::default();
    let _ = pub_parse_fat_macho_file(data, &mut macho_proto);
});
