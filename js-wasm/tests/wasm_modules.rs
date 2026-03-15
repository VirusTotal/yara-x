#![cfg(target_arch = "wasm32")]

#[path = "support/mod.rs"]
mod support;

use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;
use yara_wasm::scan_rules_js;

use crate::support::{decode_zipped_ihex_fixture, parse_scan_result};

const CRX_FIXTURE_ZIP: &[u8] = include_bytes!(
    "../../lib/src/modules/crx/tests/testdata/3d1c2b1777fb5d5f4e4707ab3a1b64131c26f8dc1c30048dce7a1944b4098f3e.in.zip"
);
const DEX_FIXTURE_ZIP: &[u8] = include_bytes!(
    "../../lib/src/modules/dex/tests/testdata/c14c75d58399825287e0ee0fcfede6ec06f93489fb52f70bca2736fae5fceab2.in.zip"
);
const ELF_FIXTURE_ZIP: &[u8] = include_bytes!(
    "../../lib/src/modules/elf/tests/testdata/8bfe885838b4d1fba194b761ca900a0425aa892e4b358bf5a9bf4304e571df1b.in.zip"
);
const DOTNET_TYPES2_FIXTURE_ZIP: &[u8] = include_bytes!(
    "../../lib/src/modules/dotnet/tests/testdata/types2.dll.in.zip"
);
const DOTNET_EMPTY_FIXTURE_ZIP: &[u8] = include_bytes!(
    "../../lib/src/modules/dotnet/tests/testdata/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.in.zip"
);
const MACHO_TINY_UNIVERSAL_FIXTURE_ZIP: &[u8] = include_bytes!(
    "../../lib/src/modules/macho/tests/testdata/tiny_universal.in.zip"
);
const LNK_STANDARD_FIXTURE_ZIP: &[u8] = include_bytes!(
    "../../lib/src/modules/lnk/tests/testdata/lnk-standard.in.zip"
);
const LNK_NETWORK_FIXTURE_ZIP: &[u8] = include_bytes!(
    "../../lib/src/modules/lnk/tests/testdata/lnk-network.in.zip"
);
const LNK_EMPTY_FIXTURE_ZIP: &[u8] = include_bytes!(
    "../../lib/src/modules/lnk/tests/testdata/lnk-empty.in.zip"
);
const PE_RICH_FIXTURE_ZIP: &[u8] = include_bytes!(
    "../../lib/src/modules/pe/tests/testdata/079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885.in.zip"
);
const PE_IMPORTS_FIXTURE_ZIP: &[u8] = include_bytes!(
    "../../lib/src/modules/pe/tests/testdata/2775d97f8bdb3311ace960a42eee35dbec84b9d71a6abbacb26c14e83f5897e4.in.zip"
);
const PE_IMPORT_RVA_FIXTURE_ZIP: &[u8] = include_bytes!(
    "../../lib/src/modules/pe/tests/testdata/0ba6042247d90a187919dd88dc2d55cd882c80e5afc511c4f7b2e0e193968f7f.in.zip"
);

fn assert_rule_matches(rule: &str, payload: &[u8]) {
    let result = scan_rules_js(JsValue::from_str(rule), payload)
        .expect("scanRules should return a result object");
    let parsed = parse_scan_result(result);

    assert!(parsed.valid, "{}", parsed.errors.join("\n"));
    assert_eq!(parsed.matches.len(), 1);
}

fn assert_rule_does_not_match(rule: &str, payload: &[u8]) {
    let result = scan_rules_js(JsValue::from_str(rule), payload)
        .expect("scanRules should return a result object");
    let parsed = parse_scan_result(result);

    assert!(parsed.valid, "{}", parsed.errors.join("\n"));
    assert!(parsed.matches.is_empty());
}

#[wasm_bindgen_test]
fn hash_module_functions_work() {
    assert_rule_matches(
        r#"
        import "hash"
        rule test {
            condition:
                hash.md5(0, filesize) == "6df23dc03f9b54cc38a0fc1483df6e21" and
                hash.md5(3, 3) == hash.md5("bar") and
                hash.sha1(0, filesize) == "5f5513f8822fdbe5145af33b64d8d970dcf95c6e" and
                hash.sha256(0, filesize) == "97df3588b5a3f24babc3851b372f0ba71a9dcdded43b14b9d06961bfc1707d9d" and
                hash.crc32(0, filesize) == 0x1a7827aa and
                hash.checksum32(0, filesize) == 0x3b6
        }
        "#,
        b"foobarbaz",
    );
}

#[wasm_bindgen_test]
fn crx_module_parses_real_fixture() {
    let crx = decode_zipped_ihex_fixture(
        CRX_FIXTURE_ZIP,
        "3d1c2b1777fb5d5f4e4707ab3a1b64131c26f8dc1c30048dce7a1944b4098f3e.in",
    );

    assert_rule_matches(
        r#"
        import "crx"
        rule test {
            condition:
                crx.permhash() == "0bd16e5d8c30b71e844aa6f30b381adf20dc14cc555f5594fc3ac49985c9a52e"
        }
        "#,
        &crx,
    );
}

#[wasm_bindgen_test]
fn dex_module_parses_real_fixture() {
    let dex = decode_zipped_ihex_fixture(
        DEX_FIXTURE_ZIP,
        "c14c75d58399825287e0ee0fcfede6ec06f93489fb52f70bca2736fae5fceab2.in",
    );

    assert_rule_matches(
        r#"
        import "dex"
        rule test {
            condition:
                dex.checksum() == 0x200c7aa1 and
                dex.signature() == "e9bd6aa16e8eea1a71e7fd2eb3236749a10a64ef" and
                dex.contains_string("loadLibrary") and
                dex.contains_method("getPackageName") and
                dex.contains_class("Lwmczycqxv/egztwrhea;")
        }
        "#,
        &dex,
    );
}

#[wasm_bindgen_test]
fn elf_module_parses_real_fixture() {
    let elf = decode_zipped_ihex_fixture(
        ELF_FIXTURE_ZIP,
        "8bfe885838b4d1fba194b761ca900a0425aa892e4b358bf5a9bf4304e571df1b.in",
    );

    assert_rule_matches(
        r#"
        import "elf"
        rule test {
            condition:
                elf.import_md5() == "141ad500037085bdbe4665241c44f936" and
                elf.telfhash() == "T174B012188204F00184540770331E0B111373086019509C464D0ACE88181266C09774FA"
        }
        "#,
        &elf,
    );
}

#[wasm_bindgen_test]
fn dotnet_module_parses_real_fixtures() {
    let types2 =
        decode_zipped_ihex_fixture(DOTNET_TYPES2_FIXTURE_ZIP, "types2.dll.in");
    let empty = decode_zipped_ihex_fixture(
        DOTNET_EMPTY_FIXTURE_ZIP,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.in",
    );

    assert_rule_matches(
        r#"
        import "dotnet"
        rule test {
            condition:
                dotnet.is_dotnet and
                dotnet.module_name == "types2.dll" and
                dotnet.version == "v4.0.30319" and
                dotnet.classes.len() == 2 and
                dotnet.classes[1].methods.len() == 3 and
                dotnet.classes[1].methods[1].parameters[0].type == "int[3]"
        }
        "#,
        &types2,
    );

    assert_rule_matches(
        r#"
        import "dotnet"
        rule test {
            condition:
                not dotnet.is_dotnet
        }
        "#,
        &empty,
    );
}

#[wasm_bindgen_test]
fn macho_module_parses_real_fixture() {
    let macho = decode_zipped_ihex_fixture(
        MACHO_TINY_UNIVERSAL_FIXTURE_ZIP,
        "tiny_universal.in",
    );

    assert_rule_matches(
        r#"
        import "macho"
        rule test {
            condition:
                macho.file_index_for_arch(0x00000007) == 0 and
                macho.file_index_for_arch(0x01000007) == 1 and
                macho.entry_point_for_arch(0x00000007) == 0x00001EE0 and
                macho.entry_point_for_arch(0x01000007) == 0x00004EE0 and
                macho.has_dylib("/usr/lib/libSystem.B.dylib") and
                macho.has_export("_factorial")
        }
        "#,
        &macho,
    );
}

#[wasm_bindgen_test]
fn lnk_module_parses_real_fixtures() {
    let standard = decode_zipped_ihex_fixture(
        LNK_STANDARD_FIXTURE_ZIP,
        "lnk-standard.in",
    );
    let network =
        decode_zipped_ihex_fixture(LNK_NETWORK_FIXTURE_ZIP, "lnk-network.in");
    let empty =
        decode_zipped_ihex_fixture(LNK_EMPTY_FIXTURE_ZIP, "lnk-empty.in");

    assert_rule_matches(
        r#"
        import "lnk"
        rule test {
            condition:
                lnk.is_lnk and
                lnk.local_base_path == "C:\\test\\a.txt" and
                lnk.relative_path == ".\\a.txt" and
                lnk.working_dir == "C:\\test" and
                lnk.tracker_data.machine_id == "chris-xps"
        }
        "#,
        &standard,
    );

    assert_rule_matches(
        r#"
        import "lnk"
        rule test {
            condition:
                lnk.is_lnk and
                lnk.common_path_suffix == "calc.exe" and
                lnk.working_dir == "Z:\\" and
                lnk.tracker_data.machine_id == "localhost"
        }
        "#,
        &network,
    );

    assert_rule_matches(
        r#"
        import "lnk"
        rule test {
            condition:
                not lnk.is_lnk
        }
        "#,
        &empty,
    );
}

#[wasm_bindgen_test]
fn pe_module_parses_real_fixtures() {
    let rich = decode_zipped_ihex_fixture(
        PE_RICH_FIXTURE_ZIP,
        "079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885.in",
    );
    let imports = decode_zipped_ihex_fixture(
        PE_IMPORTS_FIXTURE_ZIP,
        "2775d97f8bdb3311ace960a42eee35dbec84b9d71a6abbacb26c14e83f5897e4.in",
    );
    let import_rva = decode_zipped_ihex_fixture(
        PE_IMPORT_RVA_FIXTURE_ZIP,
        "0ba6042247d90a187919dd88dc2d55cd882c80e5afc511c4f7b2e0e193968f7f.in",
    );

    assert_rule_matches(
        r#"
        import "pe"
        rule test {
            condition:
                pe.rich_signature.toolid(157) == 1 and
                pe.rich_signature.version(40219) == 22 and
                pe.delayed_import_rva("QDB.dll", 95) == 16416
        }
        "#,
        &rich,
    );

    assert_rule_matches(
        r#"
        import "pe"
        rule test {
            condition:
                pe.imports("KERNEL32.dll") == 17 and
                pe.imports(pe.IMPORT_DELAYED, "USER32.dll", "CreateMenu") and
                pe.imports(pe.IMPORT_DELAYED, "COMCTL32.dll", 17)
        }
        "#,
        &imports,
    );

    assert_rule_matches(
        r#"
        import "pe"
        rule test {
            condition:
                pe.imports("kernel32.dll") == 6 and
                pe.imports("ws2_32.dll", 20) and
                pe.import_rva("ws2_32.dll", 20) == 38116 and
                pe.import_rva("kernel32.dll", "VirtualProtect") == 38072
        }
        "#,
        &import_rva,
    );
}

#[wasm_bindgen_test]
fn math_module_functions_work() {
    assert_rule_matches(
        r#"
        import "math"
        rule test {
            condition:
                math.min(1, 2) == 1 and
                math.max(1, 2) == 2 and
                math.abs(-7) == 7 and
                math.in_range(0.5, 0.0, 1.0) and
                math.count(0x41, 0, 5) == 4 and
                math.percentage(0x41, 0, 5) > 0.79 and
                math.mode(0, 5) == 0x41 and
                math.to_string(32, 16) == "20"
        }
        "#,
        b"AAAAB",
    );
}

#[wasm_bindgen_test]
fn string_module_functions_work() {
    assert_rule_matches(
        r#"
        import "string"
        rule test {
            condition:
                string.length("AXsx00ERS") == 9 and
                string.to_int("1234") == 1234 and
                string.to_int("-011", 8) == -9 and
                string.to_int("A", 16) == 10
        }
        "#,
        b"",
    );
}

#[wasm_bindgen_test]
fn time_module_now_returns_unix_timestamp() {
    assert_rule_matches(
        r#"
        import "time"
        rule test {
            condition:
                time.now() > 1_600_000_000
        }
        "#,
        b"",
    );
}

#[wasm_bindgen_test]
fn test_proto_and_vt_modules_are_exposed() {
    assert_rule_matches(
        r#"
        import "test_proto2"
        import "test_proto3"
        import "vt"
        rule test {
            condition:
                test_proto2.add(1, 2) == 3 and
                test_proto2.uppercase("foo") == "FOO" and
                test_proto2.head(3) == "\x01\x02\x03" and
                test_proto3.int64_one == 1 and
                test_proto3.int64_undef == 0 and
                not test_proto3.bool_undef and
                test_proto3.string_foo == "foo" and
                vt.Domain.Permutation.ALL == vt.Domain.Permutation.TYPO
                    | vt.Domain.Permutation.HYPHENATION
                    | vt.Domain.Permutation.HOMOGLYPH
                    | vt.Domain.Permutation.SUBDOMAIN
                    | vt.Domain.Permutation.BITSQUATTING
        }
        "#,
        &[0x01, 0x02, 0x03, 0x04],
    );
}

#[wasm_bindgen_test]
fn macho_module_reports_absent_values_as_non_matches() {
    let macho = decode_zipped_ihex_fixture(
        MACHO_TINY_UNIVERSAL_FIXTURE_ZIP,
        "tiny_universal.in",
    );

    assert_rule_does_not_match(
        r#"
        import "macho"
        rule test {
            condition:
                macho.has_dylib("totally not present dylib")
        }
        "#,
        &macho,
    );
}
