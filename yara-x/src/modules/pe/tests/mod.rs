use pretty_assertions::assert_eq;

use crate::modules::tests::create_binary_from_zipped_ihex;
use crate::tests::rule_true;
use crate::tests::test_rule;

#[test]
fn rich_signature() {
    let pe = create_binary_from_zipped_ihex(
        "src/modules/pe/tests/testdata/079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885.in.zip",
    );

    rule_true!(
        r#"
        import "pe"
        rule test {
          condition:
            pe.rich_signature.toolid(157) == 1 and 
            pe.rich_signature.toolid(157, 40219) == 1 and 
            pe.rich_signature.toolid(1, 0) > 40 and 
            pe.rich_signature.toolid(1, 0) < 45 and
            pe.rich_signature.version(30319) == 3 and
            pe.rich_signature.version(40219) == 22 and
            pe.rich_signature.version(40219, 170) == 11
        }
        "#,
        &pe
    );
}

#[test]
fn imports() {
    let pe = create_binary_from_zipped_ihex(
        "src/modules/pe/tests/testdata/2775d97f8bdb3311ace960a42eee35dbec84b9d71a6abbacb26c14e83f5897e4.in.zip",
    );

    rule_true!(
        r#"
        import "pe"
        rule test {
          condition:
            pe.imports("KERNEL32.dll") == 17 and 
            pe.imports("kernel32.dll") == 17
        }
        "#,
        &pe
    );

    rule_true!(
        r#"
        import "pe"
        rule test {
          condition:
            pe.imports("KERNEL32.dll", "InterlockedExchange")
        }
        "#,
        &pe
    );

    rule_true!(
        r#"
        import "pe"
        rule test {
          condition:
            pe.imports(pe.IMPORT_DELAYED, "USER32.dll", "CreateMenu") and
            pe.imports(pe.IMPORT_ANY, "USER32.dll", "CreateMenu")
        }
        "#,
        &pe
    );

    rule_true!(
        r#"
        import "pe"
        rule test {
          condition:
            not pe.imports(pe.IMPORT_STANDARD, "USER32.dll", "CreateMenu")
        }
        "#,
        &pe
    );

    rule_true!(
        r#"
        import "pe"
        rule test {
          condition:
            pe.imports(pe.IMPORT_DELAYED, "COMCTL32.dll", 17)
        }
        "#,
        &pe
    );

    rule_true!(
        r#"
        import "pe"
        rule test {
          condition:
            // Matches GetModuleHandleA, GetStdHandle and CloseHandle
            pe.imports(/KERNEL32.dll/, /.*Handle/) == 3 and
            
            // Matches GetStdHandle and CloseHandle
            pe.imports(/KERNEL32.dll/, /.*Handle$/) == 2
        }
        "#,
        &pe
    );

    rule_true!(
        r#"
        import "pe"
        rule test {
          condition:
            // Matches CreateMenu and DestroyMenu
            pe.imports(pe.IMPORT_DELAYED, /user32.dll/i, /.*Menu/) == 2
        }
        "#,
        &pe
    );

    rule_true!(
        r#"
        import "pe"
        rule test {
          condition:
            // Matches ADVAPI32:RegOpenKeyExA, ADVAPI32:RegCloseKey and GDI32:DeleteObject.
            pe.imports(pe.IMPORT_DELAYED, /(ADVAPI|GDI)32.dll/, /^((.*Key)|(.*Object))/) == 3
        }
        "#,
        &pe
    );

    let pe = create_binary_from_zipped_ihex(
        "src/modules/pe/tests/testdata/0ba6042247d90a187919dd88dc2d55cd882c80e5afc511c4f7b2e0e193968f7f.in.zip",
    );

    rule_true!(
        r#"
        import "pe"
        rule test {
          condition:
            pe.imports("kernel32.dll") == 6
        }
        "#,
        &pe
    );

    rule_true!(
        r#"
        import "pe"
        rule test {
          condition:
            pe.imports("ws2_32.dll", 20)
        }
        "#,
        &pe
    );

    rule_true!(
        r#"
        import "pe"
        rule test {
          condition:
            pe.imports(pe.IMPORT_ANY, "ws2_32.dll") == 1
        }
        "#,
        &pe
    );
}

#[test]
fn import_rva() {
    let pe = create_binary_from_zipped_ihex(
        "src/modules/pe/tests/testdata/0ba6042247d90a187919dd88dc2d55cd882c80e5afc511c4f7b2e0e193968f7f.in.zip",
    );

    rule_true!(
        r#"
        import "pe"
        rule test {
          condition:
            pe.import_rva("ws2_32.dll", 20) == 38116
        }
        "#,
        &pe
    );

    rule_true!(
        r#"
        import "pe"
        rule test {
          condition:
            pe.import_rva("kernel32.dll", "VirtualProtect") == 38072
        }
        "#,
        &pe
    );
}

#[test]
fn delayed_import_rva() {
    let pe = create_binary_from_zipped_ihex(
        "src/modules/pe/tests/testdata/079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885.in.zip",
    );

    rule_true!(
        r#"
        import "pe"
        rule test {
          condition:
            pe.delayed_import_rva("QDB.dll", 95) == 16416
        }
        "#,
        &pe
    );

    rule_true!(
        r#"
        import "pe"
        rule test {
          condition:
            pe.delayed_import_rva("QDB.dll", "ord102") == 16412
        }
        "#,
        &pe
    );
}

#[test]
fn exports() {
    let pe = create_binary_from_zipped_ihex(
        "src/modules/pe/tests/testdata/2d80c403b5c50f8bbacb65f58e7a19f272c62d1889216b7a6f1141571ec12649.in.zip",
    );

    rule_true!(
        r#"
        import "pe"
        rule test {
          condition:
            pe.exports("Socks5GetCmd") and
            pe.exports(/Socks.*$/) and
            pe.exports(9)
        }
        "#,
        &pe
    );

    rule_true!(
        r#"
        import "pe"
        rule test {
          condition:
            pe.exports_index("Socks5GetCmd") == 8 and
            pe.exports_index(/Socks.*$/) == 5 and
            pe.exports_index(9) == 8 
        }
        "#,
        &pe
    );
}

#[test]
fn imphash() {
    let pe = create_binary_from_zipped_ihex(
        "src/modules/pe/tests/testdata/c704cca0fe4c9bdee18a302952540073b860e3b4d42e081f86d27bdb1cf6ede4.in.zip",
    );

    rule_true!(
        r#"
        import "pe"
        rule test {
          condition:
            pe.imphash() == "1720bf764274b7a4052bbef0a71adc0d"
        }
        "#,
        &pe
    );

    let pe = create_binary_from_zipped_ihex(
        "src/modules/pe/tests/testdata/e3d45a2865818756068757d7e319258fef40dad54532ee4355b86bc129f27345.in.zip",
    );

    rule_true!(
        r#"
        import "pe"
        rule test {
          condition:
            pe.imphash() == "d49b7870cb53f29ec3f42b11cc8bea8b"
        }
        "#,
        &pe
    );
}

#[test]
fn checksum() {
    let pe = create_binary_from_zipped_ihex(
        "src/modules/pe/tests/testdata/af3f20a9272489cbef4281c8c86ad42ccfb04ccedd3ada1e8c26939c726a4c8e.in.zip",
    );

    rule_true!(
        r#"
        import "pe"
        rule test {
          condition:
            pe.calculate_checksum() == 0x3CE9BA
        }
        "#,
        &pe
    );
}
