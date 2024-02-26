use pretty_assertions::assert_eq;

use crate::modules::tests::create_binary_from_zipped_ihex;
use crate::tests::rule_false;
use crate::tests::rule_true;
use crate::tests::test_rule;

#[test]
fn test_macho_module() {
    let tiny_universal_macho_data = create_binary_from_zipped_ihex(
        "src/modules/macho/tests/testdata/tiny_universal.in.zip",
    );

    let x86_macho_data = create_binary_from_zipped_ihex(
        "src/modules/macho/tests/testdata/macho_x86_file.in.zip",
    );

    let chess_macho_data = create_binary_from_zipped_ihex(
        "src/modules/macho/tests/testdata/chess.in.zip",
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.MH_MAGIC == 0xfeedface and
            macho.MH_NO_REEXPORTED_DYLIBS == 0x00100000 and
            macho.MH_CIGAM == 0xcefaedfe and
            macho.CPU_TYPE_MIPS == 0x00000008
        }
        "#,
        &[]
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.MH_MAGIC == 0xfeedface and
            macho.MH_NO_REEXPORTED_DYLIBS == 0x00100000 and
            macho.MH_CIGAM == 0xcefaedfe and
            macho.CPU_TYPE_MIPS == 0x00000008
        }
        "#,
        &[]
    );

    rule_false!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.MH_MAGIC == 0xfeeeeeee or
            macho.MH_NO_REEXPORTED_DYLIBS == 0x99999999 or
            macho.MH_CIGAM == 0xaaaaaaaa or
            macho.CPU_TYPE_MIPS == 0x00000000
        }
        "#,
        &[]
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.file_index_for_arch(0x00000007) == 0
        }
        "#,
        &tiny_universal_macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.file_index_for_arch(0x01000007) == 1
        }
        "#,
        &tiny_universal_macho_data
    );

    rule_false!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.file_index_for_arch(0x00000008) == 0
        }
        "#,
        &tiny_universal_macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            not defined macho.file_index_for_arch(0x01000008)
        }
        "#,
        &[]
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.file_index_for_arch(0x00000007, 0x00000003) == 0
        }
        "#,
        &tiny_universal_macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.file_index_for_arch(16777223, 2147483651) == 1
        }
        "#,
        &tiny_universal_macho_data
    );

    rule_false!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.file_index_for_arch(0x00000008, 0x00000004) == 0
        }
        "#,
        &tiny_universal_macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            not defined macho.file_index_for_arch(0x00000008, 0x00000004)
        }
        "#,
        &tiny_universal_macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            not defined macho.file_index_for_arch(0x00000007, 0x00000003)
        }
        "#,
        &[]
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.entry_point_for_arch(0x00000007) == 0x00001EE0
        }
        "#,
        &tiny_universal_macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.entry_point_for_arch(0x01000007) == 0x00004EE0
        }
        "#,
        &tiny_universal_macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.entry_point_for_arch(0x00000007, 0x00000003) == 0x00001EE0
        }
        "#,
        &tiny_universal_macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.entry_point_for_arch(16777223, 2147483651) == 0x00004EE0
        }
        "#,
        &tiny_universal_macho_data
    );

    rule_false!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.entry_point_for_arch(0x00000008, 0x00000003) == 0x00001EE0
        }
        "#,
        &tiny_universal_macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            not defined macho.entry_point_for_arch(0x00000007, 0x00000003)
        }
        "#,
        &[]
    );

    rule_false!(
        r#"
        import "macho"
        rule test {
            condition:
                macho.has_dylib("totally not present dylib")
        }
        "#
    );

    rule_true!(
        r#"
        import "macho"
        rule macho_test {
            condition:
                macho.has_dylib("/usr/lib/libSystem.B.dylib")
        }
        "#,
        &tiny_universal_macho_data
    );

    rule_false!(
        r#"
        import "macho"
        rule test {
            condition:
                macho.has_rpath("totally not present rpath")
        }
        "#
    );

    rule_false!(
        r#"
        import "macho"
        rule macho_test {
            condition:
                macho.has_rpath("@loader_path/../Frameworks")
        }
        "#,
        &tiny_universal_macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule macho_test {
            condition:
                macho.has_rpath("@loader_path/../Frameworks")
        }
        "#,
        &x86_macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule macho_test {
            condition:
                macho.has_entitlement("com.apple.security.network.client")
        }
        "#,
        &chess_macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule macho_test {
            condition:
                macho.has_entitlement("COM.ApplE.security.NetWoRK.client")
        }
        "#,
        &chess_macho_data
    );

    rule_false!(
        r#"
        import "macho"
        rule macho_test {
            condition:
                macho.has_entitlement("made-up-entitlement")
        }
        "#,
        &chess_macho_data
    );
}
