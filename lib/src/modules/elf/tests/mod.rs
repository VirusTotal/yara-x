use pretty_assertions::assert_eq;

use crate::modules::tests::create_binary_from_zipped_ihex;
use crate::tests::rule_true;
use crate::tests::test_rule;

#[test]
fn import_md5() {
    let elf = create_binary_from_zipped_ihex(
        "src/modules/elf/tests/testdata/8bfe885838b4d1fba194b761ca900a0425aa892e4b358bf5a9bf4304e571df1b.in.zip",
    );

    rule_true!(
        r#"
        import "elf"
        rule test {
          condition:
            elf.import_md5() == "141ad500037085bdbe4665241c44f936"
        }
        "#,
        &elf
    );
}

#[test]
fn telfhash_does_not_pollute_import_md5_cache() {
    let elf = create_binary_from_zipped_ihex(
        "src/modules/elf/tests/testdata/8bfe885838b4d1fba194b761ca900a0425aa892e4b358bf5a9bf4304e571df1b.in.zip",
    );

    rule_true!(
        r#"
        import "elf"
        rule test {
          condition:
            elf.telfhash() == "T174B012188204F00184540770331E0B111373086019509C464D0ACE88181266C09774FA" and
            elf.import_md5() == "141ad500037085bdbe4665241c44f936"
        }
        "#,
        &elf
    );
}

#[test]
fn telfhash() {
    let elf = create_binary_from_zipped_ihex(
        "src/modules/elf/tests/testdata/8bfe885838b4d1fba194b761ca900a0425aa892e4b358bf5a9bf4304e571df1b.in.zip",
    );

    rule_true!(
        r#"
        import "elf"
        rule test {
          condition:
            elf.telfhash() == "T174B012188204F00184540770331E0B111373086019509C464D0ACE88181266C09774FA"
        }
        "#,
        &elf
    );
}

#[test]
fn machines() {
    let mut elf = create_binary_from_zipped_ihex(
        "src/modules/elf/tests/testdata/8bfe885838b4d1fba194b761ca900a0425aa892e4b358bf5a9bf4304e571df1b.in.zip",
    );

    let machines: &[(&str, u16)] = &[
        ("EM_PARISC", 15),
        ("EM_SPARC32PLUS", 18),
        ("EM_S390", 22),
        ("EM_MCORE", 39),
        ("EM_RCE", 39),
        ("EM_SH", 42),
        ("EM_SPARCV9", 43),
        ("EM_ARC_COMPACT", 93),
        ("EM_BPF", 247),
        ("EM_LOONGARCH", 258),
    ];

    for (name, value) in machines {
        // e_machine sits at offset 18 and the test ELF is little-endian.
        elf[18..20].copy_from_slice(&value.to_le_bytes());

        let rule = format!(
            r#"import "elf" rule test {{ condition: elf.machine == elf.{name} and elf.machine == {value} }}"#
        );

        rule_true!(rule.as_str(), &elf);
    }
}

