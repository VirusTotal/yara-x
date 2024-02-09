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
