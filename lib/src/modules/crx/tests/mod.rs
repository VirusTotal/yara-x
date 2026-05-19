use pretty_assertions::assert_eq;

use crate::modules::tests::create_binary_from_zipped_ihex;
use crate::tests::rule_true;
use crate::tests::test_rule;

#[test]
fn permhash() {
    let crx = create_binary_from_zipped_ihex(
        "src/modules/crx/tests/testdata/3d1c2b1777fb5d5f4e4707ab3a1b64131c26f8dc1c30048dce7a1944b4098f3e.in.zip",
    );

    rule_true!(
        r#"
        import "crx"
        rule test {
          condition:
            crx.permhash() == "0bd16e5d8c30b71e844aa6f30b381adf20dc14cc555f5594fc3ac49985c9a52e"
        }
        "#,
        &crx
    );
}