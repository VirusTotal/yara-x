use pretty_assertions::assert_eq;

use crate::tests::rule_true;
use crate::tests::test_rule;

#[test]
fn rich_signature() {
    let pe = crate::modules::tests::create_binary_from_ihex(
        "src/modules/pe/tests/testdata/079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885.in",
    )
        .unwrap();

    rule_true!(
        r#"
        import "pe"
        rule test {
          condition:
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
