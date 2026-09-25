use crate::modules::tests::create_binary_from_zipped_ihex;
use crate::tests::rule_true;
use crate::tests::test_rule;

#[test]
fn has_header() {
    let eml = create_binary_from_zipped_ihex(
        "src/modules/eml/tests/testdata/1bd008595eefab8ab0653ccaeac7857989178d75f842f8b147b6cc7e1701aca5.in.zip",
    );

    rule_true!(
        r#"
        import "eml"
        rule test {
          condition:
            eml.has_header("date")
        }
        "#,
        &eml
    );
}
