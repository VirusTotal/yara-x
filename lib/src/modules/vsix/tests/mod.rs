use crate::modules::tests::create_binary_from_zipped_ihex;
use crate::tests::rule_true;
use crate::tests::test_rule;

#[test]
fn activation_events() {
    let vsix = create_binary_from_zipped_ihex(
        "src/modules/vsix/tests/testdata/sample.in.zip",
    );

    rule_true!(
        r#"
        import "vsix"
        rule test {
          condition:
            vsix.has_activation_event("*") and
            vsix.has_activation_event("onCommand:test.run") and
            not vsix.has_activation_event("nonexistent")
        }
        "#,
        &vsix
    );
}

#[test]
fn activationhash() {
    let vsix = create_binary_from_zipped_ihex(
        "src/modules/vsix/tests/testdata/sample.in.zip",
    );

    rule_true!(
        r#"
        import "vsix"
        rule test {
          condition:
            vsix.activationhash() == "cbc6d3a2274d0335cbcf4077bee3e08192a6971e2f7fe601980117dc568b06f9"
        }
        "#,
        &vsix
    );
}

#[test]
fn wildcard_activation_detection() {
    let vsix = create_binary_from_zipped_ihex(
        "src/modules/vsix/tests/testdata/sample.in.zip",
    );

    rule_true!(
        r#"
        import "vsix"
        rule wildcard_activation {
          condition:
            vsix.is_vsix and
            vsix.has_activation_event("*")
        }
        "#,
        &vsix
    );
}
