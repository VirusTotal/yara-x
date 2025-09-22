use pretty_assertions::assert_eq;

use crate::modules::tests::create_binary_from_zipped_ihex;
use crate::tests::rule_true;
use crate::tests::test_rule;

#[test]
fn checksum() {
    let dex = create_binary_from_zipped_ihex(
        "src/modules/dex/tests/testdata/c14c75d58399825287e0ee0fcfede6ec06f93489fb52f70bca2736fae5fceab2.in.zip",
    );

    rule_true!(
        r#"
        import "dex"
        rule test {
            condition:
                dex.checksum() == 0x200c7aa1
        }
        "#,
        &dex
    );

    rule_true!(
        r#"
        import "dex"
        rule test {
            condition:
                dex.header.checksum == dex.checksum()
        }
        "#,
        &dex
    );
}

#[test]
fn signature() {
    let dex = create_binary_from_zipped_ihex(
        "src/modules/dex/tests/testdata/c14c75d58399825287e0ee0fcfede6ec06f93489fb52f70bca2736fae5fceab2.in.zip",
    );

    rule_true!(
        r#"
        import "dex"
        rule test {
            condition:
                dex.signature() == "e9bd6aa16e8eea1a71e7fd2eb3236749a10a64ef"
        }
        "#,
        &dex
    );

    rule_true!(
        r#"
        import "dex"
        rule test {
            condition:
                dex.header.signature == dex.signature()
        }
        "#,
        &dex
    );
}
