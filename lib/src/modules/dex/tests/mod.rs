use pretty_assertions::assert_eq;

use crate::modules::tests::create_binary_from_zipped_ihex;
use crate::tests::rule_false;
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

#[test]
fn strings() {
    let dex = create_binary_from_zipped_ihex(
        "src/modules/dex/tests/testdata/c14c75d58399825287e0ee0fcfede6ec06f93489fb52f70bca2736fae5fceab2.in.zip",
    );

    rule_true!(
        r#"
        import "dex"
        rule test {
            condition:
                dex.has_string("loadLibrary") and
                dex.contains_string("loadLibrary")
        }
        "#,
        &dex
    );

    rule_false!(
        r#"
        import "dex"
        rule test {
            condition:
                dex.has_string("thisStringDoesNotExist") or
                dex.contains_string("thisStringDoesNotExist")
        }
        "#,
        &dex
    );
}

#[test]
fn methods() {
    let dex = create_binary_from_zipped_ihex(
        "src/modules/dex/tests/testdata/c14c75d58399825287e0ee0fcfede6ec06f93489fb52f70bca2736fae5fceab2.in.zip",
    );

    // In this DEX file `getPackageName` is a method of class
    // `Lwmczycqxv/egztwrhea;` and `loadLibrary` is a method of class
    // `Ljava/lang/System;`.

    // Single-argument string and regexp forms for both `contains_method` and
    // its alias `has_method`.
    rule_true!(
        r#"
        import "dex"
        rule test {
            condition:
                dex.contains_method("getPackageName") and
                dex.contains_method(/getPackage.*/) and
                dex.contains_method("loadLibrary") and
                dex.has_method("getPackageName") and
                dex.has_method(/getPackage.*/) and
                dex.has_method("loadLibrary")
        }
        "#,
        &dex
    );

    // Two-argument `(class_name, method_name)` forms (strings and regexps).
    rule_true!(
        r#"
        import "dex"
        rule test {
            condition:
                dex.contains_method("Lwmczycqxv/egztwrhea;", "getPackageName") and
                dex.contains_method(/Lwmczycqxv\/.*/, /getPackageName/) and
                dex.contains_method("Ljava/lang/System;", "loadLibrary") and
                dex.has_method("Lwmczycqxv/egztwrhea;", "getPackageName") and
                dex.has_method(/Lwmczycqxv\/.*/, /getPackageName/) and
                dex.has_method("Ljava/lang/System;", "loadLibrary")
        }
        "#,
        &dex
    );

    // Negatives: missing methods, case sensitivity, and class+method binding
    // (`getPackageName` does not belong to `Ljava/lang/System;`, and
    // `loadLibrary` does not belong to `Lwmczycqxv/egztwrhea;`).
    rule_false!(
        r#"
        import "dex"
        rule test {
            condition:
                dex.contains_method("thisMethodDoesNotExist") or
                dex.contains_method("getpackagename") or
                dex.contains_method(/^thisMethodDoesNotExist$/) or
                dex.contains_method("Ljava/lang/System;", "getPackageName") or
                dex.contains_method("Lwmczycqxv/egztwrhea;", "loadLibrary") or
                dex.has_method("thisMethodDoesNotExist") or
                dex.has_method(/^thisMethodDoesNotExist$/) or
                dex.has_method("Ljava/lang/System;", "getPackageName") or
                dex.has_method("Lwmczycqxv/egztwrhea;", "loadLibrary") or
                dex.has_method(/Ljava\/lang\/System;/, /getPackageName/)
        }
        "#,
        &dex
    );

    // Non-DEX input returns false.
    rule_false!(
        r#"
        import "dex"
        rule test {
            condition:
                dex.contains_method("getPackageName") or
                dex.has_method(/getPackage.*/)
        }
        "#,
        b"not a dex"
    );
}

#[test]
fn classes() {
    let dex = create_binary_from_zipped_ihex(
        "src/modules/dex/tests/testdata/c14c75d58399825287e0ee0fcfede6ec06f93489fb52f70bca2736fae5fceab2.in.zip",
    );

    // `contains_class` / `has_class` only match classes *defined* in the DEX
    // file (`class_defs`), not classes that are merely referenced. In this
    // file the only defined class is `Lwmczycqxv/egztwrhea;`.
    rule_true!(
        r#"
        import "dex"
        rule test {
            condition:
                dex.contains_class("Lwmczycqxv/egztwrhea;") and
                dex.contains_class(/Lwmczycqxv\/.*/) and
                dex.has_class("Lwmczycqxv/egztwrhea;") and
                dex.has_class(/Lwmczycqxv\/.*/)
        }
        "#,
        &dex
    );

    // `Ljava/lang/System;` is referenced but not defined, so `contains_class`
    // and `has_class` are false for it.
    rule_false!(
        r#"
        import "dex"
        rule test {
            condition:
                dex.contains_class("Ljava/lang/System;") or
                dex.contains_class("lwmczycqxv/egztwrhea;") or
                dex.contains_class("Lcom/does/not/Exist;") or
                dex.contains_class(/^Lthisclassdoesnotexist/) or
                dex.has_class("Ljava/lang/System;") or
                dex.has_class("Lcom/does/not/Exist;") or
                dex.has_class(/^Lthisclassdoesnotexist/)
        }
        "#,
        &dex
    );

    // Non-DEX input returns false.
    rule_false!(
        r#"
        import "dex"
        rule test {
            condition:
                dex.contains_class("Lwmczycqxv/egztwrhea;") or
                dex.has_class(/Lwmczycqxv\/.*/)
        }
        "#,
        b"not a dex"
    );
}
