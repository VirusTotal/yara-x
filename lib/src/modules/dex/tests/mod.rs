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

/// Builds a minimal DEX file with the given string, type, prototype, method
/// and class tables. Types refer to strings, prototypes to (shorty string,
/// return type), methods to (class type, prototype, name string) and classes
/// to a type, all by index.
fn build_dex(
    strings: &[&str],
    types: &[u32],
    protos: &[(u32, u32)],
    methods: &[(u16, u16, u32)],
    classes: &[u32],
) -> Vec<u8> {
    const HEADER_SIZE: usize = 0x70;
    const NO_INDEX: u32 = 0xffffffff;

    let string_ids_off = HEADER_SIZE;
    let type_ids_off = string_ids_off + 4 * strings.len();
    let proto_ids_off = type_ids_off + 4 * types.len();
    let method_ids_off = proto_ids_off + 12 * protos.len();
    let class_defs_off = method_ids_off + 8 * methods.len();
    let data_off = class_defs_off + 32 * classes.len();

    let mut body = Vec::new();
    let mut string_data = Vec::new();

    for s in strings {
        let offset = data_off + string_data.len();
        body.extend_from_slice(&(offset as u32).to_le_bytes());
        // The string data starts with its length in UTF-16 code units, and
        // MUTF-8 encodes the characters used here exactly like UTF-8.
        let mut len = s.encode_utf16().count();
        loop {
            let byte = (len & 0x7f) as u8;
            len >>= 7;
            if len == 0 {
                string_data.push(byte);
                break;
            }
            string_data.push(byte | 0x80);
        }
        string_data.extend_from_slice(s.as_bytes());
        string_data.push(0);
    }
    for t in types {
        body.extend_from_slice(&t.to_le_bytes());
    }
    for (shorty, return_type) in protos {
        body.extend_from_slice(&shorty.to_le_bytes());
        body.extend_from_slice(&return_type.to_le_bytes());
        body.extend_from_slice(&0_u32.to_le_bytes());
    }
    for (class, proto, name) in methods {
        body.extend_from_slice(&class.to_le_bytes());
        body.extend_from_slice(&proto.to_le_bytes());
        body.extend_from_slice(&name.to_le_bytes());
    }
    for class in classes {
        for field in [*class, 1, NO_INDEX, 0, NO_INDEX, 0, 0, 0] {
            body.extend_from_slice(&field.to_le_bytes());
        }
    }
    body.extend_from_slice(&string_data);

    let mut header = vec![0_u8; HEADER_SIZE];
    let mut put = |offset: usize, value: usize| {
        header[offset..offset + 4]
            .copy_from_slice(&(value as u32).to_le_bytes());
    };
    put(0x20, HEADER_SIZE + body.len());
    put(0x24, HEADER_SIZE);
    put(0x28, 0x12345678);
    put(0x38, strings.len());
    put(0x3c, string_ids_off);
    put(0x40, types.len());
    put(0x44, type_ids_off);
    put(0x48, protos.len());
    put(0x4c, proto_ids_off);
    put(0x58, methods.len());
    put(0x5c, method_ids_off);
    put(0x60, classes.len());
    put(0x64, class_defs_off);
    header[0..8].copy_from_slice(b"dex\n035\0");

    header.extend_from_slice(&body);
    header
}

#[test]
fn skipped_string_does_not_shift_indices() {
    // Strings longer than 65536 UTF-16 code units are not parsed. A long
    // string sorted before the class and method names must not shift the
    // indices those names are referenced by.
    let long = "A".repeat(70_000);
    let dex = build_dex(
        &[&long, "Lcom/example/Main;", "V", "evilMethod"],
        &[1, 2],
        &[(2, 1)],
        &[(0, 0, 3)],
        &[0],
    );

    rule_true!(
        r#"
        import "dex"
        rule test {
            condition:
                dex.has_string("evilMethod") and
                dex.has_method("evilMethod") and
                dex.has_method("Lcom/example/Main;", "evilMethod") and
                dex.has_class("Lcom/example/Main;") and
                dex.methods[0].proto.shorty == "V"
        }
        "#,
        &dex
    );
}

#[test]
fn non_ascii_strings() {
    // The length that precedes the string data counts UTF-16 code units,
    // not bytes, so strings with multibyte characters must be read up to
    // their null terminator.
    let dex = build_dex(
        &["Lcom/example/Main;", "V", "m\u{e9}todo", "\u{65e5}\u{672c}"],
        &[0, 1],
        &[(1, 1)],
        &[(0, 0, 2)],
        &[0],
    );

    rule_true!(
        r#"
        import "dex"
        rule test {
            condition:
                dex.has_string("método") and
                dex.has_string("日本") and
                dex.has_method("método") and
                dex.has_method(/^m.+todo$/)
        }
        "#,
        &dex
    );
}
