use pretty_assertions::assert_eq;
use protobuf::MessageDyn;
use protobuf::{Message, MessageFull};
use serde_json::json;

use crate::mods;
use crate::scanner::{MetaValue, Scanner};
use crate::variables::VariableError;

#[test]
fn iterators() {
    let rules = crate::compile(
        r#"
rule rule_1 { condition: true }
rule rule_2 { condition: false }
rule rule_3 { condition: true }
rule rule_4 { condition: false }
"#,
    )
    .unwrap();

    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(&[]).expect("scan should not fail");

    let mut iter = results.matching_rules();

    assert_eq!(iter.len(), 2);
    assert_eq!(iter.next().unwrap().identifier(), "rule_1");
    assert_eq!(iter.len(), 1);
    assert_eq!(iter.next().unwrap().identifier(), "rule_3");
    assert_eq!(iter.len(), 0);
    assert!(iter.next().is_none());

    let mut iter = results.non_matching_rules();

    assert_eq!(iter.len(), 2);
    assert_eq!(iter.next().unwrap().identifier(), "rule_2");
    assert_eq!(iter.len(), 1);
    assert_eq!(iter.next().unwrap().identifier(), "rule_4");
    assert_eq!(iter.len(), 0);
    assert!(iter.next().is_none());
}

#[test]
fn matches() {
    let rules = crate::compile(
        r#"
        rule test {
            strings:
                $a = "foobar"
                $b = "bar"
                $c = "baz"
            condition:
                any of them
        }
        "#,
    )
    .unwrap();

    let mut matches = vec![];
    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(b"foobar").expect("scan should not fail");

    for matching_rule in results.matching_rules() {
        for pattern in matching_rule.patterns() {
            matches.extend(
                pattern
                    .matches()
                    .map(|x| (pattern.identifier(), x.range(), x.data())),
            )
        }
    }

    assert_eq!(
        matches,
        [("$a", 0..6, b"foobar".as_slice()), ("$b", 3..6, b"bar".as_slice())]
    )
}

#[test]
fn metadata() {
    let rules = crate::compile(
        r#"
        rule test {
            meta:
                foo = 1
                bar = 2.0
                baz = true
                qux = "qux"
                quux = "qu\x00x"
            condition:
                true
        }
        "#,
    )
    .unwrap();

    let mut metas = vec![];
    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(b"").expect("scan should not fail");
    let matching_rule = results.matching_rules().next().unwrap();

    for meta in matching_rule.metadata() {
        metas.push(meta)
    }

    assert_eq!(
        metas,
        [
            ("foo", MetaValue::Integer(1)),
            ("bar", MetaValue::Float(2.0)),
            ("baz", MetaValue::Bool(true)),
            ("qux", MetaValue::String("qux")),
            ("quux", MetaValue::Bytes(b"qu\0x".into())),
        ]
    );

    let meta_json = matching_rule.metadata().into_json();

    assert_eq!(
        meta_json,
        json!([
            ("foo", 1),
            ("bar", 2.0),
            ("baz", true),
            ("qux", "qux"),
            ("quux", [113, 117, 0, 120])
        ])
    )
}

#[test]
fn xor_matches() {
    let rules = crate::compile(
        r#"
        rule test {
            strings:
                $a = "mississippi" xor
            condition:
                $a
        }
        "#,
    )
    .unwrap();

    let mut matches = vec![];

    for matching_rule in Scanner::new(&rules)
        .scan(b"lhrrhrrhqqh")
        .expect("scan should not fail")
        .matching_rules()
    {
        for pattern in matching_rule.patterns() {
            matches.extend(
                pattern
                    .matches()
                    .map(|x| (pattern.identifier(), x.range(), x.xor_key())),
            )
        }
    }

    // The xor key must be 1.
    assert_eq!(matches, [("$a", 0..11, Some(1))])
}

#[cfg(feature = "test_proto2-module")]
#[test]
fn reuse_scanner() {
    let rules = crate::compile(
        r#"
        import "test_proto2"
        rule test {
            condition:
                test_proto2.file_size == 3
        }
        "#,
    )
    .unwrap();

    let mut scanner = Scanner::new(&rules);

    assert_eq!(
        scanner
            .scan(b"")
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        0
    );
    assert_eq!(
        scanner
            .scan(b"123")
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );
    assert_eq!(
        scanner
            .scan(b"")
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        0
    );
}

#[cfg(feature = "test_proto2-module")]
#[test]
fn module_output() {
    let rules = crate::compile(
        r#"
        import "test_proto2"
        rule test {
            condition:
                test_proto2.file_size == 3
        }
        "#,
    )
    .unwrap();

    let mut scanner = Scanner::new(&rules);
    let scan_results = scanner.scan(b"").expect("scan should not fail");

    let output = scan_results
        .module_output("test_proto2")
        .expect("test_proto2 should produce some output");

    let output: &crate::modules::protos::test_proto2::TestProto2 =
        <dyn MessageDyn>::downcast_ref(output).unwrap();

    assert_eq!(output.int32_one, Some(1_i32));
}

#[cfg(feature = "test_proto2-module")]
#[test]
fn module_outputs() {
    let rules = crate::compile(
        r#"
        import "test_proto2"
        rule test {
            condition:
                test_proto2.file_size == 3
        }
        "#,
    )
    .unwrap();

    let mut scanner = Scanner::new(&rules);
    let scan_results = scanner.scan(b"").expect("scan should not fail");

    let mut outputs = scan_results.module_outputs();

    let (name, output) = outputs
        .next()
        .expect("module outputs iterator should produce at least one item");

    assert_eq!(name, "test_proto2");

    let output: &crate::modules::protos::test_proto2::TestProto2 =
        <dyn MessageDyn>::downcast_ref(output).unwrap();

    assert_eq!(output.int32_one, Some(1_i32));
    assert!(outputs.next().is_none());
}

#[test]
fn variables_1() {
    let mut compiler = crate::Compiler::new();

    compiler
        .define_global("bool_var", false)
        .unwrap()
        .add_source(
            r#"
        rule test {
            condition:
            bool_var
        }
        "#,
        )
        .unwrap();

    let rules = compiler.build();

    let mut scanner = Scanner::new(&rules);

    assert_eq!(
        scanner
            .scan(&[])
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        0
    );

    scanner.set_global("bool_var", true).unwrap();

    assert_eq!(
        scanner
            .scan(&[])
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );

    scanner.set_global("bool_var", false).unwrap();

    assert_eq!(
        scanner
            .scan(&[])
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        0
    );

    assert_eq!(
        scanner.set_global("bool_var", 2).err().unwrap(),
        VariableError::InvalidType {
            variable: "bool_var".to_string(),
            expected_type: "boolean".to_string(),
            actual_type: "integer".to_string()
        }
    );

    assert_eq!(
        scanner.set_global("undefined", false).err().unwrap(),
        VariableError::Undefined("undefined".to_string())
    );
}

#[test]
fn variables_2() {
    let mut compiler = crate::Compiler::new();

    compiler
        .define_global("some_bool", true)
        .unwrap()
        .define_global("some_str", "")
        .unwrap()
        .add_source(
            r#"
        rule test {
            condition:
                some_bool and
                some_str == "foo"
        }
        "#,
        )
        .unwrap();

    let rules = compiler.build();

    let mut scanner = Scanner::new(&rules);
    assert_eq!(
        scanner
            .scan(&[])
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        0
    );

    scanner.set_global("some_bool", false).unwrap();
    assert_eq!(
        scanner
            .scan(&[])
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        0
    );

    scanner.set_global("some_str", "foo").unwrap();
    assert_eq!(
        scanner
            .scan(&[])
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        0
    );

    scanner.set_global("some_bool", true).unwrap();
    assert_eq!(
        scanner
            .scan(&[])
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );
}

#[test]
fn global_rules() {
    let mut compiler = crate::Compiler::new();

    compiler
        .add_source(
            r#"
        // This rule is always true.
        private rule const_true {
            condition:
                true
        }
        // This global rule doesn't affect the results because it's true.
        global rule global_true {
            condition:
                const_true
        }
        // Even if the condition is true, this rule doesn't match because of
        // the false global rule that follows.
        rule non_matching {
            condition:
                true
        }
        // A false global rule that prevents all rules in the same namespace
        // from matching.
        global rule global_false {
            condition:
                false
        }
        "#,
        )
        .unwrap()
        .new_namespace("matching")
        .add_source(
            r#"
            // This rule matches because it is in separate namespace not
            // which is not affected by the global rule.
            rule matching {
                condition:
                    true
            }"#,
        )
        .unwrap();

    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(&[]).expect("scan should not fail");

    assert_eq!(results.matching_rules().len(), 1);

    let mut matching = results.matching_rules();
    assert_eq!(matching.next().unwrap().identifier(), "matching");
    assert!(matching.next().is_none());

    let mut non_matching = results.non_matching_rules();

    // `global_true` and `non_matching` don't match because they are in the
    // namespace as `global_false`.
    assert_eq!(non_matching.next().unwrap().identifier(), "global_true");
    assert_eq!(non_matching.next().unwrap().identifier(), "non_matching");
    assert_eq!(non_matching.next().unwrap().identifier(), "global_false");

    assert!(non_matching.next().is_none());
}

#[test]
fn private_rules() {
    let mut compiler = crate::Compiler::new();

    compiler
        .add_source(
            r#"
        global private rule test_1 {
            condition:
                true
        }

        private rule test_2 {
            condition:
                true
        }

        rule test_3 {
            condition:
                true
        }
        "#,
        )
        .unwrap();

    let rules = compiler.build();

    let mut scanner = Scanner::new(&rules);
    let scan_results = scanner.scan(&[]).expect("scan should not fail");

    // Only the matching non-private rule should be reported.
    assert_eq!(scan_results.matching_rules().len(), 1);

    // Only the non-matching, non-private rules should be reported.
    assert_eq!(scan_results.non_matching_rules().len(), 0);
}

#[test]
fn max_matches_per_pattern() {
    let mut compiler = crate::Compiler::new();

    compiler
        .add_source(
            r#"
        rule test_3 {
            strings:
              $a = "foo"
            condition:
              $a
        }
        "#,
        )
        .unwrap();

    let rules = compiler.build();

    let mut scanner = Scanner::new(&rules);
    scanner.max_matches_per_pattern(1);
    let scan_results =
        scanner.scan(b"foofoofoo").expect("scan should not fail");

    assert_eq!(scan_results.matching_rules().len(), 1);

    let mut matches = scan_results
        .matching_rules()
        .next()
        .unwrap()
        .patterns()
        .next()
        .unwrap()
        .matches();

    // Only one match is returned for pattern $a because the limit has been
    // set to 1.
    let match_ = matches.next().unwrap();

    assert_eq!(match_.range(), (0..3));
    assert_eq!(match_.data(), b"foo");

    assert!(matches.next().is_none());

    // If the scanner is used again it should produce results because the
    // number of matches must be reset to 0 for the new scan.
    assert_eq!(scanner.scan(b"foo").unwrap().matching_rules().len(), 1);
}

#[test]
fn set_module_output() {
    let mut compiler = crate::Compiler::new();

    compiler
        .add_source(
            r#"
        import "pe"
        rule test {
            condition:
              pe.entry_point == 1
        }
        "#,
        )
        .unwrap();

    let rules = compiler.build();

    let mut scanner = Scanner::new(&rules);
    let mut pe_data = Box::new(mods::PE::new());

    pe_data.set_entry_point(1);
    pe_data.set_is_pe(true);

    let pe_data_raw = pe_data.write_to_bytes().unwrap();

    scanner.set_module_output(pe_data).unwrap();

    // The data being scanned is empty, but we set the output for the PE module
    // by ourselves.
    let scan_results = scanner.scan(b"").expect("scan should not fail");
    assert_eq!(scan_results.matching_rules().len(), 1);

    // In this second call we haven't set a value for entry point, so it's
    // undefined.
    let scan_results = scanner.scan(b"").expect("scan should not fail");
    assert_eq!(scan_results.matching_rules().len(), 0);

    // This should fail because `foobar` is not a valid module name.
    assert_eq!(
        scanner
            .set_module_output_raw("foobar", &[])
            .err()
            .unwrap()
            .to_string()
            .as_str(),
        "unknown module `foobar`"
    );

    // This should fail while trying to parse the empty slice as the protobuf
    // corresponding to the `pe` module.
    assert_eq!(
        scanner
            .set_module_output_raw("pe", &[])
            .err()
            .unwrap()
            .to_string()
            .as_str(),
        "can not deserialize protobuf message for YARA module `pe`: Message `PE` is missing required fields"
    );

    // Now test by passing a valid protobuf for the PE module.
    scanner.set_module_output_raw("pe", pe_data_raw.as_slice()).unwrap();
    let scan_results = scanner.scan(b"").expect("scan should not fail");
    assert_eq!(scan_results.matching_rules().len(), 1);

    // Try calling `set_module_output_raw` but this time pass the fully-qualified
    // name of the protobuf message, instead of the module name.
    scanner
        .set_module_output_raw(
            mods::PE::descriptor().full_name(),
            pe_data_raw.as_slice(),
        )
        .unwrap();
    let scan_results = scanner.scan(b"").expect("scan should not fail");
    assert_eq!(scan_results.matching_rules().len(), 1);
}

#[test]
fn namespaces() {
    let mut compiler = crate::Compiler::new();

    compiler
        .new_namespace("foo")
        .add_source(r#"rule foo {strings: $foo = "foo" condition: $foo }"#)
        .unwrap()
        .new_namespace("bar")
        .add_source(r#"rule bar {strings: $bar = "bar" condition: $bar }"#)
        .unwrap();

    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);
    let scan_results = scanner.scan(b"foobar").expect("scan should not fail");
    let matching_rules: Vec<_> = scan_results.matching_rules().collect();

    assert_eq!(matching_rules.len(), 2);
    assert_eq!(matching_rules[0].identifier(), "foo");
    assert_eq!(matching_rules[0].namespace(), "foo");
    assert_eq!(matching_rules[1].identifier(), "bar");
    assert_eq!(matching_rules[1].namespace(), "bar");
}
