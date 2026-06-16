use pretty_assertions::assert_eq;
use protobuf::MessageDyn;
use protobuf::{Message, MessageFull};
use serde_json::json;

use crate::models::MetaValue;
use crate::variables::VariableError;
use crate::{Rule, Scanner};
use crate::{ScanOptions, mods};

#[cfg(feature = "rules-profiling")]
use std::time::Duration;

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

    let mut scanner = Scanner::new(&rules);

    let mut matches = vec![];
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
    );

    let mut matches = vec![];
    let results = scanner.scan(b"baz").expect("scan should not fail");

    for matching_rule in results.matching_rules() {
        for pattern in matching_rule.patterns() {
            matches.extend(
                pattern
                    .matches()
                    .map(|x| (pattern.identifier(), x.range(), x.data())),
            )
        }
    }

    assert_eq!(matches, [("$c", 0..3, b"baz".as_slice())]);
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

    assert_eq!(outputs.len(), 1);

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
fn variables_3() {
    let mut compiler = crate::Compiler::new();

    compiler
        .define_global("some_array", json!(["foo", "bar", "baz"]))
        .unwrap()
        .add_source(
            r#"
        rule test {
            condition:
                for any s in some_array : ( s == "bar" )
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
        
        rule test_4 {
            condition:
                 false
        }
        "#,
        )
        .unwrap();

    let rules = compiler.build();

    let mut scanner = Scanner::new(&rules);
    let scan_results = scanner.scan(&[]).expect("scan should not fail");

    let mut matching_rules = scan_results.matching_rules();

    // Only the matching non-private rule should be reported.
    assert_eq!(matching_rules.len(), 1);
    assert_eq!(matching_rules.next().unwrap().identifier(), "test_3");
    assert_eq!(matching_rules.len(), 0);
    assert!(matching_rules.next().is_none());

    let mut non_matching_rules = scan_results.non_matching_rules();

    // Only the non-matching, non-private rules should be reported.
    assert_eq!(non_matching_rules.len(), 1);
    assert_eq!(non_matching_rules.next().unwrap().identifier(), "test_4");
    assert_eq!(non_matching_rules.len(), 0);
    assert!(non_matching_rules.next().is_none());

    let mut all_matching_rules =
        scan_results.matching_rules().include_private(true);

    assert_eq!(all_matching_rules.len(), 3);
    assert_eq!(all_matching_rules.next().unwrap().identifier(), "test_1");
    assert_eq!(all_matching_rules.len(), 2);
    assert_eq!(all_matching_rules.next().unwrap().identifier(), "test_2");
    assert_eq!(all_matching_rules.len(), 1);
    assert_eq!(all_matching_rules.next().unwrap().identifier(), "test_3");
    assert_eq!(all_matching_rules.len(), 0);
    assert!(all_matching_rules.next().is_none());
}

#[test]
fn private_patterns() {
    let mut compiler = crate::Compiler::new();

    compiler
        .add_source(
            r#"
        rule test_1 {
            strings:
                $a = "foo" private
                $b = "bar"
            condition:
                $a and $b
        }
        "#,
        )
        .unwrap();

    let rules = compiler.build();

    let mut scanner = Scanner::new(&rules);
    let scan_results = scanner.scan(b"foobar").expect("scan should not fail");

    assert_eq!(scan_results.matching_rules().len(), 1);

    let rule = scan_results.matching_rules().next().unwrap();

    let mut patterns = rule.patterns();
    assert_eq!(patterns.len(), 1);
    assert_eq!(patterns.next().unwrap().identifier(), "$b");
    assert_eq!(patterns.len(), 0);
    assert!(patterns.next().is_none());

    let mut patterns = rule.patterns().include_private(true);
    assert_eq!(patterns.len(), 2);
    assert_eq!(patterns.next().unwrap().identifier(), "$a");
    assert_eq!(patterns.len(), 1);
    assert_eq!(patterns.next().unwrap().identifier(), "$b");
    assert_eq!(patterns.len(), 0);
    assert!(patterns.next().is_none());

    let mut patterns = rule.patterns();

    assert_eq!(patterns.len(), 1);
    assert_eq!(patterns.next().unwrap().identifier(), "$b");
    assert_eq!(patterns.len(), 0);

    let mut patterns = patterns.include_private(true);
    assert!(patterns.next().is_none());
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

#[test]
fn scan_file() {
    let rules = crate::compile(
        r#"
    rule test {
      strings:
        $a = "aaaa"
      condition: 
        $a
    }
    "#,
    )
    .unwrap();

    let mut scanner = Scanner::new(&rules);
    let scan_results =
        scanner.scan_file("src/tests/testdata/jumps.bin").unwrap();

    assert_eq!(scan_results.matching_rules().len(), 1);

    let scan_results = scanner
        .scan_file_with_options(
            "src/tests/testdata/jumps.bin",
            ScanOptions::default(),
        )
        .unwrap();

    assert_eq!(scan_results.matching_rules().len(), 1)
}

#[test]
fn scan_no_mmap() {
    let rules = crate::compile(
        r#"
    rule test {
      strings:
        $a = "aaaa"
      condition:
        $a
    }
    "#,
    )
    .unwrap();

    let mut scanner = Scanner::new(&rules);

    let scan_results = scanner
        .use_mmap(false)
        .scan_file("src/tests/testdata/jumps.bin")
        .unwrap();

    assert_eq!(scan_results.matching_rules().len(), 1);
}

#[test]
fn rule_serialization() {
    let rules = crate::compile(
        r#"
    rule test: foo bar {
      meta:
        foo = "foo"
        bar = 1
        baz = 2.0
        qux = true
      strings:
        $a = "aaaa"
      condition:
        $a
    }
    "#,
    )
    .unwrap();

    let mut scanner = Scanner::new(&rules);

    let scan_results = scanner.scan(b"aaaa").unwrap();
    let matching_rules: Vec<Rule> = scan_results.matching_rules().collect();

    let expected = json!([{
        "identifier": "test",
        "namespace": "default",
        "is_global": false,
        "is_private": false,
        "metadata": [
            ["foo", "foo"],
            ["bar", 1],
            ["baz", 2.0],
            ["qux", true],
        ],
        "tags": ["foo", "bar"],
        "patterns": [
            {
                "identifier": "$a",
                "kind": "Text",
                "is_private": false,
                "matches": [
                    {
                        "range": {
                            "start": 0,
                            "end": 4
                        },
                        "xor_key": null
                    }
                ]
            }
        ]
    }]);

    assert_eq!(serde_json::to_value(&matching_rules).unwrap(), expected);
}

#[cfg(feature = "rules-profiling")]
#[test]
fn rules_profiling() {
    let rules = crate::compile(
        r#"
    rule slow {
      condition: 
        for any i in (0..1000000) : (
           uint8(i) == 0xCC
        )
    }
    "#,
    )
    .unwrap();

    let mut scanner = Scanner::new(&rules);

    scanner.scan(b"foobar").unwrap();

    let slowest_rules = scanner.slowest_rules(10);

    assert_eq!(slowest_rules.len(), 1);
    assert!(slowest_rules[0].condition_exec_time.gt(&Duration::from_secs(0)));

    scanner.clear_profiling_data();

    let slowest_rules = scanner.slowest_rules(10);
    assert_eq!(slowest_rules.len(), 0);
}

#[test]
fn max_scan_size() {
    let rules = crate::compile(
        r#"
    rule test {
      strings:
        $a = "aaaa"
      condition:
        $a
    }
    "#,
    )
    .unwrap();

    let mut scanner = Scanner::new(&rules);

    // Without truncation, it matches
    assert_eq!(scanner.scan(b"aaaabbbb").unwrap().matching_rules().len(), 1);
    assert_eq!(
        scanner
            .scan_file("src/tests/testdata/jumps.bin")
            .unwrap()
            .matching_rules()
            .len(),
        1
    );

    // With truncation to 2 bytes, it shouldn't match "aaaa" (4 bytes)
    scanner.max_scan_size(2);
    assert_eq!(scanner.scan(b"aaaabbbb").unwrap().matching_rules().len(), 0);
    assert_eq!(
        scanner
            .scan_file("src/tests/testdata/jumps.bin")
            .unwrap()
            .matching_rules()
            .len(),
        0
    );
}

#[cfg(feature = "test_proto2-module")]
#[test]
fn regex_set_optimization() {
    let rules = crate::compile(
        r#"
        import "test_proto2"
        rule test {
            condition:
                test_proto2.string_foo matches /foo/ and
                test_proto2.string_foo matches /bar/
        }
        rule test_match {
            condition:
                test_proto2.string_foo matches /foo/ or
                test_proto2.string_foo matches /bar/
        }
        "#,
    )
    .unwrap();

    let mut scanner = crate::Scanner::new(&rules);
    let results = scanner.scan(b"").unwrap();

    let matching_rules: Vec<_> =
        results.matching_rules().map(|r| r.identifier().to_string()).collect();
    assert_eq!(matching_rules, vec!["test_match"]);
}

#[test]
fn fast_scan_mode() {
    let rules = crate::compile(
        r#"
    rule test_boolean {
      strings:
        $a = "foo"
        $b = "bar"
      condition:
        $a and $b
    }
    rule test_count {
      strings:
        $c = "baz"
      condition:
        #c > 1
    }
    "#,
    )
    .unwrap();

    // Test standard scan first (fast_scan = false by default)
    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(b"foofoobarbarbazbaz").unwrap();

    // Check pattern $a matches
    let test_boolean = results
        .matching_rules()
        .find(|r| r.identifier() == "test_boolean")
        .unwrap();
    let mut patterns_a =
        test_boolean.patterns().filter(|p| p.identifier() == "$a");
    assert_eq!(patterns_a.next().unwrap().matches().len(), 2); // foofoo has 2 matches

    // Check pattern $c matches
    let test_count = results
        .matching_rules()
        .find(|r| r.identifier() == "test_count")
        .unwrap();
    let mut patterns_c =
        test_count.patterns().filter(|p| p.identifier() == "$c");
    assert_eq!(patterns_c.next().unwrap().matches().len(), 2); // bazbaz has 2 matches

    // Test fast scan mode (fast_scan = true)
    let mut scanner = Scanner::new(&rules);
    scanner.fast_scan(true);
    let results = scanner.scan(b"foofoobarbarbazbaz").unwrap();

    // Rule test_boolean still matches
    let test_boolean = results
        .matching_rules()
        .find(|r| r.identifier() == "test_boolean")
        .unwrap();
    // But pattern $a must only have 1 match because it is fast-scanned!
    let mut patterns_a =
        test_boolean.patterns().filter(|p| p.identifier() == "$a");
    assert_eq!(patterns_a.next().unwrap().matches().len(), 1);

    // Pattern $c must still have 2 matches because #c is used, disabling fast scan!
    let test_count = results
        .matching_rules()
        .find(|r| r.identifier() == "test_count")
        .unwrap();
    let mut patterns_c =
        test_count.patterns().filter(|p| p.identifier() == "$c");
    assert_eq!(patterns_c.next().unwrap().matches().len(), 2);
}

#[test]
fn test_pikevm_literal_run_optimization() {
    let rules = crate::compile(
        r#"
        rule test_opt {
            strings:
                $a = /abcdefg.*hijk.*lmno/
            condition:
                $a
        }
        "#,
    )
    .unwrap();

    let mut scanner = Scanner::new(&rules);

    let results = scanner.scan(b"abcdefg_hijk_lmno").unwrap();
    assert_eq!(results.matching_rules().count(), 1);

    let results = scanner.scan(b"abcdefg_hijk_lmn").unwrap();
    assert_eq!(results.matching_rules().count(), 0);

    let results = scanner.scan(b"abcdef_hijk_lmno").unwrap();
    assert_eq!(results.matching_rules().count(), 0);
}

#[test]
fn test_slow_rule_hang() {
    let rules = crate::compile(
        r#"
        rule test {
            strings:
                $zero_padding = /\x00{860,}/
            condition:
                $zero_padding
        }
        "#,
    )
    .unwrap();

    let mut scanner = Scanner::new(&rules);
    let data = vec![0u8; 2000];
    let results = scanner.scan(&data).unwrap();
    assert_eq!(results.matching_rules().count(), 1);
}

#[test]
fn zip_file_extraction_scan() {
    let rules = crate::compile(
        r#"
        rule malicious_payload_in_zip {
            strings:
                $a = "suspicious YARA payload"
            condition:
                $a
        }
        "#,
    )
    .unwrap();

    let mut scanner = Scanner::new(&rules);
    scanner.enable_extraction(true);

    let zip_data = [
        0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00, 0x33, 0x63,
        0xd0, 0x5c, 0xe7, 0xb0, 0x5a, 0x76, 0x35, 0x00, 0x00, 0x00, 0x36, 0x00,
        0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x73, 0x75, 0x73, 0x70, 0x69, 0x63,
        0x69, 0x6f, 0x75, 0x73, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
        0x2e, 0x65, 0x78, 0x65, 0x0b, 0xc9, 0xc8, 0x2c, 0x56, 0x00, 0xa2, 0x44,
        0x85, 0xe2, 0xd2, 0xe2, 0x82, 0xcc, 0xe4, 0xcc, 0xfc, 0xd2, 0x62, 0x85,
        0x48, 0xc7, 0x20, 0x47, 0x85, 0x82, 0xc4, 0xca, 0x9c, 0xfc, 0xc4, 0x14,
        0x85, 0xcc, 0xbc, 0xe2, 0xcc, 0x94, 0x54, 0xa0, 0x82, 0x28, 0xcf, 0x00,
        0x85, 0xc4, 0xa2, 0xe4, 0x8c, 0xcc, 0xb2, 0x54, 0x00, 0x50, 0x4b, 0x01,
        0x02, 0x14, 0x03, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00, 0x33, 0x63, 0xd0,
        0x5c, 0xe7, 0xb0, 0x5a, 0x76, 0x35, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00,
        0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x73, 0x75, 0x73, 0x70, 0x69,
        0x63, 0x69, 0x6f, 0x75, 0x73, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61,
        0x64, 0x2e, 0x65, 0x78, 0x65, 0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x44, 0x00, 0x00, 0x00, 0x69, 0x00, 0x00,
        0x00, 0x00, 0x00,
    ];

    let results = scanner
        .scan(&zip_data)
        .expect("scan should not fail");

    let matching_rules: Vec<_> = results.matching_rules().collect();
    assert_eq!(matching_rules.len(), 1);

    let matching_rule = &matching_rules[0];
    assert_eq!(matching_rule.identifier(), "malicious_payload_in_zip");
    assert_eq!(
        matching_rule.logical_path(),
        std::path::Path::new("suspicious_payload.exe")
    );

    let pattern = matching_rule.patterns().next().unwrap();
    assert_eq!(pattern.identifier(), "$a");

    let mut matches = pattern.matches();
    let match1 = matches.next().unwrap();
    assert_eq!(match1.data(), b"suspicious YARA payload".as_slice());
}
