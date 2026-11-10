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
    );

    let rules = crate::compile(
        b"rule test { meta: raw_nul = \"qu\0x\" condition: true }".as_slice(),
    )
    .unwrap();
    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(b"").expect("scan should not fail");
    let matching_rule = results.matching_rules().next().unwrap();
    let metas: Vec<_> = matching_rule.metadata().collect();

    assert_eq!(metas, [("raw_nul", MetaValue::Bytes(b"qu\0x".into()))]);
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
                $c = { aa bb cc } private
                $d = /fo.ba./ private
            condition:
                $a and $b and $c and $d
        }
        "#,
        )
        .unwrap();

    let rules = compiler.build();

    let mut scanner = Scanner::new(&rules);
    let scan_results =
        scanner.scan(b"foobar\xaa\xbb\xcc").expect("scan should not fail");

    assert_eq!(scan_results.matching_rules().len(), 1);

    let rule = scan_results.matching_rules().next().unwrap();

    let mut patterns = rule.patterns();
    assert_eq!(patterns.len(), 1);
    assert_eq!(patterns.next().unwrap().identifier(), "$b");
    assert_eq!(patterns.len(), 0);
    assert!(patterns.next().is_none());

    // Iterate all patterns, including private ones.
    let mut patterns = rule.patterns().include_private(true);
    assert_eq!(patterns.len(), 4);
    assert_eq!(patterns.next().unwrap().identifier(), "$a");
    assert_eq!(patterns.len(), 3);
    assert_eq!(patterns.next().unwrap().identifier(), "$b");
    assert_eq!(patterns.len(), 2);
    assert_eq!(patterns.next().unwrap().identifier(), "$c");
    assert_eq!(patterns.len(), 1);
    assert_eq!(patterns.next().unwrap().identifier(), "$d");
    assert_eq!(patterns.len(), 0);
    assert!(patterns.next().is_none());

    // Start iterating non-private patterns only...
    let mut patterns = rule.patterns();

    // There is only one, which is $b.
    assert_eq!(patterns.len(), 1);
    assert_eq!(patterns.next().unwrap().identifier(), "$b");
    assert_eq!(patterns.len(), 0);

    // Turn on private patterns after $b.
    let mut patterns = patterns.include_private(true);

    // Now we have $c and $d.
    assert_eq!(patterns.len(), 2);
    assert_eq!(patterns.next().unwrap().identifier(), "$c");

    // Turn off private patterns again after $c.
    let mut patterns = patterns.include_private(false);

    // No more patterns, $d is not returned because it is private.
    assert_eq!(patterns.len(), 0);
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
        rule test_eq_true {
            condition:
                test_proto2.string_foo == "bar" or
                test_proto2.string_foo == "foo"
        }
        rule test_eq_commuted_true {
            condition:
                "bar" == test_proto2.string_foo or
                "foo" == test_proto2.string_foo
        }
        rule test_eq_false_partial {
            condition:
                test_proto2.string_foo == "fo" or
                test_proto2.string_foo == "oo"
        }
        rule test_eq_false_case {
            condition:
                test_proto2.string_foo == "FOO" or
                test_proto2.string_foo == "BAR"
        }
        rule test_iequals_true {
            condition:
                test_proto2.string_foo iequals "BAR" or
                "FOO" iequals test_proto2.string_foo
        }
        rule test_iequals_false_partial {
            condition:
                test_proto2.string_foo iequals "FO" or
                test_proto2.string_foo iequals "OO"
        }
        rule test_contains_true {
            condition:
                test_proto2.string_foo contains "ba" or
                test_proto2.string_foo contains "oo"
        }
        rule test_contains_false {
            condition:
                test_proto2.string_foo contains "FO" or
                test_proto2.string_foo contains "BA"
        }
        rule test_icontains_true {
            condition:
                test_proto2.string_foo icontains "BA" or
                test_proto2.string_foo icontains "OO"
        }
        rule test_startswith_true {
            condition:
                test_proto2.string_foo startswith "ba" or
                test_proto2.string_foo startswith "fo"
        }
        rule test_startswith_false {
            condition:
                test_proto2.string_foo startswith "oo" or
                test_proto2.string_foo startswith "FO"
        }
        rule test_istartswith_true {
            condition:
                test_proto2.string_foo istartswith "BA" or
                test_proto2.string_foo istartswith "FO"
        }
        rule test_istartswith_false {
            condition:
                test_proto2.string_foo istartswith "OO" or
                test_proto2.string_foo istartswith "AR"
        }
        rule test_endswith_true {
            condition:
                test_proto2.string_foo endswith "ar" or
                test_proto2.string_foo endswith "oo"
        }
        rule test_endswith_false {
            condition:
                test_proto2.string_foo endswith "fo" or
                test_proto2.string_foo endswith "OO"
        }
        rule test_iendswith_true {
            condition:
                test_proto2.string_foo iendswith "AR" or
                test_proto2.string_foo iendswith "OO"
        }
        rule test_iendswith_false {
            condition:
                test_proto2.string_foo iendswith "FO" or
                test_proto2.string_foo iendswith "BA"
        }
        rule test_mixed_true {
            condition:
                test_proto2.string_foo == "nope" or
                test_proto2.string_foo startswith "ba" or
                test_proto2.string_foo matches /b.r/ or
                test_proto2.string_foo iendswith "OO"
        }
        rule test_special_chars_true {
            condition:
                test_proto2.head(10) == "other" or
                test_proto2.head(10) == "a+b/c\nd\x00\xff*"
        }
        rule test_special_chars_multiline_anchor_false {
            condition:
                test_proto2.head(10) == "a+b/c" or
                test_proto2.head(10) == "d\x00\xff*"
        }
        rule test_undef_false {
            condition:
                test_proto2.string_undef == "foo" or
                test_proto2.string_undef contains "bar"
        }
        "#,
    )
    .unwrap();

    let mut scanner = crate::Scanner::new(&rules);
    let results = scanner.scan(b"a+b/c\nd\x00\xff*").unwrap();

    let matching_rules: Vec<_> =
        results.matching_rules().map(|r| r.identifier().to_string()).collect();
    assert_eq!(
        matching_rules,
        vec![
            "test_match",
            "test_eq_true",
            "test_eq_commuted_true",
            "test_iequals_true",
            "test_contains_true",
            "test_icontains_true",
            "test_startswith_true",
            "test_istartswith_true",
            "test_endswith_true",
            "test_iendswith_true",
            "test_mixed_true",
            "test_special_chars_true",
        ]
    );
}

#[test]
fn fast_scan_mode() {
    let rules = crate::compile(
        r#"
    import "math"

    rule test_boolean {
      strings:
        $a = "foo"
        $b = "bar"
      condition:
        $a and $b
    }
    rule test_count_gt {
      strings:
        $c = "baz"
      condition:
        #c > 2
    }
    rule test_count_lt {
      strings:
        $d = "qux"
      condition:
        not (#d < 3)
    }
    rule test_count_eq {
      strings:
        $e = "zap"
      condition:
        #e != 2
    }
    rule test_for_of_count {
      strings:
        $f = "wim"
      condition:
        for any of ($f) : ( # >= 3 )
    }
    rule test_unbounded_offset {
      strings:
        $g = "nub"
      condition:
        @g[1] >= 0
    }
    rule test_shared_pattern_fast_scan {
      strings:
        $g = "nub"
      condition:
        $g
    }
    rule test_anchored_and_all_of_them {
      strings:
        $j = "$"
        $k = "foo"
      condition:
        all of them and $j at 0
    }
    "#,
    )
    .unwrap();

    let input = b"$foofoobarbarbazbazbazbazquxquxquxquxzapzapzapzapwimwimwimwimnubnubnubnubzenzenzenzenorborborborb$$$";

    // Test standard scan first (fast_scan = false by default)
    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(input).unwrap();

    let get_match_count =
        |results: &crate::ScanResults, rule_name: &str, pat_name: &str| {
            results
                .matching_rules()
                .find(|r| r.identifier() == rule_name)
                .unwrap()
                .patterns()
                .find(|p| p.identifier() == pat_name)
                .unwrap()
                .matches()
                .len()
        };

    assert_eq!(get_match_count(&results, "test_boolean", "$a"), 2);
    assert_eq!(get_match_count(&results, "test_count_gt", "$c"), 4);
    assert_eq!(get_match_count(&results, "test_count_lt", "$d"), 4);
    assert_eq!(get_match_count(&results, "test_count_eq", "$e"), 4);
    assert_eq!(get_match_count(&results, "test_for_of_count", "$f"), 4);
    assert_eq!(get_match_count(&results, "test_unbounded_offset", "$g"), 4);
    assert_eq!(
        get_match_count(&results, "test_shared_pattern_fast_scan", "$g"),
        4
    );
    // $j is anchored at 0 even when `all of them` is also present, so only the
    // match at offset 0 is checked and recorded.
    assert_eq!(
        get_match_count(&results, "test_anchored_and_all_of_them", "$j"),
        1
    );
    assert_eq!(
        get_match_count(&results, "test_anchored_and_all_of_them", "$k"),
        2
    );

    // Test fast scan mode (fast_scan = true)
    let mut scanner = Scanner::new(&rules);
    scanner.fast_scan(true);
    let results = scanner.scan(input).unwrap();

    // $a only needs 1 match
    assert_eq!(get_match_count(&results, "test_boolean", "$a"), 1);
    // #c > 2 stops after 2 + 1 = 3 matches (even though 4 exist in input)
    assert_eq!(get_match_count(&results, "test_count_gt", "$c"), 3);
    // #d < 3 stops after 3 matches (even though 4 exist in input)
    assert_eq!(get_match_count(&results, "test_count_lt", "$d"), 3);
    // #e != 2 stops after 2 + 1 = 3 matches (even though 4 exist in input)
    assert_eq!(get_match_count(&results, "test_count_eq", "$e"), 3);
    // for any of ($f) : ( # >= 3 ) stops after 3 matches
    assert_eq!(get_match_count(&results, "test_for_of_count", "$f"), 3);
    // @g[1] >= 0 disallows fast-scan, so all 4 matches are tracked
    assert_eq!(get_match_count(&results, "test_unbounded_offset", "$g"), 4);
    // In test_shared_pattern_fast_scan, $g only needs 1 match even though
    // test_unbounded_offset declares the same literal without fast-scan.
    assert_eq!(
        get_match_count(&results, "test_shared_pattern_fast_scan", "$g"),
        1
    );
    // $j is anchored at 0 and $k stops after 1 match in fast-scan mode
    assert_eq!(
        get_match_count(&results, "test_anchored_and_all_of_them", "$j"),
        1
    );
    assert_eq!(
        get_match_count(&results, "test_anchored_and_all_of_them", "$k"),
        1
    );
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
#[cfg(any(
    all(target_arch = "x86_64", target_feature = "sse2"),
    all(
        target_arch = "aarch64",
        target_feature = "neon",
        target_endian = "little"
    )
))]
fn test_teddy_scan_timeout() {
    use std::fmt::Write;
    use std::time::Duration;

    // Build a rule with 64 distinct literal patterns (the maximum number of
    // patterns supported by Teddy) that all share the 4-byte atom `"aaaa"`.
    // All 64 atoms hash to the same Teddy bucket, so scanning a buffer of `'a'`
    // bytes triggers 64 Teddy atom matches per byte while failing literal
    // verification on the trailing `\x00` bytes (which prevents the patterns
    // from reaching `max_matches_per_pattern` and being disabled).
    let mut rule = String::from("rule test { strings:\n");
    for i in 1..=64 {
        writeln!(rule, r#"$ = "aaaa{}""#, "\\x00".repeat(i)).unwrap();
    }
    rule.push_str("condition: any of them }");

    let rules = crate::compile(rule.as_str()).unwrap();

    assert_eq!(rules.atoms.len(), 64);
    assert!(rules.ac_automaton().teddy.is_some());

    let mut scanner = Scanner::new(&rules);
    scanner.set_timeout(Duration::from_secs(1));

    let data = vec![b'a'; 10_000_000];

    let err = scanner.scan(&data).unwrap_err();
    assert_eq!(err.to_string(), "timeout");
}

#[cfg(feature = "test_proto2-module")]
#[test]
fn runtime_string_from_large_slice() {
    let rules = crate::compile(
        r#"
        import "test_proto2"
        rule exact_u16_max {
            condition:
                test_proto2.head(65535) startswith "aaaa" and
                test_proto2.head(65535) endswith "aaaa"
        }
        rule larger_than_u16_max {
            condition:
                test_proto2.head(65536) startswith "aaaa" and
                test_proto2.head(65536) endswith "aaaa"
        }
        "#,
    )
    .unwrap();

    let data = vec![b'a'; 70_000];
    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(&data).unwrap();
    assert_eq!(results.matching_rules().len(), 2);
}

#[test]
fn anchored_pattern_large_offsets() {
    let rules = crate::compile(
        r#"
        rule r1 {
            strings:
                $a = "foobar"
            condition:
                $a at 0xffffffff
        }
        rule r2 {
            strings:
                $a = "foobar"
            condition:
                $a at 0x100000000
        }
        rule r3 {
            strings:
                $a = "foobar"
            condition:
                all of ($a) at 0x100000000
        }
        rule r4 {
            strings:
                $a = "foobar"
            condition:
                $a and $a at 0x100000000
        }
        "#,
    )
    .unwrap();

    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(b"foobar").unwrap();
    assert_eq!(results.matching_rules().len(), 0);
}

#[cfg(feature = "pe-module")]
#[test]
fn pe_section_index_overflow() {
    let rules = crate::compile(
        r#"
        import "pe"
        rule test {
            condition:
                pe.section_index(0xffffff80) == 0 and
                not defined pe.section_index(0x00000080)
        }
        "#,
    )
    .unwrap();

    let mut valid_pe = mods::PE::new();
    valid_pe.set_is_pe(true);
    let mut sec = mods::pe::Section::new();
    sec.set_name(b".text".to_vec());
    sec.set_full_name(b".text".to_vec());
    sec.set_characteristics(0);
    sec.set_raw_data_offset(0xffff_ff00);
    sec.set_raw_data_size(0x200);
    sec.set_virtual_address(0x1000);
    sec.set_virtual_size(0x200);
    sec.set_pointer_to_relocations(0);
    sec.set_pointer_to_line_numbers(0);
    sec.set_number_of_relocations(0);
    sec.set_number_of_line_numbers(0);
    valid_pe.sections.push(sec);

    let mut scanner = Scanner::new(&rules);
    scanner.set_module_output(Box::new(valid_pe)).unwrap();
    let results = scanner.scan(b"").unwrap();
    assert_eq!(results.matching_rules().len(), 1);
}

#[cfg(feature = "pe-module")]
#[test]
fn set_module_output_partial_pe() {
    let rules = crate::compile(
        r#"
        import "pe"
        rule test {
            condition:
                not defined pe.rva_to_offset(0x1000) and
                pe.offset_to_rva(0x200) == 0 and
                pe.imphash() == "d41d8cd98f00b204e9800998ecf8427e" and
                pe.rich_signature.toolid(1) == 0 and
                pe.rich_signature.version(1) == 0 and
                pe.rich_signature.toolid(1, 1) == 0
        }
        "#,
    )
    .unwrap();

    let mut scanner = Scanner::new(&rules);

    // Run a normal scan first so `pe::main` clears thread-local caches.
    let _ = scanner.scan(b"").unwrap();

    let mut pe_data = Box::new(mods::PE::new());
    pe_data.set_is_pe(true);
    pe_data.set_file_alignment(0x200);
    pe_data.set_section_alignment(0x1000);

    // Unpopulated section (`None` fields) and partial section missing
    // `virtual_address` / `virtual_size`.
    pe_data.sections.push(mods::pe::Section::new());
    let mut partial_sec = mods::pe::Section::new();
    partial_sec.set_raw_data_offset(0x200);
    partial_sec.set_raw_data_size(0x200);
    pe_data.sections.push(partial_sec);

    // Partial `Import` entries missing `library_name` or `func.name`.
    pe_data.import_details.push(mods::pe::Import::new());
    let mut imp = mods::pe::Import::new();
    imp.set_library_name("kernel32.dll".to_string());
    imp.functions.push(mods::pe::Function::new());
    pe_data.import_details.push(imp);

    // Partial `RichTool` entry missing `toolid` and `version`.
    let mut rich = mods::pe::RichSignature::new();
    rich.tools.push(mods::pe::RichTool::new());
    pe_data.rich_signature = protobuf::MessageField::some(rich);

    scanner.set_module_output(pe_data).unwrap();
    let results = scanner.scan(b"").unwrap();
    assert_eq!(results.matching_rules().len(), 1);

    // Also verify a wire-valid PE protobuf via `set_module_output_raw` where
    // optional `Function.name` is unset (`None`).
    let imphash_rules = crate::compile(
        r#"
        import "pe"
        rule test_imphash {
            condition:
                pe.imphash() == "d41d8cd98f00b204e9800998ecf8427e"
        }
        "#,
    )
    .unwrap();

    let mut valid_pe = mods::PE::new();
    valid_pe.set_is_pe(true);
    let mut func = mods::pe::Function::new();
    func.set_ordinal(1);
    func.set_rva(0x2000);
    let mut imp = mods::pe::Import::new();
    imp.set_library_name("kernel32.dll".to_string());
    imp.set_number_of_functions(1);
    imp.functions.push(func);
    valid_pe.import_details.push(imp);

    let raw = valid_pe.write_to_bytes().unwrap();
    let mut scanner = Scanner::new(&imphash_rules);
    let _ = scanner.scan(b"").unwrap();
    scanner.set_module_output_raw("pe", &raw).unwrap();
    assert_eq!(scanner.scan(b"").unwrap().matching_rules().len(), 1);
}

#[test]
fn hoisting_percentage_quantifier_var_shift() {
    let mut compiler = crate::Compiler::new();
    compiler
        .condition_optimization(true)
        .add_source(
            r#"
            import "math"
            rule test {
                condition:
                    for any i in (0..1) : (
                        i >= 0 and
                        with s = math.to_string(filesize) : (
                            for (math.to_number(s == "1") * 100)% j in (0..1) : (
                                int8(0) == 65 and j >= 0
                            )
                        )
                    )
            }
            "#,
        )
        .unwrap();

    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);
    assert_eq!(scanner.scan(b"A").unwrap().matching_rules().len(), 1);
    assert_eq!(scanner.scan(b"B").unwrap().matching_rules().len(), 0);
}

#[test]
fn loop_frame_allocation_order() {
    let rules = crate::compile(
        r#"
        import "math"
        rule tuple_with_inner_vars {
            condition:
                for all v in (
                    1,
                    math.to_number(with x = 2, y = 0 : ( x + y == 2 ))
                ) : (
                    v == 1
                )
        }
        rule for_of_quantifier_with_inner_vars {
            strings:
                $a = "abc"
            condition:
                for (math.to_number(with x = 1, y = 99 : ( x + y == 100 ))) of ($a) : ( $ )
        }
        rule of_quantifier_with_inner_vars {
            condition:
                (math.to_number(with x = 1, y = 99 : ( x + y == 100 ))) of (true, false)
        }
        "#,
    )
    .unwrap();

    let mut scanner = Scanner::new(&rules);
    assert_eq!(scanner.scan(b"abc").unwrap().matching_rules().len(), 3);

    // Also verify `IR::hoisting` when an outer `with` binds a module function
    // (`TypeValue::Func`, which reserves a frame slot without pushing to
    // `With::declarations`) alongside an inner `RuntimeString` variable.
    let mut compiler = crate::Compiler::new();
    compiler
        .condition_optimization(true)
        .add_source(
            r#"
            import "math"
            rule hoisting_with_func_alias {
                condition:
                    with f = math.abs : (
                        with s = math.to_string(filesize) : (
                            for any i in (0..1) : (
                                f(int8(0)) == 65 + i and s == "1"
                            )
                        )
                    )
            }
            "#,
        )
        .unwrap();

    let opt_rules = compiler.build();
    let mut opt_scanner = Scanner::new(&opt_rules);
    assert_eq!(opt_scanner.scan(b"A").unwrap().matching_rules().len(), 1);
    assert_eq!(opt_scanner.scan(b"C").unwrap().matching_rules().len(), 0);
}

#[test]
fn hoisting_in_for_in_iterable() {
    let mut compiler = crate::Compiler::new();
    compiler
        .condition_optimization(true)
        .add_source(
            r#"
            import "math"
            rule test {
                condition:
                    for any v in (
                        math.to_number(
                            for any i in (0..2) : (
                                math.to_string(filesize) == math.to_string(i)
                            )
                        ),
                        0
                    ) : (
                        v == 1
                    )
            }
            "#,
        )
        .unwrap();

    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);
    assert_eq!(scanner.scan(b"A").unwrap().matching_rules().len(), 1);
    assert_eq!(scanner.scan(b"ABCD").unwrap().matching_rules().len(), 0);
}

#[test]
fn hoisting_for_of_pattern_vars() {
    let mut compiler = crate::Compiler::new();
    compiler
        .condition_optimization(true)
        .add_source(
            r#"
            rule test {
                strings:
                    $a = "zzz"
                    $b = "abc"
                condition:
                    for any i in (0..1) : (
                        i == 0 and
                        for any of ($a, $b) : (
                            $ and # == 1 and @[1] == 0 and ![1] == 3
                        )
                    )
            }
            "#,
        )
        .unwrap();

    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);
    assert_eq!(scanner.scan(b"abc").unwrap().matching_rules().len(), 1);
    assert_eq!(scanner.scan(b"def").unwrap().matching_rules().len(), 0);
}

#[test]
fn hoisting_max_vars_and_candidate_limit() {
    // 1. Many loop-invariant expressions inside a single `for` loop (`None`
    // dependency branch in `find_hoisting_candidates`).
    let many_checks = (0..150)
        .map(|k| format!("uint8(0) + {k} == {}", 65 + k))
        .collect::<Vec<_>>()
        .join(" and ");
    let src_many = format!(
        "rule many_invariants {{ condition: for any i in (0..1) : ( i == 0 and {} ) }}",
        many_checks
    );

    let mut compiler = crate::Compiler::new();
    compiler
        .condition_optimization(true)
        .add_source(src_many.as_str())
        .unwrap();
    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);
    assert_eq!(scanner.scan(b"A").unwrap().matching_rules().len(), 1);
    assert_eq!(scanner.scan(b"B").unwrap().matching_rules().len(), 0);

    // 2. Outer `with` occupying `MAX_VARS - FOR_IN_FRAME_SIZE` (2048 - 7 = 2041)
    // slots so the inner `for` loop sits right at the `wasm::MAX_VARS` ceiling
    // with zero room to shift variables during hoisting.
    let num_with_vars = (crate::wasm::MAX_VARS - 7) as usize;
    let decls = (0..num_with_vars)
        .map(|k| format!("v{k} = {k}"))
        .collect::<Vec<_>>()
        .join(", ");
    let uses = (0..num_with_vars)
        .map(|k| format!("v{k}"))
        .collect::<Vec<_>>()
        .join(" + ");
    let expected_sum: usize = (0..num_with_vars).sum();
    let src_ceiling = format!(
        "rule at_max_vars {{ condition: with {decls} : ( ({uses}) == {expected_sum} and for any i in (0..1) : ( uint8(0) == 65 and i == 0 ) ) }}"
    );

    let mut compiler = crate::Compiler::new();
    compiler
        .condition_optimization(true)
        .add_source(src_ceiling.as_str())
        .unwrap();
    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);
    assert_eq!(scanner.scan(b"A").unwrap().matching_rules().len(), 1);
    assert_eq!(scanner.scan(b"B").unwrap().matching_rules().len(), 0);
}

#[test]
fn non_matching_private_rules() {
    // Regression test: the number of non-matching private rules was tracked
    // only for global rules (or with profiling), which made the length of
    // `non_matching_rules()` wrong and iterating it overflow.
    let rules = crate::compile(
        r#"
        private rule p1 { condition: filesize > 100 }
        private rule p2 { condition: filesize == 3 }
        private global rule pg { condition: filesize < 1000 }
        rule a { condition: filesize > 100 }
        rule b { condition: true }
        "#,
    )
    .unwrap();

    let mut scanner = Scanner::new(&rules);

    for (data, matching, non_matching) in [
        (&b"abc"[..], vec!["p2", "pg", "b"], vec!["p1", "a"]),
        (&[0_u8; 500][..], vec!["p1", "pg", "a", "b"], vec!["p2"]),
        (&[0_u8; 2000][..], vec![], vec!["p1", "p2", "pg", "a", "b"]),
    ] {
        let results = scanner.scan(data).unwrap();

        let m = results.matching_rules().include_private(true);
        assert_eq!(m.len(), matching.len());
        assert_eq!(m.map(|r| r.identifier()).collect::<Vec<_>>(), matching);

        let n = results.non_matching_rules().include_private(true);
        assert_eq!(n.len(), non_matching.len());
        assert_eq!(
            n.map(|r| r.identifier()).collect::<Vec<_>>(),
            non_matching
        );

        let public: Vec<_> =
            non_matching.iter().filter(|r| !r.starts_with('p')).collect();
        let n = results.non_matching_rules();
        assert_eq!(n.len(), public.len());
        assert_eq!(n.count(), public.len());
    }
}

#[cfg(feature = "pe-module")]
#[test]
fn hoisting_nested_field_access_after_lookup() {
    let mut compiler = crate::Compiler::new();
    compiler
        .condition_optimization(true)
        .add_source(
            r#"
            import "pe"
            rule match_version {
              condition:
                for any i in (0..pe.number_of_signatures) : (
                  pe.signatures[i].signer_info.chain[0].version == 1
                )
            }
            rule mismatch_version {
              condition:
                for any i in (0..pe.number_of_signatures) : (
                  pe.signatures[i].signer_info.chain[0].version == 2
                )
            }
            rule match_program_name_len {
              condition:
                for any i in (0..pe.number_of_signatures) : (
                  pe.signatures[i].signer_info.program_name.len() == 1
                )
            }
            rule mismatch_program_name_len {
              condition:
                for any i in (0..pe.number_of_signatures) : (
                  pe.signatures[i].signer_info.program_name.len() == 2
                )
            }
            "#,
        )
        .unwrap();

    let rules = compiler.build();

    let mut cert = mods::pe::Certificate::new();
    cert.set_version(1);

    let mut signer_info = mods::pe::SignerInfo::new();
    signer_info.set_program_name("a".to_string());
    signer_info.chain.push(cert);

    let mut sig = mods::pe::Signature::new();
    sig.signer_info = protobuf::MessageField::some(signer_info);

    let mut pe = Box::new(mods::PE::new());
    pe.set_is_pe(true);
    pe.set_number_of_signatures(1);
    pe.signatures.push(sig);

    let mut scanner = Scanner::new(&rules);
    scanner.set_module_output(pe).unwrap();
    let results = scanner.scan(b"").unwrap();

    assert_eq!(
        results.matching_rules().map(|r| r.identifier()).collect::<Vec<_>>(),
        vec!["match_version", "match_program_name_len"]
    );
}
