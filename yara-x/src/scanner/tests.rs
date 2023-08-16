use pretty_assertions::assert_eq;

use crate::scanner;
use crate::scanner::matches::Match;
use crate::scanner::Scanner;
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
    assert_eq!(iter.next().unwrap().name(), "rule_1");
    assert_eq!(iter.len(), 1);
    assert_eq!(iter.next().unwrap().name(), "rule_3");
    assert_eq!(iter.len(), 0);
    assert!(iter.next().is_none());

    let mut iter = results.non_matching_rules();

    assert_eq!(iter.len(), 2);
    assert_eq!(iter.next().unwrap().name(), "rule_2");
    assert_eq!(iter.len(), 1);
    assert_eq!(iter.next().unwrap().name(), "rule_4");
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

    for matching_rules in results.matching_rules() {
        for pattern in matching_rules.patterns() {
            matches.extend(
                pattern
                    .matches()
                    .map(|x| (pattern.identifier(), x.range, x.data)),
            )
        }
    }

    assert_eq!(
        matches,
        [("$a", 0..6, b"foobar".as_slice()), ("$b", 3..6, b"bar".as_slice())]
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

    for matching_rules in Scanner::new(&rules)
        .scan(b"lhrrhrrhqqh")
        .expect("scan should not fail")
        .matching_rules()
    {
        for pattern in matching_rules.patterns() {
            matches.extend(
                pattern
                    .matches()
                    .map(|x| (pattern.identifier(), x.range, x.xor_key)),
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
        scanner.set_global("undeclared", false).err().unwrap(),
        VariableError::Undeclared("undeclared".to_string())
    );
}

#[test]
fn variables_2() {
    let mut compiler = crate::Compiler::new();

    compiler
        .define_global("some_int", 0)
        .unwrap()
        .add_source(
            r#"
        rule test {
            condition:
                some_int == 1
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

    scanner.set_global("some_int", 1).unwrap();
    assert_eq!(
        scanner
            .scan(&[])
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        1
    );

    scanner.set_global("some_int", 2).unwrap();
    assert_eq!(
        scanner
            .scan(&[])
            .expect("scan should not fail")
            .matching_rules()
            .len(),
        0
    );
}

#[test]
fn global_rules() {
    let mut compiler = crate::Compiler::new();

    compiler
        .add_source(
            r#"
        // This global rule doesn't affect the results because it's true.
        global rule global_true {
            condition:
                true
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
    assert_eq!(matching.next().unwrap().name(), "matching");
    assert!(matching.next().is_none());

    let mut non_matching = results.non_matching_rules();

    // `global_true` and `non_matching` don't match because they are in the
    // namespace as `global_false`.
    assert_eq!(non_matching.next().unwrap().name(), "global_true");
    assert_eq!(non_matching.next().unwrap().name(), "non_matching");
    assert_eq!(non_matching.next().unwrap().name(), "global_false");

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

    // Only one match is returned for pattern $a because the limit has been set
    // to 1.
    assert_eq!(
        matches.next(),
        Some(scanner::Match { range: (0..3), data: b"foo", xor_key: None })
    );

    assert_eq!(matches.next(), None);
}
