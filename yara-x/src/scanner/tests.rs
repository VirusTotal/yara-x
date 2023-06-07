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
    let results = scanner.scan(&[]);

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

    for matching_rules in Scanner::new(&rules).scan(b"foobar") {
        for pattern in matching_rules.patterns() {
            matches.extend(
                pattern.matches().map(|x| (pattern.identifier(), x.range)),
            )
        }
    }

    assert_eq!(matches, [("$a", 0..6), ("$b", 3..6)])
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

    for matching_rules in Scanner::new(&rules).scan(b"lhrrhrrhqqh") {
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

    assert_eq!(scanner.scan(b"").matching_rules().len(), 0);
    assert_eq!(scanner.scan(b"123").matching_rules().len(), 1);
    assert_eq!(scanner.scan(b"").matching_rules().len(), 0);
}

#[test]
fn variables_1() {
    let rules = crate::Compiler::new()
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
        .unwrap()
        .build();

    let mut scanner = Scanner::new(&rules);

    assert_eq!(scanner.scan(&[]).matching_rules().len(), 0);

    scanner.set_global("bool_var", true).unwrap();

    assert_eq!(scanner.scan(&[]).matching_rules().len(), 1);

    scanner.set_global("bool_var", false).unwrap();

    assert_eq!(scanner.scan(&[]).matching_rules().len(), 0);

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
    let rules = crate::Compiler::new()
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
        .unwrap()
        .build();

    let mut scanner = Scanner::new(&rules);
    assert_eq!(scanner.scan(&[]).matching_rules().len(), 0);

    scanner.set_global("some_int", 1).unwrap();
    assert_eq!(scanner.scan(&[]).matching_rules().len(), 1);

    scanner.set_global("some_int", 2).unwrap();
    assert_eq!(scanner.scan(&[]).matching_rules().len(), 0);
}

#[test]
fn global_rules() {
    let rules = crate::Compiler::new()
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
        .unwrap()
        .build();

    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(&[]);

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
