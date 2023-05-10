use crate::scanner::Scanner;

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

    assert_eq!(results.num_matching_rules(), 2);

    let mut iter = results.matching_rules();

    assert_eq!(iter.next().unwrap().name(), "rule_1");
    assert_eq!(iter.next().unwrap().name(), "rule_3");
    assert!(iter.next().is_none());

    let mut iter = results.non_matching_rules();

    assert_eq!(iter.next().unwrap().name(), "rule_2");
    assert_eq!(iter.next().unwrap().name(), "rule_4");
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

    assert_eq!(scanner.scan(b"").num_matching_rules(), 0);
    assert_eq!(scanner.scan(b"123").num_matching_rules(), 1);
    assert_eq!(scanner.scan(b"").num_matching_rules(), 0);
}
