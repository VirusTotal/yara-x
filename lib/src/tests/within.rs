//! Tests for the `within` operator (`<quantifier> of <patterns> within <n>`).
//!
//! The main test is a differential one: random pattern sets, quantifiers and
//! distances are evaluated over random data, and the result is compared with
//! a brute-force implementation that finds every occurrence of every pattern
//! with a naive search and checks every possible group of matches.

use pretty_assertions::assert_eq;

use super::sliding_window::{Rng, first_seed, iterations};
use crate::{Compiler, Rules, Scanner};

/// Starting offsets of every occurrence of `pattern` in `data`, including
/// overlapping ones.
fn occurrences(data: &[u8], pattern: &[u8], nocase: bool) -> Vec<usize> {
    if pattern.len() > data.len() {
        return vec![];
    }
    (0..=data.len() - pattern.len())
        .filter(|&i| {
            let window = &data[i..i + pattern.len()];
            if nocase {
                window.eq_ignore_ascii_case(pattern)
            } else {
                window == pattern
            }
        })
        .collect()
}

/// Brute-force evaluation of `<required> of <members> within <distance>`:
/// true if, starting at the offset of some match, the `distance` bytes that
/// follow contain matches of at least `required` different members.
fn brute_force(
    members: &[Vec<usize>],
    required: usize,
    distance: usize,
) -> bool {
    let with_matches = members.iter().filter(|m| !m.is_empty()).count();
    if required == 0 {
        // Documented: zero means that none of the patterns match.
        return with_matches == 0;
    }
    if required > members.len() || with_matches < required {
        return false;
    }
    members.iter().flatten().any(|&start| {
        members
            .iter()
            .filter(|offsets| {
                offsets.iter().any(|&o| o >= start && o - start <= distance)
            })
            .count()
            >= required
    })
}

#[test]
fn within_differential() {
    const ALPHABET: &[u8] = b"abAB";
    let first = first_seed();

    for seed in first..first + iterations(300) as u64 {
        let mut rng = Rng::new(seed.wrapping_add(7_000_000));

        // Patterns: short strings over "ab", some repeated on purpose (two
        // identical patterns share the same ID in the compiled rules, but
        // each one is a different member of the set).
        let num_patterns = rng.range(1, 6);
        let patterns: Vec<(Vec<u8>, bool)> = (0..num_patterns)
            .map(|_| {
                let len = rng.range(1, 4);
                let text: Vec<u8> =
                    (0..len).map(|_| *rng.pick(b"ab")).collect();
                (text, rng.chance(25))
            })
            .collect();

        let data: Vec<u8> =
            (0..rng.range(0, 400)).map(|_| *rng.pick(ALPHABET)).collect();

        let (quantifier, required) = match rng.range(0, 5) {
            0 => ("any".to_string(), 1),
            1 => ("all".to_string(), num_patterns),
            2 => {
                let n = rng.range(0, num_patterns + 1);
                (n.to_string(), n)
            }
            3 => {
                let p = rng.range(0, 100);
                (
                    format!("{p}%"),
                    (num_patterns as f64 * p as f64 / 100.0).ceil() as usize,
                )
            }
            _ => ("none".to_string(), usize::MAX),
        };

        let distance = match rng.range(0, 4) {
            0 => 0,
            1 => rng.range(1, 5),
            _ => rng.range(0, 200),
        };

        let members: Vec<Vec<usize>> = patterns
            .iter()
            .map(|(text, nocase)| occurrences(&data, text, *nocase))
            .collect();

        let expected = if quantifier == "none" {
            !brute_force(&members, 1, distance)
        } else {
            brute_force(&members, required, distance)
        };

        let strings: String = patterns
            .iter()
            .enumerate()
            .map(|(i, (text, nocase))| {
                format!(
                    "$p{i} = \"{}\"{} ",
                    String::from_utf8_lossy(text),
                    if *nocase { " nocase" } else { "" }
                )
            })
            .collect();

        let src = format!(
            "rule test {{ strings: {strings} condition: {quantifier} of them within {distance} }}"
        );

        for optimize in [false, true] {
            let mut compiler = Compiler::new();
            compiler
                .condition_optimization(optimize)
                .add_source(src.as_str())
                .unwrap();
            let rules = compiler.build();
            let actual = Scanner::new(&rules)
                .scan(&data)
                .unwrap()
                .matching_rules()
                .len()
                == 1;

            assert_eq!(
                actual,
                expected,
                "\nseed: {seed}, optimize: {optimize}\nrule: {src}\ndata: {:?}\nmatches: {members:?}",
                bstr::BStr::new(&data),
            );
        }
    }
}

fn matches(rules: &Rules, data: &[u8]) -> bool {
    Scanner::new(rules).scan(data).unwrap().matching_rules().len() == 1
}

fn compile(src: &str) -> Rules {
    crate::compile(src).unwrap_or_else(|err| panic!("{err}"))
}

fn data_with(len: usize, plants: &[(usize, &[u8])]) -> Vec<u8> {
    let mut data = vec![0_u8; len];
    for (offset, bytes) in plants {
        data[*offset..*offset + bytes.len()].copy_from_slice(bytes);
    }
    data
}

#[test]
fn within_overlapping_matches() {
    // Matches of different patterns that start at the same offset are at
    // distance 0, overlapping matches are at the distance between their
    // starting offsets.
    let rule = |condition: &str| {
        compile(&format!(
            r#"rule test {{ strings: $a = "foo" $b = "foobar" $c = "bar" condition: {condition} }}"#
        ))
    };
    assert!(matches(&rule("all of ($a, $b) within 0 and $c"), b"xxfoobarxx"));
    assert!(matches(&rule("all of them within 3"), b"xxfoobarxx"));
    assert!(!matches(&rule("all of them within 2"), b"xxfoobarxx"));
    assert!(!matches(
        &rule("all of ($a, $b) within 0 and #c >= 0"),
        b"xxfoo xxfobar"
    ));
}

#[test]
fn within_distance_limits() {
    let rules = compile(
        r#"rule test { strings: $a = "foo" $b = "bar" condition: all of them within 0x7FFFFFFFFFFFFFFF }"#,
    );
    assert!(matches(
        &rules,
        &data_with(100_000, &[(0, b"foo"), (99_990, b"bar")])
    ));

    // Distances out of range or negative are compile-time errors.
    let err = crate::compile(
        r#"rule test { strings: $a = "foo" $b = "bar" condition: all of them within 0x8000000000000000 }"#,
    );
    assert!(err.is_err());

    let err = crate::compile(
        r#"rule test { strings: $a = "foo" $b = "bar" condition: all of them within -1 }"#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("negative"), "{err}");

    // Size suffixes.
    let rules = compile(
        r#"rule test { strings: $a = "foo" $b = "bar" condition: all of them within 1KB }"#,
    );
    assert!(matches(&rules, &data_with(5000, &[(0, b"foo"), (1024, b"bar")])));
    assert!(!matches(
        &rules,
        &data_with(5000, &[(0, b"foo"), (1025, b"bar")])
    ));
}

#[test]
fn within_quantifiers() {
    let src = |q: &str| {
        format!(
            r#"rule test {{ strings: $a = "foo" $b = "bar" $c = "baz" condition: {q} of them within 10 }}"#
        )
    };
    let data = data_with(1000, &[(0, b"foo"), (5, b"bar"), (500, b"baz")]);

    assert!(!matches(&compile(&src("4")), &data));
    assert!(!matches(&compile(&src("3")), &data));
    assert!(matches(&compile(&src("2")), &data));
    assert!(!matches(&compile(&src("100%")), &data));
    // 67% of 3 rounds up to 3.
    assert!(!matches(&compile(&src("67%")), &data));
    assert!(matches(&compile(&src("66%")), &data));
    assert!(!matches(&compile(&src("0%")), &data));
    assert!(matches(&compile(&src("0%")), b""));

    // Percentages above 100 are rejected, like in other `of` expressions.
    assert!(crate::compile(src("101%").as_str()).is_err());
}

#[test]
fn within_pattern_modifiers() {
    let rules = compile(
        r#"rule test {
             strings:
               $a = "foo" wide
               $b = "bar" xor
               $c = "baz" nocase
               $d = "qux" base64
               $e = { 61 ?? 63 }
               $f = /de+f/
             condition:
               all of them within 100
           }"#,
    );
    // "qux" in base64 is "cXV4".
    let data = data_with(
        1000,
        &[
            (500, b"f\x00o\x00o\x00"),
            (510, b"BAR"),
            (520, b"BaZ"),
            (530, b"cXV4"),
            (540, b"axc"),
            (550, b"deeeeef"),
        ],
    );
    assert!(matches(&rules, &data));

    // Moving one of them away breaks the group.
    let mut far = data.clone();
    far[550..557].fill(0);
    far[900..907].copy_from_slice(b"deeeeef");
    assert!(!matches(&rules, &far));
}

#[test]
fn within_pattern_sets() {
    let rules = compile(
        r#"rule test {
             strings:
               $a1 = "foo"
               $a2 = "bar"
               $b = "baz"
               $ = "anon"
               $private = "qux" private
             condition:
               all of ($a*) within 10 and
               2 of ($b, $private, $) within 10
           }"#,
    );
    assert!(matches(&rules, b"foo bar ... anon qux"));
    assert!(!matches(&rules, b"foo bar ... anon ......... qux"));
}

#[test]
fn within_in_other_expressions() {
    let data = data_with(1000, &[(0, b"foo"), (50, b"bar")]);
    let rule = |condition: &str| {
        compile(&format!(
            r#"rule test {{ strings: $a = "foo" $b = "bar" condition: {condition} }}"#
        ))
    };

    // Under `not`.
    assert!(matches(&rule("not (all of them within 10)"), &data));
    // The distance can use loop variables.
    assert!(matches(
        &rule("for any i in (1..10) : ( all of them within i * 10 )"),
        &data
    ));
    assert!(!matches(
        &rule("for any i in (1..4) : ( all of them within i * 10 )"),
        &data
    ));
    // In a `with` statement.
    assert!(matches(
        &rule("with d = 25 * 2 : ( all of them within d )"),
        &data
    ));
    // Inside a tuple of boolean expressions.
    assert!(matches(&rule("all of (all of them within 50, $a, true)"), &data));
    assert!(!matches(&rule("any of (all of them within 49, false)"), &data));
    // An undefined distance makes the expression undefined (false).
    assert!(!matches(&rule("all of them within uint8(100000)"), &data));
    assert!(matches(
        &rule("not defined (all of them within uint8(100000))"),
        &data
    ));

    // In a global rule, and referenced from other rules.
    let rules = compile(
        r#"
        global rule g { strings: $a = "foo" $b = "bar" condition: all of them within 100 }
        rule r { condition: g }
        "#,
    );
    let results_len = |data: &[u8]| {
        Scanner::new(&rules).scan(data).unwrap().matching_rules().len()
    };
    assert_eq!(results_len(&data), 2);
    assert_eq!(
        results_len(&data_with(1000, &[(0, b"foo"), (500, b"bar")])),
        0
    );
}

#[test]
fn within_with_condition_optimization() {
    // Hoisting moves loop-invariant expressions out of loops. `within`
    // expressions must give the same results.
    let src = r#"rule test {
         strings:
           $a = "foo"
           $b = "bar"
         condition:
           for any i in (0..2) : (
             all of them within 50 and i >= 0 and (all of them within 49 or i == 1)
           )
       }"#;
    let data = data_with(1000, &[(0, b"foo"), (50, b"bar")]);
    for optimize in [false, true] {
        let mut compiler = Compiler::new();
        compiler.condition_optimization(optimize).add_source(src).unwrap();
        let rules = compiler.build();
        assert!(matches(&rules, &data), "optimize: {optimize}");
    }
}

#[test]
fn within_max_matches_per_pattern() {
    // Documented: matches beyond the limit are not seen by `within`.
    let rules = compile(
        r#"rule test { strings: $a = "a" $b = "b" condition: all of them within 1 }"#,
    );
    let mut data = vec![b'a'; 100];
    data[99] = b'b';
    let mut scanner = Scanner::new(&rules);
    assert_eq!(scanner.scan(&data).unwrap().matching_rules().len(), 1);
    scanner.max_matches_per_pattern(10);
    assert_eq!(scanner.scan(&data).unwrap().matching_rules().len(), 0);
}

#[test]
fn within_many_patterns() {
    // 200 patterns that must all be within 4KB of each other. They are 12
    // bytes apart, so the group spans 199 * 12 = 2388 bytes.
    let strings: String =
        (0..200).map(|i| format!("$s{i} = \"pattern_{i:03}\" ")).collect();
    let rules = compile(&format!(
        "rule test {{ strings: {strings} condition: all of them within 4KB }}"
    ));

    let mut data = vec![0_u8; 100_000];
    for i in 0..200 {
        let text = format!("pattern_{i:03}");
        data[50_000 + i * 12..50_000 + i * 12 + 11]
            .copy_from_slice(text.as_bytes());
    }
    assert!(matches(&rules, &data));

    // Move the last one to 6000 bytes after the first one.
    data[50_000 + 199 * 12..50_000 + 199 * 12 + 11].fill(0);
    data[56_000..56_011].copy_from_slice(b"pattern_199");
    assert!(!matches(&rules, &data));
}

#[test]
fn within_is_a_keyword() {
    // Breaking change: `within` can't be used as an identifier anymore.
    for src in [
        "rule within { condition: true }",
        "rule test { condition: within }",
        "rule test { condition: for any within in (1..2) : ( true ) }",
    ] {
        assert!(crate::compile(src).is_err(), "{src}");
    }

    // An external variable named `within` can be defined, but not used.
    let mut compiler = Compiler::new();
    compiler.define_global("within", true).unwrap();
    assert!(compiler.add_source("rule test { condition: within }").is_err());

    // But it can be part of identifiers, and of pattern identifiers.
    compile(
        r#"
        rule within_x { strings: $within = "foo" condition: $within }
        rule x_within { condition: within_x }
        "#,
    );
}

#[test]
fn within_serialized_rules() {
    // The pattern sets used by `within` must survive serialization.
    let rules = compile(
        r#"
        rule one { strings: $a = "foo" $b = "bar" condition: all of them within 10 }
        rule two { strings: $a = "foo" $b = "baz" $c = "qux" condition: 2 of ($b, $c) within 10 and $a }
        "#,
    );
    let rules = Rules::deserialize(rules.serialize().unwrap()).unwrap();

    let data = data_with(
        1000,
        &[(0, b"foo"), (5, b"bar"), (500, b"baz"), (505, b"qux")],
    );
    let results =
        Scanner::new(&rules).scan(&data).unwrap().matching_rules().len();
    assert_eq!(results, 2);

    let data = data_with(
        1000,
        &[(0, b"foo"), (50, b"bar"), (500, b"baz"), (600, b"qux")],
    );
    let results =
        Scanner::new(&rules).scan(&data).unwrap().matching_rules().len();
    assert_eq!(results, 0);
}

#[test]
fn within_parsing() {
    let data = data_with(1000, &[(0, b"foo"), (10, b"bar")]);
    let rule = |condition: &str| {
        crate::compile(
            format!(
                r#"rule test {{ strings: $a = "foo" $b = "bar" condition: {condition} }}"#
            )
            .as_str(),
        )
    };

    // The distance is an arithmetic expression, `and`/`or` end it.
    for (condition, expected) in [
        ("all of them within 2 * 5", true),
        ("all of them within 2 * 4", false),
        ("all of them within -5 + 15", true),
        ("all of them within (10)", true),
        ("all of them within filesize - 990", true),
        ("all of them within filesize - 991", false),
        ("all of them within 10 and $a", true),
        ("all of them within 9 or $a", true),
        ("all of them within 9 and $a", false),
    ] {
        let rules =
            rule(condition).unwrap_or_else(|err| panic!("{condition}: {err}"));
        assert_eq!(matches(&rules, &data), expected, "{condition}");
    }

    // Like `at` and `in`, `within` can't be combined with another anchor,
    // and the `of` expression can't be compared.
    for condition in [
        "all of them at 0 within 10",
        "all of them within 10 at 0",
        "all of them in (0..10) within 10",
        "all of them within 10 == 10",
        "all of them within",
    ] {
        assert!(rule(condition).is_err(), "{condition}");
    }
}
