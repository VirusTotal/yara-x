//! Tests for sliding window scanning ([`crate::Scanner::sliding_window`]).
//!
//! The main test is a differential one: random rules are scanned over random
//! data with a sliding window, and the results are compared with a reference
//! implementation that cuts the data into the same windows and scans each of
//! them separately with a regular scanner. Both must report the same matching
//! rules, the same matching windows and the same pattern matches.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use pretty_assertions::assert_eq;

use crate::{Compiler, Rules, Scanner};

/// Small deterministic pseudo-random number generator (xorshift64*), so that
/// failures can be reproduced from the seed printed by the tests.
pub(super) struct Rng(u64);

impl Rng {
    pub(super) fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    pub(super) fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Returns a number in `lo..=hi`.
    pub(super) fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + (self.next() % (hi - lo + 1) as u64) as usize
    }

    /// Returns true with the given probability (in percent).
    pub(super) fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }

    pub(super) fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.range(0, items.len() - 1)]
    }
}

/// Number of iterations for differential tests. Can be overridden with the
/// `YRX_DIFF_ITERATIONS` environment variable for longer runs.
pub(super) fn iterations(default: usize) -> usize {
    std::env::var("YRX_DIFF_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Seed of the first iteration. Can be overridden with `YRX_DIFF_SEED` for
/// reproducing a failure.
pub(super) fn first_seed() -> u64 {
    std::env::var("YRX_DIFF_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Random data made of a few bytes, so that the generated patterns match
/// often and close to each other.
fn random_data(rng: &mut Rng) -> Vec<u8> {
    const ALPHABET: &[u8] = b"aabbAB\x00";
    let len = match rng.range(0, 9) {
        0 => rng.range(0, 8),
        1..=2 => rng.range(9, 120),
        _ => rng.range(121, 1500),
    };
    (0..len).map(|_| *rng.pick(ALPHABET)).collect()
}

/// Generates the patterns for a set of rules. All of them have a fixed
/// length: variable-length patterns can match differently when the data is
/// cut in pieces, which is a documented difference tested separately. Some
/// patterns may be identical, which makes the compiler share them between
/// rules.
fn random_patterns(rng: &mut Rng, count: usize) -> Vec<String> {
    // All the strings of length 2 to 4 over "ab", in random order.
    let mut pool: Vec<String> = (2..=4)
        .flat_map(|len| {
            (0..1_u32 << len).map(move |bits| {
                (0..len)
                    .map(|i| if bits & (1 << i) != 0 { 'b' } else { 'a' })
                    .collect::<String>()
            })
        })
        .collect();

    for i in (1..pool.len()).rev() {
        pool.swap(i, rng.range(0, i));
    }

    pool.into_iter()
        .take(count)
        .map(|s| {
            let hex = |s: &str| {
                s.bytes().map(|b| format!("{b:02X}")).collect::<Vec<_>>()
            };
            match rng.range(0, 9) {
                // Plain text, with some modifiers.
                0..=2 => format!("\"{s}\""),
                3 => format!("\"{s}\" nocase"),
                4 => format!("\"{s}\" wide"),
                5 => format!("\"{s}\" wide ascii"),
                6 => format!("\"{s}\" xor"),
                // Hex pattern, with a wildcard or an alternative in the
                // middle when the pattern is long enough.
                7 => {
                    let mut bytes = hex(&s);
                    if bytes.len() >= 3 {
                        let i = rng.range(1, bytes.len() - 2);
                        bytes[i] = if rng.chance(50) {
                            "??".to_string()
                        } else {
                            format!("( {} | 41 )", bytes[i])
                        };
                    }
                    format!("{{ {} }}", bytes.join(" "))
                }
                // Regular expression with a character class.
                _ => {
                    let mut chars: Vec<String> =
                        s.chars().map(|c| c.to_string()).collect();
                    let i = rng.range(0, chars.len() - 1);
                    chars[i] = "[ab]".to_string();
                    let flags = if rng.chance(30) { "i" } else { "" };
                    format!("/{}/{flags}", chars.concat())
                }
            }
        })
        .collect()
}

/// Generated rules.
struct GeneratedRules {
    /// Source code of the rules.
    src: String,
    /// The same rules, preceded by a rule (`force_search`) whose condition
    /// needs the pattern search. A regular scan searches the patterns only
    /// when some condition needs them, while in sliding window mode they are
    /// always searched. With this rule, which is evaluated first, the
    /// reference scans always search the patterns too. The rule never
    /// matches, as its pattern is not in the generated data.
    with_forced_search: String,
}

/// Generates random rules.
fn random_rules(rng: &mut Rng) -> GeneratedRules {
    let num_rules = rng.range(1, 5);
    let num_patterns: Vec<usize> =
        (0..num_rules).map(|_| rng.range(0, 4)).collect();
    let mut patterns =
        random_patterns(rng, num_patterns.iter().sum()).into_iter();

    let mut src = String::new();
    let mut names = Vec::new();

    if cfg!(feature = "math-module") {
        src.push_str("import \"math\"\n");
    }

    let header_len = src.len();
    let mut used_patterns: Vec<String> = Vec::new();

    for (i, n) in num_patterns.iter().enumerate() {
        let name = format!("r{i}");
        let idents: Vec<String> = (0..*n).map(|j| format!("p{j}")).collect();
        let mut used = BTreeSet::new();

        let condition = bool_expr(rng, &idents, &names, &mut used, 2);

        // Every pattern must be used. The ones that the condition doesn't
        // use are added with a sub-expression that is always false.
        let unused: Vec<String> = idents
            .iter()
            .filter(|ident| !used.contains(*ident))
            .map(|ident| format!("#{ident} == 100000"))
            .collect();

        let condition = if unused.is_empty() {
            condition
        } else {
            format!("({condition}) or {}", unused.join(" or "))
        };

        if rng.chance(15) {
            src.push_str("private ");
        }
        if rng.chance(8) {
            src.push_str("global ");
        }

        src.push_str(&format!("rule {name} {{\n"));
        if *n > 0 {
            src.push_str("  strings:\n");
            for ident in &idents {
                let pattern = patterns.next().unwrap();
                // Sometimes reuse a pattern from a previous rule, so that
                // the compiler shares it between both rules.
                let pattern = match used_patterns.is_empty() {
                    false if rng.chance(20) => {
                        rng.pick(&used_patterns).clone()
                    }
                    _ => pattern,
                };
                src.push_str(&format!("    ${ident} = {pattern}\n"));
                used_patterns.push(pattern);
            }
        }
        src.push_str(&format!("  condition:\n    {condition}\n}}\n"));
        names.push(name);
    }

    let mut with_forced_search = src.clone();
    with_forced_search.insert_str(
        header_len,
        "rule force_search { strings: $force = \"zzzz\" condition: $force }\n",
    );

    GeneratedRules { src, with_forced_search }
}

/// Generates a random boolean expression. `idents` are the identifiers of the
/// patterns in the current rule (without `$`), `rules` are the names of the
/// rules declared before this one, which can be referenced. The identifiers
/// of the patterns used are added to `used`.
fn bool_expr(
    rng: &mut Rng,
    idents: &[String],
    rules: &[String],
    used: &mut BTreeSet<String>,
    depth: usize,
) -> String {
    if depth > 0 && rng.chance(45) {
        let op = rng.range(0, 2);
        let a = bool_expr(rng, idents, rules, used, depth - 1);
        if op == 2 {
            return format!("not ({a})");
        }
        // Generated only when it is used, so that `used` doesn't contain
        // patterns that are not in the expression.
        let b = bool_expr(rng, idents, rules, used, depth - 1);
        return if op == 0 {
            format!("({a} and {b})")
        } else {
            format!("({a} or {b})")
        };
    }

    let quantifier = |rng: &mut Rng| {
        rng.pick(&["any", "all", "none", "1", "2", "50%", "100%"]).to_string()
    };

    loop {
        let choice = rng.range(0, 19);

        // Expressions that don't need patterns.
        match choice {
            0 => return format!("filesize < {}", rng.range(0, 700)),
            1 => return format!("filesize >= {}", rng.range(0, 700)),
            2 => return format!("uint8({}) == 0x61", rng.range(0, 10)),
            3 => return format!("uint16({}) == 0x6261", rng.range(0, 10)),
            4 if !rules.is_empty() => return rng.pick(rules).clone(),
            5 if cfg!(feature = "math-module") => {
                return format!(
                    "math.entropy(0, filesize) {} 1.0",
                    rng.pick(&["<", ">="])
                );
            }
            _ => {}
        }

        if idents.is_empty() {
            continue;
        }

        let x = rng.pick(idents).clone();

        // A set of patterns: `them` or a non-empty subset.
        let set = |rng: &mut Rng, used: &mut BTreeSet<String>| {
            if rng.chance(30) {
                used.extend(idents.iter().cloned());
                "them".to_string()
            } else {
                let subset: Vec<&String> =
                    idents.iter().filter(|_| rng.chance(60)).collect();
                let subset = if subset.is_empty() { vec![&x] } else { subset };
                used.extend(subset.iter().map(|s| (*s).clone()));
                format!(
                    "({})",
                    subset
                        .iter()
                        .map(|s| format!("${s}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        };

        let expr = match choice {
            7 => format!("${x}"),
            8 => format!("#{x} == {}", rng.range(0, 3)),
            9 => format!("#{x} >= {}", rng.range(1, 4)),
            10 => format!("${x} at {}", rng.range(0, 12)),
            11 => {
                let lo = rng.range(0, 40);
                format!("${x} in ({lo}..{})", lo + rng.range(0, 60))
            }
            12 => format!("@{x}[1] < {}", rng.range(0, 300)),
            13 => format!("!{x}[1] > {}", rng.range(1, 4)),
            14 => format!(
                "for any i in (1..#{x}) : ( @{x}[i] {} {} )",
                rng.pick(&["<", ">="]),
                rng.range(0, 300)
            ),
            15 => {
                let s = set(rng, used);
                return format!(
                    "for all of {s} : ( # {} {} )",
                    rng.pick(&["<", ">="]),
                    rng.range(0, 3)
                );
            }
            16 => {
                let (q, s) = (quantifier(rng), set(rng, used));
                return format!("{q} of {s}");
            }
            17 => {
                let (q, s) = (quantifier(rng), set(rng, used));
                let lo = rng.range(0, 40);
                return format!(
                    "{q} of {s} in ({lo}..{})",
                    lo + rng.range(0, 80)
                );
            }
            _ => {
                let (q, s) = (quantifier(rng), set(rng, used));
                return format!("{q} of {s} within {}", rng.range(0, 120));
            }
        };

        used.insert(x);
        return expr;
    }
}

/// What a scan reported for one rule: the windows where it matched, and for
/// each pattern the `(offset, length, xor key)` of its matches.
#[derive(Debug, PartialEq, Eq, Default)]
struct RuleOutcome {
    windows: Vec<(usize, usize)>,
    patterns: BTreeMap<String, BTreeSet<(usize, usize, Option<u8>)>>,
}

type Outcome = BTreeMap<String, RuleOutcome>;

/// Merges `window` into a list of sorted, non-overlapping ranges, as
/// documented for [`crate::Rule::matching_windows`].
fn merge_window(windows: &mut Vec<(usize, usize)>, window: &Range<usize>) {
    match windows.last_mut() {
        Some(last) if window.start <= last.1 => {
            last.1 = last.1.max(window.end)
        }
        _ => windows.push((window.start, window.end)),
    }
}

/// Scans `data` with a sliding window and returns the outcome. Also checks
/// that the reported matches point to the right data, and that the number of
/// matching and non-matching rules add up.
fn windowed_scan(
    rules: &Rules,
    data: &[u8],
    size: usize,
    overlap: usize,
) -> Outcome {
    let mut scanner = Scanner::new(rules);
    scanner.sliding_window(size, overlap);
    let results = scanner.scan(data).unwrap();

    assert_eq!(
        results.matching_rules().include_private(true).len()
            + results.non_matching_rules().include_private(true).len(),
        rules.iter().len()
    );

    let mut outcome = Outcome::new();

    for rule in results.matching_rules().include_private(true) {
        let mut rule_outcome = RuleOutcome {
            windows: rule
                .matching_windows()
                .iter()
                .map(|w| (w.start, w.end))
                .collect(),
            ..Default::default()
        };
        for pattern in rule.patterns().include_private(true) {
            let matches = rule_outcome
                .patterns
                .entry(pattern.identifier().to_string())
                .or_default();
            for m in pattern.matches() {
                assert_eq!(m.data(), &data[m.range()]);
                matches.insert((
                    m.range().start,
                    m.range().len(),
                    m.xor_key(),
                ));
            }
        }
        outcome.insert(rule.identifier().to_string(), rule_outcome);
    }

    for rule in results.non_matching_rules().include_private(true) {
        assert!(rule.matching_windows().is_empty());
    }

    outcome
}

/// Reference implementation: cuts `data` into windows and scans each one with
/// a regular scanner. A rule matches if it matched in some window; its
/// matches are those found in the windows where it matched.
///
/// `rules` must be compiled from [`GeneratedRules::with_forced_search`] when
/// the data doesn't fit in a single window, so that every window scan
/// searches the patterns, as the sliding window mode does.
fn reference_scan(
    rules: &Rules,
    data: &[u8],
    size: usize,
    overlap: usize,
) -> Outcome {
    let mut scanner = Scanner::new(rules);

    // Data that fits in a single window is scanned as a whole, and no
    // windows are reported.
    if data.len() <= size {
        let results = scanner.scan(data).unwrap();
        let mut outcome = Outcome::new();
        for rule in results.matching_rules().include_private(true) {
            let mut rule_outcome = RuleOutcome::default();
            for pattern in rule.patterns().include_private(true) {
                rule_outcome.patterns.insert(
                    pattern.identifier().to_string(),
                    pattern
                        .matches()
                        .map(|m| {
                            (m.range().start, m.range().len(), m.xor_key())
                        })
                        .collect(),
                );
            }
            outcome.insert(rule.identifier().to_string(), rule_outcome);
        }
        return outcome;
    }

    let step = size - overlap;
    let mut windows = Vec::new();
    let mut start = 0;
    loop {
        windows.push(start..(start + size).min(data.len()));
        if start + size >= data.len() {
            break;
        }
        start += step;
    }

    let mut outcome = Outcome::new();

    for window in windows {
        let results = scanner.scan(&data[window.clone()]).unwrap();
        for rule in results.matching_rules().include_private(true) {
            let rule_outcome =
                outcome.entry(rule.identifier().to_string()).or_default();
            merge_window(&mut rule_outcome.windows, &window);
            for pattern in rule.patterns().include_private(true) {
                let matches = rule_outcome
                    .patterns
                    .entry(pattern.identifier().to_string())
                    .or_default();
                for m in pattern.matches() {
                    matches.insert((
                        m.range().start + window.start,
                        m.range().len(),
                        m.xor_key(),
                    ));
                }
            }
        }
    }

    outcome
}

/// Compiles the rules, with or without condition optimizations.
fn compile(src: &str, optimize: bool) -> Rules {
    let mut compiler = Compiler::new();
    compiler.condition_optimization(optimize);
    compiler
        .add_source(src)
        .unwrap_or_else(|err| panic!("{err}\n\nrules:\n{src}"));
    compiler.build()
}

#[test]
fn sliding_window_differential() {
    let first = first_seed();
    for seed in first..first + iterations(150) as u64 {
        let mut rng = Rng::new(seed);
        let generated = random_rules(&mut rng);
        let src = &generated.src;
        let optimize = rng.chance(50);
        let rules = compile(src, optimize);
        let forced = compile(&generated.with_forced_search, optimize);

        // Several data buffers and window layouts for the same rules.
        for _ in 0..4 {
            let data = random_data(&mut rng);
            let size = match rng.range(0, 5) {
                0 => rng.range(1, 4),
                1 => data.len().max(1),
                2 => data.len() + 1,
                _ => rng.range(5, 400),
            };
            let overlap = match rng.range(0, 3) {
                0 => 0,
                1 => size - 1,
                _ => rng.range(0, size - 1),
            };

            if std::env::var("YRX_DIFF_DEBUG").is_ok() {
                eprintln!(
                    "seed {seed} size {size} overlap {overlap} data {:?}\n{src}",
                    bstr::BStr::new(&data)
                );
            }
            // When the data fits in one window it is scanned as a whole, as
            // in a regular scan, so the reference is a regular scan of the
            // same rules.
            let reference_rules =
                if data.len() <= size { &rules } else { &forced };
            let expected =
                reference_scan(reference_rules, &data, size, overlap);
            let actual = windowed_scan(&rules, &data, size, overlap);

            assert_eq!(
                actual,
                expected,
                "\nseed: {seed}, window size: {size}, overlap: {overlap}\n\
                 data ({} bytes): {:?}\n\nrules:\n{src}",
                data.len(),
                bstr::BStr::new(&data),
            );
        }
    }
}

/// Same rules and data scanned twice with the same scanner, with different
/// window layouts: the second scan must not see anything from the first one.
#[test]
fn sliding_window_differential_reused_scanner() {
    let first = first_seed();
    for seed in first..first + iterations(40) as u64 {
        let mut rng = Rng::new(seed.wrapping_add(1_000_000));
        let generated = random_rules(&mut rng);
        let src = &generated.src;
        let rules = compile(src, false);
        let mut scanner = Scanner::new(&rules);

        for _ in 0..6 {
            let data = random_data(&mut rng);
            let size = rng.range(1, 300);
            let overlap = rng.range(0, size - 1);
            scanner.sliding_window(size, overlap);

            let actual: BTreeSet<String> = scanner
                .scan(&data)
                .unwrap()
                .matching_rules()
                .include_private(true)
                .map(|r| r.identifier().to_string())
                .collect();

            let expected: BTreeSet<String> =
                reference_scan(&rules, &data, size, overlap)
                    .into_keys()
                    .collect();

            assert_eq!(
                actual, expected,
                "\nseed: {seed}, size: {size}, overlap: {overlap}\n{src}"
            );
        }
    }
}

/// Returns the identifiers of the matching rules.
fn matching(
    rules: &Rules,
    data: &[u8],
    window: Option<(usize, usize)>,
) -> Vec<String> {
    let mut scanner = Scanner::new(rules);
    if let Some((size, overlap)) = window {
        scanner.sliding_window(size, overlap);
    }
    scanner
        .scan(data)
        .unwrap()
        .matching_rules()
        .map(|r| r.identifier().to_string())
        .collect()
}

/// Converts ranges to `(start, end)` pairs, for comparing them in asserts.
fn pairs(ranges: &[Range<usize>]) -> Vec<(usize, usize)> {
    ranges.iter().map(|r| (r.start, r.end)).collect()
}

fn data_with(len: usize, plants: &[(usize, &[u8])]) -> Vec<u8> {
    let mut data = vec![0_u8; len];
    for (offset, bytes) in plants {
        data[*offset..*offset + bytes.len()].copy_from_slice(bytes);
    }
    data
}

#[test]
fn sliding_window_layout_edges() {
    let rules = crate::compile(
        r#"
        rule a { strings: $a = "a" condition: $a }
        rule ab { strings: $a = "ab" condition: $a }
        rule size { condition: filesize == 1 }
        "#,
    )
    .unwrap();

    // Single-byte windows: one-byte patterns match, longer ones never do.
    let data = b"xxabxx";
    assert_eq!(matching(&rules, data, Some((1, 0))), ["a", "size"]);

    // Window size equal to the data length: scanned as a whole.
    assert_eq!(matching(&rules, data, Some((6, 0))), ["a", "ab"]);

    // One byte more than the window: two windows, the last one is 1 byte.
    let data = b"xxxxxab";
    assert_eq!(matching(&rules, data, Some((6, 0))), ["a", "size"]);
    // With 1 byte of overlap, "ab" is in the second window.
    assert_eq!(matching(&rules, data, Some((6, 1))), ["a", "ab"]);

    // Maximum overlap (step of 1 byte).
    let data = data_with(50, &[(48, b"ab")]);
    assert_eq!(matching(&rules, &data, Some((2, 1))), ["a", "ab"]);

    // Empty data.
    assert!(matching(&rules, b"", Some((10, 5))).is_empty());

    // Windows larger than any data.
    assert_eq!(
        matching(&rules, b"ab", Some((usize::MAX, usize::MAX - 1))),
        ["a", "ab"]
    );
}

#[test]
fn sliding_window_changing_layout() {
    let rules = crate::compile(
        r#"rule test { strings: $a = "foo" $b = "bar" condition: $a and $b }"#,
    )
    .unwrap();

    let data = data_with(1000, &[(0, b"foo"), (500, b"bar")]);
    let mut scanner = Scanner::new(&rules);

    scanner.sliding_window(100, 10);
    assert_eq!(scanner.scan(&data).unwrap().matching_rules().len(), 0);

    scanner.sliding_window(600, 10);
    assert_eq!(scanner.scan(&data).unwrap().matching_rules().len(), 1);

    scanner.sliding_window(100, 10);
    assert_eq!(scanner.scan(&data).unwrap().matching_rules().len(), 0);
}

#[test]
fn sliding_window_negations() {
    // `not $a` and `none of them` are evaluated per window: they are true in
    // any window that doesn't contain the pattern. This is documented.
    let rules = crate::compile(
        r#"
        rule not_a { strings: $a = "foo" condition: not $a }
        rule none_of { strings: $a = "foo" condition: none of them }
        "#,
    )
    .unwrap();

    let data = data_with(1000, &[(0, b"foo")]);
    assert!(matching(&rules, &data, None).is_empty());
    assert_eq!(matching(&rules, &data, Some((100, 10))), ["not_a", "none_of"]);

    // With "foo" in every window, neither matches.
    let mut data = vec![0_u8; 1000];
    for offset in (0..990).step_by(50) {
        data[offset..offset + 3].copy_from_slice(b"foo");
    }
    assert!(matching(&rules, &data, Some((100, 10))).is_empty());
}

#[test]
fn sliding_window_rule_references() {
    // A rule that references another one sees whether that rule matched in
    // the same window.
    let rules = crate::compile(
        r#"
        rule a { strings: $a = "foo" condition: $a }
        rule b { strings: $b = "bar" condition: a and $b }
        "#,
    )
    .unwrap();

    let far = data_with(1000, &[(0, b"foo"), (900, b"bar")]);
    assert_eq!(matching(&rules, &far, None), ["a", "b"]);
    assert_eq!(matching(&rules, &far, Some((100, 10))), ["a"]);

    // The window starting at 450 contains both.
    let near = data_with(1000, &[(500, b"foo"), (520, b"bar")]);
    assert_eq!(matching(&rules, &near, Some((100, 10))), ["a", "b"]);
}

#[test]
fn sliding_window_global_rules_per_namespace() {
    let mut compiler = Compiler::new();
    compiler
        .new_namespace("one")
        .add_source(
            r#"
            global rule g { strings: $g = "key" condition: $g }
            rule r { strings: $a = "foo" condition: $a }
            "#,
        )
        .unwrap()
        .new_namespace("two")
        .add_source(r#"rule r { strings: $a = "foo" condition: $a }"#)
        .unwrap();
    let rules = compiler.build();

    // "key" and "foo" are in different windows: in namespace "one" the
    // global rule fails in the window where "foo" is.
    let data = data_with(1000, &[(0, b"key"), (900, b"foo")]);
    let mut scanner = Scanner::new(&rules);
    scanner.sliding_window(100, 10);
    let results = scanner.scan(&data).unwrap();
    let matching: Vec<_> = results
        .matching_rules()
        .map(|r| format!("{}:{}", r.namespace(), r.identifier()))
        .collect();
    assert_eq!(matching, ["one:g", "two:r"]);
}

#[test]
fn sliding_window_chained_patterns() {
    // Hex patterns with large jumps are split into chained sub-patterns. A
    // chain that crosses window boundaries is not visible in any window
    // that doesn't contain it completely.
    let rules = crate::compile(
        r#"rule test { strings: $a = { 61 62 63 [100-2000] 64 65 66 } condition: $a }"#,
    )
    .unwrap();

    let data = data_with(5000, &[(100, b"abc"), (700, b"def")]);
    assert_eq!(matching(&rules, &data, None), ["test"]);
    assert!(matching(&rules, &data, Some((500, 50))).is_empty());
    assert_eq!(matching(&rules, &data, Some((1000, 50))), ["test"]);

    let mut scanner = Scanner::new(&rules);
    scanner.sliding_window(1000, 50);
    let results = scanner.scan(&data).unwrap();
    let rule = results.matching_rules().next().unwrap();
    let m = rule.patterns().next().unwrap().matches().next().unwrap();
    assert_eq!(m.range(), 100..703);
}

#[test]
fn sliding_window_long_matches() {
    // A match longer than the window is never visible.
    let rules =
        crate::compile(r#"rule test { strings: $a = /a{50}/ condition: $a }"#)
            .unwrap();
    let data = vec![b'a'; 200];
    assert_eq!(matching(&rules, &data, None), ["test"]);
    assert!(matching(&rules, &data, Some((40, 10))).is_empty());
    assert_eq!(matching(&rules, &data, Some((60, 10))), ["test"]);
}

#[test]
fn sliding_window_variable_length_matches() {
    // Documented difference with scanning each window on its own: matches
    // are found once over the whole data, and a match that doesn't fit in a
    // window is not visible there, even if a shorter match would fit.
    let rules = crate::compile(
        r#"rule test { strings: $a = /fo+/ condition: $a and @a[1] == 0 }"#,
    )
    .unwrap();

    // "fooooo..." starting at 100, crossing the end of the window 0..110.
    let data = data_with(1000, &[(100, b"foooooooooooooooooooo")]);
    let mut scanner = Scanner::new(&rules);
    scanner.sliding_window(110, 10);
    let results = scanner.scan(&data).unwrap();
    // In the window starting at 100 the whole match is visible, at offset 0.
    assert_eq!(results.matching_rules().len(), 1);
    assert_eq!(
        pairs(results.matching_rules().next().unwrap().matching_windows()),
        [(100, 210)]
    );
}

#[test]
fn sliding_window_fullword() {
    // `fullword` looks at the bytes around the match in the whole data, even
    // at the start or end of a window. This is documented.
    let rules = crate::compile(
        r#"rule test { strings: $a = "foo" fullword condition: $a }"#,
    )
    .unwrap();

    // "xfoo" at 99: "foo" at 100 is preceded by "x", so it is not a full
    // word, even though in the window starting at 100 it is at offset 0.
    let mut data = data_with(1000, &[(99, b"xfoo")]);
    assert!(matching(&rules, &data, Some((100, 0))).is_empty());

    data[99] = b' ';
    assert_eq!(matching(&rules, &data, Some((100, 0))), ["test"]);
}

#[test]
fn sliding_window_match_details() {
    let rules = crate::compile(
        r#"rule test {
             strings:
               $a = "foo" xor
               $b = "bar" wide
             condition:
               $a and $b
           }"#,
    )
    .unwrap();

    // "foo" xored with 0x20 is "FOO".
    let data =
        data_with(10_000, &[(5000, b"FOO"), (5010, b"b\x00a\x00r\x00")]);
    let mut scanner = Scanner::new(&rules);
    scanner.sliding_window(1000, 100).match_context_size(4);
    let results = scanner.scan(&data).unwrap();
    let rule = results.matching_rules().next().unwrap();
    let mut patterns = rule.patterns();

    let a = patterns.next().unwrap().matches().next().unwrap();
    assert_eq!(a.range(), 5000..5003);
    assert_eq!(a.xor_key(), Some(0x20));
    assert_eq!(a.data(), b"FOO");
    let (with_context, range) = a.data_with_context();
    assert_eq!(&with_context[range], b"FOO");
    assert_eq!(with_context.len(), 3 + 8);

    let b = patterns.next().unwrap().matches().next().unwrap();
    assert_eq!(b.range(), 5010..5016);
    assert_eq!(b.data(), b"b\x00a\x00r\x00");
}

#[test]
fn sliding_window_timeout() {
    // A timeout while evaluating windows fails the scan, and the scanner
    // works normally afterwards.
    let rules = crate::compile(
        r#"
        rule slow {
          strings: $a = "foo"
          condition: $a and for all i in (0..10000000) : ( i >= 0 and uint8(i % 10) != 0x100 )
        }
        rule fast { strings: $b = "bar" condition: $b }
        "#,
    )
    .unwrap();

    let data = data_with(10_000, &[(0, b"foo"), (9000, b"bar")]);
    let mut scanner = Scanner::new(&rules);
    scanner
        .sliding_window(1000, 100)
        .set_timeout(std::time::Duration::from_secs(1));

    assert!(matches!(scanner.scan(&data), Err(crate::ScanError::Timeout)));

    let data = data_with(10_000, &[(9000, b"bar")]);
    let results = scanner.scan(&data).unwrap();
    let matching: Vec<_> =
        results.matching_rules().map(|r| r.identifier()).collect();
    assert_eq!(matching, ["fast"]);
    // "bar" at 9000 is in the windows starting at 8100 and 9000.
    assert_eq!(
        pairs(results.matching_rules().next().unwrap().matching_windows()),
        [(8100, 10_000)]
    );
}

#[test]
fn sliding_window_console_log() {
    // `console.log` is called once per window where the rule is evaluated.
    #[cfg(feature = "console-module")]
    {
        let rules = crate::compile(
            r#"
            import "console"
            rule test { condition: console.log("size: ", filesize) }
            "#,
        )
        .unwrap();

        let mut messages = Vec::new();
        let mut scanner = Scanner::new(&rules);
        scanner.sliding_window(1000, 0).console_log(|m| messages.push(m));
        scanner.scan(&vec![0_u8; 2500]).unwrap();
        drop(scanner);
        assert_eq!(messages, ["size: 1000", "size: 1000", "size: 500"]);
    }
}

#[test]
fn sliding_window_max_scan_size() {
    let rules = crate::compile(
        r#"rule test { strings: $a = "foo" $b = "bar" condition: $a and $b }"#,
    )
    .unwrap();

    // "bar" is beyond the maximum scan size.
    let data =
        data_with(10_000, &[(100, b"foo"), (150, b"bar"), (9500, b"bar")]);
    let path = std::env::temp_dir()
        .join(format!("yrx-sliding-window-{}.bin", std::process::id()));
    std::fs::write(&path, &data).unwrap();

    let mut scanner = Scanner::new(&rules);
    scanner.sliding_window(1000, 100).max_scan_size(5000);
    let results = scanner.scan_file(&path).unwrap();
    let rule = results.matching_rules().next().unwrap();
    assert_eq!(pairs(rule.matching_windows()), [(0, 1000)]);
    let offsets: Vec<_> = rule
        .patterns()
        .flat_map(|p| p.matches().map(|m| m.range().start).collect::<Vec<_>>())
        .collect();
    assert_eq!(offsets, [100, 150]);
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn sliding_window_memory_mapped_file() {
    // Files larger than 32MB are memory-mapped. The result must be the same
    // as scanning the same data in memory.
    let rules = crate::compile(
        r#"
        rule pair { strings: $a = "foo" $b = "bar" condition: $a and $b }
        rule head { condition: uint32(0) == 0x46464952 }
        "#,
    )
    .unwrap();

    let mut data = vec![0_u8; 40 * 1024 * 1024];
    data[0..3].copy_from_slice(b"foo");
    data[30_000_000..30_000_003].copy_from_slice(b"bar");
    data[35_000_000..35_000_003].copy_from_slice(b"foo");
    data[35_000_050..35_000_053].copy_from_slice(b"bar");
    // "RIFF" at the start of a window: windows start every 1MB - 64KB.
    let window_start = 20 * (1024 * 1024 - 64 * 1024);
    data[window_start..window_start + 4].copy_from_slice(b"RIFF");

    let path = std::env::temp_dir()
        .join(format!("yrx-sliding-window-mmap-{}.bin", std::process::id()));
    std::fs::write(&path, &data).unwrap();

    let collect =
        |results: crate::ScanResults| -> Vec<(String, Vec<Range<usize>>)> {
            results
                .matching_rules()
                .map(|r| {
                    (r.identifier().to_string(), r.matching_windows().to_vec())
                })
                .collect()
        };

    let mut scanner = Scanner::new(&rules);
    scanner.sliding_window(1024 * 1024, 64 * 1024);
    let from_file = collect(scanner.scan_file(&path).unwrap());
    let from_memory = collect(scanner.scan(&data).unwrap());
    std::fs::remove_file(&path).unwrap();

    assert_eq!(from_file, from_memory);
    assert_eq!(from_file.len(), 2);
    assert_eq!(
        pairs(&from_file[1].1),
        [(window_start, window_start + 1024 * 1024)]
    );
}

#[test]
fn sliding_window_serialized_rules() {
    // Rules that went through serialization behave the same.
    let rules = crate::compile(
        r#"
        rule pair { strings: $a = "foo" $b = "bar" condition: all of them within 100 }
        rule size { condition: filesize == 1000 }
        "#,
    )
    .unwrap();
    let rules = Rules::deserialize(rules.serialize().unwrap()).unwrap();

    let data =
        data_with(10_000, &[(0, b"foo"), (5000, b"foo"), (5050, b"bar")]);
    assert_eq!(matching(&rules, &data, Some((1000, 100))), ["pair", "size"]);
    assert_eq!(matching(&rules, &data, None), ["pair"]);
}

#[test]
fn sliding_window_modules() {
    // Modules parse the whole data once, and their functions that read the
    // data (like `math.entropy`) read from the window.
    #[cfg(all(feature = "math-module", feature = "pe-module"))]
    {
        let rules = crate::compile(
            r#"
            import "math"
            import "pe"
            rule low_entropy { condition: math.entropy(0, filesize) == 0.0 }
            rule not_pe { condition: not pe.is_pe }
            "#,
        )
        .unwrap();

        // Random-looking data except one window of zeros.
        let mut data: Vec<u8> =
            (0..10_000_u32).map(|i| (i * 7 + i / 3) as u8).collect();
        data[3600..4600].fill(0);

        assert_eq!(matching(&rules, &data, None), ["not_pe"]);
        let mut scanner = Scanner::new(&rules);
        scanner.sliding_window(1000, 100);
        let results = scanner.scan(&data).unwrap();
        let low = results.matching_rules().next().unwrap();
        assert_eq!(low.identifier(), "low_entropy");
        assert_eq!(pairs(low.matching_windows()), [(3600, 4600)]);
    }
}

#[test]
fn sliding_window_many_matches() {
    // Patterns with lots of matches, in many windows.
    let rules = crate::compile(
        r#"rule test { strings: $a = "a" $b = "b" condition: #a == 50 and #b == 50 }"#,
    )
    .unwrap();

    // "ab" every 2 bytes: every window of 100 bytes has 50 of each.
    let data: Vec<u8> = b"ab".iter().copied().cycle().take(100_000).collect();
    let mut scanner = Scanner::new(&rules);
    scanner.sliding_window(100, 0);
    let results = scanner.scan(&data).unwrap();
    let rule = results.matching_rules().next().unwrap();
    assert_eq!(pairs(rule.matching_windows()), [(0, 100_000)]);
    let num_matches: usize = rule.patterns().map(|p| p.matches().len()).sum();
    assert_eq!(num_matches, 100_000);
}

#[test]
fn sliding_window_anchored_patterns() {
    // `$a at 10` is searched at offset 10 of each window. In each window,
    // only the match at its own offset 10 is visible, so the matches
    // reported are the same as when scanning each window on its own.
    let rules = crate::compile(
        r#"rule test { strings: $a = "ab" condition: not ($a at 10) }"#,
    )
    .unwrap();

    // Windows of 73 bytes start every 31 bytes. "ab" at 258 is at offset 10
    // of the window starting at 248, and at offset 41 of the one at 217.
    let data = data_with(624, &[(258, b"ab")]);
    let mut scanner = Scanner::new(&rules);
    scanner.sliding_window(73, 42);
    let results = scanner.scan(&data).unwrap();
    let rule = results.matching_rules().next().unwrap();
    // The rule doesn't match in the window starting at 248 only, but the
    // windows before and after it overlap, so the range is not split.
    assert_eq!(pairs(rule.matching_windows()), [(0, 624)]);
    // The match at 258 is not reported: it is visible only in the window
    // starting at 248, where the rule didn't match.
    assert_eq!(rule.patterns().next().unwrap().matches().len(), 0);
}

#[test]
fn sliding_window_shared_patterns() {
    // Two rules with the same pattern share it in the compiled rules. Each
    // rule reports only the matches in the windows where it matched.
    let rules = crate::compile(
        r#"
        rule a { strings: $x = "foo" $a = "aaa" condition: $x and $a }
        rule b { strings: $x = "foo" $b = "bbb" condition: $x and $b }
        "#,
    )
    .unwrap();

    let data = data_with(
        10_000,
        &[(1000, b"foo"), (1010, b"aaa"), (8000, b"foo"), (8010, b"bbb")],
    );
    let mut scanner = Scanner::new(&rules);
    scanner.sliding_window(1000, 100);
    let results = scanner.scan(&data).unwrap();

    let offsets: Vec<(String, Vec<usize>)> = results
        .matching_rules()
        .map(|r| {
            let x = r.patterns().next().unwrap();
            (
                r.identifier().to_string(),
                x.matches().map(|m| m.range().start).collect(),
            )
        })
        .collect();

    assert_eq!(
        offsets,
        [("a".to_string(), vec![1000]), ("b".to_string(), vec![8000])]
    );
}
