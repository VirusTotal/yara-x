use std::fmt::Write;
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

/// Returns a rule set with `n` rules, each one with a text, hex and regexp
/// pattern.
fn rules_with_patterns(n: usize) -> String {
    let mut src = String::new();
    for i in 0..n {
        writeln!(
            src,
            "rule r{i} {{ strings: $a = \"text_{i}_pattern\" $b = {{ 68 78 {:02X} {:02X} ?? 00 }} $c = /re{i}_[0-9]+_abc/ condition: any of them }}",
            i % 256,
            (i / 256) % 256,
        )
        .unwrap();
    }
    src
}

/// Returns a rule set with `n` rules that call functions from the `pe`,
/// `math` and `hash` modules.
fn rules_with_modules(n: usize) -> String {
    let mut src =
        String::from("import \"pe\"\nimport \"math\"\nimport \"hash\"\n");
    for i in 0..n {
        writeln!(
            src,
            "rule m{i} {{ condition: pe.is_pe and pe.number_of_sections > {i} and math.entropy(0, filesize) > 7.0 and hash.md5(0, {i}) == \"d41d8cd98f00b204e9800998ecf8427e\" }}",
        )
        .unwrap();
    }
    src
}

fn bench_scanner_new(c: &mut Criterion) {
    let rule_sets = [
        ("1_rule", "rule r { condition: true }".to_string()),
        ("1k_rules", rules_with_patterns(1_000)),
        ("10k_rules", rules_with_patterns(10_000)),
        ("100_rules_with_modules", rules_with_modules(100)),
    ];

    let mut group = c.benchmark_group("scanner_new");

    for (name, src) in rule_sets {
        let rules = yara_x::compile(src.as_str()).unwrap();
        group.bench_function(name, |b| {
            b.iter(|| black_box(yara_x::Scanner::new(black_box(&rules))));
        });
    }

    group.finish();
}

criterion_group!(benches, bench_scanner_new);
criterion_main!(benches);
