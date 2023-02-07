use criterion::{criterion_group, criterion_main, Criterion};
use yara_x;

fn bench_loop(c: &mut Criterion) {
    let mut group = c.benchmark_group("Loop");

    group.sample_size(50);

    let src =
        r#"rule test { condition: for any x in (0..1000000) : (false) }"#;

    group.bench_function("yara", |b| {
        let rules = yara::Compiler::new()
            .unwrap()
            .add_rules_str(src)
            .unwrap()
            .compile_rules()
            .unwrap();

        let mut scanner = rules.scanner().unwrap();

        b.iter(|| {
            scanner.scan_mem(&[]).unwrap();
        })
    });

    group.bench_function("yara-x", |b| {
        let rules = yara_x::Compiler::new()
            .add_source(src)
            .unwrap()
            .build()
            .unwrap();

        let mut scanner = yara_x::Scanner::new(&rules);

        b.iter(|| {
            scanner.scan(&[]);
        });
    });
}

fn bench_pattern(c: &mut Criterion) {
    let mut group = c.benchmark_group("Pattern");

    group.sample_size(100);

    let src = r#"rule test { strings: $a = "foo" condition: for any x in (0..1000000) : ($a) }"#;

    group.bench_function("yara", |b| {
        let rules = yara::Compiler::new()
            .unwrap()
            .add_rules_str(src)
            .unwrap()
            .compile_rules()
            .unwrap();

        let mut scanner = rules.scanner().unwrap();

        b.iter(|| {
            scanner.scan_mem(&[]).unwrap();
        })
    });

    group.bench_function("yara-x", |b| {
        let rules = yara_x::Compiler::new()
            .add_source(src)
            .unwrap()
            .build()
            .unwrap();

        let mut scanner = yara_x::Scanner::new(&rules);

        b.iter(|| {
            scanner.scan(&[]);
        });
    });
}

criterion_group!(
    name = benches; 
    config = Criterion::default(); 
    targets = bench_loop, bench_pattern);

criterion_main!(benches);
