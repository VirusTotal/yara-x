use criterion::{criterion_group, criterion_main, Criterion};

macro_rules! gen_bench {
    ($name:ident, $desc:literal, $rule:literal) => {
        fn $name(c: &mut Criterion) {
            let mut group = c.benchmark_group($desc);

            group.sample_size(50);

            group.bench_function("yara", |b| {
                let rules = yara::Compiler::new()
                    .unwrap()
                    .add_rules_str($rule)
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
                    .add_source($rule)
                    .unwrap()
                    .build()
                    .unwrap();

                let mut scanner = yara_x::Scanner::new(&rules);

                b.iter(|| {
                    scanner.scan(&[]);
                });
            });
        }
    };
}

gen_bench!(
    bench_loop_1,
    "Simple loop",
    r#"rule test { condition: for any x in (0..1000000) : (false) }"#
);

gen_bench!(
    bench_loop_2,
    "Loop with pattern",
    r#"rule test { strings: $a = "foo" condition: for any x in (0..1000000) : ($a) }"#
);

gen_bench!(
    bench_loop_3,
    "Loop with uint8",
    r#"rule test { condition: for any x in (0..1000000) : (uint8(x) == 0xCC) }"#
);

criterion_group!(
    name = benches; 
    config = Criterion::default(); 
    targets = bench_loop_1, bench_loop_2, bench_loop_3);

criterion_main!(benches);
