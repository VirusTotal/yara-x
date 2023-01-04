use criterion::{criterion_group, criterion_main, Criterion};
use yara_x::{compiler, scanner};

fn bench_loop(c: &mut Criterion) {
    let mut group = c.benchmark_group("Loop");

    group.sample_size(50);

    group.bench_function("yara", |b| {
        let rules = yara::Compiler::new()
            .unwrap()
            .add_rules_str(
                r#"rule test { condition: for any x in (0..1000000) : (false) }"#,
            )
            .unwrap()
            .compile_rules()
            .unwrap();

        let mut scanner = rules.scanner().unwrap();

        b.iter(|| {
            scanner.scan_mem(&[]).unwrap();
        })
    });

    group.bench_function("yara-x", |b| {
        let rules = compiler::Compiler::new()
            .add_source(
                r#"rule test { condition: for any x in (0..1000000) : (false) }"#,
            )
            .unwrap()
            .build()
            .unwrap();

        let mut scanner = scanner::Scanner::new(&rules);

        b.iter(|| {
            scanner.scan(&[]);
        });
    });
}

criterion_group!(
    name = benches; 
    config = Criterion::default(); 
    targets = bench_loop);

criterion_main!(benches);
