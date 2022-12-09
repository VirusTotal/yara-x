use criterion::{criterion_group, criterion_main, Criterion};
use yara_x::{compiler, scanner};

fn bench_compiler(c: &mut Criterion) {
    c.bench_function("compiler", |b| {
        b.iter(|| {
            let rules = compiler::Compiler::new()
                .add_source(
                    r#"
import "test_proto2"
rule test {
      condition: test_proto2.nested.nested_int32_one == 1
}
"#,
                )
                .unwrap()
                .build()
                .unwrap();

            let mut scanner = scanner::Scanner::new(&rules);
            scanner.scan(&[]);
        });
    });
}

criterion_group!(benches, bench_compiler);
criterion_main!(benches);
