use criterion::{criterion_group, criterion_main, Criterion};

macro_rules! gen_bench {
    ($name:ident, $samples:expr, $desc:literal, $rule:literal, $data:expr) => {
        fn $name(c: &mut Criterion) {
            let mut group = c.benchmark_group($desc);

            group.sample_size($samples);

            group.bench_function("yara", |b| {
                let rules = yara::Compiler::new()
                    .unwrap()
                    .add_rules_str($rule)
                    .unwrap()
                    .compile_rules()
                    .unwrap();

                let mut scanner = rules.scanner().unwrap();

                b.iter(|| {
                    let _ = scanner.scan_mem($data).unwrap();
                })
            });

            group.bench_function("yara-x", |b| {
                let rules = yara_x::compile($rule).unwrap();
                let mut scanner = yara_x::Scanner::new(&rules);

                b.iter(|| {
                    let _ = scanner.scan($data);
                });
            });
        }
    };
}

gen_bench!(
    bench_loop_1,
    50,
    "Simple loop",
    r#"rule test { condition: for any x in (0..1000000) : (false) }"#,
    &[]
);

gen_bench!(
    bench_loop_2,
    50,
    "Loop with pattern",
    r#"rule test { strings: $a = "foo" condition: for any x in (0..1000000) : ($a) }"#,
    &[]
);

gen_bench!(
    bench_loop_3,
    50,
    "Loop with uint8",
    r#"rule test { condition: for any x in (0..1000000) : (uint8(x) == 0xCC) }"#,
    &[]
);

gen_bench!(
    bench_simple_pattern,
    500,
    "Simple pattern",
    r#"rule test { strings: $a = "fabada" condition: $a }"#,
    "fabadafabafabadafabafabafafabadafabafabadafabafabafafabadafabafabadafabafabafa".as_bytes()
);

const JUMPS_DATA: &[u8; 1664] =
    include_bytes!("../src/tests/testdata/jumps.bin");

gen_bench!(
    bench_jumps,
    500,
    "Jumps",
    r#"rule test {
        strings:
            $a = { 00 00 00 00 [0-476] 00 00 00 00 [0-476] 00 00 00 00 [0-508] 00 00 00 00 }
        condition:
            $a
    }"#,
    JUMPS_DATA
);

criterion_group!(
    name = benches; 
    config = Criterion::default(); 
    targets = bench_jumps, /*bench_loop_1, bench_loop_2, bench_loop_3, bench_simple_pattern*/);

criterion_main!(benches);
