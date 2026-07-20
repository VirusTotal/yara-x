use criterion::{Criterion, black_box, criterion_group, criterion_main};

mod commons;

use commons::create_binary_from_zipped_ihex;

fn bench_pe(c: &mut Criterion) {
    let data = create_binary_from_zipped_ihex(
        "src/modules/pe/tests/testdata/c704cca0fe4c9bdee18a302952540073b860e3b4d42e081f86d27bdb1cf6ede4.in.zip",
    );

    let mut group = c.benchmark_group("pe");

    group.bench_function("parse", |b| {
        b.iter(|| {
            let _ = black_box(yara_x::mods::invoke::<yara_x::mods::PE>(
                black_box(&data),
            ));
        });
    });

    group.finish();
}

criterion_group!(benches, bench_pe);
criterion_main!(benches);
