use criterion::{black_box, criterion_group, criterion_main, Criterion};

mod commons;

use commons::create_binary_from_zipped_ihex;

fn bench_dex(c: &mut Criterion) {
    let data = create_binary_from_zipped_ihex(
        "src/modules/dex/tests/testdata/c14c75d58399825287e0ee0fcfede6ec06f93489fb52f70bca2736fae5fceab2.in.zip",
    );

    let mut group = c.benchmark_group("dex");

    group.bench_function("parse", |b| {
        b.iter(|| {
            let _ = black_box(yara_x::mods::invoke::<yara_x::mods::Dex>(black_box(&data)));
        });
    });

    group.finish();
}

criterion_group!(benches, bench_dex);
criterion_main!(benches);
