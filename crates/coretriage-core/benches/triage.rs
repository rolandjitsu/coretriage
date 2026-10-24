//! Criterion bench skeleton for the triage pipeline. A placeholder until the pipeline lands;
//! real benchmarks will run `triage` over the golden cores in `tests/fixtures`.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

fn triage_benchmark(c: &mut Criterion) {
    c.bench_function("noop", |b| b.iter(|| black_box(1_u64) + black_box(1_u64)));
}

criterion_group!(benches, triage_benchmark);
criterion_main!(benches);
