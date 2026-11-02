//! Arc-versus-clone micro-bench for the per-poll status delivery (tui-4).
//!
//! Every completed status poll deep-clones the whole `TorideStatus` for the
//! about collector (`app/mod.rs:510`) although the about view reads only a
//! handful of identity fields. This pins the clone cost against an
//! `Arc<TorideStatus>` refcount bump over the same simulated tick cadence.

mod common;

use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};

use common::fixed_status;

fn status_clone(c: &mut Criterion) {
    let status = fixed_status();
    let shared = Arc::new(fixed_status());

    let mut group = c.benchmark_group("status_delivery");
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(2));
    group.sample_size(20);

    group.bench_function("deep_clone_per_poll", |b| {
        b.iter(|| black_box(status.clone()));
    });

    group.bench_function("arc_clone_per_poll", |b| {
        b.iter(|| black_box(Arc::clone(&shared)));
    });

    group.finish();
}

criterion_group!(benches, status_clone);
criterion_main!(benches);
