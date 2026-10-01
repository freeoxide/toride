use std::collections::{HashMap, HashSet};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

const CACHED_PIDS: u32 = 500;
const LIVE_PIDS: u32 = 400;
const CACHED_PIDS_BIG: u32 = 4_000;
const LIVE_PIDS_BIG: u32 = 3_600;

fn make_cache(cached: u32) -> HashMap<u32, u8> {
    (0..cached).map(|pid| (pid, 0)).collect()
}

fn make_live_set(cached: u32, live: u32) -> Vec<u32> {
    (cached / 2..cached / 2 + live).collect()
}

fn bench_prune(c: &mut Criterion) {
    let mut group = c.benchmark_group("prune_slow_proc_cache");

    for (name, cached, live) in [
        ("500x400", CACHED_PIDS, LIVE_PIDS),
        ("4000x3600", CACHED_PIDS_BIG, LIVE_PIDS_BIG),
    ] {
        group.bench_function(format!("{name}/vec_contains_O_cache_x_live"), |b| {
            b.iter_batched(
                || (make_cache(cached), make_live_set(cached, live)),
                |(mut cache, live)| {
                    cache.retain(|pid, _| live.contains(pid));
                    cache
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_function(format!("{name}/hashset_contains_O_cache"), |b| {
            b.iter_batched(
                || {
                    (
                        make_cache(cached),
                        make_live_set(cached, live)
                            .into_iter()
                            .collect::<HashSet<u32>>(),
                    )
                },
                |(mut cache, live)| {
                    cache.retain(|pid, _| live.contains(pid));
                    cache
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_prune);
criterion_main!(benches);
