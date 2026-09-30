//! Criterion benchmarks for the F08 shared config-AST cache.
//!
//! Round 0 baselined the raw parse kernels (key parse, fingerprint passes).
//! This bench measures the new seam those findings' fixes route through:
//! [`toride_ssh_config::cache::load_cached_ast`], which the config tab, the
//! key inventory's `IdentityFile` scan, and eleven doctor checks all share
//! — one parse per collection run for an unchanged config instead of one
//! parse per consumer.
//!
//! Groups:
//! - `config/parse_fresh` — `ast::parse` over the committed fixture, the
//!   per-consumer cost every consumer paid before the cache.
//! - `config/load_cached_hit` — `load_cached_ast` on an unchanged file: one
//!   `stat` plus a map lookup and an Arc clone; the parse is skipped.
//!
//! The fixture is a committed throwaway config; no network, no host
//! `~/.ssh` is read.

use std::hint::black_box;
use std::path::PathBuf;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

const FIXTURE: &str = include_str!("../tests/fixtures/ssh_config");

/// Samples per bench; small on purpose — the campaign re-runs this rig
/// every round and the kernels are microsecond-scale.
const SAMPLE_SIZE: usize = 30;
const MEASUREMENT_TIME: Duration = Duration::from_secs(2);
const WARM_UP_TIME: Duration = Duration::from_millis(500);

fn cached_ast(c: &mut Criterion) {
    let mut group = c.benchmark_group("config/ast");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);

    // Startup sanity: the fixture must parse into the expected host blocks,
    // so a fixture regression fails loudly instead of skewing numbers.
    let ast = toride_ssh_config::ast::parse(FIXTURE);
    let hosts = ast
        .nodes
        .iter()
        .filter(|n| matches!(n, toride_ssh_config::ast::ConfigNode::HostBlock(_)))
        .count();
    assert_eq!(hosts, 4, "fixture must contain 4 host blocks");

    // A unique temp file per bench process: cache keys are per path, and
    // other tests in the same process must not collide with this path.
    let dir = tempfile::tempdir().expect("tempdir");
    let path: PathBuf = dir.path().join("ssh_config");
    std::fs::write(&path, FIXTURE).expect("write fixture");

    group.throughput(Throughput::Bytes(FIXTURE.len() as u64));
    group.bench_function("parse_fresh", |b| {
        b.iter(|| toride_ssh_config::ast::parse(black_box(FIXTURE)));
    });

    // Warm the cache once, then every iteration is a hit (the file is never
    // rewritten inside the loop).
    toride_ssh_config::cache::load_cached_ast(&path).expect("warm the cache");
    group.bench_function("load_cached_hit", |b| {
        b.iter(|| {
            let ast =
                toride_ssh_config::cache::load_cached_ast(black_box(&path)).expect("cached load");
            black_box(ast)
        });
    });

    group.finish();
}

criterion_group!(benches, cached_ast);
criterion_main!(benches);
