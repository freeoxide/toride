use std::hint::black_box;
use std::path::PathBuf;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

const FIXTURE: &str = include_str!("../tests/fixtures/ssh_config");

const SAMPLE_SIZE: usize = 30;
const MEASUREMENT_TIME: Duration = Duration::from_secs(2);
const WARM_UP_TIME: Duration = Duration::from_millis(500);

fn cached_ast(c: &mut Criterion) {
    let mut group = c.benchmark_group("config/ast");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);

    let ast = toride_ssh_config::ast::parse(FIXTURE);
    let hosts = ast
        .nodes
        .iter()
        .filter(|n| matches!(n, toride_ssh_config::ast::ConfigNode::HostBlock(_)))
        .count();
    assert_eq!(hosts, 4, "fixture must contain 4 host blocks");

    let dir = tempfile::tempdir().expect("tempdir");
    let path: PathBuf = dir.path().join("ssh_config");
    std::fs::write(&path, FIXTURE).expect("write fixture");

    group.throughput(Throughput::Bytes(FIXTURE.len() as u64));
    group.bench_function("parse_fresh", |b| {
        b.iter(|| toride_ssh_config::ast::parse(black_box(FIXTURE)));
    });

    toride_ssh_config::cache::load_cached_ast(&path).expect("warm the cache");
    group.bench_function("load_cached_hit", |b| {
        b.iter(|| {
            let ast =
                toride_ssh_config::cache::load_cached_ast(black_box(&path)).expect("cached load");
            black_box(ast)
        });
    });

    group.bench_function("content_cached_hit", |b| {
        b.iter(|| {
            let content = toride_ssh_config::cache::load_cached_content(black_box(&path))
                .expect("cached content");
            black_box(content)
        });
    });

    group.finish();
}

criterion_group!(benches, cached_ast);
criterion_main!(benches);
