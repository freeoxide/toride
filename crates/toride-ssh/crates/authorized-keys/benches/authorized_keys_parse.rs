use std::hint::black_box;
use std::sync::OnceLock;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use toride_ssh_authorized_keys::AuthorizedKeysService;
use toride_ssh_authorized_keys::Entry;
use toride_ssh_authorized_keys::parse::parse_authorized_keys;
use toride_ssh_core::SshPaths;

const FIXTURE: &str = include_str!("../tests/fixtures/authorized_keys.txt");

const SAMPLE_SIZE: usize = 100;
const MEASUREMENT_TIME: Duration = Duration::from_secs(8);
const WARM_UP_TIME: Duration = Duration::from_secs(1);
/// Deltas under 20 percent are shared-host regime drift, matching the
/// campaign's bench gate tolerance; larger ones still fail as regressions.
const NOISE_THRESHOLD: f64 = 0.20;

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Runtime::new().expect("failed to build tokio runtime"))
}

struct Rig {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
}

fn super_rig() -> Rig {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("authorized_keys");
    std::fs::write(&path, FIXTURE).expect("write authorized_keys fixture");
    Rig { _dir: dir, path }
}

fn authorized_keys_pass(c: &mut Criterion) {
    let rig = super_rig();
    let rt = runtime();

    let entries = rt
        .block_on(parse_authorized_keys(&rig.path))
        .expect("authorized_keys fixture must parse");
    assert_eq!(entries.len(), 6, "fixture must yield 6 entries");

    let mut group = c.benchmark_group("authorized_keys/parse_fingerprint");
    group.noise_threshold(NOISE_THRESHOLD);
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);
    group.throughput(Throughput::Bytes(FIXTURE.len() as u64));

    group.bench_function("parse_file", |b| {
        b.iter(|| {
            let entries = rt
                .block_on(parse_authorized_keys(&rig.path))
                .expect("authorized_keys fixture must parse");
            black_box(entries.len())
        });
    });

    group.bench_function("fingerprint_entries", |b| {
        b.iter(|| {
            let ok = entries
                .iter()
                .map(Entry::fingerprint)
                .fold(0usize, |acc, fp| acc + fp.len());
            black_box(ok)
        });
    });

    group.bench_function("parse_and_fingerprint", |b| {
        b.iter(|| {
            let entries = rt
                .block_on(parse_authorized_keys(&rig.path))
                .expect("authorized_keys fixture must parse");
            let ok = entries
                .iter()
                .map(Entry::fingerprint)
                .fold(0usize, |acc, fp| acc + fp.len());
            black_box(ok)
        });
    });

    group.finish();

    let first_fingerprint = entries
        .first()
        .map(Entry::fingerprint)
        .expect("first entry carries a fingerprint");

    let remove_rig = super_rig();
    let paths: &'static SshPaths = Box::leak(Box::new(SshPaths::with_dir(
        remove_rig
            .path
            .parent()
            .expect("authorized_keys parent dir"),
    )));
    let service = AuthorizedKeysService::new(paths);

    let removed = rt
        .block_on(service.remove(&first_fingerprint))
        .expect("remove answers");
    assert_eq!(
        removed, 2,
        "the fixture carries the first key's material twice, so one fingerprint removes two entries"
    );
    let remaining = rt
        .block_on(parse_authorized_keys(&remove_rig.path))
        .expect("post-remove file parses");
    assert_eq!(remaining.len(), 4, "four entries survive the removal");
    let removed_again = rt
        .block_on(service.remove(&first_fingerprint))
        .expect("second remove answers");
    assert_eq!(removed_again, 0, "a spent fingerprint removes nothing");

    let mut group = c.benchmark_group("authorized_keys/remove");
    group.noise_threshold(NOISE_THRESHOLD);
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);
    group.throughput(Throughput::Bytes(FIXTURE.len() as u64));

    group.bench_function("remove_one_fresh_copy", |b| {
        b.iter(|| {
            std::fs::write(&remove_rig.path, FIXTURE).expect("fresh copy writable");
            let removed = rt
                .block_on(service.remove(black_box(&first_fingerprint)))
                .expect("remove answers");
            black_box(removed)
        });
    });

    group.finish();
}

criterion_group!(benches, authorized_keys_pass);
criterion_main!(benches);
