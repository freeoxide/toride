//! Criterion benchmarks for the F08 `authorized_keys` parse + fingerprint pass.
//!
//! Uses the fixture committed at `tests/fixtures/authorized_keys.txt`
//! (6 entries: plain ed25519 / rsa / ecdsa keys plus option-prefixed
//! ed25519 entries with quoted commands and `from` patterns). The fixture is
//! embedded at compile time and written to a temp dir, so the bench is
//! hermetic: no network, no host binaries, no `~/.ssh` access.
//!
//! Benches:
//! - `parse_file`             — file → [`Entry`] list
//! - `fingerprint_entries`    — pre-parsed entries → SHA-256 fingerprints
//! - `parse_and_fingerprint`  — the full F08 pass (file → fingerprints)

use std::hint::black_box;
use std::sync::OnceLock;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use toride_ssh_authorized_keys::Entry;
use toride_ssh_authorized_keys::parse::parse_authorized_keys;

const FIXTURE: &str = include_str!("../tests/fixtures/authorized_keys.txt");

const SAMPLE_SIZE: usize = 30;
const MEASUREMENT_TIME: Duration = Duration::from_secs(2);
const WARM_UP_TIME: Duration = Duration::from_millis(500);

/// Shared tokio runtime: the public parse API is async and offloads the
/// CPU-bound line parsing to `spawn_blocking`.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Runtime::new().expect("failed to build tokio runtime"))
}

struct Rig {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("authorized_keys");
    std::fs::write(&path, FIXTURE).expect("write authorized_keys fixture");
    Rig { _dir: dir, path }
}

fn authorized_keys_pass(c: &mut Criterion) {
    let rig = rig();
    let rt = runtime();

    // Startup sanity (mirrors the count oracle in tests/fixtures_oracle.rs).
    let entries = rt
        .block_on(parse_authorized_keys(&rig.path))
        .expect("authorized_keys fixture must parse");
    assert_eq!(entries.len(), 6, "fixture must yield 6 entries");

    let mut group = c.benchmark_group("authorized_keys/parse_fingerprint");
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
            let ok = entries.iter().filter_map(Entry::fingerprint).count();
            black_box(ok)
        });
    });

    group.bench_function("parse_and_fingerprint", |b| {
        b.iter(|| {
            let entries = rt
                .block_on(parse_authorized_keys(&rig.path))
                .expect("authorized_keys fixture must parse");
            let ok = entries.iter().filter_map(Entry::fingerprint).count();
            black_box(ok)
        });
    });

    group.finish();
}

criterion_group!(benches, authorized_keys_pass);
criterion_main!(benches);
