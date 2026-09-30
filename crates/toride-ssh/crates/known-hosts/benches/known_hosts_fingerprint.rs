//! Criterion benchmarks for the F08 `known_hosts` fingerprint pass.
//!
//! Reuses the facade crate's fixture `crates/toride-ssh/tests/fixtures/
//! known_hosts_markers.txt` (9 entries: plain/marked/hashed/bracketed/
//! comma-separated hosts, ed25519 + rsa + ecdsa key types). The file is
//! embedded at compile time and written to a temp dir, so the bench is
//! hermetic: no network, no host binaries, no `~/.ssh` access.
//!
//! Benches:
//! - `parse_file`             — file → [`KnownHostEntry`] list
//! - `fingerprint_entries`    — pre-parsed entries → SHA-256 fingerprints
//! - `parse_and_fingerprint`  — the full F08 pass (file → fingerprints)

use std::hint::black_box;
use std::sync::OnceLock;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use toride_ssh_core::{MockCliRunner, SshPaths};
use toride_ssh_known_hosts::KnownHostsService;

/// The `known_hosts` fixture, reloaded from the facade crate's tests dir.
const FIXTURE: &str = include_str!("../../../tests/fixtures/known_hosts_markers.txt");

const SAMPLE_SIZE: usize = 30;
const MEASUREMENT_TIME: Duration = Duration::from_secs(2);
const WARM_UP_TIME: Duration = Duration::from_millis(500);

/// Shared tokio runtime: the public parse API (`KnownHostsService::list`)
/// is async and offloads to `spawn_blocking`.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Runtime::new().expect("failed to build tokio runtime"))
}

/// Owned, process-lifetime rig so `KnownHostsService`'s borrows stay valid
/// across every criterion iteration. Leaking exactly once per bench run.
struct Rig {
    _dir: tempfile::TempDir,
    service: KnownHostsService<'static>,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::write(dir.path().join("known_hosts"), FIXTURE).expect("write known_hosts fixture");

    let paths: &'static SshPaths = Box::leak(Box::new(SshPaths::with_dir(dir.path())));
    let runner: &'static MockCliRunner = Box::leak(Box::new(MockCliRunner::new()));
    Rig {
        _dir: dir,
        service: KnownHostsService::new(paths, runner),
    }
}

fn known_hosts_fingerprint_pass(c: &mut Criterion) {
    let rig = rig();
    let rt = runtime();

    // Startup sanity (mirrors the count oracle in tests/fixtures_oracle.rs):
    // fail loudly if the fixture or parser regresses.
    let entries = rt
        .block_on(rig.service.list())
        .expect("known_hosts fixture must parse");
    let expected_entries = entries
        .iter()
        .filter(|e| e.key_type == "ssh-ed25519")
        .count();
    assert_eq!(entries.len(), 9, "fixture must yield 9 entries");
    assert_eq!(expected_entries, 6, "fixture must yield 6 ed25519 entries");

    let mut group = c.benchmark_group("known_hosts/fingerprint_pass");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);
    group.throughput(Throughput::Bytes(FIXTURE.len() as u64));

    group.bench_function("parse_file", |b| {
        b.iter(|| {
            let entries = rt
                .block_on(rig.service.list())
                .expect("known_hosts fixture must parse");
            black_box(entries.len())
        });
    });

    group.bench_function("fingerprint_entries", |b| {
        b.iter(|| {
            let ok = entries
                .iter()
                .filter_map(|e| e.fingerprint().ok().map(|fp| fp.hash))
                .fold(0usize, |acc, hash| acc + hash.len());
            black_box(ok)
        });
    });

    group.bench_function("parse_and_fingerprint", |b| {
        b.iter(|| {
            let entries = rt
                .block_on(rig.service.list())
                .expect("known_hosts fixture must parse");
            let ok = entries
                .iter()
                .filter_map(|e| e.fingerprint().ok().map(|fp| fp.hash))
                .fold(0usize, |acc, hash| acc + hash.len());
            black_box(ok)
        });
    });

    group.finish();
}

criterion_group!(benches, known_hosts_fingerprint_pass);
criterion_main!(benches);
