//! Criterion benchmarks for the F08 private-key parse kernel.
//!
//! Measures `ssh_key::PrivateKey::from_openssh` — the entry point the key
//! inventory/repair paths use to load a private key file
//! (`crates/key/src/inventory.rs` and `crates/key/src/repair.rs`) — on the
//! two private-key fixtures committed under `tests/fixtures/`:
//!
//! - `id_ed25519`   — unencrypted OpenSSH-format Ed25519 key
//! - `id_rsa_2048`  — unencrypted OpenSSH-format RSA-2048 key
//!
//! The fixtures are throwaway keys embedded at compile time, so the bench
//! never touches the network, the host's `~/.ssh`, or any host binary.

use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use ssh_key::PrivateKey;

const ED25519_OPENSSH: &str = include_str!("../tests/fixtures/id_ed25519");
const RSA2048_OPENSSH: &str = include_str!("../tests/fixtures/id_rsa_2048");

/// Samples per bench; small on purpose — the campaign re-runs this rig every
/// round and the kernels are microsecond-scale.
const SAMPLE_SIZE: usize = 30;
const MEASUREMENT_TIME: Duration = Duration::from_secs(2);
const WARM_UP_TIME: Duration = Duration::from_millis(500);

fn from_openssh(c: &mut Criterion) {
    let mut group = c.benchmark_group("private_key/from_openssh");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);

    // Startup sanity: fail loudly if a fixture regresses instead of quietly
    // benchmarking the error path.
    let ed = PrivateKey::from_openssh(ED25519_OPENSSH).expect("ed25519 fixture must parse");
    assert_eq!(ed.algorithm(), ssh_key::Algorithm::Ed25519);
    let rsa = PrivateKey::from_openssh(RSA2048_OPENSSH).expect("rsa fixture must parse");
    assert!(matches!(rsa.algorithm(), ssh_key::Algorithm::Rsa { .. }));

    group.throughput(Throughput::Bytes(ED25519_OPENSSH.len() as u64));
    group.bench_function("ed25519_openssh", |b| {
        b.iter(|| {
            let pk = PrivateKey::from_openssh(black_box(ED25519_OPENSSH))
                .expect("ed25519 fixture must parse");
            black_box(pk)
        });
    });

    group.throughput(Throughput::Bytes(RSA2048_OPENSSH.len() as u64));
    group.bench_function("rsa2048_openssh", |b| {
        b.iter(|| {
            let pk = PrivateKey::from_openssh(black_box(RSA2048_OPENSSH))
                .expect("rsa fixture must parse");
            black_box(pk)
        });
    });

    group.finish();
}

/// F08 cache extension: the periodic inventory scan re-inspects every key
/// file each tick; unchanged files now go through the mtime-keyed memo
/// ([`toride_ssh_key::inspect_key_cached`]) — one `stat` plus a map hit and
/// a small clone instead of the MPINT decode + SHA-256 fingerprint measured
/// by the `private_key/from_openssh` group above.
fn inspect_cache_hit(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_cache/inspect_hit");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);

    // Real files at unique temp paths (cache keys are per path).
    let dir = tempfile::tempdir().expect("tempdir");
    let ed_path = dir.path().join("id_ed25519");
    let rsa_path = dir.path().join("id_rsa_2048");
    std::fs::write(&ed_path, ED25519_OPENSSH).expect("write ed25519 fixture");
    std::fs::write(&rsa_path, RSA2048_OPENSSH).expect("write rsa fixture");

    // Sanity + warm: the first (uncached) call must parse and fingerprint.
    let ed = toride_ssh_key::inspect_key_cached(&ed_path).expect("ed25519 inspect");
    assert!(ed.fingerprint.is_some(), "fresh inspect must fingerprint");
    let rsa = toride_ssh_key::inspect_key_cached(&rsa_path).expect("rsa inspect");
    assert!(rsa.fingerprint.is_some());

    group.bench_function("ed25519_cached", |b| {
        b.iter(|| {
            let key =
                toride_ssh_key::inspect_key_cached(black_box(&ed_path)).expect("cached inspect");
            black_box(key)
        });
    });
    group.bench_function("rsa2048_cached", |b| {
        b.iter(|| {
            let key =
                toride_ssh_key::inspect_key_cached(black_box(&rsa_path)).expect("cached inspect");
            black_box(key)
        });
    });

    group.finish();
}

criterion_group!(benches, from_openssh, inspect_cache_hit);
criterion_main!(benches);
