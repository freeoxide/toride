//! Criterion benchmarks for the toride-updates output parsers.
//!
//! Input is a committed, deterministic 10,000-line synthetic
//! unattended-upgrades log (`benches/fixtures/logs/unattended_upgrades_10k.log`
//! — 2,000 runs of five lines each, timestamps stepped deterministically by
//! one minute). No host binaries, no network, no generated state: every
//! iteration parses the fixture read-only from memory, which is exactly the
//! production hot path (`UpdatesClient::status` parses the real log through
//! [`parse_unattended_upgrades_status`]).
//!
//! Run scoped:
//!
//! ```text
//! cargo bench -p toride-updates --bench parse_kernels
//! ```

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use toride_updates::parse::parse_unattended_upgrades_status;

/// Path to the committed fixture log.
const FIXTURE_LOG: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/benches/fixtures/logs/unattended_upgrades_10k.log"
);

/// Total lines in the fixture log (2,000 runs x 5 lines).
const EXPECTED_LINES: usize = 10_000;

/// Packages per "Packages that will be upgraded:" line — the count the last
/// committed run must report as `pending_security`.
const EXPECTED_PACKAGES: usize = 8;

/// One-time validation that the committed fixture still has the shape the
/// expected constants above describe.
fn assert_fixture_shape(content: &str) {
    assert_eq!(content.lines().count(), EXPECTED_LINES);
    let status = parse_unattended_upgrades_status(content).expect("fixture parses cleanly");
    assert!(
        status.auto_updates_enabled,
        "the fixture contains real runs, so the log counts as enabled"
    );
    assert_eq!(
        status.pending_security, EXPECTED_PACKAGES,
        "the last committed run upgraded the expected package count"
    );
    assert!(
        status.last_run.is_some(),
        "the last run's start timestamp must be captured"
    );
}

fn bench_parse_kernels(c: &mut Criterion) {
    let content = std::fs::read_to_string(FIXTURE_LOG).expect("committed fixture readable");
    assert_fixture_shape(&content);

    let mut group = c.benchmark_group("parse_kernels");
    group.throughput(Throughput::Bytes(content.len() as u64));
    group.bench_function("unattended_upgrades_log_10k", |b| {
        b.iter(|| {
            parse_unattended_upgrades_status(black_box(&content)).expect("fixture parses cleanly");
        });
    });
    group.finish();
}

criterion_group!(benches, bench_parse_kernels);
criterion_main!(benches);
