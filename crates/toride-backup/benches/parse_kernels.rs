//! Criterion benchmarks for the toride-backup output parsers.
//!
//! Inputs are committed, deterministic fixtures (no host binaries, no
//! network, no generated state), each mirroring the real CLI output shape:
//!
//! - `restic snapshots` — 2,000 text-table rows plus the two header lines
//!   (`benches/fixtures/restic/snapshots_table_2k.txt`). This exercises the
//!   crate's DEFAULT-feature parse path: `client` (the default) enables
//!   `dep:serde` without the `serde` feature flag, so
//!   [`parse_restic_snapshots`] takes its text arm in default builds — the
//!   JSON arm is deliberately NOT benched here because building it would
//!   require enabling a non-default feature (a behavior change this
//!   round must not make).
//! - `restic check` — 2,000 progress lines plus the clean summary
//!   (`benches/fixtures/restic/check_2k.log`).
//! - `borg list` — 2,000 `<id> <timestamp> <hostname> <path>` lines
//!   (`benches/fixtures/borg/list_2k.txt`).
//!
//! Run scoped:
//!
//! ```text
//! cargo bench -p toride-backup --bench parse_kernels
//! ```

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use toride_backup::parse::{parse_borg_list, parse_restic_check, parse_restic_snapshots};

/// Path to the committed restic snapshots fixture.
const FIXTURE_SNAPSHOTS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/benches/fixtures/restic/snapshots_table_2k.txt"
);

/// Path to the committed restic check fixture.
const FIXTURE_CHECK: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/benches/fixtures/restic/check_2k.log"
);

/// Path to the committed borg list fixture.
const FIXTURE_BORG: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/benches/fixtures/borg/list_2k.txt"
);

/// Snapshot rows in the restic fixture (header lines excluded).
const EXPECTED_SNAPSHOTS: usize = 2_000;

/// Lines in the restic check fixture.
const EXPECTED_CHECK_LINES: usize = 2_001;

/// Lines in the borg list fixture.
const EXPECTED_BORG_LINES: usize = 2_000;

/// One-time validation that the committed fixtures still have the shape the
/// expected constants above describe.
fn assert_fixture_shape(snapshots: &str, check: &str, borg: &str) {
    let parsed = parse_restic_snapshots(snapshots).expect("restic fixture parses");
    assert_eq!(parsed.len(), EXPECTED_SNAPSHOTS);
    assert_eq!(parsed[0].id.len(), 8, "short id is the first 8 chars");
    assert_eq!(parsed[0].id, parsed[0].full_id[..8]);
    // Current text-arm behavior: hostname/tags/paths stay empty (the text
    // parser only extracts id + timestamp) — pinned as-is.
    assert!(parsed.iter().all(|s| s.hostname.is_none()));

    let result = parse_restic_check(check);
    assert_eq!(result.output_lines.len(), EXPECTED_CHECK_LINES);
    assert!(result.passed, "clean fixture must pass");
    assert_eq!(result.error_count, 0, "clean fixture reports no errors");

    let borg_parsed = parse_borg_list(borg).expect("borg fixture parses");
    assert_eq!(borg_parsed.len(), EXPECTED_BORG_LINES);
    // Current borg-arm behavior: id + timestamp only, hostname stays None
    // (the text split does not map columns 3+) — pinned as-is.
    assert!(borg_parsed.iter().all(|s| s.hostname.is_none()));
    assert_eq!(borg_parsed[0].id.len(), 8, "short id is the first 8 chars");
}

fn bench_parse_kernels(c: &mut Criterion) {
    let snapshots = std::fs::read_to_string(FIXTURE_SNAPSHOTS).expect("committed fixture readable");
    let check = std::fs::read_to_string(FIXTURE_CHECK).expect("committed fixture readable");
    let borg = std::fs::read_to_string(FIXTURE_BORG).expect("committed fixture readable");
    assert_fixture_shape(&snapshots, &check, &borg);

    let mut group = c.benchmark_group("parse_kernels");

    group.throughput(Throughput::Bytes(snapshots.len() as u64));
    group.bench_function("restic_snapshots_text_2k", |b| {
        b.iter(|| parse_restic_snapshots(black_box(&snapshots)).expect("fixture parses"));
    });

    group.throughput(Throughput::Bytes(check.len() as u64));
    group.bench_function("restic_check_2k", |b| {
        b.iter(|| parse_restic_check(black_box(&check)));
    });

    group.throughput(Throughput::Bytes(borg.len() as u64));
    group.bench_function("borg_list_2k", |b| {
        b.iter(|| parse_borg_list(black_box(&borg)).expect("fixture parses"));
    });

    group.finish();
}

criterion_group!(benches, bench_parse_kernels);
criterion_main!(benches);
