use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use toride_backup::parse::{parse_borg_list, parse_restic_check, parse_restic_snapshots};

const FIXTURE_SNAPSHOTS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/benches/fixtures/restic/snapshots_table_2k.txt"
);

const FIXTURE_CHECK: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/benches/fixtures/restic/check_2k.log"
);

const FIXTURE_BORG: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/benches/fixtures/borg/list_2k.txt"
);

const EXPECTED_SNAPSHOTS: usize = 2_000;
const EXPECTED_CHECK_LINES: usize = 2_001;
const EXPECTED_BORG_LINES: usize = 2_000;

fn assert_fixture_shape(snapshots: &str, check: &str, borg: &str) {
    let parsed = parse_restic_snapshots(snapshots).expect("restic fixture parses");
    assert_eq!(parsed.len(), EXPECTED_SNAPSHOTS);
    assert_eq!(parsed[0].id.len(), 8, "short id is the first 8 chars");
    assert_eq!(parsed[0].id, parsed[0].full_id[..8]);
    assert!(parsed.iter().all(|s| s.hostname.is_none()));

    let result = parse_restic_check(check);
    assert_eq!(result.output_lines.len(), EXPECTED_CHECK_LINES);
    assert!(result.passed, "clean fixture must pass");
    assert_eq!(result.error_count, 0, "clean fixture reports no errors");

    let borg_parsed = parse_borg_list(borg).expect("borg fixture parses");
    assert_eq!(borg_parsed.len(), EXPECTED_BORG_LINES);
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
