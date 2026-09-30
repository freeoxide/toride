//! Criterion benchmarks for UFW status and rule-line parsing.
//!
//! All inputs are committed, deterministic fixtures under
//! `benches/fixtures/status/` — no host binaries, no network, no generated
//! state. Each fixture's expected parse counts are asserted once during bench
//! setup so fixture drift fails loudly instead of silently skewing numbers.
//!
//! Run scoped:
//!
//! ```text
//! cargo bench -p ufw-kit --bench status_parse
//! ```

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use ufw_kit::status;

/// Fixture directory, resolved relative to this crate's manifest.
const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/benches/fixtures/status/");

/// Load a fixture by file name, panicking if it is missing (fixtures are
/// committed, so a missing file is a broken checkout).
fn fixture(name: &str) -> String {
    let path = format!("{FIXTURE_DIR}{name}");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("bench fixture {path} should be committed and readable: {e}"))
}

/// Number of rule lines in the status fixtures (plain / verbose / numbered
/// share the same 400-line rule corpus).
const EXPECTED_STATUS_RULES: usize = 400;

/// Number of lines in the `show added` fixture after its header.
const EXPECTED_ADDED_RULES: usize = 200;

/// Number of listening entries in the `show listening` fixture.
const EXPECTED_LISTENING: usize = 128;

/// One-time validation of every fixture against the parsers, so benchmark
/// numbers are only produced from inputs with known parse counts.
fn assert_fixtures_parse_as_expected() {
    let plain = status::parse_status(&fixture("status_plain_400.txt")).expect("plain fixture");
    assert_eq!(plain.rules.len(), EXPECTED_STATUS_RULES);
    assert!(plain.active);

    let verbose =
        status::parse_status_verbose(&fixture("status_verbose_400.txt")).expect("verbose fixture");
    assert_eq!(verbose.rules.len(), EXPECTED_STATUS_RULES);
    assert!(verbose.active);
    assert!(verbose.default_incoming.is_some());

    let numbered =
        status::parse_status_numbered(&fixture("status_numbered_400.txt")).expect("numbered");
    assert_eq!(numbered.rules.len(), EXPECTED_STATUS_RULES);
    assert_eq!(numbered.rules[0].number, Some(1));
    assert_eq!(numbered.rules[EXPECTED_STATUS_RULES - 1].number, Some(400));

    let added = status::parse_show_added(&fixture("show_added_200.txt"));
    assert_eq!(added.len(), EXPECTED_ADDED_RULES);

    let listening = status::parse_show_listening(&fixture("show_listening_128.txt"));
    assert_eq!(listening.len(), EXPECTED_LISTENING);
}

fn bench_status_parsing(c: &mut Criterion) {
    assert_fixtures_parse_as_expected();

    let plain = fixture("status_plain_400.txt");
    let verbose = fixture("status_verbose_400.txt");
    let numbered = fixture("status_numbered_400.txt");

    let mut group = c.benchmark_group("status_parse");
    group.throughput(Throughput::Bytes(plain.len() as u64));
    group.bench_function("parse_status/plain_400", |b| {
        b.iter(|| {
            let status = status::parse_status(black_box(&plain)).expect("plain fixture parses");
            black_box(status.rules.len())
        });
    });

    group.bench_function("parse_status_verbose/verbose_400", |b| {
        b.iter(|| {
            let status =
                status::parse_status_verbose(black_box(&verbose)).expect("verbose fixture parses");
            black_box(status.rules.len())
        });
    });

    group.bench_function("parse_status_numbered/numbered_400", |b| {
        b.iter(|| {
            let status =
                status::parse_status_numbered(black_box(&numbered)).expect("numbered fixture");
            black_box(status.rules.len())
        });
    });

    group.finish();
}

fn bench_show_parsing(c: &mut Criterion) {
    assert_fixtures_parse_as_expected();

    let added = fixture("show_added_200.txt");
    let listening = fixture("show_listening_128.txt");

    let mut group = c.benchmark_group("show_parse");

    group.bench_function("parse_show_added/added_200", |b| {
        b.iter(|| black_box(status::parse_show_added(black_box(&added)).len()));
    });

    group.bench_function("parse_show_listening/listening_128", |b| {
        b.iter(|| black_box(status::parse_show_listening(black_box(&listening)).len()));
    });

    group.finish();
}

/// Per-rule-line resolution: run the public per-line entry point
/// `parse_status_numbered` on each of the 400 numbered rule lines in
/// isolation. This isolates single-rule parsing (including status-struct
/// construction) from whole-dump scanning, at 400 lines per sample.
fn bench_rule_line_parse(c: &mut Criterion) {
    let numbered = fixture("status_numbered_400.txt");
    let rule_lines: Vec<&str> = numbered.lines().filter(|l| l.starts_with('[')).collect();
    assert_eq!(rule_lines.len(), EXPECTED_STATUS_RULES);

    let mut group = c.benchmark_group("status_parse");
    group.throughput(Throughput::Elements(rule_lines.len() as u64));

    group.bench_function("parse_status_numbered/per_line_400", |b| {
        b.iter(|| {
            let mut count = 0usize;
            for line in &rule_lines {
                if status::parse_status_numbered(black_box(line)).is_ok() {
                    count += 1;
                }
            }
            black_box(count)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_status_parsing,
    bench_show_parsing,
    bench_rule_line_parse
);
criterion_main!(benches);
