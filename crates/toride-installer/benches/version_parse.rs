//! Criterion benchmark for the installer's version-probe parse kernel.
//!
//! Input is a committed, deterministic TSV of 300 `<bin_name> \t <--version
//! first line>` rows (`benches/fixtures/version_outputs_300.tsv`) covering
//! the catalogue's real output shapes: `<bin> version X.Y.Z`, `<bin> X.Y.Z`,
//! bare/unprefixed lines, `v`-prefixed tokens, and non-semver tokens. One
//! iteration parses all 300 rows through
//! [`ToolVersion::parse`](toride_installer::status::ToolVersion::parse) — the
//! exact kernel the tools collector's per-binary version probes feed.
//! Hermetic: no binaries are executed, no filesystem probing.
//!
//! Run scoped:
//!
//! ```text
//! cargo bench -p toride-installer --bench version_parse
//! ```

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use toride_installer::status::ToolVersion;

/// Path to the committed TSV fixture.
const FIXTURE_TSV: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/benches/fixtures/version_outputs_300.tsv"
);

/// Rows in the fixture.
const EXPECTED_ROWS: usize = 300;

/// One `<bin_name>, <output>` pair from a fixture row.
fn parse_row(row: &str) -> (&str, &str) {
    let (bin, output) = row
        .split_once('\t')
        .expect("every fixture row is <bin>\\t<version line>");
    (bin, output)
}

/// One-time validation that the committed fixture still has the shape the
/// parse pins below describe.
fn assert_fixture_shape(content: &str) {
    let rows: Vec<(&str, &str)> = content.lines().map(parse_row).collect();
    assert_eq!(rows.len(), EXPECTED_ROWS);

    // `<bin> version X.Y.Z` — the named-prefix strip path.
    let git = ToolVersion::parse("git version 2.47.2", "git");
    assert_eq!(git.raw, "2.47.2");
    assert_eq!(
        git.parsed.as_ref().map(std::string::ToString::to_string),
        Some("2.47.2".to_string())
    );
    // `<bin> X.Y.Z` — the single-space prefix strip path.
    let fd = ToolVersion::parse("fd 10.2.0", "fd");
    assert_eq!(fd.raw, "10.2.0");
    assert!(fd.parsed.is_some());
    // Unprefixed line: the first token is the product word, not a version.
    let python = ToolVersion::parse("Python 3.13.1", "python3");
    assert_eq!(python.raw, "Python");
    assert!(python.parsed.is_none(), "current behavior: not semver");
    // `v`-prefixed token parses to a raw string but not to semver.
    let node = ToolVersion::parse("v22.0.0", "node");
    assert_eq!(node.raw, "v22.0.0");
    assert!(
        node.parsed.is_none(),
        "current behavior: 'v' prefix is not semver"
    );
    // A bin name that is a PREFIX of the printed word must not strip it.
    let rg = ToolVersion::parse("ripgrep 14.1.1", "rg");
    assert_eq!(rg.raw, "ripgrep");
}

fn bench_version_parse(c: &mut Criterion) {
    let content = std::fs::read_to_string(FIXTURE_TSV).expect("committed fixture readable");
    assert_fixture_shape(&content);
    let rows: Vec<(&str, &str)> = content.lines().map(parse_row).collect();

    let mut group = c.benchmark_group("parse_kernels");
    group.throughput(Throughput::Elements(EXPECTED_ROWS as u64));
    group.bench_function("tool_version_300_outputs", |b| {
        b.iter(|| {
            for (bin, output) in black_box(&rows) {
                black_box(ToolVersion::parse(black_box(output), black_box(bin)));
            }
        });
    });
    group.finish();
}

criterion_group!(benches, bench_version_parse);
criterion_main!(benches);
