use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use toride_installer::status::ToolVersion;

const FIXTURE_TSV: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/benches/fixtures/version_outputs_300.tsv"
);

const EXPECTED_ROWS: usize = 300;

fn parse_row(row: &str) -> (&str, &str) {
    let (bin, output) = row
        .split_once('\t')
        .expect("every fixture row is <bin>\\t<version line>");
    (bin, output)
}

fn assert_fixture_shape(content: &str) {
    let rows: Vec<(&str, &str)> = content.lines().map(parse_row).collect();
    assert_eq!(rows.len(), EXPECTED_ROWS);

    let git = ToolVersion::parse("git version 2.47.2", "git");
    assert_eq!(git.raw, "2.47.2");
    assert_eq!(
        git.parsed.as_ref().map(std::string::ToString::to_string),
        Some("2.47.2".to_string())
    );
    let fd = ToolVersion::parse("fd 10.2.0", "fd");
    assert_eq!(fd.raw, "10.2.0");
    assert!(fd.parsed.is_some());
    let python = ToolVersion::parse("Python 3.13.1", "python3");
    assert_eq!(python.raw, "Python");
    assert!(python.parsed.is_none(), "current behavior: not semver");
    let node = ToolVersion::parse("v22.0.0", "node");
    assert_eq!(node.raw, "v22.0.0");
    assert!(
        node.parsed.is_none(),
        "current behavior: 'v' prefix is not semver"
    );
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
