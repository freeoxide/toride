//! Criterion benchmarks for the toride-mise JSON deserialization kernels.
//!
//! Inputs are committed, deterministic fixtures (no host binaries, no
//! network, no `mise` invocation): a 500-tool `mise ls --json` map
//! (`benches/fixtures/ls/installed_500.json`, every fifth tool carrying a
//! second version) and a 200-tool `mise outdated --json` map
//! (`benches/fixtures/outdated/entries_200.json`). These are the exact
//! `Deserialize` types the collector's probes feed
//! (`LsOutput` / `OutdatedOutput` in `serde_utils::json_outputs`).
//!
//! Run scoped:
//!
//! ```text
//! cargo bench -p toride-mise --bench serde_parse
//! ```

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use toride_mise::serde_utils::json_outputs::{LsOutput, OutdatedOutput};

/// Path to the committed `mise ls --json` fixture.
const FIXTURE_LS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/benches/fixtures/ls/installed_500.json"
);

/// Path to the committed `mise outdated --json` fixture.
const FIXTURE_OUTDATED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/benches/fixtures/outdated/entries_200.json"
);

/// Tool names in the ls fixture.
const EXPECTED_LS_TOOLS: usize = 500;

/// Version entries in the ls fixture (one per tool, plus one more for every
/// fifth tool).
const EXPECTED_LS_VERSIONS: usize = 600;

/// Entries in the outdated fixture.
const EXPECTED_OUTDATED: usize = 200;

/// One-time validation that the committed fixtures still have the shape the
/// expected constants above describe.
fn assert_fixture_shape(ls_raw: &str, outdated_raw: &str) {
    let ls: LsOutput = serde_json::from_str(ls_raw).expect("ls fixture deserializes");
    assert_eq!(ls.len(), EXPECTED_LS_TOOLS);
    assert_eq!(
        ls.values().map(Vec::len).sum::<usize>(),
        EXPECTED_LS_VERSIONS,
        "every fifth tool carries a second version"
    );
    // Every tool's first version is the active one.
    assert!(ls.values().all(|v| v[0].active.unwrap_or(false)));

    let outdated: OutdatedOutput =
        serde_json::from_str(outdated_raw).expect("outdated fixture deserializes");
    assert_eq!(outdated.len(), EXPECTED_OUTDATED);
    assert!(outdated.values().all(|e| e.current.is_some()));
}

fn bench_serde_parse(c: &mut Criterion) {
    let ls_raw = std::fs::read_to_string(FIXTURE_LS).expect("committed fixture readable");
    let outdated_raw =
        std::fs::read_to_string(FIXTURE_OUTDATED).expect("committed fixture readable");
    assert_fixture_shape(&ls_raw, &outdated_raw);

    let mut group = c.benchmark_group("serde_parse");

    group.throughput(Throughput::Bytes(ls_raw.len() as u64));
    group.bench_function("ls_json_500_tools", |b| {
        b.iter(|| {
            let ls: LsOutput =
                serde_json::from_str(black_box(&ls_raw)).expect("ls fixture deserializes");
            black_box(ls);
        });
    });

    group.throughput(Throughput::Bytes(outdated_raw.len() as u64));
    group.bench_function("outdated_json_200_tools", |b| {
        b.iter(|| {
            let outdated: OutdatedOutput = serde_json::from_str(black_box(&outdated_raw))
                .expect("outdated fixture deserializes");
            black_box(outdated);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_serde_parse);
criterion_main!(benches);
