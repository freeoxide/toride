use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use toride_mise::serde_utils::json_outputs::{LsOutput, OutdatedOutput};

const FIXTURE_LS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/benches/fixtures/ls/installed_500.json"
);

const FIXTURE_OUTDATED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/benches/fixtures/outdated/entries_200.json"
);

const EXPECTED_LS_TOOLS: usize = 500;

const EXPECTED_LS_VERSIONS: usize = 600;

const EXPECTED_OUTDATED: usize = 200;

fn assert_fixture_shape(ls_raw: &str, outdated_raw: &str) {
    let ls: LsOutput = serde_json::from_str(ls_raw).expect("ls fixture deserializes");
    assert_eq!(ls.len(), EXPECTED_LS_TOOLS);
    assert_eq!(
        ls.values().map(Vec::len).sum::<usize>(),
        EXPECTED_LS_VERSIONS,
        "every fifth tool carries a second version"
    );
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
