use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use toride_monitor::parse::{parse_ss_output, ss_entry_to_connection};

const FIXTURE: &str = include_str!("fixtures/ss/tunap_2k.txt");

fn bench_ss_parse(c: &mut Criterion) {
    c.bench_function("ss_tunap_parse_2k_rows", |b| {
        b.iter(|| {
            let entries = parse_ss_output(black_box(FIXTURE)).expect("fixture must parse");
            black_box(entries.len())
        });
    });

    c.bench_function("ss_tunap_parse_and_convert_2k_rows", |b| {
        b.iter(|| {
            let entries = parse_ss_output(black_box(FIXTURE)).expect("fixture must parse");
            let connections: Vec<_> = entries.iter().filter_map(ss_entry_to_connection).collect();
            black_box(connections.len())
        });
    });
}

criterion_group!(benches, bench_ss_parse);
criterion_main!(benches);
