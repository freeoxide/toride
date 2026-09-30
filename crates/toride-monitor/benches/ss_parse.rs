//! Criterion benchmarks for the `ss -tunap` parser (F11 fix).
//!
//! Input is a committed, deterministic fixture (no host binaries, no
//! network): 2,000 rows under the REAL `ss -tunap` header
//! (`benches/fixtures/ss/tunap_2k.txt`) — mixed tcp/tcp6/udp rows, ESTAB /
//! LISTEN / TIME-WAIT / CLOSE-WAIT / UNCONN states, ~30% of rows without an
//! owner-process token, so the bench exercises the header-driven column
//! mapping AND the row-shape variance the converter filters.
//!
//! Run scoped:
//!
//! ```text
//! cargo bench -p toride-monitor --bench ss_parse
//! ```

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use toride_monitor::parse::{parse_ss_output, ss_entry_to_connection};

/// The committed fixture, read once (deterministic, hermetic).
const FIXTURE: &str = include_str!("fixtures/ss/tunap_2k.txt");

fn bench_ss_parse(c: &mut Criterion) {
    c.bench_function("ss_tunap_parse_2k_rows", |b| {
        b.iter(|| {
            let entries = parse_ss_output(black_box(FIXTURE)).expect("fixture must parse");
            black_box(entries.len())
        });
    });

    // The full production chain: parse + the `ss_entry_to_connection`
    // conversion that filters non-connection rows (wildcard peers). Before
    // the F11 fix this produced ZERO connections on real output — the bench
    // pins that the chain now yields data and stays fast.
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
