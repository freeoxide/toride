use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use toride_monitor::parse::parse_conntrack_output;

const FIXTURE: &str = include_str!("fixtures/conntrack/conntrack_10k.txt");

fn materialized_sums() -> (u64, u64) {
    let entries = parse_conntrack_output(FIXTURE).expect("fixture must parse");
    let total_bytes = entries.iter().filter_map(|e| e.bytes).sum();
    let total_packets = entries.iter().filter_map(|e| e.packets).sum();
    (total_bytes, total_packets)
}

fn field_u64(line: &str, key: &str) -> Option<u64> {
    let start = line.find(key)?;
    let remainder = &line[start + key.len()..];
    let end = remainder.find(' ').unwrap_or(remainder.len());
    remainder[..end].parse::<u64>().ok()
}

fn known_proto(line: &str) -> bool {
    let first = line.split_whitespace().next();
    matches!(
        first,
        Some("tcp" | "udp" | "icmp" | "icmpv6" | "sctp" | "dccp" | "gre")
    )
}

fn fused_sums() -> (u64, u64) {
    let mut total_bytes = 0;
    let mut total_packets = 0;
    for line in FIXTURE.lines() {
        if !known_proto(line) {
            continue;
        }
        if let Some(bytes) = field_u64(line, "bytes=") {
            total_bytes += bytes;
        }
        if let Some(packets) = field_u64(line, "packets=") {
            total_packets += packets;
        }
    }
    (total_bytes, total_packets)
}

fn bench_conntrack_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("conntrack_parse_sum_10k");

    let materialized = materialized_sums();
    let fused = fused_sums();
    assert_eq!(materialized, fused, "both scan shapes must sum identically");
    let entries = parse_conntrack_output(FIXTURE).expect("fixture must parse");
    assert_eq!(entries.len(), 10_000, "every fixture line must parse");

    group.bench_function("materialize_entries", |b| {
        b.iter(|| black_box(materialized_sums()));
    });

    group.bench_function("fused_scan", |b| {
        b.iter(|| black_box(fused_sums()));
    });

    group.finish();
}

criterion_group!(benches, bench_conntrack_parse);
criterion_main!(benches);
