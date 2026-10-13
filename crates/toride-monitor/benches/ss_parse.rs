use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use toride_monitor::parse::{parse_ss_output, ss_entry_to_connection};
use toride_monitor::report::ConnectionInfo;

const FIXTURE: &str = include_str!("fixtures/ss/tunap_2k.txt");

fn connections_from_fixture() -> Vec<ConnectionInfo> {
    let entries = parse_ss_output(FIXTURE).expect("fixture must parse");
    entries.iter().filter_map(ss_entry_to_connection).collect()
}

fn aggregate_entry_owned(connections: &[ConnectionInfo]) -> (u64, u64) {
    let unique_destinations = connections
        .iter()
        .map(|c| c.dst)
        .collect::<std::collections::HashSet<_>>()
        .len() as u64;

    let mut by_protocol = std::collections::HashMap::new();
    let mut by_port = std::collections::HashMap::new();
    let mut by_state = std::collections::HashMap::new();

    for conn in connections {
        *by_protocol.entry(conn.protocol.clone()).or_insert(0u64) += 1;
        *by_port.entry(conn.dst_port).or_insert(0u64) += 1;
        *by_state.entry(conn.state.clone()).or_insert(0u64) += 1;
    }

    (
        unique_destinations,
        by_protocol.len() as u64 + by_port.len() as u64 + by_state.len() as u64,
    )
}

fn aggregate_get_mut(connections: &[ConnectionInfo]) -> (u64, u64) {
    let unique_destinations = connections
        .iter()
        .map(|c| c.dst)
        .collect::<std::collections::HashSet<_>>()
        .len() as u64;

    let mut by_protocol: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut by_port: std::collections::HashMap<u16, u64> = std::collections::HashMap::new();
    let mut by_state: std::collections::HashMap<String, u64> = std::collections::HashMap::new();

    for conn in connections {
        match by_protocol.get_mut(conn.protocol.as_str()) {
            Some(count) => *count += 1,
            None => {
                by_protocol.insert(conn.protocol.clone(), 1);
            }
        }
        match by_port.get_mut(&conn.dst_port) {
            Some(count) => *count += 1,
            None => {
                by_port.insert(conn.dst_port, 1);
            }
        }
        match by_state.get_mut(conn.state.as_str()) {
            Some(count) => *count += 1,
            None => {
                by_state.insert(conn.state.clone(), 1);
            }
        }
    }

    (
        unique_destinations,
        by_protocol.len() as u64 + by_port.len() as u64 + by_state.len() as u64,
    )
}

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

fn bench_snapshot_aggregate(c: &mut Criterion) {
    let mut group = c.benchmark_group("snapshot_aggregate_2k_conns");

    let connections = connections_from_fixture();
    let owned = aggregate_entry_owned(&connections);
    let get_mut = aggregate_get_mut(&connections);
    assert_eq!(owned, get_mut, "both aggregation shapes must agree");
    assert!(!connections.is_empty(), "fixture must yield connections");

    group.bench_function("entry_owned_keys", |b| {
        b.iter(|| black_box(aggregate_entry_owned(black_box(&connections))));
    });

    group.bench_function("get_mut_borrowed_keys", |b| {
        b.iter(|| black_box(aggregate_get_mut(black_box(&connections))));
    });

    group.finish();
}

criterion_group!(benches, bench_ss_parse, bench_snapshot_aggregate);
criterion_main!(benches);
