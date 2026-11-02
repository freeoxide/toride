use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use toride_monitor::anomaly::AnomalyDetector;
use toride_monitor::parse::{parse_ss_output, ss_entry_to_connection};
use toride_monitor::report::{ConnectionInfo, MonitorReport};

const FIXTURE: &str = include_str!("fixtures/ss/tunap_2k.txt");

/// A `MonitorReport` with 2k connections reusing the committed `ss -tunap`
/// fixture shape, aggregated the way `MonitorClient::snapshot` aggregates.
///
/// The fixture converts to 1718 connections (wildcard listening rows are
/// skipped like the production converter skips them); it is cycled with a
/// port offset to reach exactly 2000 rows.
fn synthetic_report() -> MonitorReport {
    let entries = parse_ss_output(FIXTURE).expect("fixture must parse");
    let base: Vec<_> = entries.iter().filter_map(ss_entry_to_connection).collect();
    assert!(!base.is_empty(), "fixture must yield connections");
    let mut connections = Vec::with_capacity(2_000);
    for i in 0..2_000usize {
        let src = &base[i % base.len()];
        let cycle = u16::try_from(i / base.len()).expect("few cycles fit u16");
        connections.push(ConnectionInfo {
            dst_port: src.dst_port.wrapping_add(cycle),
            ..src.clone()
        });
    }

    let mut report = MonitorReport::empty();
    report.total_connections = connections.len() as u64;
    report.unique_destinations = connections
        .iter()
        .map(|c| c.dst)
        .collect::<std::collections::HashSet<_>>()
        .len() as u64;
    for conn in &connections {
        match report.by_protocol.get_mut(conn.protocol.as_str()) {
            Some(count) => *count += 1,
            None => {
                report.by_protocol.insert(conn.protocol.clone(), 1);
            }
        }
        match report.by_port.get_mut(&conn.dst_port) {
            Some(count) => *count += 1,
            None => {
                report.by_port.insert(conn.dst_port, 1);
            }
        }
        match report.by_state.get_mut(conn.state.as_str()) {
            Some(count) => *count += 1,
            None => {
                report.by_state.insert(conn.state.clone(), 1);
            }
        }
    }
    report.connections = connections;
    report
}

fn bench_detect_full_report(c: &mut Criterion) {
    let mut group = c.benchmark_group("detect_full_report_2k");

    let detector = AnomalyDetector::default_detector();
    let report = synthetic_report();

    let cloning = detector.detect(&report).expect("detect always reports");
    let into = detector
        .detect_into(report.clone())
        .expect("detect_into always reports");
    assert_eq!(
        cloning.findings.len(),
        into.findings.len(),
        "both entry points must produce the same findings"
    );
    assert!(
        cloning.findings.len() >= 2,
        "the 2k fixture must trip at least the volume and diversity detectors"
    );
    assert_eq!(
        std::sync::Arc::strong_count(&into.snapshot),
        1,
        "detect_into must move the report, not clone it"
    );

    group.bench_function("cloning_detect", |b| {
        b.iter(|| {
            let found = detector.detect(black_box(&report)).expect("detect reports");
            black_box(found.findings.len())
        });
    });

    group.bench_function("detect_into_arc", |b| {
        b.iter_batched(
            || report.clone(),
            |fresh| {
                let found = detector.detect_into(fresh).expect("detect_into reports");
                black_box(found.findings.len())
            },
            BatchSize::PerIteration,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_detect_full_report);
criterion_main!(benches);
