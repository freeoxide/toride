use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

use criterion::{Criterion, criterion_group, criterion_main};
use toride_monitor::ports::{IpVersion, PortEntry, PortProtocol, PortQuery, PortState};

const ENTRY_COUNT: usize = 2_000;

const PROCESS_NAMES: [&str; 8] = [
    "nginx",
    "sshd",
    "toride-monitor",
    "systemd-resolved",
    "DockerProxy",
    "postgres",
    "node",
    "python3",
];

fn entry(index: usize) -> PortEntry {
    let name = PROCESS_NAMES[index % PROCESS_NAMES.len()];
    PortEntry {
        protocol: if index.is_multiple_of(3) {
            PortProtocol::Udp
        } else {
            PortProtocol::Tcp
        },
        ip_version: if index.is_multiple_of(7) {
            IpVersion::V6
        } else {
            IpVersion::V4
        },
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: 10_000 + u16::try_from(index % 40_000).expect("port offset fits u16"),
        remote_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        remote_port: 0,
        state: if index.is_multiple_of(3) {
            PortState::Established
        } else {
            PortState::Listen
        },
        process_name: Some(name.to_owned()),
        pid: Some(1000 + u32::try_from(index % 500).expect("pid offset fits u32")),
    }
}

fn matches_hoisted_needle(
    needle_lower: &str,
    port: u16,
    state: &PortState,
    entry: &PortEntry,
) -> bool {
    if entry.local_port != port || &entry.state != state {
        return false;
    }
    entry
        .process_name
        .as_ref()
        .is_some_and(|pn| pn.to_lowercase().contains(needle_lower))
}

fn bench_port_query(c: &mut Criterion) {
    let mut group = c.benchmark_group("port_query_matches");

    let entries: Vec<PortEntry> = (0..ENTRY_COUNT).map(entry).collect();
    let query = PortQuery::new()
        .process_name("monitor")
        .port(10_018)
        .state(PortState::Established);

    let current_hits = entries.iter().filter(|e| query.matches(e)).count();
    let needle_lower = "monitor".to_lowercase();
    let hoisted_hits = entries
        .iter()
        .filter(|e| matches_hoisted_needle(&needle_lower, 10_018, &PortState::Established, e))
        .count();
    assert_eq!(current_hits, hoisted_hits, "both matchers must agree");
    assert!(current_hits > 0, "query must hit at least one entry");

    group.bench_function("2k_entries_current", |b| {
        b.iter(|| {
            black_box(
                entries
                    .iter()
                    .filter(|e| query.matches(black_box(e)))
                    .count(),
            )
        });
    });

    group.bench_function("2k_entries_hoisted_needle", |b| {
        b.iter(|| {
            black_box(
                entries
                    .iter()
                    .filter(|e| {
                        matches_hoisted_needle(
                            black_box(&needle_lower),
                            10_018,
                            &PortState::Established,
                            black_box(e),
                        )
                    })
                    .count(),
            )
        });
    });

    group.finish();
}

criterion_group!(benches, bench_port_query);
criterion_main!(benches);
