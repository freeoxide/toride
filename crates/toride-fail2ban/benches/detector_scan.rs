use std::hint::black_box;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use toride_fail2ban::detector::LogDetector;

const FIXTURE_LOG: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/benches/fixtures/logs/sshd_auth_10k.log"
);

const EXPECTED_LINES: u64 = 10_000;

const EXPECTED_FAILED_PASSWORD_MATCHES: u32 = 750;

const EXPECTED_INVALID_USER_MATCHES: u32 = 250;

const NAMED_GROUP_IP_PATTERN: &str =
    r"Failed password for (?:invalid user )?\S+ from (?P<ip>\S+) port \d+ ssh2";

const FALLBACK_IPV4_PATTERN: &str = r"Invalid user \S+ from \S+";

fn assert_fixture_shape() {
    let mut detector = LogDetector::new(
        "fixture-check",
        std::path::Path::new(FIXTURE_LOG),
        NAMED_GROUP_IP_PATTERN,
    )
    .expect("named-group failregex compiles");
    let result = detector.scan().expect("fixture scans cleanly");
    assert_eq!(result.lines_scanned, EXPECTED_LINES);
    assert_eq!(result.matches_found, EXPECTED_FAILED_PASSWORD_MATCHES);
    assert_eq!(
        result.new_bans.len(),
        EXPECTED_FAILED_PASSWORD_MATCHES as usize,
        "every named-group match should yield a ban candidate"
    );

    let mut detector = LogDetector::new(
        "fixture-check",
        std::path::Path::new(FIXTURE_LOG),
        FALLBACK_IPV4_PATTERN,
    )
    .expect("fallback failregex compiles");
    let result = detector.scan().expect("fixture scans cleanly");
    assert_eq!(result.matches_found, EXPECTED_INVALID_USER_MATCHES);
}

fn bench_detector_scan(c: &mut Criterion) {
    assert_fixture_shape();

    let log_path = std::path::Path::new(FIXTURE_LOG);
    let log_bytes = std::fs::metadata(log_path).expect("fixture present").len() as u64;

    let mut group = c.benchmark_group("detector_scan");
    group.throughput(Throughput::Bytes(log_bytes));

    group.bench_function("named_group_ip/ssh_failed_password_10k", |b| {
        b.iter_batched(
            || {
                LogDetector::new("bench-sshd", log_path, NAMED_GROUP_IP_PATTERN)
                    .expect("failregex compiles")
            },
            |mut detector| {
                let result = detector.scan().expect("scan succeeds");
                black_box(result.matches_found)
            },
            BatchSize::PerIteration,
        );
    });

    group.bench_function("fallback_ipv4/invalid_user_10k", |b| {
        b.iter_batched(
            || {
                LogDetector::new("bench-sshd", log_path, FALLBACK_IPV4_PATTERN)
                    .expect("failregex compiles")
            },
            |mut detector| {
                let result = detector.scan().expect("scan succeeds");
                black_box(result.matches_found)
            },
            BatchSize::PerIteration,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_detector_scan);
criterion_main!(benches);
