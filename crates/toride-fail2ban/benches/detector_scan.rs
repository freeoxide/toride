//! Criterion benchmarks for the fail2ban log-detector regex scan.
//!
//! Input is a committed, deterministic 10,000-line synthetic sshd auth log
//! (`benches/fixtures/logs/sshd_auth_10k.log`, RFC 5737/3849 documentation
//! addresses only). No host binaries, no network, no generated state: every
//! scan reads the fixture read-only from disk, which is exactly the
//! production hot path (`LogDetector::scan` opens and tails the log file).
//!
//! Two regexes are measured because they exercise different extraction paths
//! in `detector.rs`:
//!
//! - `named_group_ip` — a failregex with a `(?P<ip>...)` capture, the common
//!   fail2ban filter shape.
//! - `fallback_ipv4` — a pattern with no named IP group, forcing the
//!   `FALLBACK_IPV4_RE` fallback scan over each match.
//!
//! Run scoped:
//!
//! ```text
//! cargo bench -p toride-fail2ban --bench detector_scan
//! ```

use std::hint::black_box;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use toride_fail2ban::detector::LogDetector;

/// Path to the committed fixture log.
const FIXTURE_LOG: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/benches/fixtures/logs/sshd_auth_10k.log"
);

/// Total lines in the fixture log.
const EXPECTED_LINES: u64 = 10_000;

/// Lines matching the `named_group_ip` failregex (three "Failed password"
/// shapes at i%40 in {3, 9, 17}).
const EXPECTED_FAILED_PASSWORD_MATCHES: u32 = 750;

/// Lines matching the `fallback_ipv4` pattern (the "Invalid user" shape at
/// i%40 == 27).
const EXPECTED_INVALID_USER_MATCHES: u32 = 250;

/// sshd-style failregex with a named IP capture, modelled on fail2ban's
/// stock sshd filter.
const NAMED_GROUP_IP_PATTERN: &str =
    r"Failed password for (?:invalid user )?\S+ from (?P<ip>\S+) port \d+ ssh2";

/// Pattern without a named IP group: every match must go through the
/// fallback IPv4 extraction regex.
const FALLBACK_IPV4_PATTERN: &str = r"Invalid user \S+ from \S+";

/// One-time validation that the committed fixture still has the shape the
/// expected-match constants below describe.
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

    // Regex compilation happens in setup (not measured); each sample scans
    // the full 10k-line fixture from offset 0 on a fresh detector.
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
