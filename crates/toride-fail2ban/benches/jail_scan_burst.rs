use std::hint::black_box;
use std::path::PathBuf;
use std::time::Duration;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use toride_fail2ban::command::{CommandOutput, Runner};
use toride_fail2ban::config::ResolvedJail;
use toride_fail2ban::jail::Jail;
use toride_fail2ban::store::Store;
use toride_fail2ban::types::ExecutionMode;

const FIXTURE_LOG: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/benches/fixtures/logs/sshd_auth_10k.log"
);

const EXPECTED_LINES: u64 = 10_000;
const EXPECTED_MATCHES: usize = 750;
const EXPECTED_DISTINCT_IPS: usize = 377;

const PATTERN: &str =
    r"Failed password for (?:invalid user )?\S+ from (?P<ip>\S+) port \d+ ssh2";

const SAMPLE_SIZE: usize = 30;
const MEASUREMENT_TIME: Duration = Duration::from_secs(2);
const WARM_UP_TIME: Duration = Duration::from_millis(500);

struct NoopRunner {
    dry_run: bool,
}

impl Runner for NoopRunner {
    fn run(&self, _program: &str, _args: &[&str]) -> toride_fail2ban::Result<CommandOutput> {
        Ok(CommandOutput::new(String::new(), String::new(), Some(0)))
    }

    fn run_with_timeout(
        &self,
        _program: &str,
        _args: &[&str],
        _timeout: Duration,
    ) -> toride_fail2ban::Result<CommandOutput> {
        Ok(CommandOutput::new(String::new(), String::new(), Some(0)))
    }

    fn dry_run(&self) -> bool {
        self.dry_run
    }

    fn set_dry_run(&mut self, dry_run: bool) {
        self.dry_run = dry_run;
    }
}

fn jail_config(log_path: PathBuf) -> ResolvedJail {
    ResolvedJail {
        name: "bench-sshd".to_owned(),
        enabled: true,
        log_path,
        pattern: PATTERN.to_owned(),
        find_time: 600,
        ban_time: 3600,
        max_retry: 1,
        ban_action: "ban".to_owned(),
        unban_action: "unban".to_owned(),
        ignore_ips: Vec::new(),
    }
}

fn scan_once(store_path: &std::path::Path) -> (usize, u32, u64) {
    let runner = NoopRunner { dry_run: false };
    let mut jail = Jail::new(
        jail_config(PathBuf::from(FIXTURE_LOG)),
        Store::new(store_path.to_path_buf()),
        None,
        Box::new(runner),
    )
    .expect("jail builds");
    let result = jail.scan(ExecutionMode::DryRun).expect("scan succeeds");
    (
        result.new_bans.len(),
        result.matches_found,
        result.lines_scanned,
    )
}

fn oracle(store_path: &std::path::Path) {
    let (bans, matches, lines) = scan_once(store_path);
    assert_eq!(lines, EXPECTED_LINES);
    assert_eq!(
        matches as usize, EXPECTED_MATCHES,
        "the fixture yields 750 named-group matches"
    );
    assert_eq!(
        bans, EXPECTED_DISTINCT_IPS,
        "max_retry=1 persists one ban per distinct IP; repeat hits answer AlreadyBanned"
    );

    let data = Store::new(store_path.to_path_buf())
        .load()
        .expect("store reads back");
    assert_eq!(data.active_bans.len(), EXPECTED_DISTINCT_IPS);
    assert_eq!(
        data.journals.len(),
        1,
        "the scan persists its journal in the same store"
    );

    let (bans_again, _, _) = scan_once(store_path);
    assert_eq!(
        bans_again, 0,
        "a fresh jail over the persisted journal re-scans nothing"
    );
}

fn jail_scan_burst(c: &mut Criterion) {
    let dir = tempfile::tempdir().expect("temp dir");
    oracle(&dir.path().join("oracle-bans.json"));
    let log_bytes = std::fs::metadata(FIXTURE_LOG)
        .expect("fixture present")
        .len() as u64;

    let mut group = c.benchmark_group("jail_scan_burst");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);
    group.throughput(Throughput::Bytes(log_bytes));

    group.bench_function("scan_and_persist_10k_dry_run", |b| {
        b.iter(|| {
            let dir = tempfile::tempdir().expect("fresh store dir");
            let bans = scan_once(&dir.path().join("bans.json")).0;
            black_box(bans)
        });
    });

    group.finish();
}

criterion_group!(benches, jail_scan_burst);
criterion_main!(benches);
