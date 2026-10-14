use std::hint::black_box;
use std::path::PathBuf;

use criterion::{Criterion, criterion_group, criterion_main};
use tempfile::TempDir;
use toride_audit::AuditPaths;
use toride_audit::integrity::IntegrityManager;
use toride_runner::CommandOutput;
use toride_runner::fake::FakeRunner;

const AIDE_FIXTURE_BINARY: &str = "/opt/toride-fixtures/aide";
const STATUS_CALLS_PER_CASE: usize = 5;

fn version_output() -> CommandOutput {
    CommandOutput::from_stdout("AIDE 0.18.8\n")
}

fn clean_check_output() -> CommandOutput {
    CommandOutput::from_stdout(
        "Added entries:\t\t0\nRemoved entries:\t\t0\nChanged entries:\t\t0\n",
    )
}

fn fixture_paths() -> (TempDir, AuditPaths) {
    let tmp = TempDir::new().expect("integrity bench tempdir");
    let paths = AuditPaths {
        audit_dir: tmp.path().join("etc/audit"),
        rules_d: tmp.path().join("etc/audit/rules.d"),
        aide_conf: tmp.path().join("etc/aide.conf"),
        aide_db_dir: tmp.path().join("var/lib/aide"),
        rsyslog_conf: tmp.path().join("etc/rsyslog.conf"),
        rsyslog_d: tmp.path().join("etc/rsyslog.d"),
        logrotate_d: tmp.path().join("etc/logrotate.d"),
    };
    std::fs::create_dir_all(&paths.aide_db_dir).expect("db dir");
    std::fs::write(paths.aide_db_dir.join("aide.db.gz"), b"stub").expect("db file");
    if let Some(parent) = paths.aide_conf.parent() {
        std::fs::create_dir_all(parent).expect("etc dir");
    }
    std::fs::write(&paths.aide_conf, b"@@define DBDIR /var/lib/aide\n").expect("aide.conf");
    (tmp, paths)
}

fn check_spawn_count(runner: &FakeRunner) -> usize {
    runner
        .calls()
        .iter()
        .filter(|c| c.args.iter().any(|a| a == "--check"))
        .count()
}

fn bench_integrity_status(c: &mut Criterion) {
    let mut group = c.benchmark_group("integrity_status");

    let (_tree, paths) = fixture_paths();
    let binary = PathBuf::from(AIDE_FIXTURE_BINARY);

    group.bench_function("live_probe_fake_runner", |b| {
        b.iter(|| {
            let runner = FakeRunner::new()
                .push_response(version_output())
                .push_response(clean_check_output());
            let mgr = IntegrityManager::with_binary(&runner, &paths, binary.clone());
            let status = mgr.status().expect("status must succeed");
            black_box((status.file_count, runner.calls().len()))
        });
    });

    group.bench_function("repeat_status_x5_fake_runner", |b| {
        b.iter(|| {
            let runner = FakeRunner::new().push_response(clean_check_output());
            let mgr = IntegrityManager::with_binary(&runner, &paths, binary.clone());
            let mut last = None;
            for _ in 0..STATUS_CALLS_PER_CASE {
                last = Some(mgr.status().expect("status must succeed"));
            }
            black_box((
                last.expect("at least one status").file_count,
                runner.calls().len(),
            ))
        });
    });

    let runner = FakeRunner::new().push_response(clean_check_output());
    let mgr = IntegrityManager::with_binary(&runner, &paths, binary.clone());
    for _ in 0..STATUS_CALLS_PER_CASE {
        mgr.status().expect("status must succeed");
    }
    assert_eq!(
        check_spawn_count(&runner),
        1,
        "safety-state-9 gate: within the status TTL only the first call may spawn `aide --check`"
    );

    group.finish();
}

criterion_group!(benches, bench_integrity_status);
criterion_main!(benches);
