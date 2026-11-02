use std::hint::black_box;
use std::path::PathBuf;
use std::time::Duration;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use toride_runner::fake::FakeRunner;
use toride_service::ServiceManager;
use toride_service::ledger::{ActionKind, ActionLedger, ActionRecord};

const UNIT_NAME: &str = "bench.service";

const UNIT_CONTENTS: &str = "[Unit]\nDescription=bench unit\n\n[Service]\nExecStart=/bin/true\n";

const EXPECTED_DEPLOY_SPAWNS: usize = 4;

const SAMPLE_SIZE: usize = 30;
const MEASUREMENT_TIME: Duration = Duration::from_secs(2);
const WARM_UP_TIME: Duration = Duration::from_millis(500);

fn deploy_rig(units_root: &std::path::Path) -> (FakeRunner, ServiceManager) {
    let fake = FakeRunner::new()
        .push_response(toride_runner::CommandOutput::from_stdout(""))
        .push_response(toride_runner::CommandOutput::from_stdout("enabled\n"))
        .push_response(toride_runner::CommandOutput::from_stdout(""))
        .push_response(toride_runner::CommandOutput::from_stdout("active\n"));
    let manager = ServiceManager::with_units_root(Box::new(fake.clone()), units_root);
    (fake, manager)
}

fn systemctl_calls(fake: &FakeRunner) -> Vec<(String, Vec<String>)> {
    fake.calls()
        .into_iter()
        .map(|spec| (spec.program.clone(), spec.args.clone()))
        .collect()
}

fn oracle(units_root: &std::path::Path) {
    let (fake, manager) = deploy_rig(units_root);
    manager
        .deploy_unit(UNIT_NAME, UNIT_CONTENTS)
        .unwrap_or_else(|error| panic!("deploy failed: {error}"));

    let calls = systemctl_calls(&fake);
    assert_eq!(
        calls.len(),
        EXPECTED_DEPLOY_SPAWNS,
        "the happy-path deploy of an already-enabled unit skips the no-op enable spawn"
    );
    assert_eq!(
        calls,
        vec![
            ("systemctl".to_owned(), vec!["daemon-reload".to_owned()]),
            (
                "systemctl".to_owned(),
                vec![
                    "is-enabled".to_owned(),
                    "--".to_owned(),
                    UNIT_NAME.to_owned()
                ]
            ),
            (
                "systemctl".to_owned(),
                vec!["start".to_owned(), "--".to_owned(), UNIT_NAME.to_owned()]
            ),
            (
                "systemctl".to_owned(),
                vec![
                    "is-active".to_owned(),
                    "--".to_owned(),
                    UNIT_NAME.to_owned()
                ]
            ),
        ],
        "the exact argv sequence per deploy, pinned like the manager test"
    );
    assert_eq!(
        std::fs::read_to_string(units_root.join(UNIT_NAME)).expect("unit file readable"),
        UNIT_CONTENTS
    );
}

fn deploy_unit_bench(criterion: &mut Criterion) {
    let rig_dir = tempfile::tempdir().expect("temp dir");
    oracle(rig_dir.path());

    let mut group = criterion.benchmark_group("deploy_unit");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);

    group.bench_function("counted_five_spawn_deploy", |b| {
        b.iter_batched(
            || tempfile::tempdir().expect("fresh units root"),
            |dir| {
                let (_fake, manager) = deploy_rig(dir.path());
                manager
                    .deploy_unit(black_box(UNIT_NAME), black_box(UNIT_CONTENTS))
                    .expect("deploy succeeds");
                black_box(dir.path().join(UNIT_NAME))
            },
            BatchSize::PerIteration,
        );
    });

    group.finish();
}

/// The per-deploy ledger write, isolated so it stays its own tracked
/// metric under the deploy baseline: one load-plus-atomic-save of a
/// one-record document on a fresh ledger, exactly what `deploy_unit`
/// pays after its activity check.
fn ledger_append_bench(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("deploy_unit");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);

    group.bench_function("ledger_append_single_record", |b| {
        b.iter_batched(
            || tempfile::tempdir().expect("fresh ledger root"),
            |dir| {
                let ledger = ActionLedger::in_root(dir.path());
                ledger
                    .append(black_box(ActionRecord::now(ActionKind::UnitDeployed {
                        unit: UNIT_NAME.to_owned(),
                    })))
                    .expect("ledger append succeeds");
                black_box(ledger)
            },
            BatchSize::PerIteration,
        );
    });

    group.finish();
}

fn duct_leg(criterion: &mut Criterion) {
    if std::env::var_os("TORIDE_BENCH_DEPLOY_UNIT_DUCT").is_none() {
        return;
    }

    let shim_dir = tempfile::tempdir().expect("temp dir");
    let shim_path: PathBuf = shim_dir.path().join("systemctl");
    std::fs::write(&shim_path, "#!/bin/sh\nexit 0\n").expect("systemctl shim writable");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&shim_path, std::fs::Permissions::from_mode(0o755))
            .expect("systemctl shim executable");
    }

    let mut path = shim_dir.path().to_path_buf().into_os_string();
    path.push(":");
    if let Some(existing) = std::env::var_os("PATH") {
        path.push(existing);
    }
    unsafe { std::env::set_var("PATH", path) };

    let units_root = tempfile::tempdir().expect("temp dir");
    let manager =
        ServiceManager::with_units_root(Box::new(toride_runner::DuctRunner), units_root.path());

    let mut group = criterion.benchmark_group("deploy_unit");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);
    group.bench_function("duct_real_runner_deploy", |b| {
        b.iter(|| {
            manager
                .deploy_unit(black_box(UNIT_NAME), black_box(UNIT_CONTENTS))
                .expect("deploy succeeds against the systemctl shim");
        });
    });
    group.finish();
}

criterion_group!(benches, deploy_unit_bench, ledger_append_bench, duct_leg);
criterion_main!(benches);
