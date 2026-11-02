use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use toride_runner::CommandSpec;
use toride_runner::{DuctRunner, Runner};

const CAPTURE_1MB: usize = 1024 * 1024;

const CAPTURE_16MB: usize = 16 * 1024 * 1024;

const SAMPLE_SIZE: usize = 50;

const SLOW_SAMPLE_SIZE: usize = 20;

const MEASUREMENT_TIME: Duration = Duration::from_secs(3);

const OVERHEAD_MEASUREMENT_TIME: Duration = Duration::from_secs(8);

const WARM_UP_TIME: Duration = Duration::from_millis(500);

const TAR_ARGS_28: [&str; 28] = [
    "--create",
    "--gzip",
    "--file",
    "/var/backups/web-01-20261013.tar.gz",
    "--exclude=/proc",
    "--exclude=/sys",
    "--exclude=/dev",
    "--exclude=/run",
    "--exclude=/tmp",
    "--one-file-system",
    "--sparse",
    "--acls",
    "--xattrs",
    "--selinux",
    "--warning=no-file-changed",
    "--verbose",
    "--verbose",
    "--verbose",
    "/etc",
    "/srv/www",
    "/var/lib/postgresql",
    "/home",
    "/opt",
    "/usr/local",
    "/root",
    "/var/log",
    "--listed-incremental",
    "/var/backups/web.snar",
];

fn capture_spec(bytes: usize) -> CommandSpec {
    let size = bytes.to_string();
    CommandSpec::new("head").args(["-c", size.as_str(), "/dev/zero"])
}

fn overhead_spec() -> CommandSpec {
    CommandSpec::new("true").args(TAR_ARGS_28)
}

fn assert_fixture_shape() {
    let runner = DuctRunner;
    let output = runner.run(&capture_spec(CAPTURE_1MB)).expect("head runs");
    assert!(output.success);
    assert_eq!(output.exit_code, Some(0));
    assert_eq!(
        output.stdout.len(),
        CAPTURE_1MB,
        "1 MiB of NUL bytes must decode lossily to 1 MiB"
    );
    assert_eq!(output.stderr, "");

    let silent = DuctRunner::builder().log_commands(false).build();
    let output = silent.run(&overhead_spec()).expect("true runs");
    assert!(output.success);
    assert_eq!(output.exit_code, Some(0));
    assert_eq!(output.stdout, "");
}

fn bench_capture(c: &mut Criterion) {
    assert_fixture_shape();

    let runner = DuctRunner;
    let spec_one_mib = capture_spec(CAPTURE_1MB);
    let spec_sixteen_mib = capture_spec(CAPTURE_16MB);

    let mut group = c.benchmark_group("capture");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);

    group.throughput(Throughput::Bytes(CAPTURE_1MB as u64));
    group.bench_function("duct_runner/capture_1m", |b| {
        b.iter(|| {
            let output = runner
                .run(black_box(&spec_one_mib))
                .expect("capture succeeds");
            black_box(output.stdout.len());
        });
    });

    group.throughput(Throughput::Bytes(CAPTURE_16MB as u64));
    group.sample_size(SLOW_SAMPLE_SIZE);
    group.bench_function("duct_runner/capture_16m", |b| {
        b.iter(|| {
            let output = runner
                .run(black_box(&spec_sixteen_mib))
                .expect("capture succeeds");
            black_box(output.stdout.len());
        });
    });

    group.finish();
}

fn bench_per_run_overhead(c: &mut Criterion) {
    assert_fixture_shape();

    let logging = DuctRunner;
    let silent = DuctRunner::builder().log_commands(false).build();
    let spec = overhead_spec();

    let mut group = c.benchmark_group("per_run_overhead");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(OVERHEAD_MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);

    group.bench_function("log_commands_on/argv_28_true", |b| {
        b.iter(|| {
            let output = logging.run(black_box(&spec)).expect("true succeeds");
            black_box(output.exit_code);
        });
    });

    group.bench_function("log_commands_off/argv_28_true", |b| {
        b.iter(|| {
            let output = silent.run(black_box(&spec)).expect("true succeeds");
            black_box(output.exit_code);
        });
    });

    group.finish();
}

// The overhead group runs first: measured right after the 16 MiB capture
// benches, spawn latency inflates for pre and post builds alike and the
// group's verdicts flip between invocations on a shared machine.
criterion_group!(benches, bench_per_run_overhead, bench_capture);
criterion_main!(benches);
