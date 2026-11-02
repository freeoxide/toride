//! Pre-spawn cost of [`ExecService::run`] against a `FakeRunner`
//! (vps-surfaces-4, foundations-0).
//!
//! `run` validates the argv, probes the ssh binary on `PATH`, and builds the
//! `CommandSpec` before the runner dispatches. The probe is cached per
//! service instance once positive, so the shared-service arm measures
//! validate-plus-spec-build only, while the cold-service arm constructs a
//! fresh service per iteration and pays one `PATH` scan every time; the
//! delta between the two arms is that scan's cost. This per-command overhead
//! is also the cost oracle for the SSH-forwarding runner adapter (ruling 7),
//! which pays it for every forwarded command.

use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use toride_runner::CommandOutput;
use toride_runner::CommandSpec;
use toride_runner::Runner as _;
use toride_runner::discovery::binary_exists;
use toride_runner::fake::FakeRunner;
use toride_ssh_core::HostSpec;
use toride_ssh_exec::{ExecService, SshRunner};

const COMMAND: [&str; 3] = ["systemctl", "is-active", "toride-web"];

const LOCAL_SPEC_ARGS: [&str; 1] = ["is-active"];

fn exec_run_overhead(c: &mut Criterion) {
    assert!(
        binary_exists("ssh"),
        "this bench needs a real `ssh` binary on PATH for the presence probe"
    );

    let host = HostSpec::parse("root@203.0.113.10").expect("bench host parses");
    let fake = FakeRunner::new().push_response(CommandOutput::from_stdout("active\n"));
    let shared = ExecService::new(Box::new(fake.clone()));

    let mut group = c.benchmark_group("exec_run_overhead");
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(2));
    group.sample_size(20);

    group.bench_function("presence_probe", |b| {
        b.iter(|| black_box(binary_exists(black_box("ssh"))));
    });

    group.bench_function("run_shared_service", |b| {
        b.iter(|| {
            black_box(
                shared
                    .run(black_box(&host), black_box(&COMMAND))
                    .expect("fake-backed run succeeds"),
            )
        });
    });

    group.bench_function("run_cold_service", |b| {
        b.iter(|| {
            let service = ExecService::new(Box::new(fake.clone()));
            black_box(
                service
                    .run(black_box(&host), black_box(&COMMAND))
                    .expect("fake-backed run succeeds"),
            )
        });
    });

    group.bench_function("run_ssh_runner_adapter", |b| {
        let adapter = SshRunner::new(Box::new(fake.clone()), host.clone());
        b.iter(|| {
            let spec = CommandSpec::new("systemctl").args(LOCAL_SPEC_ARGS);
            black_box(
                adapter
                    .run(black_box(&spec))
                    .expect("fake-backed forwarded run succeeds"),
            )
        });
    });

    group.finish();
}

criterion_group!(benches, exec_run_overhead);
criterion_main!(benches);
