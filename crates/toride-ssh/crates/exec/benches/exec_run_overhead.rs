//! Pre-spawn cost of [`ExecService::run`] against a `FakeRunner`
//! (vps-surfaces-4, foundations-0).
//!
//! `run` validates the argv, probes the ssh binary on `PATH` per call, and
//! builds the `CommandSpec` before the runner dispatches. The shared-service
//! and cold-service arms are equal today (the presence probe is uncached);
//! once the probe is cached per service instance the shared arm must drop to
//! the cold arm minus one `PATH` scan. This per-command overhead is also the
//! cost oracle for the SSH-forwarding runner adapter (ruling 7), which pays
//! it for every forwarded command.

use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use toride_runner::CommandOutput;
use toride_runner::discovery::binary_exists;
use toride_runner::fake::FakeRunner;
use toride_ssh_core::HostSpec;
use toride_ssh_exec::ExecService;

const COMMAND: [&str; 3] = ["systemctl", "is-active", "toride-web"];

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

    group.finish();
}

criterion_group!(benches, exec_run_overhead);
criterion_main!(benches);
