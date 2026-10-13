//! Per-call staging cost of [`UploadService::upload`] against a `FakeRunner`
//! (vps-surfaces-13, vps-surfaces-4).
//!
//! Every `upload` call canonicalizes the local path, probes the sftp binary
//! on `PATH`, stages a private tempdir plus a `0o600` batch file, dispatches
//! the runner, and removes the staging whether the transfer succeeds or
//! fails. With the fake runner the subprocess cost is zero, so the measured
//! time is exactly the staging overhead the `upload_many` batching must
//! amortize. The shared-service and cold-service arms are equal today; once
//! the presence probe is cached per service instance only the cold arm keeps
//! paying a `PATH` scan.

use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use toride_runner::CommandOutput;
use toride_runner::discovery::binary_exists;
use toride_runner::fake::FakeRunner;
use toride_ssh_core::HostSpec;
use toride_ssh_upload::{RemotePath, UploadService};

const PAYLOAD: &[u8] = &[b'x'; 4096];

fn upload_stage_overhead(c: &mut Criterion) {
    assert!(
        binary_exists("sftp"),
        "this bench needs a real `sftp` binary on PATH for the presence probe"
    );

    let host = HostSpec::parse("root@203.0.113.10").expect("bench host parses");
    let remote = RemotePath::parse("/etc/toride/app.conf").expect("bench remote path parses");
    let payload = tempfile::NamedTempFile::new().expect("payload temp file");
    std::fs::write(payload.path(), PAYLOAD).expect("write payload fixture");

    let fake = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
    let shared = UploadService::new(Box::new(fake.clone()));

    let mut group = c.benchmark_group("upload_stage_overhead");
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(2));
    group.sample_size(20);

    group.bench_function("upload_stage_shared_service", |b| {
        b.iter(|| {
            black_box(
                shared
                    .upload(black_box(&host), black_box(payload.path()), black_box(&remote))
                    .expect("fake-backed upload succeeds"),
            )
        });
    });

    group.bench_function("upload_stage_cold_service", |b| {
        b.iter(|| {
            let service = UploadService::new(Box::new(fake.clone()));
            black_box(
                service
                    .upload(black_box(&host), black_box(payload.path()), black_box(&remote))
                    .expect("fake-backed upload succeeds"),
            )
        });
    });

    group.finish();
}

criterion_group!(benches, upload_stage_overhead);
criterion_main!(benches);
