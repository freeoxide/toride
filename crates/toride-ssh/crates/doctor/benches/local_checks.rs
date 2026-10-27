//! Times the agent-identity `ssh-keygen -lf` fan-out with a fake probe
//! (ssh-data-subsystems-25).
//!
//! Each spawn is replaced by a probe that sleeps a fixed delay, so the case
//! isolates the bounded-concurrency sweep over an `IdentityFile` list. The
//! in-flight counters assert the probes overlap and the outputs stay in
//! input order.

use std::hint::black_box;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use toride_ssh_doctor::{KeygenProbeFuture, probe_identity_fingerprints};

const KEYS: usize = 24;
const PROBE_DELAY: Duration = Duration::from_millis(2);
/// Deltas under 20 percent are shared-host regime drift, matching the
/// campaign's bench gate tolerance; larger ones still fail as regressions.
const NOISE_THRESHOLD: f64 = 0.20;

fn local_checks(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench runtime");
    let pub_paths: Vec<std::path::PathBuf> = (0..KEYS)
        .map(|index| std::path::PathBuf::from(format!("/keys/bench-{index:02}.pub")))
        .collect();

    let in_flight = Arc::new(AtomicUsize::new(0));
    let max_in_flight = Arc::new(AtomicUsize::new(0));
    let observed_max = Arc::clone(&max_in_flight);
    let probe = move |path: &Path| -> KeygenProbeFuture {
        let in_flight = Arc::clone(&in_flight);
        let max_in_flight = Arc::clone(&max_in_flight);
        let path = path.to_path_buf();
        Box::pin(async move {
            let current = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            max_in_flight.fetch_max(current, Ordering::SeqCst);
            tokio::time::sleep(PROBE_DELAY).await;
            in_flight.fetch_sub(1, Ordering::SeqCst);
            Some(format!("256 SHA256:bench {}", path.display()))
        })
    };

    let outputs = rt.block_on(probe_identity_fingerprints(&pub_paths, &probe));
    assert!(
        outputs.iter().all(std::option::Option::is_some),
        "every probe must answer"
    );
    for (index, output) in outputs.iter().enumerate() {
        let Some(output) = output else { continue };
        assert!(
            output.ends_with(&format!("bench-{index:02}.pub")),
            "outputs must stay in input order: position {index} got {output}"
        );
    }
    let observed = observed_max.load(Ordering::SeqCst);
    assert!(
        observed > 1,
        "probes must overlap (serial execution would defeat the fan-out): {observed}"
    );

    let mut group = c.benchmark_group("local_checks");
    group.noise_threshold(NOISE_THRESHOLD);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(8));
    group.sample_size(100);
    group.bench_function("agent_identity_24_keys", |b| {
        b.iter(|| {
            let outputs = rt.block_on(probe_identity_fingerprints(black_box(&pub_paths), &probe));
            black_box(outputs.len())
        });
    });
    group.finish();
}

criterion_group!(benches, local_checks);
criterion_main!(benches);
