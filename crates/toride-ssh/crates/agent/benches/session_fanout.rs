//! Times the `ControlMaster` candidate fan-out with a fake verifier
//! (ssh-data-subsystems-24).
//!
//! Each socket's `ssh -O check` spawn is replaced by a verifier that sleeps
//! a fixed delay, so the measurement isolates the bounded-concurrency sweep
//! from process-spawn cost. The in-flight counters assert the cap: at most
//! `MAX_CONCURRENT_CHECKS` verifiers overlap, and more than one does.

#[cfg(unix)]
mod bench {
    use std::hint::black_box;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use criterion::{Criterion, criterion_group};
    use toride_ssh_agent::BoxedVerifyFuture;

    const SOCKETS: usize = 24;
    const VERIFY_DELAY: Duration = Duration::from_millis(2);
    const SAMPLE_SIZE: usize = 30;
    const MEASUREMENT_TIME: Duration = Duration::from_secs(2);
    const WARM_UP_TIME: Duration = Duration::from_millis(500);

    #[cfg(unix)]
    fn bind_sockets(dir: &std::path::Path) {
        for index in 0..SOCKETS {
            let path = dir.join(format!("cm-bench-{index:02}@host:22"));
            std::os::unix::net::UnixListener::bind(path).expect("bind bench socket");
        }
    }

    #[cfg(unix)]
    fn session_fanout(c: &mut Criterion) {
        // SAFETY: set before any runtime or collector thread exists; the bench
        // process never mutates the environment again afterwards. Keeps the
        // unconditional /tmp sweep out of the measurement.
        let scratch = tempfile::tempdir().expect("scratch tempdir");
        unsafe {
            std::env::set_var("TMPDIR", scratch.path());
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("bench runtime");
        let dir = tempfile::tempdir().expect("bench tempdir");
        bind_sockets(dir.path());

        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_in_flight = Arc::new(AtomicUsize::new(0));
        let observed_max = Arc::clone(&max_in_flight);
        let verify = move |path: PathBuf| -> BoxedVerifyFuture {
            let in_flight = Arc::clone(&in_flight);
            let max_in_flight = Arc::clone(&max_in_flight);
            Box::pin(async move {
                let current = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                max_in_flight.fetch_max(current, Ordering::SeqCst);
                tokio::time::sleep(VERIFY_DELAY).await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
                let _ = path;
                Some(true)
            })
        };

        let sessions = rt
            .block_on(toride_ssh_agent::list_sessions_with(dir.path(), &verify))
            .expect("list_sessions_with answers");
        let ours = sessions
            .iter()
            .filter(|s| s.control_path.starts_with(dir.path()))
            .count();
        assert_eq!(ours, SOCKETS, "every bench socket must be reported alive");
        let observed = observed_max.load(Ordering::SeqCst);
        assert!(
            observed > 1,
            "verifiers must overlap (serial execution would defeat the fan-out): {observed}"
        );

        let mut group = c.benchmark_group("agent/session_fanout");
        group.sample_size(SAMPLE_SIZE);
        group.measurement_time(MEASUREMENT_TIME);
        group.warm_up_time(WARM_UP_TIME);
        group.bench_function("list_sessions_24_sockets", |b| {
            b.iter(|| {
                let sessions = rt
                    .block_on(toride_ssh_agent::list_sessions_with(
                        black_box(dir.path()),
                        &verify,
                    ))
                    .expect("list_sessions_with answers");
                black_box(sessions.len())
            });
        });
        group.finish();
    }

    criterion_group!(benches, session_fanout);
}

#[cfg(unix)]
pub use bench::benches;
#[cfg(unix)]
use criterion::criterion_main;

#[cfg(unix)]
criterion_main!(benches);

#[cfg(not(unix))]
fn main() {}
