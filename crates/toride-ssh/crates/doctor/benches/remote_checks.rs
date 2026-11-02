//! Counts runner invocations per `run_remote_checks` (ssh-data-subsystems-11)
//! and times one full remote-check pass against a counting fake runner.
//!
//! Every remote check routes its subprocess through `CliRunner`, so a fake
//! runner sees each would-be ssh handshake. The printed invocation count is
//! the fan-out oracle: the shared-`sshd -T` and bounded-concurrency work must
//! reduce it without changing the diagnostics.

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use criterion::{Criterion, criterion_group, criterion_main};
use toride_ssh_core::paths::SshPaths;
use toride_ssh_core::{CliRunner, Result};
use toride_ssh_doctor::DoctorService;

const SSHD_T_OUTPUT: &str = concat!(
    "port 22\n",
    "addressfamily any\n",
    "listenaddress 0.0.0.0:22\n",
    "protocol 2\n",
    "passwordauthentication no\n",
    "kbdinteractiveauthentication no\n",
    "pubkeyauthentication yes\n",
    "permitrootlogin prohibit-password\n",
    "maxauthtries 4\n",
    "x11forwarding no\n",
    "allowtcpforwarding yes\n",
    "strictmodes yes\n",
    "authorizedkeysfile .ssh/authorized_keys\n",
    "authorizedkeyscommand none\n",
    "authorizedprincipalsfile none\n",
);

const STORED_HOST_KEY_LINE: &str = "localhost ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB8Qm0kQx9pN2rBench7vJw4uZ1yT0hKqM5sEdRfGh6L toride-bench";

const KEYSCAN_HOST_KEY_LINE: &str =
    "localhost ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB8Qm0kQx9pN2rBench7vJw4uZ1yT0hKqM5sEdRfGh6L";

const REMOTE_AUTHORIZED_KEYS: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB8Qm0kQx9pN2rBench7vJw4uZ1yT0hKqM5sEdRfGh6L deploy@toride-bench\n";

/// Deltas under 20 percent are shared-host regime drift, matching the
/// campaign's bench gate tolerance; larger ones still fail as regressions.
const NOISE_THRESHOLD: f64 = 0.20;

#[derive(Default)]
struct CountingFakeRunner {
    total: AtomicUsize,
    per_tool: Mutex<HashMap<String, usize>>,
    sshd_t_fetches: AtomicUsize,
}

impl CountingFakeRunner {
    fn new() -> Self {
        Self::default()
    }

    fn record(&self, cmd: &str, args: &[String]) {
        self.total.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut per_tool) = self.per_tool.lock() {
            *per_tool.entry(cmd.to_owned()).or_insert(0) += 1;
        }
        let joined = args.join(" ");
        if cmd == "ssh" && joined.contains("sshd -T") {
            self.sshd_t_fetches.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn snapshot(&self) -> (usize, HashMap<String, usize>, usize) {
        (
            self.total.load(Ordering::Relaxed),
            self.per_tool.lock().map(|m| m.clone()).unwrap_or_default(),
            self.sshd_t_fetches.load(Ordering::Relaxed),
        )
    }
}

fn response_for(cmd: &str, args: &[String]) -> String {
    match cmd {
        "ssh-keygen" => format!("# Host localhost found: line 1\n{STORED_HOST_KEY_LINE}\n"),
        "ssh-keyscan" => format!("{KEYSCAN_HOST_KEY_LINE}\n"),
        "ssh" => {
            let Some(remote) = args.last() else {
                return String::new();
            };
            if remote.contains("sshd -T") {
                SSHD_T_OUTPUT.to_owned()
            } else if remote.contains("stat ") {
                "700\n".to_owned()
            } else if remote.contains("echo $HOME") {
                "/home/remote\n".to_owned()
            } else if remote.contains("cat ") {
                REMOTE_AUTHORIZED_KEYS.to_owned()
            } else {
                String::new()
            }
        }
        _ => String::new(),
    }
}

#[async_trait]
impl CliRunner for CountingFakeRunner {
    async fn run(&self, cmd: &str, args: Vec<String>) -> Result<String> {
        self.record(cmd, &args);
        Ok(response_for(cmd, &args))
    }

    async fn run_with_env(
        &self,
        cmd: &str,
        args: Vec<String>,
        _env: Vec<(String, String)>,
    ) -> Result<String> {
        self.record(cmd, &args);
        Ok(response_for(cmd, &args))
    }

    fn tool_exists(&self, name: &str) -> bool {
        matches!(name, "ssh" | "ssh-keygen" | "ssh-keyscan")
    }
}

fn fixture_ssh_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("fixture ssh tempdir");
    std::fs::write(
        dir.path().join("config"),
        "Host localhost\n  HostName 127.0.0.1\n",
    )
    .expect("write fixture ssh config");
    std::fs::write(
        dir.path().join("known_hosts"),
        format!("{STORED_HOST_KEY_LINE}\n"),
    )
    .expect("write fixture known_hosts");
    std::fs::write(dir.path().join("authorized_keys"), REMOTE_AUTHORIZED_KEYS)
        .expect("write fixture authorized_keys");
    dir
}

fn remote_checks(c: &mut Criterion) {
    // SAFETY: set before any runtime or collector thread exists; the bench
    // process never mutates the environment again afterwards.
    unsafe {
        std::env::set_var("SSH_AUTH_SOCK", "/tmp/toride-bench-agent.sock");
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench runtime");
    let dir = fixture_ssh_dir();
    let paths = SshPaths::with_dir(dir.path());
    let runner = CountingFakeRunner::new();
    let service = DoctorService::new(&paths, &runner);

    let diagnostics = rt
        .block_on(service.run_remote_checks("localhost"))
        .expect("run_remote_checks over the fake runner");
    let (total, per_tool, sshd_t) = runner.snapshot();
    println!("remote_checks: {total} runner invocations per run_all (sshd -T fetches: {sshd_t})");
    let mut per_tool: Vec<(String, usize)> = per_tool.into_iter().collect();
    per_tool.sort();
    for (tool, count) in &per_tool {
        println!("remote_checks:   {tool} x {count}");
    }
    assert!(
        !diagnostics.is_empty(),
        "fake-backed run_all must produce diagnostics"
    );

    let mut group = c.benchmark_group("remote_checks");
    group.noise_threshold(NOISE_THRESHOLD);
    group.warm_up_time(std::time::Duration::from_secs(1));
    group.measurement_time(std::time::Duration::from_secs(8));
    group.sample_size(100);
    group.bench_function("run_all", |b| {
        b.iter(|| {
            rt.block_on(service.run_remote_checks(black_box("localhost")))
                .expect("run_remote_checks over the fake runner")
        });
    });
    group.finish();
}

criterion_group!(benches, remote_checks);
criterion_main!(benches);
