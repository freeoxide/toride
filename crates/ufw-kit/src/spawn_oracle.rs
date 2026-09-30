//! Test-only spawn-counting oracle for the UFW doctor.
//!
//! Compiled only under `cfg(test)` (with the `client` and `doctor` features,
//! both default). It provides:
//!
//! - [`CountingRunner`] — a [`CommandRunner`](crate::command::CommandRunner)
//!   that never spawns a process, answers every command with a generic
//!   success (empty stdout, exit 0), reports every binary as present, counts
//!   each `run` call as one "spawn", and records every executed
//!   `(program, args)` pair. Cheaply cloneable: the clone shares the counter,
//!   so a test can hand one clone to
//!   [`Ufw::with_runner`](crate::client::Ufw::with_runner) and read the count
//!   from the other.
//! - [`doctor_all_spawn_report`] — runs `doctor(DoctorScope::All)` plus every
//!   individual scope against fresh runners and returns the spawn counts,
//!   so a fixed implementation can pin exact per-category and total spawn
//!   budgets. The smoke tests at the bottom of this file pin the invariants
//!   the harness itself guarantees (determinism, per-category sum as an upper
//!   bound on the All run) plus the F09 read-document budgets: one spawn per
//!   document per `doctor(All)` run and a total well below the pre-sharing
//!   baseline of 18.
//!
//! Spawn counts are deterministic for a fixed set of canned responses: no
//! code path in `doctor.rs` conditions a spawn on host filesystem state
//! (binary presence is faked to `true`, and per-app follow-ups are driven by
//! the canned stdout, which is empty here).

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::Ufw;
use crate::command::CommandRunner;
use crate::doctor::doctor;
use crate::error::Result;
use crate::spec::{CommandResult, CommandSpec, DoctorScope};

/// One executed `(program, args)` pair, as recorded by [`CountingRunner`].
type CallEntry = (String, Vec<String>);

/// Command runner that counts spawns and always succeeds with empty output.
#[derive(Clone)]
pub struct CountingRunner {
    spawns: Arc<AtomicUsize>,
    calls: Arc<Mutex<Vec<CallEntry>>>,
}

impl CountingRunner {
    /// Create a runner with a zero spawn count.
    pub fn new() -> Self {
        Self {
            spawns: Arc::new(AtomicUsize::new(0)),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Number of commands "spawned" (i.e. `run` calls) so far, across all
    /// clones of this runner.
    pub fn spawn_count(&self) -> usize {
        self.spawns.load(Ordering::Relaxed)
    }

    /// Every executed `(program, args)` pair, in order, across all clones of
    /// this runner — for asserting *which* documents were fetched how often.
    ///
    /// Best-effort on a poisoned lock (empty log) since this is a test oracle.
    pub fn calls(&self) -> Vec<CallEntry> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }

    /// How many `ufw` commands with exactly these args were executed.
    pub fn count_ufw_args(&self, args: &[&str]) -> usize {
        self.calls()
            .iter()
            .filter(|(program, call_args)| {
                program == "ufw"
                    && call_args.len() == args.len()
                    && call_args.iter().zip(args).all(|(a, b)| a == b)
            })
            .count()
    }
}

impl Default for CountingRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandRunner for CountingRunner {
    fn run(&self, spec: &CommandSpec) -> Result<CommandResult> {
        self.spawns.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut calls) = self.calls.lock() {
            calls.push((spec.program.clone(), spec.args.clone()));
        }
        Ok(CommandResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: Some(0),
        })
    }

    /// Not a spawn: binary discovery is answered optimistically so every
    /// check proceeds down its fullest (most spawn-hungry) path.
    fn binary_exists(&self, _name: &str) -> bool {
        true
    }
}

/// Spawn counts for one full doctor run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorSpawnReport {
    /// Spawns caused by a single `doctor(DoctorScope::All)` invocation.
    pub all_run_total: usize,
    /// Spawns per individual scope, in execution order.
    pub per_category: Vec<(&'static str, usize)>,
}

/// Run `doctor(DoctorScope::All)` and every individual scope against fresh
/// [`CountingRunner`]s and report the spawn counts.
///
/// `all_run_total` is what a fixed implementation should pin as the budget
/// for one doctor pass; `per_category` shows where those spawns come from.
#[must_use]
pub fn doctor_all_spawn_report() -> DoctorSpawnReport {
    let all_runner = CountingRunner::new();
    let ufw = Ufw::with_runner(all_runner.clone());
    doctor(&ufw, DoctorScope::All).expect("doctor(All) completes with always-ok responses");
    let all_run_total = all_runner.spawn_count();

    let categories: Vec<(&'static str, DoctorScope)> = vec![
        ("Binaries", DoctorScope::Binaries),
        ("Service", DoctorScope::Service),
        ("Policy", DoctorScope::Policy),
        ("Rules", DoctorScope::Rules),
        ("Ssh", DoctorScope::Ssh),
        ("Ipv6", DoctorScope::Ipv6),
        ("Logging", DoctorScope::Logging),
        ("AppProfiles", DoctorScope::AppProfiles),
        ("Permissions", DoctorScope::Permissions),
        ("Docker", DoctorScope::Docker),
        ("Routing", DoctorScope::Routing),
    ];

    let per_category = categories
        .into_iter()
        .map(|(name, scope)| {
            let runner = CountingRunner::new();
            let ufw = Ufw::with_runner(runner.clone());
            doctor(&ufw, scope).expect("scoped doctor completes with always-ok responses");
            (name, runner.spawn_count())
        })
        .collect();

    DoctorSpawnReport {
        all_run_total,
        per_category,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The harness counts one spawn per `run` call (across clones), and
    /// `binary_exists` is free (it must not be counted as a spawn). The call
    /// log mirrors the counter one-to-one.
    #[test]
    fn counting_runner_counts_runs_not_binary_probes() {
        let runner = CountingRunner::new();
        let via_clone = runner.clone();
        let spec = CommandSpec::ufw(vec!["status".to_string()]);
        assert!(runner.binary_exists("ufw"));
        assert!(via_clone.binary_exists("iptables"));
        assert_eq!(runner.spawn_count(), 0, "binary probes are not spawns");

        via_clone.run(&spec).expect("counting runner succeeds");
        runner.run(&spec).expect("counting runner succeeds");
        runner.run(&spec).expect("counting runner succeeds");
        assert_eq!(runner.spawn_count(), 3);
        assert_eq!(via_clone.spawn_count(), 3, "clones share the counter");
        assert_eq!(runner.calls().len(), 3, "call log tracks every run");
        assert_eq!(via_clone.count_ufw_args(&["status"]), 3);
    }

    /// doctor(All) spawns the same number of processes every run, and the
    /// per-category breakdown is an upper bound on the All-run total: the All
    /// arm runs exactly the same checks as the individual scopes, but F09's
    /// client-layer read-document caches let the All arm reuse one
    /// `status` / `status verbose` / `app list` / `--version` fetch across
    /// categories, so sharing can only remove spawns, never add them.
    #[test]
    fn doctor_all_spawn_report_is_deterministic_and_bounded_by_category_sum() {
        let first = doctor_all_spawn_report();
        let second = doctor_all_spawn_report();

        assert_eq!(
            first, second,
            "spawn counts must be deterministic for fixed canned responses"
        );
        assert!(
            first.all_run_total > 0,
            "an always-ok environment should still exercise spawns"
        );

        let sum: usize = first.per_category.iter().map(|(_, n)| n).sum();
        assert!(
            sum >= first.all_run_total,
            "sharing documents across the All arm must not exceed the sum of \
             standalone category runs: {first:?}"
        );
    }

    /// F09 spawn budget: one `doctor(All)` pass re-read the same three
    /// documents (`status`, `status verbose`, `app list`) plus `--version`
    /// and `show listening` from up to 16 fetch sites, totalling 18 spawns
    /// before the client-layer caches. After the fix each document is
    /// fetched at most once per run; the budget pins the measured post-fix
    /// total (8 on an IPV6=yes host — `show listening` is skipped when IPv6
    /// is disabled, so 8 covers both).
    #[test]
    fn doctor_all_spawn_budget_is_bounded_after_f09() {
        let report = doctor_all_spawn_report();
        assert!(
            report.all_run_total <= 8,
            "doctor(All) must stay within the F09 spawn budget, got {report:?}"
        );
    }

    /// F09 once-per-document oracle: within one `doctor(All)` pass each read
    /// document is fetched exactly once, however many checks consume it
    /// (`status` ×8 sites, `status verbose` ×3, `app list` ×3, `--version`).
    #[test]
    fn doctor_all_fetches_each_read_document_once() {
        let runner = CountingRunner::new();
        let ufw = Ufw::with_runner(runner.clone());
        doctor(&ufw, DoctorScope::All).expect("doctor(All) completes");

        assert_eq!(runner.count_ufw_args(&["status"]), 1);
        assert_eq!(runner.count_ufw_args(&["status", "verbose"]), 1);
        assert_eq!(runner.count_ufw_args(&["app", "list"]), 1);
        assert_eq!(runner.count_ufw_args(&["--version"]), 1);
    }

    /// F09 cached-vs-fresh parity oracle: re-running `doctor(All)` on the
    /// SAME client (so the second pass is served from the status TTL cache
    /// and the version memo) must produce byte-identical findings to a pass
    /// on a fresh client.
    #[test]
    fn doctor_all_cached_pass_matches_fresh_findings() {
        let shared_runner = CountingRunner::new();
        let shared = Ufw::with_runner(shared_runner.clone());
        let fresh_findings = doctor(&shared, DoctorScope::All).expect("first pass");
        let cached_findings = doctor(&shared, DoctorScope::All).expect("second, cached pass");

        assert_eq!(
            fresh_findings, cached_findings,
            "a cache-served doctor pass must not change findings"
        );

        // The second pass served every read document from the client caches:
        // no additional `status` / `status verbose` / `--version` fetches.
        assert_eq!(shared_runner.count_ufw_args(&["status"]), 1);
        assert_eq!(shared_runner.count_ufw_args(&["status", "verbose"]), 1);
        assert_eq!(shared_runner.count_ufw_args(&["--version"]), 1);
    }
}
