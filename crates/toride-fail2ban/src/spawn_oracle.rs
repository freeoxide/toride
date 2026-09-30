//! Test-only spawn-counting oracle for the fail2ban doctor.
//!
//! Compiled only under `cfg(test)` (with the `doctor` feature, which is
//! default). It provides:
//!
//! - [`CountingRunner`] — a [`Runner`](crate::command::Runner) that never
//!   spawns a process, answers every command with a generic success (empty
//!   stdout, exit 0), and counts each `run` / `run_with_timeout` call as one
//!   "spawn". Cheaply cloneable: the clone shares the counter, so a test can
//!   hand one clone to [`Doctor::new`](crate::doctor::Doctor::new) and read
//!   the count from the other.
//! - [`doctor_all_spawn_report`] — runs [`DoctorScope::All`] plus every
//!   individual category against fresh runners and returns the spawn counts,
//!   so a fixed implementation can pin exact per-category and total spawn
//!   budgets. The smoke tests at the bottom of this file pin the invariants
//!   the harness itself guarantees (determinism, additivity).
//!
//! One caveat, inherited from the production code: `doctor` calls
//! [`find_binary`](crate::command::find_binary) directly (outside the
//! `Runner` trait) for `fail2ban-regex` / `journalctl` probes (`fail2ban-client`
//! lookups are memoized once per run since F13), and some spawns are gated on
//! those lookups. Counts are therefore deterministic for a *fixed host* but
//! may differ on machines with different `$PATH` contents. Pin thresholds on
//! the campaign host.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use crate::command::{CommandOutput, Runner};
use crate::doctor::{Doctor, DoctorScope};

/// One executed `(program, args)` pair, as recorded by [`CountingRunner`].
type CallEntry = (String, Vec<String>);

/// Command runner that counts spawns and always succeeds with empty output.
#[derive(Clone)]
pub struct CountingRunner {
    spawns: Arc<AtomicUsize>,
    dry_run: Arc<AtomicBool>,
    calls: Arc<Mutex<Vec<CallEntry>>>,
}

impl CountingRunner {
    /// Create a runner with a zero spawn count and dry-run disabled.
    pub fn new() -> Self {
        Self {
            spawns: Arc::new(AtomicUsize::new(0)),
            dry_run: Arc::new(AtomicBool::new(false)),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Number of commands "spawned" (i.e. `run` / `run_with_timeout` calls)
    /// so far, across all clones of this runner.
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

    /// How many commands whose program basename is `fail2ban-client` were
    /// executed with exactly these args.
    pub fn count_client_args(&self, args: &[&str]) -> usize {
        self.calls()
            .iter()
            .filter(|(program, call_args)| {
                program
                    .rsplit('/')
                    .next()
                    .is_some_and(|base| base == "fail2ban-client")
                    && call_args.len() == args.len()
                    && call_args.iter().zip(args).all(|(a, b)| a == b)
            })
            .count()
    }

    fn record_spawn(&self) {
        self.spawns.fetch_add(1, Ordering::Relaxed);
    }

    fn record_call(&self, program: &str, args: &[&str]) {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push((
                program.to_string(),
                args.iter().map(|s| (*s).to_string()).collect(),
            ));
        }
    }

    fn ok_output() -> CommandOutput {
        CommandOutput::new(String::new(), String::new(), Some(0))
    }
}

impl Default for CountingRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl Runner for CountingRunner {
    fn run(&self, program: &str, args: &[&str]) -> crate::Result<CommandOutput> {
        self.record_spawn();
        self.record_call(program, args);
        Ok(Self::ok_output())
    }

    fn run_with_timeout(
        &self,
        program: &str,
        args: &[&str],
        _timeout: Duration,
    ) -> crate::Result<CommandOutput> {
        self.record_spawn();
        self.record_call(program, args);
        Ok(Self::ok_output())
    }

    fn dry_run(&self) -> bool {
        self.dry_run.load(Ordering::Relaxed)
    }

    fn set_dry_run(&mut self, dry_run: bool) {
        self.dry_run.store(dry_run, Ordering::Relaxed);
    }
}

/// Spawn counts for one full doctor run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorSpawnReport {
    /// Spawns caused by a single `DoctorScope::All` invocation.
    pub all_run_total: usize,
    /// Spawns per individual category, in `DoctorScope::all_categories`
    /// order.
    pub per_category: Vec<(&'static str, usize)>,
}

/// Run `DoctorScope::All` and every individual category against fresh
/// [`CountingRunner`]s and report the spawn counts.
///
/// `all_run_total` is what a fixed implementation should pin as the budget
/// for one doctor pass; `per_category` shows where those spawns come from.
///
/// # Panics
///
/// Panics if any doctor scope fails against the always-ok counting runner,
/// which would indicate a doctor regression rather than a test-environment
/// problem.
#[must_use]
pub fn doctor_all_spawn_report() -> DoctorSpawnReport {
    let all_runner = CountingRunner::new();
    let doctor = Doctor::new(&all_runner);
    doctor
        .run(&DoctorScope::All)
        .expect("doctor(All) completes with always-ok responses");
    let all_run_total = all_runner.spawn_count();

    let categories: Vec<(&'static str, DoctorScope)> = vec![
        ("Binary", DoctorScope::Binary),
        ("Service", DoctorScope::Service),
        ("Config", DoctorScope::Config),
        ("LogPath", DoctorScope::LogPath),
        ("Journal", DoctorScope::Journal),
        ("Regex", DoctorScope::Regex),
        ("Action", DoctorScope::Action),
        ("Permission", DoctorScope::Permission),
        ("Safety", DoctorScope::Safety),
        ("Proxy", DoctorScope::Proxy),
    ];

    let per_category = categories
        .into_iter()
        .map(|(name, scope)| {
            let runner = CountingRunner::new();
            let doctor = Doctor::new(&runner);
            doctor
                .run(&scope)
                .expect("scoped doctor completes with always-ok responses");
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

    /// The harness counts one spawn per `run` call (across clones); dry-run
    /// state is carried but never counted as a spawn.
    #[test]
    fn counting_runner_counts_runs_not_dry_run_queries() {
        let runner = CountingRunner::new();
        let via_clone = runner.clone();

        assert!(!runner.dry_run());
        assert_eq!(runner.spawn_count(), 0, "dry_run queries are not spawns");

        via_clone
            .run("systemctl", &["is-active", "fail2ban"])
            .expect("ok");
        runner
            .run_with_timeout("nft", &["--version"], Duration::from_secs(5))
            .expect("ok");
        runner.run("iptables", &["--version"]).expect("ok");
        assert_eq!(runner.spawn_count(), 3);
        assert_eq!(via_clone.spawn_count(), 3, "clones share the counter");
    }

    /// doctor(All) spawns the same number of processes every run, and the
    /// per-category breakdown is an upper bound on the All-run total: the All
    /// arm runs exactly `DoctorScope::all_categories()`, but F13's per-run
    /// shared fetch lets the All arm reuse one `fail2ban-client status`
    /// spawn across its six jail-list consumers, so sharing can only remove
    /// spawns, never add them.
    #[test]
    fn doctor_all_spawn_report_is_deterministic_and_bounded_by_category_sum() {
        let first = doctor_all_spawn_report();
        let second = doctor_all_spawn_report();

        assert_eq!(
            first, second,
            "spawn counts must be deterministic for a fixed host and canned responses"
        );
        assert!(
            first.all_run_total > 0,
            "an always-ok environment should still exercise spawns"
        );

        let sum: usize = first.per_category.iter().map(|(_, n)| n).sum();
        assert!(
            sum >= first.all_run_total,
            "sharing the jail-list fetch across the All arm must not exceed the \
             sum of standalone category runs: {first:?}"
        );
    }

    /// F13 spawn budget: one `doctor(All)` pass used to spawn the identical
    /// `fail2ban-client status` six times (log-path, journal, regex, action,
    /// safety, and proxy checks each re-fetched and re-parsed it), for a
    /// baseline total of 21 spawns on this host. After the per-run shared
    /// fetch the measured total is 16; the budget pins that. Host-sensitive:
    /// requires `fail2ban-client` on `$PATH` (see the module docs).
    #[test]
    fn doctor_all_spawn_budget_is_bounded_after_f13() {
        let report = doctor_all_spawn_report();
        assert!(
            report.all_run_total <= 16,
            "doctor(All) must stay within the F13 spawn budget, got {report:?}"
        );
    }

    /// F13 once-per-run oracle: within one `doctor(All)` pass the jail list
    /// is fetched exactly once, however many checks consume it. No-op on a
    /// host without `fail2ban-client` on `$PATH` (nothing to share).
    #[test]
    fn doctor_all_fetches_jail_list_once() {
        let runner = CountingRunner::new();
        let doctor = Doctor::new(&runner);
        doctor
            .run(&DoctorScope::All)
            .expect("doctor(All) completes with always-ok responses");

        let client_on_path = crate::command::find_binary("fail2ban-client").is_ok();
        let expected = usize::from(client_on_path);
        assert_eq!(
            runner.count_client_args(&["status"]),
            expected,
            "the six jail-list consumers must share one `fail2ban-client status` run"
        );
    }

    /// F13 per-run freshness oracle: two consecutive `doctor(All)` runs on
    /// the same `Doctor` each fetch the jail list once — the memo is scoped
    /// to a single run, never to the `Doctor` instance.
    #[test]
    fn doctor_run_resets_the_shared_fetch_per_run() {
        let runner = CountingRunner::new();
        let doctor = Doctor::new(&runner);
        doctor.run(&DoctorScope::All).expect("first run");
        doctor.run(&DoctorScope::All).expect("second run");

        let client_on_path = crate::command::find_binary("fail2ban-client").is_ok();
        let expected = if client_on_path { 2 } else { 0 };
        assert_eq!(
            runner.count_client_args(&["status"]),
            expected,
            "each doctor run must re-fetch the jail list exactly once"
        );
    }
}
