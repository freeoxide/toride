//! Test-only spawn-counting oracle for the UFW doctor.
//!
//! Compiled only under `cfg(test)` (with the `client` and `doctor` features,
//! both default). It provides:
//!
//! - [`CountingRunner`] — a [`CommandRunner`](crate::command::CommandRunner)
//!   that never spawns a process, answers every command with a generic
//!   success (empty stdout, exit 0), reports every binary as present, and
//!   counts each `run` call as one "spawn". Cheaply cloneable: the clone
//!   shares the counter, so a test can hand one clone to
//!   [`Ufw::with_runner`](crate::client::Ufw::with_runner) and read the count
//!   from the other.
//! - [`doctor_all_spawn_report`] — runs `doctor(DoctorScope::All)` plus every
//!   individual scope against fresh runners and returns the spawn counts,
//!   so a fixed implementation can pin exact per-category and total spawn
//!   budgets. The smoke tests at the bottom of this file pin the invariants
//!   the harness itself guarantees (determinism, additivity).
//!
//! Spawn counts are deterministic for a fixed set of canned responses: no
//! code path in `doctor.rs` conditions a spawn on host filesystem state
//! (binary presence is faked to `true`, and per-app follow-ups are driven by
//! the canned stdout, which is empty here).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::Ufw;
use crate::command::CommandRunner;
use crate::doctor::doctor;
use crate::error::Result;
use crate::spec::{CommandResult, CommandSpec, DoctorScope};

/// Command runner that counts spawns and always succeeds with empty output.
#[derive(Clone)]
pub struct CountingRunner {
    spawns: Arc<AtomicUsize>,
}

impl CountingRunner {
    /// Create a runner with a zero spawn count.
    pub fn new() -> Self {
        Self {
            spawns: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Number of commands "spawned" (i.e. `run` calls) so far, across all
    /// clones of this runner.
    pub fn spawn_count(&self) -> usize {
        self.spawns.load(Ordering::Relaxed)
    }
}

impl Default for CountingRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandRunner for CountingRunner {
    fn run(&self, _spec: &CommandSpec) -> Result<CommandResult> {
        self.spawns.fetch_add(1, Ordering::Relaxed);
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
    /// `binary_exists` is free (it must not be counted as a spawn).
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
    }

    /// doctor(All) spawns the same number of processes every run, and the
    /// per-category breakdown sums to the All-run total (the All arm runs
    /// exactly the same checks as the individual scopes).
    #[test]
    fn doctor_all_spawn_report_is_deterministic_and_additive() {
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
        assert_eq!(
            sum, first.all_run_total,
            "per-category spawns should sum to the doctor(All) total: {first:?}"
        );
    }
}
