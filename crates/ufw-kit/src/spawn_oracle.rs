use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::Ufw;
use crate::command::CommandRunner;
use crate::doctor::doctor;
use crate::error::Result;
use crate::spec::{CommandResult, CommandSpec, DoctorScope};

type CallEntry = (String, Vec<String>);

#[derive(Clone)]
pub struct CountingRunner {
    spawns: Arc<AtomicUsize>,
    calls: Arc<Mutex<Vec<CallEntry>>>,
}

impl CountingRunner {
    pub fn new() -> Self {
        Self {
            spawns: Arc::new(AtomicUsize::new(0)),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn spawn_count(&self) -> usize {
        self.spawns.load(Ordering::Relaxed)
    }

    pub fn calls(&self) -> Vec<CallEntry> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }

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

    fn binary_exists(&self, _name: &str) -> bool {
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorSpawnReport {
    pub all_run_total: usize,
    pub per_category: Vec<(&'static str, usize)>,
}

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

    #[test]
    fn doctor_all_spawn_budget_is_bounded_after_f09() {
        let report = doctor_all_spawn_report();
        assert!(
            report.all_run_total <= 8,
            "doctor(All) must stay within the F09 spawn budget, got {report:?}"
        );
    }

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

        assert_eq!(shared_runner.count_ufw_args(&["status"]), 1);
        assert_eq!(shared_runner.count_ufw_args(&["status", "verbose"]), 1);
        assert_eq!(shared_runner.count_ufw_args(&["--version"]), 1);
    }
}
