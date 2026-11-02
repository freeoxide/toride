//! Test-only spawn-counting oracle: [`CountingRunner`] answers every command
//! with success and counts spawns; [`doctor_all_spawn_report`] reports per-scope counts.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use crate::command::{CommandOutput, Runner};
use crate::doctor::{Doctor, DoctorScope};

type CallEntry = (String, Vec<String>);

/// Command runner that counts spawns and always succeeds with empty output.
#[derive(Clone)]
pub struct CountingRunner {
    spawns: Arc<AtomicUsize>,
    dry_run: Arc<AtomicBool>,
    calls: Arc<Mutex<Vec<CallEntry>>>,
    client_status: Arc<Option<String>>,
}

impl CountingRunner {
    /// Create a runner with a zero spawn count and dry-run disabled.
    pub fn new() -> Self {
        Self {
            spawns: Arc::new(AtomicUsize::new(0)),
            dry_run: Arc::new(AtomicBool::new(false)),
            calls: Arc::new(Mutex::new(Vec::new())),
            client_status: Arc::new(None),
        }
    }

    /// Serve this canned stdout for every `fail2ban-client status` call
    /// instead of empty output, so `Jail list:`-carrying status output
    /// makes per-jail spawns countable. Consume-and-return.
    #[must_use]
    pub fn with_client_status(mut self, stdout: impl Into<String>) -> Self {
        self.client_status = Arc::new(Some(stdout.into()));
        self
    }

    fn canned_client_status(&self, program: &str, args: &[&str]) -> Option<String> {
        let is_client_status = program.rsplit('/').next() == Some("fail2ban-client")
            && args.len() == 1
            && args[0] == "status";
        is_client_status
            .then(|| self.client_status.as_ref())?
            .clone()
    }

    /// Number of commands "spawned" (i.e. `run` / `run_with_timeout` calls)
    /// so far, across all clones of this runner.
    pub fn spawn_count(&self) -> usize {
        self.spawns.load(Ordering::Relaxed)
    }

    /// Every executed `(program, args)` pair, in order, across all clones.
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
        if let Some(stdout) = self.canned_client_status(program, args) {
            return Ok(CommandOutput::new(stdout, String::new(), Some(0)));
        }
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
        if let Some(stdout) = self.canned_client_status(program, args) {
            return Ok(CommandOutput::new(stdout, String::new(), Some(0)));
        }
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
/// # Panics
/// If any doctor scope fails against the always-ok runner.
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

/// The canned `fail2ban-client status` stdout naming the two jails every
/// per-jail spawn oracle run feeds ([`CountingRunner::with_client_status`]).
pub const CANNED_JAIL_STATUS: &str =
    "Status\n|- Number of jail:      2\n`- Jail list:\tsshd, nginx\n";

/// [`doctor_all_spawn_report`] over runners that answer `fail2ban-client
/// status` with `client_status`, so per-jail spawns fire and are counted.
///
/// # Panics
/// If any doctor scope fails against the always-ok runner.
#[must_use]
pub fn doctor_all_spawn_report_with_jails(client_status: &str) -> DoctorSpawnReport {
    let all_runner = CountingRunner::new().with_client_status(client_status);
    let doctor = Doctor::new(&all_runner);
    doctor
        .run(&DoctorScope::All)
        .expect("doctor(All) completes with canned jails");
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
            let runner = CountingRunner::new().with_client_status(client_status);
            let doctor = Doctor::new(&runner);
            doctor
                .run(&scope)
                .expect("scoped doctor completes with canned jails");
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

    #[test]
    fn doctor_all_spawn_budget_is_bounded() {
        let report = doctor_all_spawn_report();
        // 17 deterministic spawns on a full host (version probes, service
        // checks, one `id -u` writability probe); 18 leaves no room for a
        // per-jail or per-action regression to hide.
        assert!(
            report.all_run_total <= 18,
            "doctor(All) must stay within its spawn budget, got {report:?}"
        );
    }

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

    #[test]
    fn canned_jail_list_makes_per_jail_spawns_countable() {
        let runner = CountingRunner::new().with_client_status(CANNED_JAIL_STATUS);
        let doctor = Doctor::new(&runner)
            .with_binary(
                "fail2ban-client",
                std::path::PathBuf::from("fail2ban-client"),
            )
            .with_binary("fail2ban-regex", std::path::PathBuf::from("fail2ban-regex"));
        doctor
            .run(&DoctorScope::All)
            .expect("doctor(All) completes with canned jails");

        for jail in ["sshd", "nginx"] {
            assert_eq!(
                runner.count_client_args(&["get", jail, "logpath"]),
                1,
                "logpath is fetched once per jail and memoized across check_log_paths, \
                 check_journal, and check_proxy"
            );
            assert_eq!(
                runner.count_client_args(&["get", jail, "actions"]),
                1,
                "actions are fetched once per jail and memoized across check_actions \
                 and check_proxy"
            );
            for key in ["backend", "failregex", "datepattern", "ignoreip"] {
                assert_eq!(
                    runner.count_client_args(&["get", jail, key]),
                    1,
                    "per-jail `{key}` spawns exactly once today"
                );
            }
        }
    }

    #[test]
    fn doctor_all_with_jails_stays_within_the_per_jail_budget() {
        let report = doctor_all_spawn_report_with_jails(CANNED_JAIL_STATUS);
        // 29 measured: 7 fixed probes plus 11 one-shot client queries shared
        // across categories; every per-jail get is memoized to one spawn.
        assert!(
            report.all_run_total <= 34,
            "doctor(All) over two jails must stay within the per-jail spawn budget, got {report:?}"
        );
    }
}
