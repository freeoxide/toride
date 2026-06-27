//! CLI argument parsing for the updates command.
//!
//! Uses [`clap`] to define the command-line interface for managing automatic
//! security updates. This module is gated behind the `cli` feature.

use crate::client::UpdatesClient;

// ---------------------------------------------------------------------------
// CLI types
// ---------------------------------------------------------------------------

/// Top-level CLI arguments for the `toride updates` subcommand.
#[derive(Debug, Clone, clap::Parser)]
#[command(name = "updates", about = "Manage automatic security updates")]
pub struct UpdatesCli {
    /// The subcommand to execute.
    #[command(subcommand)]
    pub command: UpdatesCommand,
}

/// Subcommands for the updates CLI.
#[derive(Debug, Clone, clap::Subcommand)]
pub enum UpdatesCommand {
    /// Show the current update status.
    Status,

    /// Configure automatic updates.
    Configure(ConfigureArgs),

    /// Check for available updates without applying them.
    Check,

    /// Apply pending updates now.
    Apply,

    /// Run diagnostic checks on the update subsystem.
    Doctor,

    /// Show the update schedule.
    Schedule(ScheduleArgs),
}

/// Arguments for the `configure` subcommand.
#[derive(Debug, Clone, clap::Parser)]
#[command(about = "Configure automatic update settings")]
pub struct ConfigureArgs {
    /// Enable or disable automatic updates.
    #[arg(long, action = clap::ArgAction::Set)]
    pub auto_update: Option<bool>,

    /// Only install security updates (skip feature/bugfix updates).
    #[arg(long, action = clap::ArgAction::Set)]
    pub security_only: Option<bool>,

    /// Set the reboot policy after updates.
    #[arg(long, value_enum)]
    pub reboot: Option<RebootPolicyArg>,

    /// Add an APT origin pattern for update selection.
    #[arg(long, action = clap::ArgAction::Append)]
    pub origin: Option<Vec<String>>,
}

/// Arguments for the `schedule` subcommand.
#[derive(Debug, Clone, clap::Parser)]
#[command(about = "Manage the automatic update schedule")]
pub struct ScheduleArgs {
    /// Set the update frequency.
    #[arg(long, value_enum)]
    pub set: Option<ScheduleArg>,

    /// Set a custom systemd calendar expression.
    #[arg(long)]
    pub custom: Option<String>,

    /// Remove the current schedule.
    #[arg(long)]
    pub remove: bool,
}

/// CLI argument for schedule frequency.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ScheduleArg {
    /// Run once per day.
    Daily,
    /// Run once per week.
    Weekly,
    /// Run once per month.
    Monthly,
}

/// CLI argument for reboot policy.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum RebootPolicyArg {
    /// Never reboot automatically.
    Never,
    /// Reboot only when required by an updated package.
    WhenNeeded,
    /// Always reboot after applying updates.
    Always,
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

impl From<ScheduleArg> for crate::spec::Schedule {
    fn from(val: ScheduleArg) -> Self {
        match val {
            ScheduleArg::Daily => Self::Daily,
            ScheduleArg::Weekly => Self::Weekly,
            ScheduleArg::Monthly => Self::Monthly,
        }
    }
}

impl From<RebootPolicyArg> for crate::spec::RebootPolicy {
    fn from(val: RebootPolicyArg) -> Self {
        match val {
            RebootPolicyArg::Never => Self::Never,
            RebootPolicyArg::WhenNeeded => Self::WhenNeeded,
            RebootPolicyArg::Always => Self::Always,
        }
    }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

impl UpdatesCli {
    /// Execute the parsed subcommand against production defaults.
    ///
    /// Builds a real [`UpdatesClient`] (via [`UpdatesClient::new`], which uses
    /// `duct` and auto-detects paths) and a `DuctRunner` for the doctor /
    /// schedule paths, then dispatches every [`UpdatesCommand`] variant to its
    /// corresponding real method via [`Self::dispatch`].
    ///
    /// # Errors
    ///
    /// Propagates any error from client construction or the dispatched call.
    pub fn run(&self) -> crate::Result<()> {
        let client = UpdatesClient::new()?;
        let runner = crate::DuctRunner;
        self.dispatch(&client, &runner)
    }

    /// Execute the parsed subcommand against an injected client + runner.
    ///
    /// Every [`UpdatesCommand`] variant is mapped to its corresponding real
    /// method: `status` / `check` / `apply` / `configure` go through the
    /// [`UpdatesClient`], while `doctor` and `schedule` use
    /// [`crate::doctor::Doctor`] / [`crate::schedule::ScheduleManager`], which
    /// take `&dyn Runner` directly.
    ///
    /// The split is necessary because [`UpdatesClient`] owns its runner
    /// (`Box<dyn Runner>`) while [`crate::doctor::Doctor`] and
    /// [`crate::schedule::ScheduleManager`] *borrow* theirs. For the
    /// FakeRunner-backed tests both are built from the same shared fake, so
    /// they observe one call log.
    ///
    /// # Errors
    ///
    /// Propagates any error from the underlying client / doctor / schedule call.
    pub fn dispatch(
        &self,
        client: &UpdatesClient,
        runner: &dyn crate::Runner,
    ) -> crate::Result<()> {
        match &self.command {
            UpdatesCommand::Status => {
                let status = client.status()?;
                println!("{status:?}");
                Ok(())
            }
            UpdatesCommand::Check => {
                let (security, total) = client.check_updates()?;
                println!("{security} security / {total} total updates pending");
                Ok(())
            }
            UpdatesCommand::Apply => {
                client.apply_updates()?;
                println!("updates applied");
                Ok(())
            }
            UpdatesCommand::Configure(args) => {
                let spec = build_spec(args);
                client.configure(&spec)?;
                println!("update configuration applied");
                Ok(())
            }
            UpdatesCommand::Doctor => {
                let findings = crate::doctor::Doctor::new(runner).run()?;
                if findings.is_empty() {
                    println!("no issues found");
                } else {
                    for finding in &findings {
                        println!("{finding:?}");
                    }
                }
                Ok(())
            }
            UpdatesCommand::Schedule(args) => {
                let mgr = crate::schedule::ScheduleManager::new(runner);
                if args.remove {
                    mgr.remove_schedule()?;
                    println!("schedule removed");
                    return Ok(());
                }
                if let Some(expr) = &args.custom {
                    mgr.set_schedule(&crate::spec::Schedule::Custom(expr.clone()))?;
                    println!("schedule set to custom: {expr}");
                    return Ok(());
                }
                if let Some(freq) = args.set {
                    let schedule = crate::spec::Schedule::from(freq);
                    mgr.set_schedule(&schedule)?;
                    println!("schedule set to {schedule}");
                    return Ok(());
                }
                // No flags: print the current schedule (if any).
                match mgr.get_schedule()? {
                    Some(schedule) => println!("current schedule: {schedule}"),
                    None => println!("no schedule configured"),
                }
                Ok(())
            }
        }
    }
}

/// Build an [`UpdateSpec`] from the parsed `configure` arguments.
///
/// Unspecified fields fall back to the [`UpdateSpec::default()`] values, so a
/// bare `configure` with no flags writes the secure default spec, while a
/// partial `configure --security-only false` only overrides that one field.
fn build_spec(args: &ConfigureArgs) -> crate::spec::UpdateSpec {
    let mut spec = crate::spec::UpdateSpec::default();
    if let Some(auto) = args.auto_update {
        spec.auto_update = auto;
    }
    if let Some(security) = args.security_only {
        spec.security_only = security;
    }
    if let Some(reboot) = args.reboot {
        spec.reboot = crate::spec::RebootPolicy::from(reboot);
    }
    if let Some(origins) = args.origin.clone() {
        spec.origins = origins;
    }
    spec
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::UpdatePaths;
    use clap::Parser;
    use std::sync::Arc;
    use toride_runner::fake::FakeRunner;
    use toride_runner::{CommandOutput, CommandSpec, Runner};

    /// A shared handle to a [`FakeRunner`] that can be inspected *after* views
    /// of it have been handed to both [`UpdatesClient`] (as a `Box<dyn Runner>`)
    /// and [`crate::doctor::Doctor`] / [`crate::schedule::ScheduleManager`]
    /// (as a `&dyn Runner`).
    ///
    /// `FakeRunner` records calls into internal `Arc<Mutex<..>>` storage, so the
    /// boxed [`ArcRunner`] view and the borrowed [`ArcRunnerRef`] view observe
    /// the same call log. Mirrors the `SharedRunner` helper in `client.rs`.
    struct SharedRunner {
        inner: Arc<FakeRunner>,
        /// A long-lived borrowed view, so `runner_ref()` can return `&dyn Runner`
        /// without lifetime gymnastics at the call site.
        view: ArcRunnerRef,
    }

    impl SharedRunner {
        fn new(runner: FakeRunner) -> Self {
            let inner = Arc::new(runner);
            Self {
                view: ArcRunnerRef(inner.clone()),
                inner,
            }
        }

        /// An owning `Box<dyn Runner>` view, for `UpdatesClient::with_runner`.
        fn boxed(&self) -> Box<dyn Runner> {
            Box::new(ArcRunner(self.inner.clone()))
        }

        /// A borrowed `&dyn Runner` view, for `Doctor::new` / `ScheduleManager::new`.
        fn runner_ref(&self) -> &dyn Runner {
            &self.view
        }

        fn assert_called_with(&self, spec: &CommandSpec) {
            self.inner.assert_called_with(spec);
        }
    }

    /// Owning newtype so we can impl [`Runner`] for a shared `Arc<FakeRunner>`
    /// (orphan rule). Used to box into `Box<dyn Runner>` for the client.
    struct ArcRunner(Arc<FakeRunner>);

    impl Runner for ArcRunner {
        fn run(&self, spec: &CommandSpec) -> std::result::Result<CommandOutput, toride_runner::Error> {
            self.0.run(spec)
        }
    }

    /// By-value wrapper behind a reference, stored inside [`SharedRunner`] so a
    /// `&dyn Runner` over the shared `Arc<FakeRunner>` can be vended for the
    /// borrowed doctor / schedule paths.
    struct ArcRunnerRef(Arc<FakeRunner>);

    impl Runner for ArcRunnerRef {
        fn run(&self, spec: &CommandSpec) -> std::result::Result<CommandOutput, toride_runner::Error> {
            self.0.run(spec)
        }
    }

    /// Build a minimal [`UpdatePaths`] rooted in a temp dir so the dispatch does
    /// not touch real `/etc` paths during tests.
    fn temp_paths() -> (tempfile::TempDir, UpdatePaths) {
        let dir = tempfile::tempdir().unwrap();
        let mut paths = UpdatePaths::new();
        paths.log_file = dir.path().join("unattended-upgrades.log");
        paths.auto_upgrades_enabled = dir.path().join("20auto-upgrades");
        paths.auto_upgrades_conf = dir.path().join("50unattended-upgrades");
        paths.apt_conf_d = dir.path().join("apt.conf.d");
        paths.dnf_automatic_conf = dir.path().join("automatic.conf");
        paths.dnf_conf_d = dir.path().to_path_buf();
        paths.systemd_timer_d = dir.path().join("systemd");
        (dir, paths)
    }

    // -----------------------------------------------------------------------
    // Dispatch: `doctor` parses AND reaches the real Doctor::run path
    // -----------------------------------------------------------------------

    /// `UpdatesCli::parse_from(["toride-updates", "doctor"])` must parse into
    /// `UpdatesCommand::Doctor`, and `dispatch` must route it to
    /// [`crate::doctor::Doctor::run`]. On a host without `systemctl` the doctor
    /// short-circuits with the `auto-update.manager-not-detected` finding, which
    /// is enough to prove the dispatch reached the real doctor (it inspected the
    /// environment via the runner / `which`).
    #[test]
    fn dispatch_doctor_parses_and_invokes_real_doctor() {
        let runner = SharedRunner::new(FakeRunner::new());
        let (_dir, paths) = temp_paths();

        let cli = UpdatesCli::parse_from(["toride-updates", "doctor"]);
        assert!(
            matches!(cli.command, UpdatesCommand::Doctor),
            "parse should produce UpdatesCommand::Doctor, got {:?}",
            cli.command,
        );

        // The client variant is irrelevant for `doctor`; pass a throwaway client
        // built from the same shared runner so the assertion log is unified.
        let client = UpdatesClient::with_runner_and_paths(runner.boxed(), paths);

        cli.dispatch(&client, runner.runner_ref())
            .expect("doctor dispatch should succeed (findings, not errors)");

        // On a systemctl-less host the doctor short-circuits before any runner
        // call; on a host WITH systemctl it issues `systemctl is-active` probes.
        // Either way the dispatch must not panic. If systemctl is present the
        // FakeRunner recorded zero *matching* responses, so only assert when we
        // know probes ran.
        if which::which("systemctl").is_ok() && which::which("apt-get").is_ok() {
            runner.assert_called_with(
                &CommandSpec::new("systemctl")
                    .args(["is-active", "--quiet", "apt-daily-upgrade.timer"]),
            );
        }
    }

    // -----------------------------------------------------------------------
    // Dispatch: `check` parses AND invokes the real client backend
    // -----------------------------------------------------------------------

    /// `UpdatesCli::parse_from(["toride-updates", "check"])` must parse into
    /// `UpdatesCommand::Check` and dispatch to [`UpdatesClient::check_updates`].
    /// On an APT host that issues the real `apt-check` probe through the runner;
    /// the `FakeRunner` observes exactly that command, proving the dispatch is
    /// real glue rather than a stub.
    #[test]
    fn dispatch_check_parses_and_invokes_real_client() {
        // apt-check writes "<security>;<total>" to stderr.
        let runner = SharedRunner::new(
            FakeRunner::new().push_response(CommandOutput::from_stderr("3;7", 0)),
        );
        let (_dir, paths) = temp_paths();

        let cli = UpdatesCli::parse_from(["toride-updates", "check"]);
        assert!(
            matches!(cli.command, UpdatesCommand::Check),
            "parse should produce UpdatesCommand::Check, got {:?}",
            cli.command,
        );

        let client = UpdatesClient::with_runner_and_paths(runner.boxed(), paths);

        cli.dispatch(&client, runner.runner_ref())
            .expect("check dispatch should reach the backend and succeed");

        if which::which("apt-get").is_ok() {
            runner.assert_called_with(
                &CommandSpec::new("/usr/lib/update-notifier/apt-check"),
            );
        }
    }

    // -----------------------------------------------------------------------
    // build_spec: parsed args map onto UpdateSpec fields
    // -----------------------------------------------------------------------

    /// `build_spec` honours every `configure` flag and leaves unspecified
    /// fields at the secure default. Proves the configure dispatch will feed a
    /// correct spec to `UpdatesClient::configure`.
    #[test]
    fn build_spec_maps_every_flag() {
        use crate::spec::{RebootPolicy, Schedule};

        // Bare: secure defaults preserved.
        let bare = ConfigureArgs {
            auto_update: None,
            security_only: None,
            reboot: None,
            origin: None,
        };
        let s = build_spec(&bare);
        assert!(s.auto_update);
        assert!(s.security_only);
        assert_eq!(s.schedule, Schedule::Daily);
        assert_eq!(s.reboot, RebootPolicy::WhenNeeded);

        // All flags overridden.
        let full = ConfigureArgs {
            auto_update: Some(false),
            security_only: Some(false),
            reboot: Some(RebootPolicyArg::Always),
            origin: Some(vec!["origin=Ubuntu,codename=${distro_codename}".into()]),
        };
        let s = build_spec(&full);
        assert!(!s.auto_update);
        assert!(!s.security_only);
        assert_eq!(s.reboot, RebootPolicy::Always);
        assert_eq!(
            s.origins,
            vec!["origin=Ubuntu,codename=${distro_codename}"]
        );
    }
}
