//! Client for executing update-related commands.
//!
//! [`UpdatesClient`] wraps a [`toride_runner::Runner`] and provides high-level
//! methods for checking, applying, configuring, and querying the status of
//! automatic security updates. It dispatches to the APT ([`crate::apt`]) or
//! DNF ([`crate::dnf`]) backend based on the detected package manager.

use tracing::info;

#[cfg(feature = "apt")]
use crate::apt::AptBackend;
use crate::detect::PackageManager;
#[cfg(feature = "dnf")]
use crate::dnf::DnfBackend;
use crate::error::{Error, Result};
use crate::paths::UpdatePaths;
use crate::report::UpdateStatus;
use crate::spec::UpdateSpec;

// ---------------------------------------------------------------------------
// UpdatesClient
// -----------------------------------------------------------------------

/// Client for interacting with the system's automatic update subsystem.
///
/// Owns a boxed [`toride_runner::Runner`] for command execution and resolved
/// [`UpdatePaths`] for locating configuration files.
///
/// # Construction
///
/// - [`UpdatesClient::new`] -- production defaults using `duct`.
/// - [`UpdatesClient::with_runner`] -- inject a custom runner for testing.
pub struct UpdatesClient {
    runner: Box<dyn toride_runner::Runner>,
    paths: UpdatePaths,
}

impl UpdatesClient {
    /// Create a new client with production defaults.
    ///
    /// Uses `duct` for command execution and auto-detects update paths.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PackageDetection`] if no supported package manager is
    /// detected on the system.
    pub fn new() -> Result<Self> {
        let pkg_mgr = crate::detect::detect_package_manager();
        let paths = UpdatePaths::detect();

        if pkg_mgr == PackageManager::Unknown {
            return Err(Error::PackageDetection(
                "neither apt-get nor dnf found on $PATH".into(),
            ));
        }

        Ok(Self {
            runner: Box::new(toride_runner::DuctRunner),
            paths,
        })
    }

    /// Create a client with a custom runner (for testing).
    pub fn with_runner(runner: Box<dyn toride_runner::Runner>) -> Self {
        Self {
            runner,
            paths: UpdatePaths::new(),
        }
    }

    /// Create a client with both a custom runner and explicit paths.
    pub fn with_runner_and_paths(
        runner: Box<dyn toride_runner::Runner>,
        paths: UpdatePaths,
    ) -> Self {
        Self { runner, paths }
    }

    /// A reference to the owned runner (used to construct backends).
    fn runner_ref(&self) -> &dyn toride_runner::Runner {
        self.runner.as_ref()
    }

    /// The detected package manager.
    fn package_manager(&self) -> PackageManager {
        let _ = self;
        crate::detect::detect_package_manager()
    }

    // -----------------------------------------------------------------------
    // Operations
    // -----------------------------------------------------------------------

    /// Check for available updates and return the counts.
    ///
    /// On APT systems, runs `apt-check`. On DNF systems, runs
    /// `dnf check-update --security`. When the `apt`/`dnf` features are
    /// enabled the full backend is used; otherwise the command is constructed
    /// inline so the minimal `client` build still works.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the command fails, or
    /// [`Error::PackageDetection`] if no supported package manager is present.
    pub fn check_updates(&self) -> Result<(usize, usize)> {
        match self.package_manager() {
            PackageManager::Apt => {
                #[cfg(feature = "apt")]
                {
                    return AptBackend::with_paths(self.runner_ref(), self.paths.clone())
                        .check_updates();
                }
                #[cfg(not(feature = "apt"))]
                {
                    self.check_updates_apt_inline()
                }
            }
            PackageManager::Dnf => {
                #[cfg(feature = "dnf")]
                {
                    return DnfBackend::with_paths(self.runner_ref(), self.paths.clone())
                        .check_updates();
                }
                #[cfg(not(feature = "dnf"))]
                {
                    self.check_updates_dnf_inline()
                }
            }
            PackageManager::Unknown => Err(Error::PackageDetection(
                "no supported package manager".into(),
            )),
        }
    }

    /// Apply pending updates now.
    ///
    /// On APT systems, runs `unattended-upgrades`. On DNF systems, runs
    /// `dnf-automatic --install`. Uses the full backend when the `apt`/`dnf`
    /// features are enabled, otherwise constructs the command inline.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the update command fails.
    pub fn apply_updates(&self) -> Result<()> {
        info!("Applying pending updates");
        match self.package_manager() {
            PackageManager::Apt => {
                #[cfg(feature = "apt")]
                {
                    return AptBackend::with_paths(self.runner_ref(), self.paths.clone())
                        .apply_updates();
                }
                #[cfg(not(feature = "apt"))]
                {
                    self.apply_updates_apt_inline()
                }
            }
            PackageManager::Dnf => {
                #[cfg(feature = "dnf")]
                {
                    return DnfBackend::with_paths(self.runner_ref(), self.paths.clone())
                        .apply_updates();
                }
                #[cfg(not(feature = "dnf"))]
                {
                    self.apply_updates_dnf_inline()
                }
            }
            PackageManager::Unknown => Err(Error::PackageDetection(
                "no supported package manager".into(),
            )),
        }
    }

    /// Configure automatic updates according to the given spec.
    ///
    /// Writes the appropriate config files (via [`crate::config::ConfigManager`]
    /// when the `config` feature is enabled, which backs up existing configs
    /// and atomically renders the new ones), then enables and starts the
    /// relevant update service / timer so the new schedule takes effect
    /// immediately.
    ///
    /// On APT hosts the canonical systemd timer is `apt-daily-upgrade.timer`
    /// (the unit that triggers `unattended-upgrades`, per the Ubuntu Server
    /// "Automatic updates" documentation). On DNF hosts it is
    /// `dnf-automatic.timer`. The enable is issued as
    /// `systemctl enable --now <unit>` through the runner, so it is observable
    /// in tests via [`toride_runner::fake::FakeRunner`].
    ///
    /// When the `config` feature is disabled this returns
    /// [`Error::Other`] noting that config writing is unavailable — the
    /// spec is otherwise validated but not persisted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigWrite`] if any config file cannot be written,
    /// or [`Error::CommandFailed`] if enabling the service fails.
    pub fn configure(&self, spec: &UpdateSpec) -> Result<()> {
        info!("Configuring automatic updates");
        #[cfg(feature = "config")]
        {
            let mgr = crate::config::ConfigManager::with_paths(self.paths.clone());
            mgr.write_spec(spec)?;
            // Persisted: enable + start the timer so the new schedule is live.
            self.enable_auto_update_timer()?;
            Ok(())
        }
        #[cfg(not(feature = "config"))]
        {
            // Config persistence is optional; surface a clear error so callers
            // know the spec was not written to disk.
            let _ = spec;
            Err(Error::Other(
                "config feature is disabled; cannot write update configuration".into(),
            ))
        }
    }

    /// Enable and start the systemd timer that drives automatic updates for the
    /// detected package manager.
    ///
    /// APT: `apt-daily-upgrade.timer` (the unattended-upgrades trigger).
    /// DNF: `dnf-automatic.timer`. Unknown: no-op.
    fn enable_auto_update_timer(&self) -> Result<()> {
        let unit = match self.package_manager() {
            PackageManager::Apt => "apt-daily-upgrade.timer",
            PackageManager::Dnf => "dnf-automatic.timer",
            PackageManager::Unknown => return Ok(()),
        };
        // Insert `--` before the unit name for defense-in-depth (the backup
        // crate's systemctl helpers do the same), so a unit name can never be
        // parsed as a flag. The unit is a hardcoded literal today, but this
        // keeps the surface safe if it ever flows in from config.
        let spec = toride_runner::CommandSpec::new("systemctl").args(["enable", "--now", "--", unit]);
        self.runner.run_checked(&spec).map_err(|e| {
            Error::CommandFailed(format!("systemctl enable --now {unit} failed: {e}"))
        })?;
        Ok(())
    }

    /// Query the current update status.
    ///
    /// Returns an [`UpdateStatus`] reflecting the current state of automatic
    /// updates on this host: parses the backend's update log/journal and
    /// reports the service-active flag.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend status query fails fundamentally (a
    /// missing log file is treated as a never-run empty status, not an error).
    pub fn status(&self) -> Result<UpdateStatus> {
        info!("Querying update status");
        let mut status = match self.package_manager() {
            PackageManager::Apt => {
                #[cfg(feature = "apt")]
                {
                    AptBackend::with_paths(self.runner_ref(), self.paths.clone()).status()?
                }
                #[cfg(not(feature = "apt"))]
                {
                    self.status_apt_inline()?
                }
            }
            PackageManager::Dnf => {
                #[cfg(feature = "dnf")]
                {
                    DnfBackend::with_paths(self.runner_ref(), self.paths.clone()).status()?
                }
                #[cfg(not(feature = "dnf"))]
                {
                    self.status_dnf_inline()?
                }
            }
            PackageManager::Unknown => UpdateStatus::empty(),
        };

        // Augment with the service-active flag via systemctl is-active.
        status.service_active = self.is_service_active()?;
        Ok(status)
    }

    // -----------------------------------------------------------------------
    // Inline backend helpers (used when the apt/dnf feature modules are absent)
    // -----------------------------------------------------------------------

    #[cfg(not(feature = "apt"))]
    fn check_updates_apt_inline(&self) -> Result<(usize, usize)> {
        let spec = toride_runner::CommandSpec::new("/usr/lib/update-notifier/apt-check");
        let output = self
            .runner
            .run_checked(&spec)
            .map_err(|e| Error::CommandFailed(format!("apt-check failed: {e}")))?;
        crate::parse::parse_apt_check(&output.stderr)
    }

    #[cfg(not(feature = "apt"))]
    fn apply_updates_apt_inline(&self) -> Result<()> {
        let spec = toride_runner::CommandSpec::new("unattended-upgrades").arg("-v");
        self.runner
            .run_checked(&spec)
            .map_err(|e| Error::CommandFailed(format!("unattended-upgrades failed: {e}")))?;
        Ok(())
    }

    #[cfg(not(feature = "apt"))]
    fn status_apt_inline(&self) -> Result<UpdateStatus> {
        let log_path = &self.paths.log_file;
        if !log_path.exists() {
            return Ok(UpdateStatus::empty());
        }
        let content = std::fs::read_to_string(log_path)?;
        let mut status = crate::parse::parse_unattended_upgrades_status(&content)?;
        if content.lines().any(|l| !l.trim().is_empty()) {
            status.auto_updates_enabled = true;
        }
        Ok(status)
    }

    #[cfg(not(feature = "dnf"))]
    fn check_updates_dnf_inline(&self) -> Result<(usize, usize)> {
        let spec = toride_runner::CommandSpec::new("dnf").args(["check-update", "--security"]);
        let output = self.runner.run(&spec)?;
        match output.exit_code {
            Some(0 | 100) => crate::parse::parse_dnf_check(&output.stdout),
            None => Err(Error::CommandFailed(
                "dnf check-update produced no exit code (terminated by signal?)".to_string(),
            )),
            Some(code) => Err(Error::CommandFailed(format!(
                "dnf check-update failed (exit {code})"
            ))),
        }
    }

    #[cfg(not(feature = "dnf"))]
    fn apply_updates_dnf_inline(&self) -> Result<()> {
        let spec = toride_runner::CommandSpec::new("dnf-automatic").arg("--install");
        self.runner
            .run_checked(&spec)
            .map_err(|e| Error::CommandFailed(format!("dnf-automatic failed: {e}")))?;
        Ok(())
    }

    #[cfg(not(feature = "dnf"))]
    fn status_dnf_inline(&self) -> Result<UpdateStatus> {
        let spec = toride_runner::CommandSpec::new("journalctl").args([
            "-u",
            "dnf-automatic",
            "--no-pager",
            "-n",
            "50",
        ]);
        match self.runner.run(&spec) {
            Ok(output) if output.success => {
                crate::parse::parse_dnf_automatic_journal(&output.stdout)
            }
            Ok(_) | Err(_) => Ok(UpdateStatus::empty()),
        }
    }

    // -----------------------------------------------------------------------
    // Service helper
    // -----------------------------------------------------------------------

    /// Probe whether the auto-update service is currently active.
    ///
    /// Returns `false` (rather than an error) when the package manager is
    /// unknown or `systemctl is-active` returns a non-zero exit, since an
    /// inactive service is a legitimate status, not a failure.
    fn is_service_active(&self) -> Result<bool> {
        let service = match self.package_manager() {
            PackageManager::Apt => "unattended-upgrades",
            PackageManager::Dnf => "dnf-automatic.timer",
            PackageManager::Unknown => return Ok(false),
        };
        let spec =
            toride_runner::CommandSpec::new("systemctl").args(["is-active", "--quiet", service]);
        // A non-zero exit (service inactive) is not a runner error here.
        let output = self.runner.run(&spec)?;
        Ok(output.success)
    }
}

impl Default for UpdatesClient {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            runner: Box::new(toride_runner::DuctRunner),
            paths: UpdatePaths::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "config")]
    use crate::spec::{RebootPolicy, Schedule};
    use std::sync::Arc;
    use toride_runner::fake::FakeRunner;
    use toride_runner::{CommandOutput, CommandSpec, Runner};

    /// A shared handle to a [`FakeRunner`] that can be inspected *after* the
    /// owning `Box<dyn Runner>` has been handed to a client.
    ///
    /// `FakeRunner` records calls into internal `Arc<Mutex<..>>` storage, so an
    /// `Arc<FakeRunner>` and the boxed [`ArcRunner`] view over it observe the
    /// same call log. This avoids needing `FakeRunner: Clone` at the call site.
    struct SharedRunner {
        inner: Arc<FakeRunner>,
    }

    impl SharedRunner {
        fn new(runner: FakeRunner) -> Self {
            Self {
                inner: Arc::new(runner),
            }
        }

        /// Produce an owning `Box<dyn Runner>` view over the shared runner.
        fn boxed(&self) -> Box<dyn Runner> {
            Box::new(ArcRunner(self.inner.clone()))
        }

        fn assert_called_with(&self, spec: &CommandSpec) {
            self.inner.assert_called_with(spec);
        }
    }

    /// Newtype wrapper so we can implement [`Runner`] for a shared
    /// `Arc<FakeRunner>` without running afoul of the orphan rule.
    struct ArcRunner(Arc<FakeRunner>);

    impl Runner for ArcRunner {
        fn run(
            &self,
            spec: &CommandSpec,
        ) -> std::result::Result<CommandOutput, toride_runner::Error> {
            self.0.run(spec)
        }
    }

    fn apt_host() -> bool {
        which::which("apt-get").is_ok()
    }

    fn dnf_host() -> bool {
        which::which("dnf").is_ok()
    }

    #[test]
    fn apply_updates_dispatches_to_backend() {
        let runner =
            SharedRunner::new(FakeRunner::new().push_response(CommandOutput::from_stdout("done")));
        let client = UpdatesClient::with_runner(runner.boxed());
        let result = client.apply_updates();
        if apt_host() {
            result.unwrap();
            runner.assert_called_with(&CommandSpec::new("unattended-upgrades").arg("-v"));
        } else if dnf_host() {
            result.unwrap();
            runner.assert_called_with(&CommandSpec::new("dnf-automatic").arg("--install"));
        } else {
            assert!(result.is_err(), "unknown host should error");
        }
    }

    #[test]
    fn status_augments_service_active_via_systemctl() {
        // Missing log file -> backend status empty; then is_service_active is
        // probed via `systemctl is-active --quiet`.
        let dir = tempfile::tempdir().unwrap();
        let mut paths = UpdatePaths::new();
        paths.log_file = dir.path().join("missing.log");

        let runner = SharedRunner::new(
            FakeRunner::new().push_response(CommandOutput::from_stdout("active")),
        );
        let client = UpdatesClient::with_runner_and_paths(runner.boxed(), paths);
        let status = client.status().unwrap();
        if apt_host() {
            assert!(
                status.service_active,
                "service_active should reflect systemctl"
            );
            runner.assert_called_with(&CommandSpec::new("systemctl").args([
                "is-active",
                "--quiet",
                "unattended-upgrades",
            ]));
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn configure_writes_config_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut paths = UpdatePaths::new();
        let apt_dir = dir.path().join("apt.conf.d");
        std::fs::create_dir_all(&apt_dir).unwrap();
        paths.auto_upgrades_conf = apt_dir.join("50unattended-upgrades");
        paths.auto_upgrades_enabled = apt_dir.join("20auto-upgrades");
        paths.apt_conf_d = apt_dir.clone();

        // configure() now enables the timer after writing configs, so the
        // runner needs a successful response for `systemctl enable --now`.
        let runner =
            SharedRunner::new(FakeRunner::new().push_response(CommandOutput::from_stdout("")));
        let client = UpdatesClient::with_runner_and_paths(runner.boxed(), paths.clone());
        let spec = UpdateSpec {
            auto_update: true,
            security_only: true,
            schedule: Schedule::Daily,
            reboot: RebootPolicy::WhenNeeded,
            origins: vec![],
        };
        if apt_host() {
            client.configure(&spec).unwrap();
            let written = std::fs::read_to_string(&paths.auto_upgrades_enabled).unwrap();
            assert!(written.contains("APT::Periodic::Update-Package-Lists"));
        }
    }

    /// `configure()` must enable the auto-update systemd timer after writing
    /// the config files, so the new schedule takes effect immediately.
    ///
    /// Per the Ubuntu Server "Automatic updates" docs, the systemd timer that
    /// drives `unattended-upgrades` is `apt-daily-upgrade.timer`.
    /// https://ubuntu.com/server/docs/how-to/software/automatic-updates/
    #[cfg(feature = "config")]
    #[test]
    fn configure_enables_apt_timer_on_apt_host() {
        let dir = tempfile::tempdir().unwrap();
        let mut paths = UpdatePaths::new();
        let apt_dir = dir.path().join("apt.conf.d");
        std::fs::create_dir_all(&apt_dir).unwrap();
        paths.auto_upgrades_conf = apt_dir.join("50unattended-upgrades");
        paths.auto_upgrades_enabled = apt_dir.join("20auto-upgrades");
        paths.apt_conf_d = apt_dir.clone();

        let runner =
            SharedRunner::new(FakeRunner::new().push_response(CommandOutput::from_stdout("")));
        let client = UpdatesClient::with_runner_and_paths(runner.boxed(), paths.clone());
        if apt_host() {
            client.configure(&UpdateSpec::default()).unwrap();
            runner.assert_called_with(&CommandSpec::new("systemctl").args([
                "enable",
                "--now",
                "apt-daily-upgrade.timer",
            ]));
        }
    }

    /// On DNF hosts `configure()` enables `dnf-automatic.timer`.
    #[cfg(feature = "config")]
    #[test]
    fn configure_enables_dnf_timer_on_dnf_host() {
        let dir = tempfile::tempdir().unwrap();
        let mut paths = UpdatePaths::new();
        paths.dnf_automatic_conf = dir.path().join("automatic.conf");
        paths.dnf_conf_d = dir.path().to_path_buf();

        let runner =
            SharedRunner::new(FakeRunner::new().push_response(CommandOutput::from_stdout("")));
        let client = UpdatesClient::with_runner_and_paths(runner.boxed(), paths.clone());
        if dnf_host() {
            client.configure(&UpdateSpec::default()).unwrap();
            runner.assert_called_with(&CommandSpec::new("systemctl").args([
                "enable",
                "--now",
                "dnf-automatic.timer",
            ]));
        }
    }

    #[test]
    fn configure_returns_clear_error_without_config_feature() {
        // Only the disabled-feature branch is host-independent and worth
        // asserting here; the write path is covered by configure_writes_config_files.
        #[cfg(not(feature = "config"))]
        {
            let runner = SharedRunner::new(FakeRunner::new());
            let client = UpdatesClient::with_runner(runner.boxed());
            let err = client.configure(&UpdateSpec::default()).unwrap_err();
            assert!(matches!(err, Error::Other(_)));
        }
        #[cfg(feature = "config")]
        {
            // No-op: the write path is tested above.
        }
    }

    #[test]
    fn with_runner_keeps_runner_alive() {
        let runner = SharedRunner::new(FakeRunner::new());
        let _client = UpdatesClient::with_runner(runner.boxed());
    }
}
