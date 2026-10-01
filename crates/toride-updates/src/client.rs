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

/// Client for the host's automatic update subsystem (APT or DNF backend).
pub struct UpdatesClient {
    runner: Box<dyn toride_runner::Runner>,
    paths: UpdatePaths,
    pkg_mgr: PackageManager,
}

impl UpdatesClient {
    /// Create a client with production defaults (`duct` runner, detected paths).
    /// Returns [`Error::PackageDetection`] if no supported manager is on `$PATH`.
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
            pkg_mgr,
        })
    }

    /// Create a client with a custom runner (for testing).
    pub fn with_runner(runner: Box<dyn toride_runner::Runner>) -> Self {
        Self {
            runner,
            paths: UpdatePaths::new(),
            pkg_mgr: crate::detect::detect_package_manager(),
        }
    }

    /// Create a client with both a custom runner and explicit paths.
    pub fn with_runner_and_paths(
        runner: Box<dyn toride_runner::Runner>,
        paths: UpdatePaths,
    ) -> Self {
        Self {
            runner,
            paths,
            pkg_mgr: crate::detect::detect_package_manager(),
        }
    }

    fn runner_ref(&self) -> &dyn toride_runner::Runner {
        self.runner.as_ref()
    }

    /// The detected package manager — resolved once at construction, never re-probed.
    #[must_use]
    pub fn package_manager(&self) -> PackageManager {
        self.pkg_mgr
    }

    /// Check for available updates (`apt-check` / `dnf check-update --security`);
    /// errors with [`Error::CommandFailed`] or [`Error::PackageDetection`].
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

    /// Apply pending updates (`unattended-upgrades` / `dnf-automatic --install`);
    /// errors with [`Error::CommandFailed`] if the command fails.
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

    /// Write the spec's config files, then `systemctl enable --now` the backend timer
    /// (`apt-daily-upgrade.timer`/`dnf-automatic.timer`); errors with
    /// [`Error::ConfigWrite`]/[`Error::CommandFailed`], or [`Error::Other`] without `config`.
    pub fn configure(&self, spec: &UpdateSpec) -> Result<()> {
        info!("Configuring automatic updates");
        #[cfg(feature = "config")]
        {
            let mgr = crate::config::ConfigManager::with_paths(self.paths.clone());
            mgr.write_spec(spec)?;
            self.enable_auto_update_timer()?;
            Ok(())
        }
        #[cfg(not(feature = "config"))]
        {
            let _ = spec;
            Err(Error::Other(
                "config feature is disabled; cannot write update configuration".into(),
            ))
        }
    }

    fn enable_auto_update_timer(&self) -> Result<()> {
        let unit = match self.package_manager() {
            PackageManager::Apt => "apt-daily-upgrade.timer",
            PackageManager::Dnf => "dnf-automatic.timer",
            PackageManager::Unknown => return Ok(()),
        };
        let spec =
            toride_runner::CommandSpec::new("systemctl").args(["enable", "--now", "--", unit]);
        self.runner.run_checked(&spec).map_err(|e| {
            Error::CommandFailed(format!("systemctl enable --now {unit} failed: {e}"))
        })?;
        Ok(())
    }

    /// Query the current update status; a missing log file is a never-run
    /// empty status, not an error.
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

        status.service_active = self.is_service_active()?;
        Ok(status)
    }

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

    fn is_service_active(&self) -> Result<bool> {
        let service = match self.package_manager() {
            PackageManager::Apt => "unattended-upgrades",
            PackageManager::Dnf => "dnf-automatic.timer",
            PackageManager::Unknown => return Ok(false),
        };
        let spec =
            toride_runner::CommandSpec::new("systemctl").args(["is-active", "--quiet", service]);
        let output = self.runner.run(&spec)?;
        Ok(output.success)
    }
}

impl Default for UpdatesClient {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            runner: Box::new(toride_runner::DuctRunner),
            paths: UpdatePaths::new(),
            pkg_mgr: PackageManager::Unknown,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "config")]
    use crate::spec::{RebootPolicy, Schedule};
    use std::sync::Arc;
    use toride_runner::fake::FakeRunner;
    use toride_runner::{CommandOutput, CommandSpec, Runner};

    struct SharedRunner {
        inner: Arc<FakeRunner>,
    }

    impl SharedRunner {
        fn new(runner: FakeRunner) -> Self {
            Self {
                inner: Arc::new(runner),
            }
        }

        fn boxed(&self) -> Box<dyn Runner> {
            Box::new(ArcRunner(self.inner.clone()))
        }

        fn assert_called_with(&self, spec: &CommandSpec) {
            self.inner.assert_called_with(spec);
        }
    }

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
        #[cfg(not(feature = "config"))]
        {
            let runner = SharedRunner::new(FakeRunner::new());
            let client = UpdatesClient::with_runner(runner.boxed());
            let err = client.configure(&UpdateSpec::default()).unwrap_err();
            assert!(matches!(err, Error::Other(_)));
        }
        #[cfg(feature = "config")]
        {}
    }

    #[test]
    fn with_runner_keeps_runner_alive() {
        let runner = SharedRunner::new(FakeRunner::new());
        let _client = UpdatesClient::with_runner(runner.boxed());
    }

    #[test]
    fn package_manager_is_memoized_and_matches_detection() {
        let client = UpdatesClient::with_runner(Box::new(FakeRunner::new()));
        assert_eq!(
            client.package_manager(),
            crate::detect::detect_package_manager(),
            "memoized answer must agree with a fresh detection on the same host"
        );
        assert_eq!(
            client.package_manager(),
            client.package_manager(),
            "repeated reads must be stable (served from the field, not re-probed)"
        );
    }
}
