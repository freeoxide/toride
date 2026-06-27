//! Service management for unattended-upgrades / dnf-automatic.
//!
//! Provides start/stop/enable/disable operations for the automatic update
//! service. Each operation shells out to `systemctl` through the injected
//! [`toride_runner::Runner`], mirroring the command construction used by
//! [`toride_service::ServiceManager`] so the call stack stays testable and
//! honours dry-run/fake runners in tests.

use tracing::info;

use crate::detect::PackageManager;
use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// ServiceManager
// ---------------------------------------------------------------------------

/// Manages the automatic update systemd service.
///
/// On APT systems, manages `unattended-upgrades` / `apt-daily-upgrade.timer`.
/// On DNF systems, manages `dnf-automatic.timer`.
///
/// All `systemctl` invocations are routed through the injected
/// [`toride_runner::Runner`] so the behaviour is identical between production
/// ([`toride_runner::DuctRunner`]) and tests
/// ([`toride_runner::fake::FakeRunner`]).
pub struct ServiceManager<'a> {
    pkg_mgr: PackageManager,
    runner: &'a dyn toride_runner::Runner,
}

impl<'a> ServiceManager<'a> {
    /// Create a new service manager.
    pub fn new(runner: &'a dyn toride_runner::Runner) -> Self {
        Self {
            pkg_mgr: crate::detect::detect_package_manager(),
            runner,
        }
    }

    /// Create a service manager with an explicit package manager (for tests).
    pub fn with_pkg_mgr(runner: &'a dyn toride_runner::Runner, pkg_mgr: PackageManager) -> Self {
        Self { pkg_mgr, runner }
    }

    /// Return the service name for the detected package manager.
    pub fn service_name(&self) -> &'static str {
        match self.pkg_mgr {
            PackageManager::Apt => "unattended-upgrades",
            PackageManager::Dnf => "dnf-automatic.timer",
            PackageManager::Unknown => "unknown",
        }
    }

    /// Return the timer unit name (DNF only).
    pub fn timer_name(&self) -> Option<&'static str> {
        match self.pkg_mgr {
            PackageManager::Dnf => Some("dnf-automatic.timer"),
            _ => None,
        }
    }

    /// Enable and start the automatic update service / timer.
    ///
    /// Runs `systemctl enable --now <unit>` through the runner, the same
    /// command `toride_service::ServiceManager` would issue.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if `systemctl` fails.
    pub fn enable(&self) -> Result<()> {
        let service = self.service_name();
        info!("Enabling service: {service}");
        self.run_systemctl(&["enable", "--now", service])
    }

    /// Disable and stop the automatic update service / timer.
    ///
    /// Runs `systemctl disable --now <unit>` through the runner.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if `systemctl` fails.
    pub fn disable(&self) -> Result<()> {
        let service = self.service_name();
        info!("Disabling service: {service}");
        self.run_systemctl(&["disable", "--now", service])
    }

    /// Check whether the service is currently active.
    ///
    /// Runs `systemctl is-active --quiet <unit>` and returns `true` when it
    /// exits successfully (code 0).
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] only if the runner itself fails to
    /// spawn `systemctl`. A non-active service returns `Ok(false)`, not an
    /// error — matching `systemctl`'s exit-code semantics.
    pub fn is_active(&self) -> Result<bool> {
        let service = self.service_name();
        let spec = systemctl_spec(&["is-active", "--quiet", service]);
        let output = self.runner.run(&spec)?;
        Ok(output.success)
    }

    /// Restart the service.
    ///
    /// Runs `systemctl restart <unit>` through the runner.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if `systemctl` fails.
    pub fn restart(&self) -> Result<()> {
        let service = self.service_name();
        info!("Restarting service: {service}");
        self.run_systemctl(&["restart", service])
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Execute a `systemctl` subcommand through the runner, mapping a non-zero
    /// exit into [`Error::CommandFailed`]. Mirrors the private helper in
    /// `toride_service::ServiceManager`.
    fn run_systemctl(&self, args: &[&str]) -> Result<()> {
        let spec = systemctl_spec(args);
        let output = self.runner.run(&spec)?;
        if output.success {
            Ok(())
        } else {
            let code = output
                .exit_code
                .map_or("signal".to_owned(), |c| c.to_string());
            let stderr = output.stderr.trim();
            let detail = if stderr.is_empty() {
                format!("systemctl {} failed (exit {code})", args.join(" "))
            } else {
                format!(
                    "systemctl {} failed (exit {code}): {stderr}",
                    args.join(" ")
                )
            };
            Err(Error::CommandFailed(detail))
        }
    }
}

/// Build a [`toride_runner::CommandSpec`] for a `systemctl` subcommand.
fn systemctl_spec(args: &[&str]) -> toride_runner::CommandSpec {
    toride_runner::CommandSpec::new("systemctl").args(args.iter().copied())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use toride_runner::fake::FakeRunner;
    use toride_runner::{CommandOutput, CommandSpec};

    fn mgr_with(pkg_mgr: PackageManager, runner: &FakeRunner) -> ServiceManager<'_> {
        ServiceManager::with_pkg_mgr(runner, pkg_mgr)
    }

    #[test]
    fn enable_builds_systemctl_enable_now_unattended_upgrades() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        mgr_with(PackageManager::Apt, &runner).enable().unwrap();
        runner.assert_called_with(
            &CommandSpec::new("systemctl").args(["enable", "--now", "unattended-upgrades"]),
        );
    }

    #[test]
    fn enable_dnf_targets_timer_unit() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        mgr_with(PackageManager::Dnf, &runner).enable().unwrap();
        runner.assert_called_with(
            &CommandSpec::new("systemctl").args(["enable", "--now", "dnf-automatic.timer"]),
        );
    }

    #[test]
    fn disable_builds_systemctl_disable_now() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        mgr_with(PackageManager::Apt, &runner).disable().unwrap();
        runner.assert_called_with(
            &CommandSpec::new("systemctl").args(["disable", "--now", "unattended-upgrades"]),
        );
    }

    #[test]
    fn restart_builds_systemctl_restart() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        mgr_with(PackageManager::Dnf, &runner).restart().unwrap();
        runner.assert_called_with(
            &CommandSpec::new("systemctl").args(["restart", "dnf-automatic.timer"]),
        );
    }

    #[test]
    fn is_active_returns_true_when_exit_zero() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout("active"));
        let active = mgr_with(PackageManager::Apt, &runner).is_active().unwrap();
        assert!(active);
        runner.assert_called_with(
            &CommandSpec::new("systemctl").args(["is-active", "--quiet", "unattended-upgrades"]),
        );
    }

    #[test]
    fn is_active_returns_false_on_nonzero_exit() {
        // systemctl is-active exits 3 when inactive — not a runner error.
        let runner = FakeRunner::new().push_response(CommandOutput::from_stderr("inactive", 3));
        let active = mgr_with(PackageManager::Apt, &runner).is_active().unwrap();
        assert!(!active);
    }

    #[test]
    fn enable_errors_on_nonzero_exit() {
        let runner = FakeRunner::new()
            .push_response(CommandOutput::from_stderr("Failed to enable unit: Access denied", 1));
        let err = mgr_with(PackageManager::Apt, &runner).enable().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("systemctl"), "{msg}");
        assert!(msg.contains("Access denied"), "{msg}");
    }

    #[test]
    fn timer_name_only_for_dnf() {
        let runner = FakeRunner::new();
        assert_eq!(mgr_with(PackageManager::Dnf, &runner).timer_name(), Some("dnf-automatic.timer"));
        assert_eq!(mgr_with(PackageManager::Apt, &runner).timer_name(), None);
    }
}
