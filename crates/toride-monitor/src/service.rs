//! Service management for the toride-monitor daemon.
//!
//! Provides [`MonitorService`] for managing the monitoring daemon lifecycle:
//! start, stop, restart, status checks, and enable/disable on boot.

use crate::client::MonitorClient;
use crate::paths::MonitorPaths;
use crate::spec::MonitorSpec;
use crate::Result;

/// The systemd unit name the monitor daemon runs under.
pub const MONITOR_UNIT: &str = "toride-monitor.service";

/// Manages the toride-monitor system service.
///
/// Wraps service management operations via [`toride_service::ServiceManager`]
/// (which shells out to `systemctl` through the shared runner) and delegates
/// iptables logging setup/teardown to [`MonitorClient`].
pub struct MonitorService<'a> {
    /// The underlying monitoring client (logging setup/teardown).
    client: MonitorClient,
    /// Binary paths for system commands.
    paths: &'a MonitorPaths,
    /// systemd unit lifecycle manager.
    service: toride_service::ServiceManager,
}

impl<'a> MonitorService<'a> {
    /// Create a new `MonitorService` with the given client, paths, and runner.
    #[must_use]
    pub fn with_runner(
        client: MonitorClient,
        paths: &'a MonitorPaths,
        runner: Box<dyn toride_runner::Runner>,
    ) -> Self {
        Self {
            client,
            paths,
            service: toride_service::ServiceManager::new(runner),
        }
    }

    /// Create a new `MonitorService` using the client's runner.
    ///
    /// Spawns a thin `systemctl`-only runner distinct from the client's
    /// runner. In practice you usually want [`MonitorService::with_runner`]
    /// so the same runner (and thus the same test fakes) drives both paths.
    #[must_use]
    pub fn new(client: MonitorClient, paths: &'a MonitorPaths) -> Self {
        Self::with_runner(client, paths, Box::new(toride_runner::DuctRunner))
    }

    /// Return a reference to the underlying monitor client.
    #[must_use]
    pub fn client(&self) -> &MonitorClient {
        &self.client
    }

    /// Return a reference to the resolved paths.
    #[must_use]
    pub fn paths(&self) -> &MonitorPaths {
        self.paths
    }

    /// Start the monitoring service.
    ///
    /// Sets up logging rules and asks systemd to start the monitor unit.
    ///
    /// # Errors
    ///
    /// Returns an error if logging setup or `systemctl start` fails.
    pub fn start(&self, spec: &MonitorSpec) -> Result<()> {
        tracing::info!("Starting toride-monitor service");
        self.client.setup_logging(&spec.logging_rules)?;
        self.service.start(MONITOR_UNIT)?;
        Ok(())
    }

    /// Stop the monitoring service.
    ///
    /// Tears down logging rules and asks systemd to stop the monitor unit.
    ///
    /// # Errors
    ///
    /// Returns an error if logging teardown or `systemctl stop` fails.
    pub fn stop(&self) -> Result<()> {
        tracing::info!("Stopping toride-monitor service");
        // Surface the first error, preferring the teardown error so callers
        // learn about lingering iptables rules.
        self.client.teardown_logging()?;
        self.service.stop(MONITOR_UNIT)?;
        Ok(())
    }

    /// Restart the monitoring service.
    ///
    /// Equivalent to `stop()` followed by `start()`.
    ///
    /// # Errors
    ///
    /// Returns an error if either stop or start fails.
    pub fn restart(&self, spec: &MonitorSpec) -> Result<()> {
        self.stop()?;
        self.start(spec)
    }

    /// Check whether the monitoring service is currently active.
    ///
    /// Queries `systemctl is-active` for the monitor unit.
    ///
    /// # Errors
    ///
    /// Returns an error if the check cannot be performed.
    pub fn is_active(&self) -> Result<bool> {
        Ok(self.service.is_active(MONITOR_UNIT)?)
    }

    /// Enable the monitor unit to start at boot.
    ///
    /// # Errors
    ///
    /// Returns an error if `systemctl enable` fails.
    pub fn enable(&self) -> Result<()> {
        self.service.enable(MONITOR_UNIT)?;
        Ok(())
    }

    /// Disable the monitor unit from starting at boot.
    ///
    /// # Errors
    ///
    /// Returns an error if `systemctl disable` fails.
    pub fn disable(&self) -> Result<()> {
        self.service.disable(MONITOR_UNIT)?;
        Ok(())
    }

    /// Run a single monitoring cycle.
    ///
    /// Takes a snapshot, detects anomalies, and dispatches alerts according
    /// to the provided spec. Intended to be called periodically by the
    /// daemon loop.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot or detection fails.
    pub fn run_cycle(&self, spec: &MonitorSpec) -> Result<crate::report::AnomalyReport> {
        self.client.apply(spec)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::MonitorClient;
    use crate::paths::MonitorPaths;
    use std::path::PathBuf;
    use toride_runner::{CommandOutput, CommandSpec, FakeRunner};

    fn test_paths() -> MonitorPaths {
        MonitorPaths {
            iptables: PathBuf::from("/usr/sbin/iptables"),
            iptables_save: PathBuf::from("/usr/sbin/iptables-save"),
            conntrack: PathBuf::from("/usr/sbin/conntrack"),
            ss: PathBuf::from("/usr/bin/ss"),
            journalctl: PathBuf::from("/usr/bin/journalctl"),
            systemd_cat: PathBuf::from("/usr/bin/systemd-cat"),
        }
    }

    #[test]
    fn is_active_issues_systemctl_is_active_for_monitor_unit() {
        // The previously-hardcoded Ok(false) stub is replaced by a real
        // systemctl is-active probe routed through the runner.
        let runner = FakeRunner::new().respond(
            CommandSpec::new("systemctl")
                .args(["is-active", "toride-monitor.service"]),
            CommandOutput::new("active\n".into(), String::new(), Some(0)),
        );
        let paths = test_paths();
        let client = MonitorClient::with_paths(paths.clone());
        let svc = MonitorService::with_runner(client, &paths, Box::new(runner));

        assert!(svc.is_active().unwrap());
    }

    #[test]
    fn is_active_returns_false_for_inactive_unit() {
        let runner = FakeRunner::new().respond(
            CommandSpec::new("systemctl")
                .args(["is-active", "toride-monitor.service"]),
            CommandOutput::new("inactive\n".into(), String::new(), Some(3)),
        );
        let paths = test_paths();
        let client = MonitorClient::with_paths(paths.clone());
        let svc = MonitorService::with_runner(client, &paths, Box::new(runner));

        assert!(!svc.is_active().unwrap());
    }
}

