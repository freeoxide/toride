//! Diagnostic checks for the monitoring subsystem.
//!
//! Provides [`Doctor`] which runs a series of health checks against a
//! monitoring installation and produces a [`DoctorReport`] with findings.

use crate::paths::MonitorPaths;
use crate::report::{AnomalyFinding, AnomalySeverity};
use crate::Result;

/// The systemd unit name under which the toride-monitor daemon runs.
const MONITOR_UNIT: &str = "toride-monitor.service";

/// Scope of doctor checks to run.
#[derive(Debug, Clone, Default)]
pub enum DoctorScope {
    /// Run all available checks.
    #[default]
    All,
    /// Check only binary availability.
    Binaries,
    /// Check only iptables logging configuration.
    Logging,
    /// Check only service status.
    Service,
    /// Check only thresholds and configuration.
    Config,
}

/// Diagnostic engine for the monitoring subsystem.
///
/// Runs targeted health checks and collects findings into a structured
/// report. Designed to be resilient: individual check failures do not
/// abort the overall diagnostic run.
pub struct Doctor<'a> {
    /// Binary paths for system commands.
    paths: &'a MonitorPaths,
    /// Command runner used to probe the system.
    runner: &'a dyn toride_runner::Runner,
}

impl<'a> Doctor<'a> {
    /// Create a new `Doctor` with the given paths and runner.
    #[must_use]
    pub fn new(paths: &'a MonitorPaths, runner: &'a dyn toride_runner::Runner) -> Self {
        Self { paths, runner }
    }

    /// Run doctor checks within the given scope.
    ///
    /// # Errors
    ///
    /// Returns an error only for fundamental failures (e.g. broken runner).
    /// Individual check failures appear as findings in the report.
    pub fn run(&self, scope: &DoctorScope) -> Result<DoctorReport> {
        let mut findings = Vec::new();

        match scope {
            DoctorScope::All => {
                self.check_binaries(&mut findings);
                self.check_logging(&mut findings);
                self.check_service(&mut findings);
                self.check_config(&mut findings);
            }
            DoctorScope::Binaries => {
                self.check_binaries(&mut findings);
            }
            DoctorScope::Logging => {
                self.check_logging(&mut findings);
            }
            DoctorScope::Service => {
                self.check_service(&mut findings);
            }
            DoctorScope::Config => {
                self.check_config(&mut findings);
            }
        }

        Ok(DoctorReport { findings })
    }

    /// Check that required binaries exist and are executable.
    fn check_binaries(&self, findings: &mut Vec<AnomalyFinding>) {
        let binaries = [
            ("iptables", &self.paths.iptables),
            ("iptables-save", &self.paths.iptables_save),
            ("conntrack", &self.paths.conntrack),
            ("ss", &self.paths.ss),
            ("systemd-cat", &self.paths.systemd_cat),
        ];

        for (name, path) in binaries {
            if !path.exists() {
                findings.push(AnomalyFinding::new(
                    format!("doctor.binary.{name}.missing"),
                    AnomalySeverity::Critical,
                    format!("Required binary not found: {name}"),
                    format!("Expected at: {}", path.display()),
                    "Binary must exist and be executable",
                ).fix(format!("Install the package providing {name}.")));
            }
        }
    }

    /// Check iptables OUTPUT chain logging configuration.
    fn check_logging(&self, findings: &mut Vec<AnomalyFinding>) {
        // Check if iptables LOG rules exist in the OUTPUT chain.
        let chain = crate::output::OutputChain::new(self.paths, self.runner);
        match chain.list_rules() {
            Ok(rules) => {
                if rules.is_empty() {
                    findings.push(AnomalyFinding::new(
                        "doctor.logging.no-rules",
                        AnomalySeverity::Warning,
                        "No OUTPUT chain LOG rules configured",
                        "0 LOG rules in OUTPUT chain",
                        "At least one LOG rule expected",
                    ).fix("Run monitor setup to install logging rules."));
                } else if rules.len() > 50 {
                    findings.push(AnomalyFinding::new(
                        "doctor.logging.excessive-rules",
                        AnomalySeverity::Warning,
                        "Excessive number of OUTPUT chain LOG rules",
                        format!("{} LOG rules in OUTPUT chain", rules.len()),
                        "Fewer than 50 rules recommended",
                    ).fix("Review and remove unnecessary logging rules."));
                }
            }
            Err(e) => {
                findings.push(AnomalyFinding::new(
                    "doctor.logging.check-failed",
                    AnomalySeverity::Error,
                    "Failed to list iptables OUTPUT chain rules",
                    format!("{e}"),
                    "Should be able to list rules",
                ).fix("Verify iptables permissions and kernel modules."));
            }
        }
    }

    /// Check monitoring service status via systemd.
    ///
    /// Queries `systemctl is-active` for the monitor unit and reports the
    /// result. A unit that is inactive or not installed surfaces as a finding
    /// rather than an error.
    fn check_service(&self, findings: &mut Vec<AnomalyFinding>) {
        let spec =
            toride_runner::CommandSpec::new("systemctl").args(["is-active", MONITOR_UNIT]);
        match self.runner.run(&spec) {
            Ok(output) => {
                let state = output.stdout.trim();
                // `systemctl is-active` exits 0 only when active; otherwise it
                // returns the textual state on stdout and a non-zero code.
                if output.success && state == "active" {
                    findings.push(AnomalyFinding::new(
                        "doctor.service.active",
                        AnomalySeverity::Info,
                        "Monitoring service is active",
                        state.to_owned(),
                        "active",
                    ));
                } else {
                    findings.push(AnomalyFinding::new(
                        "doctor.service.inactive",
                        AnomalySeverity::Warning,
                        "Monitoring service is not active",
                        state.to_owned(),
                        "active",
                    ).fix(format!("Run `systemctl start {MONITOR_UNIT}`.")));
                }
            }
            Err(e) => {
                findings.push(AnomalyFinding::new(
                    "doctor.service.check-failed",
                    AnomalySeverity::Error,
                    "Failed to query monitoring service status",
                    format!("{e}"),
                    "systemctl should be reachable",
                ).fix("Verify systemd is running and systemctl is on $PATH."));
            }
        }
    }

    /// Check configuration validity.
    fn check_config(&self, findings: &mut Vec<AnomalyFinding>) {
        // Validate default thresholds.
        let threshold = crate::spec::AnomalyThreshold::default();
        if let Err(e) = crate::validate::validate_threshold(&threshold) {
            findings.push(AnomalyFinding::new(
                "doctor.config.invalid-threshold",
                AnomalySeverity::Error,
                "Default threshold configuration is invalid",
                format!("{e}"),
                "Valid thresholds required",
            ).fix("Review default threshold values."));
        }
    }
}

/// Aggregated doctor report for monitoring diagnostics.
#[derive(Debug, Clone)]
pub struct DoctorReport {
    /// All findings collected during the doctor run.
    pub findings: Vec<AnomalyFinding>,
}

impl DoctorReport {
    /// Create an empty report.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            findings: Vec::new(),
        }
    }

    /// Returns `true` if no findings were produced.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// Returns `true` if any finding has critical severity.
    #[must_use]
    pub fn has_critical(&self) -> bool {
        self.findings.iter().any(|f| f.severity == AnomalySeverity::Critical)
    }

    /// Returns the number of findings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.findings.len()
    }

    /// Returns `true` if there are no findings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
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
    fn check_service_reports_active_when_unit_is_running() {
        // The previously-not-implemented stub is replaced by a real
        // systemctl is-active probe.
        let runner = FakeRunner::new().respond(
            CommandSpec::new("systemctl")
                .args(["is-active", "toride-monitor.service"]),
            CommandOutput::new("active\n".into(), String::new(), Some(0)),
        );
        let paths = test_paths();
        let doctor = Doctor::new(&paths, &runner);

        let mut findings = Vec::new();
        doctor.check_service(&mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, AnomalySeverity::Info);
        assert_eq!(findings[0].id, "doctor.service.active");
    }

    #[test]
    fn check_service_flags_inactive_unit() {
        let runner = FakeRunner::new().respond(
            CommandSpec::new("systemctl")
                .args(["is-active", "toride-monitor.service"]),
            CommandOutput::new("inactive\n".into(), String::new(), Some(3)),
        );
        let paths = test_paths();
        let doctor = Doctor::new(&paths, &runner);

        let mut findings = Vec::new();
        doctor.check_service(&mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, AnomalySeverity::Warning);
        assert_eq!(findings[0].id, "doctor.service.inactive");
    }
}

