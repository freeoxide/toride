//! Diagnostic engine for audit subsystem health checks.
//!
//! Provides a `Doctor` struct that runs a battery of checks against the
//! audit subsystem and produces an [`crate::report::AuditReport`] with
//! findings describing any issues detected.

use toride_runner::CommandSpec;

use crate::{AuditPaths, Result, report::AuditReport};

// ---------------------------------------------------------------------------
// DoctorScope
// ---------------------------------------------------------------------------

/// Scope for doctor diagnostic checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorScope {
    /// Run all available checks.
    All,
    /// Check only audit daemon health.
    Auditd,
    /// Check only file integrity monitoring.
    Integrity,
    /// Check only log management.
    Logs,
    /// Check only configuration files.
    Config,
}

// ---------------------------------------------------------------------------
// Doctor
// ---------------------------------------------------------------------------

/// Diagnostic engine for the audit subsystem.
///
/// Runs checks against auditd, AIDE, rsyslog, journald, and logrotate
/// installations and produces a structured report.
pub struct Doctor<'a> {
    runner: &'a dyn toride_runner::Runner,
    paths: &'a AuditPaths,
}

impl<'a> Doctor<'a> {
    /// Create a new `Doctor` with the given runner and paths.
    pub fn new(runner: &'a dyn toride_runner::Runner, paths: &'a AuditPaths) -> Self {
        Self { runner, paths }
    }

    /// Run diagnostic checks according to the given scope.
    ///
    /// # Errors
    ///
    /// Returns an error only for fundamental failures (e.g. a broken runner).
    /// Individual check failures appear as findings in the report.
    pub fn run(&self, scope: &DoctorScope) -> Result<AuditReport> {
        let mut report = AuditReport::empty();

        match scope {
            DoctorScope::All => {
                Self::check_auditd_binaries(&mut report);
                self.check_auditd_service(&mut report);
                self.check_audit_rules(&mut report);
                self.check_aide(&mut report);
                Self::check_rsyslog(&mut report);
                self.check_logrotate(&mut report);
            }
            DoctorScope::Auditd => {
                Self::check_auditd_binaries(&mut report);
                self.check_auditd_service(&mut report);
                self.check_audit_rules(&mut report);
            }
            DoctorScope::Integrity => {
                self.check_aide(&mut report);
            }
            DoctorScope::Logs => {
                Self::check_rsyslog(&mut report);
                self.check_logrotate(&mut report);
            }
            DoctorScope::Config => {
                self.check_audit_rules(&mut report);
                self.check_aide(&mut report);
                Self::check_rsyslog(&mut report);
            }
        }

        Ok(report)
    }

    // -----------------------------------------------------------------------
    // Individual checks
    // -----------------------------------------------------------------------

    fn check_auditd_binaries(report: &mut AuditReport) {
        for binary in &["auditctl", "auditd", "aureport", "ausearch"] {
            if which::which(binary).is_err() {
                report.push(
                    crate::report::AuditFinding::new(
                        format!("binary.{binary}.missing"),
                        crate::report::AuditSeverity::Critical,
                        format!("{binary} not found"),
                    )
                    .detail(format!(
                        "The {binary} binary could not be located on $PATH."
                    ))
                    .fix("Install auditd: apt install auditd".to_owned()),
                );
            }
        }
    }

    fn check_auditd_service(&self, report: &mut AuditReport) {
        let spec = CommandSpec::new("systemctl").args(["is-active", "auditd"]);
        match self.runner.run(&spec) {
            Ok(output) if output.success => {}
            Ok(_output) => {
                report.push(
                    crate::report::AuditFinding::new(
                        "service.auditd.inactive",
                        crate::report::AuditSeverity::Error,
                        "auditd service is not running",
                    )
                    .fix("Start the auditd service: systemctl start auditd"),
                );
            }
            Err(e) => {
                report.push(
                    crate::report::AuditFinding::new(
                        "service.auditd.check-failed",
                        crate::report::AuditSeverity::Warning,
                        "Could not check auditd service status",
                    )
                    .detail(format!("{e}")),
                );
            }
        }
    }

    fn check_audit_rules(&self, report: &mut AuditReport) {
        if !self.paths.rules_d.exists() {
            report.push(
                crate::report::AuditFinding::new(
                    "config.rules-d.missing",
                    crate::report::AuditSeverity::Warning,
                    "Audit rules directory does not exist",
                )
                .detail(format!("Expected: {}", self.paths.rules_d.display()))
                .fix("Install auditd to create the default rules directory"),
            );
        }
    }

    fn check_aide(&self, report: &mut AuditReport) {
        if which::which("aide").is_err() {
            report.push(
                crate::report::AuditFinding::new(
                    "binary.aide.missing",
                    crate::report::AuditSeverity::Warning,
                    "aide not found",
                )
                .detail("The AIDE binary could not be located on $PATH.")
                .fix("Install AIDE: apt install aide"),
            );
            return;
        }

        if !self.paths.aide_conf.exists() {
            report.push(
                crate::report::AuditFinding::new(
                    "config.aide.missing",
                    crate::report::AuditSeverity::Warning,
                    "AIDE configuration file not found",
                )
                .detail(format!("Expected: {}", self.paths.aide_conf.display()))
                .fix("Initialize AIDE: aideinit"),
            );
        }
    }

    fn check_rsyslog(report: &mut AuditReport) {
        if which::which("rsyslogd").is_err() {
            report.push(
                crate::report::AuditFinding::new(
                    "binary.rsyslogd.missing",
                    crate::report::AuditSeverity::Info,
                    "rsyslogd not found",
                )
                .detail("The rsyslogd binary could not be located on $PATH.")
                .fix("Install rsyslog: apt install rsyslog"),
            );
        }
    }

    fn check_logrotate(&self, report: &mut AuditReport) {
        if which::which("logrotate").is_err() {
            report.push(
                crate::report::AuditFinding::new(
                    "binary.logrotate.missing",
                    crate::report::AuditSeverity::Info,
                    "logrotate not found",
                )
                .detail("The logrotate binary could not be located on $PATH.")
                .fix("Install logrotate: apt install logrotate"),
            );
        }

        if !self.paths.logrotate_d.exists() {
            report.push(
                crate::report::AuditFinding::new(
                    "config.logrotate-d.missing",
                    crate::report::AuditSeverity::Warning,
                    "logrotate configuration directory does not exist",
                )
                .detail(format!("Expected: {}", self.paths.logrotate_d.display()))
                .fix("Install logrotate to create the default directory"),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuditPaths;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use toride_runner::fake::FakeRunner;

    /// Build an `AuditPaths` whose directories all live under a fresh tempdir
    /// (so none of them exist on disk). This makes the file-existence checks
    /// deterministic regardless of the host.
    fn paths_under(dir: &std::path::Path) -> AuditPaths {
        AuditPaths {
            audit_dir: dir.join("audit"),
            rules_d: dir.join("audit/rules.d"),
            aide_conf: dir.join("aide.conf"),
            aide_db_dir: dir.join("aide"),
            rsyslog_conf: dir.join("rsyslog.conf"),
            rsyslog_d: dir.join("rsyslog.d"),
            logrotate_d: dir.join("logrotate.d"),
        }
    }

    /// The `systemctl is-active auditd` spec that `check_auditd_service` runs.
    fn systemctl_auditd_spec() -> toride_runner::CommandSpec {
        CommandSpec::new("systemctl").args(["is-active", "auditd"])
    }

    /// Collect the finding IDs produced by a run.
    fn finding_ids(report: &AuditReport) -> Vec<&str> {
        report.findings.iter().map(|f| f.id.as_str()).collect()
    }

    #[test]
    fn run_returns_empty_report_when_everything_healthy() {
        // If auditd reports active and all the path-based checks pass (because
        // the directories exist), the report should be empty.
        let dir = TempDir::new().expect("tempdir");
        // Create the directories the checks look for so no `config.*.missing`
        // findings fire.
        std::fs::create_dir_all(dir.path().join("audit/rules.d")).expect("mkdir rules.d");
        std::fs::create_dir_all(dir.path().join("logrotate.d")).expect("mkdir logrotate.d");
        let paths = paths_under(dir.path());

        let runner =
            FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout("active"));
        let doctor = Doctor::new(&runner, &paths);

        let report = doctor.run(&DoctorScope::Auditd).expect("run succeeds");
        // The path-based checks pass; the only remaining findings would be
        // from missing auditd binaries on the host. Filter those out so the
        // assertion is host-independent.
        let non_binary: Vec<&str> = finding_ids(&report)
            .into_iter()
            .filter(|id| !id.starts_with("binary."))
            .collect();
        assert!(
            non_binary.is_empty(),
            "expected no path/service findings on a healthy mock host, got {non_binary:?}"
        );
    }

    #[test]
    fn auditd_scope_reports_inactive_service() {
        let dir = TempDir::new().expect("tempdir");
        let paths = paths_under(dir.path());
        let runner = FakeRunner::new()
            .push_response(toride_runner::CommandOutput::from_stderr("inactive", 3));
        let doctor = Doctor::new(&runner, &paths);

        let report = doctor.run(&DoctorScope::Auditd).expect("run succeeds");
        let ids = finding_ids(&report);
        assert!(
            ids.contains(&"service.auditd.inactive"),
            "Auditd scope should flag an inactive auditd service, got {ids:?}"
        );
    }

    #[test]
    fn auditd_scope_runs_systemctl_check() {
        let dir = TempDir::new().expect("tempdir");
        let paths = paths_under(dir.path());
        let runner =
            FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout("active"));
        let doctor = Doctor::new(&runner, &paths);

        let _ = doctor.run(&DoctorScope::Auditd).expect("run succeeds");
        runner.assert_called_with(&systemctl_auditd_spec());
    }

    #[test]
    fn integrity_scope_does_not_check_auditd_service() {
        // Integrity scope must NOT touch the systemctl/auditd service path.
        let dir = TempDir::new().expect("tempdir");
        let paths = paths_under(dir.path());
        let runner = FakeRunner::new().strict();
        let doctor = Doctor::new(&runner, &paths);

        // In strict mode an unexpected systemctl call would error the run.
        let report = doctor.run(&DoctorScope::Integrity).expect("run succeeds");
        // The runner was never consulted.
        assert!(runner.calls().is_empty());
        // check_aide ran: with a missing aide.conf it emits either
        // `binary.aide.missing` (no aide installed) or `config.aide.missing`
        // (aide installed but conf absent). Both are acceptable — assert one.
        let ids = finding_ids(&report);
        let has_aide_finding = ids
            .iter()
            .any(|id| *id == "binary.aide.missing" || *id == "config.aide.missing");
        assert!(
            has_aide_finding,
            "Integrity scope should run check_aide, got {ids:?}"
        );
    }

    #[test]
    fn logs_scope_flags_missing_logrotate_dir() {
        let dir = TempDir::new().expect("tempdir");
        let paths = paths_under(dir.path());
        let runner = FakeRunner::new();
        let doctor = Doctor::new(&runner, &paths);

        let report = doctor.run(&DoctorScope::Logs).expect("run succeeds");
        let ids = finding_ids(&report);
        assert!(
            ids.contains(&"config.logrotate-d.missing"),
            "Logs scope should flag the missing logrotate.d directory, got {ids:?}"
        );
        // Logs scope must not check the auditd service.
        assert!(
            !runner.calls().iter().any(|c| c.program == "systemctl"),
            "Logs scope should not invoke systemctl"
        );
    }

    #[test]
    fn config_scope_flags_missing_rules_dir() {
        let dir = TempDir::new().expect("tempdir");
        let paths = paths_under(dir.path());
        let runner = FakeRunner::new();
        let doctor = Doctor::new(&runner, &paths);

        let report = doctor.run(&DoctorScope::Config).expect("run succeeds");
        let ids = finding_ids(&report);
        assert!(
            ids.contains(&"config.rules-d.missing"),
            "Config scope should flag the missing rules.d directory, got {ids:?}"
        );
        // Config scope must not check the auditd service either.
        assert!(
            !runner.calls().iter().any(|c| c.program == "systemctl"),
            "Config scope should not invoke systemctl"
        );
    }

    #[test]
    fn all_scope_runs_every_group() {
        // All scope must exercise the auditd-service check AND the file-based
        // checks for rules.d and logrotate.d.
        let dir = TempDir::new().expect("tempdir");
        let paths = paths_under(dir.path());
        let runner = FakeRunner::new()
            .push_response(toride_runner::CommandOutput::from_stderr("inactive", 3));
        let doctor = Doctor::new(&runner, &paths);

        let report = doctor.run(&DoctorScope::All).expect("run succeeds");
        let ids = finding_ids(&report);
        assert!(
            ids.contains(&"service.auditd.inactive"),
            "All scope should run the auditd service check, got {ids:?}"
        );
        assert!(
            ids.contains(&"config.rules-d.missing"),
            "All scope should run the rules-d check, got {ids:?}"
        );
        assert!(
            ids.contains(&"config.logrotate-d.missing"),
            "All scope should run the logrotate-d check, got {ids:?}"
        );
        runner.assert_called_with(&systemctl_auditd_spec());
    }

    #[test]
    fn check_service_runner_error_is_warning_finding() {
        // If the runner itself fails, the doctor must surface a warning finding
        // rather than propagating an error.
        let dir = TempDir::new().expect("tempdir");
        let paths = paths_under(dir.path());
        let runner = FakeRunner::new().strict().respond_err(
            systemctl_auditd_spec(),
            toride_runner::Error::Other("spawn failed".to_owned()),
        );
        let doctor = Doctor::new(&runner, &paths);

        let report = doctor
            .run(&DoctorScope::Auditd)
            .expect("run must not error on a runner failure");
        let ids = finding_ids(&report);
        assert!(
            ids.contains(&"service.auditd.check-failed"),
            "a runner failure should become a service.auditd.check-failed finding, got {ids:?}"
        );
    }

    #[test]
    fn doctor_paths_override_takes_effect() {
        // Sanity: constructing Doctor with custom paths drives check_audit_rules.
        let dir = TempDir::new().expect("tempdir");
        let custom = PathBuf::from(dir.path());
        let paths = paths_under(&custom);
        let runner =
            FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout("active"));
        let doctor = Doctor::new(&runner, &paths);

        let report = doctor.run(&DoctorScope::Auditd).expect("run succeeds");
        let ids = finding_ids(&report);
        assert!(
            ids.contains(&"config.rules-d.missing"),
            "rules_d under the tempdir should be reported missing, got {ids:?}"
        );
    }
}
