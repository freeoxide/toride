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
