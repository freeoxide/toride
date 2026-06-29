//! Audit report types for doctor findings and status summaries.
//!
//! Every diagnostic or mutating workflow in the crate returns one of these
//! report types so that callers can inspect results programmatically and
//! produce human-readable output independently.

// ---------------------------------------------------------------------------
// AuditReport
// ---------------------------------------------------------------------------

/// Aggregated audit report containing findings from a diagnostic run.
///
/// Provides convenience methods for summarising findings and checking
/// for blocking issues.
#[derive(Debug, Clone, Default)]
pub struct AuditReport {
    /// All findings collected during the audit run.
    pub findings: Vec<AuditFinding>,
    /// Summary statistics.
    pub summary: AuditSummary,
}

impl AuditReport {
    /// Create an empty report.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Add a finding to the report.
    pub fn push(&mut self, finding: AuditFinding) {
        self.findings.push(finding);
    }

    /// Returns the number of findings in this report.
    #[must_use]
    pub fn len(&self) -> usize {
        self.findings.len()
    }

    /// Returns `true` if this report contains no findings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Returns `true` if any finding has severity [`AuditSeverity::Error`] or higher.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity >= AuditSeverity::Error)
    }
}

impl std::fmt::Display for AuditReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.findings.is_empty() {
            return writeln!(f, "no findings — audit subsystem healthy");
        }
        for finding in &self.findings {
            writeln!(
                f,
                "[{}] {} ({})",
                finding.severity, finding.title, finding.id
            )?;
            if !finding.detail.is_empty() {
                writeln!(f, "    {}", finding.detail)?;
            }
            if let Some(fix) = &finding.fix {
                writeln!(f, "    fix: {fix}")?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AuditFinding
// ---------------------------------------------------------------------------

/// A single structured finding produced during an audit check.
///
/// Use [`AuditFinding::new`] to construct the mandatory fields, then chain
/// the `.detail()` and `.fix()` builder methods for optional context.
#[derive(Debug, Clone)]
pub struct AuditFinding {
    /// Machine-readable dot-separated identifier,
    /// e.g. `"binary.auditctl.missing"`.
    pub id: String,
    /// How severe this finding is.
    pub severity: AuditSeverity,
    /// Short human-readable title (one line).
    pub title: String,
    /// Longer description of the finding.
    pub detail: String,
    /// Suggested remediation action, if applicable.
    pub fix: Option<String>,
}

impl AuditFinding {
    /// Create a new finding with the mandatory fields.
    ///
    /// The `detail` and `fix` fields default to empty / `None` and can be
    /// filled in via the `.detail()` and `.fix()` chain methods.
    #[must_use]
    pub fn new(id: impl Into<String>, severity: AuditSeverity, title: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            severity,
            title: title.into(),
            detail: String::new(),
            fix: None,
        }
    }

    /// Attach a longer description, replacing any previous detail text.
    #[must_use]
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    /// Attach a suggested fix action, replacing any previous fix.
    #[must_use]
    pub fn fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
}

// ---------------------------------------------------------------------------
// AuditSeverity
// ---------------------------------------------------------------------------

/// Diagnostic severity level for audit findings.
///
/// Ordered from least severe ([`AuditSeverity::Ok`]) to most severe
/// ([`AuditSeverity::Critical`]) so that reports can be sorted and filtered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuditSeverity {
    /// No issue detected.
    Ok,
    /// Informational note; no action required.
    Info,
    /// Non-critical issue that may cause problems later.
    Warning,
    /// An error that should be addressed before proceeding.
    Error,
    /// A critical problem that blocks normal operation.
    Critical,
}

impl std::fmt::Display for AuditSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => write!(f, "OK"),
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARNING"),
            Self::Error => write!(f, "ERROR"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ---------------------------------------------------------------------------
// AuditSummary
// ---------------------------------------------------------------------------

/// Summary statistics for an audit report.
#[derive(Debug, Clone, Default)]
pub struct AuditSummary {
    /// Number of audit rules loaded.
    pub rules_loaded: usize,
    /// Whether auditd is running.
    pub auditd_running: bool,
    /// Whether AIDE database is initialized.
    pub aide_initialized: bool,
    /// Last AIDE check timestamp, if available.
    pub last_aide_check: Option<String>,
    /// Number of log files managed.
    pub log_files_count: usize,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_report_empty_is_empty() {
        let report = AuditReport::empty();
        assert!(report.is_empty());
        assert!(!report.has_errors());
        assert_eq!(report.len(), 0);
    }

    #[test]
    fn audit_report_push_adds_findings() {
        let mut report = AuditReport::empty();
        report.push(AuditFinding::new("test.1", AuditSeverity::Ok, "All good"));
        report.push(AuditFinding::new("test.2", AuditSeverity::Info, "FYI"));
        assert_eq!(report.len(), 2);
        assert!(!report.is_empty());
    }

    #[test]
    fn audit_report_has_errors_detects_error_severity() {
        let mut report = AuditReport::empty();
        report.push(AuditFinding::new("test.ok", AuditSeverity::Ok, "Ok"));
        assert!(!report.has_errors());

        report.push(AuditFinding::new(
            "test.warn",
            AuditSeverity::Warning,
            "Hmm",
        ));
        assert!(!report.has_errors());

        report.push(AuditFinding::new(
            "test.err",
            AuditSeverity::Error,
            "Broken",
        ));
        assert!(report.has_errors());
    }

    #[test]
    fn audit_report_has_errors_detects_critical_severity() {
        let mut report = AuditReport::empty();
        report.push(AuditFinding::new(
            "test.crit",
            AuditSeverity::Critical,
            "Fatal",
        ));
        assert!(report.has_errors());
    }

    #[test]
    fn audit_finding_builder_pattern() {
        let finding = AuditFinding::new(
            "binary.auditctl.missing",
            AuditSeverity::Error,
            "Missing auditctl",
        )
        .detail("The auditctl binary was not found on PATH")
        .fix("Install the auditd package: apt install auditd");
        assert_eq!(finding.id, "binary.auditctl.missing");
        assert_eq!(finding.severity, AuditSeverity::Error);
        assert_eq!(finding.title, "Missing auditctl");
        assert_eq!(finding.detail, "The auditctl binary was not found on PATH");
        assert_eq!(
            finding.fix.as_deref(),
            Some("Install the auditd package: apt install auditd")
        );
    }

    #[test]
    fn audit_finding_detail_and_fix_are_optional() {
        let finding = AuditFinding::new("test", AuditSeverity::Info, "Title");
        assert!(finding.detail.is_empty());
        assert!(finding.fix.is_none());
    }

    #[test]
    fn audit_severity_ordering() {
        assert!(AuditSeverity::Critical > AuditSeverity::Error);
        assert!(AuditSeverity::Error > AuditSeverity::Warning);
        assert!(AuditSeverity::Warning > AuditSeverity::Info);
        assert!(AuditSeverity::Info > AuditSeverity::Ok);
    }

    #[test]
    fn audit_severity_display() {
        assert_eq!(AuditSeverity::Ok.to_string(), "OK");
        assert_eq!(AuditSeverity::Info.to_string(), "INFO");
        assert_eq!(AuditSeverity::Warning.to_string(), "WARNING");
        assert_eq!(AuditSeverity::Error.to_string(), "ERROR");
        assert_eq!(AuditSeverity::Critical.to_string(), "CRITICAL");
    }
}
