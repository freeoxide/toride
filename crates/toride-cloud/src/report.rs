//! Structured report types for cloud provider operations.
//!
//! Every mutating or diagnostic workflow in the crate returns one of these
//! report types so that callers can inspect results programmatically and
//! produce human-readable output independently.

// ---------------------------------------------------------------------------
// CloudReport
// ---------------------------------------------------------------------------

/// Aggregated report from a cloud provider operation.
///
/// Contains the detected provider, resolved security groups, and any
/// findings generated during the operation.
#[derive(Debug, Clone)]
pub struct CloudReport {
    /// The detected cloud provider.
    pub provider: crate::CloudProvider,
    /// Security groups discovered or managed.
    pub security_groups: Vec<crate::spec::SecurityGroup>,
    /// Findings produced during the operation.
    pub findings: Vec<Finding>,
}

impl CloudReport {
    /// Create an empty report for the given provider.
    #[must_use]
    pub fn new(provider: crate::CloudProvider) -> Self {
        Self {
            provider,
            security_groups: Vec::new(),
            findings: Vec::new(),
        }
    }

    /// Returns `true` if this report contains no security groups and no findings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.security_groups.is_empty() && self.findings.is_empty()
    }

    /// Returns `true` if any finding has severity [`Severity::Error`] or higher.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.findings.iter().any(|f| f.severity >= Severity::Error)
    }

    /// Add a finding to the report.
    pub fn push(&mut self, finding: Finding) {
        self.findings.push(finding);
    }
}

impl std::fmt::Display for CloudReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Cloud report for {}: {} security group(s), {} finding(s)",
            self.provider,
            self.security_groups.len(),
            self.findings.len()
        )?;
        for finding in &self.findings {
            writeln!(
                f,
                "  [{severity}] {id}: {title}",
                severity = finding.severity,
                id = finding.id,
                title = finding.title
            )?;
            if !finding.detail.is_empty() {
                writeln!(f, "    {detail}", detail = finding.detail)?;
            }
            if let Some(fix) = &finding.fix {
                writeln!(f, "    fix: {fix}")?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

/// Diagnostic severity level for findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
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

impl std::fmt::Display for Severity {
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
// Finding
// ---------------------------------------------------------------------------

/// A single structured finding produced by a cloud operation or diagnostic.
///
/// Use [`Finding::new`] to construct the mandatory fields, then chain the
/// `.detail()` and `.fix()` builder methods for optional context.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Machine-readable dot-separated identifier,
    /// e.g. `"aws.security-group.open-ingress"`.
    pub id: String,
    /// How severe this finding is.
    pub severity: Severity,
    /// Short human-readable title (one line).
    pub title: String,
    /// Longer description of the finding.
    pub detail: String,
    /// Suggested remediation action, if applicable.
    pub fix: Option<String>,
}

impl Finding {
    /// Create a new finding with the mandatory fields.
    #[must_use]
    pub fn new(id: impl Into<String>, severity: Severity, title: impl Into<String>) -> Self {
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CloudProvider;

    // -- CloudReport ---------------------------------------------------------

    #[test]
    fn cloud_report_new_is_empty() {
        let report = CloudReport::new(CloudProvider::Aws);
        assert!(report.is_empty());
        assert!(report.findings.is_empty());
        assert!(report.security_groups.is_empty());
    }

    #[test]
    fn cloud_report_is_empty_true_when_nothing_added() {
        let report = CloudReport::new(CloudProvider::Gcp);
        assert!(report.is_empty());
    }

    #[test]
    fn cloud_report_push_adds_finding() {
        let mut report = CloudReport::new(CloudProvider::Aws);
        let finding = Finding::new("test.001", Severity::Info, "Test finding");
        report.push(finding);
        assert!(!report.is_empty());
        assert_eq!(report.findings.len(), 1);
    }

    #[test]
    fn cloud_report_has_errors_false_when_no_errors() {
        let report = CloudReport::new(CloudProvider::Aws);
        assert!(!report.has_errors());
    }

    #[test]
    fn cloud_report_has_errors_true_with_error_severity() {
        let mut report = CloudReport::new(CloudProvider::Aws);
        report.push(Finding::new("err.001", Severity::Error, "Something broke"));
        assert!(report.has_errors());
    }

    #[test]
    fn cloud_report_has_errors_true_with_critical_severity() {
        let mut report = CloudReport::new(CloudProvider::Aws);
        report.push(Finding::new(
            "crit.001",
            Severity::Critical,
            "Everything is on fire",
        ));
        assert!(report.has_errors());
    }

    #[test]
    fn cloud_report_has_errors_false_with_only_warnings() {
        let mut report = CloudReport::new(CloudProvider::Aws);
        report.push(Finding::new("warn.001", Severity::Warning, "Minor issue"));
        assert!(!report.has_errors());
    }

    // -- Finding builder pattern ---------------------------------------------

    #[test]
    fn finding_new_sets_mandatory_fields() {
        let f = Finding::new("aws.sg.open", Severity::Warning, "Open ingress");
        assert_eq!(f.id, "aws.sg.open");
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.title, "Open ingress");
        assert!(f.detail.is_empty());
        assert!(f.fix.is_none());
    }

    #[test]
    fn finding_builder_chains_detail_and_fix() {
        let f = Finding::new("test.001", Severity::Error, "Bad config")
            .detail("The CIDR block is too permissive")
            .fix("Restrict the CIDR to your VPC range");
        assert_eq!(f.detail, "The CIDR block is too permissive");
        assert_eq!(
            f.fix,
            Some("Restrict the CIDR to your VPC range".to_string())
        );
    }

    // -- Severity ordering ---------------------------------------------------

    #[test]
    fn severity_ordering_critical_is_highest() {
        assert!(Severity::Critical > Severity::Error);
        assert!(Severity::Critical > Severity::Warning);
        assert!(Severity::Critical > Severity::Info);
        assert!(Severity::Critical > Severity::Ok);
    }

    #[test]
    fn severity_ordering_error_above_warning() {
        assert!(Severity::Error > Severity::Warning);
        assert!(Severity::Error > Severity::Info);
        assert!(Severity::Error > Severity::Ok);
    }

    #[test]
    fn severity_ordering_warning_above_info() {
        assert!(Severity::Warning > Severity::Info);
        assert!(Severity::Warning > Severity::Ok);
    }

    #[test]
    fn severity_ordering_info_above_ok() {
        assert!(Severity::Info > Severity::Ok);
    }

    // -- Severity Display ----------------------------------------------------

    #[test]
    fn severity_display_formats() {
        assert_eq!(Severity::Ok.to_string(), "OK");
        assert_eq!(Severity::Info.to_string(), "INFO");
        assert_eq!(Severity::Warning.to_string(), "WARNING");
        assert_eq!(Severity::Error.to_string(), "ERROR");
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
    }
}
