//! Doctor report -- a collection of findings for a single domain.

use crate::{Finding, Severity};

/// Summary statistics for a [`DoctorReport`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReportSummary {
    /// Total number of findings.
    pub total: usize,
    /// Count per severity level.
    pub by_severity: Vec<(Severity, usize)>,
    /// Whether the report is considered healthy.
    pub healthy: bool,
}

/// A completed diagnostic run for a single domain.
///
/// ```
/// use toride_diagnostic_types::{DoctorReport, Finding, Severity};
///
/// let report = DoctorReport::new(
///     "ssh",
///     vec![Finding::new("ssh:key-exists", Severity::Ok, "Key present")],
/// );
/// assert!(report.is_healthy());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DoctorReport {
    /// The domain this report covers (e.g. `"ssh"`, `"firewall"`).
    pub domain: String,
    /// All findings from the run, in order.
    pub findings: Vec<Finding>,
    /// ISO-8601 timestamp of when the checks were executed.
    pub checked_at: String,
}

impl DoctorReport {
    /// Create a new report with the current UTC timestamp.
    #[must_use]
    pub fn new(domain: impl Into<String>, findings: Vec<Finding>) -> Self {
        Self {
            domain: domain.into(),
            findings,
            checked_at: String::from("<now>"), // TODO: use chrono/time when available
        }
    }

    /// Create a report with a specific timestamp.
    #[must_use]
    pub fn with_timestamp(
        domain: impl Into<String>,
        findings: Vec<Finding>,
        checked_at: impl Into<String>,
    ) -> Self {
        Self {
            domain: domain.into(),
            findings,
            checked_at: checked_at.into(),
        }
    }

    /// Returns `true` when there are no [`Severity::Critical`] or
    /// [`Severity::Important`] findings.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        !self
            .findings
            .iter()
            .any(|f| matches!(f.severity, Severity::Critical | Severity::Important))
    }

    /// Compute a summary of severity counts.
    #[must_use]
    pub fn summary(&self) -> ReportSummary {
        let severities = [
            Severity::Critical,
            Severity::Important,
            Severity::Warning,
            Severity::Info,
            Severity::Ok,
        ];

        let by_severity: Vec<(Severity, usize)> = severities
            .iter()
            .map(|&sev| {
                let count = self.findings.iter().filter(|f| f.severity == sev).count();
                (sev, count)
            })
            .filter(|(_, c)| *c > 0)
            .collect();

        ReportSummary {
            total: self.findings.len(),
            by_severity,
            healthy: self.is_healthy(),
        }
    }

    /// Return only actionable (critical + important) findings.
    #[must_use]
    pub fn actionable(&self) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.is_actionable()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthy_when_all_ok() {
        let r = DoctorReport::new(
            "ssh",
            vec![
                Finding::new("a", Severity::Ok, "fine"),
                Finding::new("b", Severity::Ok, "also fine"),
            ],
        );
        assert!(r.is_healthy());
    }

    #[test]
    fn not_healthy_with_critical() {
        let r = DoctorReport::new("ssh", vec![Finding::new("a", Severity::Critical, "broken")]);
        assert!(!r.is_healthy());
    }

    #[test]
    fn not_healthy_with_important() {
        let r = DoctorReport::new("ssh", vec![Finding::new("a", Severity::Important, "bad")]);
        assert!(!r.is_healthy());
    }

    #[test]
    fn summary_counts() {
        let r = DoctorReport::new(
            "ssh",
            vec![
                Finding::new("a", Severity::Ok, "fine"),
                Finding::new("b", Severity::Ok, "fine"),
                Finding::new("c", Severity::Warning, "meh"),
            ],
        );
        let s = r.summary();
        assert_eq!(s.total, 3);
        assert_eq!(s.by_severity.len(), 2); // Warning + Ok
        assert!(s.healthy);
    }

    #[test]
    fn actionable_filters() {
        let r = DoctorReport::new(
            "ssh",
            vec![
                Finding::new("a", Severity::Critical, "fix me"),
                Finding::new("b", Severity::Ok, "fine"),
                Finding::new("c", Severity::Important, "also fix"),
            ],
        );
        assert_eq!(r.actionable().len(), 2);
    }
}
