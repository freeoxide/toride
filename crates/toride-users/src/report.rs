//! Diagnostic report types for user and access control findings.
//!
//! Defines [`UserReport`] and [`UserFinding`] for structured reporting of
//! user security issues discovered by the doctor module.

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

/// Diagnostic severity level for user security findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
// UserFinding
// ---------------------------------------------------------------------------

/// A single structured finding about a user security issue.
///
/// Use [`UserFinding::new`] to construct, then chain `.detail()` and
/// `.fix()` for optional context.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UserFinding {
    /// Machine-readable dot-separated identifier,
    /// e.g. `"user.root-login.enabled"`.
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

impl UserFinding {
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

    /// Attach a longer description.
    #[must_use]
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    /// Attach a suggested fix action.
    #[must_use]
    pub fn fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
}

// ---------------------------------------------------------------------------
// UserReport
// ---------------------------------------------------------------------------

/// Aggregated report of user and access control findings.
///
/// Contains all findings from a diagnostic run and provides convenience
/// methods for summarising results.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UserReport {
    /// All findings collected during the diagnostic run.
    pub findings: Vec<UserFinding>,
}

impl UserReport {
    /// Create an empty report.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a finding to the report.
    pub fn push(&mut self, finding: UserFinding) {
        self.findings.push(finding);
    }

    /// Returns the number of findings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.findings.len()
    }

    /// Returns `true` if this report contains no findings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Returns `true` if any finding has severity [`Severity::Error`] or higher.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.findings.iter().any(|f| f.severity >= Severity::Error)
    }

    /// Returns `true` if any finding has severity [`Severity::Critical`].
    #[must_use]
    pub fn has_critical(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == Severity::Critical)
    }

    /// Returns all findings with severity at or above the given level.
    #[must_use]
    pub fn findings_at_or_above(&self, min_severity: Severity) -> Vec<&UserFinding> {
        self.findings
            .iter()
            .filter(|f| f.severity >= min_severity)
            .collect()
    }
}
