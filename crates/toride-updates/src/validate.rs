//! Spec and configuration validation.
//!
//! [`validate_spec`] checks an [`UpdateSpec`] for common misconfigurations
//! and returns a list of diagnostic findings. This is called before rendering
//! or applying any configuration changes.

use crate::error::Result;
use crate::spec::{Schedule, UpdateSpec};

// ---------------------------------------------------------------------------
// validate_spec
// ---------------------------------------------------------------------------

/// Validate an [`UpdateSpec`] and return a list of findings.
///
/// Checks include:
///
/// - Schedule format validity (for custom schedules)
/// - Origin pattern format
/// - Consistency between `auto_update` and related settings
///
/// Returns an empty `Vec` when the spec is valid. Individual findings are
/// informational warnings or errors; the caller decides how to act on them.
pub fn validate_spec(spec: &UpdateSpec) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // Validate schedule.
    if let Schedule::Custom(expr) = &spec.schedule {
        if expr.trim().is_empty() {
            findings.push(Finding::warning(
                "config.schedule.empty-custom",
                "Custom schedule expression is empty",
            ));
        }
        // Basic systemd calendar expression validation.
        // A full validator would use `systemd-analyze calendar`, but we do
        // a simple structural check here.
        if !expr.contains('*') && !expr.contains(':') {
            findings.push(Finding::info(
                "config.schedule.suspicious-custom",
                "Custom schedule does not look like a systemd calendar expression",
            ));
        }
    }

    // Validate origins (APT-specific).
    for origin in &spec.origins {
        if origin.trim().is_empty() {
            findings.push(Finding::warning(
                "config.origin.empty",
                "Empty origin pattern in spec",
            ));
        }
        // APT origin patterns should contain at least one comma-separated field.
        if spec.security_only && !origin.contains(',') {
            findings.push(Finding::info(
                "config.origin.simple-pattern",
                &format!("Origin pattern may be too broad: {origin}"),
            ));
        }
    }

    // Consistency: if auto_update is false but origins are set, warn.
    if !spec.auto_update && !spec.origins.is_empty() {
        findings.push(Finding::info(
            "config.consistency.disabled-with-origins",
            "Auto-update is disabled but origin patterns are configured",
        ));
    }

    Ok(findings)
}

// ---------------------------------------------------------------------------
// Finding (local lightweight finding type for validation)
// ---------------------------------------------------------------------------

/// A lightweight finding produced during validation.
///
/// Unlike the full [`toride_diagnostic_types::Finding`], this is a simple
/// struct used for pre-apply validation checks.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Machine-readable dot-separated identifier.
    pub id: String,
    /// Severity of the finding.
    pub severity: Severity,
    /// Short human-readable description.
    pub message: String,
}

/// Severity level for validation findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informational; no action required.
    Info,
    /// Non-critical issue.
    Warning,
    /// Error that may prevent correct operation.
    Error,
}

impl Finding {
    /// Create an informational finding.
    #[must_use]
    pub fn info(id: &str, message: &str) -> Self {
        Self {
            id: id.to_owned(),
            severity: Severity::Info,
            message: message.to_owned(),
        }
    }

    /// Create a warning finding.
    #[must_use]
    pub fn warning(id: &str, message: &str) -> Self {
        Self {
            id: id.to_owned(),
            severity: Severity::Warning,
            message: message.to_owned(),
        }
    }

    /// Create an error finding.
    #[must_use]
    pub fn error(id: &str, message: &str) -> Self {
        Self {
            id: id.to_owned(),
            severity: Severity::Error,
            message: message.to_owned(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_spec() -> UpdateSpec {
        UpdateSpec::default()
    }

    #[test]
    fn valid_spec_no_findings() {
        let findings = validate_spec(&valid_spec()).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn empty_custom_schedule_warns() {
        let spec = UpdateSpec {
            schedule: Schedule::Custom(String::new()),
            ..valid_spec()
        };
        let findings = validate_spec(&spec).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.id == "config.schedule.empty-custom")
        );
    }

    #[test]
    fn disabled_with_origins_info() {
        let spec = UpdateSpec::disabled();
        let findings = validate_spec(&spec).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.id == "config.consistency.disabled-with-origins")
        );
    }
}
