//! Structured report of hardening operations.
//!
//! [`HardenReport`] captures which parameters were applied, which were
//! skipped (already set), and the current state snapshot.

use crate::spec::SysctlParam;

/// Result of a hardening apply operation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HardenReport {
    /// Parameters that were successfully applied (changed from previous value).
    pub applied: Vec<SysctlParam>,
    /// Parameters that were skipped because they already had the desired value.
    pub skipped: Vec<SysctlParam>,
    /// Current sysctl values at the time of the report (key, value).
    pub current: Vec<(String, String)>,
}

impl HardenReport {
    /// Create an empty report.
    pub fn new() -> Self {
        Self {
            applied: Vec::new(),
            skipped: Vec::new(),
            current: Vec::new(),
        }
    }

    /// Total number of parameters processed.
    pub fn total(&self) -> usize {
        self.applied.len() + self.skipped.len()
    }

    /// Returns `true` if no parameters were applied (all were already set).
    pub fn is_noop(&self) -> bool {
        self.applied.is_empty()
    }

    /// Render the report as a human-readable summary.
    pub fn to_summary(&self) -> String {
        let mut lines = Vec::new();

        if self.applied.is_empty() && self.skipped.is_empty() {
            lines.push("No parameters processed.".into());
            return lines.join("\n");
        }

        if !self.applied.is_empty() {
            lines.push(format!("Applied {} parameter(s):", self.applied.len()));
            for p in &self.applied {
                lines.push(format!("  {} = {}", p.key, p.value));
            }
        }

        if !self.skipped.is_empty() {
            lines.push(format!(
                "Skipped {} parameter(s) (already set):",
                self.skipped.len()
            ));
            for p in &self.skipped {
                lines.push(format!("  {} = {}", p.key, p.value));
            }
        }

        lines.join("\n")
    }
}

impl Default for HardenReport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_report_is_noop() {
        let report = HardenReport::new();
        assert!(report.is_noop());
        assert_eq!(report.total(), 0);
    }

    #[test]
    fn summary_format() {
        let report = HardenReport {
            applied: vec![SysctlParam::new("kernel.kptr_restrict", "1", "kptr")],
            skipped: vec![SysctlParam::new("kernel.aslr", "2", "aslr")],
            current: vec![("kernel.kptr_restrict".into(), "1".into())],
        };
        let summary = report.to_summary();
        assert!(summary.contains("Applied 1 parameter"));
        assert!(summary.contains("Skipped 1 parameter"));
        assert!(!report.is_noop());
    }
}
