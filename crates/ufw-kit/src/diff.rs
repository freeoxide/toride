//! Diff utilities for comparing file contents before and after changes.
//!
//! Provides both generic file diff and firewall-specific diff operations.

use crate::spec::{Finding, Severity};

/// Compute a unified diff between old and new content.
#[must_use]
pub fn unified_diff(old: &str, new: &str, context: &str) -> String {
    similar::TextDiff::from_lines(old, new)
        .unified_diff()
        .context_radius(3)
        .header(&format!("a/{context}"), &format!("b/{context}"))
        .to_string()
}

/// Check if two strings are identical.
#[must_use]
pub fn is_identical(old: &str, new: &str) -> bool {
    old == new
}

/// Result of comparing two firewall configurations.
#[derive(Debug, Clone)]
pub struct FirewallDiff {
    /// Files that changed.
    pub changed_files: Vec<FileDiff>,
    /// Files that are identical.
    pub unchanged_files: Vec<String>,
    /// Summary of changes as findings.
    pub findings: Vec<Finding>,
}

/// Diff for a single file.
#[derive(Debug, Clone)]
pub struct FileDiff {
    /// File path or name.
    pub path: String,
    /// Unified diff output.
    pub diff: String,
    /// Number of lines added.
    pub lines_added: usize,
    /// Number of lines removed.
    pub lines_removed: usize,
}

/// Compare two firewall configuration file sets.
///
/// Takes parallel lists of file names and their before/after contents.
/// Returns a structured diff result with findings for significant changes.
#[must_use]
pub fn diff_firewall_configs(
    files: &[(&str, &str, &str)], // (name, before, after)
) -> FirewallDiff {
    let mut changed_files = Vec::new();
    let mut unchanged_files = Vec::new();
    let mut findings = Vec::new();

    for &(name, before, after) in files {
        if is_identical(before, after) {
            unchanged_files.push(name.to_string());
            continue;
        }

        let diff = unified_diff(before, after, name);
        let lines_added = diff
            .lines()
            .filter(|l| l.starts_with('+') && !l.starts_with("+++"))
            .count();
        let lines_removed = diff
            .lines()
            .filter(|l| l.starts_with('-') && !l.starts_with("---"))
            .count();

        // Generate findings for significant changes
        let name_lower = name.to_lowercase();

        if name_lower.contains("before.rules") || name_lower.contains("after.rules") {
            findings.push(Finding {
                id: "diff:framework:changed",
                severity: Severity::Warning,
                title: format!("Framework file changed: {name}"),
                detail: format!(
                    "Framework file {name} has {lines_added} line(s) added and {lines_removed} line(s) removed. \
                     Changes to framework files can affect firewall behavior."
                ),
                fix: Some(
                    "Review the changes carefully. Ensure managed blocks are intact and \
                     no unmanaged rules were introduced.".into(),
                ),
            });
        }

        if name_lower.contains("user.rules") {
            findings.push(Finding {
                id: "diff:user-rules:changed",
                severity: Severity::Warning,
                title: format!("User rules file changed: {name}"),
                detail: format!(
                    "User rules file {name} has {lines_added} line(s) added and {lines_removed} line(s) removed."
                ),
                fix: Some(
                    "Review the changes. User rules should typically be managed via the UFW CLI, \
                     not edited directly.".into(),
                ),
            });
        }

        if name_lower.contains("ufw.conf") || name_lower.contains("default/ufw") {
            findings.push(Finding {
                id: "diff:config:changed",
                severity: Severity::Info,
                title: format!("Config file changed: {name}"),
                detail: format!(
                    "Configuration file {name} has {lines_added} line(s) added and {lines_removed} line(s) removed."
                ),
                fix: None,
            });
        }

        changed_files.push(FileDiff {
            path: name.to_string(),
            diff,
            lines_added,
            lines_removed,
        });
    }

    FirewallDiff {
        changed_files,
        unchanged_files,
        findings,
    }
}

/// Compare two UFW status snapshots and return findings for differences.
///
/// Useful for detecting changes between two points in time.
#[must_use]
pub fn diff_status_findings(
    before_rules: &[crate::spec::ParsedRule],
    after_rules: &[crate::spec::ParsedRule],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Find added rules
    for after_rule in after_rules {
        let exists_before = before_rules.iter().any(|b| b.raw == after_rule.raw);
        if !exists_before {
            findings.push(Finding {
                id: "diff:rule:added",
                severity: Severity::Info,
                title: "Rule added".into(),
                detail: format!("New rule detected: {}", after_rule.raw),
                fix: None,
            });
        }
    }

    // Find removed rules
    for before_rule in before_rules {
        let exists_after = after_rules.iter().any(|a| a.raw == before_rule.raw);
        if !exists_after {
            findings.push(Finding {
                id: "diff:rule:removed",
                severity: Severity::Warning,
                title: "Rule removed".into(),
                detail: format!("Rule was removed: {}", before_rule.raw),
                fix: None,
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unified_diff_should_show_changes() {
        let old = "line1\nline2\nline3\n";
        let new = "line1\nmodified\nline3\n";
        let diff = unified_diff(old, new, "test.txt");
        assert!(diff.contains("-line2"));
        assert!(diff.contains("+modified"));
    }

    #[test]
    fn is_identical_should_return_true_for_same_content() {
        assert!(is_identical("hello", "hello"));
    }

    #[test]
    fn is_identical_should_return_false_for_different_content() {
        assert!(!is_identical("hello", "world"));
    }

    #[test]
    fn diff_firewall_configs_should_detect_changes() {
        let files = vec![
            (
                "before.rules",
                "*filter\n:INPUT ACCEPT\nCOMMIT\n",
                "*filter\n:INPUT DROP\nCOMMIT\n",
            ),
            ("ufw.conf", "ENABLED=yes\n", "ENABLED=yes\n"),
        ];
        let result = diff_firewall_configs(&files);
        assert_eq!(result.changed_files.len(), 1);
        assert_eq!(result.unchanged_files.len(), 1);
        assert!(!result.findings.is_empty());
    }

    #[test]
    fn diff_firewall_configs_should_return_empty_for_no_changes() {
        let files = vec![("ufw.conf", "ENABLED=yes\n", "ENABLED=yes\n")];
        let result = diff_firewall_configs(&files);
        assert!(result.changed_files.is_empty());
        assert_eq!(result.unchanged_files.len(), 1);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn diff_status_findings_should_detect_added_and_removed_rules() {
        let before = vec![crate::spec::ParsedRule {
            number: Some(1),
            raw: "22/tcp ALLOW IN Anywhere".into(),
            action: Some(crate::spec::Action::Allow),
            direction: Some(crate::spec::Direction::In),
            protocol: Some(crate::spec::Protocol::Tcp),
            from: Some("Anywhere".into()),
            to: Some("22/tcp".into()),
            comment: None,
            ipv6: false,
            is_route: false,
        }];
        let after = vec![crate::spec::ParsedRule {
            number: Some(1),
            raw: "80/tcp ALLOW IN Anywhere".into(),
            action: Some(crate::spec::Action::Allow),
            direction: Some(crate::spec::Direction::In),
            protocol: Some(crate::spec::Protocol::Tcp),
            from: Some("Anywhere".into()),
            to: Some("80/tcp".into()),
            comment: None,
            ipv6: false,
            is_route: false,
        }];

        let findings = diff_status_findings(&before, &after);
        assert_eq!(findings.len(), 2); // one added, one removed
    }
}
