//! Convert `toride-audit` library types to UI presentation types.
//!
//! This is the single boundary for pure type mapping between backend and
//! presentation — mirroring `fail2ban_convert.rs`'s role. The data layer
//! (`toride_audit_data.rs`) additionally calls backend facade methods, which
//! is consistent with every sibling data file in the crate. Each function
//! here handles errors gracefully: malformed input is skipped with a
//! `tracing::warn!` and a placeholder, never propagated (the read-only
//! section must never crash the TUI).

use crate::ui::screens::toride_audit::{
    AuditFindingEntry, AuditLogSourceEntry, AuditRuleEntry, IntegrityStateEntry,
};

/// Map a backend [`toride_audit::report::AuditSeverity`] to a lowercase string
/// used by the presentation layer: `"ok" | "info" | "warning" | "error" |
/// "critical"`. Kept here so the TUI never imports the Severity enum directly.
fn severity_str(s: toride_audit::report::AuditSeverity) -> &'static str {
    use toride_audit::report::AuditSeverity;
    match s {
        AuditSeverity::Ok => "ok",
        AuditSeverity::Info => "info",
        AuditSeverity::Warning => "warning",
        AuditSeverity::Error => "error",
        AuditSeverity::Critical => "critical",
    }
}

/// Convert backend doctor findings to UI entries.
///
/// Every finding maps 1:1. An empty `id` or `title` is logged and the entry is
/// still produced with a placeholder so the row count matches the backend (the
/// operator can see "something" even if the finding is malformed).
pub fn convert_findings(
    findings: Vec<toride_audit::report::AuditFinding>,
) -> Vec<AuditFindingEntry> {
    findings
        .into_iter()
        .map(|f| {
            if f.id.is_empty() || f.title.is_empty() {
                tracing::warn!(
                    "audit finding with empty id/title: id={:?} title={:?}",
                    f.id,
                    f.title
                );
            }
            AuditFindingEntry {
                id: if f.id.is_empty() {
                    "(unknown)".into()
                } else {
                    f.id
                },
                severity: severity_str(f.severity).to_string(),
                title: if f.title.is_empty() {
                    "(no title)".into()
                } else {
                    f.title
                },
                detail: f.detail,
                fix: f.fix,
            }
        })
        .collect()
}

/// Convert a backend [`toride_audit::integrity::IntegrityStatus`] into a
/// presentation entry. Malformed/unknown fields degrade to placeholders rather
/// than propagating errors.
pub fn convert_integrity(status: toride_audit::integrity::IntegrityStatus) -> IntegrityStateEntry {
    IntegrityStateEntry {
        database_initialized: status.database_initialized,
        file_count: status.file_count,
        last_check_passed: status.last_check_passed,
        last_check_output: status.last_check_output,
    }
}

/// Convert backend audit rule files into presentation entries. The active-rule
/// filter (skip blanks / `#` comments) is delegated to the backend's
/// [`toride_audit::auditd_rules::AuditRuleFile::rules()`] helper so there is a
/// single source of truth for what counts as an active rule line; this mapper
/// only trims each surviving line (the backend returns the original,
/// possibly-indented text) and flattens to owned strings.
pub fn convert_rule_files(
    files: Vec<toride_audit::auditd_rules::AuditRuleFile>,
) -> Vec<AuditRuleEntry> {
    let mut entries: Vec<AuditRuleEntry> = Vec::new();
    for file in files {
        // An empty name is malformed — log and skip the whole file rather than
        // emit a placeholder row that would inflate the count misleadingly.
        if file.name.is_empty() {
            tracing::warn!(
                "audit rule file with empty name; content len={}",
                file.content.len()
            );
            continue;
        }
        // `rules()` filters blanks/comments; we still trim so indented rule
        // lines render flush-left in the panel (the backend keeps leading
        // whitespace, which would misalign the `· ` bullet column).
        let rules: Vec<String> = file.rules().iter().map(|l| l.trim().to_string()).collect();
        entries.push(AuditRuleEntry {
            name: file.name,
            rule_count: rules.len(),
            rules,
        });
    }
    entries
}

/// Parse `/var/log/audit` file paths (as returned by
/// `LogManager::list_log_files`) into presentation rows. Each entry keeps the
/// full path and a best-effort basename label.
pub fn convert_log_files(paths: Vec<String>) -> Vec<AuditLogSourceEntry> {
    paths
        .into_iter()
        .map(|path| {
            let label = path
                .rsplit('/')
                .next()
                .filter(|s| !s.is_empty())
                .unwrap_or("(unnamed)")
                .to_string();
            AuditLogSourceEntry { label, path }
        })
        .collect()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use toride_audit::auditd_rules::AuditRuleFile;
    use toride_audit::integrity::IntegrityStatus;
    use toride_audit::report::{AuditFinding, AuditSeverity};

    // ── convert_findings ──────────────────────────────────────────────────────

    #[test]
    fn convert_findings_empty() {
        assert!(convert_findings(Vec::new()).is_empty());
    }

    #[test]
    fn convert_findings_maps_severity() {
        let findings = vec![
            AuditFinding::new("a", AuditSeverity::Critical, "t1"),
            AuditFinding::new("b", AuditSeverity::Error, "t2"),
            AuditFinding::new("c", AuditSeverity::Warning, "t3"),
            AuditFinding::new("d", AuditSeverity::Info, "t4"),
            AuditFinding::new("e", AuditSeverity::Ok, "t5"),
        ];
        let entries = convert_findings(findings);
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0].severity, "critical");
        assert_eq!(entries[1].severity, "error");
        assert_eq!(entries[2].severity, "warning");
        assert_eq!(entries[3].severity, "info");
        assert_eq!(entries[4].severity, "ok");
    }

    #[test]
    fn convert_findings_preserves_detail_and_fix() {
        let f = AuditFinding::new("id", AuditSeverity::Warning, "title")
            .detail("the detail")
            .fix("the fix");
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].detail, "the detail");
        assert_eq!(entries[0].fix.as_deref(), Some("the fix"));
    }

    #[test]
    fn convert_findings_placeholder_for_empty_fields() {
        let f = AuditFinding::new("", AuditSeverity::Ok, "");
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].id, "(unknown)");
        assert_eq!(entries[0].title, "(no title)");
    }

    // ── convert_integrity ─────────────────────────────────────────────────────

    #[test]
    fn convert_integrity_maps_fields() {
        let s = IntegrityStatus {
            database_initialized: true,
            file_count: Some(1234),
            last_check_passed: Some(true),
            last_check_output: Some("ok".to_string()),
        };
        let e = convert_integrity(s);
        assert!(e.database_initialized);
        assert_eq!(e.file_count, Some(1234));
        assert_eq!(e.last_check_passed, Some(true));
        assert_eq!(e.last_check_output.as_deref(), Some("ok"));
    }

    #[test]
    fn convert_integrity_empty() {
        let e = convert_integrity(IntegrityStatus {
            database_initialized: false,
            file_count: None,
            last_check_passed: None,
            last_check_output: None,
        });
        assert!(!e.database_initialized);
        assert!(e.file_count.is_none());
    }

    // ── convert_rule_files ────────────────────────────────────────────────────

    #[test]
    fn convert_rule_files_counts_rules_skipping_comments() {
        let files = vec![AuditRuleFile {
            name: "hardening".to_string(),
            content: "# header\n\n-w /etc/passwd -p wa -k identity\n-a always,exit -S open\n"
                .to_string(),
        }];
        let entries = convert_rule_files(files);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "hardening");
        assert_eq!(entries[0].rule_count, 2);
        assert_eq!(entries[0].rules.len(), 2);
    }

    #[test]
    fn convert_rule_files_skips_empty_name() {
        let files = vec![AuditRuleFile {
            name: String::new(),
            content: "-w /etc/shadow".to_string(),
        }];
        assert!(convert_rule_files(files).is_empty());
    }

    #[test]
    fn convert_rule_files_empty_input() {
        assert!(convert_rule_files(Vec::new()).is_empty());
    }

    #[test]
    fn convert_rule_files_only_comments_yields_zero_rules() {
        let files = vec![AuditRuleFile {
            name: "comments".to_string(),
            content: "# just a comment\n# another\n".to_string(),
        }];
        let entries = convert_rule_files(files);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].rule_count, 0);
        assert!(entries[0].rules.is_empty());
    }

    #[test]
    fn convert_rule_files_empty_content_yields_zero_rules() {
        // A rule file with a name but truly empty content (""), pinning the
        // degenerate path through `AuditRuleFile::rules()`.
        let files = vec![AuditRuleFile {
            name: "x".to_string(),
            content: String::new(),
        }];
        let entries = convert_rule_files(files);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].rule_count, 0);
        assert!(entries[0].rules.is_empty());
    }

    #[test]
    fn convert_rule_files_only_blanks_yields_zero_rules() {
        // Content with only blank lines (no comments, no rules).
        let files = vec![AuditRuleFile {
            name: "x".to_string(),
            content: "\n\n\n".to_string(),
        }];
        let entries = convert_rule_files(files);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].rule_count, 0);
        assert!(entries[0].rules.is_empty());
    }

    // ── convert_log_files ─────────────────────────────────────────────────────

    #[test]
    fn convert_log_files_extracts_basename() {
        let entries = convert_log_files(vec![
            "/var/log/audit/audit.log".to_string(),
            "/var/log/audit/audit.log.1".to_string(),
        ]);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].label, "audit.log");
        assert_eq!(entries[0].path, "/var/log/audit/audit.log");
        assert_eq!(entries[1].label, "audit.log.1");
    }

    #[test]
    fn convert_log_files_empty() {
        assert!(convert_log_files(Vec::new()).is_empty());
    }

    #[test]
    fn convert_log_files_unnamed_fallback() {
        // A path with no basename segment falls back to the placeholder.
        let entries = convert_log_files(vec!["/".to_string()]);
        assert_eq!(entries[0].label, "(unnamed)");
    }

    #[test]
    fn convert_log_files_trailing_slash_unnamed_fallback() {
        // The more realistic malformed case on real hosts: a trailing slash,
        // where `rsplit('/').next()` yields `Some("")` and is discarded by the
        // filter, falling back to the placeholder.
        let entries = convert_log_files(vec!["/var/log/audit/".to_string()]);
        assert_eq!(entries[0].label, "(unnamed)");
        assert_eq!(entries[0].path, "/var/log/audit/");
    }
}
