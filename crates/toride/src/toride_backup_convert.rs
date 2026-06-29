//! Convert `toride_backup` library types to UI presentation types.
//!
//! This is the ONLY module in the `toride` crate that maps backend
//! `toride_backup` types to UI presentation types — mirroring
//! `fail2ban_convert.rs`'s role as the single conversion boundary between
//! backend and presentation. (The I/O boundary — `BackupClient`,
//! `ScheduleManager`, etc. — is owned by `toride_backup_data.rs`, mirroring
//! `fail2ban_data.rs` / `toride_harden_data.rs`.) Each function handles
//! malformed input gracefully: empty ids/titles are replaced with a
//! placeholder and a `tracing::warn!` is logged, never propagated (the
//! read-only section must never crash the TUI).

use crate::ui::screens::toride_backup::FindingEntry;

/// Map a backend [`toride_backup::doctor::Severity`] to a lowercase string
/// used by the presentation layer: `"ok" | "info" | "warning" | "error" |
/// "critical"`. Kept here so the TUI never imports the Severity enum directly.
///
/// NOTE: `toride_backup::doctor` is the single module that defines the
/// `Severity` enum (the `report` module has no `Severity` of its own), so
/// mapping against the `doctor` path keeps the dependency on the single
/// stable surface that actually owns the type.
fn severity_str(s: toride_backup::doctor::Severity) -> &'static str {
    use toride_backup::doctor::Severity;
    match s {
        Severity::Ok => "ok",
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Error => "error",
        Severity::Critical => "critical",
    }
}

/// Convert backend doctor findings to UI entries.
///
/// Every finding maps 1:1. An empty `id` or `title` is logged and the entry is
/// still produced with a placeholder so the row count matches the backend (the
/// operator can see "something" even if the finding is malformed). An empty
/// `fix` string (e.g. `Some("")`) is normalized to `None` so the render layer
/// never shows a dangling `→ ` arrow implying a fix exists when none does —
/// consistent with the placeholder treatment for empty `id`/`title`. Mirrors
/// [`fail2ban_convert::convert_findings`].
pub fn convert_findings(findings: Vec<toride_backup::doctor::Finding>) -> Vec<FindingEntry> {
    findings
        .into_iter()
        .map(|f| {
            if f.id.is_empty() || f.title.is_empty() {
                tracing::warn!(
                    "backup finding with empty id/title: id={:?} title={:?}",
                    f.id,
                    f.title
                );
            }
            if f.fix.as_deref().is_some_and(str::is_empty) {
                tracing::warn!(
                    "backup finding with empty fix string: id={:?} title={:?} \
                     — normalizing to None",
                    f.id,
                    f.title
                );
            }
            FindingEntry {
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
                fix: f.fix.filter(|s| !s.is_empty()),
            }
        })
        .collect()
}

/// Derive restic/borg binary availability from the doctor findings.
///
/// The doctor's `Binary` scope emits one finding per backend with a
/// machine-readable id (`binary.restic.found` / `binary.restic.missing` and the
/// same for borg). Rather than re-shelling out to `which` here, we infer
/// presence from the finding set: `Some(true)` when a `*.found` finding is
/// present, `Some(false)` when only the corresponding `*.missing` finding is
/// present, `None` when neither appears (the doctor did not run the Binary
/// scope, e.g. a narrower `DoctorScope` was requested).
///
/// This keeps the convert layer pure (no I/O) and keeps a single source of
/// truth for "is restic installed" — the doctor — consistent with how the
/// availability flag itself is computed downstream.
///
/// Precedence: if BOTH `binary.<x>.found` AND `binary.<x>.missing` appear
/// (e.g. a future doctor check that found the binary on one PATH and missing
/// on another), the `.found` branch wins via the `if ... else if` cascade →
/// `Some(true)`. This is a defensible "optimistic" default; the resolution
/// rule is documented here and exercised by
/// `derive_availability_found_wins_when_both_present`.
pub fn derive_binary_availability(findings: &[FindingEntry], binary: BackupBinary) -> Option<bool> {
    let found_id = match binary {
        BackupBinary::Restic => "binary.restic.found",
        BackupBinary::Borg => "binary.borg.found",
    };
    let missing_id = match binary {
        BackupBinary::Restic => "binary.restic.missing",
        BackupBinary::Borg => "binary.borg.missing",
    };
    if findings.iter().any(|f| f.id == found_id) {
        Some(true)
    } else if findings.iter().any(|f| f.id == missing_id) {
        Some(false)
    } else {
        None
    }
}

/// Which backup binary to query availability for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupBinary {
    /// The `restic` binary.
    Restic,
    /// The `borg` binary.
    Borg,
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use toride_backup::doctor::{Finding, Severity};

    // ── convert_findings ──────────────────────────────────────────────────────

    #[test]
    fn convert_findings_empty() {
        assert!(convert_findings(Vec::new()).is_empty());
    }

    #[test]
    fn convert_findings_maps_severity() {
        let findings = vec![
            Finding::new("a", Severity::Critical, "t1"),
            Finding::new("b", Severity::Error, "t2"),
            Finding::new("c", Severity::Warning, "t3"),
            Finding::new("d", Severity::Info, "t4"),
            Finding::new("e", Severity::Ok, "t5"),
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
        let f = Finding::new("id", Severity::Warning, "title")
            .detail("the detail")
            .fix("the fix");
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].detail, "the detail");
        assert_eq!(entries[0].fix.as_deref(), Some("the fix"));
    }

    #[test]
    fn convert_findings_placeholder_for_empty_fields() {
        let f = Finding::new("", Severity::Ok, "");
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].id, "(unknown)");
        assert_eq!(entries[0].title, "(no title)");
    }

    #[test]
    fn convert_findings_empty_fix_normalized_to_none() {
        // An empty fix string would otherwise render a dangling `→ ` arrow in
        // the UI. The convert layer normalizes `Some("")` to `None`, consistent
        // with the placeholder treatment for empty id/title.
        let f = Finding::new("id", Severity::Warning, "title").fix("");
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].fix, None);
    }

    #[test]
    fn convert_findings_nonempty_fix_preserved() {
        let f = Finding::new("id", Severity::Warning, "title").fix("do the thing");
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].fix.as_deref(), Some("do the thing"));
    }

    // ── derive_binary_availability ───────────────────────────────────────────

    fn entry(id: &str, sev: Severity) -> FindingEntry {
        FindingEntry {
            id: id.into(),
            severity: match sev {
                Severity::Ok => "ok",
                Severity::Info => "info",
                Severity::Warning => "warning",
                Severity::Error => "error",
                Severity::Critical => "critical",
            }
            .into(),
            title: id.into(),
            detail: String::new(),
            fix: None,
        }
    }

    #[test]
    fn derive_availability_found() {
        let findings = vec![entry("binary.restic.found", Severity::Ok)];
        assert_eq!(
            derive_binary_availability(&findings, BackupBinary::Restic),
            Some(true)
        );
    }

    #[test]
    fn derive_availability_missing() {
        let findings = vec![entry("binary.borg.missing", Severity::Info)];
        assert_eq!(
            derive_binary_availability(&findings, BackupBinary::Borg),
            Some(false)
        );
    }

    #[test]
    fn derive_availability_unknown_when_no_finding() {
        // A narrower DoctorScope that skipped the Binary category yields no
        // restic/borg finding at all → None (unknown), not false.
        let findings = vec![entry("some.other.finding", Severity::Info)];
        assert_eq!(
            derive_binary_availability(&findings, BackupBinary::Restic),
            None
        );
        assert_eq!(
            derive_binary_availability(&findings, BackupBinary::Borg),
            None
        );
    }

    #[test]
    fn derive_availability_empty_findings_is_unknown() {
        let findings: Vec<FindingEntry> = Vec::new();
        assert_eq!(
            derive_binary_availability(&findings, BackupBinary::Restic),
            None
        );
    }

    #[test]
    fn derive_availability_found_wins_when_both_present() {
        // Degenerate case: a future backend could emit both `binary.restic.found`
        // (e.g. found on one PATH) and `binary.restic.missing` (missing on
        // another). The `if ... else if` cascade prefers the `.found` branch,
        // yielding `Some(true)`. This documents the resolution rule.
        let findings = vec![
            entry("binary.restic.found", Severity::Ok),
            entry("binary.restic.missing", Severity::Warning),
        ];
        assert_eq!(
            derive_binary_availability(&findings, BackupBinary::Restic),
            Some(true)
        );
    }
}
