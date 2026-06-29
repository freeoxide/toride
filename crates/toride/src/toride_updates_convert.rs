//! Convert `toride-updates` library types to UI presentation types.
//!
//! This is the ONLY module in the `toride` crate that imports `toride_updates`
//! types — mirroring `fail2ban_convert.rs`'s role as the single boundary
//! between backend and presentation. Each function handles errors gracefully:
//! malformed input is skipped with a `tracing::warn!` and a placeholder, never
//! propagated (the read-only section must never crash the TUI).

use crate::ui::screens::toride_updates::FindingEntry;

/// Map a backend [`toride_updates::Severity`] (re-exported from
/// `toride_diagnostic_types::Severity`) to a lowercase string used by the
/// presentation layer: `"ok" | "info" | "warning" | "important" | "critical"`.
/// Kept here so the TUI never imports the Severity enum directly.
fn severity_str(s: toride_updates::Severity) -> &'static str {
    use toride_updates::Severity;
    match s {
        Severity::Ok => "ok",
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Important => "important",
        Severity::Critical => "critical",
    }
}

/// Convert backend doctor findings to UI entries.
///
/// Every finding maps 1:1. An empty `id` or `message` is logged and the entry
/// is still produced with a placeholder so the row count matches the backend
/// (the operator can see "something" even if the finding is malformed).
/// `detail` / `fix_hint` are `Option<String>` in the backend; the UI carries
/// `String` / `Option<String>`, so a `None` detail becomes an empty string and
/// a `None` `fix_hint` stays `None`.
pub fn convert_findings(findings: Vec<toride_updates::Finding>) -> Vec<FindingEntry> {
    findings
        .into_iter()
        .map(|f| {
            if f.id.is_empty() || f.message.is_empty() {
                tracing::warn!(
                    "updates finding with empty id/message: id={:?} message={:?}",
                    f.id,
                    f.message
                );
            }
            FindingEntry {
                id: if f.id.is_empty() {
                    "(unknown)".into()
                } else {
                    f.id
                },
                severity: severity_str(f.severity).to_string(),
                title: if f.message.is_empty() {
                    "(no title)".into()
                } else {
                    f.message
                },
                detail: f.detail.unwrap_or_default(),
                fix: f.fix_hint,
            }
        })
        .collect()
}

/// Render a backend [`toride_updates::Schedule`] as a short human label.
///
/// `Schedule` already implements `Display` (`daily` / `weekly` / `monthly` /
/// `custom(expr)`); this helper exists so the data module never has to import
/// the `Schedule` enum, and so a `None` schedule is normalized to `None`
/// (the UI renders "not configured" for it).
///
/// Currently exercised only by tests: the `schedule` backend feature
/// (`ScheduleManager::get_schedule`) is not in the default feature set, so the
/// data module leaves the cadence label as `None` until that feature is
/// enabled. Kept (and tested) so the mapping is ready the moment the feature
/// lands.
#[allow(dead_code)]
pub fn schedule_label(schedule: Option<&toride_updates::spec::Schedule>) -> Option<String> {
    schedule.map(std::string::ToString::to_string)
}

/// Map a backend [`toride_updates::detect::PackageManager`] to a lowercase
/// display string: `"apt" | "dnf" | "unknown"`. Kept here so the TUI never
/// imports the `PackageManager` enum directly.
pub fn package_manager_str(pm: toride_updates::detect::PackageManager) -> &'static str {
    use toride_updates::detect::PackageManager;
    match pm {
        PackageManager::Apt => "apt",
        PackageManager::Dnf => "dnf",
        PackageManager::Unknown => "unknown",
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use toride_updates::detect::PackageManager;
    use toride_updates::spec::Schedule;
    use toride_updates::{Finding, Severity};

    // ── convert_findings ──────────────────────────────────────────────────────

    #[test]
    fn convert_findings_empty() {
        assert!(convert_findings(Vec::new()).is_empty());
    }

    #[test]
    fn convert_findings_maps_severity() {
        let findings = vec![
            Finding::new("a", Severity::Critical, "t1"),
            Finding::new("b", Severity::Important, "t2"),
            Finding::new("c", Severity::Warning, "t3"),
            Finding::new("d", Severity::Info, "t4"),
            Finding::new("e", Severity::Ok, "t5"),
        ];
        let entries = convert_findings(findings);
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0].severity, "critical");
        assert_eq!(entries[1].severity, "important");
        assert_eq!(entries[2].severity, "warning");
        assert_eq!(entries[3].severity, "info");
        assert_eq!(entries[4].severity, "ok");
    }

    #[test]
    fn convert_findings_preserves_detail_and_fix() {
        let f = Finding::new("id", Severity::Warning, "title")
            .detail("the detail")
            .fix_hint("the fix");
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].detail, "the detail");
        assert_eq!(entries[0].fix.as_deref(), Some("the fix"));
    }

    #[test]
    fn convert_findings_none_detail_becomes_empty() {
        let f = Finding::new("id", Severity::Ok, "title");
        let entries = convert_findings(vec![f]);
        assert!(entries[0].detail.is_empty());
        assert!(entries[0].fix.is_none());
    }

    #[test]
    fn convert_findings_placeholder_for_empty_fields() {
        let f = Finding::new("", Severity::Ok, "");
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].id, "(unknown)");
        assert_eq!(entries[0].title, "(no title)");
    }

    // ── schedule_label ────────────────────────────────────────────────────────

    #[test]
    fn schedule_label_none_for_none() {
        assert!(schedule_label(None).is_none());
    }

    #[test]
    fn schedule_label_daily() {
        assert_eq!(schedule_label(Some(&Schedule::Daily)), Some("daily".into()));
    }

    #[test]
    fn schedule_label_custom() {
        assert_eq!(
            schedule_label(Some(&Schedule::Custom("Mon *-*-* 04:00:00".into()))),
            Some("custom(Mon *-*-* 04:00:00)".into())
        );
    }

    // ── package_manager_str ──────────────────────────────────────────────────

    #[test]
    fn package_manager_str_maps() {
        assert_eq!(package_manager_str(PackageManager::Apt), "apt");
        assert_eq!(package_manager_str(PackageManager::Dnf), "dnf");
        assert_eq!(package_manager_str(PackageManager::Unknown), "unknown");
    }
}
