//! Section overview trait for the live Dashboard.
//!
//! The Dashboard's "Managed Services" grid and the MANAGED/FINDINGS stat cards
//! need a uniform read on every read-only section content struct. Each such
//! struct already carries a private `available: bool` and a `findings: Vec<_>`;
//! this trait exposes a shared shape over them so the dashboard can render a
//! one-line status per section without knowing each section's concrete type.
//!
//! SSH is intentionally **excluded** — it has no `available`/`findings` shape
//! and already dominates the sidebar.
//!
//! # Shared severity helper
//!
//! Each impl builds its `status_label` via [`status_label_for`] over its own
//! `available` flag and its findings' severity strings, so the 13 impls cannot
//! drift. Findings severities vary by backend
//! (`"ok"|"info"|"warning"|"error"|"critical"`, plus `"important"` for updates)
//! — the helper covers them all.

/// A snapshot of one section's overview.
///
/// Owned so callers can collect 13 of them without holding 13 immutable borrows
/// across a later `&mut self` render.
#[derive(Clone, Debug)]
pub struct OverviewSnapshot {
    /// `"active"` | `"degraded"` | `"offline"`.
    pub status_label: &'static str,
    /// One-line human summary (e.g. `"2 jail(s) · 12 ban(s)"`).
    pub detail: Option<String>,
    /// Number of findings for this section.
    pub findings_count: usize,
}

/// Uniform read over a read-only section content struct.
///
/// Implementations live next to each content struct (in-module) so they can
/// read the private `available` / `findings` fields directly. The required
/// `status_label` is conventionally `status_label_for(self.available, ...)`.
pub trait SectionOverview {
    /// Whether the section's backend was reachable at all.
    fn available(&self) -> bool;

    /// `"active"` | `"degraded"` | `"offline"`.
    fn status_label(&self) -> &'static str;

    /// One-line summary, if a meaningful one exists. `None` renders as nothing.
    fn detail(&self) -> Option<String>;

    /// Number of findings for this section.
    fn findings_count(&self) -> usize;
}

/// Shared severity → label mapping used by every `status_label` impl.
///
/// - `offline` when the backend is unavailable;
/// - `degraded` when any finding severity is in
///   `{warning, important, error, critical}`;
/// - `active` otherwise.
#[must_use]
pub fn status_label_for(
    available: bool,
    severities: impl IntoIterator<Item: AsRef<str>>,
) -> &'static str {
    if !available {
        return "offline";
    }
    for sev in severities {
        match sev.as_ref() {
            "warning" | "important" | "error" | "critical" => return "degraded",
            _ => {}
        }
    }
    "active"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_offline_when_unavailable() {
        assert_eq!(status_label_for(false, ["ok", "info"]), "offline");
        assert_eq!(status_label_for(false, ["critical"]), "offline");
    }

    #[test]
    fn label_active_when_no_degrading_severity() {
        assert_eq!(status_label_for(true, [] as [&str; 0]), "active");
        assert_eq!(status_label_for(true, ["ok", "info"]), "active");
    }

    #[test]
    fn label_degraded_for_each_elevated_severity() {
        for sev in ["warning", "important", "error", "critical"] {
            assert_eq!(
                status_label_for(true, [sev]),
                "degraded",
                "severity {sev} should map to degraded"
            );
        }
    }

    #[test]
    fn label_degraded_when_any_finding_elevated() {
        assert_eq!(
            status_label_for(true, ["ok", "warning", "info"]),
            "degraded"
        );
    }
}
