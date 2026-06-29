//! Render helpers: convert a [`DoctorReport`] into text, JSON, or Markdown.

#[cfg(feature = "serde")]
use crate::error::Result;
use crate::{DoctorReport, Finding};
use std::fmt::Write as _;

/// Render a report as human-readable plain text.
///
/// Each finding is printed on its own line with the severity emoji prefix.
/// A summary footer is appended.
#[must_use]
pub fn render_text(report: &DoctorReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "=== Doctor Report: {} ===", report.domain);
    let _ = writeln!(out, "Checked at: {}\n", report.checked_at);

    if report.findings.is_empty() {
        out.push_str("No findings.\n");
    } else {
        for f in &report.findings {
            let _ = writeln!(out, "[{}] {} -- {}", f.severity, f.id, f.message);
            if let Some(ref detail) = f.detail {
                let _ = writeln!(out, "    Detail: {detail}");
            }
            if let Some(ref hint) = f.fix_hint {
                let _ = writeln!(out, "    Fix:    {hint}");
            }
        }
    }

    let summary = report.summary();
    let _ = writeln!(
        out,
        "\n--- Summary: {} finding(s), healthy={} ---",
        summary.total, summary.healthy
    );
    for (sev, count) in &summary.by_severity {
        let _ = writeln!(out, "  {sev}: {count}");
    }

    out
}

/// Render a report as a JSON string.
///
/// Requires the `serde` feature. Returns an error if serialisation fails.
///
/// # Errors
///
/// Returns [`Error::Render`](crate::Error::Render) if `serde_json` fails.
#[cfg(feature = "serde")]
pub fn render_json(report: &DoctorReport) -> Result<String> {
    serde_json::to_string_pretty(report).map_err(|e| crate::Error::Render(e.to_string()))
}

/// Render a report as a Markdown document.
#[must_use]
pub fn render_markdown(report: &DoctorReport) -> String {
    let mut md = String::new();
    let _ = writeln!(md, "## Doctor Report: {}\n", report.domain);
    let _ = writeln!(md, "**Checked at:** {}\n", report.checked_at);

    if report.findings.is_empty() {
        md.push_str("*No findings.*\n");
    } else {
        md.push_str("| Severity | ID | Message |\n");
        md.push_str("|----------|----|--------|\n");
        for f in &report.findings {
            let _ = writeln!(md, "| {} | `{}` | {} |", f.severity, f.id, f.message);
        }
        md.push('\n');

        // Details section
        let with_detail: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.detail.is_some() || f.fix_hint.is_some())
            .collect();

        if !with_detail.is_empty() {
            md.push_str("### Details\n\n");
            for f in &with_detail {
                let _ = writeln!(md, "**{}**\n", f.id);
                if let Some(ref detail) = f.detail {
                    let _ = writeln!(md, "{detail}\n");
                }
                if let Some(ref hint) = f.fix_hint {
                    let _ = writeln!(md, "> **Fix:** {hint}\n");
                }
            }
        }
    }

    let summary = report.summary();
    let _ = writeln!(
        md,
        "---\n*Summary: {} finding(s) | healthy: {}*",
        summary.total, summary.healthy
    );

    md
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Severity;

    fn sample_report() -> DoctorReport {
        DoctorReport::with_timestamp(
            "ssh",
            vec![
                Finding::new("ssh:key", Severity::Critical, "No key found")
                    .domain("ssh")
                    .detail("Expected ~/.ssh/id_ed25519")
                    .fix_hint("Run ssh-keygen -t ed25519"),
                Finding::new("ssh:perms", Severity::Ok, "Permissions correct").domain("ssh"),
            ],
            "2026-06-01T12:00:00Z",
        )
    }

    #[test]
    fn render_text_contains_findings() {
        let text = render_text(&sample_report());
        assert!(text.contains("ssh:key"));
        assert!(text.contains("ssh:perms"));
        assert!(text.contains("Summary: 2 finding(s)"));
    }

    #[test]
    fn render_text_empty_report() {
        let r = DoctorReport::new("test", vec![]);
        let text = render_text(&r);
        assert!(text.contains("No findings."));
    }

    #[test]
    fn render_markdown_has_table() {
        let md = render_markdown(&sample_report());
        assert!(md.contains("| Severity | ID | Message |"));
        assert!(md.contains("ssh:key"));
    }

    #[test]
    #[cfg(feature = "serde")]
    fn render_json_roundtrip() {
        let report = sample_report();
        let json = render_json(&report).unwrap();
        assert!(json.contains("\"domain\": \"ssh\""));
    }
}
