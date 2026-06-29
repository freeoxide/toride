//! Report rendering — converts doctor findings into text, JSON, and Markdown output.

use std::fmt::Write;

use crate::spec::{Finding, Severity};

/// Render a list of findings as a human-readable text report.
#[must_use]
pub fn render_findings(findings: &[Finding]) -> String {
    let mut out = String::new();

    out.push_str("=== UFW Doctor Report ===\n\n");

    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let errors = findings
        .iter()
        .filter(|f| f.severity == Severity::Important)
        .count();
    let warnings = findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .count();
    let ok = findings
        .iter()
        .filter(|f| f.severity == Severity::Ok)
        .count();
    let info = findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();

    let _ = write!(
        out,
        "Summary: {ok} OK, {info} info, {warnings} warnings, {errors} errors, {critical} critical\n\n"
    );

    // Show critical and errors first
    for finding in findings
        .iter()
        .filter(|f| f.severity >= Severity::Important)
    {
        let _ = writeln!(out, "[{}] {}", finding.severity, finding.title);
        let _ = writeln!(out, "  {}", finding.detail);
        if let Some(fix) = &finding.fix {
            let _ = writeln!(out, "  Fix: {fix}");
        }
        out.push('\n');
    }

    // Then warnings
    for finding in findings.iter().filter(|f| f.severity == Severity::Warning) {
        let _ = writeln!(out, "[{}] {}", finding.severity, finding.title);
        let _ = writeln!(out, "  {}", finding.detail);
        if let Some(fix) = &finding.fix {
            let _ = writeln!(out, "  Fix: {fix}");
        }
        out.push('\n');
    }

    // Then info and OK
    for finding in findings.iter().filter(|f| f.severity <= Severity::Info) {
        let _ = writeln!(out, "[{}] {}", finding.severity, finding.title);
        if !finding.detail.is_empty() {
            let _ = writeln!(out, "  {}", finding.detail);
        }
    }

    out
}

/// Render a list of findings as a JSON report.
///
/// Produces a JSON array of finding objects, each with `id`, `severity`,
/// `title`, `detail`, and optional `fix` fields. No external serde
/// dependency is required — this is hand-rendered for maximum portability.
#[must_use]
pub fn render_findings_json(findings: &[Finding]) -> String {
    let mut items = Vec::new();

    for finding in findings {
        let fix_json = match &finding.fix {
            Some(fix) => format!(",\n    \"fix\": {}", escape_json_string(fix)),
            None => String::new(),
        };

        items.push(format!(
            "  {{\n    \
             \"id\": {},\n    \
             \"severity\": \"{}\",\n    \
             \"title\": {},\n    \
             \"detail\": {}{}\n  \
             }}",
            escape_json_string(finding.id),
            finding.severity,
            escape_json_string(&finding.title),
            escape_json_string(&finding.detail),
            fix_json,
        ));
    }

    format!("[\n{}\n]", items.join(",\n"))
}

/// Render a list of findings as a Markdown report.
#[must_use]
pub fn render_findings_markdown(findings: &[Finding]) -> String {
    let mut out = String::new();

    out.push_str("# UFW Doctor Report\n\n");

    // Summary table
    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let errors = findings
        .iter()
        .filter(|f| f.severity == Severity::Important)
        .count();
    let warnings = findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .count();
    let ok = findings
        .iter()
        .filter(|f| f.severity == Severity::Ok)
        .count();
    let info = findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();
    let total = findings.len();

    out.push_str("| Severity | Count |\n|----------|-------|\n");
    let _ = writeln!(out, "| Critical | {critical} |");
    let _ = writeln!(out, "| Error    | {errors} |");
    let _ = writeln!(out, "| Warning  | {warnings} |");
    let _ = writeln!(out, "| Info     | {info} |");
    let _ = writeln!(out, "| OK       | {ok} |");
    let _ = writeln!(out, "| **Total** | **{total}** |");
    out.push('\n');

    // Critical and errors
    let critical_errors: Vec<_> = findings
        .iter()
        .filter(|f| f.severity >= Severity::Important)
        .collect();
    if !critical_errors.is_empty() {
        out.push_str("## Critical / Errors\n\n");
        for finding in &critical_errors {
            render_finding_markdown(&mut out, finding);
        }
    }

    // Warnings
    let warning_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .collect();
    if !warning_findings.is_empty() {
        out.push_str("## Warnings\n\n");
        for finding in &warning_findings {
            render_finding_markdown(&mut out, finding);
        }
    }

    // Info and OK
    let info_ok: Vec<_> = findings
        .iter()
        .filter(|f| f.severity <= Severity::Info)
        .collect();
    if !info_ok.is_empty() {
        out.push_str("## Info / OK\n\n");
        for finding in &info_ok {
            render_finding_markdown(&mut out, finding);
        }
    }

    out
}

/// Render a single finding as Markdown.
fn render_finding_markdown(out: &mut String, finding: &Finding) {
    let _ = writeln!(out, "### `{} `{}`", finding.severity, finding.title);
    let _ = writeln!(out, "- **ID:** `{}`", finding.id);
    if !finding.detail.is_empty() {
        let _ = writeln!(out, "- **Detail:** {}", finding.detail);
    }
    if let Some(fix) = &finding.fix {
        let _ = writeln!(out, "- **Fix:** {fix}");
    }
    out.push('\n');
}

/// Escape a string for JSON output (wrap in double quotes).
fn escape_json_string(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len() + 2);
    escaped.push('"');
    for ch in s.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(escaped, "\\u{:04x}", c as u32);
            }
            c => escaped.push(c),
        }
    }
    escaped.push('"');
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_findings_should_show_summary() {
        let findings = vec![
            Finding {
                id: "test:ok",
                severity: Severity::Ok,
                title: "All good".into(),
                detail: "Everything is fine.".into(),
                fix: None,
            },
            Finding {
                id: "test:warn",
                severity: Severity::Warning,
                title: "Watch out".into(),
                detail: "Something might be wrong.".into(),
                fix: Some("Fix it.".into()),
            },
        ];

        let report = render_findings(&findings);
        assert!(report.contains("1 OK"));
        assert!(report.contains("1 warnings"));
        assert!(report.contains("All good"));
        assert!(report.contains("Watch out"));
        assert!(report.contains("Fix it."));
    }

    #[test]
    fn render_findings_json_should_produce_valid_json() {
        let findings = vec![
            Finding {
                id: "test:ok",
                severity: Severity::Ok,
                title: "All good".into(),
                detail: "Everything is fine.".into(),
                fix: None,
            },
            Finding {
                id: "test:warn",
                severity: Severity::Warning,
                title: "Watch out".into(),
                detail: "Something might be wrong.".into(),
                fix: Some("Fix it.".into()),
            },
        ];

        let json = render_findings_json(&findings);

        // Should start/end with brackets
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));

        // Should contain key fields
        assert!(json.contains("\"id\""));
        assert!(json.contains("\"severity\""));
        assert!(json.contains("\"title\""));
        assert!(json.contains("\"detail\""));
        assert!(json.contains("\"fix\""));
        assert!(json.contains("test:ok"));
        assert!(json.contains("test:warn"));
        assert!(json.contains("Fix it."));
    }

    #[test]
    fn render_findings_json_should_escape_special_chars() {
        let findings = vec![Finding {
            id: "test:escape",
            severity: Severity::Warning,
            title: "Line \"break\" and \\slash".into(),
            detail: "Has\nnewlines\tand\ttabs".into(),
            fix: None,
        }];

        let json = render_findings_json(&findings);
        assert!(json.contains("\\\""));
        assert!(json.contains("\\\\"));
        assert!(json.contains("\\n"));
        assert!(json.contains("\\t"));
    }

    #[test]
    fn render_findings_markdown_should_produce_markdown() {
        let findings = vec![
            Finding {
                id: "test:crit",
                severity: Severity::Critical,
                title: "Critical issue".into(),
                detail: "This is critical.".into(),
                fix: Some("Fix it now.".into()),
            },
            Finding {
                id: "test:warn",
                severity: Severity::Warning,
                title: "Warning issue".into(),
                detail: "This is a warning.".into(),
                fix: None,
            },
            Finding {
                id: "test:ok",
                severity: Severity::Ok,
                title: "All good".into(),
                detail: String::new(),
                fix: None,
            },
        ];

        let md = render_findings_markdown(&findings);
        assert!(md.contains("# UFW Doctor Report"));
        assert!(md.contains("## Critical / Errors"));
        assert!(md.contains("## Warnings"));
        assert!(md.contains("## Info / OK"));
        assert!(md.contains("CRITICAL"));
        assert!(md.contains("Critical issue"));
        assert!(md.contains("Fix it now."));
        assert!(md.contains("| **Total** | **3** |"));
    }

    #[test]
    fn escape_json_string_should_handle_edge_cases() {
        assert_eq!(escape_json_string("hello"), "\"hello\"");
        assert_eq!(escape_json_string("line\nbreak"), "\"line\\nbreak\"");
        assert_eq!(escape_json_string("tab\there"), "\"tab\\there\"");
        assert_eq!(escape_json_string("quote\"here"), "\"quote\\\"here\"");
        assert_eq!(escape_json_string("back\\slash"), "\"back\\\\slash\"");
    }
}
