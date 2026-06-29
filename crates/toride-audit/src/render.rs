//! Configuration file renderers for audit subsystems.
//!
//! Converts structured types into text suitable for writing to
//! `/etc/audit/`, `/etc/aide.conf`, and `/etc/rsyslog.conf`.

use std::fmt::Write as _;

// ---------------------------------------------------------------------------
// Audit rules renderer
// ---------------------------------------------------------------------------

/// Render a list of audit rules into a rules file suitable for
/// `/etc/audit/rules.d/`.
///
/// Each rule is emitted on its own line. Empty lines and comments
/// (lines starting with `#`) are preserved as-is.
pub fn render_audit_rules(rules: &[String]) -> String {
    rules
        .iter()
        .map(String::as_str)
        .collect::<Vec<&str>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// AIDE configuration renderer
// ---------------------------------------------------------------------------

/// Render an AIDE configuration string from integrity options.
///
/// Produces a minimal but functional `aide.conf` with database paths,
/// custom groups, and monitored directories.
///
/// # Arguments
///
/// * `database_path` - Path to the AIDE reference database.
/// * `database_out_path` - Path for the new database after initialization.
/// * `monitored_paths` - Directories and files to monitor.
/// * `report_url` - Where to send reports (e.g. `stdout`, `file:/var/log/aide.report`).
pub fn render_aide_config(
    database_path: &str,
    database_out_path: &str,
    monitored_paths: &[String],
    report_url: &str,
) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "database=file:{database_path}");
    let _ = writeln!(out, "database_out=file:{database_out_path}");
    let _ = writeln!(out, "report_url={report_url}");
    out.push('\n');

    for path in monitored_paths {
        let _ = writeln!(out, "{path} ALL");
    }

    out
}

// ---------------------------------------------------------------------------
// rsyslog configuration renderer
// ---------------------------------------------------------------------------

/// Render an rsyslog configuration snippet for audit log forwarding.
///
/// Produces configuration lines suitable for a drop-in file in
/// `/etc/rsyslog.d/`.
///
/// # Arguments
///
/// * `facility` - The syslog facility (e.g. `authpriv`, `local6`).
/// * `log_path` - Path to the log file.
/// * `template` - Optional template name for log formatting.
pub fn render_rsyslog_config(facility: &str, log_path: &str, template: Option<&str>) -> String {
    let template_directive = template.map(|t| format!(";{t}")).unwrap_or_default();
    format!("{facility}.*\t{log_path}{template_directive}\n")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_audit_rules_joins_with_newlines() {
        let rules: Vec<String> = vec![
            "-w /etc/passwd -p wa -k identity".to_owned(),
            "-w /etc/shadow -p wa -k identity".to_owned(),
            "# comment".to_owned(),
        ];
        let output = render_audit_rules(&rules);
        assert_eq!(
            output,
            "-w /etc/passwd -p wa -k identity\n\
             -w /etc/shadow -p wa -k identity\n\
             # comment"
        );
    }

    #[test]
    fn render_audit_rules_empty_vec() {
        let rules: Vec<String> = vec![];
        let output = render_audit_rules(&rules);
        assert!(output.is_empty());
    }

    #[test]
    fn render_aide_config_contains_database_and_monitored_paths() {
        let paths: Vec<String> = vec!["/etc".to_owned(), "/var/log".to_owned()];
        let output = render_aide_config(
            "/var/lib/aide/aide.db",
            "/var/lib/aide/aide.db.new",
            &paths,
            "stdout",
        );
        assert!(output.contains("database=file:/var/lib/aide/aide.db"));
        assert!(output.contains("database_out=file:/var/lib/aide/aide.db.new"));
        assert!(output.contains("report_url=stdout"));
        assert!(output.contains("/etc ALL"));
        assert!(output.contains("/var/log ALL"));
    }

    #[test]
    fn render_rsyslog_config_with_template() {
        let output =
            render_rsyslog_config("authpriv", "/var/log/audit.log", Some("AuditLogFormat"));
        assert!(output.contains("authpriv.*"));
        assert!(output.contains("/var/log/audit.log"));
        assert!(output.contains(";AuditLogFormat"));
    }

    #[test]
    fn render_rsyslog_config_without_template() {
        let output = render_rsyslog_config("local6", "/var/log/test.log", None);
        assert!(output.contains("local6.*"));
        assert!(output.contains("/var/log/test.log"));
        assert!(!output.contains(';'));
    }
}
