//! Validation functions for audit rules and configuration.
//!
//! Provides pre-flight validation for audit rules and AIDE configuration
//! strings before they are applied to the system.

// ---------------------------------------------------------------------------
// Audit rule validation
// ---------------------------------------------------------------------------

/// Validate a single audit rule string.
///
/// Checks that the rule starts with a recognized flag (`-a`, `-A`, `-d`,
/// `-D`, `-S`, `-F`, `-m`, `-s`, `-l`, `-e`, `-k`, `-w`, `-p`, `-W`).
///
/// # Errors
///
/// Returns [`crate::Error::AuditRuleParse`] if the rule is malformed.
pub fn validate_audit_rule(rule: &str) -> crate::Result<()> {
    let trimmed = rule.trim();

    // Skip empty lines and comments.
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(());
    }

    // Check for a recognized flag prefix.
    let valid_prefixes = [
        "-a ", "-A ", "-d ", "-D ", "-S ", "-F ", "-m ", "-s ", "-l ", "-e ", "-k ", "-w ", "-p ",
        "-W ",
    ];

    let has_valid_prefix = valid_prefixes
        .iter()
        .any(|prefix| trimmed.starts_with(prefix));

    if has_valid_prefix {
        Ok(())
    } else {
        Err(crate::Error::AuditRuleParse(format!(
            "unrecognized audit rule: {trimmed}"
        )))
    }
}

// ---------------------------------------------------------------------------
// AIDE configuration validation
// ---------------------------------------------------------------------------

/// Validate an AIDE configuration string.
///
/// Performs basic syntax checks: ensures database paths are specified
/// and monitored paths are absolute.
///
/// # Errors
///
/// Returns [`crate::Error::AideError`] if the configuration is invalid.
pub fn validate_aide_config(config: &str) -> crate::Result<()> {
    let has_database = config
        .lines()
        .any(|line| line.trim().starts_with("database="));

    if !has_database {
        return Err(crate::Error::AideError(
            "AIDE configuration must specify a database path".to_owned(),
        ));
    }

    // Check that path entries are absolute.
    for line in config.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.contains('=') {
            continue;
        }
        // Lines that look like path entries should start with '/'.
        if !trimmed.starts_with('/') && !trimmed.starts_with('!') {
            return Err(crate::Error::AideError(format!(
                "AIDE path entry must be absolute: {trimmed}"
            )));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- validate_audit_rule --------------------------------------------------

    #[test]
    fn validate_audit_rule_accepts_watch_rule() {
        assert!(validate_audit_rule("-w /etc/passwd -p wa -k identity").is_ok());
    }

    #[test]
    fn validate_audit_rule_accepts_comment() {
        assert!(validate_audit_rule("# this is a comment").is_ok());
    }

    #[test]
    fn validate_audit_rule_accepts_empty_string() {
        assert!(validate_audit_rule("").is_ok());
    }

    #[test]
    fn validate_audit_rule_accepts_a_flag() {
        assert!(validate_audit_rule("-a always,exit -F arch=b64 -S open -k test").is_ok());
    }

    #[test]
    fn validate_audit_rule_accepts_d_flag() {
        assert!(validate_audit_rule("-d never").is_ok());
    }

    #[test]
    fn validate_audit_rule_accepts_w_flag() {
        assert!(validate_audit_rule("-W /etc/passwd").is_ok());
    }

    #[test]
    fn validate_audit_rule_rejects_invalid_rule() {
        let result = validate_audit_rule("INVALID RULE HERE");
        assert!(result.is_err());
    }

    #[test]
    fn validate_audit_rule_rejects_unrecognized_prefix() {
        let result = validate_audit_rule("--bad-flag something");
        assert!(result.is_err());
    }

    // -- validate_aide_config -------------------------------------------------

    #[test]
    fn validate_aide_config_accepts_valid_config() {
        let config = "database=file:/var/lib/aide/aide.db\n\
                      database_out=file:/var/lib/aide/aide.db.new\n\
                      /etc ALL\n\
                      /var/log ALL\n";
        assert!(validate_aide_config(config).is_ok());
    }

    #[test]
    fn validate_aide_config_rejects_missing_database() {
        let config = "/etc ALL\n/var/log ALL\n";
        let result = validate_aide_config(config);
        assert!(result.is_err());
    }

    #[test]
    fn validate_aide_config_allows_comments_and_empty_lines() {
        let config = "# comment\n\n\ndatabase=file:/var/lib/aide/aide.db\n/etc ALL\n";
        assert!(validate_aide_config(config).is_ok());
    }

    #[test]
    fn validate_aide_config_rejects_non_absolute_path() {
        let config = "database=file:/var/lib/aide/aide.db\nrelative/path ALL\n";
        let result = validate_aide_config(config);
        assert!(result.is_err());
    }

    #[test]
    fn validate_aide_config_allows_exclamation_prefix() {
        let config = "database=file:/var/lib/aide/aide.db\n!/tmp ALL\n";
        assert!(validate_aide_config(config).is_ok());
    }
}
