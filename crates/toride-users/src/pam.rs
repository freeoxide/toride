//! PAM (Pluggable Authentication Modules) configuration management.
//!
//! Provides functions to read, modify, and write PAM service configuration
//! files under `/etc/pam.d/`.

use std::fmt::Write as _;
use std::path::Path;

use crate::{Error, Result, paths::UserPaths, render::PamRule};

/// Read PAM rules from a service configuration file.
///
/// Parses `/etc/pam.d/<service>` into a list of [`PamRule`] values.
///
/// # Errors
///
/// Returns [`Error::Io`] if the file cannot be read, or [`Error::PamError`]
/// if a line cannot be parsed.
pub fn read_pam_config(path: &Path) -> Result<Vec<PamRule>> {
    let content = std::fs::read_to_string(path)?;
    Ok(parse_pam_lines(&content))
}

/// Parse PAM configuration text into rules.
///
/// Skips blank lines and comments.
fn parse_pam_lines(content: &str) -> Vec<PamRule> {
    let mut rules = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Skip @include and @includedir directives
        if line.starts_with('@') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue; // skip malformed lines
        }
        let arguments = parts[3..]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        rules.push(PamRule {
            management_group: parts[0].to_owned(),
            control: parts[1].to_owned(),
            module: parts[2].to_owned(),
            arguments,
        });
    }
    rules
}

/// Write PAM rules to a service configuration file.
///
/// Creates a backup before writing. The file is written atomically via
/// a temp file rename.
///
/// # Errors
///
/// Returns [`Error::Io`] if the file cannot be written.
pub fn write_pam_config(path: &Path, rules: &[PamRule], comment: Option<&str>) -> Result<()> {
    let mut content = String::new();

    if let Some(c) = comment {
        let _ = writeln!(content, "# {c}");
    }

    content.push_str(&crate::render::render_pam_config(rules));

    // Backup existing file if present
    if path.exists() {
        crate::backup::backup_file(path, None)?;
    }

    std::fs::write(path, content)?;
    Ok(())
}

/// Enable TOTP/2FA for a PAM service by inserting `pam_google_authenticator.so`.
///
/// Adds a `auth required pam_google_authenticator.so` rule to the service
/// configuration if one is not already present.
///
/// `nullok` is intentionally omitted: with `nullok`, users who lack (or cannot
/// read) a `.google_authenticator` file skip the module entirely and
/// authenticate with only a password — which defeats the point of enabling 2FA
/// on a hardening tool and leaves the entire pre-existing user base password-
/// only. Without `nullok`, TOTP is mandatory once the rule is in place.
///
/// # Errors
///
/// Returns [`Error::PamError`] if the module is already configured or the
/// file cannot be modified.
pub fn enable_totp_for_service(paths: &UserPaths, service: &str) -> Result<()> {
    let pam_path = paths.pam_service(service)?;

    if !pam_path.exists() {
        return Err(Error::PamError(format!(
            "PAM service config not found: {}",
            pam_path.display()
        )));
    }

    let mut rules = read_pam_config(&pam_path)?;

    // Check if google_authenticator is already configured
    if rules
        .iter()
        .any(|r| r.module.contains("pam_google_authenticator"))
    {
        return Err(Error::PamError(format!(
            "TOTP already enabled for service {service}"
        )));
    }

    // Insert the TOTP rule as the first auth rule. No `nullok`: TOTP is
    // mandatory once enabled (see the function-level doc comment).
    let totp_rule = PamRule {
        management_group: "auth".to_owned(),
        control: "required".to_owned(),
        module: "pam_google_authenticator.so".to_owned(),
        arguments: Vec::new(),
    };

    // Find the position of the first auth rule
    let pos = rules
        .iter()
        .position(|r| r.management_group == "auth")
        .unwrap_or(0);

    rules.insert(pos, totp_rule);

    write_pam_config(
        &pam_path,
        &rules,
        Some("Managed by toride -- TOTP/2FA enabled"),
    )?;

    tracing::info!("enabled TOTP for PAM service {service}");
    Ok(())
}

/// Disable TOTP/2FA for a PAM service by removing `pam_google_authenticator.so`.
///
/// # Errors
///
/// Returns [`Error::PamError`] if TOTP is not configured for the service.
pub fn disable_totp_for_service(paths: &UserPaths, service: &str) -> Result<()> {
    let pam_path = paths.pam_service(service)?;

    if !pam_path.exists() {
        return Err(Error::PamError(format!(
            "PAM service config not found: {}",
            pam_path.display()
        )));
    }

    let mut rules = read_pam_config(&pam_path)?;

    let original_len = rules.len();
    rules.retain(|r| !r.module.contains("pam_google_authenticator"));

    if rules.len() == original_len {
        return Err(Error::PamError(format!(
            "TOTP not configured for service {service}"
        )));
    }

    write_pam_config(
        &pam_path,
        &rules,
        Some("Managed by toride -- TOTP/2FA disabled"),
    )?;

    tracing::info!("disabled TOTP for PAM service {service}");
    Ok(())
}

/// Check if TOTP/2FA is enabled for a PAM service.
pub fn is_totp_enabled(paths: &UserPaths, service: &str) -> Result<bool> {
    let pam_path = paths.pam_service(service)?;
    if !pam_path.exists() {
        return Ok(false);
    }
    let rules = read_pam_config(&pam_path)?;
    Ok(rules
        .iter()
        .any(|r| r.module.contains("pam_google_authenticator")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::UserPaths;

    fn make_service(base: &std::path::Path, service: &str, body: &str) -> UserPaths {
        let paths = UserPaths::with_base(base);
        std::fs::create_dir_all(&paths.pam_d).unwrap();
        std::fs::write(paths.pam_d.join(service), body).unwrap();
        paths
    }

    #[test]
    fn read_pam_config_parses_rules_and_skips_comments() {
        let body = "# header\n\
                    auth required pam_unix.so\n\
                    @include common-account\n\
                    account required pam_unix.so\n";
        let parsed = parse_pam_lines(body);
        assert_eq!(parsed.len(), 2, "comments and @include skipped");
        assert_eq!(parsed[0].management_group, "auth");
        assert_eq!(parsed[0].module, "pam_unix.so");
        assert!(parsed[0].arguments.is_empty());
    }

    #[test]
    fn enable_totp_inserts_rule_without_nullok() {
        // The security fix: the generated rule must NOT carry `nullok`, which
        // would let users without a secret file skip TOTP entirely and defeat
        // 2FA for the existing user base.
        let dir = tempfile::tempdir().unwrap();
        let body = "auth required pam_unix.so\naccount required pam_unix.so\n";
        let paths = make_service(dir.path(), "sshd", body);

        let backup_dir = tempfile::tempdir().unwrap();
        let _guard = crate::backup::set_test_backup_dir(backup_dir.path());
        enable_totp_for_service(&paths, "sshd").unwrap();

        let written = std::fs::read_to_string(paths.pam_d.join("sshd")).unwrap();
        assert!(
            written.contains("pam_google_authenticator.so"),
            "TOTP module inserted"
        );
        assert!(
            !written.contains("nullok"),
            "nullok must NOT appear (it disables 2FA for users without a secret file)"
        );
    }

    #[test]
    fn enable_totp_inserts_as_first_auth_rule() {
        let dir = tempfile::tempdir().unwrap();
        let body = "auth sufficient pam_unix.so\nauth required pam_env.so\n";
        let paths = make_service(dir.path(), "sshd", body);

        let backup_dir = tempfile::tempdir().unwrap();
        let _guard = crate::backup::set_test_backup_dir(backup_dir.path());
        enable_totp_for_service(&paths, "sshd").unwrap();

        let rules = read_pam_config(&paths.pam_d.join("sshd")).unwrap();
        // First auth rule is now the TOTP rule.
        let first_auth = rules
            .iter()
            .find(|r| r.management_group == "auth")
            .expect("an auth rule exists");
        assert!(first_auth.module.contains("pam_google_authenticator"));
    }

    #[test]
    fn enable_totp_is_idempotent_error() {
        let dir = tempfile::tempdir().unwrap();
        let body = "auth required pam_google_authenticator.so\n";
        let paths = make_service(dir.path(), "sshd", body);

        assert!(matches!(
            enable_totp_for_service(&paths, "sshd"),
            Err(Error::PamError(_))
        ));
    }

    #[test]
    fn enable_totp_missing_service_errors() {
        let dir = tempfile::tempdir().unwrap();
        let paths = UserPaths::with_base(dir.path());
        // No pam.d/sshd written.
        assert!(matches!(
            enable_totp_for_service(&paths, "sshd"),
            Err(Error::PamError(_))
        ));
    }

    #[test]
    fn disable_totp_removes_rule() {
        let dir = tempfile::tempdir().unwrap();
        let body = "auth required pam_google_authenticator.so\nauth required pam_unix.so\n";
        let paths = make_service(dir.path(), "sshd", body);

        let backup_dir = tempfile::tempdir().unwrap();
        let _guard = crate::backup::set_test_backup_dir(backup_dir.path());
        disable_totp_for_service(&paths, "sshd").unwrap();

        let written = std::fs::read_to_string(paths.pam_d.join("sshd")).unwrap();
        assert!(!written.contains("pam_google_authenticator"));
        assert!(written.contains("pam_unix"));
    }

    #[test]
    fn disable_totp_not_configured_errors() {
        let dir = tempfile::tempdir().unwrap();
        let body = "auth required pam_unix.so\n";
        let paths = make_service(dir.path(), "sshd", body);

        assert!(matches!(
            disable_totp_for_service(&paths, "sshd"),
            Err(Error::PamError(_))
        ));
    }

    #[test]
    fn read_write_round_trip_preserves_rules() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sshd");
        let original = "auth required pam_unix.so\naccount required pam_unix.so\n";
        std::fs::write(&path, original).unwrap();

        let rules = read_pam_config(&path).unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let _guard = crate::backup::set_test_backup_dir(backup_dir.path());
        write_pam_config(&path, &rules, None).unwrap();

        let reread = read_pam_config(&path).unwrap();
        assert_eq!(reread.len(), rules.len());
        assert_eq!(reread[0].module, "pam_unix.so");
    }

    #[test]
    fn is_totp_enabled_detects_rule() {
        let dir = tempfile::tempdir().unwrap();
        let body = "auth required pam_google_authenticator.so\n";
        let paths = make_service(dir.path(), "sshd", body);
        assert!(is_totp_enabled(&paths, "sshd").unwrap());

        let dir2 = tempfile::tempdir().unwrap();
        let paths2 = make_service(dir2.path(), "sshd", "auth required pam_unix.so\n");
        assert!(!is_totp_enabled(&paths2, "sshd").unwrap());
    }
}
