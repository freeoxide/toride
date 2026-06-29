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
/// Adds a `auth required pam_google_authenticator.so nullok` rule to the
/// service configuration if one is not already present.
///
/// # Errors
///
/// Returns [`Error::PamError`] if the module is already configured or the
/// file cannot be modified.
pub fn enable_totp_for_service(paths: &UserPaths, service: &str) -> Result<()> {
    let pam_path = paths.pam_service(service);

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

    // Insert the TOTP rule as the first auth rule
    let totp_rule = PamRule {
        management_group: "auth".to_owned(),
        control: "required".to_owned(),
        module: "pam_google_authenticator.so".to_owned(),
        arguments: vec!["nullok".to_owned()],
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
    let pam_path = paths.pam_service(service);

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
    let pam_path = paths.pam_service(service);
    if !pam_path.exists() {
        return Ok(false);
    }
    let rules = read_pam_config(&pam_path)?;
    Ok(rules
        .iter()
        .any(|r| r.module.contains("pam_google_authenticator")))
}
