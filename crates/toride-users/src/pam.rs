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

/// Mode for PAM service files.
///
/// `/etc/pam.d/<service>` files are conventionally `0o644` (world-readable) so
/// the PAM stack -- which may run as any user -- can parse them. Writing them
/// `0o600` would silently break authentication for unprivileged services.
const PAM_FILE_MODE: u32 = 0o644;

/// Write PAM rules to a service configuration file.
///
/// Creates a backup before writing. The file is written **atomically** via a
/// temp file in the same directory (created with the final `0o644` mode),
/// fsynced on both sides of the rename, and renamed into place -- so a crash
/// or signal mid-write can never leave a truncated PAM file that would lock
/// users out of the system. The temp file lives in the same directory as the
/// target so `rename(2)` is a same-filesystem atomic operation.
///
/// # Errors
///
/// Returns [`Error::Io`] if the backup or permission step fails, or an
/// [`Error`] wrapping a `toride_fs` atomic-write failure if the
/// temp file cannot be created, written, fsynced, or persisted.
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

    // Atomic write: temp file in the same dir (created at 0o644 so the final
    // inode is correct the instant the rename lands), fsync + rename + best-
    // effort dir fsync. A crash at any point leaves either the old file or the
    // complete new file -- never a truncated one.
    toride_fs::atomic_write_with_perms(path, &content, PAM_FILE_MODE)
        .map_err(|e| Error::PamError(format!("atomic write of {} failed: {e}", path.display())))?;
    Ok(())
}

/// Enable TOTP/2FA for a PAM service by inserting `pam_google_authenticator.so`.
///
/// Adds a `auth required pam_google_authenticator.so` rule to the service
/// configuration if one is not already present. The edit is line-preserving:
/// `@include`/`@includedir` directives, comments, and every other verbatim
/// line survive untouched, because rewriting a Debian-style stack from
/// parsed rules would strip its include chain and lock users out.
///
/// `nullok` is intentionally omitted: with `nullok`, users who lack (or cannot
/// read) a `.google_authenticator` file skip the module entirely and
/// authenticate with only a password, which defeats the point of enabling 2FA
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

    let content = std::fs::read_to_string(&pam_path)?;

    if content
        .lines()
        .any(|line| line_references_module(line, "pam_google_authenticator"))
    {
        return Err(Error::PamError(format!(
            "TOTP already enabled for service {service}"
        )));
    }

    let mut lines: Vec<String> = content.lines().map(str::to_owned).collect();
    let pos = lines
        .iter()
        .position(|line| line_is_auth_rule(line))
        .unwrap_or(0);
    lines.insert(pos, "auth required pam_google_authenticator.so".to_owned());
    set_managed_marker(&mut lines, "TOTP/2FA enabled");

    write_pam_lines(&pam_path, &lines, content.ends_with('\n'))?;

    tracing::info!("enabled TOTP for PAM service {service}");
    Ok(())
}

/// Disable TOTP/2FA for a PAM service by removing `pam_google_authenticator.so`.
///
/// Line-preserving like [`enable_totp_for_service`]: only the module's rule
/// lines are removed; `@include` directives, comments, and all other lines
/// are written back verbatim.
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

    let content = std::fs::read_to_string(&pam_path)?;

    let original_count = content
        .lines()
        .filter(|line| line_references_module(line, "pam_google_authenticator"))
        .count();
    if original_count == 0 {
        return Err(Error::PamError(format!(
            "TOTP not configured for service {service}"
        )));
    }

    let mut lines: Vec<String> = content
        .lines()
        .filter(|line| !line_references_module(line, "pam_google_authenticator"))
        .map(str::to_owned)
        .collect();
    set_managed_marker(&mut lines, "TOTP/2FA disabled");

    write_pam_lines(&pam_path, &lines, content.ends_with('\n'))?;

    tracing::info!("disabled TOTP for PAM service {service}");
    Ok(())
}

/// Whether a raw PAM line is a rule invoking a module whose path contains
/// `module`; comments, blank lines, and `@include` directives are not rules.
fn line_references_module(line: &str, module: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('@') {
        return false;
    }
    trimmed
        .split_whitespace()
        .nth(2)
        .is_some_and(|m| m.contains(module))
}

/// Whether a raw PAM line is a rule in the `auth` management group.
fn line_is_auth_rule(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('@') {
        return false;
    }
    trimmed.split_whitespace().next() == Some("auth")
}

/// Place the `# Managed by toride` marker line, replacing the previous marker
/// so repeated toggles do not accumulate comment lines.
fn set_managed_marker(lines: &mut Vec<String>, note: &str) {
    let marker = format!("# Managed by toride -- {note}");
    match lines
        .iter()
        .position(|line| line.starts_with("# Managed by toride"))
    {
        Some(index) => lines[index] = marker,
        None => lines.insert(0, marker),
    }
}

/// Write raw PAM lines back to `path` atomically at the conventional 0o644
/// mode, backing up the existing file first. A trailing newline is written
/// only when the original file had one.
///
/// # Errors
///
/// Returns [`Error::Io`] if the backup fails, or [`Error::PamError`] if the
/// atomic write fails.
fn write_pam_lines(path: &Path, lines: &[String], trailing_newline: bool) -> Result<()> {
    let mut content = lines.join("\n");
    if trailing_newline {
        content.push('\n');
    }
    if path.exists() {
        crate::backup::backup_file(path, None)?;
    }
    toride_fs::atomic_write_with_perms(path, &content, PAM_FILE_MODE)
        .map_err(|e| Error::PamError(format!("atomic write of {} failed: {e}", path.display())))?;
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
        assert_eq!(parsed[0].arguments, Vec::<String>::new());
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

    /// The lockout blocker: toggling TOTP on a Debian-shaped stack must keep
    /// every `@include` directive, comment, and non-rule line verbatim.
    #[test]
    fn enable_disable_totp_preserves_debian_include_chain() {
        let dir = tempfile::tempdir().unwrap();
        let body = "#%PAM-1.0\n\
                    auth required pam_env.so\n\
                    @include common-auth\n\
                    account required pam_nologin.so\n\
                    # site policy\n\
                    @include common-account\n\
                    session include common-session-noninteractive\n";
        let paths = make_service(dir.path(), "sshd", body);

        let backup_dir = tempfile::tempdir().unwrap();
        let _guard = crate::backup::set_test_backup_dir(backup_dir.path());
        enable_totp_for_service(&paths, "sshd").unwrap();

        let enabled = std::fs::read_to_string(paths.pam_d.join("sshd")).unwrap();
        assert!(
            enabled.contains("auth required pam_google_authenticator.so"),
            "TOTP rule inserted:\n{enabled}"
        );
        let totp_pos = enabled
            .find("pam_google_authenticator")
            .expect("TOTP rule present");
        let first_auth_pos = enabled
            .find("auth required pam_env.so")
            .expect("original auth rule present");
        assert!(
            totp_pos < first_auth_pos,
            "TOTP rule must precede the first auth rule:\n{enabled}"
        );
        for expected in [
            "#%PAM-1.0",
            "@include common-auth",
            "account required pam_nologin.so",
            "# site policy",
            "@include common-account",
            "session include common-session-noninteractive",
        ] {
            assert!(
                enabled.contains(expected),
                "enable dropped `{expected}`:\n{enabled}"
            );
        }

        disable_totp_for_service(&paths, "sshd").unwrap();

        let disabled = std::fs::read_to_string(paths.pam_d.join("sshd")).unwrap();
        assert!(
            !disabled.contains("pam_google_authenticator"),
            "TOTP rule removed:\n{disabled}"
        );
        for expected in [
            "#%PAM-1.0",
            "auth required pam_env.so",
            "@include common-auth",
            "account required pam_nologin.so",
            "# site policy",
            "@include common-account",
            "session include common-session-noninteractive",
        ] {
            assert!(
                disabled.contains(expected),
                "disable dropped `{expected}`:\n{disabled}"
            );
        }
    }

    /// Repeated toggles must replace the managed marker, not stack one
    /// comment line per toggle.
    #[test]
    fn managed_marker_does_not_accumulate_across_toggles() {
        let dir = tempfile::tempdir().unwrap();
        let paths = make_service(dir.path(), "sshd", "auth required pam_unix.so\n");

        let backup_dir = tempfile::tempdir().unwrap();
        let _guard = crate::backup::set_test_backup_dir(backup_dir.path());
        enable_totp_for_service(&paths, "sshd").unwrap();
        disable_totp_for_service(&paths, "sshd").unwrap();
        enable_totp_for_service(&paths, "sshd").unwrap();

        let written = std::fs::read_to_string(paths.pam_d.join("sshd")).unwrap();
        assert_eq!(
            written.matches("# Managed by toride").count(),
            1,
            "exactly one managed marker line:\n{written}"
        );
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
    fn write_pam_config_leaves_no_temp_file_behind() {
        // The atomic write must not leak its temp file into the target dir.
        // After a successful write the directory should contain exactly the
        // target file (plus the service files created by `make_service`).
        let dir = tempfile::tempdir().unwrap();
        let paths = make_service(dir.path(), "sshd", "auth required pam_unix.so\n");

        let backup_dir = tempfile::tempdir().unwrap();
        let _guard = crate::backup::set_test_backup_dir(backup_dir.path());
        enable_totp_for_service(&paths, "sshd").unwrap();

        let pam_d = std::fs::read_dir(&paths.pam_d).unwrap();
        for entry in pam_d {
            let entry = entry.unwrap();
            let name = entry.file_name();
            // No leftover `.tmpXXXX`/tempfile scratch files: only the real
            // service config ("sshd") should be present.
            assert_eq!(
                name.to_string_lossy(),
                "sshd",
                "atomic write must not leave a temp file behind: {}",
                name.to_string_lossy()
            );
        }
    }

    #[test]
    fn write_pam_config_is_atomic_overwrites_completely() {
        // Simulate the crash-safety guarantee: a prior file is fully replaced
        // by the new content, never partially overwritten. After the write the
        // file must contain exactly the rendered rules (no truncation, no
        // mix of old+new bytes).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom");
        // A long pre-existing body so a partial overwrite would be detectable.
        let original = "auth required pam_unix.so\n".repeat(50);
        std::fs::write(&path, &original).unwrap();

        let rules = vec![PamRule {
            management_group: "auth".to_owned(),
            control: "required".to_owned(),
            module: "pam_google_authenticator.so".to_owned(),
            arguments: Vec::new(),
        }];
        let backup_dir = tempfile::tempdir().unwrap();
        let _guard = crate::backup::set_test_backup_dir(backup_dir.path());
        write_pam_config(&path, &rules, None).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        // The new file is short (one rule); a non-atomic overwrite that crashed
        // mid-write could leave a prefix of the old long content followed by
        // the new bytes. Assert the file is exactly the rendered new rules.
        assert!(
            written.contains("pam_google_authenticator.so"),
            "new rule present"
        );
        assert!(
            !written.contains("pam_unix.so"),
            "no stale bytes from the previous (longer) file -- write was atomic"
        );
    }

    #[cfg(unix)] // asserts Unix mode bits on the written file
    #[test]
    fn write_pam_config_sets_world_readable_mode() {
        // PAM service files must be 0o644 so the PAM stack (which may run as
        // any user) can read them. An atomic write that defaulted to 0o600
        // would silently break authentication.
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("modecheck");
        std::fs::write(&path, "auth required pam_unix.so\n").unwrap();

        let rules = read_pam_config(&path).unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let _guard = crate::backup::set_test_backup_dir(backup_dir.path());
        write_pam_config(&path, &rules, None).unwrap();

        let mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o644, "PAM files must remain world-readable (0o644)");
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
