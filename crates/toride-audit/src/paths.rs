//! Path constants and resolution for audit subsystem configuration files.
//!
//! Provides well-known paths for the Linux audit daemon (`/etc/audit/`),
//! AIDE configuration (`/etc/aide.conf`), rsyslog (`/etc/rsyslog.conf`),
//! and logrotate drop-in directory (`/etc/logrotate.d/`).

use std::path::PathBuf;

use crate::{Error, Result};

/// Validate a user/config-supplied `name` before joining it onto a managed
/// `/etc` directory.
///
/// Rejects anything that could escape the target directory or be interpreted
/// as a flag by a downstream tool:
///
/// - empty names,
/// - names containing a path separator (`/` or `\`),
/// - names containing a NUL byte,
/// - names that equal or contain a parent-directory segment (`..`),
/// - absolute names (already caught by the `/` rule, but rejected explicitly
///   for a clear error),
/// - names that look like a command-line flag (leading `-`).
///
/// Returns the validated name unchanged on success.
///
/// # Errors
///
/// Returns [`Error::Other`] with a descriptive message on a rejected name.
pub fn validate_name(name: &str) -> Result<&str> {
    if name.is_empty() {
        return Err(Error::Other("name must not be empty".to_owned()));
    }
    if name.contains('\0') {
        return Err(Error::Other("name must not contain NUL".to_owned()));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(Error::Other(format!(
            "name must not contain a path separator: {name:?}"
        )));
    }
    // Reject the literal `..` and any path component that is `..`
    // (e.g. `foo/..` is already caught above; `foo..bar` is benign and allowed,
    // but a standalone `..` or `..something` starting the name is suspicious
    // only when it is exactly `..`).
    if name == ".." || name == "." {
        return Err(Error::Other(format!("name must not be '.' or '..': {name:?}")));
    }
    if name.starts_with('-') {
        return Err(Error::Other(format!(
            "name must not start with '-' (looks like a flag): {name:?}"
        )));
    }
    Ok(name)
}

/// Well-known system paths used by the audit subsystem.
///
/// These are the default Linux FHS locations. Production code should
/// prefer [`crate::AuditPaths`] which supports override, but these
/// constants are useful for validation and display.
pub struct AuditPathsConst;

impl AuditPathsConst {
    /// Default audit daemon configuration directory.
    pub const AUDIT_DIR: &'static str = "/etc/audit";

    /// Default audit rules directory.
    pub const RULES_D: &'static str = "/etc/audit/rules.d";

    /// Default auditd configuration file.
    pub const AUDITD_CONF: &'static str = "/etc/audit/auditd.conf";

    /// Default AIDE configuration file.
    pub const AIDE_CONF: &'static str = "/etc/aide.conf";

    /// Default rsyslog configuration file.
    pub const RSYSLOG_CONF: &'static str = "/etc/rsyslog.conf";

    /// Default rsyslog drop-in directory.
    pub const RSYSLOG_D: &'static str = "/etc/rsyslog.d";

    /// Default logrotate drop-in directory.
    pub const LOGROTATE_D: &'static str = "/etc/logrotate.d";

    /// Default AIDE database directory.
    pub const AIDE_DB_DIR: &'static str = "/var/lib/aide";
}

/// Resolves the path to a managed audit rules file.
///
/// Returns `{rules_d}/{name}.rules` using the default rules directory.
#[must_use]
pub fn rules_file(name: &str) -> PathBuf {
    PathBuf::from(AuditPathsConst::RULES_D).join(format!("{name}.rules"))
}

/// Resolves the path to a managed logrotate config file.
///
/// Returns `{logrotate_d}/{name}` using the default logrotate directory.
#[must_use]
pub fn logrotate_file(name: &str) -> PathBuf {
    PathBuf::from(AuditPathsConst::LOGROTATE_D).join(name)
}

/// Resolves the path to a managed rsyslog drop-in file.
///
/// Returns `{rsyslog_d}/{name}.conf` using the default rsyslog directory.
#[must_use]
pub fn rsyslog_dropin(name: &str) -> PathBuf {
    PathBuf::from(AuditPathsConst::RSYSLOG_D).join(format!("{name}.conf"))
}

/// Restrictive permission mode for managed configuration files (`rw-r--r--`).
///
/// Managed `/etc` config files written by this crate embed root-run shell
/// snippets (e.g. logrotate `postrotate`) and must never be group/other
/// writable regardless of the process umask.
pub const CONFIG_FILE_MODE: u32 = 0o644;

/// Restrictive permission mode for managed configuration directories.
pub const CONFIG_DIR_MODE: u32 = 0o755;

/// Pin a freshly-written managed config file to a restrictive mode.
///
/// On Unix this is `0o644` by default; on non-Unix targets it is a no-op.
/// Call this immediately after `fs::write` so a permissive umask (e.g. `0`,
/// common in Docker entrypoints / cloud-init / `UMask=0` systemd units)
/// cannot leave the file group/other writable.
///
/// # Errors
///
/// Returns [`Error::Io`] if the permissions cannot be set.
pub fn secure_file_mode(path: &std::path::Path) -> Result<()> {
    secure_mode(path, CONFIG_FILE_MODE)
}

/// Pin a managed config directory to a restrictive mode (default `0o755`).
///
/// # Errors
///
/// Returns [`Error::Io`] if the permissions cannot be set.
pub fn secure_dir_mode(path: &std::path::Path) -> Result<()> {
    secure_mode(path, CONFIG_DIR_MODE)
}

#[cfg(unix)]
fn secure_mode(path: &std::path::Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(Error::from)
}

#[cfg(not(unix))]
fn secure_mode(_path: &std::path::Path, _mode: u32) -> Result<()> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_name_accepts_normal_names() {
        assert_eq!(validate_name("99-hardening").unwrap(), "99-hardening");
        assert_eq!(validate_name("audit_rules").unwrap(), "audit_rules");
        assert_eq!(validate_name("my.config").unwrap(), "my.config");
    }

    #[test]
    fn validate_name_rejects_empty() {
        assert!(validate_name("").is_err());
    }

    #[test]
    fn validate_name_rejects_traversal_and_separators() {
        // `..` parent reference.
        assert!(validate_name("..").is_err());
        // Absolute / separator-bearing names.
        assert!(validate_name("/x").is_err());
        assert!(validate_name("a/b").is_err());
        assert!(validate_name("a\\b").is_err());
        assert!(validate_name(".").is_err());
    }

    #[test]
    fn validate_name_rejects_nul_and_leading_dash() {
        assert!(validate_name("a\0b").is_err());
        assert!(validate_name("-evil").is_err());
        assert!(validate_name("--").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn secure_file_mode_clears_group_other_write() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg");
        std::fs::write(&path, b"hi").unwrap();
        secure_file_mode(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            CONFIG_FILE_MODE,
            "no group/other write bits should be set"
        );
        // No write for group/other specifically.
        assert_eq!(mode & 0o022, 0, "group/other write bits must be clear");
    }

    #[cfg(unix)]
    #[test]
    fn secure_dir_mode_sets_755() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subdir");
        std::fs::create_dir(&path).unwrap();
        secure_dir_mode(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, CONFIG_DIR_MODE);
    }
}
