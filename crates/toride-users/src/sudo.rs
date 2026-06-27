//! Sudoers configuration management.
//!
//! Provides functions to manage sudo access by writing drop-in files to
//! `/etc/sudoers.d/` and validating sudoers syntax via `visudo -c`.

use std::path::Path;

use crate::{paths::UserPaths, render, Error, Result};

/// Grant sudo access to a user by creating a drop-in file.
///
/// Creates `/etc/sudoers.d/<username>` with the appropriate rule.
/// Optionally sets `NOPASSWD` mode.
///
/// # Errors
///
/// - [`Error::UserExists`] if a sudoers drop-in already exists for this user.
/// - [`Error::SudoError`] if the written file fails `visudo -c` validation.
/// - [`Error::Io`] if the file cannot be written.
pub fn grant_sudo(paths: &UserPaths, username: &str, nopasswd: bool) -> Result<()> {
    let dropin = paths.sudoers_dropin(username);

    if dropin.exists() {
        return Err(Error::SudoError(format!(
            "sudoers drop-in already exists: {}",
            dropin.display()
        )));
    }

    let content = render::render_sudoers_entry(username, "ALL", nopasswd, Some("ALL"));
    let content = format!("# Managed by toride\n{content}\n");

    // Write with mode 0440 (sudoers requirement)
    write_sudoers_file(&dropin, &content)?;

    // Validate
    validate_sudoers(&dropin)?;

    tracing::info!("granted sudo to {username} (nopasswd={nopasswd})");
    Ok(())
}

/// Revoke sudo access for a user by removing their drop-in file.
///
/// Removes `/etc/sudoers.d/<username>` if it is managed by toride
/// (starts with `# Managed by toride`).
///
/// # Errors
///
/// - [`Error::SudoError`] if the file is not managed by toride or does not
///   exist.
/// - [`Error::Io`] if the file cannot be removed.
pub fn revoke_sudo(paths: &UserPaths, username: &str) -> Result<()> {
    let dropin = paths.sudoers_dropin(username);

    if !dropin.exists() {
        return Err(Error::SudoError(format!(
            "sudoers drop-in not found: {}",
            dropin.display()
        )));
    }

    // Check that it's managed by toride
    let content = std::fs::read_to_string(&dropin)?;
    if !content.contains("# Managed by toride") {
        return Err(Error::SudoError(format!(
            "sudoers drop-in is not managed by toride: {}",
            dropin.display()
        )));
    }

    // Backup before removal
    crate::backup::backup_file(&dropin, None)?;

    std::fs::remove_file(&dropin)?;

    tracing::info!("revoked sudo for {username}");
    Ok(())
}

/// Check if a user has sudo access.
///
/// Checks for the existence of a drop-in file in `/etc/sudoers.d/` or
/// entries in the main sudoers file.
pub fn has_sudo(paths: &UserPaths, username: &str) -> Result<bool> {
    let dropin = paths.sudoers_dropin(username);
    if dropin.exists() {
        return Ok(true);
    }

    // Check main sudoers file
    if paths.sudoers.exists() {
        let entries = crate::parse::read_sudoers(&paths.sudoers)?;
        return Ok(entries.iter().any(|e| e.who == username));
    }

    Ok(false)
}

/// Write a sudoers file with the correct permissions (0440).
fn write_sudoers_file(path: &Path, content: &str) -> Result<()> {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(path, content)?;

    // Set permissions to 0440
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o440);
        std::fs::set_permissions(path, perms)?;
    }

    Ok(())
}

/// Validate a sudoers file using `visudo -c -f <path>`.
///
/// # Errors
///
/// Returns [`Error::SudoError`] if `visudo` reports a syntax error or the
/// binary is not found.
#[cfg(feature = "client")]
pub fn validate_sudoers(path: &Path) -> Result<()> {
    let visudo = which::which("visudo").map_err(|_| Error::BinaryNotFound("visudo".into()))?;

    let path_str = path.to_string_lossy().to_string();
    let output = duct::cmd(&visudo, ["-c", "-f", &path_str])
        .stderr_to_stdout()
        .read()
        .map_err(|e| Error::CommandFailed {
            program: "visudo".to_owned(),
            code: None,
            stderr: e.to_string(),
        })?;

    if output.contains("syntax error") || output.contains("parse error") {
        return Err(Error::SudoError(format!(
            "sudoers validation failed for {}: {output}",
            path.display()
        )));
    }

    Ok(())
}

/// Validate a sudoers file for non-client builds.
///
/// The `client` feature gates the real `visudo -c -f <path>` invocation. When
/// `client` is disabled this build cannot shell out, so rather than silently
/// returning `Ok(())` (which would let an invalid sudoers file through
/// `grant_sudo`), this returns an explicit error telling the caller that
/// validation is unavailable in this configuration.
///
/// Callers that need the no-op behavior (e.g. a deliberately minimal build
/// that has already validated the content out-of-band) can match
/// [`Error::SudoError`] and treat it as a warning.
#[cfg(not(feature = "client"))]
pub fn validate_sudoers(path: &Path) -> Result<()> {
    Err(Error::SudoError(format!(
        "sudoers validation unavailable without the 'client' feature (cannot run \
         `visudo -c`); left {} unchecked",
        path.display()
    )))
}

#[cfg(all(test, not(feature = "client")))]
mod no_client_tests {
    use super::*;

    /// Regression: the `not(client)` branch of `validate_sudoers` must NOT be a
    /// silent `Ok(())` no-op, because `grant_sudo` calls it after writing a
    /// sudoers drop-in and a silent pass lets an invalid file through. It now
    /// returns an explicit `Error::SudoError` so the caller knows validation
    /// was skipped. The path appears in the message so the operator can see
    /// which file was left unchecked.
    #[test]
    fn validate_sudoers_without_client_feature_is_explicit_error() {
        let path = Path::new("/etc/sudoers.d/example");
        let err = validate_sudoers(path).expect_err("should error without client feature");
        assert!(
            matches!(err, Error::SudoError(_)),
            "expected SudoError, got {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("/etc/sudoers.d/example"),
            "error should name the unchecked path: {msg}"
        );
        assert!(
            msg.contains("client"),
            "error should explain the 'client' feature is required: {msg}"
        );
    }
}
