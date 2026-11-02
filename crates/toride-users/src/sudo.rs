//! Sudoers configuration management.
//!
//! Provides functions to manage sudo access by writing drop-in files to
//! `/etc/sudoers.d/` and validating sudoers syntax via `visudo -c`.

use std::path::{Path, PathBuf};

use crate::{Error, Result, paths::UserPaths, render};

/// Resolve and validate a sudoers drop-in path for `username`.
///
/// Validates the username first (so a malformed name is rejected before any
/// filesystem activity), then joins it onto [`UserPaths::sudoers_d`] and
/// verifies the result stays within that directory. The check uses
/// [`Path::starts_with`], which compares by component, rather than calling
/// `canonicalize` -- `canonicalize` fails on the not-yet-existing drop-in file
/// during `grant_sudo` and requires the base to exist on disk. The component
/// comparison catches traversal attempts (`../`), embedded absolute paths, and
/// drive prefixes regardless of whether the paths currently exist.
///
/// # Errors
///
/// - [`Error::Validation`] if the username is invalid.
/// - [`Error::SudoError`] if the resolved path escapes `sudoers_d`.
fn sudoers_dropin_contained(paths: &UserPaths, username: &str) -> Result<PathBuf> {
    crate::validate::validate_username(username)?;
    let dropin = paths.sudoers_d.join(username);
    // `Path::starts_with` compares by component, so a malicious username
    // containing `..` or an absolute segment is caught even though the file
    // does not exist yet (canonicalize would fail on a missing path).
    if !dropin.starts_with(&paths.sudoers_d) {
        return Err(Error::SudoError(format!(
            "sudoers drop-in path escapes sudoers.d: {}",
            dropin.display()
        )));
    }
    Ok(dropin)
}

/// Grant sudo access to a user by creating a drop-in file.
///
/// Creates `/etc/sudoers.d/<username>` with the appropriate rule.
/// Optionally sets `NOPASSWD` mode.
///
/// The content is written to a probe file inside `sudoers.d` and validated
/// with `visudo -c -f` before anything lands at the final path: sudo refuses
/// to run while any file in `sudoers.d` has a syntax error, so an invalid
/// drop-in left in place would brick the system's sudo until manual removal.
/// Only a validated file is atomically renamed into place at mode 0440.
///
/// # Errors
///
/// - [`Error::Validation`] if the username is invalid.
/// - [`Error::UserExists`] if a sudoers drop-in already exists for this user.
/// - [`Error::SudoError`] if the drop-in path escapes `sudoers.d` or the
///   content fails `visudo -c` validation.
/// - [`Error::Io`] if the file cannot be written.
pub fn grant_sudo(paths: &UserPaths, username: &str, nopasswd: bool) -> Result<()> {
    let dropin = sudoers_dropin_contained(paths, username)?;

    if dropin.exists() {
        return Err(Error::SudoError(format!(
            "sudoers drop-in already exists: {}",
            dropin.display()
        )));
    }

    let content = render::render_sudoers_entry(username, "ALL", nopasswd, Some("ALL"));
    let content = format!("# Managed by toride\n{content}\n");

    std::fs::create_dir_all(&paths.sudoers_d)?;
    let probe = unique_probe_path(&paths.sudoers_d, username);
    let grant = install_validated_dropin(&dropin, &probe, &content);

    if grant.is_err()
        && let Err(cleanup_error) = std::fs::remove_file(&probe)
        && cleanup_error.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(
            probe = %probe.display(),
            error = %cleanup_error,
            "could not remove the sudoers validation probe"
        );
    }
    grant?;

    tracing::info!("granted sudo to {username} (nopasswd={nopasswd})");
    Ok(())
}

/// Write `content` to `probe`, validate it with `visudo -c -f`, and only then
/// atomically rename the probe onto `dropin` (mode 0440, the sudoers
/// requirement).
///
/// # Errors
///
/// Returns [`Error::Io`] for filesystem failures and propagates
/// [`validate_sudoers`]'s error when the content is rejected.
fn install_validated_dropin(dropin: &Path, probe: &Path, content: &str) -> Result<()> {
    std::fs::write(probe, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(probe, std::fs::Permissions::from_mode(0o440))?;
    }
    validate_sudoers(probe)?;
    std::fs::rename(probe, dropin)?;
    Ok(())
}

/// A collision-resistant probe path inside `sudoers.d` for `username`.
fn unique_probe_path(dir: &Path, username: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    dir.join(format!(".toride-{username}-sudoers-probe-{nanos}"))
}

/// Revoke sudo access for a user by removing their drop-in file.
///
/// Removes `/etc/sudoers.d/<username>` if it is managed by toride
/// (starts with `# Managed by toride`).
///
/// # Errors
///
/// - [`Error::Validation`] if the username is invalid.
/// - [`Error::SudoError`] if the drop-in path escapes `sudoers.d`, the file is
///   not managed by toride, or does not exist.
/// - [`Error::Io`] if the file cannot be removed.
pub fn revoke_sudo(paths: &UserPaths, username: &str) -> Result<()> {
    let dropin = sudoers_dropin_contained(paths, username)?;

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
    let dropin = paths.sudoers_dropin(username)?;
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

/// Validate a sudoers file using `visudo -c -f <path>`.
///
/// The command's merged output and exit code are captured even on failure;
/// visudo's syntax-error exit (4) or a `syntax error`/`parse error` in the
/// output maps to [`Error::SudoError`], other failures to
/// [`Error::CommandFailed`] with the real exit code.
///
/// # Errors
///
/// Returns [`Error::BinaryNotFound`] if `visudo` is not on `$PATH`,
/// [`Error::SudoError`] on a syntax error, and [`Error::CommandFailed`] for
/// other non-zero exits.
#[cfg(feature = "client")]
pub fn validate_sudoers(path: &Path) -> Result<()> {
    let visudo = which::which("visudo").map_err(|_| Error::BinaryNotFound("visudo".into()))?;

    let args = [
        "-c".to_owned(),
        "-f".to_owned(),
        path.to_string_lossy().into_owned(),
    ];
    let output = crate::capture::run_captured("visudo", &visudo, &args)?;
    if output.status.success() {
        return Ok(());
    }
    let text = crate::capture::merged_output_text(&output);
    let syntax_error = output.status.code() == Some(4)
        || text.contains("syntax error")
        || text.contains("parse error");
    if syntax_error {
        return Err(Error::SudoError(format!(
            "sudoers validation failed for {}: {text}",
            path.display()
        )));
    }
    Err(Error::CommandFailed {
        program: "visudo".to_owned(),
        code: output.status.code(),
        stderr: text,
    })
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

/// The lockout guard for `grant_sudo`: validation must run on a probe file
/// and a rejected grant must leave neither the drop-in nor the probe behind,
/// because sudo refuses to run while sudoers.d holds a syntax error.
#[cfg(all(test, feature = "client"))]
mod grant_tests {
    use super::*;
    use crate::paths::UserPaths;

    #[cfg(feature = "client")]
    fn sudoers_dir_with_visudo_absent() -> (tempfile::TempDir, UserPaths) {
        // This host has no visudo on PATH in the test sandbox; if a real
        // visudo IS found the test would exercise the success path instead,
        // so skip in that case.
        let dir = tempfile::tempdir().unwrap();
        let paths = UserPaths::with_base(dir.path());
        (dir, paths)
    }

    #[test]
    fn grant_sudo_leaves_no_files_behind_when_validation_cannot_run() {
        if which::which("visudo").is_ok() {
            return;
        }
        let (dir, paths) = sudoers_dir_with_visudo_absent();

        let err = grant_sudo(&paths, "alice", false)
            .expect_err("grant must fail when visudo cannot validate");

        assert!(
            matches!(err, Error::BinaryNotFound(ref b) if b == "visudo"),
            "expected BinaryNotFound(visudo), got {err:?}"
        );
        let entries: Vec<String> = std::fs::read_dir(&paths.sudoers_d)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            entries.is_empty(),
            "a failed grant must leave no drop-in and no probe file: {entries:?}"
        );
        assert!(!dir.path().join("sudoers.d/alice").exists());
    }
}

#[cfg(all(test, not(feature = "client")))]
mod no_client_tests {

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
