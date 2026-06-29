//! TOTP/2FA enrollment via `google-authenticator`.
//!
//! Provides functions to set up and manage TOTP-based two-factor
//! authentication using the `google-authenticator` PAM module.

use crate::{Error, Result, paths::UserPaths};

/// Check if TOTP is set up for a user.
///
/// Checks for the existence of `~<username>/.google_authenticator`. The home
/// directory is resolved by reading `paths.passwd` so a custom base dir (e.g.
/// for tests or chrooted operation) is honored.
pub fn is_totp_configured(paths: &UserPaths, username: &str) -> Result<bool> {
    let home = get_user_home(paths, username)?;
    let ga_file = home.join(".google_authenticator");
    Ok(ga_file.exists())
}

/// Get the path to a user's `.google_authenticator` file.
///
/// # Errors
///
/// Returns [`Error::UserNotFound`] if the user's home directory cannot be
/// determined.
pub fn totp_file_path(paths: &UserPaths, username: &str) -> Result<std::path::PathBuf> {
    let home = get_user_home(paths, username)?;
    Ok(home.join(".google_authenticator"))
}

/// Enroll a user in TOTP/2FA.
///
/// This function creates the initial `.google_authenticator` file by running
/// `google-authenticator` in non-interactive mode with sensible defaults:
///
/// - Time-based (TOTP)
/// - Rate-limiting enabled (3 attempts per 30 seconds)
/// - Window size of 3 (allows slight clock drift)
/// - Emergency scratch codes generated
///
/// # Security
///
/// The generated secret key and scratch codes are sensitive. In production,
/// this function should be called interactively so the user can scan the QR
/// code and store their scratch codes securely.
///
/// # Errors
///
/// - [`Error::BinaryNotFound`] if `google-authenticator` is not installed.
/// - [`Error::TotpError`] if TOTP is already configured for this user.
/// - [`Error::CommandFailed`] if the command fails.
#[cfg(feature = "client")]
pub fn enroll_totp(paths: &UserPaths, username: &str) -> Result<String> {
    // Check if already enrolled
    if is_totp_configured(paths, username)? {
        return Err(Error::TotpError(format!(
            "TOTP already configured for user {username}"
        )));
    }

    let ga_bin = which::which("google-authenticator")
        .map_err(|_| Error::BinaryNotFound("google-authenticator".into()))?;

    let output = duct::cmd(
        &ga_bin,
        [
            "-t", // time-based
            "-d", // disallow reuse
            "-r", "3", // rate limit: 3 per 30s
            "-w", "3",  // window size
            "-s", // generate scratch codes
            "-f", // force (non-interactive)
        ],
    )
    .stderr_to_stdout()
    .read()
    .map_err(|e| Error::CommandFailed {
        program: "google-authenticator".to_owned(),
        code: None,
        stderr: e.to_string(),
    })?;

    tracing::info!("enrolled TOTP for user {username}");
    Ok(output)
}

/// Remove TOTP configuration for a user.
///
/// Deletes the `.google_authenticator` file from the user's home directory.
/// A backup is created before deletion. The home directory is resolved by
/// reading `paths.passwd`.
///
/// # Errors
///
/// - [`Error::TotpError`] if TOTP is not configured for this user.
/// - [`Error::Io`] if the file cannot be removed.
pub fn remove_totp(paths: &UserPaths, username: &str) -> Result<()> {
    let path = totp_file_path(paths, username)?;

    if !path.exists() {
        return Err(Error::TotpError(format!(
            "TOTP not configured for user {username}"
        )));
    }

    // Backup before removal
    crate::backup::backup_file(&path, None)?;

    std::fs::remove_file(&path)?;

    tracing::info!("removed TOTP for user {username}");
    Ok(())
}

/// Enable TOTP/2FA for SSH login for a specific user.
///
/// This combines:
/// 1. TOTP enrollment via [`enroll_totp`]
/// 2. PAM configuration update for the `sshd` service
///
/// # Errors
///
/// Returns any error from enrollment or PAM configuration.
#[cfg(feature = "client")]
pub fn enable_totp_ssh(paths: &UserPaths, username: &str) -> Result<String> {
    let output = enroll_totp(paths, username)?;
    crate::pam::enable_totp_for_service(paths, "sshd")?;
    tracing::info!("enabled TOTP for SSH login for user {username}");
    Ok(output)
}

/// Disable TOTP/2FA for SSH login for a specific user.
///
/// # Errors
///
/// Returns any error from removal or PAM configuration.
pub fn disable_totp_ssh(paths: &UserPaths, username: &str) -> Result<()> {
    remove_totp(paths, username)?;
    crate::pam::disable_totp_for_service(paths, "sshd")?;
    tracing::info!("disabled TOTP for SSH login for user {username}");
    Ok(())
}

/// Resolve the home directory for a user from `paths.passwd`.
fn get_user_home(paths: &UserPaths, username: &str) -> Result<std::path::PathBuf> {
    let entries = crate::parse::read_passwd(&paths.passwd)?;
    entries
        .iter()
        .find(|e| e.username == username)
        .map(|e| std::path::PathBuf::from(&e.home))
        .ok_or_else(|| Error::UserNotFound(username.to_owned()))
}
