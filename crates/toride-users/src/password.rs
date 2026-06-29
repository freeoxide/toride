//! Password policy enforcement via `chage` and `passwd`.
//!
//! Provides functions to set password aging policies, enforce complexity
//! requirements, and check for insecure password configurations.

use crate::spec::{Complexity, PasswordPolicy};
use crate::{Error, Result};

/// Apply a password policy to a user via `chage`.
///
/// Sets the password aging parameters: maximum days, minimum days, and
/// warning days.
///
/// # Errors
///
/// - [`Error::BinaryNotFound`] if `chage` is not on `$PATH`.
/// - [`Error::UserNotFound`] if the user does not exist.
/// - [`Error::CommandFailed`] if `chage` returns a non-zero exit code.
#[cfg(feature = "client")]
pub fn apply_password_policy(username: &str, policy: &PasswordPolicy) -> Result<()> {
    let chage = which::which("chage").map_err(|_| Error::BinaryNotFound("chage".into()))?;

    // Set maximum days
    duct::cmd(&chage, ["-M", &policy.max_days.to_string(), username])
        .stderr_to_stdout()
        .read()
        .map_err(|e| Error::CommandFailed {
            program: "chage".to_owned(),
            code: None,
            stderr: e.to_string(),
        })?;

    // Set minimum days
    duct::cmd(&chage, ["-m", &policy.min_days.to_string(), username])
        .stderr_to_stdout()
        .read()
        .map_err(|e| Error::CommandFailed {
            program: "chage".to_owned(),
            code: None,
            stderr: e.to_string(),
        })?;

    // Set warning days
    duct::cmd(&chage, ["-W", &policy.warn_days.to_string(), username])
        .stderr_to_stdout()
        .read()
        .map_err(|e| Error::CommandFailed {
            program: "chage".to_owned(),
            code: None,
            stderr: e.to_string(),
        })?;

    tracing::info!(
        "applied password policy to {username}: max={} min={} warn={}",
        policy.max_days,
        policy.min_days,
        policy.warn_days
    );
    Ok(())
}

/// Force a user to change their password on next login.
///
/// Executes `chage -d 0 <username>`.
///
/// # Errors
///
/// - [`Error::BinaryNotFound`] if `chage` is not on `$PATH`.
/// - [`Error::CommandFailed`] if `chage` returns a non-zero exit code.
#[cfg(feature = "client")]
pub fn force_password_change(username: &str) -> Result<()> {
    let chage = which::which("chage").map_err(|_| Error::BinaryNotFound("chage".into()))?;

    duct::cmd(&chage, ["-d", "0", username])
        .stderr_to_stdout()
        .read()
        .map_err(|e| Error::CommandFailed {
            program: "chage".to_owned(),
            code: None,
            stderr: e.to_string(),
        })?;

    tracing::info!("forced password change for {username}");
    Ok(())
}

/// Lock a user account.
///
/// Executes `usermod -L <username>` to lock the account by prepending `!`
/// to the password hash in `/etc/shadow`.
///
/// # Errors
///
/// - [`Error::BinaryNotFound`] if `usermod` is not on `$PATH`.
/// - [`Error::CommandFailed`] if `usermod` returns a non-zero exit code.
#[cfg(feature = "client")]
pub fn lock_account(username: &str) -> Result<()> {
    let usermod = which::which("usermod").map_err(|_| Error::BinaryNotFound("usermod".into()))?;

    duct::cmd(&usermod, ["-L", username])
        .stderr_to_stdout()
        .read()
        .map_err(|e| Error::CommandFailed {
            program: "usermod".to_owned(),
            code: None,
            stderr: e.to_string(),
        })?;

    tracing::info!("locked account {username}");
    Ok(())
}

/// Unlock a user account.
///
/// Executes `usermod -U <username>`.
///
/// # Errors
///
/// - [`Error::BinaryNotFound`] if `usermod` is not on `$PATH`.
/// - [`Error::CommandFailed`] if `usermod` returns a non-zero exit code.
#[cfg(feature = "client")]
pub fn unlock_account(username: &str) -> Result<()> {
    let usermod = which::which("usermod").map_err(|_| Error::BinaryNotFound("usermod".into()))?;

    duct::cmd(&usermod, ["-U", username])
        .stderr_to_stdout()
        .read()
        .map_err(|e| Error::CommandFailed {
            program: "usermod".to_owned(),
            code: None,
            stderr: e.to_string(),
        })?;

    tracing::info!("unlocked account {username}");
    Ok(())
}

/// Check if a user account is locked.
///
/// Reads `shadow` (usually `/etc/shadow`, or a redirect via
/// [`crate::paths::UserPaths`]) for a `!` prefix on the password hash.
///
/// # Errors
///
/// - [`Error::Io`] if `shadow` is missing or unreadable (e.g. permission
///   denied). This is distinguished from a missing user so callers can tell
///   "cannot tell" apart from "user not present".
/// - [`Error::UserNotFound`] if the file is readable but the user is absent.
pub fn is_account_locked(shadow: &std::path::Path, username: &str) -> Result<bool> {
    // Surface a missing/unreadable shadow file as an I/O error rather than
    // conflating it with UserNotFound. `read_to_string` returns an EACCES /
    // NotFound io::Error here, which converts into `Error::Io` via `?`.
    let shadow = std::fs::read_to_string(shadow)?;
    for line in shadow.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 2 && parts[0] == username {
            return Ok(parts[1].starts_with('!') || parts[1].starts_with("!!"));
        }
    }
    Err(Error::UserNotFound(username.to_owned()))
}

/// Check if a user has an empty password.
///
/// Reads `shadow` (usually `/etc/shadow`) for an empty password field.
pub fn has_empty_password(shadow: &std::path::Path, username: &str) -> Result<bool> {
    let shadow = std::fs::read_to_string(shadow)?;
    for line in shadow.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 2 && parts[0] == username {
            return Ok(parts[1].is_empty());
        }
    }
    Err(Error::UserNotFound(username.to_owned()))
}

/// Validate a password against the complexity requirements.
///
/// This is a local check that does not call any external commands.
///
/// # Errors
///
/// Returns [`Error::PasswordPolicy`] if the password does not meet the
/// complexity requirements.
pub fn validate_password_complexity(password: &str, complexity: Complexity) -> Result<()> {
    match complexity {
        Complexity::None => {}
        Complexity::Standard => {
            if password.len() < 8 {
                return Err(Error::PasswordPolicy(
                    "password must be at least 8 characters".into(),
                ));
            }
        }
        Complexity::Strong => {
            if password.len() < 12 {
                return Err(Error::PasswordPolicy(
                    "password must be at least 12 characters".into(),
                ));
            }
            let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
            let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
            let has_digit = password.chars().any(|c| c.is_ascii_digit());
            let has_special = password.chars().any(|c| !c.is_alphanumeric());

            if !has_upper {
                return Err(Error::PasswordPolicy(
                    "password must contain at least one uppercase letter".into(),
                ));
            }
            if !has_lower {
                return Err(Error::PasswordPolicy(
                    "password must contain at least one lowercase letter".into(),
                ));
            }
            if !has_digit {
                return Err(Error::PasswordPolicy(
                    "password must contain at least one digit".into(),
                ));
            }
            if !has_special {
                return Err(Error::PasswordPolicy(
                    "password must contain at least one special character".into(),
                ));
            }
        }
    }
    Ok(())
}
