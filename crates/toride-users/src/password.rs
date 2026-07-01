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
            // Count characters, not bytes: a short password padded with
            // multi-byte UTF-8 (e.g. 4 emoji) would otherwise satisfy a
            // 12-byte minimum while having a trivially small keyspace.
            if password.chars().count() < 8 {
                return Err(Error::PasswordPolicy(
                    "password must be at least 8 characters".into(),
                ));
            }
        }
        Complexity::Strong => {
            if password.chars().count() < 12 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::Complexity;

    // ---- validate_password_complexity length boundaries ----

    #[test]
    fn standard_rejects_seven_chars() {
        // 7 ASCII chars -> under the 8-char minimum.
        assert!(validate_password_complexity("aaaaaaa", Complexity::Standard).is_err());
    }

    #[test]
    fn standard_accepts_eight_chars() {
        assert!(validate_password_complexity("aaaaaaaa", Complexity::Standard).is_ok());
    }

    #[test]
    fn strong_rejects_eleven_chars() {
        // Meets all class requirements but is only 11 chars -> rejected.
        let pw = "Aa1!aaaaaaa"; // 11 chars: upper, lower, digit, special
        assert_eq!(pw.chars().count(), 11);
        assert!(validate_password_complexity(pw, Complexity::Strong).is_err());
    }

    #[test]
    fn strong_accepts_twelve_chars() {
        let pw = "Aa1!aaaaaaaa"; // 12 chars: upper, lower, digit, special
        assert_eq!(pw.chars().count(), 12);
        assert!(validate_password_complexity(pw, Complexity::Strong).is_ok());
    }

    #[test]
    fn strong_rejects_missing_uppercase() {
        let pw = "aa1!aaaaaaaa"; // no uppercase
        assert!(validate_password_complexity(pw, Complexity::Strong).is_err());
    }

    #[test]
    fn strong_rejects_missing_lowercase() {
        let pw = "AA1!AAAAAAAA"; // no lowercase
        assert!(validate_password_complexity(pw, Complexity::Strong).is_err());
    }

    #[test]
    fn strong_rejects_missing_digit() {
        let pw = "Aa!?aaaaaaaa"; // no digit
        assert!(validate_password_complexity(pw, Complexity::Strong).is_err());
    }

    #[test]
    fn strong_rejects_missing_special() {
        let pw = "Aa1aaaaaaaaa"; // no special
        assert!(validate_password_complexity(pw, Complexity::Strong).is_err());
    }

    // ---- the multi-byte bypass the byte-count bug allowed ----

    #[test]
    fn strong_rejects_multibyte_padding() {
        // Four emoji are 4 *chars* but 16 BYTES. The old `password.len() < 12`
        // byte check saw 16 and accepted this as a 12+ char password even
        // though it is only 4 code points with a trivially small keyspace.
        let pw = "\u{1F600}\u{1F601}\u{1F602}\u{1F923}";
        assert_eq!(pw.len(), 16); // bytes
        assert_eq!(pw.chars().count(), 4); // chars -- the real length
        // After the fix, char-count is used, so this MUST be rejected.
        assert!(
            validate_password_complexity(pw, Complexity::Strong).is_err(),
            "4-char emoji password must not satisfy the 12-char Strong minimum"
        );
    }

    #[test]
    fn standard_rejects_multibyte_padding() {
        // Two emoji = 8 bytes but only 2 chars. Old byte check passed it for
        // the 8-char Standard minimum; char-count correctly rejects it.
        let pw = "\u{1F600}\u{1F601}";
        assert_eq!(pw.len(), 8);
        assert_eq!(pw.chars().count(), 2);
        assert!(validate_password_complexity(pw, Complexity::Standard).is_err());
    }

    // ---- is_account_locked / has_empty_password against fixture shadow ----

    fn write_shadow(content: &str) -> std::path::PathBuf {
        // Keep the tempdir alive for the whole test by leaking it; the OS
        // reclaims the filesystem space on process exit. This keeps the tests
        // hermetic (no real /etc/shadow read).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shadow");
        std::fs::write(&path, content).unwrap();
        std::mem::forget(dir);
        path
    }

    #[test]
    fn is_account_locked_detects_single_bang() {
        // Locked by usermod -L: single '!' prefix.
        let shadow = write_shadow("bob:!$6$hash:19000:0:99999:7:::\n");
        assert!(is_account_locked(&shadow, "bob").unwrap());
    }

    #[test]
    fn is_account_locked_detects_double_bang() {
        // A freshly created account with no password set: '!!'.
        let shadow = write_shadow("carol:!!:19000:0:99999:7:::\n");
        assert!(is_account_locked(&shadow, "carol").unwrap());
    }

    #[test]
    fn is_account_locked_false_for_valid_hash() {
        let shadow = write_shadow("alice:$6$validhash:19000:0:99999:7:::\n");
        assert!(!is_account_locked(&shadow, "alice").unwrap());
    }

    #[test]
    fn is_account_locked_user_not_found() {
        let shadow = write_shadow("alice:$6$hash:19000:0:99999:7:::\n");
        assert!(matches!(
            is_account_locked(&shadow, "nobody"),
            Err(Error::UserNotFound(_))
        ));
    }

    #[test]
    fn has_empty_password_detects_blank_field() {
        let shadow = write_shadow("dave::19000:0:99999:7:::\n");
        assert!(has_empty_password(&shadow, "dave").unwrap());
    }

    #[test]
    fn has_empty_password_false_for_hash_or_lock() {
        let shadow = write_shadow(
            "alice:$6$hash:19000:0:99999:7:::\n\
             bob:!:19000:0:99999:7:::\n",
        );
        assert!(!has_empty_password(&shadow, "alice").unwrap());
        assert!(!has_empty_password(&shadow, "bob").unwrap());
    }

    #[test]
    fn has_empty_password_user_not_found() {
        let shadow = write_shadow("alice:$6$hash:19000:0:99999:7:::\n");
        assert!(matches!(
            has_empty_password(&shadow, "ghost"),
            Err(Error::UserNotFound(_))
        ));
    }
}
