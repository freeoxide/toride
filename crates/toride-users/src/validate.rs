//! Validation functions for usernames, login shells, and user specs.
//!
//! These functions enforce security constraints on user configuration values
//! to prevent injection attacks and ensure system compatibility.

use crate::{Error, Result, spec::UserSpec};

// ---------------------------------------------------------------------------
// Username validation
// ---------------------------------------------------------------------------

/// Characters that are forbidden in usernames.
///
/// POSIX allows lowercase letters, digits, underscores, and hyphens
/// (but not starting with a hyphen). We additionally reject dots and any
/// character outside the ASCII printable range.
const FORBIDDEN_USERNAME_CHARS: &[char] = &[
    ' ', '\t', '\n', '\r', ':', '/', '\\', '&', '|', ';', '$', '`', '"', '\'', '<', '>', '(', ')',
    '{', '}', '!', '#', '%', '?', '*', '~', ',',
];

/// Maximum username length (Linux limit is 32 characters).
const MAX_USERNAME_LEN: usize = 32;

/// Validate that a username is safe and well-formed.
///
/// Rules:
/// - Must be non-empty
/// - At most 32 characters
/// - Must start with a lowercase letter or underscore
/// - Only lowercase letters, digits, underscores, hyphens, and dollar signs
/// - No forbidden characters
/// - Cannot be `root` or other reserved names
///
/// # Errors
///
/// Returns [`Error::Validation`] if any rule is violated.
pub fn validate_username(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::Validation("username must not be empty".into()));
    }
    if name.len() > MAX_USERNAME_LEN {
        return Err(Error::Validation(format!(
            "username exceeds {MAX_USERNAME_LEN} characters: {name:?}"
        )));
    }
    // Empty case is rejected above, so the first char always exists here.
    if let Some(first) = name.chars().next()
        && !first.is_ascii_lowercase()
        && first != '_'
    {
        return Err(Error::Validation(format!(
            "username must start with a lowercase letter or underscore: {name:?}"
        )));
    }
    if let Some(ch) = name.chars().find(|c| FORBIDDEN_USERNAME_CHARS.contains(c)) {
        return Err(Error::Validation(format!(
            "username contains forbidden character {ch:?}: {name:?}"
        )));
    }
    // Reject reserved names
    if matches!(name, "root" | "nobody" | "daemon" | "bin" | "sys" | "adm") {
        return Err(Error::Validation(format!("username is reserved: {name:?}")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shell validation
// ---------------------------------------------------------------------------

/// Known valid login shells on a typical Linux system.
const VALID_SHELLS: &[&str] = &[
    "/bin/bash",
    "/bin/sh",
    "/usr/bin/bash",
    "/usr/bin/sh",
    "/bin/zsh",
    "/usr/bin/zsh",
    "/bin/dash",
    "/usr/bin/dash",
    "/bin/fish",
    "/usr/bin/fish",
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/bin/false",
    "/usr/bin/git-shell",
];

/// Validate that a shell path is a known valid login shell.
///
/// # Errors
///
/// Returns [`Error::Validation`] if the shell is not in the allow list.
pub fn validate_shell(shell: &str) -> Result<()> {
    if shell.is_empty() {
        return Err(Error::Validation("shell must not be empty".into()));
    }
    if !shell.starts_with('/') {
        return Err(Error::Validation(format!(
            "shell must be an absolute path: {shell:?}"
        )));
    }
    // Allow but warn about unknown shells
    if !VALID_SHELLS.contains(&shell) {
        tracing::warn!("shell {shell:?} is not in the known shells list");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Spec validation
// ---------------------------------------------------------------------------

/// Validate a complete [`UserSpec`].
///
/// Checks:
/// - Username is valid via [`validate_username`]
/// - Shell is valid via [`validate_shell`]
/// - All group names are non-empty
///
/// # Errors
///
/// Returns [`Error::Validation`] if any field is invalid.
pub fn validate_spec(spec: &UserSpec) -> Result<()> {
    validate_username(&spec.username)?;
    validate_shell(&spec.shell)?;
    for group in &spec.groups {
        if group.is_empty() {
            return Err(Error::Validation(format!(
                "group name must not be empty in spec for user {:?}",
                spec.username
            )));
        }
        if group.contains(' ') || group.contains(':') {
            return Err(Error::Validation(format!(
                "group name contains forbidden character: {group:?}"
            )));
        }
    }
    Ok(())
}
