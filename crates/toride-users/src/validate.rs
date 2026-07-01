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
/// - Only lowercase letters, digits, underscores, and hyphens
/// - No forbidden characters (shell metacharacters, whitespace, etc.)
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
    // Allowlist: the doc comment promises "only lowercase letters, digits,
    // underscores, hyphens, and dollar signs". The denylist above is not
    // sufficient -- characters like '@', '+', '.', and non-ASCII letters are
    // absent from it and would otherwise pass into `useradd`/`/etc/sudoers.d`
    // argv and filenames. Enforce the documented set explicitly so the
    // validator matches its contract and cannot be bypassed with characters
    // the denylist happened to omit.
    if let Some(ch) = name.chars().find(|c| {
        !c.is_ascii_lowercase() && !c.is_ascii_digit() && *c != '_' && *c != '-'
    }) {
        return Err(Error::Validation(format!(
            "username contains character {ch:?} which is not a lowercase letter, digit, '_', or '-': {name:?}"
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

#[cfg(test)]
mod tests {
    use super::*;

    fn is_invalid(r: &Result<()>) -> bool {
        matches!(r, Err(Error::Validation(_)))
    }

    // ---- happy path ----

    #[test]
    fn accepts_simple_username() {
        assert!(validate_username("alice").is_ok());
        assert!(validate_username("a_b-1").is_ok());
        assert!(validate_username("_deploy").is_ok());
        assert!(validate_username("svc-1").is_ok());
        assert!(validate_username("svc$").is_err()); // '$' forbidden by denylist
        assert!(validate_username("a.b").is_err()); // dot NOT in allowlist
    }

    // ---- negative cases from the audit ----

    #[test]
    fn rejects_empty() {
        assert!(is_invalid(&validate_username("")));
    }

    #[test]
    fn rejects_too_long() {
        let long = "a".repeat(33);
        assert!(is_invalid(&validate_username(&long)));
    }

    #[test]
    fn rejects_leading_digit() {
        // Must start with lowercase letter or underscore.
        assert!(is_invalid(&validate_username("1alice")));
        assert!(is_invalid(&validate_username("9bob")));
    }

    #[test]
    fn rejects_leading_hyphen() {
        // A leading hyphen is parsed as an option by useradd/usermod/userdel,
        // so even though '-' is in the allowed charset, the start-char rule
        // (lowercase or underscore only) rejects it.
        assert!(is_invalid(&validate_username("-alice")));
    }

    #[test]
    fn rejects_at_sign() {
        // '@' survives the denylist-by-doc but is a classic injection char for
        // passwd/group/cron entries.
        assert!(is_invalid(&validate_username("ali@ce")));
    }

    #[test]
    fn rejects_plus_sign() {
        assert!(is_invalid(&validate_username("ali+ce")));
    }

    #[test]
    fn rejects_non_ascii_letters() {
        // The allowlist restricts usernames to ASCII lowercase letters,
        // digits, '_', '-', '$'. Non-ASCII letters like 'é' are rejected
        // anywhere in the name (not just as the first char). Previously the
        // denylist let "andré" pass, contradicting the doc; the allowlist fix
        // closes that gap.
        assert!(is_invalid(&validate_username("andr\u{e9}"))); // "andré"
        assert!(is_invalid(&validate_username("Ωmega")));
    }

    #[test]
    fn rejects_shell_metacharacters() {
        for bad in ["alice;rm -rf /", "alice$HOME", "alice`id`", "alice|cat"] {
            assert!(is_invalid(&validate_username(bad)), "rejected {bad:?}");
        }
    }

    #[test]
    fn rejects_path_and_colon() {
        // ':' delimits passwd/group fields; '/' is a path separator.
        assert!(is_invalid(&validate_username("a/b")));
        assert!(is_invalid(&validate_username("a:b")));
    }

    // ---- reserved names ----

    #[test]
    fn rejects_reserved_names() {
        for reserved in ["root", "nobody", "daemon", "bin", "sys", "adm"] {
            assert!(is_invalid(&validate_username(reserved)), "rejected {reserved:?}");
        }
    }

    // ---- allowlist now closes the former denylist gaps ----

    #[test]
    fn allowlist_rejects_dot_in_name() {
        // '.' was the canonical denylist gap (not in FORBIDDEN_USERNAME_CHARS)
        // and let "a.b" pass into useradd/sudoers-d filenames. The allowlist
        // fix rejects it.
        assert!(is_invalid(&validate_username("a.b")));
    }
}
