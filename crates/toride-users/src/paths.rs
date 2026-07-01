//! System paths for user and access control configuration files.
//!
//! [`UserPaths`] resolves the standard Linux paths used by user management
//! tools: `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers`,
//! `/etc/sudoers.d/`, and `/etc/pam.d/`.

use std::path::{Path, PathBuf};

use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Safe-name validation for path components built from `&str`
// ---------------------------------------------------------------------------

/// Validate that `name` is safe to interpolate as a single path component
/// (e.g. a PAM service name or a sudoers drop-in filename).
///
/// Rejects everything that could escape the intended directory or be parsed
/// as a flag by a downstream tool:
///
/// - empty strings
/// - any path separator (`/`, `\`)
/// - parent-directory traversal (`..`)
/// - NUL bytes
/// - a leading `-` (option injection for argv consumers)
///
/// This is a denylist guard, not an allowlist; callers that need stricter
/// semantics (e.g. POSIX username characters) should layer their own check on
/// top.
///
/// # Errors
///
/// Returns [`Error::Validation`] when `name` is not a safe single path
/// component.
pub fn validate_path_component(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::Validation("path component must not be empty".into()));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(Error::Validation(format!(
            "path component must not contain a path separator: {name:?}"
        )));
    }
    if name == ".." {
        // A bare `..` component would escape the parent directory. (A name
        // like `..foo` or `foo..bar` is not a traversal and is allowed; the
        // separator check above already rejects embedded `..`/`/` fragments.)
        return Err(Error::Validation(format!(
            "path component must not be a parent-directory reference: {name:?}"
        )));
    }
    if name.contains('\0') {
        return Err(Error::Validation(format!(
            "path component must not contain a NUL byte: {name:?}"
        )));
    }
    if name.starts_with('-') {
        return Err(Error::Validation(format!(
            "path component must not start with a dash (option injection): {name:?}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// UserPaths
// ---------------------------------------------------------------------------

/// Resolved paths to OS-level user and access control configuration files.
///
/// All paths use standard Linux filesystem locations. The struct provides
/// convenience methods for constructing drop-in file paths under
/// `/etc/sudoers.d/` and `/etc/pam.d/`.
#[derive(Debug, Clone)]
pub struct UserPaths {
    /// `/etc/passwd` -- user account information.
    pub passwd: PathBuf,
    /// `/etc/shadow` -- shadowed password data (root-readable only).
    pub shadow: PathBuf,
    /// `/etc/group` -- group definitions.
    pub group: PathBuf,
    /// `/etc/gshadow` -- shadowed group password data.
    pub gshadow: PathBuf,
    /// `/etc/sudoers` -- main sudoers configuration file.
    pub sudoers: PathBuf,
    /// `/etc/sudoers.d/` -- sudoers drop-in directory.
    pub sudoers_d: PathBuf,
    /// `/etc/pam.d/` -- PAM service configuration directory.
    pub pam_d: PathBuf,
    /// `/etc/login.defs` -- shadow password suite configuration.
    pub login_defs: PathBuf,
    /// `/etc/security/` -- PAM module configuration directory.
    pub security_dir: PathBuf,
    /// `/etc/default/useradd` -- default values for `useradd`.
    pub useradd_defaults: PathBuf,
    /// `/etc/ssh/sshd_config` -- OpenSSH daemon configuration.
    ///
    /// Used by the doctor's root-login check. Lives outside `/etc` proper
    /// (under `/etc/ssh/`) but is plumbed through [`UserPaths`] so a custom
    /// base dir (e.g. for tests or chrooted operation) redirects the read.
    pub sshd_config: PathBuf,
}

impl UserPaths {
    /// Create a `UserPaths` pointing at the standard `/etc` locations.
    ///
    /// This constructor always succeeds; it does not verify that the files
    /// exist on disk. Use [`Self::verify`] to check existence.
    #[must_use]
    pub fn new() -> Self {
        let etc = PathBuf::from("/etc");
        Self {
            passwd: etc.join("passwd"),
            shadow: etc.join("shadow"),
            group: etc.join("group"),
            gshadow: etc.join("gshadow"),
            sudoers: etc.join("sudoers"),
            sudoers_d: etc.join("sudoers.d"),
            pam_d: etc.join("pam.d"),
            login_defs: etc.join("login.defs"),
            security_dir: etc.join("security"),
            useradd_defaults: etc.join("default").join("useradd"),
            sshd_config: etc.join("ssh").join("sshd_config"),
        }
    }

    /// Create a `UserPaths` rooted at an alternative base directory.
    ///
    /// Useful for testing against a chroot or temporary directory tree.
    ///
    /// `sshd_config` resolves to `<base>/ssh/sshd_config`, mirroring the
    /// `/etc/ssh/sshd_config` layout on a real system.
    #[must_use]
    pub fn with_base(base: &Path) -> Self {
        Self {
            passwd: base.join("passwd"),
            shadow: base.join("shadow"),
            group: base.join("group"),
            gshadow: base.join("gshadow"),
            sudoers: base.join("sudoers"),
            sudoers_d: base.join("sudoers.d"),
            pam_d: base.join("pam.d"),
            login_defs: base.join("login.defs"),
            security_dir: base.join("security"),
            useradd_defaults: base.join("default").join("useradd"),
            sshd_config: base.join("ssh").join("sshd_config"),
        }
    }

    /// Returns the path for a sudoers drop-in file under `/etc/sudoers.d/`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Validation`] if `name` is not a safe single path
    /// component (see [`validate_path_component`]). This prevents a caller
    /// from joining `../`-traversal, absolute paths, NUL bytes, or leading
    /// dashes onto `/etc/sudoers.d/`.
    pub fn sudoers_dropin(&self, name: &str) -> Result<PathBuf> {
        validate_path_component(name)?;
        Ok(self.sudoers_d.join(name))
    }

    /// Returns the path for a PAM service config under `/etc/pam.d/`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Validation`] if `service` is not a safe single path
    /// component (see [`validate_path_component`]). This prevents a caller
    /// from joining `../`-traversal, absolute paths, NUL bytes, or leading
    /// dashes onto `/etc/pam.d/`.
    pub fn pam_service(&self, service: &str) -> Result<PathBuf> {
        validate_path_component(service)?;
        Ok(self.pam_d.join(service))
    }

    /// Verify that the critical configuration files exist.
    ///
    /// Returns a list of missing file paths. If the list is empty, all
    /// critical files are present.
    pub fn verify(&self) -> Vec<PathBuf> {
        let critical = [&self.passwd, &self.group];
        critical
            .iter()
            .filter(|p| !p.exists())
            .map(|p| (*p).clone())
            .collect()
    }
}

impl Default for UserPaths {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pam_service_joins_safe_name() {
        let p = UserPaths::new();
        assert_eq!(
            p.pam_service("sshd").unwrap(),
            PathBuf::from("/etc/pam.d/sshd")
        );
    }

    #[test]
    fn sudoers_dropin_joins_safe_name() {
        let p = UserPaths::new();
        assert_eq!(
            p.sudoers_dropin("alice").unwrap(),
            PathBuf::from("/etc/sudoers.d/alice")
        );
    }

    #[test]
    fn validate_rejects_empty() {
        assert!(matches!(
            validate_path_component(""),
            Err(Error::Validation(_))
        ));
    }

    #[test]
    fn validate_rejects_unix_separator_traversal() {
        // A leading `/` makes an absolute path that escapes /etc/pam.d.
        assert!(validate_path_component("/etc/shadow").is_err());
        // An embedded `/` also escapes.
        assert!(validate_path_component("../shadow").is_err());
        assert!(validate_path_component("a/b").is_err());
    }

    #[test]
    fn validate_rejects_windows_separator() {
        assert!(validate_path_component("..\\shadow").is_err());
        assert!(validate_path_component("a\\b").is_err());
    }

    #[test]
    fn validate_rejects_parent_dir_token() {
        assert!(validate_path_component("..").is_err());
    }

    #[test]
    fn validate_rejects_nul_byte() {
        assert!(validate_path_component("ssh\0d").is_err());
        assert!(validate_path_component("\0").is_err());
    }

    #[test]
    fn validate_rejects_leading_dash() {
        // A leading dash is parsed as an option by argv consumers (chown,
        // useradd, ...). Reject it.
        assert!(validate_path_component("-x").is_err());
        assert!(validate_path_component("--help").is_err());
    }

    #[test]
    fn validate_accepts_unsafe_looking_but_safe_names() {
        // `..foo` and `foo..bar` are NOT traversal: they contain no separator
        // and are not the bare `..` component.
        assert!(validate_path_component("..foo").is_ok());
        assert!(validate_path_component("foo..bar").is_ok());
        assert!(validate_path_component("sshd").is_ok());
        assert!(validate_path_component("alice.bob").is_ok());
        assert!(validate_path_component("a_b-1").is_ok());
    }

    #[test]
    fn pam_service_rejects_traversal() {
        let p = UserPaths::new();
        // The joined path must NOT escape /etc/pam.d.
        let bad = p.pam_service("../shadow");
        assert!(bad.is_err());
        // And the rejection must be Validation, not a silent escape.
        assert!(matches!(bad, Err(Error::Validation(_))));
    }

    #[test]
    fn sudoers_dropin_rejects_traversal() {
        let p = UserPaths::new();
        let bad = p.sudoers_dropin("../sudoers");
        assert!(bad.is_err());
        assert!(matches!(bad, Err(Error::Validation(_))));
    }
}
