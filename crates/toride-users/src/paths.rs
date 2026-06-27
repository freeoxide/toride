//! System paths for user and access control configuration files.
//!
//! [`UserPaths`] resolves the standard Linux paths used by user management
//! tools: `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers`,
//! `/etc/sudoers.d/`, and `/etc/pam.d/`.

use std::path::PathBuf;

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
    pub fn with_base(base: PathBuf) -> Self {
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
    #[must_use]
    pub fn sudoers_dropin(&self, name: &str) -> PathBuf {
        self.sudoers_d.join(name)
    }

    /// Returns the path for a PAM service config under `/etc/pam.d/`.
    #[must_use]
    pub fn pam_service(&self, service: &str) -> PathBuf {
        self.pam_d.join(service)
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
