//! Typed specification module for user accounts and password policies.
//!
//! Defines [`UserSpec`] for describing a desired user state, and
//! [`PasswordPolicy`] for password aging and complexity rules.

// ---------------------------------------------------------------------------
// PasswordPolicy
// ---------------------------------------------------------------------------

/// Password aging and complexity policy.
///
/// Maps to fields in `/etc/login.defs` and the `chage` command.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PasswordPolicy {
    /// Maximum number of days a password is valid (`PASS_MAX_DAYS`).
    pub max_days: u64,
    /// Minimum number of days between password changes (`PASS_MIN_DAYS`).
    pub min_days: u64,
    /// Number of days before expiration to issue a warning (`PASS_WARN_AGE`).
    pub warn_days: u64,
    /// Required password complexity level.
    pub complexity: Complexity,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            max_days: 90,
            min_days: 1,
            warn_days: 7,
            complexity: Complexity::default(),
        }
    }
}

/// Password complexity requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Complexity {
    /// No complexity requirements.
    None,
    /// Minimum length only.
    #[default]
    Standard,
    /// Require uppercase, lowercase, digit, and special character.
    Strong,
}

// ---------------------------------------------------------------------------
// UserSpec
// ---------------------------------------------------------------------------

/// Complete specification for a user account.
///
/// Describes the desired state of a user, including shell, group memberships,
/// sudo access, TOTP enrollment, and password policy.
///
/// # Example
///
/// ```rust
/// use toride_users::spec::{UserSpec, PasswordPolicy, Complexity};
///
/// let spec = UserSpec {
///     username: "deployer".to_owned(),
///     shell: "/usr/bin/bash".to_owned(),
///     groups: vec!["sudo".to_owned(), "docker".to_owned()],
///     sudo_access: true,
///     totp_enabled: false,
///     password_policy: PasswordPolicy::default(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UserSpec {
    /// Login name of the user.
    pub username: String,
    /// Login shell (e.g. `/usr/bin/bash`, `/usr/sbin/nologin`).
    pub shell: String,
    /// Supplementary groups the user should belong to.
    pub groups: Vec<String>,
    /// Whether the user should have sudo access.
    pub sudo_access: bool,
    /// Whether TOTP/2FA should be enabled for this user.
    pub totp_enabled: bool,
    /// Password aging and complexity policy for this user.
    pub password_policy: PasswordPolicy,
}

impl UserSpec {
    /// Create a minimal `UserSpec` with sensible defaults.
    ///
    /// Defaults:
    /// - shell: `/usr/bin/bash`
    /// - groups: empty
    /// - `sudo_access`: `false`
    /// - `totp_enabled`: `false`
    /// - `password_policy`: [`PasswordPolicy::default`]
    #[must_use]
    pub fn new(username: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            shell: "/usr/bin/bash".to_owned(),
            groups: Vec::new(),
            sudo_access: false,
            totp_enabled: false,
            password_policy: PasswordPolicy::default(),
        }
    }

    /// Set the login shell.
    #[must_use]
    pub fn with_shell(mut self, shell: impl Into<String>) -> Self {
        self.shell = shell.into();
        self
    }

    /// Set supplementary groups.
    #[must_use]
    pub fn with_groups(mut self, groups: Vec<String>) -> Self {
        self.groups = groups;
        self
    }

    /// Enable or disable sudo access.
    #[must_use]
    pub fn with_sudo(mut self, sudo_access: bool) -> Self {
        self.sudo_access = sudo_access;
        self
    }

    /// Enable or disable TOTP/2FA.
    #[must_use]
    pub fn with_totp(mut self, totp_enabled: bool) -> Self {
        self.totp_enabled = totp_enabled;
        self
    }

    /// Set the password policy.
    #[must_use]
    pub fn with_password_policy(mut self, policy: PasswordPolicy) -> Self {
        self.password_policy = policy;
        self
    }

    /// Validate this spec using the rules in [`crate::validate`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Validation`] if any field is invalid.
    pub fn validate(&self) -> crate::Result<()> {
        crate::validate::validate_spec(self)
    }
}
