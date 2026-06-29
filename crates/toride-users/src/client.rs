//! High-level client facade composing all user management subsystems.
//!
//! [`UsersClient`] is the main entry point for user management operations.
//! It resolves system paths and provides accessor methods for each subsystem.

use crate::Result;
use crate::paths::UserPaths;

// ---------------------------------------------------------------------------
// UsersClient
// ---------------------------------------------------------------------------

/// High-level user management client.
///
/// Owns system paths and provides access to user, group, sudo, PAM, TOTP,
/// password, and doctor subsystems.
///
/// # Construction
///
/// - [`UsersClient::new`] -- production defaults pointing at `/etc`.
/// - [`UsersClient::with_paths`] -- custom paths (useful for testing).
///
/// # Example
///
/// ```rust,no_run
/// use toride_users::client::UsersClient;
///
/// let client = UsersClient::new();
/// let exists = client.user().exists("deployer").unwrap();
/// ```
pub struct UsersClient {
    paths: UserPaths,
}

impl UsersClient {
    /// Create a client with production defaults.
    ///
    /// Uses standard `/etc` paths.
    #[must_use]
    pub fn new() -> Self {
        Self {
            paths: UserPaths::new(),
        }
    }

    /// Create a client with custom paths.
    ///
    /// Useful for testing against a temporary directory tree.
    #[must_use]
    pub fn with_paths(paths: UserPaths) -> Self {
        Self { paths }
    }

    /// Returns a reference to the system paths.
    #[must_use]
    pub fn paths(&self) -> &UserPaths {
        &self.paths
    }

    /// User account management operations.
    #[must_use]
    pub fn user(&self) -> UserOps<'_> {
        UserOps { paths: &self.paths }
    }

    /// Group management operations.
    #[must_use]
    pub fn group(&self) -> GroupOps<'_> {
        GroupOps { paths: &self.paths }
    }

    /// Sudoers management operations.
    #[must_use]
    pub fn sudo(&self) -> SudoOps<'_> {
        SudoOps { paths: &self.paths }
    }

    /// PAM configuration operations.
    #[must_use]
    pub fn pam(&self) -> PamOps<'_> {
        PamOps { paths: &self.paths }
    }

    /// TOTP/2FA enrollment operations.
    #[must_use]
    pub fn totp(&self) -> TotpOps<'_> {
        TotpOps { paths: &self.paths }
    }

    /// Password policy operations.
    #[must_use]
    pub fn password(&self) -> PasswordOps<'_> {
        PasswordOps { paths: &self.paths }
    }
}

impl Default for UsersClient {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Subsystem operation handles
// ---------------------------------------------------------------------------

/// User account operations.
pub struct UserOps<'a> {
    paths: &'a UserPaths,
}

impl UserOps<'_> {
    /// Check if a user exists.
    pub fn exists(&self, username: &str) -> Result<bool> {
        crate::user::user_exists(&self.paths.passwd, username)
    }

    /// Get the UID of a user.
    pub fn uid(&self, username: &str) -> Result<u32> {
        crate::user::get_uid(&self.paths.passwd, username)
    }

    /// Get the login shell of a user.
    pub fn get_shell(&self, username: &str) -> Result<String> {
        crate::user::get_shell(&self.paths.passwd, username)
    }

    /// Create a new user account.
    pub fn create(
        &self,
        username: &str,
        shell: &str,
        groups: &[String],
        home_dir: Option<&str>,
    ) -> Result<()> {
        crate::user::create_user(username, shell, groups, home_dir)
    }

    /// Delete a user account.
    pub fn delete(&self, username: &str, remove_home: bool) -> Result<()> {
        crate::user::delete_user(username, remove_home)
    }

    /// Modify a user account.
    pub fn modify(
        &self,
        username: &str,
        shell: Option<&str>,
        groups: Option<&[String]>,
        append_groups: Option<&[String]>,
    ) -> Result<()> {
        crate::user::modify_user(username, shell, groups, append_groups)
    }
}

/// Group management operations.
pub struct GroupOps<'a> {
    paths: &'a UserPaths,
}

impl GroupOps<'_> {
    /// Check if a group exists.
    pub fn exists(&self, name: &str) -> Result<bool> {
        crate::group::group_exists(&self.paths.group, name)
    }

    /// Create a new group.
    pub fn create(&self, name: &str, system: bool) -> Result<()> {
        crate::group::create_group(name, system)
    }

    /// Delete a group.
    pub fn delete(&self, name: &str) -> Result<()> {
        crate::group::delete_group(name)
    }

    /// Add a user to a group.
    pub fn add_user(&self, username: &str, group: &str) -> Result<()> {
        crate::group::add_user_to_group(username, group)
    }

    /// Remove a user from a group.
    pub fn remove_user(&self, username: &str, group: &str) -> Result<()> {
        crate::group::remove_user_from_group(username, group)
    }
}

/// Sudoers management operations.
pub struct SudoOps<'a> {
    paths: &'a UserPaths,
}

impl SudoOps<'_> {
    /// Check if a user has sudo access.
    pub fn has_sudo(&self, username: &str) -> Result<bool> {
        crate::sudo::has_sudo(self.paths, username)
    }

    /// Grant sudo access.
    pub fn grant(&self, username: &str, nopasswd: bool) -> Result<()> {
        crate::sudo::grant_sudo(self.paths, username, nopasswd)
    }

    /// Revoke sudo access.
    pub fn revoke(&self, username: &str) -> Result<()> {
        crate::sudo::revoke_sudo(self.paths, username)
    }
}

/// PAM configuration operations.
pub struct PamOps<'a> {
    paths: &'a UserPaths,
}

impl PamOps<'_> {
    /// Check if TOTP is enabled for a PAM service.
    pub fn is_totp_enabled(&self, service: &str) -> Result<bool> {
        crate::pam::is_totp_enabled(self.paths, service)
    }

    /// Enable TOTP for a PAM service.
    pub fn enable_totp(&self, service: &str) -> Result<()> {
        crate::pam::enable_totp_for_service(self.paths, service)
    }

    /// Disable TOTP for a PAM service.
    pub fn disable_totp(&self, service: &str) -> Result<()> {
        crate::pam::disable_totp_for_service(self.paths, service)
    }
}

/// TOTP/2FA enrollment operations.
pub struct TotpOps<'a> {
    paths: &'a UserPaths,
}

impl TotpOps<'_> {
    /// Check if TOTP is configured for a user.
    pub fn is_configured(&self, username: &str) -> Result<bool> {
        crate::totp::is_totp_configured(self.paths, username)
    }

    /// Enroll a user in TOTP.
    pub fn enroll(&self, username: &str) -> Result<String> {
        crate::totp::enroll_totp(self.paths, username)
    }

    /// Remove TOTP for a user.
    pub fn remove(&self, username: &str) -> Result<()> {
        crate::totp::remove_totp(self.paths, username)
    }
}

/// Password policy operations.
pub struct PasswordOps<'a> {
    paths: &'a UserPaths,
}

impl PasswordOps<'_> {
    /// Check if an account is locked.
    pub fn is_locked(&self, username: &str) -> Result<bool> {
        crate::password::is_account_locked(&self.paths.shadow, username)
    }

    /// Check if a user has an empty password.
    pub fn has_empty_password(&self, username: &str) -> Result<bool> {
        crate::password::has_empty_password(&self.paths.shadow, username)
    }

    /// Lock an account.
    pub fn lock(&self, username: &str) -> Result<()> {
        crate::password::lock_account(username)
    }

    /// Unlock an account.
    pub fn unlock(&self, username: &str) -> Result<()> {
        crate::password::unlock_account(username)
    }

    /// Apply a password policy.
    pub fn apply_policy(&self, username: &str, policy: &crate::spec::PasswordPolicy) -> Result<()> {
        crate::password::apply_password_policy(username, policy)
    }
}
