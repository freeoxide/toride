//! High-level client facade composing all user management subsystems.
//!
//! [`UsersClient`](crate::client::UsersClient) is the main entry point for user management operations.
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
/// - [`UsersClient::with_dry_run`] -- log-only mode for the mutating
///   operations.
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
    dry_run: bool,
}

/// Log the intended action and report that the caller must no-op, for the
/// Ops handles when the client runs in dry-run mode.
fn dry_run_noop(dry_run: bool, action: &str) -> bool {
    if dry_run {
        tracing::info!(action, "users: dry-run; skipping mutation");
        true
    } else {
        false
    }
}

impl UsersClient {
    /// Create a client with production defaults.
    ///
    /// Uses standard `/etc` paths.
    #[must_use]
    pub fn new() -> Self {
        Self {
            paths: UserPaths::new(),
            dry_run: false,
        }
    }

    /// Create a client with custom paths.
    ///
    /// Useful for testing against a temporary directory tree.
    #[must_use]
    pub fn with_paths(paths: UserPaths) -> Self {
        Self {
            paths,
            dry_run: false,
        }
    }

    /// Set dry-run mode: every mutating operation on this client logs the
    /// intended action at `info` level and returns `Ok(())` without
    /// executing it (no `useradd`/`visudo`/`chage` spawns, no PAM or sudoers
    /// writes). Read-only queries run normally. TOTP enrollment is the one
    /// exception: it cannot produce its secret without enrolling, so it
    /// returns an error in dry-run mode.
    #[must_use]
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Returns whether this client is in dry-run mode.
    #[must_use]
    pub fn dry_run(&self) -> bool {
        self.dry_run
    }

    /// Toggle dry-run mode on an existing client.
    pub fn set_dry_run(&mut self, dry_run: bool) {
        self.dry_run = dry_run;
    }

    /// Returns a reference to the system paths.
    #[must_use]
    pub fn paths(&self) -> &UserPaths {
        &self.paths
    }

    /// User account management operations.
    #[must_use]
    pub fn user(&self) -> UserOps<'_> {
        UserOps {
            paths: &self.paths,
            dry_run: self.dry_run,
        }
    }

    /// Group management operations.
    #[must_use]
    pub fn group(&self) -> GroupOps<'_> {
        GroupOps {
            paths: &self.paths,
            dry_run: self.dry_run,
        }
    }

    /// Sudoers management operations.
    #[must_use]
    pub fn sudo(&self) -> SudoOps<'_> {
        SudoOps {
            paths: &self.paths,
            dry_run: self.dry_run,
        }
    }

    /// PAM configuration operations.
    #[must_use]
    pub fn pam(&self) -> PamOps<'_> {
        PamOps {
            paths: &self.paths,
            dry_run: self.dry_run,
        }
    }

    /// TOTP/2FA enrollment operations.
    #[must_use]
    pub fn totp(&self) -> TotpOps<'_> {
        TotpOps {
            paths: &self.paths,
            dry_run: self.dry_run,
        }
    }

    /// Password policy operations.
    #[must_use]
    pub fn password(&self) -> PasswordOps<'_> {
        PasswordOps {
            paths: &self.paths,
            dry_run: self.dry_run,
        }
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
    dry_run: bool,
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
        if dry_run_noop(self.dry_run, "create user") {
            return Ok(());
        }
        crate::user::create_user(username, shell, groups, home_dir)
    }

    /// Delete a user account.
    pub fn delete(&self, username: &str, remove_home: bool) -> Result<()> {
        if dry_run_noop(self.dry_run, "delete user") {
            return Ok(());
        }
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
        if dry_run_noop(self.dry_run, "modify user") {
            return Ok(());
        }
        crate::user::modify_user(username, shell, groups, append_groups)
    }
}

/// Group management operations.
pub struct GroupOps<'a> {
    paths: &'a UserPaths,
    dry_run: bool,
}

impl GroupOps<'_> {
    /// Check if a group exists.
    pub fn exists(&self, name: &str) -> Result<bool> {
        crate::group::group_exists(&self.paths.group, name)
    }

    /// Create a new group.
    pub fn create(&self, name: &str, system: bool) -> Result<()> {
        if dry_run_noop(self.dry_run, "create group") {
            return Ok(());
        }
        crate::group::create_group(name, system)
    }

    /// Delete a group.
    pub fn delete(&self, name: &str) -> Result<()> {
        if dry_run_noop(self.dry_run, "delete group") {
            return Ok(());
        }
        crate::group::delete_group(name)
    }

    /// Add a user to a group.
    pub fn add_user(&self, username: &str, group: &str) -> Result<()> {
        if dry_run_noop(self.dry_run, "add user to group") {
            return Ok(());
        }
        crate::group::add_user_to_group(username, group)
    }

    /// Remove a user from a group.
    pub fn remove_user(&self, username: &str, group: &str) -> Result<()> {
        if dry_run_noop(self.dry_run, "remove user from group") {
            return Ok(());
        }
        crate::group::remove_user_from_group(username, group)
    }
}

/// Sudoers management operations.
pub struct SudoOps<'a> {
    paths: &'a UserPaths,
    dry_run: bool,
}

impl SudoOps<'_> {
    /// Check if a user has sudo access.
    pub fn has_sudo(&self, username: &str) -> Result<bool> {
        crate::sudo::has_sudo(self.paths, username)
    }

    /// Grant sudo access.
    pub fn grant(&self, username: &str, nopasswd: bool) -> Result<()> {
        if dry_run_noop(self.dry_run, "grant sudo") {
            return Ok(());
        }
        crate::sudo::grant_sudo(self.paths, username, nopasswd)
    }

    /// Revoke sudo access.
    pub fn revoke(&self, username: &str) -> Result<()> {
        if dry_run_noop(self.dry_run, "revoke sudo") {
            return Ok(());
        }
        crate::sudo::revoke_sudo(self.paths, username)
    }
}

/// PAM configuration operations.
pub struct PamOps<'a> {
    paths: &'a UserPaths,
    dry_run: bool,
}

impl PamOps<'_> {
    /// Check if TOTP is enabled for a PAM service.
    pub fn is_totp_enabled(&self, service: &str) -> Result<bool> {
        crate::pam::is_totp_enabled(self.paths, service)
    }

    /// Enable TOTP for a PAM service.
    pub fn enable_totp(&self, service: &str) -> Result<()> {
        if dry_run_noop(self.dry_run, "enable TOTP in PAM") {
            return Ok(());
        }
        crate::pam::enable_totp_for_service(self.paths, service)
    }

    /// Disable TOTP for a PAM service.
    pub fn disable_totp(&self, service: &str) -> Result<()> {
        if dry_run_noop(self.dry_run, "disable TOTP in PAM") {
            return Ok(());
        }
        crate::pam::disable_totp_for_service(self.paths, service)
    }
}

/// TOTP/2FA enrollment operations.
pub struct TotpOps<'a> {
    paths: &'a UserPaths,
    dry_run: bool,
}

impl TotpOps<'_> {
    /// Check if TOTP is configured for a user.
    pub fn is_configured(&self, username: &str) -> Result<bool> {
        crate::totp::is_totp_configured(self.paths, username)
    }

    /// Enroll a user in TOTP.
    ///
    /// Returns the `google-authenticator` output (TOTP seed + scratch codes)
    /// wrapped in a [`crate::totp::TotpSecret`], which redacts on `Debug` and
    /// zeroizes on drop. Callers surface it to the operator once via `Display`
    /// or [`crate::totp::TotpSecret::expose_secret`]; never log it raw.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Other`] in dry-run mode: enrollment cannot be
    /// previewed, because the secret only exists once the enrollment ran.
    pub fn enroll(&self, username: &str) -> Result<crate::totp::TotpSecret> {
        if self.dry_run {
            return Err(crate::Error::Other(format!(
                "TOTP enrollment cannot be previewed in dry-run mode; it must run \
                 google-authenticator to produce the secret for {username}"
            )));
        }
        crate::totp::enroll_totp(self.paths, username)
    }

    /// Remove TOTP for a user.
    pub fn remove(&self, username: &str) -> Result<()> {
        if dry_run_noop(self.dry_run, "remove TOTP") {
            return Ok(());
        }
        crate::totp::remove_totp(self.paths, username)
    }
}

/// Password policy operations.
pub struct PasswordOps<'a> {
    paths: &'a UserPaths,
    dry_run: bool,
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
        if dry_run_noop(self.dry_run, "lock account") {
            return Ok(());
        }
        crate::password::lock_account(username)
    }

    /// Unlock an account.
    pub fn unlock(&self, username: &str) -> Result<()> {
        if dry_run_noop(self.dry_run, "unlock account") {
            return Ok(());
        }
        crate::password::unlock_account(username)
    }

    /// Apply a password policy.
    pub fn apply_policy(&self, username: &str, policy: &crate::spec::PasswordPolicy) -> Result<()> {
        if dry_run_noop(self.dry_run, "apply password policy") {
            return Ok(());
        }
        crate::password::apply_password_policy(username, policy)
    }
}

#[cfg(all(test, feature = "client"))]
mod tests {
    use super::*;

    fn temp_client() -> (tempfile::TempDir, UsersClient) {
        let dir = tempfile::tempdir().expect("temp dir");
        let paths = UserPaths::with_base(dir.path());
        std::fs::write(&paths.passwd, "root:x:0:0:root:/root:/bin/bash\n").expect("passwd seed");
        std::fs::write(&paths.group, "root:x:0:\n").expect("group seed");
        let client = UsersClient::with_paths(paths);
        (dir, client)
    }

    /// Dry-run must log and no-op every facade mutator: none of them may
    /// reach the underlying subsystem (which would error here, since the
    /// sandbox has no useradd/groupadd/gpasswd on PATH).
    #[test]
    fn dry_run_skips_every_facade_mutation() {
        let (_dir, client) = temp_client();
        let client = client.with_dry_run(true);
        assert!(client.dry_run());

        let policy = crate::spec::PasswordPolicy::default();
        client
            .user()
            .create("alice", "/bin/bash", &[], None)
            .expect("dry-run create must no-op");
        client.user().delete("alice", false).expect("no-op");
        client
            .user()
            .modify("alice", None, None, None)
            .expect("no-op");
        client.group().create("wheel-x", false).expect("no-op");
        client.group().delete("wheel-x").expect("no-op");
        client.group().add_user("alice", "wheel-x").expect("no-op");
        client
            .group()
            .remove_user("alice", "wheel-x")
            .expect("no-op");
        client.sudo().grant("alice", false).expect("no-op");
        client.sudo().revoke("alice").expect("no-op");
        client.pam().enable_totp("sshd").expect("no-op");
        client.pam().disable_totp("sshd").expect("no-op");
        client.totp().remove("alice").expect("no-op");
        client.password().lock("alice").expect("no-op");
        client.password().unlock("alice").expect("no-op");
        client
            .password()
            .apply_policy("alice", &policy)
            .expect("no-op");
    }

    /// Enrollment cannot be previewed: it must refuse in dry-run rather
    /// than pretend a secret exists.
    #[test]
    fn dry_run_enrollment_refuses_with_a_typed_error() {
        let (_dir, client) = temp_client();
        let client = client.with_dry_run(true);

        let err = client
            .totp()
            .enroll("alice")
            .expect_err("enrollment must refuse in dry-run");

        assert!(
            err.to_string().contains("cannot be previewed"),
            "got {err:?}"
        );
    }

    /// Read-only queries are untouched by dry-run.
    #[test]
    fn dry_run_leaves_read_only_queries_working() {
        let (_dir, client) = temp_client();
        let client = client.with_dry_run(true);

        assert!(!client.user().exists("alice").expect("query runs"));
        assert!(!client.group().exists("wheel-x").expect("query runs"));
        assert!(!client.sudo().has_sudo("alice").expect("query runs"));
    }
}
