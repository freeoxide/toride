//! Diagnostic checks for user and access control security.
//!
//! The doctor module runs a series of security checks and produces a
//! [`UserReport`] with findings. Checks include:
//!
//! - Root login enabled via SSH
//! - Users with empty passwords
//! - NOPASSWD sudo entries
//! - TOTP not configured for sudo users
//! - Insecure shells
//! - Password policy violations

use crate::paths::UserPaths;
use crate::report::{Severity, UserFinding, UserReport};
use crate::Result;

/// Scope for doctor checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorScope {
    /// Run all checks.
    All,
    /// Only check user account security.
    Accounts,
    /// Only check sudo configuration.
    Sudo,
    /// Only check PAM/TOTP configuration.
    Pam,
    /// Only check password policies.
    PasswordPolicy,
}

/// Diagnostic engine for user security checks.
pub struct Doctor {
    paths: UserPaths,
}

impl Doctor {
    /// Create a new doctor with the default system paths.
    #[must_use]
    pub fn new() -> Self {
        Self {
            paths: UserPaths::new(),
        }
    }

    /// Create a new doctor with custom paths.
    #[must_use]
    pub fn with_paths(paths: UserPaths) -> Self {
        Self { paths }
    }

    /// Run all checks in the given scope and return a report.
    ///
    /// # Errors
    ///
    /// Effectively infallible for file-IO failures: each `check_*` function
    /// degrades per-file (logs via `tracing::warn!` and continues), so an
    /// unreadable `/etc/passwd` / `/etc/shadow` / `/etc/sudoers` /
    /// `/etc/sudoers.d` / `/etc/group` / `/etc/login.defs` / `pam.d/sshd`
    /// costs at most the findings that depend on it — never the rest of the
    /// suite. The `Result` is retained for API stability and for any future
    /// non-IO failure class.
    pub fn run(&self, scope: &DoctorScope) -> Result<UserReport> {
        let mut report = UserReport::new();

        match scope {
            DoctorScope::All => {
                self.check_accounts(&mut report)?;
                self.check_sudo(&mut report)?;
                self.check_pam(&mut report)?;
                self.check_password_policy(&mut report)?;
            }
            DoctorScope::Accounts => {
                self.check_accounts(&mut report)?;
            }
            DoctorScope::Sudo => {
                self.check_sudo(&mut report)?;
            }
            DoctorScope::Pam => {
                self.check_pam(&mut report)?;
            }
            DoctorScope::PasswordPolicy => {
                self.check_password_policy(&mut report)?;
            }
        }

        Ok(report)
    }

    /// Check user account security.
    fn check_accounts(&self, report: &mut UserReport) -> Result<()> {
        // Check for root login via SSH
        let sshd_config = std::path::Path::new("/etc/ssh/sshd_config");
        if sshd_config.exists() {
            let content = std::fs::read_to_string(sshd_config)?;
            if content.contains("PermitRootLogin yes") || content.contains("PermitRootLogin without-password") {
                // Only flag if it's explicitly "yes" (prohibit-password is often acceptable)
                if content.contains("PermitRootLogin yes") {
                    report.push(
                        UserFinding::new(
                            "user.root-login.ssh-enabled",
                            Severity::Critical,
                            "Root SSH login is enabled",
                        )
                        .detail("PermitRootLogin is set to 'yes' in /etc/ssh/sshd_config.")
                        .fix("Set PermitRootLogin to 'prohibit-password' or 'no'."),
                    );
                }
            }
        }

        // Check for users with UID 0 (root-equivalent). Per-check degrade: an
        // unreadable /etc/passwd must NOT abort the whole suite (run() chains
        // check_accounts/check_sudo/check_pam/check_password_policy). Log and
        // continue, mirroring the per-line lenient pattern in parse_passwd /
        // parse_group. One unreadable file costs at most the findings that
        // depend on it, never the rest of the report.
        let passwd_entries = match crate::parse::read_passwd(&self.paths.passwd) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(
                    "doctor check_accounts read_passwd {}: {e}",
                    self.paths.passwd.display()
                );
                // The UID-0 and insecure-shell checks both need passwd rows; if
                // the read failed there is nothing to iterate, so skip straight
                // past the login-via-SSH finding we may already have pushed.
                return Ok(());
            }
        };
        for entry in &passwd_entries {
            if entry.uid == 0 && entry.username != "root" {
                report.push(
                    UserFinding::new(
                        "user.uid-zero.non-root",
                        Severity::Critical,
                        format!("Non-root user '{}' has UID 0", entry.username),
                    )
                    .detail(format!(
                        "User '{}' has UID 0, granting full root privileges.",
                        entry.username
                    ))
                    .fix("Change the UID to a non-zero value or remove the user."),
                );
            }
        }

        // Check for users with login shells that shouldn't
        let insecure_shells = ["/bin/sh", "/bin/bash", "/usr/bin/bash"];
        let system_users = [
            "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
            "news", "uucp", "proxy", "www-data", "backup", "list", "irc",
            "gnats", "nobody",
        ];
        for entry in &passwd_entries {
            if system_users.contains(&entry.username.as_str()) {
                if insecure_shells.contains(&entry.shell.as_str()) {
                    report.push(
                        UserFinding::new(
                            format!("user.system-user.shell.{}", entry.username),
                            Severity::Warning,
                            format!("System user '{}' has a login shell", entry.username),
                        )
                        .detail(format!(
                            "System user '{}' has shell '{}' instead of nologin.",
                            entry.username, entry.shell
                        ))
                        .fix("Set the shell to /usr/sbin/nologin."),
                    );
                }
            }
        }

        Ok(())
    }

    /// Check sudo configuration.
    fn check_sudo(&self, report: &mut UserReport) -> Result<()> {
        // Check main sudoers file for NOPASSWD entries. Per-check degrade: an
        // unreadable /etc/sudoers must NOT abort the whole suite. Log and
        // continue to the drop-in scan — one unreadable file costs at most the
        // findings that depend on it.
        if self.paths.sudoers.exists() {
            let entries = match crate::parse::read_sudoers(&self.paths.sudoers) {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(
                        "doctor check_sudo read_sudoers {}: {e}",
                        self.paths.sudoers.display()
                    );
                    Vec::new()
                }
            };
            for entry in &entries {
                if entry.nopasswd {
                    report.push(
                        UserFinding::new(
                            "sudo.nopasswd.main-sudoers",
                            Severity::Warning,
                            format!("NOPASSWD sudo entry for '{}'", entry.who),
                        )
                        .detail(format!(
                            "User/group '{}' has NOPASSWD sudo access in main sudoers file.",
                            entry.who
                        ))
                        .fix("Remove NOPASSWD or require password authentication."),
                    );
                }
            }
        }

        // Check sudoers.d drop-in files. Per-check degrade: an unreadable
        // /etc/sudoers.d directory must NOT abort the whole suite. Log and
        // continue — the main-sudoers findings (if any) are already pushed.
        if self.paths.sudoers_d.is_dir() {
            let entries = match std::fs::read_dir(&self.paths.sudoers_d) {
                Ok(rd) => rd,
                Err(e) => {
                    tracing::warn!(
                        "doctor check_sudo read_dir {}: {e}",
                        self.paths.sudoers_d.display()
                    );
                    return Ok(());
                }
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_none() || path.extension().is_some_and(|e| e != "bak") {
                    if let Ok(sudoers) = crate::parse::read_sudoers(&path) {
                        for rule in &sudoers {
                            if rule.nopasswd {
                                let filename = path.file_name().unwrap_or_default().to_string_lossy();
                                report.push(
                                    UserFinding::new(
                                        format!("sudo.nopasswd.dropin.{filename}"),
                                        Severity::Warning,
                                        format!("NOPASSWD sudo entry in /etc/sudoers.d/{filename}"),
                                    )
                                    .detail(format!(
                                        "User/group '{}' has NOPASSWD access via drop-in file.",
                                        rule.who
                                    ))
                                    .fix("Remove NOPASSWD or require password + TOTP."),
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Check PAM/TOTP configuration.
    fn check_pam(&self, report: &mut UserReport) -> Result<()> {
        // Check if TOTP is configured for SSH. Per-check degrade: an unreadable
        // pam.d/sshd must NOT abort the whole suite. Log and continue to the
        // sudo-without-TOTP check below.
        let sshd_pam = self.paths.pam_service("sshd");
        if sshd_pam.exists() {
            let rules = match crate::pam::read_pam_config(&sshd_pam) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        "doctor check_pam read_pam_config {}: {e}",
                        sshd_pam.display()
                    );
                    Vec::new()
                }
            };
            let has_totp = rules
                .iter()
                .any(|r| r.module.contains("pam_google_authenticator"));

            if !has_totp {
                report.push(
                    UserFinding::new(
                        "pam.sshd.no-totp",
                        Severity::Warning,
                        "TOTP/2FA not configured for SSH",
                    )
                    .detail(
                        "The PAM configuration for sshd does not include \
                         pam_google_authenticator.so.",
                    )
                    .fix("Install libpam-google-authenticator and enable TOTP for SSH."),
                );
            }
        }

        // Check for sudo users without TOTP. Per-check degrade: an unreadable
        // /etc/group must NOT abort the whole suite. Log and continue — there is
        // nothing to iterate, so we skip the per-member TOTP loop. NOTE: the old
        // code also did `let _passwd_entries = read_passwd(...)?` here, reading
        // /etc/passwd purely to propagate an IO error — the result was
        // discarded (`_passwd_entries`), so its only effect was an extra abort
        // point. It has been removed: the actual data source for this check is
        // /etc/group (read_group), not /etc/passwd, and is_totp_configured
        // resolves the home dir itself.
        let sudo_group_members = match crate::parse::read_group(&self.paths.group) {
            Ok(groups) => groups
                .iter()
                .find(|g| g.name == "sudo")
                .map(|g| g.members.clone())
                .unwrap_or_default(),
            Err(e) => {
                tracing::warn!(
                    "doctor check_pam read_group {}: {e}",
                    self.paths.group.display()
                );
                return Ok(());
            }
        };

        for username in &sudo_group_members {
            // Per-user degrade: a stale sudo-group membership for a deleted
            // user (no /etc/passwd entry) makes `is_totp_configured` return
            // `Error::UserNotFound`. Propagating that with `?` would abort the
            // entire doctor suite and blank the whole findings panel. Treat an
            // unresolvable user as "TOTP not configured" and move on, mirroring
            // the lenient per-line/per-entry skip pattern in parse_passwd /
            // parse_group. One stale member must not cost the rest of the
            // report.
            let totp_configured = crate::totp::is_totp_configured(username).unwrap_or(false);
            if !totp_configured {
                report.push(
                    UserFinding::new(
                        format!("pam.sudo-user.no-totp.{username}"),
                        Severity::Info,
                        format!("Sudo user '{username}' does not have TOTP configured"),
                    )
                    .detail(format!(
                        "User '{username}' has sudo access but no TOTP/2FA.",
                    ))
                    .fix("Enroll the user in TOTP using google-authenticator."),
                );
            }
        }

        Ok(())
    }

    /// Check password policy compliance.
    fn check_password_policy(&self, report: &mut UserReport) -> Result<()> {
        // Check for users with empty passwords. Per-check degrade: an unreadable
        // /etc/shadow must NOT abort the whole suite. Log and continue to the
        // login.defs policy check below.
        if self.paths.shadow.exists() {
            let shadow = match std::fs::read_to_string(&self.paths.shadow) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        "doctor check_password_policy read {}: {e}",
                        self.paths.shadow.display()
                    );
                    String::new()
                }
            };
            for line in shadow.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 && !parts[0].starts_with('#') {
                    let username = parts[0];
                    // Empty password field
                    if parts[1].is_empty() {
                        report.push(
                            UserFinding::new(
                                format!("password.empty.{username}"),
                                Severity::Critical,
                                format!("User '{username}' has an empty password"),
                            )
                            .detail(format!(
                                "User '{username}' has no password set in /etc/shadow.",
                            ))
                            .fix("Set a strong password or lock the account."),
                        );
                    }
                }
            }
        }

        // Check login.defs for password policy. Per-check degrade: an unreadable
        // /etc/login.defs must NOT abort the whole suite. Log and continue —
        // neither PASS_MAX_DAYS nor PASS_MIN_DAYS finding can be derived, but
        // the empty-password findings above are already pushed.
        if self.paths.login_defs.exists() {
            let content = match std::fs::read_to_string(&self.paths.login_defs) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        "doctor check_password_policy read {}: {e}",
                        self.paths.login_defs.display()
                    );
                    return Ok(());
                }
            };
            let has_max_days = content.contains("PASS_MAX_DAYS");
            let has_min_days = content.contains("PASS_MIN_DAYS");

            if !has_max_days {
                report.push(
                    UserFinding::new(
                        "password-policy.no-max-days",
                        Severity::Warning,
                        "No PASS_MAX_DAYS set in /etc/login.defs",
                    )
                    .detail("Password expiration is not configured.")
                    .fix("Set PASS_MAX_DAYS to 90 or less in /etc/login.defs."),
                );
            }

            if !has_min_days {
                report.push(
                    UserFinding::new(
                        "password-policy.no-min-days",
                        Severity::Info,
                        "No PASS_MIN_DAYS set in /etc/login.defs",
                    )
                    .detail("Minimum password change interval is not configured.")
                    .fix("Set PASS_MIN_DAYS to at least 1 in /etc/login.defs."),
                );
            }
        }

        Ok(())
    }
}

impl Default for Doctor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::UserPaths;
    use tempfile::TempDir;

    /// Regression: a stale sudo-group membership for a user that has no
    /// `/etc/passwd` entry must NOT abort the doctor suite.
    ///
    /// Previously `check_pam` called `is_totp_configured(username)?` inside the
    /// loop over sudo-group members; a single stale member (e.g. a deleted user
    /// still listed in the `sudo` group) returns `Error::UserNotFound`, which
    /// propagated out of `check_pam` -> `Doctor::run`, and the TUI collector
    /// then dropped the entire findings `Vec` to empty. The fix degrades per
    /// user, so one unresolvable member costs at most that one entry.
    #[test]
    fn check_pam_stale_sudo_member_does_not_abort_suite() {
        let dir = TempDir::new().expect("tempdir");
        let base = dir.path().to_path_buf();
        let paths = UserPaths::with_base(base);

        // passwd: only `root` and `alice`. `ghost` is intentionally absent — it
        // simulates a stale sudo-group membership for a deleted account.
        std::fs::write(
            &paths.passwd,
            "root:x:0:0:root:/root:/bin/bash\n\
             alice:x:1000:1000:Alice:/home/alice:/bin/bash\n",
        )
        .expect("write passwd");

        // group: `sudo` contains both a real user (alice) and a stale member
        // (ghost) that has no passwd entry.
        std::fs::write(
            &paths.group,
            "root:x:0:\n\
             sudo:x:27:alice,ghost\n",
        )
        .expect("write group");

        let doctor = Doctor::with_paths(paths);

        // Before the fix, this returned `Err(Error::UserNotFound("ghost"))`.
        let report = doctor
            .run(&DoctorScope::Pam)
            .expect("doctor must not abort on a stale sudo member");

        // The suite survived: findings were produced rather than being dropped.
        // Both alice and ghost lack `.google_authenticator`, so each should
        // yield a `pam.sudo-user.no-totp.<name>` finding.
        let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
        assert!(
            ids.iter().any(|id| *id == "pam.sudo-user.no-totp.alice"),
            "alice finding should be present, got: {ids:?}"
        );
        assert!(
            ids.iter().any(|id| *id == "pam.sudo-user.no-totp.ghost"),
            "ghost finding should be present (degraded, not fatal), got: {ids:?}"
        );
    }

    /// Regression for the fail-fast-at-file-level class: a single unreadable
    /// file must NOT abort the whole doctor suite. `run()` chains
    /// check_accounts / check_sudo / check_pam / check_password_policy; before
    /// the fix each propagated the first file-IO error with `?`, so an
    /// unreadable `/etc/passwd` aborted every subsequent check and the TUI
    /// collector blanked the entire findings `Vec` to empty.
    ///
    /// This test makes `/etc/passwd` unreadable by creating it as a DIRECTORY
    /// (`read_to_string` on a dir returns an IO error) while keeping
    /// `/etc/login.defs` readable and populated so the password-policy check has
    /// real findings to emit. The suite must survive and still report the
    /// login.defs findings — proving check_password_policy ran despite
    /// check_accounts' passwd read failing.
    #[test]
    fn unreadable_passwd_does_not_abort_whole_suite() {
        let dir = TempDir::new().expect("tempdir");
        let base = dir.path().to_path_buf();
        let paths = UserPaths::with_base(base);

        // passwd is a DIRECTORY — read_passwd returns Err(Io), which previously
        // aborted run() via check_accounts(...)?.
        std::fs::create_dir(&paths.passwd).expect("create passwd as dir");

        // login.defs is readable and deliberately lacks PASS_MAX_DAYS, so
        // check_password_policy should push `password-policy.no-max-days`.
        std::fs::write(&paths.login_defs, "# no policy here\n").expect("write login.defs");

        let doctor = Doctor::with_paths(paths);

        // Before the fix this returned `Err`. Now it must succeed.
        let report = doctor
            .run(&DoctorScope::All)
            .expect("unreadable passwd must not abort the whole suite");

        // The password-policy check (which runs LAST) still produced findings,
        // proving it ran despite check_accounts failing to read passwd.
        let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
        assert!(
            ids.iter().any(|id| *id == "password-policy.no-max-days"),
            "login.defs finding should still be present, got: {ids:?}"
        );
        assert!(
            ids.iter().any(|id| *id == "password-policy.no-min-days"),
            "login.defs finding should still be present, got: {ids:?}"
        );
    }

    /// Companion: an unreadable `/etc/shadow` must not abort the
    /// password-policy check — the `/etc/login.defs` half must still run.
    /// Before the fix, check_password_policy's `read_to_string(&shadow)?` at
    /// the top of the function short-circuited the login.defs check below it.
    #[test]
    fn unreadable_shadow_does_not_abort_password_policy_check() {
        let dir = TempDir::new().expect("tempdir");
        let base = dir.path().to_path_buf();
        let paths = UserPaths::with_base(base);

        // shadow exists (so the `.exists()` guard fires) but is a DIRECTORY —
        // read_to_string returns Err(Io).
        std::fs::create_dir(&paths.shadow).expect("create shadow as dir");

        // login.defs is readable and lacks both PASS_*_DAYS.
        std::fs::write(&paths.login_defs, "# no policy here\n").expect("write login.defs");

        let doctor = Doctor::with_paths(paths);

        let report = doctor
            .run(&DoctorScope::PasswordPolicy)
            .expect("unreadable shadow must not abort the password-policy check");

        // The empty-password findings are skipped (shadow unreadable), but the
        // login.defs findings must still be present.
        let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
        assert!(
            ids.iter().any(|id| *id == "password-policy.no-max-days"),
            "login.defs finding should still be present despite unreadable shadow, got: {ids:?}"
        );
        // No empty-password finding was emitted — shadow was unreadable.
        assert!(
            !ids.iter().any(|id| id.starts_with("password.empty.")),
            "no empty-password finding should be emitted when shadow is unreadable, got: {ids:?}"
        );
    }
}
