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

use crate::Result;
use crate::paths::UserPaths;
use crate::report::{Severity, UserFinding, UserReport};

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
                self.check_accounts(&mut report);
                self.check_sudo(&mut report);
                self.check_pam(&mut report);
                self.check_password_policy(&mut report);
            }
            DoctorScope::Accounts => {
                self.check_accounts(&mut report);
            }
            DoctorScope::Sudo => {
                self.check_sudo(&mut report);
            }
            DoctorScope::Pam => {
                self.check_pam(&mut report);
            }
            DoctorScope::PasswordPolicy => {
                self.check_password_policy(&mut report);
            }
        }

        Ok(report)
    }

    /// Check user account security.
    fn check_accounts(&self, report: &mut UserReport) {
        // Check for root login via SSH. The path is plumbed through
        // `self.paths.sshd_config` (rather than hardcoded `/etc/ssh/sshd_config`)
        // so a `UserPaths::with_base(tmp)` redirects this read for tests and
        // chrooted operation, matching every other file read in the doctor.
        //
        // Modern Debian/Ubuntu/Fedora ship the *effective* PermitRootLogin in
        // `/etc/ssh/sshd_config.d/*.conf` via an `Include` directive, and the
        // directive can also appear inside a `Match` block (conditional). We
        // therefore resolve the config per sshd_config(5):
        //   - "for each keyword, the first obtained value will be used" (global)
        //   - Include paths "may contain glob(7) wildcards ... expanded and
        //     processed in lexical order"; non-absolute paths are relative to
        //     /etc/ssh; "an Include directive may appear inside a Match block
        //     to perform conditional inclusion"
        //   - Match keywords "override those set in the global section ...
        //     until either another Match line or the end of the file" and are
        //     *conditional* on the Match criteria.
        // Per-check degrade: an unreadable sshd_config / drop-in must NOT abort
        // the whole suite. Log and continue to the UID-0 / insecure-shell checks.
        if self.paths.sshd_config.exists() {
            let root = resolve_sshd_root_login(&self.paths.sshd_config);
            if root.global_yes {
                report.push(
                    UserFinding::new(
                        "user.root-login.ssh-enabled",
                        Severity::Critical,
                        "Root SSH login is enabled",
                    )
                    .detail(format!(
                        "PermitRootLogin is set to 'yes' (effective at global scope) in {}.",
                        root.global_source.as_deref().unwrap_or_else(|| self
                            .paths
                            .sshd_config
                            .to_str()
                            .unwrap_or("?"))
                    ))
                    .fix("Set PermitRootLogin to 'prohibit-password' or 'no'."),
                );
            }
            // Match-block directives are *conditional*: they only grant root
            // login when the Match criteria (User/Group/Host/Address/...) are
            // satisfied for the connecting client. We cannot evaluate the
            // condition here, so surface each one as a distinct Warning so an
            // operator can audit it rather than silently flag (or miss) it.
            for cond in &root.conditional_yes {
                report.push(
                    UserFinding::new(
                        "user.root-login.match-block.ssh-enabled",
                        Severity::Warning,
                        "Root SSH login is enabled inside a Match block",
                    )
                    .detail(format!(
                        "PermitRootLogin is set to 'yes' inside a conditional \
                         `Match {}` block in {}. This only applies when the Match \
                         criteria are met — verify it is intentional.",
                        cond.match_clause,
                        cond.source.as_deref().unwrap_or_else(|| self
                            .paths
                            .sshd_config
                            .to_str()
                            .unwrap_or("?"))
                    ))
                    .fix(
                        "If unintended, set PermitRootLogin to 'prohibit-password' or 'no' \
                         inside the Match block, or close it with `Match all`.",
                    ),
                );
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
                return;
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
            "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy",
            "www-data", "backup", "list", "irc", "gnats", "nobody",
        ];
        for entry in &passwd_entries {
            if system_users.contains(&entry.username.as_str())
                && insecure_shells.contains(&entry.shell.as_str())
            {
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

    /// Check sudo configuration.
    fn check_sudo(&self, report: &mut UserReport) {
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
                    return;
                }
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_none_or(|e| e != "bak")
                    && let Ok(sudoers) = crate::parse::read_sudoers(&path)
                {
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

    /// Check PAM/TOTP configuration.
    fn check_pam(&self, report: &mut UserReport) {
        // Check if TOTP is configured for SSH. Per-check degrade: an unreadable
        // pam.d/sshd must NOT abort the whole suite. Log and continue to the
        // sudo-without-TOTP check below.
        let sshd_pam = match self.paths.pam_service("sshd") {
            Ok(p) => p,
            // "sshd" is a constant safe name, so this only fails on a broken
            // base dir; degrade like the read below rather than aborting.
            Err(e) => {
                tracing::warn!("could not resolve sshd PAM path: {e}");
                return;
            }
        };
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
                return;
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
            let totp_configured =
                crate::totp::is_totp_configured(&self.paths, username).unwrap_or(false);
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
    }

    /// Check password policy compliance.
    fn check_password_policy(&self, report: &mut UserReport) {
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
                    return;
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
    }
}

impl Default for Doctor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// sshd_config(5) Include / Match resolution for PermitRootLogin
// ---------------------------------------------------------------------------
//
// Format source: sshd_config(5), https://man.openbsd.com/sshd_config
//   "Unless noted otherwise, for each keyword, the first obtained value will
//    be used. Lines starting with '#' and empty lines are interpreted as
//    comments. ... keywords are case-insensitive and ... arguments are
//    case-sensitive."
//   Include: "Multiple pathnames may be specified and each pathname may contain
//    glob(7) wildcards that will be expanded and processed in lexical order.
//    Files without absolute paths are assumed to be in /etc/ssh. An Include
//    directive may appear inside a Match block to perform conditional
//    inclusion."
//   Match: "Introduces a conditional block. If all of the criteria on the Match
//    line are satisfied, the keywords on the following lines override those set
//    in the global section of the config file, until either another Match line
//    or the end of the file."
//
// The default PermitRootLogin is `prohibit-password`; the only value that
// grants unrestricted password root login is `yes`.

/// A `PermitRootLogin yes` directive that lives inside a conditional
/// `Match <criteria>` block. It only applies when the criteria are met for the
/// connecting client, so the doctor surfaces it separately rather than folding
/// it into the global effective value.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ConditionalRootLogin {
    /// The raw `Match` clause text, e.g. `User admin` or `Address 10.0.0.0/8`.
    match_clause: String,
    /// File the directive was read from (for the finding detail). `None` only
    /// when the source path cannot be rendered as UTF-8.
    source: Option<String>,
}

/// Result of resolving `PermitRootLogin` across a full `sshd_config` tree.
#[derive(Debug, Default)]
struct ResolvedRootLogin {
    /// `true` if the effective *global-scope* `PermitRootLogin` is `yes`
    /// (first obtained value wins, after Include expansion in read order).
    global_yes: bool,
    /// File the effective global directive was read from.
    global_source: Option<String>,
    /// Each `PermitRootLogin yes` found inside a `Match` block, with the Match
    /// clause and source file. These are conditional and surfaced individually.
    conditional_yes: Vec<ConditionalRootLogin>,
}

impl ResolvedRootLogin {
    /// Push a directive at the given scope.
    ///
    /// At global scope only the *first* `yes`/not-`yes` value is recorded as
    /// effective (per "first obtained value will be used"); subsequent global
    /// values are ignored. Inside a Match block every `yes` is captured because
    /// each is a distinct conditional grant.
    fn record(&mut self, arg: &str, match_scope: Option<&str>, source: &str) {
        if let Some(clause) = match_scope {
            if arg == "yes" {
                self.conditional_yes.push(ConditionalRootLogin {
                    match_clause: clause.to_owned(),
                    source: Some(source.to_owned()),
                });
            }
        } else if self.global_source.is_none() {
            // First global directive wins (effective value). We only need to
            // remember whether it was `yes`; once set, later globals are inert.
            self.global_yes = arg == "yes";
            self.global_source = Some(source.to_owned());
        }
    }
}

/// Resolve `PermitRootLogin` across the main `sshd_config` and every `Include`
/// it transitively pulls in (glob-expanded in lexical order).
///
/// `main_path` is the top-level config file (e.g. `/etc/ssh/sshd_config`). The
/// directory of the file being parsed is used to resolve relative Include
/// paths, which per `sshd_config(5)` default to `/etc/ssh` — and on a stock
/// system the main file lives in `/etc/ssh`, so the file's parent dir is the
/// correct base for relative resolution under both the real host and a temp
/// `UserPaths::with_base` tree.
fn resolve_sshd_root_login(main_path: &std::path::Path) -> ResolvedRootLogin {
    let mut out = ResolvedRootLogin::default();
    // Per-check degrade: a missing/unreadable main config yields the (empty)
    // default — no findings — rather than aborting. The doctor's caller treats
    // a missing sshd_config as "feature absent".
    if !main_path.is_file() {
        return out;
    }
    let mut seen: std::collections::HashSet<std::path::PathBuf> = std::collections::HashSet::new();
    resolve_in_file(main_path, None, &mut seen, &mut out);
    out
}

/// Parse one config file, recursing into `Include` directives.
///
/// `match_scope` is the clause text of the enclosing `Match` block, or `None`
/// at global scope. Per `sshd_config(5)`, an `Include` inside a Match block is
/// *conditional*, so the scope propagates into the included file's directives.
/// `seen` guards against Include cycles (a file that includes itself directly
/// or transitively) — sshd itself rejects such loops, but a malformed config
/// must not send us into infinite recursion.
fn resolve_in_file(
    path: &std::path::Path,
    match_scope: Option<&str>,
    seen: &mut std::collections::HashSet<std::path::PathBuf>,
    out: &mut ResolvedRootLogin,
) {
    // Canonicalise for cycle detection; fall back to the raw path if the file
    // is not present or the cwd makes canonicalisation fail.
    let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if !seen.insert(canon.clone()) {
        tracing::warn!(
            "doctor sshd_config: skipping already-included {} (Include cycle)",
            canon.display()
        );
        return;
    }

    let content = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            // Per-check degrade: an unreadable drop-in must not abort the rest
            // of the tree. Log and continue with what we have so far.
            tracing::warn!("doctor sshd_config read {}: {e}", path.display());
            return;
        }
    };
    let source = path.to_str().unwrap_or("?");

    // The current Match scope *within this file*. A `Match` line opens a scope
    // that persists until another `Match` line or end-of-file. It does NOT
    // propagate back out to the caller's scope: after this file returns, the
    // caller resumes its own (outer) scope. An `Include` however inherits the
    // active scope (handled at the call site below).
    let mut local_scope: Option<String> = match_scope.map(str::to_owned);

    for raw_line in content.lines() {
        let line = raw_line.trim_start();
        // Per spec: blank lines and lines whose first non-whitespace char is
        // '#' are comments and are inert (a `#` mid-line does not start one).
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut tokens = line.split_ascii_whitespace();
        let Some(key) = tokens.next() else { continue };

        // Keywords are case-insensitive (sshd_config(5)).
        if key.eq_ignore_ascii_case("Match") {
            // Rest of the line is the criteria clause. A new `Match` line
            // supersedes any prior block's scope for subsequent directives.
            // `Match all` is itself a (always-satisfied) Match block, not a
            // reset to global scope — the clause text is recorded verbatim so
            // the finding detail stays faithful.
            let clause: String = tokens.collect::<Vec<_>>().join(" ");
            local_scope = Some(clause);
            continue;
        }

        if key.eq_ignore_ascii_case("Include") {
            // Per spec: relative paths resolve against /etc/ssh (the main
            // file's dir). The file's parent dir is the correct base for both
            // the real host and a temp tree. Each token is a separate pathname,
            // each may glob, and globs expand in lexical order.
            let base = path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("/etc/ssh"));
            for tok in tokens {
                // Arguments may be double-quoted (per the line-format rule that
                // arguments containing spaces are quoted). Strip surrounding
                // quotes for path resolution.
                let pat = strip_quotes(tok);
                for inc in expand_include(base, pat) {
                    // Conditional inclusion: the included file inherits the
                    // active Match scope (sshd_config(5)).
                    resolve_in_file(&inc, local_scope.as_deref(), seen, out);
                }
            }
            continue;
        }

        if key.eq_ignore_ascii_case("PermitRootLogin") {
            // Argument matching is case-sensitive; `yes` grants unrestricted
            // (password) root login. A directive with no argument is a config
            // error sshd would reject — treat as inert here.
            if let Some(arg) = tokens.next() {
                let arg = strip_quotes(arg);
                out.record(arg, local_scope.as_deref(), source);
            }
        }
    }
}

/// Strip a single layer of surrounding double quotes from a `sshd_config`
/// argument. `sshd_config(5)`: "Arguments may optionally be enclosed in double
/// quotes (\") in order to represent arguments containing spaces."
fn strip_quotes(s: &str) -> &str {
    let s = s.strip_prefix('"').unwrap_or(s);
    s.strip_suffix('"').unwrap_or(s)
}

/// Expand a single `Include` pathname against `base`, returning the matched
/// files in lexical order. Per `sshd_config(5)` + glob(7), `*` matches any run
/// of characters within a path segment and `?` matches a single character.
/// Non-absolute patterns resolve relative to `base` (the config file's dir,
/// which on a stock system is `/etc/ssh`). Non-matching patterns yield no
/// entries (sshd silently ignores a glob with no hits, but treats a literal
/// missing file as an error — we follow the lenient "no hits" path so a stale
/// drop-in glob never aborts the suite).
///
/// The pattern may carry a literal directory prefix (e.g. `sshd_config.d/`
/// in `sshd_config.d/*.conf`); that prefix is resolved against `base` and the
/// glob applies only to the final path component.
fn expand_include(base: &std::path::Path, pattern: &str) -> Vec<std::path::PathBuf> {
    // Resolve the pathname relative to `base` for non-absolute patterns.
    let resolved = if std::path::Path::new(pattern).is_absolute() {
        std::path::PathBuf::from(pattern)
    } else {
        base.join(pattern)
    };
    // Split into the directory part (literal, no wildcards) and the final
    // component (which may carry `*`/`?`). Wildcards only appear in the last
    // segment for Include globs (glob(7) `*` does not cross `/`).
    let Some(file_name) = resolved.file_name() else {
        return Vec::new();
    };
    let search_dir = resolved.parent().unwrap_or(base);
    let pattern_str = file_name.to_string_lossy();

    // Fast path: no wildcard — return the literal path if it is a file.
    if !pattern_str.contains(['*', '?']) {
        return if resolved.is_file() {
            vec![resolved]
        } else {
            Vec::new()
        };
    }

    let Ok(entries) = std::fs::read_dir(search_dir) else {
        return Vec::new();
    };
    let mut matched: Vec<std::path::PathBuf> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name();
            if glob_segment_match(pattern_str.as_bytes(), name.as_encoded_bytes())
                && e.path().is_file()
            {
                Some(e.path())
            } else {
                None
            }
        })
        .collect();
    // "expanded and processed in lexical order" (sshd_config(5)).
    matched.sort();
    matched
}

/// Match a single glob(7) path segment (`*` = any run, `?` = one char) against
/// a candidate name, byte-wise. Case-sensitive on bytes, matching how the
/// filesystem and glob(7) behave (sshd defers to glob(7)).
fn glob_segment_match(pat: &[u8], txt: &[u8]) -> bool {
    // Iterative two-pointer match with backtracking on `*`, the classic
    // non-recursive glob implementation. `wildcard_pat`/`wildcard_txt` record
    // the last `*` position so a later mismatch can extend what it consumes.
    let mut pi = 0;
    let mut ti = 0;
    let mut wildcard_pat: Option<usize> = None;
    let mut wildcard_txt = 0;
    while ti < txt.len() {
        if pi < pat.len() && (pat[pi] == b'?' || pat[pi] == txt[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pat.len() && pat[pi] == b'*' {
            wildcard_pat = Some(pi);
            wildcard_txt = ti;
            pi += 1;
        } else if let Some(wp) = wildcard_pat {
            // Backtrack: let the `*` consume one more char.
            pi = wp + 1;
            wildcard_txt += 1;
            ti = wildcard_txt;
        } else {
            return false;
        }
    }
    while pi < pat.len() && pat[pi] == b'*' {
        pi += 1;
    }
    pi == pat.len()
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
        let paths = UserPaths::with_base(&base);

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
            ids.contains(&"pam.sudo-user.no-totp.alice"),
            "alice finding should be present, got: {ids:?}"
        );
        assert!(
            ids.contains(&"pam.sudo-user.no-totp.ghost"),
            "ghost finding should be present (degraded, not fatal), got: {ids:?}"
        );
    }

    /// Regression for the fail-fast-at-file-level class: a single unreadable
    /// file must NOT abort the whole doctor suite. `run()` chains
    /// `check_accounts` / `check_sudo` / `check_pam` / `check_password_policy`; before
    /// the fix each propagated the first file-IO error with `?`, so an
    /// unreadable `/etc/passwd` aborted every subsequent check and the TUI
    /// collector blanked the entire findings `Vec` to empty.
    ///
    /// This test makes `/etc/passwd` unreadable by creating it as a DIRECTORY
    /// (`read_to_string` on a dir returns an IO error) while keeping
    /// `/etc/login.defs` readable and populated so the password-policy check has
    /// real findings to emit. The suite must survive and still report the
    /// login.defs findings — proving `check_password_policy` ran despite
    /// `check_accounts`' passwd read failing.
    #[test]
    fn unreadable_passwd_does_not_abort_whole_suite() {
        let dir = TempDir::new().expect("tempdir");
        let base = dir.path().to_path_buf();
        let paths = UserPaths::with_base(&base);

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
            ids.contains(&"password-policy.no-max-days"),
            "login.defs finding should still be present, got: {ids:?}"
        );
        assert!(
            ids.contains(&"password-policy.no-min-days"),
            "login.defs finding should still be present, got: {ids:?}"
        );
    }

    /// Companion: an unreadable `/etc/shadow` must not abort the
    /// password-policy check — the `/etc/login.defs` half must still run.
    /// Before the fix, `check_password_policy`'s `read_to_string(&shadow)?` at
    /// the top of the function short-circuited the login.defs check below it.
    #[test]
    fn unreadable_shadow_does_not_abort_password_policy_check() {
        let dir = TempDir::new().expect("tempdir");
        let base = dir.path().to_path_buf();
        let paths = UserPaths::with_base(&base);

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
            ids.contains(&"password-policy.no-max-days"),
            "login.defs finding should still be present despite unreadable shadow, got: {ids:?}"
        );
        // No empty-password finding was emitted — shadow was unreadable.
        assert!(
            !ids.iter().any(|id| id.starts_with("password.empty.")),
            "no empty-password finding should be emitted when shadow is unreadable, got: {ids:?}"
        );
    }

    /// Regression for the `sshd_config` unwired-backend gap: `check_accounts`
    /// previously hardcoded `Path::new("/etc/ssh/sshd_config")`, so a
    /// `UserPaths::with_base(tmp)` could NOT redirect the root-login check.
    /// With the path now plumbed through `UserPaths::sshd_config`
    /// (`<base>/ssh/sshd_config`), writing a fake `sshd_config` with
    /// `PermitRootLogin yes` under the temp base must surface the
    /// `user.root-login.ssh-enabled` finding against the temp file, not the
    /// real `/etc/ssh/sshd_config`.
    #[test]
    fn check_accounts_reads_sshd_config_via_paths() {
        let dir = TempDir::new().expect("tempdir");
        let base = dir.path().to_path_buf();
        let paths = UserPaths::with_base(&base);

        // sshd_config lives at <base>/ssh/sshd_config under the temp base.
        let sshd_dir = dir.path().join("ssh");
        std::fs::create_dir_all(&sshd_dir).expect("mkdir ssh");
        std::fs::write(
            sshd_dir.join("sshd_config"),
            "# sshd\nPermitRootLogin yes\n",
        )
        .expect("write sshd_config");

        // A minimal passwd so check_accounts' downstream reads don't trip.
        std::fs::write(&paths.passwd, "root:x:0:0:root:/root:/bin/bash\n").expect("write passwd");

        let doctor = Doctor::with_paths(paths);
        let report = doctor
            .run(&DoctorScope::Accounts)
            .expect("doctor accounts scope");

        let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
        assert!(
            ids.contains(&"user.root-login.ssh-enabled"),
            "root-login finding should be read from the temp sshd_config, got: {ids:?}"
        );
    }

    /// Companion: when `PermitRootLogin yes` is NOT present, the finding must
    /// not fire (guards against the check spuriously matching the real host's
    /// `/etc/ssh/sshd_config`, which the hardcoded path would have done).
    #[test]
    fn check_accounts_no_root_login_finding_when_disabled() {
        let dir = TempDir::new().expect("tempdir");
        let base = dir.path().to_path_buf();
        let paths = UserPaths::with_base(&base);

        let sshd_dir = dir.path().join("ssh");
        std::fs::create_dir_all(&sshd_dir).expect("mkdir ssh");
        std::fs::write(
            sshd_dir.join("sshd_config"),
            "# sshd\nPermitRootLogin prohibit-password\n",
        )
        .expect("write sshd_config");

        std::fs::write(&paths.passwd, "root:x:0:0:root:/root:/bin/bash\n").expect("write passwd");

        let doctor = Doctor::with_paths(paths);
        let report = doctor
            .run(&DoctorScope::Accounts)
            .expect("doctor accounts scope");

        let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
        assert!(
            !ids.contains(&"user.root-login.ssh-enabled"),
            "no root-login finding when PermitRootLogin is not 'yes', got: {ids:?}"
        );
    }

    // --- PermitRootLogin comment/false-match regression tests ---
    //
    // Format source: sshd_config(5), man7.org/linux/man-pages/man5/sshd_config.5.html
    //   "Lines starting with '#' and empty lines are interpreted as comments."
    //   "note that keywords are case-insensitive and arguments are case-sensitive"
    //   PermitRootLogin takes: yes | prohibit-password | forced-commands-only | no
    //
    // The previous `content.contains("PermitRootLogin yes")` matcher
    // FALSE-MATCHED the commented-out `# PermitRootLogin yes` line that ships
    // in Debian/Ubuntu's default sshd_config. These tests guard against that.

    /// A commented-out `PermitRootLogin yes` (as found in Debian/Ubuntu's
    /// default `/etc/ssh/sshd_config`, which ships with the directive
    /// commented) MUST NOT trigger the finding. This is the exact
    /// false-positive the Wave-2a verify pass caught.
    #[test]
    fn check_accounts_ignores_commented_permit_root_login() {
        let dir = TempDir::new().expect("tempdir");
        let paths = UserPaths::with_base(dir.path());

        let sshd_dir = dir.path().join("ssh");
        std::fs::create_dir_all(&sshd_dir).expect("mkdir ssh");
        // Faithful slice of a Debian/Ubuntu default sshd_config: the only
        // `PermitRootLogin` line present is commented out, and the effective
        // default (`prohibit-password`) would never grant password root login.
        std::fs::write(
            sshd_dir.join("sshd_config"),
            "# This is the sshd server system-wide configuration file.\n\
             \n\
             #LoginGraceTime 2m\n\
             #PermitRootLogin yes\n\
             #StrictModes yes\n\
             #MaxAuthTries 6\n",
        )
        .expect("write sshd_config");

        std::fs::write(&paths.passwd, "root:x:0:0:root:/root:/bin/bash\n").expect("write passwd");

        let doctor = Doctor::with_paths(paths);
        let report = doctor
            .run(&DoctorScope::Accounts)
            .expect("doctor accounts scope");

        let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
        assert!(
            !ids.contains(&"user.root-login.ssh-enabled"),
            "commented `# PermitRootLogin yes` must NOT be flagged as enabled, got: {ids:?}"
        );
    }

    /// An uncommented, active `PermitRootLogin yes` directive (preceded by
    /// leading whitespace, as is common in indented drop-in fragments) MUST
    /// be flagged.
    #[test]
    fn check_accounts_flags_uncommented_permit_root_login() {
        let dir = TempDir::new().expect("tempdir");
        let paths = UserPaths::with_base(dir.path());

        let sshd_dir = dir.path().join("ssh");
        std::fs::create_dir_all(&sshd_dir).expect("mkdir ssh");
        // Leading-whitespace + mixed case keyword: sshd_config(5) states
        // keywords are case-insensitive, so `permitrootlogin yes` is an
        // active directive granting root password login. Arguments are
        // case-sensitive, so lowercase `yes` still matches.
        std::fs::write(
            sshd_dir.join("sshd_config"),
            "# Managed by toride\n\
             \tpermitrootlogin yes\n",
        )
        .expect("write sshd_config");

        std::fs::write(&paths.passwd, "root:x:0:0:root:/root:/bin/bash\n").expect("write passwd");

        let doctor = Doctor::with_paths(paths);
        let report = doctor
            .run(&DoctorScope::Accounts)
            .expect("doctor accounts scope");

        let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
        assert!(
            ids.contains(&"user.root-login.ssh-enabled"),
            "uncommented `permitrootlogin yes` (leading ws, lowercase keyword) \
             must be flagged, got: {ids:?}"
        );
    }

    /// `PermitRootLogin` set to a hardening value (`prohibit-password`) while
    /// a separate commented line mentions `yes` must not be flagged.
    /// Also pins the case-sensitivity of the argument: `YES` is NOT `yes`
    /// per `sshd_config(5)` and should NOT be flagged.
    #[test]
    fn check_accounts_respects_first_value_and_case_sensitive_arg() {
        let dir = TempDir::new().expect("tempdir");
        let paths = UserPaths::with_base(dir.path());

        let sshd_dir = dir.path().join("ssh");
        std::fs::create_dir_all(&sshd_dir).expect("mkdir ssh");
        // sshd applies the first obtained value for a keyword. Here the
        // active directive is `prohibit-password`; the later `YES` is both
        // out of precedence and not a valid (case-sensitive) argument.
        std::fs::write(
            sshd_dir.join("sshd_config"),
            "PermitRootLogin prohibit-password\n\
             # PermitRootLogin yes\n\
             PermitRootLogin YES\n",
        )
        .expect("write sshd_config");

        std::fs::write(&paths.passwd, "root:x:0:0:root:/root:/bin/bash\n").expect("write passwd");

        let doctor = Doctor::with_paths(paths);
        let report = doctor
            .run(&DoctorScope::Accounts)
            .expect("doctor accounts scope");

        let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
        assert!(
            !ids.contains(&"user.root-login.ssh-enabled"),
            "first value `prohibit-password` wins; `YES` is not the case-sensitive `yes`; \
             got: {ids:?}"
        );
    }

    // --- sshd_config(5) Include + Match resolution ---

    /// Helper: write `sshd_config` text into a temp tree and resolve
    /// `PermitRootLogin` through it. Returns the resolved result. The temp sshd
    /// dir lives at `<tmp>/ssh/`, matching `UserPaths::with_base`, so relative
    /// `Include` patterns resolve against that dir exactly as they do on a real
    /// host under `/etc/ssh`.
    fn resolve_from_config(sshd_text: &str) -> (TempDir, ResolvedRootLogin) {
        let dir = TempDir::new().expect("tempdir");
        let sshd_dir = dir.path().join("ssh");
        std::fs::create_dir_all(&sshd_dir).expect("mkdir ssh");
        let main = sshd_dir.join("sshd_config");
        std::fs::write(&main, sshd_text).expect("write sshd_config");
        let resolved = resolve_sshd_root_login(&main);
        (dir, resolved)
    }

    /// Direct unit test of the resolver against a faithful Debian/Ubuntu-style
    /// default `sshd_config` slice (commented directive only).
    #[test]
    fn sshd_resolver_parses_real_default_config() {
        // Slice drawn from a stock Debian /etc/ssh/sshd_config header where
        // PermitRootLogin is shipped commented out (effective default
        // `prohibit-password`). See sshd_config(5).
        let debian_default = "\
# This is the sshd server system-wide configuration file.

#LoginGraceTime 2m
#PermitRootLogin prohibit-password
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10
";
        let (_dir, resolved) = resolve_from_config(debian_default);
        assert!(
            !resolved.global_yes,
            "stock Debian default (commented directive) must not be flagged as enabled"
        );
        assert!(
            resolved.global_source.is_none(),
            "commented directive must not be recorded as the effective source"
        );
        assert!(
            resolved.conditional_yes.is_empty(),
            "no Match-block directives in this fixture"
        );

        // An admin who actively enables it (uncommented).
        let (_dir, resolved) = resolve_from_config("# Managed by admin\nPermitRootLogin yes\n");
        assert!(
            resolved.global_yes,
            "uncommented `PermitRootLogin yes` must be flagged"
        );
        assert!(
            resolved.global_source.is_some(),
            "effective directive should carry its source file"
        );
    }

    /// Regression: modern Debian/Ubuntu/Fedora ship the *effective*
    /// `PermitRootLogin` in `/etc/ssh/sshd_config.d/*.conf`, pulled in by an
    /// `Include` directive in the main file. The resolver must follow the
    /// Include, glob the `*.conf` files in lexical order, and report the
    /// directive from the drop-in as the effective global value.
    ///
    /// Without Include resolution (the old single-file reader), this config
    /// would read as "no `PermitRootLogin`" and miss the drop-in's `yes`,
    /// silently passing a root-login-enabled host as clean.
    #[test]
    fn sshd_resolver_follows_include_glob_dropin() {
        let dir = TempDir::new().expect("tempdir");
        let sshd_dir = dir.path().join("ssh");
        std::fs::create_dir_all(sshd_dir.join("sshd_config.d")).expect("mkdir dropin dir");

        // Main config mirrors the stock Debian/Ubuntu layout: an Include of a
        // drop-in directory at the top, and NO top-level PermitRootLogin.
        let main = sshd_dir.join("sshd_config");
        // sshd_config(5) says relative Include paths resolve against /etc/ssh
        // (the main file's dir). The main file's parent here IS the temp sshd
        // dir, so a bare `sshd_config.d/*.conf` resolves against it correctly,
        // exactly as `/etc/ssh/sshd_config.d/*.conf` would on a real host.
        std::fs::write(
            &main,
            "Include sshd_config.d/*.conf\n\
             # (no PermitRootLogin at global scope here)\n",
        )
        .expect("write main sshd_config");

        // Drop-in: the effective directive lives here.
        std::fs::write(
            sshd_dir.join("sshd_config.d").join("50-cloudimg.conf"),
            "# Managed by cloud-init\nPermitRootLogin yes\n",
        )
        .expect("write dropin");

        let resolved = resolve_sshd_root_login(&main);
        assert!(
            resolved.global_yes,
            "Include'd drop-in PermitRootLogin yes must be the effective global value"
        );
        assert!(
            resolved
                .global_source
                .as_deref()
                .is_some_and(|s| s.contains("50-cloudimg.conf")),
            "effective source should name the drop-in file, got: {:?}",
            resolved.global_source
        );
        assert!(
            resolved.conditional_yes.is_empty(),
            "global directive must not be mis-classified as a Match-block directive"
        );
    }

    /// Include globs expand in lexical order and the FIRST obtained global
    /// value wins (`sshd_config(5)`). With two drop-ins where the lexically-first
    /// one sets `no` and a later one sets `yes`, the effective value must be
    /// `no` — proving we honour both lexical Include ordering and first-wins.
    #[test]
    fn sshd_resolver_include_lexical_order_first_wins() {
        let dir = TempDir::new().expect("tempdir");
        let sshd_dir = dir.path().join("ssh");
        let dropin = sshd_dir.join("sshd_config.d");
        std::fs::create_dir_all(&dropin).expect("mkdir dropin");

        let main = sshd_dir.join("sshd_config");
        std::fs::write(&main, "Include sshd_config.d/*.conf\n").expect("write main");

        // `00-hardening.conf` sorts BEFORE `99-legacy.conf`, so its `no` is
        // obtained first and must win over the later `yes`.
        std::fs::write(dropin.join("00-hardening.conf"), "PermitRootLogin no\n").expect("00");
        std::fs::write(dropin.join("99-legacy.conf"), "PermitRootLogin yes\n").expect("99");

        let resolved = resolve_sshd_root_login(&main);
        assert!(
            !resolved.global_yes,
            "lexically-first Include'd `no` must win over later `yes`"
        );
        assert!(
            resolved
                .global_source
                .as_deref()
                .is_some_and(|s| s.contains("00-hardening.conf")),
            "effective source should be the first drop-in, got: {:?}",
            resolved.global_source
        );
    }

    /// A `PermitRootLogin yes` inside a `Match` block is *conditional* — it
    /// only applies when the Match criteria are satisfied. The resolver must
    /// NOT fold it into the global effective value (the host's global default
    /// may be the safe `prohibit-password`); it must surface it separately so
    /// an operator can audit the conditional grant.
    #[test]
    fn sshd_resolver_surfaces_match_block_directive_as_conditional() {
        // Global scope is the safe default; only a Match block enables root.
        // Per sshd_config(5), the Match scope persists until the next Match or
        // end-of-file.
        let (_dir, resolved) = resolve_from_config(
            "PermitRootLogin prohibit-password\n\
             Match User admin\n\
             PermitRootLogin yes\n",
        );

        assert!(
            !resolved.global_yes,
            "global value `prohibit-password` must be effective, not the Match-block `yes`"
        );
        assert_eq!(
            resolved.conditional_yes.len(),
            1,
            "exactly one Match-block `yes` should be surfaced"
        );
        let cond = &resolved.conditional_yes[0];
        assert_eq!(
            cond.match_clause, "User admin",
            "Match clause text preserved"
        );
        assert!(
            cond.source
                .as_deref()
                .is_some_and(|s| s.contains("sshd_config")),
            "conditional should carry its source file, got: {:?}",
            cond.source
        );
    }

    /// `Match all` (OpenSSH 6.5p1+) is itself a Match block whose criteria are
    /// always satisfied — it does NOT reset to global scope (the common
    /// "use `Match all` to close a block" idiom is really "open an
    /// always-matching block"). Per `sshd_config(5)`, directives following any
    /// `Match` line — including `Match all` — are conditional. A
    /// `PermitRootLogin yes` after `Match all` is therefore surfaced as a
    /// conditional directive (clause `all`), NOT folded into the global value.
    #[test]
    fn sshd_resolver_match_all_is_a_match_block() {
        let (_dir, resolved) = resolve_from_config(
            "PermitRootLogin prohibit-password\n\
             Match User bob\n\
             PermitRootLogin no\n\
             Match all\n\
             PermitRootLogin yes\n",
        );
        // Global stays the first directive (`prohibit-password`); the `yes`
        // after `Match all` is conditional, not global.
        assert!(
            !resolved.global_yes,
            "global effective value is `prohibit-password`; got global_yes=true"
        );
        // Exactly one Match-block `yes` (the one after `Match all`). The
        // `no` inside `Match User bob` is not `yes` so it is not surfaced.
        assert_eq!(
            resolved.conditional_yes.len(),
            1,
            "only the `Match all` `yes` should be surfaced; got: {:?}",
            resolved.conditional_yes
        );
        assert_eq!(
            resolved.conditional_yes[0].match_clause, "all",
            "the clause text for `Match all` is the literal `all`"
        );
    }

    /// Match scope does NOT leak out of an included file back into the parent.
    /// If a drop-in opens a Match block and never closes it, the parent file's
    /// subsequent directives must still resolve at the parent's (global) scope,
    /// not the drop-in's. (This is the classic "Include without `Match all`
    /// swallows the rest" footgun, but sshd isolates the scope per-file; the
    /// resolver mirrors that.)
    #[test]
    fn sshd_resolver_match_scope_does_not_leak_from_include() {
        let dir = TempDir::new().expect("tempdir");
        let sshd_dir = dir.path().join("ssh");
        let dropin = sshd_dir.join("sshd_config.d");
        std::fs::create_dir_all(&dropin).expect("mkdir dropin");

        let main = sshd_dir.join("sshd_config");
        // Parent includes the drop-in, then sets PermitRootLogin at global scope.
        std::fs::write(
            &main,
            "Include sshd_config.d/*.conf\n\
             PermitRootLogin yes\n",
        )
        .expect("write main");

        // Drop-in opens a Match block and leaves it unclosed. If the resolver
        // naively propagated the drop-in's scope into the parent, the parent's
        // `yes` would be mis-filed as conditional. sshd resolves each file with
        // its own scope, so the parent's directive stays global.
        std::fs::write(
            dropin.join("10-match.conf"),
            "Match User carol\n\
             PermitRootLogin no\n",
        )
        .expect("write dropin");

        let resolved = resolve_sshd_root_login(&main);
        assert!(
            resolved.global_yes,
            "parent-file `yes` after the Include must be global, not swallowed by the drop-in's Match scope"
        );
        assert!(
            resolved.conditional_yes.is_empty(),
            "no Match-block `yes` exists in this tree; got: {:?}",
            resolved.conditional_yes
        );
    }

    /// An Include directive inside a Match block performs *conditional*
    /// inclusion (`sshd_config(5)`): directives in the included file inherit the
    /// active Match scope. A drop-in's `PermitRootLogin yes` pulled in this way
    /// must be surfaced as a Match-block (conditional) directive, not global.
    #[test]
    fn sshd_resolver_include_inside_match_is_conditional() {
        let dir = TempDir::new().expect("tempdir");
        let sshd_dir = dir.path().join("ssh");
        let dropin = sshd_dir.join("sshd_config.d");
        std::fs::create_dir_all(&dropin).expect("mkdir dropin");

        let main = sshd_dir.join("sshd_config");
        std::fs::write(
            &main,
            "PermitRootLogin prohibit-password\n\
             Match Group wheel\n\
             Include sshd_config.d/*.conf\n",
        )
        .expect("write main");
        std::fs::write(dropin.join("admins.conf"), "PermitRootLogin yes\n").expect("write dropin");

        let resolved = resolve_sshd_root_login(&main);
        assert!(
            !resolved.global_yes,
            "global default stays `prohibit-password`"
        );
        assert_eq!(
            resolved.conditional_yes.len(),
            1,
            "Include'd `yes` inherits the enclosing Match scope and is conditional"
        );
        assert_eq!(
            resolved.conditional_yes[0].match_clause, "Group wheel",
            "the enclosing Match clause propagates into the included file"
        );
    }

    /// End-to-end through the doctor: a config with a global `prohibit-password`
    /// plus a Match-block `yes` must produce BOTH the no-global-finding outcome
    /// AND a distinct `user.root-login.match-block.ssh-enabled` Warning. This is
    /// the user-facing behaviour for the modern Include + Match scenario.
    #[test]
    fn check_accounts_flags_match_block_root_login_separately() {
        let dir = TempDir::new().expect("tempdir");
        let paths = UserPaths::with_base(dir.path());
        let sshd_dir = dir.path().join("ssh");
        std::fs::create_dir_all(&sshd_dir).expect("mkdir ssh");
        std::fs::write(
            sshd_dir.join("sshd_config"),
            "PermitRootLogin prohibit-password\n\
             Match Address 192.168.1.0/24\n\
             PermitRootLogin yes\n",
        )
        .expect("write sshd_config");
        std::fs::write(&paths.passwd, "root:x:0:0:root:/root:/bin/bash\n").expect("write passwd");

        let doctor = Doctor::with_paths(paths);
        let report = doctor
            .run(&DoctorScope::Accounts)
            .expect("doctor accounts scope");

        let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
        assert!(
            !ids.contains(&"user.root-login.ssh-enabled"),
            "global value is prohibit-password -> no global finding; got: {ids:?}"
        );
        assert!(
            ids.contains(&"user.root-login.match-block.ssh-enabled"),
            "Match-block `yes` must surface a conditional finding; got: {ids:?}"
        );
        // And it should be a Warning (conditional, not yet a confirmed exposure).
        let cond = report
            .findings
            .iter()
            .find(|f| f.id == "user.root-login.match-block.ssh-enabled")
            .expect("conditional finding present");
        assert_eq!(
            cond.severity,
            Severity::Warning,
            "conditional Match-block directive is a Warning, not Critical"
        );
        assert!(
            cond.detail.contains("192.168.1.0/24"),
            "detail should name the Match clause; got: {}",
            cond.detail
        );
    }

    /// Glob segment matcher: `*` and `?` semantics for the Include path name
    /// component, byte-wise and case-sensitive (filesystem / glob(7)).
    #[test]
    fn glob_segment_matches_star_and_question() {
        assert!(glob_segment_match(b"*.conf", b"50-cloudimg.conf"));
        assert!(glob_segment_match(b"*.conf", b"a.conf"));
        assert!(!glob_segment_match(b"*.conf", b"a.txt"));
        // `?` is exactly one char.
        assert!(glob_segment_match(b"a?c", b"abc"));
        assert!(!glob_segment_match(b"a?c", b"ac"));
        assert!(!glob_segment_match(b"a?c", b"abbc"));
        // No wildcard -> exact match only.
        assert!(glob_segment_match(b"foo.conf", b"foo.conf"));
        assert!(!glob_segment_match(b"foo.conf", b"bar.conf"));
        // Trailing star consumes the rest.
        assert!(glob_segment_match(b"cloud*", b"cloudimg"));
        // Case-sensitive.
        assert!(!glob_segment_match(b"*.CONF", b"x.conf"));
    }
}
