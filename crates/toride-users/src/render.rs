//! Rendering functions for sudoers entries and PAM configuration files.
//!
//! These functions take typed Rust values and produce the text format expected
//! by the corresponding system files.

// ---------------------------------------------------------------------------
// Sudoers rendering
// ---------------------------------------------------------------------------

/// Render a sudoers rule line for a user.
///
/// Produces a line of the form:
///
/// ```text
/// username ALL = (ALL) ALL
/// deployer ALL = (ALL) NOPASSWD: ALL
/// ```
///
/// # Arguments
///
/// * `username` - The user or `%group` the rule applies to.
/// * `commands` - The command list (e.g. `ALL` or `/usr/bin/systemctl`).
/// * `nopasswd` - Whether to include the `NOPASSWD` prefix.
/// * `runas` - Optional run-as user (defaults to `ALL`).
///
/// # Example
///
/// ```rust
/// use toride_users::render::render_sudoers_entry;
///
/// let line = render_sudoers_entry("deployer", "ALL", true, Some("ALL"));
/// assert_eq!(line, "deployer ALL = (ALL) NOPASSWD: ALL");
/// ```
#[must_use]
pub fn render_sudoers_entry(
    username: &str,
    commands: &str,
    nopasswd: bool,
    runas: Option<&str>,
) -> String {
    let runas_part = match runas {
        Some(r) => format!("({r})"),
        None => "(ALL)".to_owned(),
    };
    if nopasswd {
        format!("{username} ALL = {runas_part} NOPASSWD: {commands}")
    } else {
        format!("{username} ALL = {runas_part} {commands}")
    }
}

// ---------------------------------------------------------------------------
// PAM rendering
// ---------------------------------------------------------------------------

/// A single PAM rule line.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PamRule {
    /// Management group: `auth`, `account`, `password`, or `session`.
    pub management_group: String,
    /// Control flag: `required`, `requisite`, `sufficient`, `optional`, or a
    /// complex `[value1=action1 ...]` syntax.
    pub control: String,
    /// PAM module name (e.g. `pam_unix.so`).
    pub module: String,
    /// Module arguments.
    pub arguments: Vec<String>,
}

impl std::fmt::Display for PamRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}",
            self.management_group, self.control, self.module
        )?;
        for arg in &self.arguments {
            write!(f, " {arg}")?;
        }
        Ok(())
    }
}

/// Render a complete PAM configuration file from a list of rules.
///
/// Produces one line per rule, separated by newlines, with a trailing newline.
///
/// # Example
///
/// ```rust
/// use toride_users::render::{PamRule, render_pam_config};
///
/// let rules = vec![
///     PamRule {
///         management_group: "auth".to_owned(),
///         control: "required".to_owned(),
///         module: "pam_google_authenticator.so".to_owned(),
///         arguments: vec!["nullok".to_owned()],
///     },
/// ];
/// let config = render_pam_config(&rules);
/// assert!(config.contains("auth\trequired\tpam_google_authenticator.so nullok"));
/// ```
#[must_use]
pub fn render_pam_config(rules: &[PamRule]) -> String {
    let mut out = String::new();
    for rule in rules {
        out.push_str(&rule.to_string());
        out.push('\n');
    }
    out
}

/// Render a sudoers drop-in file for a user with TOTP enforcement.
///
/// Produces a file suitable for `/etc/sudoers.d/<username>` that requires
/// the user to authenticate with both a password and a TOTP code.
#[must_use]
pub fn render_totp_sudoers(username: &str) -> String {
    format!(
        "# Managed by toride -- TOTP required for sudo\n\
         {username} ALL = (ALL) ALL\n"
    )
}

/// Render PAM rules for TOTP/2FA integration with `pam_google_authenticator.so`.
///
/// Returns the rules to insert into `/etc/pam.d/sshd` or `/etc/pam.d/sudo`.
///
/// No `nullok`: TOTP is mandatory once enabled. `nullok` lets users without a
/// secret file skip the module, which defeats 2FA for the existing user base.
#[must_use]
pub fn render_totp_pam_rules() -> Vec<PamRule> {
    vec![PamRule {
        management_group: "auth".to_owned(),
        control: "required".to_owned(),
        module: "pam_google_authenticator.so".to_owned(),
        arguments: Vec::new(),
    }]
}
