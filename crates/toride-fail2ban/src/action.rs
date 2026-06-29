//! Command execution for ban/unban actions.
//!
//! Handles command templating with variable expansion and execution.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::command::Runner;
use crate::types::PlatformCommands;

/// Escape a value for safe use in `sh -c` command strings.
///
/// Wraps the value in single quotes and escapes embedded single quotes.
/// Numeric values and simple alphanumeric strings are passed through unchanged.
fn shell_escape(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    let needs_escape = value.chars().any(|c| {
        !c.is_ascii_alphanumeric() && c != '_' && c != '-' && c != '.' && c != '/' && c != ':'
    });
    if !needs_escape {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Reject templates that place shell-escaped placeholders inside double quotes.
///
/// When a placeholder like `<ip>` or `<jail>` appears inside double quotes in a
/// command template (e.g. `echo "<jail>"`), the single-quote wrapping produced by
/// [`shell_escape`] becomes literal characters and no longer protects against
/// shell expansion (`$`, backtick, etc.). This function scans the template for
/// that pattern and returns an error if found.
fn check_dq_placeholders(template: &str) -> Result<(), crate::Error> {
    // Only check string-valued placeholders that go through shell_escape.
    const PLACEHOLDERS: &[&str] = &["<ip>", "<jail>", "<log-path>"];
    let bytes = template.as_bytes();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'\'' if !in_double_quote => {
                in_single_quote = !in_single_quote;
                i += 1;
            }
            b'"' if !in_single_quote => {
                in_double_quote = !in_double_quote;
                i += 1;
            }
            b'\\' if !in_single_quote => {
                i += if i + 1 < bytes.len() { 2 } else { 1 };
            }
            _ if in_double_quote => {
                let remaining = &template[i..];
                for &ph in PLACEHOLDERS {
                    if remaining.starts_with(ph) {
                        return Err(crate::Error::InvalidConfig(format!(
                            "template contains {ph} inside double quotes which bypasses \
                             shell escaping; use single quotes or no quotes around placeholders"
                        )));
                    }
                }
                i += 1;
            }
            _ => i += 1,
        }
    }

    Ok(())
}

/// Perform single-pass template expansion.
///
/// Scans the template left-to-right, replacing each `<placeholder>` exactly once.
/// Already-substituted values are never re-scanned, preventing corruption when a
/// substituted value contains placeholder-like text (e.g. a jail name containing `<ip>`).
fn expand_template(template: &str, replacements: &[(&str, &str)]) -> String {
    let mut result = String::with_capacity(template.len() * 2);
    let mut pos = 0;
    let bytes = template.as_bytes();

    while pos < bytes.len() {
        if bytes[pos] == b'<' {
            if let Some(close) = template[pos..].find('>') {
                let placeholder = &template[pos..pos + close + 1];
                if let Some((_, value)) = replacements.iter().find(|(k, _)| placeholder == *k) {
                    result.push_str(value);
                    pos += placeholder.len();
                    continue;
                }
            }
        }
        let ch = template[pos..]
            .chars()
            .next()
            .expect("valid UTF-8 position");
        result.push(ch);
        pos += ch.len_utf8();
    }

    result
}

/// An action executor that runs platform-specific commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionExec {
    /// Name of this action.
    pub name: String,
    /// Platform-specific command templates.
    pub commands: PlatformCommands,
    /// Optional validation commands.
    #[serde(default, alias = "validate")]
    pub validation_commands: Vec<String>,
    /// Environment variables for command execution.
    #[serde(default)]
    pub env: HashMap<String, String>,
}

/// Variables available for command template expansion.
#[derive(Debug, Clone)]
pub struct ActionVars {
    /// The target IP address.
    pub ip: String,
    /// The CIDR prefix length.
    pub prefix: u8,
    /// The jail name.
    pub jail_name: String,
    /// Ban duration in seconds.
    pub ban_time: u64,
    /// Failure count.
    pub fail_count: u32,
    /// Log path.
    pub log_path: String,
}

impl ActionVars {
    /// Create new action variables.
    #[must_use]
    pub fn new(
        ip: impl Into<String>,
        prefix: u8,
        jail_name: impl Into<String>,
        ban_time: u64,
        fail_count: u32,
        log_path: impl Into<String>,
    ) -> Self {
        Self {
            ip: ip.into(),
            prefix,
            jail_name: jail_name.into(),
            ban_time,
            fail_count,
            log_path: log_path.into(),
        }
    }
}

impl ActionExec {
    /// Create a new action executor.
    pub fn new(name: String, commands: PlatformCommands) -> Self {
        Self {
            name,
            commands,
            validation_commands: Vec::new(),
            env: HashMap::new(),
        }
    }

    /// Expand command templates with the given variables.
    ///
    /// All string values are shell-escaped to prevent command injection.
    /// Numeric values (`<prefix>`, `<ban-time>`, `<fail-count>`) are not escaped
    /// since they are guaranteed to be numeric.
    ///
    /// # Errors
    ///
    /// Returns `InvalidConfig` if a shell-escaped placeholder (`<ip>`, `<jail>`,
    /// `<log-path>`) appears inside double quotes in the template, which would
    /// bypass single-quote shell escaping.
    pub fn expand_command(template: &str, vars: &ActionVars) -> crate::Result<String> {
        check_dq_placeholders(template)?;

        let ip_escaped = shell_escape(&vars.ip);
        let prefix_str = vars.prefix.to_string();
        let jail_escaped = shell_escape(&vars.jail_name);
        let bantime_str = vars.ban_time.to_string();
        let failcount_str = vars.fail_count.to_string();
        let logpath_escaped = shell_escape(&vars.log_path);

        let replacements: [(&str, &str); 6] = [
            ("<ip>", &ip_escaped),
            ("<prefix>", &prefix_str),
            ("<jail>", &jail_escaped),
            ("<ban-time>", &bantime_str),
            ("<fail-count>", &failcount_str),
            ("<log-path>", &logpath_escaped),
        ];

        Ok(expand_template(template, &replacements))
    }

    /// Execute the action for the current platform using the provided runner.
    pub fn exec(&self, vars: &ActionVars, runner: &dyn Runner) -> crate::Result<()> {
        let commands = self.commands.for_current_platform();

        for template in commands {
            let cmd_str = Self::expand_command(template, vars)?;
            Self::run_command(&cmd_str, &self.env, runner)?;
        }
        Ok(())
    }

    /// Execute the action in dry-run mode (log only, don't execute).
    pub fn dry_run(&self, vars: &ActionVars) -> crate::Result<Vec<String>> {
        let commands = self.commands.for_current_platform();
        let mut expanded = Vec::new();

        for template in commands {
            let cmd_str = Self::expand_command(template, vars)?;
            tracing::info!(action = %self.name, command = %cmd_str, "dry-run: would execute");
            expanded.push(cmd_str);
        }
        Ok(expanded)
    }

    /// Validate that the action can be executed using the provided runner.
    pub fn validate(&self, runner: &dyn Runner) -> crate::Result<()> {
        for template in &self.validation_commands {
            let replacements: [(&str, &str); 6] = [
                ("<ip>", "127.0.0.1"),
                ("<prefix>", "32"),
                ("<jail>", "test"),
                ("<ban-time>", "1"),
                ("<fail-count>", "1"),
                ("<log-path>", "/dev/null"),
            ];
            let cmd_str = expand_template(template, &replacements);

            let output = runner.run("sh", &["-c", &cmd_str])?;

            if !output.success {
                return Err(crate::Error::CommandFailed(format!(
                    "Validation command '{cmd_str}' exited with status: {}",
                    output
                        .exit_code
                        .map_or("unknown".to_string(), |c| c.to_string())
                )));
            }
        }
        Ok(())
    }

    /// Get commands for the current platform.
    #[must_use]
    pub fn platform_commands(&self) -> &[String] {
        self.commands.for_current_platform()
    }

    /// Execute a shell command using the provided runner.
    ///
    /// # Security
    /// Commands are executed via `sh -c`. Template variables (`<ip>`, `<jail>`, etc.)
    /// are substituted before execution. Callers must ensure template values are safe
    /// for shell interpolation. IP addresses from regex captures are generally safe,
    /// but user-provided paths or jail names should be validated.
    fn run_command(
        cmd_str: &str,
        _env: &HashMap<String, String>,
        runner: &dyn Runner,
    ) -> crate::Result<()> {
        let output = runner.run("sh", &["-c", cmd_str])?;

        if !output.success {
            return Err(crate::Error::CommandFailed(format!(
                "Command '{}' failed (exit {}): {}",
                cmd_str,
                output
                    .exit_code
                    .map_or("unknown".to_string(), |c| c.to_string()),
                output.stderr.trim()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "action.test.rs"]
mod tests;
