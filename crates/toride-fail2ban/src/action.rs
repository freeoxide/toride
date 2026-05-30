//! Command execution for ban/unban actions.
//!
//! Handles command templating with variable expansion and execution.

use std::collections::HashMap;
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::types::PlatformCommands;

/// An action executor that runs platform-specific commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionExec {
    /// Name of this action.
    pub name: String,
    /// Platform-specific command templates.
    pub commands: PlatformCommands,
    /// Optional validation commands.
    #[serde(default)]
    pub validate: Vec<String>,
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
    pub fn new(
        ip: &str,
        prefix: u8,
        jail_name: &str,
        ban_time: u64,
        fail_count: u32,
        log_path: &str,
    ) -> Self {
        Self {
            ip: ip.to_string(),
            prefix,
            jail_name: jail_name.to_string(),
            ban_time,
            fail_count,
            log_path: log_path.to_string(),
        }
    }

}

impl ActionExec {
    /// Create a new action executor.
    pub fn new(name: String, commands: PlatformCommands) -> Self {
        Self {
            name,
            commands,
            validate: Vec::new(),
            env: HashMap::new(),
        }
    }

    /// Expand command templates with the given variables.
    pub fn expand_command(template: &str, vars: &ActionVars) -> String {
        template
            .replace("<ip>", &vars.ip)
            .replace("<prefix>", &vars.prefix.to_string())
            .replace("<jail>", &vars.jail_name)
            .replace("<ban-time>", &vars.ban_time.to_string())
            .replace("<fail-count>", &vars.fail_count.to_string())
            .replace("<log-path>", &vars.log_path)
    }

    /// Execute the action for the current platform.
    pub fn exec(&self, vars: &ActionVars) -> crate::Result<()> {
        let commands = self.commands.for_current_platform();

        for template in commands {
            let cmd_str = Self::expand_command(template, vars);
            Self::run_command(&cmd_str, &self.env)?;
        }
        Ok(())
    }

    /// Execute the action in dry-run mode (log only, don't execute).
    pub fn dry_run(&self, vars: &ActionVars) -> crate::Result<Vec<String>> {
        let commands = self.commands.for_current_platform();
        let mut expanded = Vec::new();

        for template in commands {
            let cmd_str = Self::expand_command(template, vars);
            tracing::info!(action = %self.name, command = %cmd_str, "dry-run: would execute");
            expanded.push(cmd_str);
        }
        Ok(expanded)
    }

    /// Validate that the action can be executed.
    pub fn validate(&self) -> crate::Result<()> {
        for template in &self.validate {
            let cmd_str = template
                .replace("<ip>", "127.0.0.1")
                .replace("<prefix>", "32")
                .replace("<jail>", "test")
                .replace("<ban-time>", "1")
                .replace("<fail-count>", "1")
                .replace("<log-path>", "/dev/null");

            let status = Command::new("sh")
                .args(["-c", &cmd_str])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();

            match status {
                Ok(s) if s.success() => {}
                Ok(s) => {
                    return Err(crate::Error::CommandFailed(format!(
                        "Validation command '{cmd_str}' exited with status: {s}"
                    )));
                }
                Err(e) => {
                    return Err(crate::Error::CommandFailed(format!(
                        "Failed to run validation command '{cmd_str}': {e}"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Get commands for the current platform.
    pub fn platform_commands(&self) -> &[String] {
        self.commands.for_current_platform()
    }

    /// Execute a shell command with environment variables.
    ///
    /// # Security
    /// Commands are executed via `sh -c`. Template variables (`<ip>`, `<jail>`, etc.)
    /// are substituted before execution. Callers must ensure template values are safe
    /// for shell interpolation. IP addresses from regex captures are generally safe,
    /// but user-provided paths or jail names should be validated.
    fn run_command(cmd_str: &str, env: &HashMap<String, String>) -> crate::Result<()> {
        let output = Command::new("sh")
            .args(["-c", cmd_str])
            .envs(env)
            .output()
            .map_err(|e| crate::Error::CommandFailed(format!("Failed to execute '{cmd_str}': {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(crate::Error::CommandFailed(format!(
                "Command '{}' failed (exit {}): {}",
                cmd_str, output.status, stderr
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "action.test.rs"]
mod tests;
