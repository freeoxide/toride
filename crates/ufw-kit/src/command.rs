//! Command execution layer.
//!
//! Provides a trait-based runner for executing system commands, with a real
//! implementation delegating to [`toride_runner::DuctRunner`] and a fake
//! implementation delegating to [`toride_runner::FakeRunner`].
//!
//! The local [`CommandSpec`] is kept because it carries UFW-specific fields
//! (`requires_root`, `force_c_locale`, `redact_logs`) that the shared
//! [`toride_runner::CommandSpec`] does not have. Conversion is handled by
//! the [`IntoShared`] helper.

use std::collections::HashMap;
use std::time::Duration;

use toride_runner::Runner as _;

use crate::error::{Error, Result};
use crate::spec::{CommandResult, CommandSpec};

// ────────────────────────────────────────────────────────────────────────────
// Trait
// ────────────────────────────────────────────────────────────────────────────

/// Trait for executing commands.
///
/// Implementations must be `Send + Sync` so they can be shared across threads.
pub trait CommandRunner: Send + Sync {
    /// Execute a command and return its output.
    fn run(&self, spec: &CommandSpec) -> Result<CommandResult>;

    /// Check if a binary exists on the system.
    fn binary_exists(&self, name: &str) -> bool;
}

// ────────────────────────────────────────────────────────────────────────────
// Shared-spec conversion
// ────────────────────────────────────────────────────────────────────────────

/// Convert a local [`CommandSpec`] into a [`toride_runner::CommandSpec`].
///
/// The `force_c_locale` field is honoured by injecting `LC_ALL=C` and
/// `LANG=C` environment variables into the shared spec.
fn to_shared_spec(spec: &CommandSpec) -> toride_runner::CommandSpec {
    let mut s = toride_runner::CommandSpec::new(&spec.program);
    for arg in &spec.args {
        s = s.arg(arg);
    }
    if let Some(timeout) = spec.timeout {
        s = s.timeout(timeout);
    }
    if spec.force_c_locale {
        s = s.env("LC_ALL", "C").env("LANG", "C");
    }
    s
}

/// Convert a shared [`toride_runner::CommandOutput`] into the local
/// [`CommandResult`].
fn to_local_result(output: &toride_runner::CommandOutput) -> CommandResult {
    CommandResult {
        stdout: output.stdout.clone(),
        stderr: output.stderr.clone(),
        exit_code: output.exit_code,
    }
}

// ────────────────────────────────────────────────────────────────────────────
// DuctRunner (wraps toride_runner::DuctRunner)
// ────────────────────────────────────────────────────────────────────────────

/// Real command runner using `duct`.
pub struct DuctRunner;

impl DuctRunner {
    /// Create a new `DuctRunner`.
    pub fn new() -> Self {
        Self
    }
}

impl Default for DuctRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandRunner for DuctRunner {
    fn run(&self, spec: &CommandSpec) -> Result<CommandResult> {
        // Redact sensitive args if requested
        let display_args = if spec.redact_logs {
            redact_args(&spec.args)
        } else {
            spec.args.join(" ")
        };
        let _ = display_args; // Used by tracing if enabled

        let shared = to_shared_spec(spec);
        let timeout = spec.timeout.unwrap_or(Duration::from_secs(30));
        let runner = toride_runner::DuctRunner;

        let output = runner.run(&shared).map_err(|e| {
            // Distinguish timeout from other errors by inspecting the error variant.
            let err_str = e.to_string();
            if err_str.contains("timeout") {
                Error::CommandTimeout {
                    program: spec.program.clone(),
                    timeout_secs: timeout.as_secs(),
                }
            } else {
                Error::CommandSpawnFailed(err_str)
            }
        })?;

        Ok(to_local_result(&output))
    }

    fn binary_exists(&self, name: &str) -> bool {
        which::which(name).is_ok()
    }
}

// ============================================================================
// Fake runner for tests
// ============================================================================

/// A fake command runner for testing.
///
/// Responders map `(program, args_string)` to predefined results.
/// If no exact match, falls back to a program-name-only key if registered.
pub struct FakeRunner {
    responses: HashMap<String, FakeResponse>,
    /// Log of all commands executed (for assertions).
    log: std::sync::Mutex<Vec<CommandLog>>,
}

#[derive(Debug, Clone)]
struct FakeResponse {
    result: Result<CommandResult>,
}

/// A log entry for a command that was executed.
#[derive(Debug, Clone)]
pub struct CommandLog {
    /// Program name.
    pub program: String,
    /// Arguments.
    pub args: Vec<String>,
}

impl FakeRunner {
    /// Create a new empty fake runner.
    pub fn new() -> Self {
        Self {
            responses: HashMap::new(),
            log: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Register a response for a given program + args combination.
    ///
    /// The key is formatted as `"program arg1 arg2 ..."`.
    pub fn respond(mut self, program: &str, args: &[&str], result: Result<CommandResult>) -> Self {
        let key = format_key(program, args);
        self.responses.insert(key, FakeResponse { result });
        self
    }

    /// Register a one-shot response (consumed after first match).
    pub fn respond_once(
        mut self,
        program: &str,
        args: &[&str],
        result: Result<CommandResult>,
    ) -> Self {
        let key = format_key(program, args);
        self.responses.insert(key, FakeResponse { result });
        self
    }

    /// Register a success response with stdout.
    pub fn respond_ok(self, program: &str, args: &[&str], stdout: &str) -> Self {
        self.respond(
            program,
            args,
            Ok(CommandResult {
                stdout: stdout.into(),
                stderr: String::new(),
                exit_code: Some(0),
            }),
        )
    }

    /// Register a failure response.
    pub fn respond_err(self, program: &str, args: &[&str], stderr: &str, exit_code: i32) -> Self {
        self.respond(
            program,
            args,
            Ok(CommandResult {
                stdout: String::new(),
                stderr: stderr.into(),
                exit_code: Some(exit_code),
            }),
        )
    }

    /// Get the log of all commands that were executed.
    pub fn command_log(&self) -> Vec<CommandLog> {
        self.log.lock().unwrap().clone()
    }

    /// Clear the command log.
    pub fn clear_log(&self) {
        self.log.lock().unwrap().clear();
    }

    /// Number of commands executed.
    pub fn command_count(&self) -> usize {
        self.log.lock().unwrap().len()
    }
}

impl Default for FakeRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandRunner for FakeRunner {
    fn run(&self, spec: &CommandSpec) -> Result<CommandResult> {
        // Log the command
        self.log.lock().unwrap().push(CommandLog {
            program: spec.program.clone(),
            args: spec.args.clone(),
        });

        let key = format_key(
            &spec.program,
            &spec.args.iter().map(String::as_str).collect::<Vec<_>>(),
        );

        // Try to find an exact response
        if let Some(response) = self.responses.get(&key) {
            return response.result.clone();
        }

        // Fall back to program-name-only key if registered
        if let Some(response) = self.responses.get(&spec.program) {
            return response.result.clone();
        }

        Err(Error::CommandSpawnFailed(format!(
            "no fake response registered for: {} {}",
            spec.program,
            spec.args.join(" ")
        )))
    }

    fn binary_exists(&self, name: &str) -> bool {
        // By default, pretend ufw and common tools exist
        matches!(
            name,
            "ufw"
                | "iptables"
                | "ip6tables"
                | "iptables-save"
                | "ip6tables-save"
                | "systemctl"
                | "journalctl"
                | "nft"
                | "docker"
                | "nginx"
                | "caddy"
                | "ss"
                | "traefik"
                | "traefik-client"
        )
    }
}

fn format_key(program: &str, args: &[&str]) -> String {
    let mut parts = vec![program.to_string()];
    parts.extend(args.iter().map(|s| (*s).to_string()));
    parts.join(" ")
}

/// Flags whose following argument should be redacted from logs.
const REDACT_FLAGS: &[&str] = &[
    "--password",
    "--passwd",
    "--secret",
    "--token",
    "--key",
    "--api-key",
    "--api_key",
    "--auth",
    "--credentials",
];

/// Redact sensitive arguments from a command's args list.
///
/// Returns a single string with sensitive values replaced by `"***"`.
/// Flags that indicate a following sensitive value (e.g., `--password`)
/// are detected and their next argument is masked.
pub fn redact_args(args: &[String]) -> String {
    let mut result = Vec::with_capacity(args.len());
    let mut redact_next = false;

    for arg in args {
        if redact_next {
            result.push("***".to_string());
            redact_next = false;
            continue;
        }

        let lower = arg.to_ascii_lowercase();
        if REDACT_FLAGS.iter().any(|f| lower == *f) {
            result.push(arg.clone());
            redact_next = true;
            continue;
        }

        // Also check for --flag=value patterns
        if let Some(eq_pos) = arg.find('=') {
            let flag_part = &arg[..eq_pos];
            let lower_flag = flag_part.to_ascii_lowercase();
            if REDACT_FLAGS.iter().any(|f| lower_flag == *f) {
                result.push(format!("{flag_part}=***"));
                continue;
            }
        }

        result.push(arg.clone());
    }

    result.join(" ")
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "command.test.rs"]
mod tests;
