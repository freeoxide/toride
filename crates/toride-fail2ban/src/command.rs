//! Centralized command execution module.
//!
//! All external process spawning in this crate **must** go through the
//! [`Runner`] trait defined here. No ad-hoc `std::process::Command` calls are
//! allowed elsewhere in the codebase.
//!
//! Two implementations are provided:
//!
//! - [`DuctRunner`] -- production implementation backed by the `duct` crate.
//! - [`FakeRunner`] -- test double that records calls and returns pre-canned
//!   responses.
//!
//! # Migration note
//!
//! This module re-exports [`CommandOutput`] and [`find_binary`] from the shared
//! `toride-runner` crate. The local [`Runner`] trait is kept for backward
//! compatibility with existing call sites that use `runner.run("cmd", &["args"])`.
//!
//! # Security
//!
//! Arguments are always passed as arrays (no shell string concatenation).
//! Sensitive values containing "password", "token", "key", or "secret" are
//! redacted in log output.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
#[cfg(feature = "client")]
use std::sync::mpsc;
use std::time::Duration;

use crate::Error;
use crate::Result;

// ---------------------------------------------------------------------------
// Re-exports from toride-runner
// ---------------------------------------------------------------------------

pub use toride_runner::CommandOutput;
pub use toride_runner::CommandSpec;

/// Locate a binary on the system `$PATH`.
///
/// Delegates to [`toride_runner::discovery::find_binary`].
///
/// Returns [`Error::NotFound`] if the binary cannot be found.
pub fn find_binary(name: &str) -> Result<PathBuf> {
    toride_runner::discovery::find_binary(name).map_err(|_| Error::NotFound(name.to_string()))
}

// ---------------------------------------------------------------------------
// Runner trait
// ---------------------------------------------------------------------------

/// Trait for executing external commands.
///
/// Every subprocess in this crate is spawned through a `Runner` implementation.
/// This makes the entire call stack testable via [`FakeRunner`] and keeps
/// logging / dry-run / timeout behaviour in one place.
pub trait Runner: Send + Sync {
    /// Execute `program` with `args`, waiting up to the runner's default timeout.
    fn run(&self, program: &str, args: &[&str]) -> Result<CommandOutput>;

    /// Execute `program` with `args`, waiting at most `timeout`.
    fn run_with_timeout(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<CommandOutput>;

    /// Whether the runner is in dry-run mode (no real commands executed).
    fn dry_run(&self) -> bool;

    /// Enable or disable dry-run mode.
    fn set_dry_run(&mut self, dry_run: bool);
}

// ---------------------------------------------------------------------------
// Redaction helper
// ---------------------------------------------------------------------------

/// Keywords that mark an argument value as sensitive.
#[cfg(feature = "client")]
const SENSITIVE_KEYWORDS: &[&str] = &["password", "token", "key", "secret"];

/// Redact any argument whose value contains a sensitive keyword.
///
/// Returns a formatted string suitable for logging.
#[cfg(feature = "client")]
fn redacted_cmd_str(program: &str, args: &[&str]) -> String {
    let mut parts = vec![program.to_string()];
    for arg in args {
        let lower = arg.to_ascii_lowercase();
        if SENSITIVE_KEYWORDS.iter().any(|kw| lower.contains(kw)) {
            parts.push("***".to_string());
        } else {
            parts.push((*arg).to_string());
        }
    }
    parts.join(" ")
}

// ---------------------------------------------------------------------------
// DuctRunner
// ---------------------------------------------------------------------------

/// Production command runner backed by the `duct` crate.
///
/// Uses [`duct::cmd`] for execution. Timeouts are implemented by spawning the
/// child via `start()`, then waiting on a channel with a deadline. If the
/// deadline expires the child is killed.
///
/// Only available when the `client` feature is enabled.
#[cfg(feature = "client")]
pub struct DuctRunner {
    /// Default timeout applied by [`Runner::run`].
    default_timeout: Duration,
    /// When `true`, commands are logged but not executed.
    dry_run: bool,
}

#[cfg(feature = "client")]
impl DuctRunner {
    /// Create a new runner with a 30-second default timeout.
    #[must_use]
    pub fn new() -> Self {
        Self::with_timeout(Duration::from_secs(30))
    }

    /// Create a new runner with the given default timeout.
    #[must_use]
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            default_timeout: timeout,
            dry_run: false,
        }
    }

    /// Execute a command with an explicit timeout using duct.
    ///
    /// The child is spawned with `stdout_capture` / `stderr_capture` and
    /// `unchecked()` so that we can inspect output even on non-zero exit.
    /// A timeout is enforced by waiting on a channel with `recv_timeout`.
    fn execute(program: &str, args: &[&str], timeout: Duration) -> Result<CommandOutput> {
        let cmd_str = redacted_cmd_str(program, args);
        tracing::debug!(cmd = %cmd_str, "executing");

        // Spawn the child.  `unchecked()` prevents duct from turning a
        // non-zero exit status into an `io::Error`, which lets us inspect the
        // output ourselves.
        let handle = duct::cmd(program, args)
            .stdout_capture()
            .stderr_capture()
            .unchecked()
            .start()
            .map_err(|e| Error::CommandFailed(format!("failed to spawn {program}: {e}")))?;

        // Channel for the owned output of `handle.wait()`.
        let (tx, rx) = mpsc::channel();

        std::thread::spawn(move || {
            let result = handle.wait().cloned();
            let _ = tx.send(result);
        });

        // Wait up to the timeout for the child to finish.
        let raw_output = rx
            .recv_timeout(timeout)
            .map_err(|_| Error::CommandTimeout(timeout))?
            .map_err(|e| Error::CommandFailed(format!("wait failed for {program}: {e}")))?;

        let stdout = String::from_utf8_lossy(&raw_output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&raw_output.stderr).into_owned();
        let exit_code = raw_output.status.code();
        let success = raw_output.status.success();

        let result = CommandOutput::new(stdout, stderr, exit_code);

        if !success {
            tracing::warn!(
                cmd = %cmd_str,
                exit = ?exit_code,
                stderr = %result.stderr.trim(),
                "command failed"
            );
        }

        Ok(result)
    }
}

#[cfg(feature = "client")]
impl Default for DuctRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "client")]
impl Runner for DuctRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<CommandOutput> {
        let cmd_str = redacted_cmd_str(program, args);

        if self.dry_run {
            tracing::info!(cmd = %cmd_str, "[dry-run]");
            return Ok(CommandOutput::new(String::new(), String::new(), Some(0)));
        }

        Self::execute(program, args, self.default_timeout)
    }

    fn run_with_timeout(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<CommandOutput> {
        let cmd_str = redacted_cmd_str(program, args);

        if self.dry_run {
            tracing::info!(cmd = %cmd_str, timeout = ?timeout, "[dry-run]");
            return Ok(CommandOutput::new(String::new(), String::new(), Some(0)));
        }

        Self::execute(program, args, timeout)
    }

    fn dry_run(&self) -> bool {
        self.dry_run
    }

    fn set_dry_run(&mut self, dry_run: bool) {
        self.dry_run = dry_run;
    }
}

// ---------------------------------------------------------------------------
// FakeRunner
// ---------------------------------------------------------------------------

/// Test double that records invocations and returns pre-configured responses.
///
/// # Example
///
/// ```ignore
/// let mut fake = FakeRunner::new();
/// fake.with_response("echo", &["hello"], CommandOutput::new(String::new(), String::new(), Some(0)));
///
/// let out = fake.run("echo", &["hello"]).unwrap();
/// assert!(out.success);
/// assert_eq!(fake.calls().len(), 1);
/// ```
pub struct FakeRunner {
    /// Pre-configured responses keyed by `"{program} {args.join(" ")}"`.
    responses: HashMap<String, CommandOutput>,
    /// Dry-run flag (mirrors the trait method).
    dry_run: bool,
    /// Ordered record of all calls made through [`Runner::run`] and
    /// [`Runner::run_with_timeout`].
    calls: Mutex<Vec<(String, Vec<String>)>>,
}

impl FakeRunner {
    /// Create a `FakeRunner` with no pre-configured responses.
    #[must_use]
    pub fn new() -> Self {
        Self {
            responses: HashMap::new(),
            dry_run: false,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Register a canned response for a specific `(program, args)` pair.
    ///
    /// Uses the builder pattern so multiple responses can be chained.
    pub fn with_response(
        &mut self,
        program: &str,
        args: &[&str],
        output: CommandOutput,
    ) -> &mut Self {
        let key = format!("{program} {}", args.join(" "));
        self.responses.insert(key, output);
        self
    }

    /// Return a snapshot of all recorded calls in order.
    ///
    /// Each entry is `(program, args)`.
    ///
    /// # Panics
    ///
    /// Panics if the internal calls mutex is poisoned (i.e. another thread
    /// panicked while holding the lock).
    pub fn calls(&self) -> Vec<(String, Vec<String>)> {
        self.calls
            .lock()
            .expect("FakeRunner calls mutex should not be poisoned")
            .clone()
    }

    /// Look up the canned response for a given program/args pair.
    fn lookup(&self, program: &str, args: &[&str]) -> CommandOutput {
        let key = format!("{program} {}", args.join(" "));
        self.responses
            .get(&key)
            .cloned()
            .unwrap_or_else(|| CommandOutput::new(String::new(), String::new(), Some(0)))
    }

    /// Record a call in the internal log.
    fn record(&self, program: &str, args: &[&str]) {
        self.calls
            .lock()
            .expect("FakeRunner calls mutex should not be poisoned")
            .push((
                program.to_string(),
                args.iter().map(|s| (*s).to_string()).collect(),
            ));
    }
}

impl Default for FakeRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl Runner for FakeRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<CommandOutput> {
        self.record(program, args);
        Ok(self.lookup(program, args))
    }

    fn run_with_timeout(
        &self,
        program: &str,
        args: &[&str],
        _timeout: Duration,
    ) -> Result<CommandOutput> {
        self.record(program, args);
        Ok(self.lookup(program, args))
    }

    fn dry_run(&self) -> bool {
        self.dry_run
    }

    fn set_dry_run(&mut self, dry_run: bool) {
        self.dry_run = dry_run;
    }
}

#[cfg(test)]
#[path = "command.test.rs"]
mod tests;
