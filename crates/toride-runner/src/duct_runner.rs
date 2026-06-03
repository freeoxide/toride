//! Real command execution via the `duct` crate.
//!
//! [`DuctRunner`] is the production implementation of [`Runner`](crate::Runner).
//! It spawns subprocesses, captures stdout/stderr, and respects timeouts.

use std::time::Duration;

use crate::error::{Error, Result};
use crate::output::CommandOutput;
use crate::runner::Runner;
use crate::spec::CommandSpec;

/// Default command timeout in seconds when none is specified.
const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// A [`Runner`] implementation that executes commands via the `duct` crate.
///
/// # Examples
///
/// ```rust,ignore
/// use toride_runner::{CommandSpec, DuctRunner, Runner};
///
/// let runner = DuctRunner;
/// let spec = CommandSpec::new("echo").arg("hello");
/// let output = runner.run(&spec)?;
/// assert!(output.success);
/// assert_eq!(output.stdout_trimmed(), "hello");
/// ```
pub struct DuctRunner;

impl Runner for DuctRunner {
    fn run(&self, spec: &CommandSpec) -> Result<CommandOutput> {
        let mut cmd = duct::cmd(&spec.program, &spec.args);

        // Apply working directory if specified.
        if let Some(ref cwd) = spec.cwd {
            cmd = cmd.dir(cwd);
        }

        // Apply environment variables.
        for (key, value) in &spec.env {
            cmd = cmd.env(key, value);
        }

        // Pipe stdin data if provided.
        if let Some(ref stdin_data) = spec.stdin {
            cmd = cmd.stdin_bytes(stdin_data.as_bytes());
        }

        let timeout = spec
            .timeout
            .unwrap_or(Duration::from_secs(DEFAULT_TIMEOUT_SECS));

        // Spawn with stdout/stderr capture. Use unchecked so non-zero exit
        // does not immediately error — we capture it in CommandOutput.
        let handle = cmd
            .stdout_capture()
            .stderr_capture()
            .unchecked()
            .start()
            .map_err(|e| Error::Io(format!("failed to spawn '{}': {e}", spec.program)))?;

        // Wait with timeout.
        let output = match handle.wait_timeout(timeout) {
            Ok(Some(output)) => output.clone(),
            Ok(None) => {
                // Timeout expired — kill the process tree.
                let _ = handle.kill();
                let _ = handle.wait();
                return Err(Error::CommandTimeout {
                    program: spec.program.clone(),
                    args: spec.args.clone(),
                    timeout,
                });
            }
            Err(e) => {
                return Err(Error::CommandFailed {
                    program: spec.program.clone(),
                    args: spec.args.join(" "),
                    exit_code: None,
                    stderr: e.to_string(),
                });
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let exit_code = output.status.code();

        tracing::debug!(
            program = %spec.program,
            exit_code = ?exit_code,
            "command completed"
        );

        Ok(CommandOutput::new(stdout, stderr, exit_code))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn echo_hello() {
        let runner = DuctRunner;
        let spec = CommandSpec::new("echo").arg("hello");
        let output = runner.run(&spec).unwrap();
        assert!(output.success);
        assert_eq!(output.stdout_trimmed(), "hello");
    }

    #[test]
    fn failed_command() {
        let runner = DuctRunner;
        let spec = CommandSpec::new("false");
        let output = runner.run(&spec).unwrap();
        assert!(!output.success);
    }

    #[test]
    fn timeout_expires() {
        let runner = DuctRunner;
        let spec = CommandSpec::new("sleep")
            .arg("10")
            .timeout(Duration::from_millis(50));
        let result = runner.run(&spec);
        assert!(result.is_err());
    }

    #[test]
    fn stdin_piped() {
        let runner = DuctRunner;
        let spec = CommandSpec::new("cat").stdin("piped content");
        let output = runner.run(&spec).unwrap();
        assert_eq!(output.stdout_trimmed(), "piped content");
    }

    #[test]
    fn env_passed() {
        let runner = DuctRunner;
        let spec = CommandSpec::new("env").env("TORIDE_TEST_VAR", "42");
        let output = runner.run(&spec).unwrap();
        assert!(output.stdout.contains("TORIDE_TEST_VAR=42"));
    }
}
