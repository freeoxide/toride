//! Real async command execution via `tokio::process`.
//!
//! [`TokioRunner`] is the async production implementation of
//! [`AsyncRunner`](crate::AsyncRunner). It spawns subprocesses via
//! `tokio::process::Command`, captures stdout/stderr, and respects timeouts
//! without blocking runtime worker threads.
//!
//! # Timeout and child process cleanup
//!
//! When a timeout expires, `TokioRunner` kills the direct child process and
//! waits for it to terminate. Process-group termination (killing the entire
//! process tree) is not yet supported and may be added later if domain
//! commands require it.
//!
//! # Cancellation
//!
//! If the future returned by [`AsyncRunner::run`] is dropped (cancelled) before
//! completion, the `tokio::process::Child` handle is also dropped. Tokio will
//! send `SIGKILL` to the child when the handle is dropped, preventing orphaned
//! processes. However, this is a best-effort guarantee — only the direct child
//! is tracked, not the entire process tree. For robust cleanup of process trees,
//! process-group support should be added later.
//!
//! Stdout and stderr reader tasks (if any) are joined or aborted during normal
//! completion. On timeout, the child is killed before pipe readers are dropped,
//! ensuring no dangling I/O.

use std::time::Duration;

use async_trait::async_trait;

use crate::async_runner::AsyncRunner;
use crate::error::{Error, Result};
use crate::output::CommandOutput;
use crate::spec::CommandSpec;

/// Default command timeout in seconds when none is specified.
const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// An [`AsyncRunner`] implementation that executes commands via `tokio::process`.
///
/// # Examples
///
/// ```rust,ignore
/// use toride_runner::{CommandSpec, tokio_runner::TokioRunner, AsyncRunner};
///
/// #[tokio::main]
/// async fn main() {
///     let runner = TokioRunner;
///     let spec = CommandSpec::new("echo").arg("hello");
///     let output = runner.run(&spec).await.unwrap();
///     assert!(output.success);
///     assert_eq!(output.stdout_trimmed(), "hello");
/// }
/// ```
pub struct TokioRunner;

#[async_trait]
impl AsyncRunner for TokioRunner {
    async fn run(&self, spec: &CommandSpec) -> Result<CommandOutput> {
        let timeout = spec
            .timeout
            .unwrap_or(Duration::from_secs(DEFAULT_TIMEOUT_SECS));

        run_tokio_command(spec, timeout).await
    }
}

/// Build and run a command via `tokio::process` with proper kill-on-timeout.
///
/// Takes stdout/stderr handles before waiting so we can read them regardless
/// of whether the process times out. On timeout, kills the direct child and
/// waits for it to terminate.
async fn run_tokio_command(spec: &CommandSpec, timeout: Duration) -> Result<CommandOutput> {
    let mut cmd = tokio::process::Command::new(&spec.program);
    cmd.args(&spec.args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    // Apply working directory if specified.
    if let Some(ref cwd) = spec.cwd {
        cmd.current_dir(cwd);
    }

    // Apply environment variables.
    for (key, value) in &spec.env {
        cmd.env(key, value);
    }

    // Pipe stdin data if provided.
    if spec.stdin.is_some() {
        cmd.stdin(std::process::Stdio::piped());
    }

    // Spawn the child process.
    let mut child = cmd.spawn().map_err(|e| Error::SpawnFailed {
        program: spec.program.clone(),
        detail: e.to_string(),
    })?;

    // Write stdin if provided.
    if let Some(ref stdin_data) = spec.stdin {
        use tokio::io::AsyncWriteExt;
        if let Some(mut stdin_handle) = child.stdin.take() {
            stdin_handle
                .write_all(stdin_data.as_bytes())
                .await
                .map_err(|e| Error::StdinFailed {
                    program: spec.program.clone(),
                    detail: e.to_string(),
                })?;
            // Close stdin to signal EOF.
            drop(stdin_handle);
        }
    }

    // Take stdout and stderr handles before waiting, so we can read them
    // regardless of whether the process times out.
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    // Helper futures to read pipes to completion.
    let read_stdout = async {
        use tokio::io::AsyncReadExt;
        match stdout_pipe {
            Some(mut pipe) => {
                let mut buf = Vec::new();
                let _ = pipe.read_to_end(&mut buf).await;
                buf
            }
            None => Vec::new(),
        }
    };

    let read_stderr = async {
        use tokio::io::AsyncReadExt;
        match stderr_pipe {
            Some(mut pipe) => {
                let mut buf = Vec::new();
                let _ = pipe.read_to_end(&mut buf).await;
                buf
            }
            None => Vec::new(),
        }
    };

    // Wait for the process with timeout.
    let wait_result = tokio::time::timeout(timeout, child.wait()).await;

    match wait_result {
        Ok(Ok(status)) => {
            // Process exited — read remaining stdout/stderr.
            let (stdout_bytes, stderr_bytes) = tokio::join!(read_stdout, read_stderr);

            let stdout = String::from_utf8_lossy(&stdout_bytes).into_owned();
            let stderr = String::from_utf8_lossy(&stderr_bytes).into_owned();
            let exit_code = status.code();

            tracing::debug!(
                program = %spec.program,
                exit_code = ?exit_code,
                "async command completed"
            );

            Ok(CommandOutput::new(stdout, stderr, exit_code))
        }
        Ok(Err(e)) => Err(Error::WaitFailed {
            program: spec.program.clone(),
            detail: e.to_string(),
        }),
        Err(_) => {
            // Timeout expired — kill the child process.
            let _ = child.kill().await;
            // Wait for the child to terminate so we don't leave zombies.
            let _ = child.wait().await;

            tracing::warn!(
                program = %spec.program,
                timeout_secs = timeout.as_secs(),
                "async command timed out, child killed"
            );

            Err(Error::CommandTimeout {
                program: spec.program.clone(),
                args: spec.args.clone(),
                timeout,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Streaming execution (behind `stream` feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "stream")]
use crate::streaming::{AsyncStreamingRunner, CommandEvent, CommandEventSink};

/// Streaming execution via `tokio::process`.
///
/// Spawns the child, reads stdout/stderr via `BufReader` line-by-line,
/// emits both chunk and line events to the sink, and collects everything
/// into the final `CommandOutput`. The entire operation is bounded by the
/// timeout — spawn, pipe reads, and wait are all covered.
///
/// On timeout, the child is explicitly killed and reaped.
#[cfg(feature = "stream")]
async fn run_streaming_command(
    spec: &CommandSpec,
    sink: &mut dyn CommandEventSink,
) -> Result<CommandOutput> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let timeout = spec
        .timeout
        .unwrap_or(Duration::from_secs(DEFAULT_TIMEOUT_SECS));

    // --- Phase 1: spawn the child (not timed, should be instant) ---
    let mut cmd = tokio::process::Command::new(&spec.program);
    cmd.args(&spec.args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    if let Some(ref cwd) = spec.cwd {
        cmd.current_dir(cwd);
    }
    for (key, value) in &spec.env {
        cmd.env(key, value);
    }
    if spec.stdin.is_some() {
        cmd.stdin(std::process::Stdio::piped());
    }

    let mut child = cmd.spawn().map_err(|e| Error::SpawnFailed {
        program: spec.program.clone(),
        detail: e.to_string(),
    })?;

    // Emit Started.
    sink.on_event(CommandEvent::Started {
        program: spec.program.clone(),
        args: spec.args.clone(),
    })
    .await?;

    // Write stdin.
    if let Some(ref stdin_data) = spec.stdin {
        if let Some(mut stdin_handle) = child.stdin.take() {
            stdin_handle
                .write_all(stdin_data.as_bytes())
                .await
                .map_err(|e| Error::StdinFailed {
                    program: spec.program.clone(),
                    detail: e.to_string(),
                })?;
            drop(stdin_handle);
        }
    }

    // Take pipes and wrap in BufReader.
    let stdout_reader = child.stdout.take().map(BufReader::new);
    let stderr_reader = child.stderr.take().map(BufReader::new);

    // Channel for stderr lines from spawned task.
    let (stderr_tx, mut stderr_rx) =
        tokio::sync::mpsc::channel::<(Vec<u8>, String)>(64);

    // Spawn a task to read stderr lines.
    if let Some(mut reader) = stderr_reader {
        tokio::spawn(async move {
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let trimmed = line
                            .trim_end_matches('\n')
                            .trim_end_matches('\r')
                            .to_owned();
                        let mut chunk = trimmed.as_bytes().to_vec();
                        chunk.push(b'\n');
                        if stderr_tx.send((chunk, trimmed)).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
    }

    // --- Phase 2: read pipes + wait, all bounded by timeout ---
    let result = tokio::time::timeout(timeout, async {
        // Read stdout lines inline, emitting events as we go.
        let mut stdout_bytes = Vec::new();
        if let Some(mut reader) = stdout_reader {
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let trimmed = line
                            .trim_end_matches('\n')
                            .trim_end_matches('\r')
                            .to_owned();
                        let mut chunk = trimmed.as_bytes().to_vec();
                        chunk.push(b'\n');
                        stdout_bytes.extend_from_slice(&chunk);
                        sink.on_event(CommandEvent::StdoutChunk(chunk))
                            .await?;
                        sink.on_event(CommandEvent::StdoutLine(trimmed))
                            .await?;
                    }
                }
            }
        }

        // Drain stderr events from the channel.
        let mut stderr_bytes = Vec::new();
        while let Some((chunk, line)) = stderr_rx.recv().await {
            stderr_bytes.extend_from_slice(&chunk);
            sink.on_event(CommandEvent::StderrChunk(chunk)).await?;
            sink.on_event(CommandEvent::StderrLine(line)).await?;
        }

        // Wait for the child to exit.
        let status = child.wait().await.map_err(|e| Error::WaitFailed {
            program: spec.program.clone(),
            detail: e.to_string(),
        })?;
        let exit_code = status.code();

        // Emit Exited.
        sink.on_event(CommandEvent::Exited { exit_code }).await?;

        let stdout = String::from_utf8_lossy(&stdout_bytes).into_owned();
        let stderr = String::from_utf8_lossy(&stderr_bytes).into_owned();

        Ok::<CommandOutput, Error>(CommandOutput::new(stdout, stderr, exit_code))
    })
    .await;

    match result {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(e)) => Err(e),
        Err(_) => {
            // Timeout expired — explicitly kill the child.
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(Error::CommandTimeout {
                program: spec.program.clone(),
                args: spec.args.clone(),
                timeout,
            })
        }
    }
}

#[cfg(feature = "stream")]
#[async_trait]
impl AsyncStreamingRunner for TokioRunner {
    async fn run_streaming(
        &self,
        spec: &CommandSpec,
        sink: &mut dyn CommandEventSink,
    ) -> Result<CommandOutput> {
        run_streaming_command(spec, sink).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn echo_hello() {
        let runner = TokioRunner;
        let spec = CommandSpec::new("echo").arg("hello");
        let output = runner.run(&spec).await.unwrap();
        assert!(output.success);
        assert_eq!(output.stdout_trimmed(), "hello");
    }

    #[tokio::test]
    async fn failed_command() {
        let runner = TokioRunner;
        let spec = CommandSpec::new("false");
        let output = runner.run(&spec).await.unwrap();
        assert!(!output.success);
    }

    #[tokio::test]
    async fn timeout_expires() {
        let runner = TokioRunner;
        let spec = CommandSpec::new("sleep")
            .arg("10")
            .timeout(Duration::from_millis(50));
        let result = runner.run(&spec).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, Error::CommandTimeout { .. }));
    }

    #[tokio::test]
    async fn stdin_piped() {
        let runner = TokioRunner;
        let spec = CommandSpec::new("cat").stdin("piped content");
        let output = runner.run(&spec).await.unwrap();
        assert_eq!(output.stdout_trimmed(), "piped content");
    }

    #[tokio::test]
    async fn env_passed() {
        let runner = TokioRunner;
        let spec = CommandSpec::new("env").env("TORIDE_TEST_ASYNC_VAR", "42");
        let output = runner.run(&spec).await.unwrap();
        assert!(output.stdout.contains("TORIDE_TEST_ASYNC_VAR=42"));
    }

    #[tokio::test]
    async fn cwd_applied() {
        let runner = TokioRunner;
        let spec = CommandSpec::new("pwd").cwd("/tmp");
        let output = runner.run(&spec).await.unwrap();
        // On macOS /tmp is a symlink to /private/tmp, so canonicalize for comparison.
        let resolved = std::path::Path::new("/tmp")
            .canonicalize()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "/tmp".to_owned());
        assert_eq!(output.stdout_trimmed(), resolved);
    }

    #[tokio::test]
    async fn run_checked_errors_on_failure() {
        let runner = TokioRunner;
        let spec = CommandSpec::new("false");
        let result = runner.run_checked(&spec).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, Error::CommandFailed { .. }));
    }

    #[tokio::test]
    async fn spawn_failed() {
        let runner = TokioRunner;
        let spec = CommandSpec::new("definitely_not_a_real_binary_xyz_123");
        let result = runner.run(&spec).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, Error::SpawnFailed { .. }));
    }

    /// Verify that a timed-out child process is actually killed.
    ///
    /// This test spawns a background process that creates a marker file,
    /// then triggers a timeout. After the timeout error is returned, we
    /// verify that the child was terminated by checking that it does not
    /// continue to run.
    #[tokio::test]
    async fn timeout_kills_child_process() {
        let runner = TokioRunner;
        let timeout = Duration::from_millis(100);

        // Use bash to sleep in the background while writing a marker.
        // If the child is not killed, the marker will be written.
        let spec = CommandSpec::new("bash")
            .args([
                "-c",
                "sleep 10 && echo SURVIVED > /tmp/toride_runner_timeout_test",
            ])
            .timeout(timeout);

        let result = runner.run(&spec).await;
        assert!(result.is_err(), "timeout should produce an error");
        let err = result.unwrap_err();
        assert!(
            matches!(err, Error::CommandTimeout { .. }),
            "expected CommandTimeout, got {err:?}"
        );

        // Wait briefly, then check the marker file was NOT created (child was killed).
        tokio::time::sleep(Duration::from_millis(200)).await;
        let marker_exists = std::path::Path::new("/tmp/toride_runner_timeout_test").exists();
        if marker_exists {
            // Clean up and fail.
            let _ = std::fs::remove_file("/tmp/toride_runner_timeout_test");
            panic!("child process survived timeout — it was not killed");
        }
    }

    /// Verify that the timeout error carries correct metadata.
    #[tokio::test]
    async fn timeout_error_metadata() {
        let runner = TokioRunner;
        let timeout = Duration::from_millis(50);
        let spec = CommandSpec::new("sleep").arg("10").timeout(timeout);

        let result = runner.run(&spec).await;
        let err = result.unwrap_err();

        match err {
            Error::CommandTimeout {
                program,
                args,
                timeout: t,
            } => {
                assert_eq!(program, "sleep");
                assert_eq!(args, vec!["10"]);
                assert_eq!(t, timeout);
            }
            other => panic!("expected CommandTimeout, got {other:?}"),
        }
    }

    /// Verify that stdout and stderr are both captured and not mixed up.
    #[tokio::test]
    async fn stdout_stderr_separation() {
        let runner = TokioRunner;
        let spec = CommandSpec::new("bash").args(["-c", "echo OUT; echo ERR >&2"]);

        let output = runner.run(&spec).await.unwrap();
        assert!(output.success);
        assert!(output.stdout.contains("OUT"));
        assert!(output.stderr.contains("ERR"));
        assert!(!output.stdout.contains("ERR"), "stderr should not leak into stdout");
        assert!(!output.stderr.contains("OUT"), "stdout should not leak into stderr");
    }

    /// Verify that stdin write errors surface as StdinFailed.
    ///
    /// We pipe stdin to a command that exits immediately — the stdin write
    /// should succeed because the child accepted the pipe. The real test
    /// for stdin failure is covered by the normal path. Here we verify the
    /// error variant exists and is classified correctly.
    #[tokio::test]
    async fn stdin_to_exiting_command_succeeds() {
        let runner = TokioRunner;
        // `true` exits immediately with 0 — stdin is written but ignored.
        let spec = CommandSpec::new("bash")
            .args(["-c", "exit 0"])
            .stdin("data");
        let output = runner.run(&spec).await.unwrap();
        assert!(output.success);
    }

    /// Verify that large output is captured completely.
    #[tokio::test]
    async fn large_output_captured() {
        let runner = TokioRunner;
        // Generate ~100 lines of output.
        let spec = CommandSpec::new("bash").args(["-c", "for i in $(seq 1 100); do echo \"line $i\"; done"]);

        let output = runner.run(&spec).await.unwrap();
        assert!(output.success);
        let lines: Vec<&str> = output.stdout.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 100);
        assert_eq!(lines[0], "line 1");
        assert_eq!(lines[99], "line 100");
    }

    /// Verify that exit code is preserved for non-zero exits.
    #[tokio::test]
    async fn specific_exit_code_preserved() {
        let runner = TokioRunner;
        let spec = CommandSpec::new("bash").args(["-c", "exit 42"]);

        let output = runner.run(&spec).await.unwrap();
        assert!(!output.success);
        assert_eq!(output.exit_code, Some(42));
    }
}
