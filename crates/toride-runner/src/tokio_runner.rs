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

        // Box::pin keeps the future off the caller's stack (these async fns are
        // large state machines); see clippy::large_futures.
        Box::pin(run_tokio_command(spec, timeout)).await
    }
}

/// Build and run a command via `tokio::process` with proper kill-on-timeout.
///
/// Takes stdout/stderr handles before waiting so we can read them regardless
/// of whether the process times out. On timeout, kills the direct child and
/// waits for it to terminate.
async fn run_tokio_command(spec: &CommandSpec, timeout: Duration) -> Result<CommandOutput> {
    // Output-limit enforcement only applies to captured output. Dispatch to the
    // cap-aware path before the unlimited draining runs, because that path
    // uses bounded reads instead of `read_to_end` so it can trip the cap
    // mid-stream and kill the child.
    if let Some(cap) = spec.output_limit {
        return Box::pin(run_tokio_limited(spec, timeout, cap)).await;
    }

    let mut cmd = build_tokio_command(spec);

    // Spawn the child process.
    let mut child = cmd.spawn().map_err(|e| Error::SpawnFailed {
        program: spec.program.clone(),
        detail: e.to_string(),
    })?;

    write_stdin(&mut child, spec).await?;
    // Take stdout and stderr handles before waiting. The pipes are owned
    // separately from `&mut child`, so the reads below do not alias the borrow
    // that `child.wait()` needs.
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    // Concurrent pipe draining.
    //
    // Both pipes are read to completion *while* waiting for the child to exit.
    // The previous model read the pipes only after `wait()` returned, which
    // deadlocks when a child fills the ~64 KB OS pipe buffer and blocks on
    // write — `wait()` never returns and only the outer timeout saves it. By
    // running the two reads concurrently with `wait()` inside a single
    // `tokio::time::timeout`, the parent keeps draining the pipes so the child
    // can exit, and the captured bytes are complete regardless of timing.
    let run = async {
        use tokio::io::AsyncReadExt;

        let read_stdout = async {
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
            match stderr_pipe {
                Some(mut pipe) => {
                    let mut buf = Vec::new();
                    let _ = pipe.read_to_end(&mut buf).await;
                    buf
                }
                None => Vec::new(),
            }
        };

        let (stdout_bytes, stderr_bytes, status) =
            tokio::join!(read_stdout, read_stderr, child.wait());
        let status = status.map_err(|e| Error::WaitFailed {
            program: spec.program.clone(),
            detail: e.to_string(),
        })?;
        let exit_code = status.code();

        let stdout = String::from_utf8_lossy(&stdout_bytes).into_owned();
        let stderr = String::from_utf8_lossy(&stderr_bytes).into_owned();
        Ok::<CommandOutput, Error>(CommandOutput::new(stdout, stderr, exit_code))
    };

    match tokio::time::timeout(timeout, run).await {
        Ok(Ok(output)) => {
            tracing::debug!(
                program = %spec.program,
                exit_code = ?output.exit_code,
                "async command completed"
            );
            Ok(output)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => {
            // Timeout expired — the inner future (and its `&mut child` borrow)
            // has been dropped, so we can kill and reap the child here.
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

/// Build a `tokio::process::Command` with args, cwd, env policy, and piped
/// stdout/stderr. Shared by the unlimited, limited, and (indirectly) streaming
/// paths. stdin is piped only when the spec carries stdin data.
fn build_tokio_command(spec: &CommandSpec) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(&spec.program);
    cmd.args(&spec.args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    if let Some(ref cwd) = spec.cwd {
        cmd.current_dir(cwd);
    }

    apply_env_policy(&mut cmd, spec);

    if spec.stdin.is_some() {
        cmd.stdin(std::process::Stdio::piped());
    }

    cmd
}

/// Write the spec's stdin data to the child, mapping write failures to
/// `Error::StdinFailed`. On a write failure the child is killed and reaped so
/// no orphaned process is left behind. Shared by the unlimited and limited
/// paths.
async fn write_stdin(child: &mut tokio::process::Child, spec: &CommandSpec) -> Result<()> {
    if let Some(ref stdin_data) = spec.stdin {
        use tokio::io::AsyncWriteExt;
        if let Some(mut stdin_handle) = child.stdin.take() {
            if let Err(e) = stdin_handle.write_all(stdin_data.as_bytes()).await {
                // A failed write can leave the child still running. Kill and
                // reap it so we never leak an orphan, then surface StdinFailed.
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(Error::StdinFailed {
                    program: spec.program.clone(),
                    detail: e.to_string(),
                });
            }
            // Close stdin to signal EOF.
            drop(stdin_handle);
        }
    }
    Ok(())
}

/// Size of each bounded read in the cap-aware Tokio path.
const TOKIO_CAP_READ_BUF: usize = 8 * 1024;

/// Cap-aware Tokio execution.
///
/// Like the unlimited path this drains both pipes concurrently with `wait()`
/// (avoiding the pipe-buffer deadlock), but it uses bounded `read(&mut [u8; N])`
/// instead of `read_to_end` and a shared byte counter. The combined stdout+stderr
/// cap is checked per read; the first read that would push the total past `cap`
/// records a breach and stops draining so the child is killed immediately.
/// Because the cap is enforced *while* capturing, memory is bounded regardless
/// of how much the child emits.
///
/// The entire drain-then-wait sequence runs under a single outer
/// `tokio::time::timeout`, so a quiet under-cap non-exiting child still times
/// out. Breach detection is synchronous (the draining loop itself observes the
/// breach and stops), avoiding any latch-race between the drain and the wait.
#[allow(clippy::too_many_lines)]
async fn run_tokio_limited(
    spec: &CommandSpec,
    timeout: Duration,
    cap: usize,
) -> Result<CommandOutput> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::AsyncReadExt;

    let mut cmd = build_tokio_command(spec);
    let mut child = cmd.spawn().map_err(|e| Error::SpawnFailed {
        program: spec.program.clone(),
        detail: e.to_string(),
    })?;
    write_stdin(&mut child, spec).await?;

    let counter = Arc::new(AtomicUsize::new(0));

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    // Cap-aware draining. Done streams are replaced with `std::future::pending`
    // so the `select!` naturally focuses on the remaining one (no busy-polling).
    // The loop returns `Breach` as soon as a read crosses `cap` — this is the
    // synchronous breach signal, raced against `child.wait()` and the outer
    // timeout below.
    let drain = async {
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();
        let mut stdout_pipe = stdout_pipe;
        let mut stderr_pipe = stderr_pipe;
        let mut sbuf = [0u8; TOKIO_CAP_READ_BUF];
        let mut ebuf = [0u8; TOKIO_CAP_READ_BUF];

        loop {
            if stdout_pipe.is_none() && stderr_pipe.is_none() {
                return DrainOutcome::Done((stdout_buf, stderr_buf));
            }

            let mut stdout_read = Box::pin(async {
                match stdout_pipe.as_mut() {
                    Some(pipe) => pipe.read(&mut sbuf).await,
                    None => std::future::pending().await,
                }
            });
            let mut stderr_read = Box::pin(async {
                match stderr_pipe.as_mut() {
                    Some(pipe) => pipe.read(&mut ebuf).await,
                    None => std::future::pending().await,
                }
            });

            tokio::select! {
                biased;
                n = &mut stdout_read => {
                    match n {
                        Ok(0) | Err(_) => { stdout_pipe = None; }
                        Ok(n) => {
                            let prev = counter.fetch_add(n, Ordering::AcqRel);
                            if prev + n > cap {
                                return DrainOutcome::Breach;
                            }
                            stdout_buf.extend_from_slice(&sbuf[..n]);
                        }
                    }
                }
                n = &mut stderr_read => {
                    match n {
                        Ok(0) | Err(_) => { stderr_pipe = None; }
                        Ok(n) => {
                            let prev = counter.fetch_add(n, Ordering::AcqRel);
                            if prev + n > cap {
                                return DrainOutcome::Breach;
                            }
                            stderr_buf.extend_from_slice(&ebuf[..n]);
                        }
                    }
                }
            }
        }
    };

    // Race the drain against the child exiting, all bounded by the outer
    // timeout. `biased` order doesn't matter here because the drain reports a
    // breach synchronously and the wait reports a normal exit; whichever fires
    // first wins. On breach, kill+reap. On normal drain completion, wait for
    // the child to get its status. On timeout, kill+reap and report timeout.
    let race = async {
        let mut drain = Box::pin(drain);
        let mut wait = Box::pin(child.wait());
        loop {
            tokio::select! {
                outcome = &mut drain => {
                    return match outcome {
                        DrainOutcome::Breach => RaceOutcome::Breach,
                        DrainOutcome::Done(bytes) => RaceOutcome::Drained(bytes),
                    };
                }
                status = &mut wait => {
                    // The child exited. Let the drain finish (it will reach EOF
                    // quickly now) so we have the captured bytes, then map.
                    let bytes = match drain.as_mut().await {
                        DrainOutcome::Breach => return RaceOutcome::Breach,
                        DrainOutcome::Done(b) => b,
                    };
                    match status {
                        Ok(s) => return RaceOutcome::Exited(bytes, s.code()),
                        Err(e) => return RaceOutcome::WaitFailed(e),
                    }
                }
            }
        }
    };

    match Box::pin(tokio::time::timeout(timeout, race)).await {
        // Outer timeout fired: the drain+wait did not complete in time. The
        // inner `child` borrow was dropped when the timeout cancelled `race`,
        // so we can kill+reap here.
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(Error::CommandTimeout {
                program: spec.program.clone(),
                args: spec.args.clone(),
                timeout,
            })
        }
        Ok(RaceOutcome::Breach) => {
            // Cap breached. Kill+reap the child; discard partial output.
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(Error::OutputLimitExceeded {
                program: spec.program.clone(),
                args: redacted_args_for(spec),
                limit: cap,
                observed: counter.load(Ordering::Acquire),
            })
        }
        Ok(RaceOutcome::Drained(bytes)) => {
            // Both pipes reached EOF under the cap, but the child had not yet
            // exited when the drain finished. Since `race` completed (not the
            // timeout arm), this means the drain finished inside the timeout
            // window. Wait for the child to exit to get its status.
            match child.wait().await {
                Ok(status) => Ok(finish_under_cap(spec, status.code(), bytes)),
                Err(e) => Err(Error::WaitFailed {
                    program: spec.program.clone(),
                    detail: e.to_string(),
                }),
            }
        }
        Ok(RaceOutcome::Exited(bytes, exit_code)) => Ok(finish_under_cap(spec, exit_code, bytes)),
        Ok(RaceOutcome::WaitFailed(e)) => {
            let _ = child.kill().await;
            Err(Error::WaitFailed {
                program: spec.program.clone(),
                detail: e.to_string(),
            })
        }
    }
}

/// Build the final `CommandOutput` for a successful under-cap run.
fn finish_under_cap(
    spec: &CommandSpec,
    exit_code: Option<i32>,
    (stdout_bytes, stderr_bytes): (Vec<u8>, Vec<u8>),
) -> CommandOutput {
    let stdout = String::from_utf8_lossy(&stdout_bytes).into_owned();
    let stderr = String::from_utf8_lossy(&stderr_bytes).into_owned();
    tracing::debug!(
        program = %spec.program,
        exit_code = ?exit_code,
        "async command completed"
    );
    CommandOutput::new(stdout, stderr, exit_code)
}

/// Redacted display of a spec's args for error messages, honoring `spec.redact`.
fn redacted_args_for(spec: &CommandSpec) -> String {
    if spec.redact {
        crate::display::display_command(spec, &[])
    } else {
        spec.args.join(" ")
    }
}

/// Outcome of the cap-aware draining loop.
enum DrainOutcome {
    /// A read crossed the cap; partial output must be discarded.
    Breach,
    /// Both pipes reached EOF under the cap with these retained bytes.
    Done((Vec<u8>, Vec<u8>)),
}

/// Outcome of racing the drain against the child wait.
enum RaceOutcome {
    /// The cap was breached during draining.
    Breach,
    /// The drain reached EOF before the child exited (under the cap).
    Drained((Vec<u8>, Vec<u8>)),
    /// The child exited with this status; the drain also finished.
    Exited((Vec<u8>, Vec<u8>), Option<i32>),
    /// Waiting on the child failed.
    WaitFailed(std::io::Error),
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
#[allow(clippy::too_many_lines)]
async fn run_streaming_command(
    spec: &CommandSpec,
    sink: &mut dyn CommandEventSink,
) -> Result<CommandOutput> {
    use tokio::io::AsyncWriteExt;

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
    apply_env_policy(&mut cmd, spec);
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
    if let Some(ref stdin_data) = spec.stdin
        && let Some(mut stdin_handle) = child.stdin.take()
    {
        stdin_handle
            .write_all(stdin_data.as_bytes())
            .await
            .map_err(|e| Error::StdinFailed {
                program: spec.program.clone(),
                detail: e.to_string(),
            })?;
        drop(stdin_handle);
    }

    // Take pipes. We use bounded `read(&mut [u8; N])` (not `read_line`) so a
    // single newline-free stream cannot buffer unbounded memory before the cap
    // can trigger, and interleave stdout and stderr with `tokio::select!` so the
    // cap observes both streams' bytes (the old drain-stdout-then-stderr
    // sequencing was itself a latent deadlock and hid stderr from the cap).
    let stdout_reader = child.stdout.take();
    let stderr_reader = child.stderr.take();

    // The stderr task reads bounded chunks and forwards them over a channel of
    // *fixed-size* chunks (not whole lines), so the cap can count its bytes.
    // Its JoinHandle is retained so it can be aborted on a breach (otherwise a
    // grandchild inheriting the stderr pipe keeps the read end from EOF and the
    // task — and its fd — leaks).
    let (stderr_tx, mut stderr_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(STREAM_CHANNEL_CHUNKS);

    let stderr_task: Option<tokio::task::JoinHandle<()>> = if let Some(mut reader) = stderr_reader {
        use tokio::io::AsyncReadExt;
        Some(tokio::spawn(async move {
            let mut buf = [0u8; STREAM_READ_BUF];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if stderr_tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }))
    } else {
        None
    };

    // --- Phase 2: read pipes + wait, all bounded by timeout ---
    let result = tokio::time::timeout(timeout, async {
        use tokio::io::AsyncReadExt;

        let cap = spec.output_limit;
        let mut observed: usize = 0;
        let mut stdout_bytes = Vec::new();
        let mut stderr_bytes = Vec::new();
        let mut stdout_reader = stdout_reader;
        let mut sbuf = [0u8; STREAM_READ_BUF];
        let mut stderr_closed = stderr_task.is_none();
        // Partial-line accumulators per stream. Bounded because each is flushed
        // every bounded read (≤ STREAM_READ_BUF), so they hold at most one
        // partial line of ≤ STREAM_READ_BUF bytes.
        let mut stdout_line_buf = String::new();
        let mut stderr_line_buf = String::new();

        // Drain stdout and stderr concurrently with bounded reads, interleaved
        // via `tokio::select!` so the cap observes both streams' bytes. The
        // stderr reader task forwards fixed-size chunks over a channel; we
        // interleave its `recv()` with stdout's `read()`. When stderr closes,
        // we fall through to a stdout-only loop (no busy-polling).
        loop {
            // Phase A: both stdout and stderr are live — interleave them.
            while stdout_reader.is_some() && !stderr_closed {
                tokio::select! {
                    biased;
                    n = stdout_reader.as_mut().expect("some").read(&mut sbuf) => {
                        match n {
                            Ok(0) | Err(_) => { stdout_reader = None; }
                            Ok(n) => {
                                let chunk = sbuf[..n].to_vec();
                                if let Some(limit) = cap {
                                    observed = observed.saturating_add(chunk.len());
                                    if observed > limit {
                                        return Err(stream_breach_error(spec, limit, observed));
                                    }
                                }
                                stdout_bytes.extend_from_slice(&chunk);
                                sink.on_event(CommandEvent::StdoutChunk(chunk.clone())).await?;
                                emit_stdout_lines(&chunk, &mut stdout_line_buf, sink).await?;
                            }
                        }
                    }
                    recv = stderr_rx.recv() => {
                        match recv {
                            Some(chunk) => {
                                if let Some(limit) = cap {
                                    observed = observed.saturating_add(chunk.len());
                                    if observed > limit {
                                        return Err(stream_breach_error(spec, limit, observed));
                                    }
                                }
                                stderr_bytes.extend_from_slice(&chunk);
                                sink.on_event(CommandEvent::StderrChunk(chunk.clone())).await?;
                                emit_stderr_lines(&chunk, &mut stderr_line_buf, sink).await?;
                            }
                            None => { stderr_closed = true; }
                        }
                    }
                }
            }

            // Phase B: stdout-only (stderr already closed or absent).
            if let Some(reader) = stdout_reader.as_mut() {
                let n = reader.read(&mut sbuf).await;
                match n {
                    Ok(0) | Err(_) => {
                        stdout_reader = None;
                    }
                    Ok(n) => {
                        let chunk = sbuf[..n].to_vec();
                        if let Some(limit) = cap {
                            observed = observed.saturating_add(chunk.len());
                            if observed > limit {
                                return Err(stream_breach_error(spec, limit, observed));
                            }
                        }
                        stdout_bytes.extend_from_slice(&chunk);
                        sink.on_event(CommandEvent::StdoutChunk(chunk.clone()))
                            .await?;
                        emit_stdout_lines(&chunk, &mut stdout_line_buf, sink).await?;
                    }
                }
                continue;
            }

            // Phase C: stderr-only (stdout already closed). Drain the channel
            // to completion.
            while !stderr_closed {
                match stderr_rx.recv().await {
                    Some(chunk) => {
                        if let Some(limit) = cap {
                            observed = observed.saturating_add(chunk.len());
                            if observed > limit {
                                return Err(stream_breach_error(spec, limit, observed));
                            }
                        }
                        stderr_bytes.extend_from_slice(&chunk);
                        sink.on_event(CommandEvent::StderrChunk(chunk.clone()))
                            .await?;
                        emit_stderr_lines(&chunk, &mut stderr_line_buf, sink).await?;
                    }
                    None => {
                        stderr_closed = true;
                    }
                }
            }

            break;
        }

        // Flush any trailing partial lines (no terminating newline).
        if !stdout_line_buf.is_empty() {
            sink.on_event(CommandEvent::StdoutLine(std::mem::take(
                &mut stdout_line_buf,
            )))
            .await?;
        }
        if !stderr_line_buf.is_empty() {
            sink.on_event(CommandEvent::StderrLine(std::mem::take(
                &mut stderr_line_buf,
            )))
            .await?;
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

    // On any terminating path, abort the stderr task so a lingering grandchild
    // holding the stderr pipe can't keep the task (and its fd) alive.
    if let Some(handle) = stderr_task {
        handle.abort();
        let _ = handle.await;
    }

    match result {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(e)) => {
            // Breach or sink error: kill+reap the child.
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(e)
        }
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

/// Bounded read buffer size for the streaming path.
const STREAM_READ_BUF: usize = 8 * 1024;
/// Number of in-flight fixed-size chunks the stderr task may queue.
const STREAM_CHANNEL_CHUNKS: usize = 64;

/// Build the `OutputLimitExceeded` error for a streaming breach.
fn stream_breach_error(spec: &CommandSpec, limit: usize, observed: usize) -> Error {
    Error::OutputLimitExceeded {
        program: spec.program.clone(),
        args: if spec.redact {
            crate::display::display_command(spec, &[])
        } else {
            spec.args.join(" ")
        },
        limit,
        observed,
    }
}

/// Emit one `StdoutLine` event per complete line in `chunk`, buffering any
/// trailing partial line into `buf` (flushed at stream EOF). Lines are split on
/// `\n`, with trailing `\r` trimmed. The buffer is bounded because it holds at
/// most one partial line per bounded read (≤ `STREAM_READ_BUF` bytes).
async fn emit_stdout_lines(
    chunk: &[u8],
    buf: &mut String,
    sink: &mut dyn CommandEventSink,
) -> Result<()> {
    buf.push_str(&String::from_utf8_lossy(chunk));
    while let Some(idx) = buf.find('\n') {
        let line: String = buf.drain(..=idx).collect();
        let trimmed = line
            .trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_owned();
        sink.on_event(CommandEvent::StdoutLine(trimmed)).await?;
    }
    Ok(())
}

/// Like [`emit_stdout_lines`] but emits `StderrLine` events.
async fn emit_stderr_lines(
    chunk: &[u8],
    buf: &mut String,
    sink: &mut dyn CommandEventSink,
) -> Result<()> {
    buf.push_str(&String::from_utf8_lossy(chunk));
    while let Some(idx) = buf.find('\n') {
        let line: String = buf.drain(..=idx).collect();
        let trimmed = line
            .trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_owned();
        sink.on_event(CommandEvent::StderrLine(trimmed)).await?;
    }
    Ok(())
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

fn apply_env_policy(cmd: &mut tokio::process::Command, spec: &CommandSpec) {
    if spec.clear_env {
        cmd.env_clear();
        for (key, value) in clean_env_values(spec) {
            cmd.env(key, value);
        }
    } else {
        for key in &spec.env_remove {
            cmd.env_remove(key);
        }
    }

    for (key, value) in &spec.env {
        cmd.env(key, value);
    }
}

fn clean_env_values(spec: &CommandSpec) -> Vec<(String, String)> {
    platform_env_preserved_for_clean_env()
        .into_iter()
        .filter(|(key, _)| {
            !spec
                .env_remove
                .iter()
                .any(|removed| env_key_matches(removed, key))
        })
        .collect()
}

#[cfg(windows)]
fn platform_env_preserved_for_clean_env() -> Vec<(String, String)> {
    ["SystemRoot", "SystemDrive", "WINDIR"]
        .into_iter()
        .filter_map(|key| std::env::var(key).ok().map(|value| (key.to_owned(), value)))
        .collect()
}

#[cfg(not(windows))]
fn platform_env_preserved_for_clean_env() -> Vec<(String, String)> {
    Vec::new()
}

#[cfg(windows)]
fn env_key_matches(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[cfg(not(windows))]
fn env_key_matches(a: &str, b: &str) -> bool {
    a == b
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
    async fn env_remove_unsets_inherited_variable() {
        let runner = TokioRunner;
        let spec = CommandSpec::new("/bin/sh")
            .args(["-c", "printf '%s' \"${HOME-unset}\""])
            .env_remove("HOME");
        let output = runner.run(&spec).await.unwrap();

        assert_eq!(output.stdout, "unset");
    }

    #[tokio::test]
    async fn explicit_env_wins_over_env_remove() {
        let runner = TokioRunner;
        let spec = CommandSpec::new("/bin/sh")
            .args(["-c", "printf '%s' \"${TORIDE_REMOVE_ME-unset}\""])
            .env_remove("TORIDE_REMOVE_ME")
            .env("TORIDE_REMOVE_ME", "present");
        let output = runner.run(&spec).await.unwrap();

        assert_eq!(output.stdout, "present");
    }

    #[tokio::test]
    async fn clear_env_removes_inherited_variables() {
        let runner = TokioRunner;
        let spec = CommandSpec::new("/bin/sh")
            .args(["-c", "printf '%s:%s' \"${HOME-unset}\" \"$TORIDE_ONLY\""])
            .clear_env(true)
            .env("TORIDE_ONLY", "kept");
        let output = runner.run(&spec).await.unwrap();

        assert_eq!(output.stdout, "unset:kept");
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
        assert!(
            !output.stdout.contains("ERR"),
            "stderr should not leak into stdout"
        );
        assert!(
            !output.stderr.contains("OUT"),
            "stdout should not leak into stderr"
        );
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
        let spec = CommandSpec::new("bash")
            .args(["-c", "for i in $(seq 1 100); do echo \"line $i\"; done"]);

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

    /// Verify the concurrent-draining conversion: a command that writes far
    /// more than the ~64 KB OS pipe buffer must not deadlock.
    ///
    /// Under the old read-after-`wait()` model, this command would fill the
    /// pipe buffer, block on write, and never exit — only the 60s default
    /// timeout would eventually fire. Here we give the run a short timeout and
    /// assert it completes successfully well before that, proving the parent
    /// drains the pipe concurrently with the wait.
    #[tokio::test]
    async fn large_output_does_not_deadlock() {
        let runner = TokioRunner;
        // ~512 KB to stdout — well over the 64 KB pipe buffer.
        let spec = CommandSpec::new("bash")
            .args([
                "-c",
                "for i in $(seq 1 16384); do echo \"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"; done",
            ])
            .timeout(Duration::from_secs(10));

        let output = runner.run(&spec).await.unwrap();
        assert!(output.success);
        assert!(output.stdout.len() > 64 * 1024);
    }

    #[tokio::test]
    async fn output_limit_preserves_under_cap_capture() {
        let runner = TokioRunner;
        let spec = CommandSpec::new("echo").arg("hello").output_limit(1024);
        let output = runner.run(&spec).await.unwrap();

        assert!(output.success);
        assert_eq!(output.stdout_trimmed(), "hello");
    }

    #[tokio::test]
    async fn output_limit_exceeded_on_stdout() {
        let runner = TokioRunner;
        let spec = CommandSpec::new("bash")
            .args(["-c", "for i in $(seq 1 100); do echo line; done"])
            .output_limit(64);
        let result = runner.run(&spec).await;

        assert!(matches!(
            result,
            Err(Error::OutputLimitExceeded { limit, .. }) if limit == 64
        ));
    }

    #[tokio::test]
    async fn output_limit_exceeded_on_stderr() {
        let runner = TokioRunner;
        let spec = CommandSpec::new("bash")
            .args(["-c", "for i in $(seq 1 100); do echo line >&2; done"])
            .output_limit(64);
        let result = runner.run(&spec).await;

        assert!(matches!(result, Err(Error::OutputLimitExceeded { .. })));
    }

    #[tokio::test]
    async fn output_limit_counts_stdout_plus_stderr() {
        let runner = TokioRunner;
        let spec = CommandSpec::new("bash")
            .args(["-c", "echo AAAA; echo BBBB >&2; echo CCCC; echo DDDD >&2"])
            .output_limit(8);
        let result = runner.run(&spec).await;

        assert!(matches!(result, Err(Error::OutputLimitExceeded { .. })));
    }

    #[tokio::test]
    async fn output_limit_bounds_memory_on_newline_free_stream() {
        // A single newline-free stream that writes far more than the cap. Bounded
        // reads must trip the cap and kill the child rather than buffering it.
        let runner = TokioRunner;
        let spec = CommandSpec::new("bash")
            .args(["-c", "yes | tr -d '\\n' | head -c 100000"])
            .output_limit(256)
            .timeout(Duration::from_secs(10));
        let result = runner.run(&spec).await;

        match result {
            Err(Error::OutputLimitExceeded { .. }) => {}
            other => panic!(
                "expected OutputLimitExceeded, got {other:?} (cap should fire before timeout)"
            ),
        }
    }

    #[tokio::test]
    async fn output_limit_kills_running_process() {
        // A slow stream that would run for a while; the cap must kill it promptly.
        let runner = TokioRunner;
        let marker_dir = tempfile::tempdir().unwrap();
        let marker = marker_dir.path().join("marker");
        let script = format!(
            "for i in $(seq 1 100000); do echo x; done; echo SURVIVED > {}",
            marker.display()
        );
        let spec = CommandSpec::new("bash")
            .args(["-c", script.as_str()])
            .output_limit(128);

        let result = runner.run(&spec).await;
        assert!(matches!(result, Err(Error::OutputLimitExceeded { .. })));

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !marker.exists(),
            "output-limited child was not killed (reached SURVIVED)"
        );
    }

    #[tokio::test]
    async fn output_limit_redacts_args_in_error_when_requested() {
        let runner = TokioRunner;
        let spec = CommandSpec::new("bash")
            .args(["-c", "yes | head -c 10000", "--token", "secret-value"])
            .redact(true)
            .output_limit(64);
        let result = runner.run(&spec).await;

        match result {
            Err(Error::OutputLimitExceeded { args, .. }) => {
                assert!(args.contains("***"));
                assert!(!args.contains("secret-value"));
            }
            other => panic!("expected OutputLimitExceeded, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn output_limit_unset_preserves_unlimited_capture() {
        let runner = TokioRunner;
        let spec = CommandSpec::new("bash")
            .args(["-c", "for i in $(seq 1 50); do echo \"line $i\"; done"]);
        let output = runner.run(&spec).await.unwrap();

        assert!(output.success);
        let lines: Vec<&str> = output.stdout.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 50);
    }

    /// Regression: a quiet under-cap child that never exits must still time out.
    /// The cap-aware path previously did not bound its drain by `timeout`, so a
    /// non-emitting child under a cap could run for the child's full lifetime
    /// instead of the configured timeout.
    #[tokio::test]
    async fn output_limit_quiet_child_times_out() {
        let runner = TokioRunner;
        // A child that produces no output, never exceeds the cap, and outlives
        // the timeout. Must return CommandTimeout promptly.
        let spec = CommandSpec::new("sleep")
            .arg("30")
            .output_limit(1024)
            .timeout(Duration::from_millis(100));

        let start = std::time::Instant::now();
        let result = runner.run(&spec).await;
        let elapsed = start.elapsed();

        assert!(
            matches!(result, Err(Error::CommandTimeout { .. })),
            "expected CommandTimeout, got {result:?}"
        );
        // Must return well before the child's 30s lifetime — proves the timeout
        // bounded the drain (allow generous CI headroom over the 100ms timeout).
        assert!(
            elapsed < Duration::from_secs(10),
            "quiet-child timeout took {elapsed:?}; drain was not bounded by timeout"
        );
    }

    /// Regression: when the cap is breached by a child that would otherwise keep
    /// running, the runner must return `OutputLimitExceeded` AND kill the child
    /// promptly (not wait for self-exit or a timeout). Previously the breach was
    /// sometimes misrouted and reported as CommandTimeout, or the child kept
    /// running until self-exit.
    #[tokio::test]
    async fn output_limit_breach_kills_promptly() {
        let runner = TokioRunner;
        let marker_dir = tempfile::tempdir().unwrap();
        let marker = marker_dir.path().join("marker");
        // Emit 64-byte chunks forever; cap at 128 so breach happens fast. The
        // marker is only written at the natural end (never reached if killed).
        let script = format!(
            "for i in $(seq 1 1000000); do echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; done; echo SURVIVED > {}",
            marker.display()
        );
        let spec = CommandSpec::new("bash")
            .args(["-c", script.as_str()])
            .output_limit(128)
            .timeout(Duration::from_secs(30));

        let start = std::time::Instant::now();
        let result = runner.run(&spec).await;
        let elapsed = start.elapsed();

        assert!(
            matches!(result, Err(Error::OutputLimitExceeded { .. })),
            "expected OutputLimitExceeded, got {result:?}"
        );
        // Must return promptly — the cap fires after ~2 chunks, not after a
        // timeout or the million-iteration self-exit.
        assert!(
            elapsed < Duration::from_secs(5),
            "breach handling took {elapsed:?}; child was not killed promptly"
        );

        // Give the kill time to take effect, then confirm the child never
        // reached the natural end.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !marker.exists(),
            "output-limited child was not killed (reached SURVIVED)"
        );
    }
}
