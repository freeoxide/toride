//! Real command execution via the `duct` crate.
//!
//! [`DuctRunner`] is the production implementation of [`Runner`](crate::Runner).
//! It spawns subprocesses, captures stdout/stderr, and respects timeouts.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::output::CommandOutput;
use crate::output_mode::OutputMode;
use crate::runner::Runner;
use crate::spec::CommandSpec;

/// Size of each bounded read from the cap-aware reader threads.
const CAP_READ_BUF: usize = 8 * 1024;

/// Default command timeout in seconds when none is specified.
const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// Runtime policy for [`DuctRunner`] command execution.
///
/// These are runner defaults. A timeout set directly on [`CommandSpec`] still
/// wins for that individual command.
#[derive(Debug, Clone)]
pub struct DuctRunnerOptions {
    /// Timeout applied when [`CommandSpec::timeout`] is absent.
    ///
    /// `None` means commands without an explicit timeout can run until they
    /// exit naturally.
    pub default_timeout: Option<Duration>,
    /// Whether completed commands emit debug tracing logs.
    pub log_commands: bool,
}

impl Default for DuctRunnerOptions {
    fn default() -> Self {
        Self {
            default_timeout: Some(Duration::from_secs(DEFAULT_TIMEOUT_SECS)),
            log_commands: true,
        }
    }
}

/// Builder for configured Duct-backed runners.
#[derive(Debug, Clone)]
pub struct DuctRunnerBuilder {
    options: DuctRunnerOptions,
}

impl DuctRunnerBuilder {
    /// Set the fallback timeout for specs that do not define one.
    pub fn default_timeout(mut self, timeout: Duration) -> Self {
        self.options.default_timeout = Some(timeout);
        self
    }

    /// Disable the fallback timeout for specs that do not define one.
    pub fn no_default_timeout(mut self) -> Self {
        self.options.default_timeout = None;
        self
    }

    /// Enable or disable completion debug logs.
    pub fn log_commands(mut self, enabled: bool) -> Self {
        self.options.log_commands = enabled;
        self
    }

    /// Build a configured Duct runner.
    pub fn build(self) -> ConfiguredDuctRunner {
        ConfiguredDuctRunner {
            options: self.options,
        }
    }
}

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
///
/// `DuctRunner` is a stateless unit struct, so it is [`Clone`]/[`Default`]
/// (matching its configured sibling [`ConfiguredDuctRunner`] and the test
/// [`FakeRunner`](crate::FakeRunner)). This lets a single shared runner be
/// handed to several owning subsystems via `Clone`.
#[derive(Debug, Clone, Default)]
pub struct DuctRunner;

impl Runner for DuctRunner {
    fn run(&self, spec: &CommandSpec) -> Result<CommandOutput> {
        run_duct_command(spec, &DuctRunnerOptions::default())
    }
}

impl DuctRunner {
    /// Start building a configured Duct runner.
    pub fn builder() -> DuctRunnerBuilder {
        DuctRunnerBuilder {
            options: DuctRunnerOptions::default(),
        }
    }

    /// Create a configured Duct runner from explicit options.
    pub fn with_options(options: DuctRunnerOptions) -> ConfiguredDuctRunner {
        ConfiguredDuctRunner { options }
    }
}

/// A Duct-backed runner with explicit execution options.
#[derive(Debug, Clone)]
pub struct ConfiguredDuctRunner {
    options: DuctRunnerOptions,
}

impl ConfiguredDuctRunner {
    /// Return this runner's execution options.
    #[must_use]
    pub fn options(&self) -> &DuctRunnerOptions {
        &self.options
    }
}

impl Runner for ConfiguredDuctRunner {
    fn run(&self, spec: &CommandSpec) -> Result<CommandOutput> {
        run_duct_command(spec, &self.options)
    }
}

fn run_duct_command(spec: &CommandSpec, options: &DuctRunnerOptions) -> Result<CommandOutput> {
    if spec.output_mode == OutputMode::Stream {
        return Err(Error::Other(
            "OutputMode::Stream is not supported by the synchronous DuctRunner; use TokioRunner with the stream feature".to_owned(),
        ));
    }

    // Output-limit enforcement only applies to captured output. Inherit mode
    // does not capture, so the limit is ignored (the real exit code is still
    // returned). Dispatch to the cap-aware path before any duct capture is
    // wired up, because `stdout_capture()`/`stderr_capture()` allocate
    // unbounded memory before the cap can be checked.
    if spec.output_mode == OutputMode::Capture
        && let Some(limit) = spec.output_limit
    {
        return run_duct_command_limited(spec, options, limit);
    }

    let started_at = Instant::now();
    let displayed = crate::display::display_command(spec, &[]);
    let mut cmd = build_duct_expression(spec);

    let timeout = spec.timeout.or(options.default_timeout);

    // Spawn with stdout/stderr capture by default. Inherit mode deliberately
    // connects child output to the parent and returns empty captured strings.
    if spec.output_mode == OutputMode::Capture {
        cmd = cmd.stdout_capture().stderr_capture();
    }

    // Use unchecked so non-zero exit
    // does not immediately error — we capture it in CommandOutput.
    let handle = cmd.unchecked().start().map_err(|e| Error::SpawnFailed {
        program: spec.program.clone(),
        detail: e.to_string(),
    })?;

    let output = if let Some(timeout) = timeout {
        match handle.wait_timeout(timeout) {
            Ok(Some(output)) => output.clone(),
            Ok(None) => {
                // Timeout expired. Duct kills all processes it started for an
                // expression; process-tree guarantees beyond that are tracked
                // in docs/duct-runner-full-fledged-plan.md.
                if let Err(err) = handle.kill() {
                    tracing::warn!(
                        command = %displayed,
                        error = %err,
                        "failed to kill timed-out command"
                    );
                }
                if let Err(err) = handle.wait() {
                    tracing::warn!(
                        command = %displayed,
                        error = %err,
                        "failed to reap timed-out command"
                    );
                }
                return Err(Error::CommandTimeout {
                    program: spec.program.clone(),
                    args: crate::display::redacted_args_vec(spec),
                    timeout,
                });
            }
            Err(e) => return Err(wait_failed(spec, &e)),
        }
    } else {
        handle.wait().map_err(|e| wait_failed(spec, &e))?.clone()
    };

    let stdout = if spec.output_mode == OutputMode::Capture {
        String::from_utf8_lossy(&output.stdout).into_owned()
    } else {
        String::new()
    };
    let stderr = if spec.output_mode == OutputMode::Capture {
        String::from_utf8_lossy(&output.stderr).into_owned()
    } else {
        String::new()
    };
    let exit_code = output.status.code();

    if options.log_commands {
        tracing::debug!(
            command = %displayed,
            program = %spec.program,
            exit_code = ?exit_code,
            elapsed_ms = started_at.elapsed().as_millis(),
            "command completed"
        );
    }

    // Honor the redact flag on the *returned* output too: scrub secret values
    // from captured stdout/stderr so a successful command never hands a caller
    // a token or passphrase that a failing command's error would have scrubbed.
    Ok(crate::display::scrub_output(
        spec,
        &CommandOutput::new(stdout, stderr, exit_code),
    ))
}

/// Build the base `duct::Expression` with cwd, env policy, and stdin applied,
/// but *without* any stdio capture wiring. Shared by both the unlimited and
/// cap-aware paths.
fn build_duct_expression(spec: &CommandSpec) -> duct::Expression {
    let mut cmd = duct::cmd(&spec.program, &spec.args);

    if let Some(ref cwd) = spec.cwd {
        cmd = cmd.dir(cwd);
    }

    cmd = apply_env_policy(cmd, spec);

    if let Some(ref stdin_data) = spec.stdin {
        cmd = cmd.stdin_bytes(stdin_data.as_bytes());
    }

    cmd
}

/// Cap-aware Duct execution.
///
/// Instead of `stdout_capture()`/`stderr_capture()` (which buffer the entire
/// output into memory before the cap can be checked), this creates two OS
/// pipes in the parent, passes the write ends to the child via
/// `stdout_file`/`stderr_file`, and spawns the child with `.unchecked().start()`.
/// Because both streams are redirected to caller-owned files, the handle starts
/// no internal capture threads and holds no hidden buffer. Two cap-aware reader
/// threads then drain the read ends with bounded reads, sharing a combined byte
/// counter (`AtomicUsize`) and a "killed" latch (`AtomicBool`).
///
/// On breach, the reader thread that pushes the total past `cap` wins the latch
/// and calls `handle.kill()` directly; the main thread, blocked in
/// `wait_timeout`, unblocks. The child is then reaped and no partial output is
/// returned.
#[allow(clippy::too_many_lines)]
fn run_duct_command_limited(
    spec: &CommandSpec,
    options: &DuctRunnerOptions,
    cap: usize,
) -> Result<CommandOutput> {
    let started_at = Instant::now();
    let displayed = crate::display::display_command(spec, &[]);

    // Create two OS pipes in the parent. On Apple targets `pipe2()` is
    // unavailable so caller-opened pipes cannot set CLOEXEC atomically; guard
    // pipe creation plus spawn under a process-wide mutex (as duct does
    // internally) to avoid leaking fds into unrelated children spawned
    // concurrently.
    let (stdout_rx_pipe, stdout_tx) = spawn_under_apple_lock(|| {
        os_pipe::pipe().map_err(|e| Error::SpawnFailed {
            program: spec.program.clone(),
            detail: format!("stdout pipe: {e}"),
        })
    })?;
    let (stderr_rx_pipe, stderr_tx) = spawn_under_apple_lock(|| {
        os_pipe::pipe().map_err(|e| Error::SpawnFailed {
            program: spec.program.clone(),
            detail: format!("stderr pipe: {e}"),
        })
    })?;

    // Redirect both child streams to the write ends. No internal duct capture
    // threads are started.
    //
    // IMPORTANT: the duct `Expression` keeps the original write-fd `OwnedFd`
    // alive until it is dropped. If it stays alive, the read ends never reach
    // EOF (the parent holds an open write end). So we scope the expression so
    // it is dropped the instant `start()` returns, leaving only the child's
    // copy of the write end open.
    let handle = {
        let cmd = build_duct_expression(spec)
            .stdout_file(stdout_tx)
            .stderr_file(stderr_tx);
        cmd.unchecked().start().map_err(|e| Error::SpawnFailed {
            program: spec.program.clone(),
            detail: e.to_string(),
        })?
    };

    // The write ends were transferred to the child via `stdout_file`/
    // `stderr_file`, so the parent holds no copy of them; the read ends reach
    // EOF once the child closes its copies. (A surviving grandchild holding an
    // inherited write end has the same effect; that grandchild-survival case is
    // documented as out of scope for the direct-child cleanup policy.)

    let shared_handle = Arc::new(handle);
    let counter = Arc::new(AtomicUsize::new(0));
    let killed = Arc::new(AtomicBool::new(false));

    // Each reader sends its retained bytes over a channel on EOF. The main
    // thread uses a bounded recv_timeout rather than a blocking join, because a
    // grandchild holding an inherited write end would hang a join forever.
    let (stdout_tx, stdout_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let (stderr_tx, stderr_rx) = std::sync::mpsc::channel::<Vec<u8>>();

    // Spawn two cap-aware reader threads. Each performs bounded reads, reserves
    // then checks the shared byte counter, and retains a chunk only while under
    // the cap. The thread that pushes the total past `cap` wins the latch and
    // kills the handle directly, unblocking the main `wait_timeout`.
    let stdout_thread = spawn_reader(
        stdout_rx_pipe,
        Arc::clone(&shared_handle),
        Arc::clone(&counter),
        Arc::clone(&killed),
        cap,
        stdout_tx,
    );
    let stderr_thread = spawn_reader(
        stderr_rx_pipe,
        Arc::clone(&shared_handle),
        Arc::clone(&counter),
        Arc::clone(&killed),
        cap,
        stderr_tx,
    );
    let _ = stdout_thread;
    let _ = stderr_thread;

    let timeout = spec.timeout.or(options.default_timeout);

    // Wait for the child, bounded by the timeout. There are three ways this
    // unblocks: (1) the process exits normally, (2) the timeout fires, or
    // (3) a reader thread trips the cap latch and calls `handle.kill()`,
    // which makes the wait return with the killed process's status.
    let wait_result = if let Some(timeout) = timeout {
        match shared_handle.wait_timeout(timeout) {
            Ok(Some(output)) => Ok(Some(output.clone())),
            Ok(None) => Err(WaitOutcome::Timeout(timeout)),
            Err(e) => Err(WaitOutcome::WaitFailed(e)),
        }
    } else {
        shared_handle
            .wait()
            .map(|o| Some(o.clone()))
            .map_err(WaitOutcome::WaitFailed)
    };

    // Observe the breach latch. A reader may have tripped it *while* the main
    // thread was blocked; the cap was breached regardless of how wait ended.
    let breached = killed.load(Ordering::Acquire);

    match (wait_result, breached) {
        // A cap breach must be attributed to OutputLimitExceeded regardless of
        // how `wait_result` resolved: the reader tripped the latch and killed
        // the child, but `wait_timeout` can still report `Timeout` if the
        // budget elapsed before the killed child was reaped. Checking `breached`
        // first prevents that timeout/breach race from mislabeling the failure
        // as CommandTimeout.
        (_, true) => {
            // Cap breached. The breaching reader already killed the handle;
            // reap it, discard partial output, and return the error.
            kill_and_reap(&shared_handle, &displayed);
            let _ = recv_reader_bytes(&stdout_rx, READER_DETACH_WAIT);
            let _ = recv_reader_bytes(&stderr_rx, READER_DETACH_WAIT);
            Err(Error::OutputLimitExceeded {
                program: spec.program.clone(),
                args: crate::display::redacted_args_display(spec),
                limit: cap,
                observed: counter.load(Ordering::Acquire),
            })
        }
        (Err(WaitOutcome::Timeout(timeout)), _) => {
            // Timeout fired (breach not tripped — `true` is handled above).
            // Kill+reap to avoid zombies.
            kill_and_reap(&shared_handle, &displayed);
            // Detach readers (bounded recv, discard any partial output).
            let _ = recv_reader_bytes(&stdout_rx, READER_DETACH_WAIT);
            let _ = recv_reader_bytes(&stderr_rx, READER_DETACH_WAIT);
            Err(Error::CommandTimeout {
                program: spec.program.clone(),
                args: crate::display::redacted_args_vec(spec),
                timeout,
            })
        }
        (Err(WaitOutcome::WaitFailed(e)), _) => {
            kill_and_reap(&shared_handle, &displayed);
            let _ = recv_reader_bytes(&stdout_rx, READER_DETACH_WAIT);
            let _ = recv_reader_bytes(&stderr_rx, READER_DETACH_WAIT);
            Err(wait_failed(spec, &e))
        }
        (Ok(output), false) => {
            // Clean exit under the cap. The readers reach EOF once the child
            // closes its write ends, so a bounded wait is enough. Collect the
            // retained bytes (detaching any reader that doesn't finish in time
            // due to a lingering grandchild).
            let stdout_bytes = recv_reader_bytes(&stdout_rx, READER_CLEAN_WAIT).unwrap_or_default();
            let stderr_bytes = recv_reader_bytes(&stderr_rx, READER_CLEAN_WAIT).unwrap_or_default();
            let exit_code = output.as_ref().and_then(|o| o.status.code());

            // A breach can be observed late: the breaching reader sets the
            // latch *and* advances the shared counter past `cap` via `fetch_add`
            // before returning. Gate the Ok return on BOTH signals so a breach
            // detected between this check and the return (e.g. by a lingering
            // grandchild's detached reader) is still caught. The counter is the
            // authoritative byte tally — it cannot decrease, so once it exceeds
            // `cap` the cap was breached regardless of latch timing.
            let observed = counter.load(Ordering::Acquire);
            if killed.load(Ordering::Acquire) || observed > cap {
                return Err(Error::OutputLimitExceeded {
                    program: spec.program.clone(),
                    args: crate::display::redacted_args_display(spec),
                    limit: cap,
                    observed,
                });
            }

            let stdout = String::from_utf8_lossy(&stdout_bytes).into_owned();
            let stderr = String::from_utf8_lossy(&stderr_bytes).into_owned();

            if options.log_commands {
                tracing::debug!(
                    command = %displayed,
                    program = %spec.program,
                    exit_code = ?exit_code,
                    elapsed_ms = started_at.elapsed().as_millis(),
                    "command completed"
                );
            }
            Ok(crate::display::scrub_output(
                spec,
                &CommandOutput::new(stdout, stderr, exit_code),
            ))
        }
    }
}

/// How long to wait for a reader to deliver its bytes after the process has
/// exited cleanly. Generous enough for a well-behaved child to close its pipes
/// and for the reader to flush, while still bounding a stuck reader.
const READER_CLEAN_WAIT: Duration = Duration::from_secs(2);

/// How long to wait for a reader to deliver its bytes after an error/cleanup
/// path (timeout or breach). Short — we discard partial output anyway.
const READER_DETACH_WAIT: Duration = Duration::from_millis(200);

/// Kill and reap a Duct handle for cleanup, warning on unexpected failures.
/// A "no such process" failure is expected (the handle may already be dead).
fn kill_and_reap(handle: &duct::Handle, displayed: &str) {
    if let Err(err) = handle.kill()
        && !err.to_string().contains("No such process")
    {
        tracing::warn!(
            command = %displayed,
            error = %err,
            "failed to kill command during cleanup"
        );
    }
    if let Err(err) = handle.wait()
        && !err.to_string().contains("No such process")
    {
        tracing::warn!(
            command = %displayed,
            error = %err,
            "failed to reap command during cleanup"
        );
    }
}

/// Outcome of the main-thread wait, used to delay error mapping until after
/// cleanup in the cap-aware path.
enum WaitOutcome {
    Timeout(Duration),
    WaitFailed(std::io::Error),
}

/// Spawn a cap-aware reader thread for one pipe.
///
/// Performs bounded `read(&mut [u8; N])` reads (never `read_to_end`, which
/// would buffer an unbounded newline-free stream before the cap can trigger).
/// Reserve-then-check with `fetch_add` so worst-case retained memory is bounded
/// to `cap + 2 * CAP_READ_BUF`. The thread that pushes the total past `cap`
/// wins the latch (via `compare_exchange`) and calls `handle.kill()` directly
/// while the main thread is blocked in `wait_timeout`.
///
/// The retained bytes are sent over `tx` when the reader reaches EOF. The main
/// thread uses a *bounded* `recv_timeout` rather than an unconditional join,
/// because a grandchild holding an inherited write end keeps the read end from
/// reaching EOF and would hang a blocking join forever. An unconsummed reader
/// is simply detached — the process it was draining is already reaped, so the
/// thread becomes harmless and exits when its pipe eventually closes.
#[allow(clippy::type_complexity)]
fn spawn_reader(
    mut rx: os_pipe::PipeReader,
    handle: Arc<duct::Handle>,
    counter: Arc<AtomicUsize>,
    killed: Arc<AtomicBool>,
    cap: usize,
    tx: std::sync::mpsc::Sender<Vec<u8>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        use std::io::Read;
        let mut retained = Vec::new();
        let mut buf = vec![0u8; CAP_READ_BUF];
        loop {
            // Stop early if another reader already tripped the latch.
            if killed.load(Ordering::Acquire) {
                return;
            }
            let n = match rx.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            // Reserve then check: atomically account for this chunk's bytes.
            let prev = counter.fetch_add(n, Ordering::AcqRel);
            if prev + n > cap {
                // Breach. Exactly one thread wins the latch and kills.
                let _ = killed.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire);
                let _ = handle.kill();
                // Discard partial output; do not send anything.
                return;
            }
            retained.extend_from_slice(&buf[..n]);
        }
        let _ = tx.send(retained);
    })
}

/// Wait for one reader's retained bytes with a bounded timeout.
///
/// This is *not* an unconditional join: a grandchild holding an inherited write
/// end keeps the reader's pipe open, so the reader may never reach EOF. We
/// detach such a reader rather than hang the runner. `duration` is the cap on
/// how long we wait after the process has already been reaped.
fn recv_reader_bytes(
    rx: &std::sync::mpsc::Receiver<Vec<u8>>,
    duration: Duration,
) -> Option<Vec<u8>> {
    rx.recv_timeout(duration).ok()
}

/// Run a pipe-creation closure under a process-wide mutex on Apple targets,
/// where caller-opened pipes cannot set `CLOEXEC` atomically (`pipe2()` is
/// unavailable) and could otherwise leak fds into unrelated children spawned
/// concurrently. On non-Apple targets this is a passthrough.
fn spawn_under_apple_lock<F, T>(f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    #[cfg(target_os = "macos")]
    {
        use std::sync::Mutex;
        static APPLE_PIPE_LOCK: Mutex<()> = Mutex::new(());
        let _guard = APPLE_PIPE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        f()
    }
    #[cfg(not(target_os = "macos"))]
    {
        f()
    }
}

fn wait_failed(spec: &CommandSpec, error: &std::io::Error) -> Error {
    Error::WaitFailed {
        program: spec.program.clone(),
        detail: error.to_string(),
    }
}

fn apply_env_policy(mut cmd: duct::Expression, spec: &CommandSpec) -> duct::Expression {
    if spec.clear_env {
        let mut env = clean_env_values(spec);
        env.extend(spec.env.iter().cloned());
        return cmd.full_env(env);
    }

    for (key, value) in &spec.env {
        cmd = cmd.env(key, value);
    }

    for key in &spec.env_remove {
        if !spec
            .env
            .iter()
            .any(|(env_key, _)| env_key_matches(env_key, key))
        {
            cmd = cmd.env_remove(key);
        }
    }

    cmd
}

fn clean_env_values(spec: &CommandSpec) -> Vec<(String, String)> {
    platform_env_preserved_for_clean_env()
        .into_iter()
        .filter(|(key, _)| {
            !spec
                .env_remove
                .iter()
                .any(|removed| env_key_matches(removed, key))
                || spec
                    .env
                    .iter()
                    .any(|(env_key, _)| env_key_matches(env_key, key))
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
        assert!(matches!(result.unwrap_err(), Error::CommandTimeout { .. }));
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

    #[test]
    fn env_remove_unsets_inherited_variable() {
        let runner = DuctRunner;
        let spec = CommandSpec::new("/bin/sh")
            .args(["-c", "printf '%s' \"${HOME-unset}\""])
            .env_remove("HOME");
        let output = runner.run(&spec).unwrap();

        assert_eq!(output.stdout, "unset");
    }

    #[test]
    fn explicit_env_wins_over_env_remove() {
        let runner = DuctRunner;
        let spec = CommandSpec::new("/bin/sh")
            .args(["-c", "printf '%s' \"${TORIDE_REMOVE_ME-unset}\""])
            .env_remove("TORIDE_REMOVE_ME")
            .env("TORIDE_REMOVE_ME", "present");
        let output = runner.run(&spec).unwrap();

        assert_eq!(output.stdout, "present");
    }

    #[test]
    fn clear_env_removes_inherited_variables() {
        let runner = DuctRunner;
        let spec = CommandSpec::new("/bin/sh")
            .args(["-c", "printf '%s:%s' \"${HOME-unset}\" \"$TORIDE_ONLY\""])
            .clear_env(true)
            .env("TORIDE_ONLY", "kept");
        let output = runner.run(&spec).unwrap();

        assert_eq!(output.stdout, "unset:kept");
    }

    #[test]
    fn cwd_applied() {
        let runner = DuctRunner;
        let spec = CommandSpec::new("pwd").cwd("/tmp");
        let output = runner.run(&spec).unwrap();
        let resolved = std::path::Path::new("/tmp")
            .canonicalize()
            .map_or_else(|_| "/tmp".to_owned(), |p| p.to_string_lossy().into_owned());
        assert_eq!(output.stdout_trimmed(), resolved);
    }

    #[test]
    fn run_checked_errors_on_failure() {
        let runner = DuctRunner;
        let spec = CommandSpec::new("false");
        let result = runner.run_checked(&spec);
        assert!(matches!(result.unwrap_err(), Error::CommandFailed { .. }));
    }

    #[test]
    fn run_checked_redacts_args_when_requested() {
        let runner = DuctRunner;
        let spec = CommandSpec::new("bash")
            .args(["-c", "exit 7", "--token", "secret-value"])
            .redact(true);
        let result = runner.run_checked(&spec);

        match result.unwrap_err() {
            Error::CommandFailed { args, .. } => {
                assert!(args.contains("***"));
                assert!(!args.contains("secret-value"));
            }
            other => panic!("expected CommandFailed, got {other:?}"),
        }
    }

    #[test]
    fn spawn_failed() {
        let runner = DuctRunner;
        let spec = CommandSpec::new("definitely_not_a_real_binary_xyz_123");
        let result = runner.run(&spec);
        assert!(matches!(result.unwrap_err(), Error::SpawnFailed { .. }));
    }

    #[test]
    fn timeout_error_metadata() {
        let runner = DuctRunner;
        let timeout = Duration::from_millis(50);
        let spec = CommandSpec::new("sleep").arg("10").timeout(timeout);
        let result = runner.run(&spec);

        match result.unwrap_err() {
            Error::CommandTimeout {
                program,
                args,
                timeout: reported,
            } => {
                assert_eq!(program, "sleep");
                assert_eq!(args, vec!["10"]);
                assert_eq!(reported, timeout);
            }
            other => panic!("expected CommandTimeout, got {other:?}"),
        }
    }

    #[test]
    fn timeout_redacts_args_when_requested() {
        // CommandTimeout must store already-redacted args so the derived Debug
        // (used by tracing ?err / {:?}) never leaks secret flag values.
        let runner = DuctRunner;
        let spec = CommandSpec::new("bash")
            .args(["-c", "sleep 10", "--token", "secret-value"])
            .redact(true)
            .timeout(Duration::from_millis(50));
        let result = runner.run(&spec);

        match result.unwrap_err() {
            Error::CommandTimeout { args, .. } => {
                assert!(
                    args.contains(&"***".to_owned()),
                    "expected redacted args, got {args:?}"
                );
                assert!(
                    !args.contains(&"secret-value".to_owned()),
                    "secret value leaked into CommandTimeout args: {args:?}"
                );
            }
            other => panic!("expected CommandTimeout, got {other:?}"),
        }
    }

    #[test]
    fn stdout_stderr_separation() {
        let runner = DuctRunner;
        let spec = CommandSpec::new("bash").args(["-c", "echo OUT; echo ERR >&2"]);
        let output = runner.run(&spec).unwrap();

        assert!(output.success);
        assert!(output.stdout.contains("OUT"));
        assert!(output.stderr.contains("ERR"));
        assert!(!output.stdout.contains("ERR"));
        assert!(!output.stderr.contains("OUT"));
    }

    #[test]
    fn large_output_captured() {
        let runner = DuctRunner;
        let spec = CommandSpec::new("bash")
            .args(["-c", "for i in $(seq 1 100); do echo \"line $i\"; done"]);
        let output = runner.run(&spec).unwrap();

        assert!(output.success);
        let lines: Vec<&str> = output
            .stdout
            .lines()
            .filter(|line| !line.is_empty())
            .collect();
        assert_eq!(lines.len(), 100);
        assert_eq!(lines[0], "line 1");
        assert_eq!(lines[99], "line 100");
    }

    #[test]
    fn specific_exit_code_preserved() {
        let runner = DuctRunner;
        let spec = CommandSpec::new("bash").args(["-c", "exit 42"]);
        let output = runner.run(&spec).unwrap();

        assert!(!output.success);
        assert_eq!(output.exit_code, Some(42));
    }

    #[test]
    fn timeout_kills_child_process() {
        let runner = DuctRunner;
        let marker = std::env::temp_dir().join(format!(
            "toride_runner_duct_timeout_{}_{}",
            std::process::id(),
            "marker"
        ));
        let _ = std::fs::remove_file(&marker);
        let script = format!("sleep 10 && echo SURVIVED > {}", marker.display());
        let spec = CommandSpec::new("bash")
            .args(["-c", script.as_str()])
            .timeout(Duration::from_millis(100));

        let result = runner.run(&spec);
        assert!(matches!(result.unwrap_err(), Error::CommandTimeout { .. }));
        std::thread::sleep(Duration::from_millis(200));

        let marker_exists = marker.exists();
        let _ = std::fs::remove_file(&marker);
        assert!(!marker_exists, "timed-out child process kept running");
    }

    #[test]
    fn options_default_preserves_unit_runner_policy() {
        let options = DuctRunnerOptions::default();

        assert_eq!(
            options.default_timeout,
            Some(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        );
        assert!(options.log_commands);
    }

    #[test]
    fn builder_configures_default_timeout() {
        let runner = DuctRunner::builder()
            .default_timeout(Duration::from_millis(50))
            .build();
        let spec = CommandSpec::new("sleep").arg("10");
        let result = runner.run(&spec);

        assert!(matches!(result.unwrap_err(), Error::CommandTimeout { .. }));
    }

    #[test]
    fn builder_can_disable_default_timeout() {
        let runner = DuctRunner::builder()
            .no_default_timeout()
            .log_commands(false)
            .build();
        let spec = CommandSpec::new("bash").args(["-c", "sleep 0.05; echo done"]);
        let output = runner.run(&spec).unwrap();

        assert_eq!(runner.options().default_timeout, None);
        assert!(!runner.options().log_commands);
        assert_eq!(output.stdout_trimmed(), "done");
    }

    #[test]
    fn spec_timeout_overrides_runner_default_timeout() {
        let runner = DuctRunner::builder()
            .default_timeout(Duration::from_millis(50))
            .build();
        let spec = CommandSpec::new("bash")
            .args(["-c", "sleep 0.1; echo done"])
            .timeout(Duration::from_secs(1));
        let output = runner.run(&spec).unwrap();

        assert_eq!(output.stdout_trimmed(), "done");
    }

    #[test]
    fn with_options_builds_configured_runner() {
        let runner = DuctRunner::with_options(DuctRunnerOptions {
            default_timeout: None,
            log_commands: false,
        });

        assert_eq!(runner.options().default_timeout, None);
        assert!(!runner.options().log_commands);
    }

    #[test]
    fn capture_output_mode_is_default_behavior() {
        let runner = DuctRunner;
        let spec = CommandSpec::new("bash")
            .args(["-c", "echo OUT; echo ERR >&2"])
            .output_mode(OutputMode::Capture);
        let output = runner.run(&spec).unwrap();

        assert!(output.stdout.contains("OUT"));
        assert!(output.stderr.contains("ERR"));
    }

    #[test]
    fn inherit_output_mode_returns_empty_captured_output() {
        let runner = DuctRunner;
        let spec = CommandSpec::new("bash")
            .args(["-c", "exit 17"])
            .output_mode(OutputMode::Inherit);
        let output = runner.run(&spec).unwrap();

        assert!(!output.success);
        assert_eq!(output.exit_code, Some(17));
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn stream_output_mode_is_explicitly_unsupported_for_duct_runner() {
        let runner = DuctRunner;
        let spec = CommandSpec::new("echo")
            .arg("hello")
            .output_mode(OutputMode::Stream);
        let result = runner.run(&spec);

        match result.unwrap_err() {
            Error::Other(message) => assert!(message.contains("OutputMode::Stream")),
            other => panic!("expected unsupported stream error, got {other:?}"),
        }
    }

    #[test]
    fn output_limit_preserves_under_cap_capture() {
        // Output well under the cap is captured exactly as in unlimited mode.
        let runner = DuctRunner;
        let spec = CommandSpec::new("echo").arg("hello").output_limit(1024);
        let output = runner.run(&spec).unwrap();

        assert!(output.success);
        assert_eq!(output.stdout_trimmed(), "hello");
    }

    #[test]
    fn output_limit_exceeded_on_stdout() {
        let runner = DuctRunner;
        // Writes ~3 KB to stdout; cap at 64 bytes.
        let spec = CommandSpec::new("bash")
            .args(["-c", "for i in $(seq 1 100); do echo line; done"])
            .output_limit(64);
        let result = runner.run(&spec);

        match result {
            Err(Error::OutputLimitExceeded { limit, .. }) => assert_eq!(limit, 64),
            other => panic!("expected OutputLimitExceeded, got {other:?}"),
        }
    }

    #[test]
    fn output_limit_exceeded_on_stderr() {
        let runner = DuctRunner;
        let spec = CommandSpec::new("bash")
            .args(["-c", "for i in $(seq 1 100); do echo line >&2; done"])
            .output_limit(64);
        let result = runner.run(&spec);

        assert!(matches!(result, Err(Error::OutputLimitExceeded { .. })));
    }

    #[test]
    fn output_limit_counts_stdout_plus_stderr() {
        // Each stream alone is under the cap, but together they exceed it.
        let runner = DuctRunner;
        let spec = CommandSpec::new("bash")
            .args(["-c", "echo AAAA; echo BBBB >&2; echo CCCC; echo DDDD >&2"])
            .output_limit(8);
        let result = runner.run(&spec);

        assert!(matches!(result, Err(Error::OutputLimitExceeded { .. })));
    }

    #[test]
    fn output_limit_bounds_memory_on_newline_free_stream() {
        // A single newline-free stream that writes far more than the cap. The
        // bounded reads must trip the cap and kill the process rather than
        // buffering the whole stream. We assert the *result* is an
        // OutputLimitExceeded error — proving the cap fired, not a timeout.
        let runner = DuctRunner;
        let spec = CommandSpec::new("bash")
            .args(["-c", "yes | tr -d '\\n' | head -c 100000"])
            .output_limit(256)
            .timeout(Duration::from_secs(10));
        let result = runner.run(&spec);

        match result {
            Err(Error::OutputLimitExceeded { .. }) => {}
            Err(other) => panic!(
                "expected OutputLimitExceeded, got {other:?} (cap should fire before timeout)"
            ),
            Ok(_) => panic!("expected OutputLimitExceeded, got Ok"),
        }
    }

    #[test]
    fn output_limit_kills_running_process() {
        // A slow stream that would run for a while; the cap must kill it
        // promptly. We assert the result returns quickly (the cap fires long
        // before the natural end) and that no leftover process survives.
        let runner = DuctRunner;
        let marker = std::env::temp_dir().join(format!(
            "toride_duct_limit_kill_{}_{}",
            std::process::id(),
            "marker"
        ));
        let _ = std::fs::remove_file(&marker);
        let script = format!(
            "for i in $(seq 1 100000); do echo x; done; echo SURVIVED > {}",
            marker.display()
        );
        let spec = CommandSpec::new("bash")
            .args(["-c", script.as_str()])
            .output_limit(128);

        let result = runner.run(&spec);
        assert!(matches!(result, Err(Error::OutputLimitExceeded { .. })));

        std::thread::sleep(Duration::from_millis(300));
        let marker_exists = marker.exists();
        let _ = std::fs::remove_file(&marker);
        assert!(
            !marker_exists,
            "output-limited child was not killed (reached SURVIVED)"
        );
    }

    #[test]
    fn output_limit_inherit_mode_is_ignored() {
        // Inherit mode does not capture, so the limit must be ignored: the
        // real exit code is returned and captured output is empty.
        let runner = DuctRunner;
        let spec = CommandSpec::new("bash")
            .args(["-c", "exit 17"])
            .output_mode(OutputMode::Inherit)
            .output_limit(8);
        let output = runner.run(&spec).unwrap();

        assert!(!output.success);
        assert_eq!(output.exit_code, Some(17));
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn output_limit_redacts_args_in_error_when_requested() {
        let runner = DuctRunner;
        let spec = CommandSpec::new("bash")
            .args(["-c", "yes | head -c 10000", "--token", "secret-value"])
            .redact(true)
            .output_limit(64);
        let result = runner.run(&spec);

        match result {
            Err(Error::OutputLimitExceeded { args, .. }) => {
                assert!(args.contains("***"));
                assert!(!args.contains("secret-value"));
            }
            other => panic!("expected OutputLimitExceeded, got {other:?}"),
        }
    }

    #[test]
    fn output_limit_non_utf8_over_limit_errors_by_byte_count() {
        // Non-UTF-8 bytes over the cap fail by byte count before any decoding.
        let runner = DuctRunner;
        let spec = CommandSpec::new("bash")
            .args(["-c", "head -c 1000 /dev/urandom"])
            .output_limit(64);
        let result = runner.run(&spec);

        assert!(matches!(result, Err(Error::OutputLimitExceeded { .. })));
    }

    #[test]
    fn output_limit_unset_preserves_unlimited_capture() {
        // Default (no limit) captures large output fully.
        let runner = DuctRunner;
        let spec = CommandSpec::new("bash")
            .args(["-c", "for i in $(seq 1 50); do echo \"line $i\"; done"]);
        let output = runner.run(&spec).unwrap();

        assert!(output.success);
        let lines: Vec<&str> = output.stdout.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 50);
    }
}
