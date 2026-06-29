//! Tailscale service lifecycle management.
//!
//! Provides [`TailscaleService`] for managing the `tailscaled` system service
//! and driving the `tailscale` CLI for connect/disconnect operations. Service
//! lifecycle (start/stop/restart/enable/disable/is_active) is delegated to
//! [`toride_service::ServiceManager`] which shells out to `systemctl`, while
//! `tailscale up/down/status` are built as [`toride_runner::CommandSpec`]s and
//! executed through the injected [`toride_runner::Runner`].
//!
//! Every command goes through the shared runner abstraction, so the entire
//! call stack is testable with [`toride_runner::FakeRunner`] and respects
//! dry-run mode.

use std::sync::Arc;
use std::time::Duration;

use toride_runner::Runner;
use toride_runner::output::CommandOutput;
use toride_runner::spec::CommandSpec;

use crate::Result;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The systemd unit name for the Tailscale daemon (without `.service`).
const TAILSCALED_UNIT: &str = "tailscaled";

/// The `tailscale` CLI binary name.
const TAILSCALE_BIN: &str = "tailscale";

/// Default timeout for `tailscale up` (it can take a while to negotiate).
const UP_TIMEOUT: Duration = Duration::from_mins(2);

/// Default timeout for `tailscale status` / `tailscale down`.
const STATUS_TIMEOUT: Duration = Duration::from_secs(15);

/// Combined stdout+stderr byte cap enforced on every `tailscale` CLI call.
///
/// `tailscale` output is bounded in normal operation, but a misbehaving
/// daemon or a tampered binary could emit an unbounded stream; capping at
/// capture time (via [`CommandSpec::output_limit`]) prevents an OOM and
/// bounds the size of captured output / error variants.
const OUTPUT_LIMIT_BYTES: usize = 8 * 1024 * 1024;

/// Maximum number of bytes of `tailscale status --json` stdout retained for
/// JSON parsing. A healthy status document is well under a megabyte; this is
/// a defensive ceiling so a huge response is rejected before it can drive
/// unbounded allocations in the JSON parser.
const STATUS_JSON_MAX_BYTES: usize = 8 * 1024 * 1024;

// ---------------------------------------------------------------------------
// SharedRunner -- lets an `Arc<dyn Runner>` back a `Box<dyn Runner>`
// ---------------------------------------------------------------------------

/// A [`Runner`] wrapper that holds a shared reference-counted runner.
///
/// This exists so that a single injected [`Runner`] can back both the
/// [`toride_service::ServiceManager`] (which requires `Box<dyn Runner>`) and
/// the direct CLI command execution performed by [`TailscaleService`], without
/// forcing the caller to construct two runners.
#[derive(Clone)]
struct SharedRunner(Arc<dyn Runner>);

impl Runner for SharedRunner {
    fn run(&self, spec: &CommandSpec) -> std::result::Result<CommandOutput, toride_runner::Error> {
        self.0.run(spec)
    }
}

// ---------------------------------------------------------------------------
// TailscaleService
// ---------------------------------------------------------------------------

/// Manager for the `tailscaled` system service and the `tailscale` CLI.
///
/// `TailscaleService` composes [`toride_service::ServiceManager`] (for systemd
/// lifecycle operations against the `tailscaled` unit) with direct
/// [`CommandSpec`] construction (for `tailscale up/down/status`).
///
/// # Construction
///
/// - [`TailscaleService::new`] -- default with a real [`toride_runner::DuctRunner`].
/// - [`TailscaleService::with_runner`] -- inject any [`Runner`] (used by tests).
/// - [`TailscaleService::with_dry_run`] -- log commands but do not execute.
///
/// # Example
///
/// ```ignore
/// use toride_tailscale::service::TailscaleService;
///
/// let svc = TailscaleService::new();
/// svc.start()?;
/// let active = svc.is_active()?;
/// ```
pub struct TailscaleService {
    /// Shared command runner for both service and CLI operations.
    runner: Arc<dyn Runner>,
    /// Whether to run in dry-run mode (log commands but do not execute).
    dry_run: bool,
}

impl TailscaleService {
    /// Create a new `TailscaleService` backed by a real [`toride_runner::DuctRunner`].
    pub fn new() -> Self {
        Self::with_runner(Arc::new(toride_runner::DuctRunner))
    }

    /// Create a new `TailscaleService` backed by the given [`Runner`].
    ///
    /// The runner is shared (via `Arc`) between the service manager and CLI
    /// command execution, so a single [`toride_runner::FakeRunner`] can drive
    /// both in tests.
    pub fn with_runner(runner: Arc<dyn Runner>) -> Self {
        Self {
            runner,
            dry_run: false,
        }
    }

    /// Enable dry-run mode (log commands but do not execute).
    #[must_use]
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Build a [`toride_service::ServiceManager`] sharing this service's runner.
    ///
    /// The manager is constructed fresh on each call; it is cheap (a single
    /// `Box` allocation wrapping the shared runner).
    fn service_manager(&self) -> toride_service::ServiceManager {
        let shared = SharedRunner(Arc::clone(&self.runner));
        toride_service::ServiceManager::new(Box::new(shared))
    }

    /// Check if the `tailscaled` service is currently active.
    ///
    /// Probes via `systemctl is-active tailscaled` (through
    /// [`toride_service::ServiceManager`]). In dry-run mode this returns
    /// `Ok(false)` without executing anything.
    ///
    /// # Errors
    ///
    /// Returns an error if the service status cannot be determined.
    pub fn is_active(&self) -> Result<bool> {
        if self.dry_run {
            tracing::debug!(unit = %TAILSCALED_UNIT, "dry-run: skipping is-active probe");
            return Ok(false);
        }
        Ok(self.service_manager().is_active(TAILSCALED_UNIT)?)
    }

    /// Start the `tailscaled` service.
    ///
    /// # Errors
    ///
    /// Returns an error if the service cannot be started.
    pub fn start(&self) -> Result<()> {
        self.run_service_op("start")
    }

    /// Stop the `tailscaled` service.
    ///
    /// # Errors
    ///
    /// Returns an error if the service cannot be stopped.
    pub fn stop(&self) -> Result<()> {
        self.run_service_op("stop")
    }

    /// Restart the `tailscaled` service.
    ///
    /// # Errors
    ///
    /// Returns an error if the service cannot be restarted.
    pub fn restart(&self) -> Result<()> {
        self.run_service_op("restart")
    }

    /// Enable the `tailscaled` service to start on boot.
    ///
    /// # Errors
    ///
    /// Returns an error if the service cannot be enabled.
    pub fn enable(&self) -> Result<()> {
        self.run_service_op("enable")
    }

    /// Disable the `tailscaled` service from starting on boot.
    ///
    /// # Errors
    ///
    /// Returns an error if the service cannot be disabled.
    pub fn disable(&self) -> Result<()> {
        self.run_service_op("disable")
    }

    /// Shared helper for the no-argument service lifecycle operations.
    fn run_service_op(&self, op: &str) -> Result<()> {
        if self.dry_run {
            tracing::info!(unit = %TAILSCALED_UNIT, op = %op, "dry-run: skipping service operation");
            return Ok(());
        }
        let mgr = self.service_manager();
        match op {
            "start" => mgr.start(TAILSCALED_UNIT)?,
            "stop" => mgr.stop(TAILSCALED_UNIT)?,
            "restart" => mgr.restart(TAILSCALED_UNIT)?,
            "enable" => mgr.enable(TAILSCALED_UNIT)?,
            "disable" => mgr.disable(TAILSCALED_UNIT)?,
            _ => return Err(crate::Error::Other(format!("unknown service op: {op}"))),
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // `tailscale` CLI operations (up / down / status)
    // ------------------------------------------------------------------

    /// Bring the node up on the tailnet via `tailscale up`.
    ///
    /// Runs `tailscale up` (without arguments) which reuses the previously
    /// stored login/opts. In dry-run mode the command is logged but not
    /// executed.
    ///
    /// # Errors
    ///
    /// Returns an error if `tailscale up` exits non-zero.
    pub fn up(&self) -> Result<()> {
        if self.dry_run {
            tracing::info!("dry-run: skipping `tailscale up`");
            return Ok(());
        }
        let spec = CommandSpec::new(TAILSCALE_BIN)
            .arg("up")
            .timeout(UP_TIMEOUT)
            .output_limit(OUTPUT_LIMIT_BYTES);
        self.run_checked(&spec)?;
        Ok(())
    }

    /// Disconnect the node from the tailnet via `tailscale down`.
    ///
    /// # Errors
    ///
    /// Returns an error if `tailscale down` exits non-zero.
    pub fn down(&self) -> Result<()> {
        if self.dry_run {
            tracing::info!("dry-run: skipping `tailscale down`");
            return Ok(());
        }
        let spec = CommandSpec::new(TAILSCALE_BIN)
            .arg("down")
            .timeout(STATUS_TIMEOUT)
            .output_limit(OUTPUT_LIMIT_BYTES);
        self.run_checked(&spec)?;
        Ok(())
    }

    /// Fetch the raw `tailscale status --json` output.
    ///
    /// Returns the full JSON document as a [`serde_json::Value`]. This is the
    /// canonical source for peer discovery, exit-node detection, and connection
    /// state when the HTTP local API is unavailable.
    ///
    /// # Errors
    ///
    /// Returns an error if `tailscale status` exits non-zero or the output is
    /// not valid JSON.
    pub fn status_json(&self) -> Result<serde_json::Value> {
        let spec = CommandSpec::new(TAILSCALE_BIN)
            .args(["status", "--json"])
            .timeout(STATUS_TIMEOUT)
            .output_limit(OUTPUT_LIMIT_BYTES);
        let output = self.run_checked(&spec)?;
        // Defensive bound on the stdout we hand to the JSON parser. The runner
        // already caps combined output at `OUTPUT_LIMIT_BYTES`, but enforce the
        // ceiling explicitly here too so a future change to the runner cap (or a
        // runner that does not honour `output_limit`) cannot let a pathological
        // response drive unbounded allocations in `serde_json`.
        if output.stdout.len() > STATUS_JSON_MAX_BYTES {
            return Err(crate::Error::ApiError(format!(
                "`tailscale status` JSON output exceeded {} bytes (got {})",
                STATUS_JSON_MAX_BYTES,
                output.stdout.len()
            )));
        }
        serde_json::from_str(&output.stdout).map_err(|e| {
            crate::Error::ApiError(format!("failed to parse `tailscale status` JSON: {e}"))
        })
    }

    /// Run a [`CommandSpec`] through the runner and propagate non-zero exits.
    ///
    /// The captured stderr is routed through
    /// [`toride_runner::display::scrub_stderr`] before being stored in a
    /// [`crate::Error::CommandFailed`]: it applies the canonical length cap
    /// ([`toride_runner::display::STDERR_CAP_BYTES`]) and, when the spec
    /// carries `redact(true)`, scrubs any secret values the failed command may
    /// have echoed to stderr. Raw, potentially huge or secret-bearing stderr
    /// therefore never reaches the error variant.
    fn run_checked(&self, spec: &CommandSpec) -> Result<CommandOutput> {
        let output = self
            .runner
            .run(spec)
            .map_err(|e| crate::Error::CommandFailed {
                program: spec.program.clone(),
                code: None,
                stderr: toride_runner::display::scrub_stderr(spec, &e.to_string()),
            })?;
        if !output.success {
            return Err(crate::Error::CommandFailed {
                program: spec.program.clone(),
                code: output.exit_code,
                stderr: toride_runner::display::scrub_stderr(spec, &output.stderr),
            });
        }
        Ok(output)
    }

    /// Return a snapshot of the shared runner (useful for wiring into other
    /// components that need the same execution layer).
    pub fn runner(&self) -> Arc<dyn Runner> {
        Arc::clone(&self.runner)
    }
}

impl Default for TailscaleService {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use toride_runner::fake::FakeRunner;

    fn spec_for(program: &str, args: &[&str]) -> CommandSpec {
        CommandSpec::new(program).args(args.iter().copied())
    }

    #[test]
    fn service_ops_use_systemctl_through_service_manager() {
        // FakeRunner in lenient mode returns success for any systemctl call.
        let runner = Arc::new(FakeRunner::new());
        let svc = TailscaleService::with_runner(runner.clone());

        svc.start().unwrap();
        svc.stop().unwrap();
        svc.restart().unwrap();
        svc.enable().unwrap();
        svc.disable().unwrap();

        let calls = runner.calls();
        let progs: Vec<(&String, Vec<String>)> =
            calls.iter().map(|c| (&c.program, c.args.clone())).collect();

        assert_eq!(progs.len(), 5);
        assert_eq!(
            progs[0],
            (
                &"systemctl".to_owned(),
                vec!["start".to_owned(), "tailscaled".to_owned()]
            )
        );
        assert_eq!(
            progs[1],
            (
                &"systemctl".to_owned(),
                vec!["stop".to_owned(), "tailscaled".to_owned()]
            )
        );
        assert_eq!(
            progs[2],
            (
                &"systemctl".to_owned(),
                vec!["restart".to_owned(), "tailscaled".to_owned()]
            )
        );
        assert_eq!(
            progs[3],
            (
                &"systemctl".to_owned(),
                vec!["enable".to_owned(), "tailscaled".to_owned()]
            )
        );
        assert_eq!(
            progs[4],
            (
                &"systemctl".to_owned(),
                vec!["disable".to_owned(), "tailscaled".to_owned()]
            )
        );
    }

    #[test]
    fn is_active_returns_true_when_systemctl_succeeds() {
        let runner = Arc::new(FakeRunner::new().respond(
            spec_for("systemctl", &["is-active", "tailscaled"]),
            CommandOutput::from_stdout("active"),
        ));
        let svc = TailscaleService::with_runner(runner.clone());
        assert!(svc.is_active().unwrap());
        runner.assert_called_with(&spec_for("systemctl", &["is-active", "tailscaled"]));
    }

    #[test]
    fn is_active_returns_false_when_systemctl_fails() {
        let runner = Arc::new(FakeRunner::new().respond(
            spec_for("systemctl", &["is-active", "tailscaled"]),
            CommandOutput::from_stderr("inactive", 3),
        ));
        let svc = TailscaleService::with_runner(runner);
        assert!(!svc.is_active().unwrap());
    }

    #[test]
    fn is_active_dry_run_skips_probe() {
        let runner = Arc::new(FakeRunner::new().strict());
        let svc = TailscaleService::with_runner(runner.clone()).with_dry_run(true);
        assert!(!svc.is_active().unwrap());
        // Strict mode would error if any call were made.
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn dry_run_skips_service_ops() {
        let runner = Arc::new(FakeRunner::new().strict());
        let svc = TailscaleService::with_runner(runner.clone()).with_dry_run(true);
        svc.start().unwrap();
        svc.stop().unwrap();
        assert!(
            runner.calls().is_empty(),
            "dry-run must not execute commands"
        );
    }

    #[test]
    fn up_builds_tailscale_up_command() {
        let runner = Arc::new(FakeRunner::new().respond(
            spec_for("tailscale", &["up"]),
            CommandOutput::from_stdout(""),
        ));
        let svc = TailscaleService::with_runner(runner.clone());
        svc.up().unwrap();
        runner.assert_called_with(&spec_for("tailscale", &["up"]));
    }

    #[test]
    fn down_builds_tailscale_down_command() {
        let runner = Arc::new(FakeRunner::new().respond(
            spec_for("tailscale", &["down"]),
            CommandOutput::from_stdout(""),
        ));
        let svc = TailscaleService::with_runner(runner.clone());
        svc.down().unwrap();
        runner.assert_called_with(&spec_for("tailscale", &["down"]));
    }

    #[test]
    fn status_json_parses_canned_output() {
        let canned = r#"{
            "BackendState": "Running",
            "Self": {"HostName": "my-host", "TailscaleIPs": ["100.64.0.1"]},
            "MagicDNSEnabled": true,
            "Peer": {}
        }"#;
        let runner = Arc::new(FakeRunner::new().respond(
            spec_for("tailscale", &["status", "--json"]),
            CommandOutput::from_stdout(canned),
        ));
        let svc = TailscaleService::with_runner(runner.clone());
        let val = svc.status_json().unwrap();
        assert_eq!(val["BackendState"], "Running");
        assert_eq!(val["Self"]["HostName"], "my-host");
        runner.assert_called_with(&spec_for("tailscale", &["status", "--json"]));
    }

    #[test]
    fn status_json_errors_on_nonzero_exit() {
        let runner = Arc::new(FakeRunner::new().respond(
            spec_for("tailscale", &["status", "--json"]),
            CommandOutput::from_stderr("tailscaled not running", 1),
        ));
        let svc = TailscaleService::with_runner(runner);
        let err = svc.status_json().unwrap_err();
        assert!(matches!(err, crate::Error::CommandFailed { .. }));
    }

    #[test]
    fn run_checked_failure_stderr_is_scrubbed_and_capped() {
        // `run_checked` routes failure stderr through
        // `toride_runner::display::scrub_stderr`, which caps it at
        // STDERR_CAP_BYTES. An unbounded burst therefore cannot blow up the
        // CommandFailed variant, and a secret echoed to stderr (when the spec
        // carries redact(true)) is scrubbed. Verify the cap path here.
        let big = "x".repeat(toride_runner::display::STDERR_CAP_BYTES + 5_000);
        let runner = Arc::new(FakeRunner::new().respond(
            spec_for("tailscale", &["status", "--json"]),
            CommandOutput::from_stderr(&big, 1),
        ));
        let svc = TailscaleService::with_runner(runner);
        let err = svc.status_json().unwrap_err();
        match err {
            crate::Error::CommandFailed { stderr, .. } => {
                assert!(
                    stderr.contains(toride_runner::display::STDERR_TRUNCATION_MARKER),
                    "stderr must be capped: {stderr}"
                );
                assert!(stderr.len() < big.len(), "stderr must be bounded");
            }
            other => panic!("expected CommandFailed, got {other:?}"),
        }
    }

    #[test]
    fn run_checked_scrubs_secret_from_failure_stderr() {
        // When the spec carries a sensitive flag value AND `redact(true)`, a
        // value echoed to stderr by the failing command must be scrubbed before
        // reaching CommandFailed. `--key` is a default redaction flag, so its
        // value is collected and replaced with `***` in the captured stderr.
        let secret = "tskey-auth-EXAMPLESECRETVALUE";
        let redacted_spec = CommandSpec::new("tailscale")
            .args(["up", "--key", secret])
            .redact(true);
        let runner = Arc::new(FakeRunner::new().respond(
            redacted_spec.clone(),
            CommandOutput::from_stderr(format!("auth failure: bad key {secret}"), 1),
        ));
        let svc = TailscaleService::with_runner(runner);
        // `run_checked` is private to the module; the test module shares the
        // parent's private items, so call it directly with the redacted spec.
        let err = svc.run_checked(&redacted_spec).unwrap_err();
        match err {
            crate::Error::CommandFailed { stderr, .. } => {
                assert!(
                    !stderr.contains(secret),
                    "secret leaked into CommandFailed stderr: {stderr}"
                );
                assert!(
                    stderr.contains("***"),
                    "expected redaction marker: {stderr}"
                );
            }
            other => panic!("expected CommandFailed, got {other:?}"),
        }
    }

    #[test]
    fn up_dry_run_skips_execution() {
        let runner = Arc::new(FakeRunner::new().strict());
        let svc = TailscaleService::with_runner(runner.clone()).with_dry_run(true);
        svc.up().unwrap();
        svc.down().unwrap();
        assert!(runner.calls().is_empty());
    }
}
