//! Debian/Ubuntu (APT) specific update backend.
//!
//! Provides APT-specific operations for managing `unattended-upgrades`:
//!
//! - Checking for available updates via `apt-check`
//! - Applying updates via `unattended-upgrades`
//! - Querying update status by parsing the unattended-upgrades log

use tracing::info;

use crate::error::{Error, Result};
use crate::paths::UpdatePaths;
use crate::report::UpdateStatus;

// ---------------------------------------------------------------------------
// AptBackend
// ---------------------------------------------------------------------------

/// APT-specific backend for automatic update operations.
///
/// Wraps command execution for `apt-check`, `unattended-upgrades`, and
/// related APT tools. Every command is built as a
/// [`toride_runner::CommandSpec`] and run through the injected
/// [`toride_runner::Runner`], so the backend is fully testable with
/// [`toride_runner::fake::FakeRunner`].
pub struct AptBackend<'a> {
    runner: &'a dyn toride_runner::Runner,
    paths: UpdatePaths,
}

impl<'a> AptBackend<'a> {
    /// Create a new APT backend with the given runner.
    pub fn new(runner: &'a dyn toride_runner::Runner) -> Self {
        Self {
            runner,
            paths: UpdatePaths::new(),
        }
    }

    /// Create an APT backend with explicit paths.
    pub fn with_paths(runner: &'a dyn toride_runner::Runner, paths: UpdatePaths) -> Self {
        Self { runner, paths }
    }

    /// Check for available updates using `apt-check`.
    ///
    /// `apt-check` prints `N;M` to **stderr** (where `N` is the number of
    /// security updates and `M` is the total). Returns `(security, total)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if `apt-check` fails, or
    /// [`Error::ConfigParse`] if its output cannot be parsed.
    pub fn check_updates(&self) -> Result<(usize, usize)> {
        info!("Checking APT updates");
        let spec = check_updates_spec();
        let output = self
            .runner
            .run_checked(&spec)
            .map_err(|e| Error::CommandFailed(format!("apt-check failed: {e}")))?;
        crate::parse::parse_apt_check(&output.stderr)
    }

    /// Apply pending security updates via `unattended-upgrades`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the command fails.
    pub fn apply_updates(&self) -> Result<()> {
        info!("Applying APT updates via unattended-upgrades");
        let spec = apply_updates_spec();
        self.runner
            .run_checked(&spec)
            .map_err(|e| Error::CommandFailed(format!("unattended-upgrades failed: {e}")))?;
        Ok(())
    }

    /// Query the current update status by parsing the log file.
    ///
    /// Reads `/var/log/unattended-upgrades/unattended-upgrades.log` (or the
    /// configured [`UpdatePaths::log_file`]) and parses the last run / pending
    /// security counts via [`crate::parse::parse_unattended_upgrades_status`].
    /// A missing log file yields an empty (never-run) status.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the log file exists but cannot be read, or
    /// [`Error::ConfigParse`] if it cannot be parsed.
    pub fn status(&self) -> Result<UpdateStatus> {
        info!("Querying APT update status");
        let log_path = &self.paths.log_file;
        if !log_path.exists() {
            return Ok(UpdateStatus::empty());
        }
        let content = std::fs::read_to_string(log_path)?;
        let mut status = crate::parse::parse_unattended_upgrades_status(&content)?;
        // The log file existing at all implies auto-updates were configured.
        if content.lines().any(|l| !l.trim().is_empty()) {
            status.auto_updates_enabled = true;
        }
        Ok(status)
    }

    /// Check if `unattended-upgrades` binary is available.
    pub fn is_available(&self) -> bool {
        which::which("unattended-upgrades").is_ok()
    }

    /// Expose the exact [`toride_runner::CommandSpec`] used by
    /// [`Self::check_updates`] (for assertions/tests).
    fn check_updates_spec_ref() -> toride_runner::CommandSpec {
        check_updates_spec()
    }

    /// Expose the exact [`toride_runner::CommandSpec`] used by
    /// [`Self::apply_updates`] (for assertions/tests).
    fn apply_updates_spec_ref() -> toride_runner::CommandSpec {
        apply_updates_spec()
    }
}

/// Build the `apt-check` [`toride_runner::CommandSpec`].
fn check_updates_spec() -> toride_runner::CommandSpec {
    toride_runner::CommandSpec::new("/usr/lib/update-notifier/apt-check")
}

/// Build the `unattended-upgrades` [`toride_runner::CommandSpec`].
fn apply_updates_spec() -> toride_runner::CommandSpec {
    toride_runner::CommandSpec::new("unattended-upgrades").arg("-v")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use toride_runner::fake::FakeRunner;
    use toride_runner::{CommandOutput, CommandSpec};

    #[test]
    fn check_updates_builds_apt_check_command() {
        // apt-check writes "N;M" to stderr.
        let runner = FakeRunner::new().push_response(CommandOutput::from_stderr("3;12", 0));
        let (security, total) = AptBackend::new(&runner).check_updates().unwrap();
        assert_eq!(security, 3);
        assert_eq!(total, 12);
        runner.assert_called_with(&CommandSpec::new("/usr/lib/update-notifier/apt-check"));
    }

    #[test]
    fn apply_updates_builds_unattended_upgrades_command() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout("done"));
        AptBackend::new(&runner).apply_updates().unwrap();
        runner.assert_called_with(&CommandSpec::new("unattended-upgrades").arg("-v"));
    }

    #[test]
    fn apply_updates_propagates_failure() {
        let runner = FakeRunner::new()
            .push_response(CommandOutput::from_stderr("dpkg lock held", 100));
        let err = AptBackend::new(&runner).apply_updates().unwrap_err();
        assert!(err.to_string().contains("unattended-upgrades failed"));
    }

    /// Real `/var/log/unattended-upgrades/unattended-upgrades.log` sample.
    ///
    /// Source: Ubuntu Server docs, "Automatic updates" -- a run that installed
    /// libc6 + python3-jinja2 (from the reboot-notification example).
    /// https://ubuntu.com/server/docs/how-to/software/automatic-updates/
    #[test]
    fn status_parses_log_file() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("unattended-upgrades.log");
        std::fs::write(
            &log,
            "2025-03-13 20:43:25,923 INFO Starting unattended upgrades script\n\
             2025-03-13 20:43:25,924 INFO Allowed origins are: o=Ubuntu,a=noble, o=Ubuntu,a=noble-security\n\
             2025-03-13 20:43:29,082 INFO Packages that will be upgraded: libc6 python3-jinja2\n\
             2025-03-13 20:43:29,082 INFO Writing dpkg log to /var/log/unattended-upgrades/unattended-upgrades-dpkg.log\n\
             2025-03-13 20:43:39,532 INFO All upgrades installed\n",
        )
        .unwrap();

        let runner = FakeRunner::new();
        let mut backend = AptBackend::new(&runner);
        backend.paths.log_file = log;
        let status = backend.status().unwrap();
        assert!(status.auto_updates_enabled);
        assert_eq!(status.last_run.as_deref(), Some("2025-03-13 20:43:25,923"));
        // 2 packages on the "Packages that will be upgraded:" line.
        assert_eq!(status.pending_security, 2);
    }

    #[test]
    fn status_returns_empty_when_log_missing() {
        let runner = FakeRunner::new();
        let mut backend = AptBackend::new(&runner);
        backend.paths.log_file = "/nonexistent/u-u.log".into();
        let status = backend.status().unwrap();
        assert_eq!(status.pending_security, 0);
        assert!(status.last_run.is_none());
    }

    /// Guard against accidental drift in the constructed command.
    #[test]
    fn command_specs_are_stable() {
        let check = AptBackend::check_updates_spec_ref();
        assert_eq!(check.program, "/usr/lib/update-notifier/apt-check");
        assert!(check.args.is_empty());

        let apply = AptBackend::apply_updates_spec_ref();
        assert_eq!(apply.program, "unattended-upgrades");
        assert_eq!(apply.args, vec!["-v".to_owned()]);
    }
}
