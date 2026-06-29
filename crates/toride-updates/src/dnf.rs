//! Fedora/RHEL (DNF) specific update backend.
//!
//! Provides DNF-specific operations for managing `dnf-automatic`:
//!
//! - Checking for available updates via `dnf check-update`
//! - Applying updates via `dnf-automatic`
//! - Querying update status from the systemd journal

use tracing::info;

use crate::error::{Error, Result};
use crate::paths::UpdatePaths;
use crate::report::UpdateStatus;

// ---------------------------------------------------------------------------
// DnfBackend
// ---------------------------------------------------------------------------

/// DNF-specific backend for automatic update operations.
///
/// Wraps command execution for `dnf check-update`, `dnf-automatic`, and
/// related DNF tools. Every command is built as a
/// [`toride_runner::CommandSpec`] and run through the injected
/// [`toride_runner::Runner`].
pub struct DnfBackend<'a> {
    runner: &'a dyn toride_runner::Runner,
    paths: UpdatePaths,
}

impl<'a> DnfBackend<'a> {
    /// Create a new DNF backend with the given runner.
    pub fn new(runner: &'a dyn toride_runner::Runner) -> Self {
        Self {
            runner,
            paths: UpdatePaths::new(),
        }
    }

    /// Create a DNF backend with explicit paths.
    pub fn with_paths(runner: &'a dyn toride_runner::Runner, paths: UpdatePaths) -> Self {
        Self { runner, paths }
    }

    /// Check for available security updates using `dnf check-update`.
    ///
    /// Returns `(security_updates, total_updates)`. Note that `dnf
    /// check-update` exits with code `0` when there is nothing to do and code
    /// `100` when updates are available; both are treated as success here and
    /// the counts come from parsing stdout.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the command fails to run.
    pub fn check_updates(&self) -> Result<(usize, usize)> {
        info!("Checking DNF updates");
        let spec = check_updates_spec();
        // dnf check-update exits 100 when updates are available; treat that as
        // success (the data is on stdout) and only fail on runner errors.
        let output = self
            .runner
            .run(&spec)
            .map_err(|e| Error::CommandFailed(format!("dnf check-update failed: {e}")))?;
        match output.exit_code {
            Some(0 | 100) => crate::parse::parse_dnf_check(&output.stdout),
            None => Err(Error::CommandFailed(
                "dnf check-update produced no exit code (terminated by signal?)".to_string(),
            )),
            Some(code) => Err(Error::CommandFailed(format!(
                "dnf check-update failed (exit {code})"
            ))),
        }
    }

    /// Apply pending updates via `dnf-automatic --install`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the command fails.
    pub fn apply_updates(&self) -> Result<()> {
        info!("Applying DNF updates via dnf-automatic");
        let spec = apply_updates_spec();
        self.runner
            .run_checked(&spec)
            .map_err(|e| Error::CommandFailed(format!("dnf-automatic failed: {e}")))?;
        Ok(())
    }

    /// Query the current update status.
    ///
    /// DNF has no persistent log comparable to APT's unattended-upgrades log,
    /// so status is derived from the systemd journal: the most recent
    /// `dnf-automatic` run. The journal query is routed through the runner so
    /// it is testable; if the journal is unavailable the status is empty.
    ///
    /// The journal output is parsed by [`crate::parse::parse_dnf_automatic_journal`],
    /// which understands the real dnf-automatic emitter messages
    /// (`The following updates have been applied on 'host':`, `Updates completed
    /// at <ts>`, `No security updates needed, but N updates available`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] only if the runner fails to spawn
    /// `journalctl`.
    pub fn status(&self) -> Result<UpdateStatus> {
        info!("Querying DNF update status");
        let spec = journal_spec();
        match self.runner.run(&spec) {
            Ok(output) if output.success => {
                crate::parse::parse_dnf_automatic_journal(&output.stdout)
            }
            // journalctl failing usually means no journal / no records: not an
            // error for the caller, just an empty status.
            Ok(_) | Err(_) => Ok(UpdateStatus::empty()),
        }
    }

    /// Check if `dnf-automatic` binary is available.
    pub fn is_available(&self) -> bool {
        which::which("dnf-automatic").is_ok()
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

    /// Expose the exact [`toride_runner::CommandSpec`] used by
    /// [`Self::status`] (for assertions/tests).
    fn journal_spec_ref() -> toride_runner::CommandSpec {
        journal_spec()
    }
}

/// Build the `dnf check-update` [`toride_runner::CommandSpec`].
fn check_updates_spec() -> toride_runner::CommandSpec {
    toride_runner::CommandSpec::new("dnf").args(["check-update", "--security"])
}

/// Build the `dnf-automatic` [`toride_runner::CommandSpec`].
fn apply_updates_spec() -> toride_runner::CommandSpec {
    toride_runner::CommandSpec::new("dnf-automatic").arg("--install")
}

/// Build the `journalctl` [`toride_runner::CommandSpec`] for the most recent
/// dnf-automatic run.
fn journal_spec() -> toride_runner::CommandSpec {
    toride_runner::CommandSpec::new("journalctl").args([
        "-u",
        "dnf-automatic",
        "--no-pager",
        "-n",
        "50",
    ])
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
    fn check_updates_builds_dnf_check_update_security() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(
            "Last metadata expiration check: 0:01:00 ago.\n\
             kernel-core.x86_64 6.1.0-1 updates/security\n",
        ));
        let (security, total) = DnfBackend::new(&runner).check_updates().unwrap();
        assert_eq!(security, 1);
        assert_eq!(total, 1);
        runner.assert_called_with(&CommandSpec::new("dnf").args(["check-update", "--security"]));
    }

    #[test]
    fn check_updates_accepts_exit_100_as_success() {
        // dnf check-update exits 100 when updates are available.
        let runner = FakeRunner::new().push_response(CommandOutput::new(
            "pkg.x86_64 1.0 updates".to_owned(),
            String::new(),
            Some(100),
        ));
        let (_security, total) = DnfBackend::new(&runner).check_updates().unwrap();
        assert_eq!(total, 1);
    }

    #[test]
    fn apply_updates_builds_dnf_automatic_install() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout("done"));
        DnfBackend::new(&runner).apply_updates().unwrap();
        runner.assert_called_with(&CommandSpec::new("dnf-automatic").arg("--install"));
    }

    #[test]
    fn apply_updates_propagates_failure() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stderr("repo locked", 1));
        let err = DnfBackend::new(&runner).apply_updates().unwrap_err();
        assert!(err.to_string().contains("dnf-automatic failed"));
    }

    /// Real `journalctl -u dnf-automatic` sample parsed via the dnf-automatic
    /// emitter format.
    ///
    /// Source: dnf upstream `dnf/automatic/emitter.py`:
    ///   APPLIED = "The following updates have been applied on '%s':"
    ///   APPLIED_TIMESTAMP = "Updates completed at %s"
    /// https://github.com/rpm-software-management/dnf/blob/master/dnf/automatic/emitter.py
    #[test]
    fn status_parses_journal_output() {
        let journal = "\
The following updates have been applied on 'host.example.com':\n\
    kernel-core-6.8.9-300.fc40.x86_64                    updates\n\
    openssl-libs-3.2.1-1.fc40.x86_64                     updates\n\
Updates completed at Mon Jun  2 06:42:11 2025\n";
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(journal));
        let status = DnfBackend::new(&runner).status().unwrap();
        assert!(status.auto_updates_enabled);
        assert_eq!(status.last_run.as_deref(), Some("Mon Jun  2 06:42:11 2025"));
        assert_eq!(status.pending_security, 2);
        runner.assert_called_with(&CommandSpec::new("journalctl").args([
            "-u",
            "dnf-automatic",
            "--no-pager",
            "-n",
            "50",
        ]));
    }

    #[test]
    fn status_empty_when_journal_unavailable() {
        // journalctl failure (exit 1) is not propagated — empty status.
        let runner = FakeRunner::new().push_response(CommandOutput::from_stderr("No journal", 1));
        let status = DnfBackend::new(&runner).status().unwrap();
        assert_eq!(status.pending_security, 0);
    }

    #[test]
    fn command_specs_are_stable() {
        let check = DnfBackend::check_updates_spec_ref();
        assert_eq!(check.program, "dnf");
        assert_eq!(
            check.args,
            vec!["check-update".to_owned(), "--security".to_owned()]
        );

        let apply = DnfBackend::apply_updates_spec_ref();
        assert_eq!(apply.program, "dnf-automatic");
        assert_eq!(apply.args, vec!["--install".to_owned()]);

        let journal = DnfBackend::journal_spec_ref();
        assert_eq!(journal.program, "journalctl");
        assert_eq!(
            journal.args,
            vec![
                "-u".to_owned(),
                "dnf-automatic".to_owned(),
                "--no-pager".to_owned(),
                "-n".to_owned(),
                "50".to_owned()
            ]
        );
    }
}
