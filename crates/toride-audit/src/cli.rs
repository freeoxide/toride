//! CLI argument definitions for the audit subsystem.
//!
//! Provides [`clap`] derive-based argument types for building CLI tools
//! that manage audit rules, file integrity, and log aggregation.

// ---------------------------------------------------------------------------
// AuditCli
// ---------------------------------------------------------------------------

/// Top-level CLI arguments for the audit tool.
#[derive(Debug, clap::Parser)]
#[command(name = "toride-audit", about = "Linux audit management", version)]
pub struct AuditCli {
    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: AuditCommand,

    /// Enable verbose output.
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Enable dry-run mode (log commands without executing).
    #[arg(long, global = true)]
    pub dry_run: bool,
}

// ---------------------------------------------------------------------------
// AuditCommand
// ---------------------------------------------------------------------------

/// Available audit subcommands.
#[derive(Debug, clap::Subcommand)]
pub enum AuditCommand {
    /// Run diagnostic checks on the audit subsystem.
    Doctor {
        /// Scope of checks to run.
        #[arg(default_value = "all")]
        scope: String,
    },

    /// Manage audit rules.
    Rules {
        /// Subcommand for rule operations.
        #[command(subcommand)]
        action: RuleAction,
    },

    /// Manage file integrity monitoring (AIDE).
    Integrity {
        /// Subcommand for integrity operations.
        #[command(subcommand)]
        action: IntegrityAction,
    },

    /// Manage system logs.
    Logs {
        /// Subcommand for log operations.
        #[command(subcommand)]
        action: LogAction,
    },

    /// Manage the audit daemon.
    Daemon {
        /// Subcommand for daemon operations.
        #[command(subcommand)]
        action: DaemonAction,
    },
}

// ---------------------------------------------------------------------------
// RuleAction
// ---------------------------------------------------------------------------

/// Audit rule subcommands.
#[derive(Debug, clap::Subcommand)]
pub enum RuleAction {
    /// List current audit rules.
    List,

    /// Apply a preset set of audit rules.
    Apply {
        /// Preset name (cis-level2, stig, minimal).
        preset: String,
    },

    /// Show diff between current and proposed rules.
    Diff {
        /// Preset name to compare against.
        preset: String,
    },
}

// ---------------------------------------------------------------------------
// IntegrityAction
// ---------------------------------------------------------------------------

/// Integrity monitoring subcommands.
#[derive(Debug, clap::Subcommand)]
pub enum IntegrityAction {
    /// Initialize the AIDE database.
    Init,

    /// Run an integrity check.
    Check,

    /// Update the AIDE database after changes.
    Update,

    /// Show integrity status.
    Status,
}

// ---------------------------------------------------------------------------
// LogAction
// ---------------------------------------------------------------------------

/// Log management subcommands.
#[derive(Debug, clap::Subcommand)]
pub enum LogAction {
    /// List managed log files.
    List,

    /// Show log storage usage.
    Usage,

    /// Vacuum old journal entries.
    Vacuum {
        /// Time specification (e.g. "7d", "2weeks").
        time: String,
    },
}

// ---------------------------------------------------------------------------
// DaemonAction
// ---------------------------------------------------------------------------

/// Audit daemon subcommands.
#[derive(Debug, clap::Subcommand)]
pub enum DaemonAction {
    /// Start the audit daemon.
    Start,

    /// Stop the audit daemon.
    Stop,

    /// Restart the audit daemon.
    Restart,

    /// Show audit daemon status.
    Status,

    /// Reload audit rules without restarting.
    Reload,
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

use crate::Result;

impl AuditCli {
    /// Run the parsed command against the production client.
    ///
    /// Constructs an [`crate::Audit`] with `DuctRunner` defaults and dispatches
    /// the parsed subcommand to the corresponding client call.
    ///
    /// # Errors
    ///
    /// Propagates any [`crate::Error`] returned by the underlying client.
    pub fn run(&self) -> Result<()> {
        let audit = crate::Audit::system()?;
        self.run_with_audit(&audit)
    }

    /// Run the parsed command against an injected [`crate::Audit`] facade.
    ///
    /// Exposed for testability: tests can construct an `Audit` backed by a
    /// `FakeRunner` and verify that each subcommand dispatches to the correct
    /// client call without touching the system.
    pub fn run_with_audit(&self, audit: &crate::Audit) -> Result<()> {
        match &self.command {
            AuditCommand::Doctor { scope } => {
                let doctor_scope = parse_doctor_scope(scope);
                let report = audit.doctor(doctor_scope)?;
                println!("{report}");
                Ok(())
            }

            AuditCommand::Rules { action } => match action {
                RuleAction::List => {
                    let client = crate::client::AuditClient::new(audit.runner(), audit.paths());
                    let rules = client.list_rules()?;
                    print!("{rules}");
                    Ok(())
                }
                RuleAction::Apply { preset } => {
                    let preset = crate::auditd_presets::find_preset(preset)
                        .ok_or_else(|| crate::Error::Other(format!("unknown preset: {preset}")))?;
                    let content = preset.rules.join("\n") + "\n";
                    crate::auditd_rules::write_rule_file(audit.paths(), preset.id, &content)?;
                    println!(
                        "applied preset '{}' ({} rules)",
                        preset.id,
                        preset.rules.len()
                    );
                    Ok(())
                }
                RuleAction::Diff { preset } => {
                    let preset = crate::auditd_presets::find_preset(preset)
                        .ok_or_else(|| crate::Error::Other(format!("unknown preset: {preset}")))?;
                    let current = match crate::auditd_rules::list_rule_files(audit.paths()) {
                        Ok(files) => crate::auditd_rules::merge_rules(&files).join("\n"),
                        Err(_) => String::new(),
                    };
                    let proposed = preset.rules.join("\n");
                    let entries = crate::diff::diff_audit_rules(&current, &proposed);
                    if entries.is_empty() {
                        println!("no differences");
                    } else {
                        for entry in &entries {
                            println!("{entry}");
                        }
                    }
                    Ok(())
                }
            },

            AuditCommand::Integrity { action } => {
                let integrity = audit.integrity();
                match action {
                    IntegrityAction::Init => {
                        integrity.initialize()?;
                        println!("AIDE database initialized");
                        Ok(())
                    }
                    IntegrityAction::Check => {
                        let output = integrity.check()?;
                        print!("{output}");
                        Ok(())
                    }
                    IntegrityAction::Update => {
                        integrity.update()?;
                        println!("AIDE database updated");
                        Ok(())
                    }
                    IntegrityAction::Status => {
                        let status = integrity.status()?;
                        println!("{status:?}");
                        Ok(())
                    }
                }
            }

            AuditCommand::Logs { action } => {
                let logs = audit.logs();
                match action {
                    LogAction::List => {
                        let files = logs.list_log_files()?;
                        if files.is_empty() {
                            println!("(no managed log files)");
                        } else {
                            for f in &files {
                                println!("{f}");
                            }
                        }
                        Ok(())
                    }
                    LogAction::Usage => {
                        let files = logs.list_log_files()?;
                        let mut total: u64 = 0;
                        for f in &files {
                            if let Ok(meta) = std::fs::metadata(f) {
                                total += meta.len();
                            }
                        }
                        println!("{total} bytes across {} files", files.len());
                        Ok(())
                    }
                    LogAction::Vacuum { time } => {
                        let spec = toride_runner::CommandSpec::new("journalctl")
                            .arg("--vacuum-time")
                            .arg(time);
                        audit.runner().run_checked(&spec)?;
                        println!("vacuumed journal entries older than {time}");
                        Ok(())
                    }
                }
            }

            AuditCommand::Daemon { action } => {
                let svc = crate::service::AuditServiceManager::new(audit.runner(), audit.paths());
                match action {
                    DaemonAction::Start => {
                        svc.enable_and_start_auditd()?;
                        println!("auditd started");
                        Ok(())
                    }
                    DaemonAction::Stop => {
                        let spec =
                            toride_runner::CommandSpec::new("systemctl").args(["stop", "auditd"]);
                        audit.runner().run_checked(&spec)?;
                        println!("auditd stopped");
                        Ok(())
                    }
                    DaemonAction::Restart => {
                        svc.restart_auditd()?;
                        println!("auditd restarted");
                        Ok(())
                    }
                    DaemonAction::Status => {
                        let running = svc.is_auditd_active()?;
                        println!("auditd: {}", if running { "active" } else { "inactive" });
                        Ok(())
                    }
                    DaemonAction::Reload => {
                        svc.reload_auditd_rules()?;
                        println!("auditd rules reloaded");
                        Ok(())
                    }
                }
            }
        }
    }
}

/// Parse the free-form doctor scope string into a [`DoctorScope`].
///
/// Unknown values fall back to [`DoctorScope::All`].
fn parse_doctor_scope(scope: &str) -> crate::doctor::DoctorScope {
    match scope.trim().to_ascii_lowercase().as_str() {
        "auditd" => crate::doctor::DoctorScope::Auditd,
        "integrity" => crate::doctor::DoctorScope::Integrity,
        "logs" => crate::doctor::DoctorScope::Logs,
        "config" => crate::doctor::DoctorScope::Config,
        _ => crate::doctor::DoctorScope::All,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use toride_runner::fake::FakeRunner;

    /// `daemon status` parses and dispatches to `systemctl is-active auditd`
    /// through the injected FakeRunner. This variant has no `which` gate, so
    /// the FakeRunner is the sole determinant of the result.
    #[test]
    fn daemon_status_dispatches_to_systemctl_is_active() {
        let expected = toride_runner::CommandSpec::new("systemctl").args(["is-active", "auditd"]);
        // Clone the runner so we can inspect recorded calls after dispatch.
        let runner = FakeRunner::new().strict().respond(
            expected.clone(),
            toride_runner::CommandOutput::from_stdout("active\n"),
        );
        let inspect = runner.clone();
        let audit = crate::Audit::with_runner(Box::new(runner));
        let cli: AuditCli = clap::Parser::try_parse_from(["toride-audit", "daemon", "status"])
            .expect("parse daemon status");
        cli.run_with_audit(&audit).expect("dispatch succeeds");

        // The FakeRunner must have observed exactly the systemctl call.
        inspect.assert_called_with(&expected);
    }

    /// `daemon stop` dispatches to `systemctl stop auditd` via `run_checked`.
    /// Verifies the dispatch reaches the runner with the right argv.
    #[test]
    fn daemon_stop_dispatches_to_systemctl_stop() {
        let expected = toride_runner::CommandSpec::new("systemctl").args(["stop", "auditd"]);
        let runner = FakeRunner::new().strict().respond(
            expected.clone(),
            toride_runner::CommandOutput::from_stdout(""),
        );
        let inspect = runner.clone();
        let audit = crate::Audit::with_runner(Box::new(runner));
        let cli: AuditCli = clap::Parser::try_parse_from(["toride-audit", "daemon", "stop"])
            .expect("parse daemon stop");
        cli.run_with_audit(&audit).expect("dispatch succeeds");

        inspect.assert_called_with(&expected);
    }

    /// `rules apply <preset>` resolves a known preset and writes its rules
    /// to a managed file under the configured rules directory.
    #[test]
    fn rules_apply_writes_known_preset() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = crate::AuditPaths::with_audit_dir(tmp.path().join("audit").into());
        std::fs::create_dir_all(&paths.rules_d).expect("mkdir rules.d");
        let audit = crate::Audit::with_runner(Box::new(FakeRunner::new()))
            .with_paths_override(paths.clone());

        let cli: AuditCli =
            clap::Parser::try_parse_from(["toride-audit", "rules", "apply", "minimal"])
                .expect("parse rules apply");
        cli.run_with_audit(&audit).expect("dispatch succeeds");

        let written =
            std::fs::read_to_string(paths.rules_path("minimal")).expect("read written file");
        assert!(written.contains("-k identity"), "written = {written}");
    }

    /// Unknown preset names surface as an error rather than silently passing.
    #[test]
    fn rules_apply_unknown_preset_errors() {
        let audit = crate::Audit::with_runner(Box::new(FakeRunner::new()));
        let cli: AuditCli =
            clap::Parser::try_parse_from(["toride-audit", "rules", "apply", "nope"])
                .expect("parse rules apply");
        let res = cli.run_with_audit(&audit);
        assert!(res.is_err(), "unknown preset should error");
    }

    /// `doctor` parses and dispatches into the diagnostic engine, returning
    /// a report even when no audit tooling is installed.
    #[test]
    fn doctor_dispatches_and_returns_report() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = crate::AuditPaths::with_audit_dir(tmp.path().join("audit").into());
        let audit =
            crate::Audit::with_runner(Box::new(FakeRunner::new())).with_paths_override(paths);
        let cli: AuditCli =
            clap::Parser::try_parse_from(["toride-audit", "doctor"]).expect("parse doctor");
        cli.run_with_audit(&audit).expect("doctor dispatches");
    }

    #[test]
    fn parse_doctor_scope_maps_known_strings() {
        assert_eq!(parse_doctor_scope("all"), crate::doctor::DoctorScope::All);
        assert_eq!(
            parse_doctor_scope("Auditd"),
            crate::doctor::DoctorScope::Auditd
        );
        assert_eq!(
            parse_doctor_scope("garbage"),
            crate::doctor::DoctorScope::All
        );
    }
}
