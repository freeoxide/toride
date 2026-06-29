//! CLI argument definitions for the toride-monitor binary.
//!
//! Uses [`clap`] derive macros to define the command-line interface. The
//! [`Cli`] enum is the top-level parser; [`Cli::run`] dispatches every variant
//! to the corresponding [`crate::client::MonitorClient`] method.

use clap::Parser;

use crate::client::MonitorClient;
use crate::doctor::DoctorScope;
use crate::spec::MonitorSpec;

/// Outbound traffic monitoring and anomaly detection.
#[derive(Debug, Parser)]
#[command(name = "toride-monitor", version, about)]
pub enum Cli {
    /// Set up iptables OUTPUT chain logging rules.
    Setup {
        /// Config file path (default: XDG config location).
        #[arg(short, long)]
        config: Option<String>,

        /// Dry run: print commands without executing.
        #[arg(long)]
        dry_run: bool,
    },

    /// Remove all iptables OUTPUT chain logging rules.
    Teardown {
        /// Dry run: print commands without executing.
        #[arg(long)]
        dry_run: bool,
    },

    /// Take a snapshot of current outbound connections.
    Snapshot {
        /// Output format.
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Run anomaly detection on the current traffic.
    Detect {
        /// Config file path with thresholds.
        #[arg(short, long)]
        config: Option<String>,

        /// Output format.
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Run diagnostic checks.
    Doctor {
        /// Scope of checks to run.
        #[arg(short, long, default_value = "all")]
        scope: String,
    },

    /// Run a single monitoring cycle (for daemon mode).
    Run {
        /// Config file path.
        #[arg(short, long)]
        config: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

impl Cli {
    /// Execute the parsed subcommand against a production [`MonitorClient`].
    ///
    /// Constructs the client with [`MonitorClient::system`] (real `DuctRunner`,
    /// paths resolved from `$PATH`). For a testable, runner-injectable entry
    /// point see [`Self::run_with_client`].
    ///
    /// # Errors
    ///
    /// Propagates any error from client construction or the underlying client
    /// call.
    pub fn run(&self) -> crate::Result<()> {
        let client = MonitorClient::system()?;
        self.run_with_client(&client)
    }

    /// Execute the parsed subcommand against an injected [`MonitorClient`].
    ///
    /// Every [`Cli`] variant is mapped to its corresponding real client method.
    /// Spec-bearing variants (`setup`, `detect`, `run`) load a [`MonitorSpec`]
    /// from the `--config` path when given, otherwise fall back to the default
    /// spec.
    ///
    /// This is the seam used by the FakeRunner-backed tests: the test builds a
    /// `MonitorClient` wired to a shared fake runner and asserts the dispatched
    /// command.
    ///
    /// # Dry run
    ///
    /// The `setup` and `teardown` variants honour `--dry-run`: when set, the
    /// intended command set is described on stdout but no mutating client call
    /// is made.
    ///
    /// # Errors
    ///
    /// Propagates any error from config loading or the underlying client call.
    pub fn run_with_client(&self, client: &MonitorClient) -> crate::Result<()> {
        match self {
            Self::Setup { config, dry_run } => {
                let spec = load_spec(config.as_deref())?;
                if *dry_run {
                    for rule in &spec.logging_rules {
                        println!(
                            "[dry-run] would install OUTPUT LOG rule {:?}: {} {}",
                            rule.name, rule.protocol, rule.destination
                        );
                    }
                    return Ok(());
                }
                client.setup_logging(&spec.logging_rules)?;
                println!(
                    "installed {} OUTPUT logging rule(s)",
                    spec.logging_rules.len()
                );
                Ok(())
            }
            Self::Teardown { dry_run } => {
                if *dry_run {
                    println!("[dry-run] would remove all OUTPUT logging rules");
                    return Ok(());
                }
                client.teardown_logging()?;
                println!("removed all OUTPUT logging rules");
                Ok(())
            }
            Self::Snapshot { format } => {
                let report = client.snapshot()?;
                print_report(&report, format)?;
                Ok(())
            }
            Self::Detect { config, format } => {
                let spec = load_spec(config.as_deref())?;
                let snapshot = client.snapshot()?;
                let anomalies = client.detect_with_thresholds(&snapshot, spec.thresholds)?;
                print_anomalies(&anomalies, format)?;
                Ok(())
            }
            Self::Doctor { scope } => {
                let scope = parse_doctor_scope(scope)?;
                let paths = client.paths();
                let doctor = crate::doctor::Doctor::new(paths, client.runner());
                let report = doctor.run(&scope)?;
                if report.is_clean() {
                    println!("doctor: no findings ({:?} scope clean)", scope);
                } else {
                    println!("doctor: {} finding(s)", report.len());
                    for finding in &report.findings {
                        println!(
                            "  [{:>8}] {}: {}",
                            finding.severity, finding.id, finding.title
                        );
                    }
                }
                Ok(())
            }
            Self::Run { config } => {
                let spec = load_spec(config.as_deref())?;
                let anomalies = client.apply(&spec)?;
                if anomalies.is_clean() {
                    println!("run: cycle complete, no anomalies");
                } else {
                    println!(
                        "run: cycle complete, {} anomaly finding(s)",
                        anomalies.findings.len()
                    );
                }
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Dispatch helpers
// ---------------------------------------------------------------------------

/// Load a [`MonitorSpec`] from `path`, or return the default spec when `path`
/// is `None`.
///
/// # Errors
///
/// Propagates a typed error if the config file cannot be read or parsed.
fn load_spec(path: Option<&str>) -> crate::Result<MonitorSpec> {
    match path {
        None => Ok(MonitorSpec::default()),
        Some(p) => {
            #[cfg(feature = "config")]
            {
                Ok(crate::config::MonitorConfig::new(p).load()?)
            }
            #[cfg(not(feature = "config"))]
            {
                let _ = p;
                Err(crate::Error::Other(format!(
                    "config file loading requires the `config` feature (got --config {p:?})"
                )))
            }
        }
    }
}

/// Map the `--scope <string>` CLI argument onto a [`DoctorScope`].
///
/// `"all"` or empty => [`DoctorScope::All`]. Recognised category labels
/// (`binaries`, `logging`, `service`, `config`) map to the corresponding scope.
/// Anything else is a typed error rather than a silent default.
fn parse_doctor_scope(scope: &str) -> crate::Result<DoctorScope> {
    match scope {
        "" | "all" => Ok(DoctorScope::All),
        "binaries" => Ok(DoctorScope::Binaries),
        "logging" => Ok(DoctorScope::Logging),
        "service" => Ok(DoctorScope::Service),
        "config" => Ok(DoctorScope::Config),
        other => Err(crate::Error::Other(format!(
            "unknown doctor scope {other:?} (expected one of: all, binaries, logging, \
             service, config)"
        ))),
    }
}

/// Render a [`crate::report::MonitorReport`] in the requested format.
///
/// Only `text` (human-readable) and `json` are supported. `json` requires the
/// `serde` feature.
fn print_report(report: &crate::report::MonitorReport, format: &str) -> crate::Result<()> {
    match format {
        "text" | "" => {
            println!(
                "snapshot: {} connection(s), {} unique destination(s)",
                report.total_connections, report.unique_destinations
            );
            if let Some(bytes) = report.total_bytes {
                println!("  total bytes: {bytes}");
            }
            if let Some(packets) = report.total_packets {
                println!("  total packets: {packets}");
            }
            Ok(())
        }
        "json" => {
            #[cfg(feature = "serde")]
            {
                let json = serde_json::to_string_pretty(report)
                    .map_err(|e| crate::Error::Other(format!("failed to serialize report: {e}")))?;
                println!("{json}");
                Ok(())
            }
            #[cfg(not(feature = "serde"))]
            {
                let _ = report;
                Err(crate::Error::Other(
                    "json output requires the `serde` feature".into(),
                ))
            }
        }
        other => Err(crate::Error::Other(format!(
            "unknown output format {other:?} (expected: text, json)"
        ))),
    }
}

/// Render an [`crate::report::AnomalyReport`] in the requested format.
fn print_anomalies(report: &crate::report::AnomalyReport, format: &str) -> crate::Result<()> {
    match format {
        "text" | "" => {
            if report.is_clean() {
                println!("detect: no anomalies");
            } else {
                println!("detect: {} finding(s)", report.findings.len());
                for finding in &report.findings {
                    println!(
                        "  [{:>8}] {}: {}",
                        finding.severity, finding.id, finding.title
                    );
                }
            }
            Ok(())
        }
        "json" => {
            #[cfg(feature = "serde")]
            {
                let json = serde_json::to_string_pretty(report)
                    .map_err(|e| crate::Error::Other(format!("failed to serialize report: {e}")))?;
                println!("{json}");
                Ok(())
            }
            #[cfg(not(feature = "serde"))]
            {
                let _ = report;
                Err(crate::Error::Other(
                    "json output requires the `serde` feature".into(),
                ))
            }
        }
        other => Err(crate::Error::Other(format!(
            "unknown output format {other:?} (expected: text, json)"
        ))),
    }
}

/// Parse CLI arguments from the process environment.
///
/// Convenience wrapper around [`Cli::parse`].
pub fn parse_args() -> Cli {
    Cli::parse()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::MonitorPaths;
    use std::path::PathBuf;
    use toride_runner::fake::FakeRunner;
    use toride_runner::{CommandOutput, CommandSpec};

    /// Standard fake `MonitorPaths` for tests (mirrors the fixtures used in
    /// client.rs / output.rs / doctor.rs).
    fn test_paths() -> MonitorPaths {
        MonitorPaths {
            iptables: PathBuf::from("/usr/sbin/iptables"),
            iptables_save: PathBuf::from("/usr/sbin/iptables-save"),
            conntrack: PathBuf::from("/usr/sbin/conntrack"),
            ss: PathBuf::from("/usr/bin/ss"),
            journalctl: PathBuf::from("/usr/bin/journalctl"),
            systemd_cat: PathBuf::from("/usr/bin/systemd-cat"),
        }
    }

    // -----------------------------------------------------------------------
    // Dispatch: `teardown` parses AND reaches the real iptables teardown
    // -----------------------------------------------------------------------

    /// `Cli::parse_from(["toride-monitor", "teardown"])` must parse into the
    /// `Teardown` variant, and `run_with_client` must dispatch to the real
    /// `MonitorClient::teardown_logging`, which issues an `iptables-save` call
    /// (to list OUTPUT rules) followed by zero-or-more `iptables -D` calls. With
    /// no saved LOG rules, only the `iptables-save` call is made. We assert the
    /// FakeRunner observed exactly that command, proving the dispatch is real
    /// glue, not a stub.
    #[test]
    fn dispatch_teardown_parses_and_invokes_real_backend() {
        let runner = FakeRunner::new()
            // iptables-save returns an empty ruleset (no LOG rules to delete).
            .push_response(CommandOutput::from_stdout("*filter\nCOMMIT\n"));
        // FakeRunner::clone shares its internal Arc<Mutex<..>> state, so the
        // clone handed to the client records the same calls we inspect here.
        let runner_clone = runner.clone();
        let client = MonitorClient::with_runner(Box::new(runner_clone), test_paths());

        let cli = Cli::parse_from(["toride-monitor", "teardown"]);

        // Prove the parse landed on the right variant before dispatch.
        assert!(matches!(cli, Cli::Teardown { dry_run: false }));

        cli.run_with_client(&client)
            .expect("dispatch should reach the backend and succeed");

        // teardown lists rules via iptables-save; with no LOG rules that is the
        // only call issued.
        let expected = CommandSpec::new("/usr/sbin/iptables-save");
        runner.assert_called_with(&expected);
        assert_eq!(
            runner.calls().len(),
            1,
            "teardown with empty ruleset should issue only iptables-save"
        );
    }

    // -----------------------------------------------------------------------
    // Dispatch: `setup` parses AND installs a default logging rule
    // -----------------------------------------------------------------------

    /// `Cli::parse_from(["toride-monitor", "setup"])` must parse into `Setup`
    /// and `run_with_client` must dispatch to `MonitorClient::setup_logging`.
    /// The default spec carries one journald alert target but no logging rules,
    /// so setup must succeed without invoking iptables at all. This proves the
    /// setup path is wired (and that an empty rule set is handled cleanly).
    #[test]
    fn dispatch_setup_parses_and_invokes_real_backend() {
        let runner = FakeRunner::new().strict();
        let runner_clone = runner.clone();
        let client = MonitorClient::with_runner(Box::new(runner_clone), test_paths());

        let cli = Cli::parse_from(["toride-monitor", "setup"]);

        assert!(matches!(
            cli,
            Cli::Setup {
                config: None,
                dry_run: false
            }
        ));

        // Default spec has no logging rules => setup_logging is a no-op that
        // issues no commands. Strict runner confirms nothing was called.
        cli.run_with_client(&client)
            .expect("setup with empty ruleset should succeed without commands");
        assert!(
            runner.calls().is_empty(),
            "setup with no logging rules should issue zero commands"
        );
    }

    // -----------------------------------------------------------------------
    // Dispatch: `doctor` parses scope AND runs the doctor engine
    // -----------------------------------------------------------------------

    /// `Cli::parse_from(["toride-monitor", "doctor"])` must parse into `Doctor`
    /// with scope `"all"` and dispatch through the `Doctor` engine. With an
    /// empty iptables-save response (no LOG rules) the doctor reports a
    /// finding rather than erroring, proving the engine is actually invoked.
    #[test]
    fn dispatch_doctor_parses_and_invokes_real_engine() {
        let runner = FakeRunner::new()
            // iptables-save: empty OUTPUT chain (no LOG rules => a finding).
            .push_response(CommandOutput::from_stdout("*filter\nCOMMIT\n"));
        let runner_clone = runner.clone();
        let client = MonitorClient::with_runner(Box::new(runner_clone), test_paths());

        let cli = Cli::parse_from(["toride-monitor", "doctor"]);

        assert!(matches!(cli, Cli::Doctor { .. } if cli_scope(&cli) == "all"));

        cli.run_with_client(&client)
            .expect("doctor dispatch should succeed");

        // The doctor (scope=all) probes logging via iptables-save and service
        // via systemctl; FakeRunner served both from its FIFO queue.
        let calls = runner.calls();
        assert!(
            calls.iter().any(|c| c.program == "/usr/sbin/iptables-save"),
            "doctor should probe iptables-save, got: {:?}",
            calls.iter().map(|c| &c.program).collect::<Vec<_>>()
        );
    }

    /// Read the `--scope` value out of a parsed `Doctor` variant for assertions.
    fn cli_scope(cli: &Cli) -> &str {
        match cli {
            Cli::Doctor { scope } => scope,
            _ => "not-doctor",
        }
    }

    // -----------------------------------------------------------------------
    // Dispatch: `--dry-run` short-circuits mutating commands
    // -----------------------------------------------------------------------

    /// `setup --dry-run` must NOT call the client's mutating method: the strict
    /// runner confirms zero commands issued.
    #[test]
    fn dispatch_setup_dry_run_does_not_execute() {
        let runner = FakeRunner::new().strict();
        let runner_clone = runner.clone();
        let client = MonitorClient::with_runner(Box::new(runner_clone), test_paths());

        let cli = Cli::parse_from(["toride-monitor", "setup", "--dry-run"]);
        assert!(matches!(cli, Cli::Setup { dry_run: true, .. }));

        cli.run_with_client(&client)
            .expect("dry-run setup should succeed without execution");
        assert!(runner.calls().is_empty());
    }

    /// `teardown --dry-run` must NOT call the client's mutating method.
    #[test]
    fn dispatch_teardown_dry_run_does_not_execute() {
        let runner = FakeRunner::new().strict();
        let runner_clone = runner.clone();
        let client = MonitorClient::with_runner(Box::new(runner_clone), test_paths());

        let cli = Cli::parse_from(["toride-monitor", "teardown", "--dry-run"]);
        assert!(matches!(cli, Cli::Teardown { dry_run: true }));

        cli.run_with_client(&client)
            .expect("dry-run teardown should succeed without execution");
        assert!(runner.calls().is_empty());
    }

    // -----------------------------------------------------------------------
    // Scope parsing
    // -----------------------------------------------------------------------

    /// `parse_doctor_scope` maps recognised labels to the right variant and
    /// rejects unknown labels with a typed error.
    #[test]
    fn parse_doctor_scope_maps_known_labels_and_rejects_unknown() {
        assert!(matches!(parse_doctor_scope("all"), Ok(DoctorScope::All)));
        assert!(matches!(parse_doctor_scope(""), Ok(DoctorScope::All)));
        assert!(matches!(
            parse_doctor_scope("binaries"),
            Ok(DoctorScope::Binaries)
        ));
        assert!(matches!(
            parse_doctor_scope("logging"),
            Ok(DoctorScope::Logging)
        ));
        assert!(matches!(
            parse_doctor_scope("service"),
            Ok(DoctorScope::Service)
        ));
        assert!(matches!(
            parse_doctor_scope("config"),
            Ok(DoctorScope::Config)
        ));
        assert!(
            matches!(parse_doctor_scope("bogus"), Err(crate::Error::Other(_))),
            "unknown scope label must error"
        );
    }

    // -----------------------------------------------------------------------
    // Output-format parsing
    // -----------------------------------------------------------------------

    /// An unknown `--format` must surface a typed error rather than silently
    /// defaulting. Uses a real (empty) report so print_report reaches the
    /// format dispatch.
    #[test]
    fn print_report_rejects_unknown_format() {
        let report = crate::report::MonitorReport::empty();
        let err = print_report(&report, "yaml").expect_err("unknown format must error");
        assert!(matches!(err, crate::Error::Other(_)));
    }
}
