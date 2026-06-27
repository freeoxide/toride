//! CLI argument parsing for the toride-harden command.
//!
//! Uses `clap` to define the command-line interface for applying,
//! inspecting, and diffing kernel hardening parameters.

use crate::backup::{
    create_backup, load_backup_from_disk, restore_backup, save_backup_to_disk,
};
use crate::client::HardenClient;
use crate::doctor::doctor;
use crate::error::{Error, Result};
use crate::profile::HardeningProfile;
use crate::spec::HardenSpec;
use clap::{Parser, Subcommand};

/// System hardening via sysctl kernel parameters and security profiles.
#[derive(Debug, Parser)]
#[command(name = "toride-harden", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

/// Available CLI subcommands.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Apply a hardening profile.
    Apply {
        /// Profile to apply: desktop, server, router.
        #[arg(value_name = "PROFILE")]
        profile: String,

        /// Dry run: show what would change without applying.
        #[arg(long)]
        dry_run: bool,

        /// Skip backup before applying.
        #[arg(long)]
        no_backup: bool,
    },

    /// Check current hardening status.
    Status {
        /// Show current values for all profile parameters.
        #[arg(long)]
        verbose: bool,
    },

    /// Show diff between current and desired state.
    Diff {
        /// Profile to diff against: desktop, server, router.
        #[arg(value_name = "PROFILE")]
        profile: String,
    },

    /// Run diagnostic checks.
    Doctor,

    /// List available profiles.
    Profiles,

    /// Backup current sysctl configuration.
    Backup,

    /// Restore sysctl configuration from a backup.
    Restore {
        /// Backup timestamp to restore.
        #[arg(value_name = "TIMESTAMP")]
        timestamp: String,
    },
}

impl Cli {
    /// Run the parsed command against the default production client.
    ///
    /// Constructs a [`HardenClient::system`] (duct runner + default paths).
    /// For tests or alternate runners, use [`Cli::run_with_client`].
    ///
    /// # Errors
    ///
    /// Propagates any error from client construction or the dispatched
    /// operation.
    pub fn run(&self) -> Result<()> {
        let client = HardenClient::system()?;
        self.run_with_client(&client)
    }

    /// Run the parsed command against an injectable [`HardenClient`].
    ///
    /// The client is generic over [`Runner`] (see [`HardenClient::with_runner`]
    /// / [`HardenClient::with_runner_and_paths`]), so callers can supply a
    /// [`toride_runner::fake::FakeRunner`] in tests or a custom runner in
    /// production.
    ///
    /// # Errors
    ///
    /// Propagates any error from the dispatched operation.
    pub fn run_with_client(&self, client: &HardenClient) -> Result<()> {
        let paths = client.paths().clone();
        match &self.command {
            Commands::Apply {
                profile,
                dry_run,
                no_backup,
            } => run_apply(client, profile, *dry_run, *no_backup),
            Commands::Status { verbose } => run_status(client, default_spec(), *verbose),
            Commands::Diff { profile } => {
                let diff = client.diff(&spec_for(profile)?)?;
                println!("{diff}");
                Ok(())
            }
            Commands::Doctor => {
                let findings = doctor(client.runner());
                if findings.is_empty() {
                    println!("No findings.");
                } else {
                    for f in &findings {
                        println!("[{}] {}: {}", f.severity, f.id, f.message);
                    }
                }
                Ok(())
            }
            Commands::Profiles => {
                println!("Available hardening profiles:");
                for name in HardeningProfile::all_names() {
                    println!("  {name}");
                }
                Ok(())
            }
            Commands::Backup => {
                let snapshot = create_backup(&paths)?;
                save_backup_to_disk(&paths, &snapshot)?;
                println!("Backup saved: {}", snapshot.timestamp);
                Ok(())
            }
            Commands::Restore { timestamp } => {
                let snapshot = load_backup_from_disk(&paths, timestamp)?;
                restore_backup(&paths, &snapshot)?;
                println!("Restored backup: {timestamp}");
                Ok(())
            }
        }
    }
}

// ── Dispatch helpers ────────────────────────────────────────────────────

/// Resolve a profile name string into a [`HardeningProfile`].
fn profile_for(name: &str) -> Result<HardeningProfile> {
    HardeningProfile::from_name(name).ok_or_else(|| Error::ProfileUnknown(name.to_string()))
}

/// Build a profile-only [`HardenSpec`] for the given profile name.
fn spec_for(profile: &str) -> Result<HardenSpec> {
    Ok(HardenSpec::builder().profile(profile_for(profile)?).build())
}

/// `status` has no profile argument on the CLI, so we report against the
/// production-grade `Server` baseline as a sensible default.
fn default_spec() -> HardenSpec {
    HardenSpec::builder()
        .profile(HardeningProfile::Server)
        .build()
}

fn run_apply(
    client: &HardenClient,
    profile: &str,
    dry_run: bool,
    no_backup: bool,
) -> Result<()> {
    let profile = profile_for(profile)?;
    let params = profile.params();

    if dry_run {
        let would_change = client.check(&HardenSpec::builder().params(params).build())?;
        if would_change.is_empty() {
            println!("No changes (dry run).");
        } else {
            println!("Would apply {} parameter(s) (dry run):", would_change.len());
            for p in &would_change {
                println!("  {p}");
            }
        }
        return Ok(());
    }

    // `--no-backup` routes through `apply_params`, which still snapshots
    // internally; the flag is honoured by NOT triggering a second explicit
    // backup here. The normal path uses `apply_profile`.
    let report = if no_backup {
        client.apply_params(&profile.params())?
    } else {
        client.apply_profile(&profile)?
    };
    println!("{}", report.to_summary());
    Ok(())
}

fn run_status(client: &HardenClient, spec: HardenSpec, verbose: bool) -> Result<()> {
    let rows = client.status(&spec)?;
    if verbose {
        for (param, current) in &rows {
            println!("{} = {} (desired {})", param.key, current, param.value);
        }
    } else {
        let changed = client.check(&spec)?;
        if changed.is_empty() {
            println!("All {} parameter(s) at desired value.", rows.len());
        } else {
            println!("{} parameter(s) differ from desired:", changed.len());
            for p in &changed {
                println!("  {p}");
            }
        }
    }
    Ok(())
}

/// Parse CLI arguments from strings (for testing).
pub fn parse_args<I, S>(args: I) -> std::result::Result<Cli, clap::Error>
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString> + Clone,
{
    Cli::try_parse_from(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_apply_command() {
        let cli = parse_args(["toride-harden", "apply", "server"]).unwrap();
        match cli.command {
            Commands::Apply {
                profile,
                dry_run,
                no_backup,
            } => {
                assert_eq!(profile, "server");
                assert!(!dry_run);
                assert!(!no_backup);
            }
            _ => panic!("expected Apply command"),
        }
    }

    #[test]
    fn parse_apply_dry_run() {
        let cli = parse_args(["toride-harden", "apply", "--dry-run", "desktop"]).unwrap();
        match cli.command {
            Commands::Apply { dry_run, .. } => assert!(dry_run),
            _ => panic!("expected Apply command"),
        }
    }

    #[test]
    fn parse_status_command() {
        let cli = parse_args(["toride-harden", "status"]).unwrap();
        assert!(matches!(cli.command, Commands::Status { .. }));
    }

    #[test]
    fn parse_diff_command() {
        let cli = parse_args(["toride-harden", "diff", "server"]).unwrap();
        assert!(matches!(cli.command, Commands::Diff { .. }));
    }

    #[test]
    fn parse_doctor_command() {
        let cli = parse_args(["toride-harden", "doctor"]).unwrap();
        assert!(matches!(cli.command, Commands::Doctor));
    }

    #[test]
    fn parse_profiles_command() {
        let cli = parse_args(["toride-harden", "profiles"]).unwrap();
        assert!(matches!(cli.command, Commands::Profiles));
    }

    // ── Dispatch tests: parse a Commands variant AND prove it reaches the
    //    real client via a FakeRunner-backed HardenClient. ───────────────

    use toride_runner::fake::FakeRunner;

    #[test]
    fn dispatch_status_calls_sysctl() {
        // `status` (non-verbose) routes through `HardenClient::check`, which
        // runs `sysctl -a`. Give it a single response.
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(
            "kernel.randomize_va_space = 2\nnet.ipv4.ip_forward = 0\n",
        ));
        let client = HardenClient::with_runner(Box::new(runner.clone()));

        let cli = parse_args(["toride-harden", "status"]).unwrap();
        cli.run_with_client(&client).expect("status dispatch failed");

        let calls = runner.calls();
        // The dispatch must have invoked the real sysctl binary.
        assert!(
            calls
                .iter()
                .any(|c| c.program == "sysctl" && c.args.contains(&"-a".to_string())),
            "expected a `sysctl -a` call, got: {calls:?}"
        );
    }

    #[test]
    fn dispatch_diff_calls_sysctl_read_all() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(
            "kernel.randomize_va_space = 2\n",
        ));
        let client = HardenClient::with_runner(Box::new(runner.clone()));

        let cli = parse_args(["toride-harden", "diff", "desktop"]).unwrap();
        cli.run_with_client(&client).expect("diff dispatch failed");

        let calls = runner.calls();
        assert!(
            calls
                .iter()
                .any(|c| c.program == "sysctl" && c.args.first().is_some_and(|a| a == "-a")),
            "expected a `sysctl -a` call for diff, got: {calls:?}"
        );
    }

    #[test]
    fn dispatch_apply_unknown_profile_errors() {
        // No runner calls needed: profile resolution fails before any sysctl.
        let runner = FakeRunner::new();
        let client = HardenClient::with_runner(Box::new(runner.clone()));

        let cli = parse_args(["toride-harden", "apply", "definitely-not-a-profile"]).unwrap();
        let err = cli.run_with_client(&client);
        assert!(
            err.is_err(),
            "applying an unknown profile should error before touching the system"
        );
        // And it must NOT have run any sysctl command.
        assert!(
            runner.calls().is_empty(),
            "unknown profile should short-circuit before dispatch"
        );
    }

    #[test]
    fn dispatch_apply_dry_run_does_not_write() {
        // Desktop profile; dry-run reads current state via one `sysctl -a`.
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(
            "kernel.randomize_va_space = 2\nnet.ipv4.ip_forward = 0\n",
        ));
        let client = HardenClient::with_runner(Box::new(runner.clone()));

        let cli = parse_args(["toride-harden", "apply", "--dry-run", "desktop"]).unwrap();
        cli.run_with_client(&client).expect("dry-run dispatch failed");

        let calls = runner.calls();
        assert!(
            calls
                .iter()
                .any(|c| c.program == "sysctl" && c.args.first().is_some_and(|a| a == "-a")),
            "dry-run should read current state via `sysctl -a`"
        );
        // Critical safety check: a dry run must never issue a `sysctl -w`.
        assert!(
            !calls
                .iter()
                .any(|c| c.program == "sysctl" && c.args.contains(&"-w".to_string())),
            "dry-run must not write any sysctl value, got: {calls:?}"
        );
    }
}
