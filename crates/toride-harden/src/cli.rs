//! CLI argument parsing for the toride-harden command.
//!
//! Uses `clap` to define the command-line interface for applying,
//! inspecting, and diffing kernel hardening parameters.

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
}
