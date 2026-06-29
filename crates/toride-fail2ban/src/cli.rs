//! Command-line interface for fail2ban.

use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::types::ExecutionMode;

/// Fail2Ban CLI for toride.
#[derive(Parser, Debug)]
#[command(
    name = "toride-fail2ban",
    about = "Fail2Ban-style intrusion prevention"
)]
pub struct Cli {
    /// Path to configuration file.
    #[arg(short, long, default_value = "~/.config/toride/fail2ban/config.json")]
    pub config: PathBuf,

    /// Enable verbose logging.
    #[arg(short, long)]
    pub verbose: bool,

    /// Dry run mode - log actions without executing.
    #[arg(long)]
    pub dry_run: bool,

    /// The subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,
}

impl Cli {
    /// Convert the `--dry-run` flag into an [`ExecutionMode`].
    #[allow(dead_code, reason = "used by CLI binary, not library tests")]
    pub const fn execution_mode(&self) -> ExecutionMode {
        if self.dry_run {
            ExecutionMode::DryRun
        } else {
            ExecutionMode::Execute
        }
    }
}

/// Available CLI subcommands.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start the fail2ban daemon.
    Start {
        /// Jail to start (defaults to all enabled).
        #[arg(long)]
        jail: Option<String>,
    },

    /// Stop the fail2ban daemon.
    Stop,

    /// Show status of all jails or a specific jail.
    Status {
        /// Jail name to show status for.
        jail: Option<String>,
    },

    /// Manually ban an IP address.
    Ban {
        /// IP address to ban.
        ip: IpAddr,
        /// Jail to ban in.
        #[arg(long, default_value = "default")]
        jail: String,
    },

    /// Unban an IP address.
    Unban {
        /// IP address to unban.
        ip: IpAddr,
        /// Jail to unban from.
        #[arg(long, default_value = "default")]
        jail: String,
    },

    /// Set a configuration value.
    Set {
        /// Jail name.
        jail: String,
        /// Parameter to set.
        param: String,
        /// Value to set.
        value: String,
    },

    /// Test a log pattern against a file.
    Test {
        /// Log file to test against.
        log_path: PathBuf,
        /// Regex pattern to test.
        #[arg(short, long)]
        pattern: String,
    },

    /// Add a new jail configuration.
    AddJail {
        /// Jail name.
        name: String,
        /// Log file path.
        #[arg(long)]
        log_path: PathBuf,
        /// Regex pattern.
        #[arg(long)]
        pattern: String,
        /// Max retries before ban.
        #[arg(long, default_value = "5")]
        max_retry: u32,
        /// Ban duration in seconds.
        #[arg(long, default_value = "3600")]
        ban_time: u64,
    },

    /// Remove a jail configuration.
    RmJail {
        /// Jail name to remove.
        name: String,
    },
}

#[cfg(test)]
#[path = "cli.test.rs"]
mod tests;
