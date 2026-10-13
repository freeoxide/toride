//! Command-line interface for fail2ban.

use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::paths::Fail2BanPaths;
use crate::types::ExecutionMode;

/// Fail2Ban CLI for toride.
#[derive(Parser, Debug)]
#[command(
    name = "toride-fail2ban",
    about = "Fail2Ban-style intrusion prevention"
)]
pub struct Cli {
    /// Path to configuration file (default: the XDG
    /// `$XDG_CONFIG_HOME/toride/fail2ban/config.json` resolved by
    /// [`Fail2BanPaths::resolve`]).
    #[arg(short, long)]
    pub config: Option<PathBuf>,

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

    /// The effective config path: the `--config` value (with a leading `~`
    /// expanded to the home directory) or the XDG default from
    /// [`Fail2BanPaths::resolve`].
    ///
    /// # Errors
    ///
    /// Returns `InvalidConfig` when `--config ~...` was given but the home
    /// directory cannot be determined, or when the XDG default cannot be
    /// resolved.
    pub fn resolved_config(&self) -> crate::Result<PathBuf> {
        match &self.config {
            Some(path) => expand_leading_tilde(path),
            #[cfg(feature = "config")]
            None => Fail2BanPaths::resolve().map(|paths| paths.config_file),
            #[cfg(not(feature = "config"))]
            None => Err(crate::Error::InvalidConfig(
                "--config is required when the `config` feature is disabled",
            )),
        }
    }
}

/// Expand a leading `~` component to the home directory; `~user` prefixes
/// and interior tildes pass through untouched.
fn expand_leading_tilde(path: &std::path::Path) -> crate::Result<PathBuf> {
    let is_bare_tilde = path
        .components()
        .next()
        .is_some_and(|c| c.as_os_str() == "~");
    if !is_bare_tilde {
        return Ok(path.to_path_buf());
    }
    let home = dirs::home_dir().ok_or_else(|| {
        crate::Error::InvalidConfig(format!(
            "cannot expand '~' in {}: home directory is unknown",
            path.display()
        ))
    })?;
    let rest: PathBuf = path.components().skip(1).collect();
    if rest.as_os_str().is_empty() {
        Ok(home)
    } else {
        Ok(home.join(rest))
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
