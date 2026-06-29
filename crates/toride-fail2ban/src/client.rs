//! Typed wrapper around the `fail2ban-client` binary.
//!
//! [`Fail2BanClient`] provides a safe, typed interface to every
//! `fail2ban-client` command the library needs. All commands go through the
//! centralised [`Runner`] trait so they are testable via [`FakeRunner`] and
//! respect dry-run mode automatically.
//!
//! # Example
//!
//! ```ignore
//! use crate::command::DuctRunner;
//! use crate::client::Fail2BanClient;
//!
//! let runner = DuctRunner::new();
//! let client = Fail2BanClient::new(&runner)?;
//!
//! client.ping()?;
//! let version = client.version()?;
//! let status = client.status()?;
//! ```

use std::path::PathBuf;

use crate::command::{CommandOutput, Runner, find_binary};
use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Fail2BanClient
// ---------------------------------------------------------------------------

/// Typed wrapper around the `fail2ban-client` binary.
///
/// Every method constructs the appropriate argument list and delegates
/// execution to the injected [`Runner`]. Arguments are always passed as
/// arrays -- no shell string concatenation is used.
///
/// # Lifetimes
///
/// The client borrows the runner (`'a`) so the caller controls ownership
/// and can swap in a [`FakeRunner`] for testing.
pub struct Fail2BanClient<'a> {
    /// Command runner used for all invocations.
    runner: &'a dyn Runner,
    /// Resolved path to the `fail2ban-client` binary.
    binary: PathBuf,
}

impl<'a> Fail2BanClient<'a> {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Create a new client by locating `fail2ban-client` on `$PATH`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the binary cannot be found.
    pub fn new(runner: &'a dyn Runner) -> Result<Self> {
        let binary = find_binary("fail2ban-client")?;
        Ok(Self { runner, binary })
    }

    /// Create a client with an explicit binary path.
    ///
    /// Use this when the caller knows the exact location of
    /// `fail2ban-client` (for example in a chroot or container).
    pub fn with_binary(runner: &'a dyn Runner, binary: PathBuf) -> Self {
        Self { runner, binary }
    }

    // -----------------------------------------------------------------------
    // Health / discovery
    // -----------------------------------------------------------------------

    /// Check that the Fail2Ban server is reachable.
    ///
    /// Runs `fail2ban-client ping`.
    pub fn ping(&self) -> Result<()> {
        let _out = self.run_cmd(&["ping"])?;
        Ok(())
    }

    /// Return the Fail2Ban version string.
    ///
    /// Runs `fail2ban-client --version` and extracts the version from the
    /// first line of output (best-effort parsing).
    pub fn version(&self) -> Result<String> {
        let out = self.run_cmd(&["--version"])?;
        // Best-effort: return the first non-empty line, trimmed.
        let line = out.stdout.lines().next().unwrap_or("").trim().to_string();
        Ok(line)
    }

    // -----------------------------------------------------------------------
    // Config validation
    // -----------------------------------------------------------------------

    /// Validate the current Fail2Ban configuration without reloading.
    ///
    /// Runs `fail2ban-client --test`.
    pub fn test_config(&self) -> Result<()> {
        let _out = self.run_cmd(&["--test"])?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Reload / restart
    // -----------------------------------------------------------------------

    /// Reload the entire Fail2Ban configuration.
    ///
    /// Runs `fail2ban-client reload`.
    pub fn reload(&self) -> Result<()> {
        let _out = self.run_cmd(&["reload"])?;
        Ok(())
    }

    /// Reload a single jail.
    ///
    /// Runs `fail2ban-client reload <jail>`.
    pub fn reload_jail(&self, jail: &str) -> Result<()> {
        let _out = self.run_cmd(&["reload", jail])?;
        Ok(())
    }

    /// Restart a single jail, optionally unbanning all current IPs first.
    ///
    /// Runs `fail2ban-client restart <jail>` and appends `--unban` when
    /// `unban` is `true`.
    pub fn restart_jail(&self, jail: &str, unban: bool) -> Result<()> {
        if unban {
            let _out = self.run_cmd(&["restart", jail, "--unban"])?;
        } else {
            let _out = self.run_cmd(&["restart", jail])?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Status / statistics
    // -----------------------------------------------------------------------

    /// Return overall Fail2Ban status as raw output.
    ///
    /// Runs `fail2ban-client status`. Returns the raw stdout so the caller
    /// can decide how to parse the free-form text (best-effort guidance
    /// from the plan).
    pub fn status(&self) -> Result<String> {
        let out = self.run_cmd(&["status"])?;
        Ok(out.stdout.trim().to_string())
    }

    /// Return status for a single jail as raw output.
    ///
    /// Runs `fail2ban-client status <jail>`.
    pub fn status_jail(&self, jail: &str) -> Result<String> {
        let out = self.run_cmd(&["status", jail])?;
        Ok(out.stdout.trim().to_string())
    }

    /// Return Fail2Ban statistics as raw output.
    ///
    /// In Fail2Ban v1 this is the same as [`Self::status`]. Kept as a
    /// separate method so callers can express intent and so the
    /// implementation can diverge in future versions.
    pub fn statistics(&self) -> Result<String> {
        // Fail2Ban v1 does not have a dedicated "statistics" sub-command.
        // "status" provides the summary information.
        self.status()
    }

    // -----------------------------------------------------------------------
    // Banned IPs
    // -----------------------------------------------------------------------

    /// List all currently banned IPs across all jails.
    ///
    /// Runs `fail2ban-client banned`. Returns raw output.
    pub fn banned(&self) -> Result<String> {
        let out = self.run_cmd(&["banned"])?;
        Ok(out.stdout.trim().to_string())
    }

    /// Check whether a specific IP is currently banned.
    ///
    /// Runs `fail2ban-client banned <ip>`. Returns raw output.
    pub fn banned_ip(&self, ip: &str) -> Result<String> {
        let out = self.run_cmd(&["banned", ip])?;
        Ok(out.stdout.trim().to_string())
    }

    // -----------------------------------------------------------------------
    // Manual ban / unban
    // -----------------------------------------------------------------------

    /// Manually ban an IP address in the given jail.
    ///
    /// Runs `fail2ban-client set <jail> banip <ip>`.
    pub fn ban_ip(&self, jail: &str, ip: &str) -> Result<()> {
        let _out = self.run_cmd(&["set", jail, "banip", ip])?;
        Ok(())
    }

    /// Manually unban an IP address in the given jail.
    ///
    /// Runs `fail2ban-client set <jail> unbanip <ip>`.
    pub fn unban_ip(&self, jail: &str, ip: &str) -> Result<()> {
        let _out = self.run_cmd(&["set", jail, "unbanip", ip])?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Ignore IP management (runtime only)
    // -----------------------------------------------------------------------

    /// Add an IP or CIDR to the ignore list for a jail at runtime.
    ///
    /// Runs `fail2ban-client set <jail> addignoreip <ip>`.
    /// This is a **runtime-only** change -- it does not persist across
    /// restarts unless also written to the config file.
    pub fn add_ignore_ip(&self, jail: &str, ip: &str) -> Result<()> {
        let _out = self.run_cmd(&["set", jail, "addignoreip", ip])?;
        Ok(())
    }

    /// Remove an IP or CIDR from the ignore list for a jail at runtime.
    ///
    /// Runs `fail2ban-client set <jail> delignoreip <ip>`.
    /// This is a **runtime-only** change.
    pub fn remove_ignore_ip(&self, jail: &str, ip: &str) -> Result<()> {
        let _out = self.run_cmd(&["set", jail, "delignoreip", ip])?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Global getters
    // -----------------------------------------------------------------------

    /// Return the current log target path.
    ///
    /// Runs `fail2ban-client get logtarget`.
    pub fn get_logtarget(&self) -> Result<String> {
        let out = self.run_cmd(&["get", "logtarget"])?;
        Ok(out.stdout.trim().to_string())
    }

    /// Return the current database file path.
    ///
    /// Runs `fail2ban-client get dbfile`.
    pub fn get_dbfile(&self) -> Result<String> {
        let out = self.run_cmd(&["get", "dbfile"])?;
        Ok(out.stdout.trim().to_string())
    }

    /// Return the current database purge age.
    ///
    /// Runs `fail2ban-client get dbpurgeage`.
    pub fn get_dbpurgeage(&self) -> Result<String> {
        let out = self.run_cmd(&["get", "dbpurgeage"])?;
        Ok(out.stdout.trim().to_string())
    }

    // -----------------------------------------------------------------------
    // Utilities
    // -----------------------------------------------------------------------

    /// Convert a Fail2Ban duration string to seconds.
    ///
    /// Runs `fail2ban-client --str2sec <value>` and returns the result.
    /// This delegates to Fail2Ban itself for correct semantics (e.g.
    /// `"10m"`, `"1h"`, `"-1"` for permanent).
    pub fn str_to_seconds(&self, value: &str) -> Result<String> {
        let out = self.run_cmd(&["--str2sec", value])?;
        Ok(out.stdout.trim().to_string())
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Run `fail2ban-client` with the given arguments.
    ///
    /// Centralises binary resolution, logging, and error handling so every
    /// public method stays minimal.
    fn run_cmd(&self, args: &[&str]) -> Result<CommandOutput> {
        let program = self.binary.to_str().ok_or_else(|| {
            Error::CommandFailed(format!(
                "binary path is not valid UTF-8: {}",
                self.binary.display()
            ))
        })?;

        tracing::debug!(
            binary = %self.binary.display(),
            args = ?args,
            "running fail2ban-client command"
        );

        let out = self.runner.run(program, args)?;

        if !out.success {
            let detail = match (&out.exit_code, out.stderr.trim()) {
                (Some(code), stderr) if !stderr.is_empty() => {
                    format!("{program} exited with status {code}: {stderr}")
                }
                (Some(code), _) => format!("{program} exited with status {code}"),
                (None, stderr) if !stderr.is_empty() => {
                    format!("{program} failed: {stderr}")
                }
                (None, _) => format!("{program} could not be started"),
            };
            return Err(Error::CommandFailed(detail));
        }

        Ok(out)
    }
}

#[cfg(test)]
#[path = "client.test.rs"]
mod tests;
