//! systemd-journald management.
//!
//! Provides functions for interacting with systemd-journald for
//! audit log aggregation and querying.

use crate::{AuditPaths, Error, Result};
use toride_runner::CommandSpec;

// ---------------------------------------------------------------------------
// JournaldManager
// ---------------------------------------------------------------------------

/// Manager for journald-based audit log operations.
///
/// Provides methods for querying journal entries related to the audit
/// subsystem and checking journald configuration.
pub struct JournaldManager<'a> {
    runner: &'a dyn toride_runner::Runner,
    /// System paths; kept for API symmetry with the other managers though
    /// not read by this manager yet.
    #[allow(dead_code)]
    paths: &'a AuditPaths,
}

impl<'a> JournaldManager<'a> {
    /// Create a new journald manager with the given runner and paths.
    pub fn new(runner: &'a dyn toride_runner::Runner, paths: &'a AuditPaths) -> Self {
        Self { runner, paths }
    }

    /// Query audit-related journal entries.
    ///
    /// Uses `journalctl` with audit-related filters.
    ///
    /// # Arguments
    ///
    /// * `since` - Optional time filter (e.g. "today", "1 hour ago").
    /// * `unit` - Optional systemd unit filter (e.g. "auditd.service").
    ///
    /// # Errors
    ///
    /// Returns [`Error::BinaryNotFound`] if `journalctl` is not available.
    pub fn query(&self, since: Option<&str>, unit: Option<&str>) -> Result<String> {
        // Presence check (the runner would also fail, but this gives a clearer error).
        which::which("journalctl").map_err(|_| Error::BinaryNotFound("journalctl".to_owned()))?;

        let mut spec = CommandSpec::new("journalctl");
        if let Some(s) = since {
            spec = spec.arg("--since").arg(s);
        }
        if let Some(u) = unit {
            spec = spec.arg("--unit").arg(u);
        }
        let output = self.runner.run(&spec)?;
        Ok(output.stdout)
    }

    /// Query journal entries for the audit daemon.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BinaryNotFound`] if `journalctl` is not available.
    pub fn query_auditd(&self) -> Result<String> {
        self.query(None, Some("auditd.service"))
    }

    /// Get disk usage of the journal.
    ///
    /// Runs `journalctl --disk-usage`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BinaryNotFound`] if `journalctl` is not available.
    pub fn disk_usage(&self) -> Result<String> {
        which::which("journalctl").map_err(|_| Error::BinaryNotFound("journalctl".to_owned()))?;
        let spec = CommandSpec::new("journalctl").arg("--disk-usage");
        let output = self.runner.run(&spec)?;
        Ok(output.stdout)
    }

    /// Vacuum journal entries older than the specified time.
    ///
    /// Runs `journalctl --vacuum-time=<time>`.
    ///
    /// # Arguments
    ///
    /// * `time` - Time specification (e.g. "7d", "2weeks").
    ///
    /// # Errors
    ///
    /// Returns [`Error::BinaryNotFound`] if `journalctl` is not available.
    /// Returns [`Error::CommandFailed`] if the vacuum fails.
    pub fn vacuum_time(&self, time: &str) -> Result<()> {
        which::which("journalctl").map_err(|_| Error::BinaryNotFound("journalctl".to_owned()))?;
        let spec = CommandSpec::new("journalctl").arg(format!("--vacuum-time={time}"));
        self.runner.run_checked(&spec)?;
        Ok(())
    }
}
