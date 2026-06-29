//! Log management facade.
//!
//! Provides a unified interface for managing system logs across multiple
//! backends (rsyslog, journald) with log rotation support.

use toride_runner::CommandSpec;

use crate::{AuditPaths, Result};

// ---------------------------------------------------------------------------
// LogManager
// ---------------------------------------------------------------------------

/// High-level manager for system log management.
///
/// Delegates to backend-specific modules (rsyslog, journald) and
/// provides a unified interface for log operations.
pub struct LogManager<'a> {
    runner: &'a dyn toride_runner::Runner,
    /// System paths; kept for API symmetry with the other managers though
    /// not read by this manager yet.
    #[allow(dead_code)]
    paths: &'a AuditPaths,
}

impl<'a> LogManager<'a> {
    /// Create a new log manager with the given runner and paths.
    pub fn new(runner: &'a dyn toride_runner::Runner, paths: &'a AuditPaths) -> Self {
        Self { runner, paths }
    }

    /// List configured log files managed by the audit subsystem.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the log directory cannot be read.
    pub fn list_log_files(&self) -> Result<Vec<String>> {
        let log_dir = std::path::Path::new("/var/log/audit");
        if !log_dir.exists() {
            return Ok(Vec::new());
        }

        let mut files = Vec::new();
        for entry in std::fs::read_dir(log_dir)? {
            let entry = entry?;
            if entry.path().is_file() {
                files.push(entry.path().to_string_lossy().to_string());
            }
        }

        files.sort();
        Ok(files)
    }

    /// Check if rsyslog is available and running.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the check cannot be performed.
    pub fn is_rsyslog_available(&self) -> Result<bool> {
        if which::which("rsyslogd").is_err() {
            return Ok(false);
        }
        let spec = CommandSpec::new("systemctl").args(["is-active", "rsyslog"]);
        let output = self.runner.run(&spec)?;
        Ok(output.success)
    }

    /// Check if journald is available and running.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the check cannot be performed.
    pub fn is_journald_available(&self) -> Result<bool> {
        if which::which("systemd-journald").is_err() && which::which("journalctl").is_err() {
            return Ok(false);
        }
        let spec = CommandSpec::new("systemctl").args(["is-active", "systemd-journald"]);
        let output = self.runner.run(&spec)?;
        Ok(output.success)
    }
}
