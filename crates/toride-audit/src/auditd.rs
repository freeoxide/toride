//! Audit daemon management.
//!
//! Provides high-level operations for managing the Linux audit daemon
//! including rule loading, status queries, and service lifecycle.

use toride_runner::CommandSpec;

use crate::{AuditPaths, Error, Result};

// ---------------------------------------------------------------------------
// AuditdManager
// ---------------------------------------------------------------------------

/// High-level manager for the Linux audit daemon.
///
/// Composes the audit client, rule management, and service operations
/// into a unified interface for auditd management.
pub struct AuditdManager<'a> {
    runner: &'a dyn toride_runner::Runner,
    paths: &'a AuditPaths,
}

impl<'a> AuditdManager<'a> {
    /// Create a new auditd manager with the given runner and paths.
    pub fn new(runner: &'a dyn toride_runner::Runner, paths: &'a AuditPaths) -> Self {
        Self { runner, paths }
    }

    /// Load audit rules from a rules file via `auditctl -R`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BinaryNotFound`] if `auditctl` is not available.
    /// Returns [`Error::CommandFailed`] if the rules cannot be loaded.
    pub fn load_rules_file(&self, rules_path: &std::path::Path) -> Result<()> {
        which::which("auditctl").map_err(|_| Error::BinaryNotFound("auditctl".to_owned()))?;
        let spec = CommandSpec::new("auditctl")
            .arg("-R")
            .arg(rules_path.to_str().unwrap_or_default());
        self.runner.run_checked(&spec)?;
        Ok(())
    }

    /// Get the current audit daemon status.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BinaryNotFound`] if `auditctl` is not available.
    pub fn status(&self) -> Result<String> {
        which::which("auditctl").map_err(|_| Error::BinaryNotFound("auditctl".to_owned()))?;
        let spec = CommandSpec::new("auditctl").arg("-s");
        let output = self.runner.run_checked(&spec)?;
        Ok(output.stdout)
    }

    /// Flush all current audit rules and load from the rules directory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BinaryNotFound`] if `auditctl` is not available.
    pub fn reload_rules(&self) -> Result<()> {
        // Delete existing rules.
        which::which("auditctl").map_err(|_| Error::BinaryNotFound("auditctl".to_owned()))?;
        let spec = CommandSpec::new("auditctl").arg("-D");
        self.runner.run_checked(&spec)?;

        // Load rules from rules.d directory.
        if self.paths.rules_d.exists() {
            let mut loaded = false;
            for entry in std::fs::read_dir(&self.paths.rules_d)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "rules") {
                    self.load_rules_file(&path)?;
                    loaded = true;
                }
            }
            if !loaded {
                tracing::warn!("no .rules files found in {}", self.paths.rules_d.display());
            }
        }

        Ok(())
    }

    /// Check if the auditd service is running.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the check cannot be performed.
    pub fn is_running(&self) -> Result<bool> {
        let spec = CommandSpec::new("systemctl").args(["is-active", "auditd"]);
        let output = self.runner.run(&spec)?;
        Ok(output.success)
    }
}
