//! Audit client for interacting with audit subsystem commands.
//!
//! Provides a high-level client wrapping `auditctl`, `aureport`, and
//! `ausearch` commands for querying and managing the Linux audit framework.

use toride_runner::CommandSpec;

use crate::{AuditPaths, Error, Result};

// ---------------------------------------------------------------------------
// AuditClient
// ---------------------------------------------------------------------------

/// Client for interacting with the Linux audit subsystem.
///
/// Wraps the `auditctl`, `aureport`, and `ausearch` binaries and
/// provides typed methods for common operations.
///
/// # Example
///
/// ```ignore
/// use toride_audit::client::AuditClient;
///
/// let client = AuditClient::new(runner.as_ref());
/// let rules = client.list_rules()?;
/// ```
pub struct AuditClient<'a> {
    runner: &'a dyn toride_runner::Runner,
    /// System paths; kept for API symmetry with the other managers though
    /// not read by this client yet.
    #[allow(dead_code)]
    paths: &'a AuditPaths,
}

impl<'a> AuditClient<'a> {
    /// Create a new audit client with the given runner.
    pub fn new(runner: &'a dyn toride_runner::Runner, paths: &'a AuditPaths) -> Self {
        Self { runner, paths }
    }

    /// List currently loaded audit rules via `auditctl -l`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BinaryNotFound`] if `auditctl` is not on `$PATH`.
    /// Returns [`Error::CommandFailed`] if the command exits non-zero.
    pub fn list_rules(&self) -> Result<String> {
        which::which("auditctl").map_err(|_| Error::BinaryNotFound("auditctl".to_owned()))?;
        let spec = CommandSpec::new("auditctl").arg("-l");
        let output = self.runner.run_checked(&spec)?;
        Ok(output.stdout)
    }

    /// Add a single audit rule via `auditctl`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BinaryNotFound`] if `auditctl` is not on `$PATH`.
    /// Returns [`Error::CommandFailed`] if the rule is rejected.
    pub fn add_rule(&self, rule: &str) -> Result<()> {
        which::which("auditctl").map_err(|_| Error::BinaryNotFound("auditctl".to_owned()))?;
        let args: Vec<&str> = rule.split_whitespace().collect();
        let spec = CommandSpec::new("auditctl").args(args);
        self.runner.run_checked(&spec)?;
        Ok(())
    }

    /// Delete all audit rules via `auditctl -D`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BinaryNotFound`] if `auditctl` is not on `$PATH`.
    pub fn delete_all_rules(&self) -> Result<()> {
        which::which("auditctl").map_err(|_| Error::BinaryNotFound("auditctl".to_owned()))?;
        let spec = CommandSpec::new("auditctl").arg("-D");
        self.runner.run_checked(&spec)?;
        Ok(())
    }

    /// Get the audit subsystem status via `auditctl -s`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BinaryNotFound`] if `auditctl` is not on `$PATH`.
    pub fn status(&self) -> Result<String> {
        which::which("auditctl").map_err(|_| Error::BinaryNotFound("auditctl".to_owned()))?;
        let spec = CommandSpec::new("auditctl").arg("-s");
        let output = self.runner.run_checked(&spec)?;
        Ok(output.stdout)
    }

    /// Generate a summary report via `aureport`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BinaryNotFound`] if `aureport` is not on `$PATH`.
    pub fn aureport(&self) -> Result<String> {
        which::which("aureport").map_err(|_| Error::BinaryNotFound("aureport".to_owned()))?;
        let spec = CommandSpec::new("aureport");
        let output = self.runner.run_checked(&spec)?;
        Ok(output.stdout)
    }

    /// Search audit logs via `ausearch`.
    ///
    /// # Arguments
    ///
    /// * `args` - Additional arguments to pass to `ausearch`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BinaryNotFound`] if `ausearch` is not on `$PATH`.
    pub fn ausearch(&self, args: &[&str]) -> Result<String> {
        which::which("ausearch").map_err(|_| Error::BinaryNotFound("ausearch".to_owned()))?;
        let spec = CommandSpec::new("ausearch").args(args.iter().copied());
        let output = self.runner.run_checked(&spec)?;
        Ok(output.stdout)
    }
}
