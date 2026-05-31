//! SSH diagnostic service ("doctor") for environment health checks.
//!
//! Provides [`DoctorService`], which orchestrates local and remote checks
//! covering directory structure, file permissions, key strength, agent
//! availability, config validity, and remote connectivity. Sub-modules
//! define the [`Check`](check::Check) trait, the local/remote check
//! implementations, and the [`CheckRegistry`](registry::CheckRegistry).

mod check;
mod local;
mod registry;
mod remote;

use crate::paths::SshPaths;
use crate::{Diagnostic, Result};

/// SSH diagnostic operations (local and remote).
///
/// Obtained from [`SshManager::doctor()`](crate::SshManager::doctor).
pub struct DoctorService<'a> {
    paths: &'a SshPaths,
    runner: &'a dyn crate::CliRunner,
}

impl<'a> DoctorService<'a> {
    pub(crate) fn new(paths: &'a SshPaths, runner: &'a dyn crate::CliRunner) -> Self {
        Self { paths, runner }
    }

    /// Run all local diagnostic checks.
    ///
    /// Executes every registered local check (directory existence,
    /// permissions, key strength, agent availability, config analysis,
    /// etc.) and returns all collected diagnostics.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the SSH directory cannot be read, or
    /// [`Error::CheckFailed`] if an individual check encounters an
    /// unrecoverable error.
    pub async fn run_local_checks(&self) -> Result<Vec<Diagnostic>> {
        local::run_all(self.paths, self.runner).await
    }

    /// Run remote diagnostic checks for a host.
    ///
    /// Connects to the given host and runs server-side diagnostic checks
    /// (SSH version, supported algorithms, host key verification, etc.).
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the SSH connection fails, or
    /// [`Error::CheckFailed`] if an individual check encounters an
    /// unrecoverable error.
    pub async fn run_remote_checks(&self, host: &str) -> Result<Vec<Diagnostic>> {
        remote::run_all(self.paths, host, self.runner).await
    }
}
