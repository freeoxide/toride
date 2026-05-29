mod check;
mod local;
mod registry;
mod remote;

use crate::paths::SshPaths;
use crate::{Diagnostic, Result};

/// SSH diagnostic operations (local and remote).
pub struct DoctorService<'a> {
    paths: &'a SshPaths,
}

impl<'a> DoctorService<'a> {
    pub(crate) fn new(paths: &'a SshPaths) -> Self {
        Self { paths }
    }

    /// Run all local diagnostic checks.
    pub async fn run_local_checks(&self) -> Result<Vec<Diagnostic>> {
        local::run_all(self.paths).await
    }

    /// Run remote diagnostic checks for a host.
    pub async fn run_remote_checks(&self, _host: &str) -> Result<Vec<Diagnostic>> {
        todo!()
    }
}
