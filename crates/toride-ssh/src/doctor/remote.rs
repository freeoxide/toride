//! Remote SSH diagnostic checks.

use crate::paths::SshPaths;
use crate::{Diagnostic, Result};

/// Run all remote diagnostic checks for a host.
pub async fn run_all(_paths: &SshPaths, _host: &str) -> Result<Vec<Diagnostic>> {
    todo!()
}
