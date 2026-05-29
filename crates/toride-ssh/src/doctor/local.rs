//! Local SSH diagnostic checks.

use crate::paths::SshPaths;
use crate::{Diagnostic, Result};

/// Run all local diagnostic checks.
pub async fn run_all(_paths: &SshPaths) -> Result<Vec<Diagnostic>> {
    todo!()
}
