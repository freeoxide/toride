//! SSH key file discovery and parsing.

use crate::paths::SshPaths;
use crate::{Result, SshKey};

/// Scan `~/.ssh/id_*` and the agent for available keys.
pub async fn scan_keys(_paths: &SshPaths) -> Result<Vec<SshKey>> {
    todo!()
}
