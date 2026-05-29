mod client;
mod session;

use crate::paths::SshPaths;
use crate::Result;

/// SSH agent operations.
pub struct AgentService<'a> {
    paths: &'a SshPaths,
}

impl<'a> AgentService<'a> {
    pub(crate) fn new(paths: &'a SshPaths) -> Self {
        Self { paths }
    }

    /// Check if the SSH agent is reachable.
    pub async fn status(&self) -> Result<bool> {
        todo!()
    }
}
