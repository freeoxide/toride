mod control;

use crate::paths::SshPaths;
use crate::Result;

/// Port forwarding management via ControlMaster sessions.
pub struct ForwardService<'a> {
    paths: &'a SshPaths,
}

impl<'a> ForwardService<'a> {
    pub(crate) fn new(paths: &'a SshPaths) -> Self {
        Self { paths }
    }

    /// List active port forwards.
    pub async fn list(&self) -> Result<()> {
        todo!()
    }
}
