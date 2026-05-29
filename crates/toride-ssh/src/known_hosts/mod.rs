mod parse;
mod scan;

use crate::paths::SshPaths;
use crate::Result;

/// `known_hosts` file management.
pub struct KnownHostsService<'a> {
    paths: &'a SshPaths,
}

impl<'a> KnownHostsService<'a> {
    pub(crate) fn new(paths: &'a SshPaths) -> Self {
        Self { paths }
    }

    /// List all known host entries.
    pub async fn list(&self) -> Result<()> {
        todo!()
    }
}
