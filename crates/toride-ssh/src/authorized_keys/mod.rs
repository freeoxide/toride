mod options;
mod parse;

use crate::paths::SshPaths;
use crate::Result;

/// `authorized_keys` file management.
pub struct AuthorizedKeysService<'a> {
    paths: &'a SshPaths,
}

impl<'a> AuthorizedKeysService<'a> {
    pub(crate) fn new(paths: &'a SshPaths) -> Self {
        Self { paths }
    }

    /// List all authorized key entries.
    pub async fn list(&self) -> Result<()> {
        todo!()
    }
}
