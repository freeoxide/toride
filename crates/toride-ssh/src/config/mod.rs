mod ast;
mod directives;
mod editor;
mod managed;
mod parse;
mod resolve;

use crate::paths::SshPaths;
use crate::Result;

/// SSH config file operations.
pub struct ConfigService<'a> {
    paths: &'a SshPaths,
}

impl<'a> ConfigService<'a> {
    pub(crate) fn new(paths: &'a SshPaths) -> Self {
        Self { paths }
    }

    /// Load and parse the SSH config.
    pub async fn load(&self) -> Result<()> {
        todo!()
    }
}
