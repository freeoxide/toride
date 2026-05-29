mod generate;
mod inventory;
mod repair;

use crate::paths::SshPaths;
use crate::{KeyCreateParams, KeyDeleteParams, Result, SshKey};

/// Key management operations.
pub struct KeyService<'a> {
    paths: &'a SshPaths,
}

impl<'a> KeyService<'a> {
    pub(crate) fn new(paths: &'a SshPaths) -> Self {
        Self { paths }
    }

    /// List all SSH keys found on disk and in the agent.
    pub async fn list(&self) -> Result<Vec<SshKey>> {
        inventory::scan_keys(self.paths).await
    }

    /// Generate a new SSH key pair.
    pub async fn create(&self, params: KeyCreateParams) -> Result<SshKey> {
        generate::generate_key(self.paths, params).await
    }

    /// Delete a key and optionally its public pair, certificate, agent entry, and config refs.
    pub async fn delete(&self, _params: KeyDeleteParams) -> Result<()> {
        todo!()
    }

    /// Derive the `.pub` file from a private key.
    pub async fn repair_public(&self, private_key_path: &std::path::Path) -> Result<()> {
        repair::repair_public_key(private_key_path).await
    }
}
