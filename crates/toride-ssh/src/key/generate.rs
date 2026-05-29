//! SSH key generation via ssh-key crate and ssh-keygen CLI.

use crate::paths::SshPaths;
use crate::{KeyCreateParams, Result, SshKey};

/// Generate a new SSH key pair.
pub async fn generate_key(_paths: &SshPaths, _params: KeyCreateParams) -> Result<SshKey> {
    todo!()
}
