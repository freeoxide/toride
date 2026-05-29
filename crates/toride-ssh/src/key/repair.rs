//! Repair missing public key files from private keys.

use std::path::Path;

use crate::Result;

/// Derive and write the `.pub` file for a private key.
pub async fn repair_public_key(_private_key_path: &Path) -> Result<()> {
    todo!()
}
