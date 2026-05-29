//! Host key scanning via `ssh-keyscan`.

use crate::Result;

/// Scan a host for its public host keys.
pub async fn scan_host(_host: &str) -> Result<()> {
    todo!()
}
