//! Parse SSH config using ssh2-config-rs.

use std::io::BufReader;
use std::path::Path;

use ssh2_config_rs::{ParseRule, SshConfig};

use toride_ssh_core::Result;

/// Parse the SSH config file at the given path using ssh2-config-rs.
///
/// Returns the typed [`SshConfig`] which supports `.query(host)` to get
/// resolved [`HostParams`].
pub async fn parse_config(path: &Path) -> Result<SshConfig> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        let file = std::fs::File::open(&path)?;
        let mut reader = BufReader::new(file);
        let config = SshConfig::default()
            .parse(&mut reader, ParseRule::ALLOW_UNSUPPORTED_FIELDS)
            .map_err(|e| toride_ssh_core::Error::ConfigParseFailed(e.to_string()))?;
        Ok(config)
    })
    .await
    .map_err(|e| {
        toride_ssh_core::Error::ConfigParseFailed(format!("blocking task panicked: {e}"))
    })?
}

/// Parse SSH config from a string using ssh2-config-rs.
///
/// Useful for testing or when the content is already in memory.
#[allow(dead_code, reason = "public API, not exercised in-workspace")]
pub fn parse_config_str(input: &str) -> Result<SshConfig> {
    let mut reader = BufReader::new(input.as_bytes());
    SshConfig::default()
        .parse(&mut reader, ParseRule::ALLOW_UNSUPPORTED_FIELDS)
        .map_err(|e| toride_ssh_core::Error::ConfigParseFailed(e.to_string()))
}
