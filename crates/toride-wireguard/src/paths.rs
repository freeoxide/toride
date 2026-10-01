//! WireGuard system path layout.
//!
//! [`WireguardPaths`](crate::paths::WireguardPaths) resolves the standard WireGuard configuration directory
//! (`/etc/wireguard/`) and provides helpers for building interface config paths,
//! key file paths, and backup locations.

use std::path::PathBuf;

use crate::error::{Error, Result};

/// Resolved paths to the WireGuard configuration directory tree.
///
/// By default this points at `/etc/wireguard`. Use [`WireguardPaths::with_root`]
/// to override (e.g. for testing).
#[derive(Debug, Clone)]
pub struct WireguardPaths {
    /// Root WireGuard configuration directory (e.g. `/etc/wireguard`).
    root: PathBuf,
}

impl WireguardPaths {
    /// Create a `WireguardPaths` pointing at `/etc/wireguard`.
    pub fn new() -> Self {
        Self {
            root: PathBuf::from("/etc/wireguard"),
        }
    }

    /// Create a `WireguardPaths` with a custom root directory.
    pub fn with_root(root: PathBuf) -> Self {
        Self { root }
    }

    /// Returns the root configuration directory.
    pub fn root(&self) -> &PathBuf {
        &self.root
    }

    /// Returns the path to an interface config file (e.g. `/etc/wireguard/wg0.conf`).
    pub fn interface_conf(&self, interface: &str) -> PathBuf {
        self.root.join(format!("{interface}.conf"))
    }

    /// Returns the path to a private key file for an interface.
    pub fn private_key(&self, interface: &str) -> PathBuf {
        self.root.join(format!("{interface}.key"))
    }

    /// Returns the path to a public key file for an interface.
    pub fn public_key(&self, interface: &str) -> PathBuf {
        self.root.join(format!("{interface}.pub"))
    }

    /// Returns the path to a backup directory for an interface.
    pub fn backup_dir(&self, interface: &str) -> PathBuf {
        self.root.join("backups").join(interface)
    }

    /// Validate that the root directory exists.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigParse`] if the root directory does not exist.
    pub fn validate(&self) -> Result<()> {
        if !self.root.is_dir() {
            return Err(Error::ConfigParse(format!(
                "WireGuard config directory does not exist: {}",
                self.root.display()
            )));
        }
        Ok(())
    }
}

impl Default for WireguardPaths {
    fn default() -> Self {
        Self::new()
    }
}
