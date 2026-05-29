use std::path::PathBuf;

use crate::Error;

/// Resolved paths for the `~/.ssh` directory.
#[derive(Debug, Clone)]
pub struct SshPaths {
    ssh_dir: PathBuf,
}

impl SshPaths {
    /// Resolve paths from the user's home directory.
    pub fn new() -> Result<Self, Error> {
        let home = dirs::home_dir().ok_or(Error::HomeNotFound)?;
        let ssh_dir = home.join(".ssh");
        Ok(Self { ssh_dir })
    }

    /// Path to `~/.ssh`.
    pub fn ssh_dir(&self) -> &PathBuf {
        &self.ssh_dir
    }

    /// Path to `~/.ssh/config`.
    pub fn config_path(&self) -> PathBuf {
        self.ssh_dir.join("config")
    }

    /// Path to `~/.ssh/known_hosts`.
    pub fn known_hosts_path(&self) -> PathBuf {
        self.ssh_dir.join("known_hosts")
    }

    /// Path to `~/.ssh/authorized_keys`.
    pub fn authorized_keys_path(&self) -> PathBuf {
        self.ssh_dir.join("authorized_keys")
    }

    /// Default key file name patterns to scan (without extension).
    pub fn default_key_names() -> &'static [&'static str] {
        &["id_rsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk"]
    }
}
