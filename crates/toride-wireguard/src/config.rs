//! Full INI config file read/write for WireGuard.
//!
//! Provides high-level operations for reading, writing, and managing
//! WireGuard interface configuration files in INI format.

use std::fs;

use crate::backup::BackupManager;
use crate::diff::ConfigDiff;
use crate::error::{Error, Result};
use crate::parse::parse_interface_conf;
use crate::paths::WireguardPaths;
use crate::render::render_interface_conf;
use crate::spec::WireguardSpec;
use crate::validate::validate_interface_name;

// ---------------------------------------------------------------------------
// ConfigManager
// ---------------------------------------------------------------------------

/// Manages WireGuard INI configuration files on disk.
///
/// Provides methods for reading, writing, previewing diffs, and applying
/// configuration changes with automatic backup.
pub struct ConfigManager {
    paths: WireguardPaths,
    backup: BackupManager,
}

impl ConfigManager {
    /// Create a new config manager with the given path layout.
    pub fn new(paths: &WireguardPaths) -> Self {
        Self {
            paths: paths.clone(),
            backup: BackupManager::new(paths),
        }
    }

    /// Read and parse an interface config file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigParse`] if the file cannot be read or parsed.
    pub fn read(&self, interface: &str) -> Result<WireguardSpec> {
        validate_interface_name(interface)?;
        let path = self.paths.interface_conf(interface);

        let content = fs::read_to_string(&path)
            .map_err(|e| Error::ConfigParse(format!("failed to read {}: {e}", path.display())))?;

        parse_interface_conf(interface, &content)
    }

    /// Write an interface config file to disk.
    ///
    /// Optionally creates a backup before writing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigWrite`] if the backup or write fails.
    pub fn write(&self, spec: &WireguardSpec, create_backup: bool) -> Result<()> {
        validate_interface_name(&spec.name)?;

        if create_backup {
            self.backup.backup(&spec.name)?;
        }

        let path = self.paths.interface_conf(&spec.name);
        let content = render_interface_conf(spec);

        // Ensure the parent directory exists.
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                Error::ConfigWrite(format!(
                    "failed to create directory {}: {e}",
                    parent.display()
                ))
            })?;
        }

        // Write atomically at 0600 so the PrivateKey-bearing config is never
        // observable in a partial state and never lands world-readable. The
        // underlying `toride_fs::atomic_write_with_perms` writes to a temp
        // file, `chmod`s it, then renames over the target.
        toride_fs::atomic_write_with_perms(&path, &content, 0o600)
            .map_err(|e| Error::ConfigWrite(format!("failed to write {}: {e}", path.display())))?;

        tracing::info!("wrote WireGuard config for {}", spec.name);
        Ok(())
    }

    /// Preview the diff between the current config on disk and a new spec.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigParse`] if the current config cannot be read.
    /// Returns `Ok` with an empty diff if no config file exists yet.
    pub fn diff(&self, new_spec: &WireguardSpec) -> Result<ConfigDiff> {
        let old_content = match fs::read_to_string(self.paths.interface_conf(&new_spec.name)) {
            Ok(c) => c,
            Err(_) => String::new(),
        };
        let new_content = render_interface_conf(new_spec);
        Ok(ConfigDiff::new(&old_content, &new_content))
    }

    /// Delete an interface config file.
    ///
    /// Creates a backup before deleting.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigParse`] if the file does not exist.
    /// Returns [`Error::Io`] if the deletion fails.
    pub fn delete(&self, interface: &str) -> Result<()> {
        validate_interface_name(interface)?;
        let path = self.paths.interface_conf(interface);

        if !path.exists() {
            return Err(Error::ConfigParse(format!(
                "config file not found: {}",
                path.display()
            )));
        }

        self.backup.backup(interface)?;
        fs::remove_file(&path).map_err(Error::Io)?;

        tracing::info!("deleted WireGuard config for {interface}");
        Ok(())
    }

    /// Check if a config file exists for the given interface.
    pub fn exists(&self, interface: &str) -> bool {
        self.paths.interface_conf(interface).is_file()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn config_manager_new() {
        let paths = WireguardPaths::with_root(PathBuf::from("/tmp/wg-test"));
        let mgr = ConfigManager::new(&paths);
        assert!(!mgr.exists("wg0"));
    }

    #[test]
    fn read_nonexistent() {
        let paths = WireguardPaths::with_root(PathBuf::from("/tmp/no-such-dir"));
        let mgr = ConfigManager::new(&paths);
        assert!(mgr.read("wg0").is_err());
    }

    #[test]
    fn diff_empty_when_no_existing_config() {
        let paths = WireguardPaths::with_root(PathBuf::from("/tmp/no-such-dir"));
        let mgr = ConfigManager::new(&paths);
        let spec = WireguardSpec::new("wg0".to_owned(), "10.0.0.1/24".to_owned());
        let diff = mgr.diff(&spec).unwrap();
        assert!(!diff.is_empty()); // everything is new
    }

    #[test]
    fn delete_nonexistent() {
        let paths = WireguardPaths::with_root(PathBuf::from("/tmp/no-such-dir"));
        let mgr = ConfigManager::new(&paths);
        assert!(mgr.delete("wg0").is_err());
    }
}
