//! Config file backup and restore for WireGuard.
//!
//! Provides a simple mechanism for backing up interface config files before
//! modification and restoring them on failure. Backups are stored in a
//! `backups/` subdirectory under the WireGuard config root.

use std::fs;
use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::paths::WireguardPaths;

// ---------------------------------------------------------------------------
// BackupManager
// ---------------------------------------------------------------------------

/// Manages config file backups for a WireGuard interface.
///
/// Each interface gets its own subdirectory under `<root>/backups/`.
/// Backups are timestamped so multiple versions are preserved.
#[derive(Debug)]
pub struct BackupManager {
    paths: WireguardPaths,
}

impl BackupManager {
    /// Create a new backup manager using the given path layout.
    pub fn new(paths: &WireguardPaths) -> Self {
        Self {
            paths: paths.clone(),
        }
    }

    /// Create a timestamped backup of the interface config file.
    ///
    /// Copies `<root>/<interface>.conf` to `<root>/backups/<interface>/<timestamp>.conf`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigWrite`] if the backup directory cannot be created
    /// or the file cannot be copied.
    pub fn backup(&self, interface: &str) -> Result<PathBuf> {
        let source = self.paths.interface_conf(interface);
        if !source.exists() {
            return Err(Error::ConfigParse(format!(
                "config file not found: {}",
                source.display()
            )));
        }

        let backup_dir = self.paths.backup_dir(interface);
        fs::create_dir_all(&backup_dir).map_err(|e| {
            Error::ConfigWrite(format!(
                "failed to create backup directory {}: {e}",
                backup_dir.display()
            ))
        })?;

        let timestamp = chrono_now_string();
        let dest = backup_dir.join(format!("{timestamp}.conf"));
        fs::copy(&source, &dest).map_err(|e| {
            Error::ConfigWrite(format!(
                "failed to backup {} to {}: {e}",
                source.display(),
                dest.display()
            ))
        })?;

        tracing::info!("backed up {} to {}", source.display(), dest.display());
        Ok(dest)
    }

    /// Restore the most recent backup for an interface.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigParse`] if no backup exists, or
    /// [`Error::ConfigWrite`] if the restore fails.
    pub fn restore_latest(&self, interface: &str) -> Result<PathBuf> {
        let backup_dir = self.paths.backup_dir(interface);
        if !backup_dir.is_dir() {
            return Err(Error::ConfigParse(format!(
                "no backups found for interface {interface}"
            )));
        }

        let mut entries: Vec<_> = fs::read_dir(&backup_dir)
            .map_err(Error::Io)?
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "conf"))
            .collect();

        entries.sort_by_key(std::fs::DirEntry::file_name);
        let latest = entries.pop().ok_or_else(|| {
            Error::ConfigParse(format!("no backup files found for interface {interface}"))
        })?;

        let dest = self.paths.interface_conf(interface);
        fs::copy(latest.path(), &dest)
            .map_err(|e| Error::ConfigWrite(format!("failed to restore backup: {e}")))?;

        tracing::info!(
            "restored {} from {}",
            dest.display(),
            latest.path().display()
        );
        Ok(dest)
    }

    /// List all backups for an interface, ordered oldest to newest.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the backup directory cannot be read.
    pub fn list_backups(&self, interface: &str) -> Result<Vec<PathBuf>> {
        let backup_dir = self.paths.backup_dir(interface);
        if !backup_dir.is_dir() {
            return Ok(Vec::new());
        }

        let mut entries: Vec<_> = fs::read_dir(&backup_dir)
            .map_err(Error::Io)?
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "conf"))
            .map(|e| e.path())
            .collect();

        entries.sort();
        Ok(entries)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a filesystem-safe timestamp string for backup filenames.
fn chrono_now_string() -> String {
    // Use a simple approach without depending on chrono.
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", duration.as_secs())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_nonexistent_interface() {
        let paths = WireguardPaths::with_root(PathBuf::from("/tmp/no-such-dir"));
        let mgr = BackupManager::new(&paths);
        let result = mgr.backup("wg0");
        assert!(result.is_err());
    }

    #[test]
    fn restore_no_backups() {
        let paths = WireguardPaths::with_root(PathBuf::from("/tmp/no-such-dir"));
        let mgr = BackupManager::new(&paths);
        let result = mgr.restore_latest("wg0");
        assert!(result.is_err());
    }

    #[test]
    fn list_backups_empty() {
        let paths = WireguardPaths::with_root(PathBuf::from("/tmp/no-such-dir"));
        let mgr = BackupManager::new(&paths);
        let result = mgr.list_backups("wg0").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn chrono_now_string_is_numeric() {
        let s = chrono_now_string();
        assert!(s.chars().all(|c| c.is_ascii_digit()));
    }
}
