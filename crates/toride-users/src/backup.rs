//! Configuration file backup and restore.
//!
//! Provides utilities for creating timestamped backups of user configuration
//! files (`/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers`, etc.)
//! before modifications.

use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// Default backup directory relative to the system root.
const BACKUP_DIR: &str = "/var/backups/toride-users";

/// Create a timestamped backup of a configuration file.
///
/// Copies `source` to `/var/backups/toride-users/<filename>.<timestamp>.bak`.
/// The backup directory is created if it does not exist.
///
/// # Errors
///
/// Returns [`Error::Io`] if the directory cannot be created or the file
/// cannot be copied.
pub fn backup_file(source: &Path, backup_dir: Option<&Path>) -> Result<PathBuf> {
    let dir = backup_dir.map_or_else(|| PathBuf::from(BACKUP_DIR), PathBuf::from);

    std::fs::create_dir_all(&dir)?;

    let filename = source
        .file_name()
        .ok_or_else(|| Error::Other(format!("path has no filename: {}", source.display())))?;

    let timestamp = chrono_less_timestamp();

    let backup_name = format!("{}.{timestamp}.bak", filename.to_string_lossy());
    let backup_path = dir.join(&backup_name);

    std::fs::copy(source, &backup_path)?;

    tracing::info!(
        "backed up {} to {}",
        source.display(),
        backup_path.display()
    );

    Ok(backup_path)
}

/// Restore a file from a backup path.
///
/// Copies the backup file back to `target`, overwriting any existing file.
///
/// # Errors
///
/// Returns [`Error::Io`] if the copy fails.
pub fn restore_file(backup: &Path, target: &Path) -> Result<()> {
    std::fs::copy(backup, target)?;
    tracing::info!("restored {} from {}", target.display(), backup.display());
    Ok(())
}

/// List all backup files in the backup directory.
///
/// Returns paths sorted by modification time (newest first).
///
/// # Errors
///
/// Returns [`Error::Io`] if the directory cannot be read.
pub fn list_backups(backup_dir: Option<&Path>) -> Result<Vec<PathBuf>> {
    let dir = backup_dir.map_or_else(|| PathBuf::from(BACKUP_DIR), PathBuf::from);

    if !dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)?
        .filter_map(std::result::Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "bak"))
        .map(|e| e.path())
        .collect();

    entries.sort_by(|a, b| {
        b.metadata()
            .and_then(|m| m.modified())
            .ok()
            .cmp(&a.metadata().and_then(|m| m.modified()).ok())
    });

    Ok(entries)
}

/// Generate a simple timestamp string for backup filenames.
fn chrono_less_timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", now.as_secs())
}
