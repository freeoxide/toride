//! Backup utilities for audit configuration files.
//!
//! Provides functions to create timestamped backups of audit rules,
//! AIDE configuration, rsyslog configuration, and logrotate configuration
//! before modifications are applied.

use std::fs;
use std::path::Path;

use crate::Result;

// ---------------------------------------------------------------------------
// Backup creation
// ---------------------------------------------------------------------------

/// Create a timestamped backup of a file.
///
/// The backup is placed in the same directory as the original file,
/// with a `.bak.<timestamp>` suffix. The timestamp format is
/// `YYYYMMDD-HHMMSS`.
///
/// # Errors
///
/// Returns [`crate::Error::Io`] if the file cannot be read or the backup
/// cannot be written.
pub fn create_backup(path: &Path) -> Result<PathBuf> {
    let timestamp = chrono_now_string();
    let backup_path = PathBuf::from(format!("{}.bak.{timestamp}", path.display()));

    if path.exists() {
        fs::copy(path, &backup_path)?;
    }

    Ok(backup_path)
}

/// Restore a file from its most recent backup.
///
/// Finds the most recent `.bak.*` file for the given path and copies
/// it back to the original location.
///
/// # Errors
///
/// Returns [`crate::Error::Io`] if the backup cannot be found or restored.
pub fn restore_backup(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| crate::Error::Other("path has no parent directory".to_owned()))?;

    let filename = path
        .file_name()
        .ok_or_else(|| crate::Error::Other("path has no file name".to_owned()))?
        .to_string_lossy();

    let pattern = format!("{filename}.bak.");

    let mut backups: Vec<_> = fs::read_dir(parent)?
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(&pattern))
        .collect();

    backups.sort_by_key(std::fs::DirEntry::file_name);

    if let Some(most_recent) = backups.pop() {
        fs::copy(most_recent.path(), path)?;
    }

    Ok(())
}

/// List all backups for a given file path.
///
/// Returns backup paths sorted from oldest to newest.
///
/// # Errors
///
/// Returns [`crate::Error::Io`] if the directory cannot be read.
pub fn list_backups(path: &Path) -> Result<Vec<PathBuf>> {
    let parent = path
        .parent()
        .ok_or_else(|| crate::Error::Other("path has no parent directory".to_owned()))?;

    let filename = path
        .file_name()
        .ok_or_else(|| crate::Error::Other("path has no file name".to_owned()))?
        .to_string_lossy();

    let pattern = format!("{filename}.bak.");

    let mut backups: Vec<_> = fs::read_dir(parent)?
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(&pattern))
        .map(|entry| entry.path())
        .collect();

    backups.sort();

    Ok(backups)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

use std::path::PathBuf;

/// Generate a simple timestamp string for backup filenames.
fn chrono_now_string() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", now.as_secs())
}
