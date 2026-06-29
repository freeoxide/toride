//! Pre-mutation config backup.
//!
//! Before modifying any update configuration file, the existing content is
//! backed up to a `.bak` file alongside the original. This enables rollback
//! if the apply fails.

use std::fs;
use std::path::Path;

use tracing::info;

use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// backup_config
// ---------------------------------------------------------------------------

/// Create a backup of an existing config file.
///
/// Reads the file at `path` and writes its contents to `{path}.bak`.
/// If the file does not exist, this is a no-op (no backup needed for a new file).
///
/// # Errors
///
/// Returns [`Error::Io`] if the file exists but cannot be read or the backup
/// cannot be written.
pub fn backup_config(path: &Path) -> Result<()> {
    if !path.exists() {
        info!("No existing config to backup at {}", path.display());
        return Ok(());
    }

    let backup_path = backup_path(path);
    let content = fs::read_to_string(path)?;
    fs::write(&backup_path, &content)?;

    info!("Backed up {} -> {}", path.display(), backup_path.display());

    Ok(())
}

// ---------------------------------------------------------------------------
// restore_backup
// ---------------------------------------------------------------------------

/// Restore a config file from its backup.
///
/// Reads the `.bak` file and writes its contents back to the original path.
///
/// # Errors
///
/// Returns [`Error::Io`] if the backup file cannot be read or the original
/// file cannot be written.
pub fn restore_backup(path: &Path) -> Result<()> {
    let backup = backup_path(path);
    if !backup.exists() {
        return Err(Error::Other(format!(
            "No backup found at {}",
            backup.display()
        )));
    }

    let content = fs::read_to_string(&backup)?;
    fs::write(path, &content)?;

    info!("Restored {} from backup", path.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// backup_path
// ---------------------------------------------------------------------------

/// Return the backup path for a given config file path.
///
/// Appends `.bak` to the original path.
#[must_use]
pub fn backup_path(path: &Path) -> std::path::PathBuf {
    let mut buf = path.to_path_buf();
    buf.set_extension(match path.extension() {
        Some(ext) => format!("{}.bak", ext.to_string_lossy()),
        None => "bak".to_owned(),
    });
    buf
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn backup_path_appends_bak() {
        let path = PathBuf::from("/etc/apt/apt.conf.d/50unattended-upgrades");
        let backup = backup_path(&path);
        assert_eq!(
            backup,
            PathBuf::from("/etc/apt/apt.conf.d/50unattended-upgrades.bak")
        );
    }

    #[test]
    fn backup_path_no_extension() {
        let path = PathBuf::from("/etc/dnf/automatic");
        let backup = backup_path(&path);
        assert_eq!(backup, PathBuf::from("/etc/dnf/automatic.bak"));
    }
}
