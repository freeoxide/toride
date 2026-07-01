//! Configuration file backup and restore.
//!
//! Provides utilities for creating timestamped backups of user configuration
//! files (`/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers`, etc.)
//! before modifications.

use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// Default backup directory relative to the system root.
const BACKUP_DIR: &str = "/var/backups/toride-users";

// ---------------------------------------------------------------------------
// Test-only backup-dir override (no env mutation, no unsafe)
// ---------------------------------------------------------------------------

// The production default (`/var/backups/toride-users`) is not writable from an
// unprivileged test runner. Rather than mutate process environment (which is
// `unsafe` under edition 2024 and forbidden by `#![deny(unsafe_code)]`), tests
// install a per-thread override via `set_test_backup_dir`. The value is read
// at backup time, so each test can point backups at its own tempdir without
// racing other threads.
#[cfg(test)]
thread_local! {
    static TEST_BACKUP_DIR: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

/// Install a per-thread backup-directory override for hermetic testing.
///
/// Only available under `cfg(test)`. Restored automatically when the returned
/// guard drops.
#[cfg(test)]
pub fn set_test_backup_dir(dir: &Path) -> TestBackupDirGuard {
    TEST_BACKUP_DIR.with(|c| *c.borrow_mut() = Some(dir.to_owned()));
    TestBackupDirGuard { _phantom: () }
}

/// RAII guard that clears the test backup-dir override on drop.
#[cfg(test)]
#[must_use]
pub struct TestBackupDirGuard {
    _phantom: (),
}

#[cfg(test)]
impl Drop for TestBackupDirGuard {
    fn drop(&mut self) {
        TEST_BACKUP_DIR.with(|c| *c.borrow_mut() = None);
    }
}

/// Resolve the effective backup directory.
///
/// Honors an explicit `backup_dir` argument first, then the test-only
/// per-thread override, then the [`BACKUP_DIR`] default.
fn resolve_backup_dir(backup_dir: Option<&Path>) -> PathBuf {
    if let Some(d) = backup_dir {
        return PathBuf::from(d);
    }
    #[cfg(test)]
    if let Some(d) = TEST_BACKUP_DIR.with(|c| c.borrow().clone()) {
        return d;
    }
    let _ = backup_dir; // (already consumed above)
    PathBuf::from(BACKUP_DIR)
}

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
    let dir = resolve_backup_dir(backup_dir);

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
    let dir = resolve_backup_dir(backup_dir);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_backup_dir_wins() {
        let dir = resolve_backup_dir(Some(Path::new("/custom/backup")));
        assert_eq!(dir, PathBuf::from("/custom/backup"));
    }

    #[test]
    fn test_override_redirects_default() {
        // Installing the per-thread override must redirect the default
        // resolution away from /var/backups/toride-users.
        let tmp = tempfile::tempdir().unwrap();
        let _guard = set_test_backup_dir(tmp.path());
        assert_eq!(resolve_backup_dir(None), tmp.path());
    }

    #[test]
    fn test_override_cleared_after_guard_drops() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let _guard = set_test_backup_dir(tmp.path());
            assert_eq!(resolve_backup_dir(None), tmp.path());
        }
        // After the guard drops, the default is restored.
        assert_eq!(resolve_backup_dir(None), PathBuf::from(BACKUP_DIR));
    }

    #[test]
    fn backup_file_writes_to_override_dir() {
        let src_dir = tempfile::tempdir().unwrap();
        let src = src_dir.path().join("sshd");
        std::fs::write(&src, "auth required pam_unix.so\n").unwrap();

        let backup_dir = tempfile::tempdir().unwrap();
        let _guard = set_test_backup_dir(backup_dir.path());
        let backup = backup_file(&src, None).unwrap();

        assert!(backup.starts_with(backup_dir.path()));
        assert!(backup.exists());
    }
}
