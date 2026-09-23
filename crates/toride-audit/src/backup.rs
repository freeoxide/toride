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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Write `body` to `<dir>/<name>`.
    fn write_file(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, body).expect("write file");
        path
    }

    #[test]
    fn create_backup_copies_existing_file_content() {
        let dir = TempDir::new().expect("tempdir");
        let original = write_file(dir.path(), "audit.rules", "original body");

        let backup = create_backup(&original).expect("create backup");
        assert!(backup.exists(), "backup file should exist on disk");
        assert_eq!(
            backup.parent().unwrap(),
            original.parent().unwrap(),
            "backup must live in the same directory as the source"
        );
        let backup_name = backup.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            backup_name.starts_with("audit.rules.bak."),
            "backup name should follow the <name>.bak.<ts> scheme: {backup_name}"
        );
        assert_eq!(
            fs::read_to_string(&backup).expect("read backup"),
            "original body",
            "backup content must match the source"
        );
    }

    #[test]
    fn create_backup_for_missing_source_still_returns_path() {
        // create_backup does not treat a missing source as an error: it returns
        // the would-be backup path without writing anything.
        let dir = TempDir::new().expect("tempdir");
        let missing = dir.path().join("never-existed.conf");

        let backup = create_backup(&missing).expect("no error for missing source");
        assert!(
            !backup.exists(),
            "no file should be written for missing source"
        );
        let name = backup.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("never-existed.conf.bak."));
    }

    #[test]
    fn restore_backup_selects_most_recent_backup() {
        let dir = TempDir::new().expect("tempdir");
        let target = write_file(dir.path(), "auditd.conf", "current live content");

        // Simulate two historical backups. restore_backup sorts by file name
        // (lexicographic) and pops the last entry as "most recent", so the
        // lexicographically-greatest suffix wins.
        write_file(dir.path(), "auditd.conf.bak.100", "older backup");
        write_file(dir.path(), "auditd.conf.bak.200", "newer backup");

        restore_backup(&target).expect("restore");

        assert_eq!(
            fs::read_to_string(&target).expect("read restored"),
            "newer backup",
            "restore should overwrite the target with the most-recent backup"
        );
    }

    #[test]
    fn restore_backup_is_noop_when_no_backups_exist() {
        let dir = TempDir::new().expect("tempdir");
        let target = write_file(dir.path(), "auditd.conf", "untouched");

        // No `.bak.*` siblings present.
        restore_backup(&target).expect("restore should not error with no backups");
        assert_eq!(
            fs::read_to_string(&target).expect("read target"),
            "untouched",
            "target must be left untouched when there is nothing to restore"
        );
    }

    #[test]
    fn restore_backup_only_considers_own_prefix() {
        let dir = TempDir::new().expect("tempdir");
        let target = write_file(dir.path(), "aide.conf", "current");
        // Backups for a *different* file must be ignored.
        write_file(dir.path(), "auditd.conf.bak.999", "not mine");
        write_file(dir.path(), "aide.conf.bak.5", "real backup");

        restore_backup(&target).expect("restore");
        assert_eq!(
            fs::read_to_string(&target).expect("read target"),
            "real backup"
        );
    }

    #[test]
    fn list_backups_returns_sorted_paths() {
        let dir = TempDir::new().expect("tempdir");
        let target = write_file(dir.path(), "audit.rules", "x");
        write_file(dir.path(), "audit.rules.bak.30", "a");
        write_file(dir.path(), "audit.rules.bak.10", "b");
        write_file(dir.path(), "audit.rules.bak.20", "c");
        // Unrelated sibling must be excluded.
        write_file(dir.path(), "other.rules.bak.5", "z");

        let backups = list_backups(&target).expect("list");
        let names: Vec<String> = backups
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec![
                "audit.rules.bak.10".to_owned(),
                "audit.rules.bak.20".to_owned(),
                "audit.rules.bak.30".to_owned(),
            ],
            "list_backups must return only matching backups, oldest-first"
        );
    }

    #[test]
    fn list_backups_empty_when_none_exist() {
        let dir = TempDir::new().expect("tempdir");
        let target = write_file(dir.path(), "audit.rules", "x");
        let backups = list_backups(&target).expect("list");
        assert!(backups.is_empty());
    }

    #[test]
    fn restore_backup_errors_for_missing_directory() {
        // Pointing at a path inside a non-existent directory makes read_dir
        // on the parent fail, surfacing an I/O error rather than panicking.
        let dir = TempDir::new().expect("tempdir");
        let missing_parent = dir.path().join("does-not-exist").join("auditd.conf");
        let result = restore_backup(&missing_parent);
        assert!(result.is_err(), "expected an error for a missing directory");
    }

    #[test]
    fn list_backups_errors_for_missing_directory() {
        // Pointing at a path inside a non-existent directory makes read_dir
        // fail on the parent, surfacing an I/O error.
        let dir = TempDir::new().expect("tempdir");
        let missing_parent = dir.path().join("does-not-exist").join("audit.rules");
        let result = list_backups(&missing_parent);
        assert!(result.is_err(), "expected an error for a missing directory");
    }

    #[test]
    fn create_then_restore_round_trip() {
        let dir = TempDir::new().expect("tempdir");
        let target = write_file(dir.path(), "rotate.conf", "v1");
        let _backup = create_backup(&target).expect("create backup");

        // Mutate the live file, then restore from the backup we just made.
        fs::write(&target, "v2-mutated").expect("mutate");
        restore_backup(&target).expect("restore");
        assert_eq!(
            fs::read_to_string(&target).expect("read"),
            "v1",
            "create+restore must return the live file to its backed-up state"
        );
    }
}
