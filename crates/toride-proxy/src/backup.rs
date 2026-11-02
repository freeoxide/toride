//! Pre-mutation backups of individual proxy configuration files.
//!
//! Every write path snapshots exactly the file it is about to overwrite:
//! one small copy per mutation instead of a whole-tree dump, so applying N
//! sites costs N short backups rather than O(N^2) bytes. Files are named
//! `<original>.<nanos>.bak` (nanosecond stamps, so two backups within one
//! second never overwrite each other), carry the original bytes verbatim,
//! and are pruned to [`MAX_RETAINED_PER_FILE`] per original name.

use crate::error::Result;
use crate::paths::ProxyPaths;
use std::path::{Path, PathBuf};

/// Backups kept per original file, newest first; older ones are pruned on
/// every save so repeated applies cannot grow the backup directory without
/// bound.
pub const MAX_RETAINED_PER_FILE: usize = 5;

/// Mode the restored file is written at: daemon-readable proxy config.
const RESTORE_MODE: u32 = 0o644;

/// A snapshot of a single configuration file, taken just before overwriting
/// it.
#[derive(Debug, Clone)]
pub struct BackupSnapshot {
    /// Stamp of the snapshot (nanoseconds since the UNIX epoch). Also names
    /// the on-disk backup file.
    pub timestamp: u128,
    /// Absolute or root-relative path of the file that was snapshotted.
    pub source: PathBuf,
    /// The file's bytes at snapshot time; `None` when it could not be read
    /// (a first write has nothing to back up).
    pub content: Option<Vec<u8>>,
}

/// Nanoseconds since the UNIX epoch, the backup filename stamp.
fn timestamp_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

/// Snapshot one file before mutating it.
///
/// A missing or unreadable file yields `content: None` rather than an error:
/// a first write has no previous content to preserve.
///
/// # Errors
///
/// Returns an error only when the backup directory itself cannot be created
/// by [`save_backup_to_disk`]; reading the source is best-effort.
pub fn create_backup(source: &Path) -> Result<BackupSnapshot> {
    Ok(BackupSnapshot {
        timestamp: timestamp_nanos(),
        source: source.to_path_buf(),
        content: std::fs::read(source).ok(),
    })
}

/// Restore a snapshot in process, writing the original bytes back atomically
/// at mode 0644.
///
/// The `.bak` files written by [`save_backup_to_disk`] are verbatim copies,
/// so an operator can equally restore one after the process has exited with
/// `cp <backup> <original>`.
///
/// # Errors
///
/// Returns an error when the snapshot carries no content or the write fails.
pub fn restore_backup(snapshot: &BackupSnapshot) -> Result<()> {
    let content = snapshot.content.as_ref().ok_or_else(|| {
        crate::Error::ConfigWrite("snapshot has no content to restore".to_owned())
    })?;
    if let Some(parent) = snapshot.source.parent() {
        std::fs::create_dir_all(parent)?;
    }
    toride_fs::atomic_write_bytes_with_perms(&snapshot.source, content, RESTORE_MODE)
        .map_err(crate::Error::from)
}

/// Persist a snapshot next to the other backups of the same file, then prune
/// that file's backups to [`MAX_RETAINED_PER_FILE`], newest first.
///
/// The backup file is `<file_name>.<nanos>.bak` under
/// [`ProxyPaths::backup_dir`], holding the original bytes verbatim.
///
/// # Errors
///
/// Returns an error if the backup directory cannot be created, the backup
/// file cannot be written, or a prune deletion fails.
pub fn save_backup_to_disk(paths: &ProxyPaths, snapshot: &BackupSnapshot) -> Result<PathBuf> {
    std::fs::create_dir_all(&paths.backup_dir)?;

    let dest = backup_path_for(paths, snapshot);
    if let Some(content) = &snapshot.content {
        toride_fs::atomic_write_bytes_with_perms(&dest, content, RESTORE_MODE)
            .map_err(crate::Error::from)?;
        tracing::debug!(
            backup = %dest.display(),
            source = %snapshot.source.display(),
            "backup: persisted pre-mutation snapshot"
        );
    }
    prune_backups(paths, snapshot)?;
    Ok(dest)
}

/// The on-disk backup path for a snapshot.
fn backup_path_for(paths: &ProxyPaths, snapshot: &BackupSnapshot) -> PathBuf {
    let name = snapshot.source.file_name().map_or_else(
        || snapshot.source.to_string_lossy().into_owned(),
        |n| n.to_string_lossy().into_owned(),
    );
    paths
        .backup_dir
        .join(format!("{name}.{}.bak", snapshot.timestamp))
}

/// Delete this source file's oldest backups beyond [`MAX_RETAINED_PER_FILE`].
///
/// # Errors
///
/// Returns an error when the backup directory cannot be listed or a deletion
/// fails.
fn prune_backups(paths: &ProxyPaths, snapshot: &BackupSnapshot) -> Result<()> {
    let prefix = snapshot.source.file_name().map_or_else(
        || snapshot.source.to_string_lossy().into_owned(),
        |n| n.to_string_lossy().into_owned(),
    ) + ".";
    let mut stamps: Vec<(u128, PathBuf)> = std::fs::read_dir(&paths.backup_dir)?
        .flatten()
        .filter_map(|entry| {
            let file_name = entry.file_name().into_string().ok()?;
            let stem = file_name.strip_prefix(&prefix)?;
            let stamp = stem.strip_suffix(".bak")?.parse::<u128>().ok()?;
            Some((stamp, entry.path()))
        })
        .collect();
    stamps.sort_by_key(|&(stamp, _)| std::cmp::Reverse(stamp));
    for (_, path) in stamps.into_iter().skip(MAX_RETAINED_PER_FILE) {
        std::fs::remove_file(&path).map_err(|e| {
            crate::Error::ConfigWrite(format!("pruning old backup {}: {e}", path.display()))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::TempDir;

    fn paths_under(root: &Path) -> ProxyPaths {
        ProxyPaths::with_root(root)
    }

    #[test]
    fn snapshot_captures_one_file_verbatim() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("example.com");
        std::fs::write(&file, "server { listen 80; }\n").unwrap();

        let snapshot = create_backup(&file).unwrap();

        assert_eq!(snapshot.source, file);
        assert_eq!(
            snapshot.content.as_deref(),
            Some(b"server { listen 80; }\n" as &[u8])
        );
    }

    #[test]
    fn snapshot_of_a_missing_file_has_no_content() {
        let dir = TempDir::new().unwrap();
        let snapshot = create_backup(&dir.path().join("absent.conf")).unwrap();
        assert!(snapshot.content.is_none());
    }

    #[test]
    fn restore_writes_the_original_bytes_back() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("example.com");
        std::fs::write(&file, "original\n").unwrap();

        let snapshot = create_backup(&file).unwrap();
        std::fs::write(&file, "mutated\n").unwrap();
        restore_backup(&snapshot).unwrap();

        assert_eq!(std::fs::read_to_string(&file).unwrap(), "original\n");
    }

    /// Only the mutated file is snapshotted: sibling sites and the Caddyfile
    /// are never read, so an N-site apply stays O(N) in bytes read.
    #[test]
    fn save_backup_writes_exactly_one_verbatim_copy() {
        let dir = TempDir::new().unwrap();
        let paths = paths_under(dir.path());
        std::fs::create_dir_all(&paths.nginx_sites_available).unwrap();
        std::fs::create_dir_all(&paths.caddy_conf_dir).unwrap();
        let site = paths.nginx_site_path("example.com");
        std::fs::write(&site, "site config\n").unwrap();
        std::fs::write(&paths.caddyfile, "caddy config\n").unwrap();

        let snapshot = create_backup(&site).unwrap();
        let dest = save_backup_to_disk(&paths, &snapshot).unwrap();

        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "site config\n");
        let backups: Vec<_> = std::fs::read_dir(&paths.backup_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(backups.len(), 1, "one backup per mutation: {backups:?}");
        assert!(
            backups[0].starts_with("example.com."),
            "named after the mutated file: {backups:?}"
        );
        assert!(
            std::path::Path::new(&backups[0])
                .extension()
                .is_some_and(|e| e == "bak"),
            "got {backups:?}"
        );
    }

    /// Two saves inside the same second must both survive; the count for one
    /// file is capped at [`MAX_RETAINED_PER_FILE`], newest kept.
    #[test]
    fn backups_are_nano_stamped_and_pruned_per_file() {
        let dir = TempDir::new().unwrap();
        let paths = paths_under(dir.path());
        let site = paths.nginx_site_path("example.com");

        for round in 0..(MAX_RETAINED_PER_FILE + 3) {
            std::fs::create_dir_all(&paths.nginx_sites_available).unwrap();
            std::fs::write(&site, format!("round {round}\n")).unwrap();
            let snapshot = create_backup(&site).unwrap();
            save_backup_to_disk(&paths, &snapshot).unwrap();
        }

        let mut backups: Vec<String> = std::fs::read_dir(&paths.backup_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        backups.sort();
        assert_eq!(
            backups.len(),
            MAX_RETAINED_PER_FILE,
            "retained backups capped per file: {backups:?}"
        );
        let stamps: Vec<&String> = backups.iter().filter(|n| !n.starts_with('.')).collect();
        for name in stamps {
            let stem = name.strip_prefix("example.com.").unwrap();
            let stamp = stem.strip_suffix(".bak").unwrap();
            assert!(
                stamp.parse::<u128>().is_ok() && stamp.len() >= 18,
                "nanosecond stamp survives same-second saves: {name}"
            );
        }
    }

    /// Pruning is per original file: another file's backups are untouched.
    #[test]
    fn prune_is_scoped_to_one_file() {
        let dir = TempDir::new().unwrap();
        let paths = paths_under(dir.path());

        for name in ["a.conf", "b.conf"] {
            for round in 0..(MAX_RETAINED_PER_FILE + 2) {
                let file = dir.path().join(name);
                std::fs::write(&file, format!("{name} round {round}\n")).unwrap();
                let snapshot = create_backup(&file).unwrap();
                save_backup_to_disk(&paths, &snapshot).unwrap();
            }
        }

        for name in ["a.conf", "b.conf"] {
            let count = std::fs::read_dir(&paths.backup_dir)
                .unwrap()
                .filter(|e| {
                    e.as_ref()
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with(&format!("{name}."))
                })
                .count();
            assert_eq!(count, MAX_RETAINED_PER_FILE, "{name} backups");
        }
    }
}
