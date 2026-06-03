//! Pre-mutation backup of sysctl configuration files.
//!
//! Before applying hardening changes, this module snapshots the current
//! sysctl configuration so that changes can be rolled back if needed.

use crate::error::Result;
use crate::paths::HardenPaths;

/// A snapshot of sysctl configuration files before mutation.
#[derive(Debug, Clone)]
pub struct BackupSnapshot {
    /// Timestamp of the backup (ISO 8601).
    pub timestamp: String,
    /// Contents of `/etc/sysctl.conf` (if readable).
    pub sysctl_conf: Option<String>,
    /// Contents of `/etc/sysctl.d/` drop-in files (name, content).
    pub dropins: Vec<(String, String)>,
}

/// Create a backup of the current sysctl configuration.
///
/// Reads `/etc/sysctl.conf` and all `.conf` files in `/etc/sysctl.d/`.
/// Returns a snapshot that can be used for restoration.
///
/// # Errors
///
/// Returns an error if the backup directory cannot be created.
/// Individual file read failures are captured as `None` in the snapshot.
pub fn create_backup(paths: &HardenPaths) -> Result<BackupSnapshot> {
    let timestamp = chrono_independent_timestamp();

    // Read main sysctl.conf
    let sysctl_conf = std::fs::read_to_string(&paths.sysctl_conf).ok();

    // Read all drop-in files
    let mut dropins = Vec::new();
    if paths.sysctl_d.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&paths.sysctl_d) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "conf") {
                    // Store the name without .conf suffix so dropin_path() works correctly
                    let name = path
                        .file_stem()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        dropins.push((name, content));
                    }
                }
            }
        }
    }

    // Sort drop-ins for deterministic output
    dropins.sort_by(|a, b| a.0.cmp(&b.0));

    tracing::info!(
        "backup: created snapshot with {} drop-in files",
        dropins.len()
    );

    Ok(BackupSnapshot {
        timestamp,
        sysctl_conf,
        dropins,
    })
}

/// Restore sysctl configuration from a backup snapshot.
///
/// Writes back the main sysctl.conf and all drop-in files.
///
/// # Errors
///
/// Returns an error if any file cannot be written.
pub fn restore_backup(paths: &HardenPaths, snapshot: &BackupSnapshot) -> Result<()> {
    // Restore main sysctl.conf
    if let Some(content) = &snapshot.sysctl_conf {
        toride_fs::atomic_write(&paths.sysctl_conf, content)?;
        tracing::info!("backup: restored {}", paths.sysctl_conf.display());
    }

    // Restore drop-in files
    for (name, content) in &snapshot.dropins {
        if let Some(path) = paths.dropin_path(name) {
            toride_fs::atomic_write(&path, content)?;
            tracing::info!("backup: restored {}", path.display());
        }
    }

    tracing::info!("backup: restoration complete");
    Ok(())
}

/// Persist a backup snapshot to disk.
///
/// Writes the snapshot as a JSON file in the backup directory.
///
/// # Errors
///
/// Returns an error if the backup directory cannot be created or the
/// file cannot be written.
pub fn save_backup_to_disk(paths: &HardenPaths, snapshot: &BackupSnapshot) -> Result<()> {
    std::fs::create_dir_all(&paths.backup_dir)?;

    let filename = format!("sysctl-backup-{}.txt", snapshot.timestamp);
    let path = paths.backup_dir.join(&filename);

    let mut content = String::new();
    content.push_str(&format!("# Backup created: {}\n\n", snapshot.timestamp));

    if let Some(conf) = &snapshot.sysctl_conf {
        content.push_str("# === /etc/sysctl.conf ===\n");
        content.push_str(conf);
        content.push_str("\n\n");
    }

    for (name, file_content) in &snapshot.dropins {
        content.push_str(&format!("# === {name} ===\n"));
        content.push_str(file_content);
        content.push_str("\n\n");
    }

    toride_fs::atomic_write(&path, &content)?;
    tracing::info!("backup: saved to {}", path.display());
    Ok(())
}

/// Generate a timestamp string without depending on chrono.
fn chrono_independent_timestamp() -> String {
    // Use a simple counter-based timestamp for now.
    // In production, this would use `SystemTime`.
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn backup_captures_files() {
        let dir = assert_fs::TempDir::new().unwrap();
        let root = dir.path();

        // Create test files
        std::fs::create_dir_all(root.join("etc/sysctl.d")).unwrap();
        std::fs::write(root.join("etc/sysctl.conf"), "kernel.aslr = 2\n").unwrap();
        std::fs::write(
            root.join("etc/sysctl.d/99-test.conf"),
            "kernel.kptr_restrict = 1\n",
        )
        .unwrap();

        let paths = HardenPaths::with_root(root);
        let snapshot = create_backup(&paths).unwrap();

        assert!(snapshot.sysctl_conf.is_some());
        assert_eq!(snapshot.dropins.len(), 1);
        assert_eq!(snapshot.dropins[0].0, "99-test");
    }

    #[test]
    fn restore_writes_files_back() {
        let dir = assert_fs::TempDir::new().unwrap();
        let root = dir.path();

        std::fs::create_dir_all(root.join("etc/sysctl.d")).unwrap();

        let paths = HardenPaths::with_root(root);
        let snapshot = BackupSnapshot {
            timestamp: "12345".into(),
            sysctl_conf: Some("kernel.aslr = 2\n".into()),
            dropins: vec![("99-test".into(), "kernel.kptr_restrict = 1\n".into())],
        };

        restore_backup(&paths, &snapshot).unwrap();

        let content = std::fs::read_to_string(root.join("etc/sysctl.conf")).unwrap();
        assert!(content.contains("kernel.aslr = 2"));
    }
}
