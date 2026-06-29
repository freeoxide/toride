//! Pre-mutation backup of proxy configuration files.
//!
//! Before applying proxy configuration changes, this module snapshots the
//! current configuration so that changes can be rolled back if needed.

use crate::error::Result;
use crate::paths::ProxyPaths;
use std::fmt::Write as _;

/// A snapshot of proxy configuration files before mutation.
#[derive(Debug, Clone)]
pub struct BackupSnapshot {
    /// Timestamp of the backup (seconds since UNIX epoch).
    pub timestamp: String,
    /// Contents of the main nginx.conf (if readable).
    pub nginx_conf: Option<String>,
    /// Contents of nginx site configs (domain, content).
    pub nginx_sites: Vec<(String, String)>,
    /// Contents of the Caddyfile (if readable).
    pub caddyfile: Option<String>,
}

/// Generate a timestamp string using `SystemTime`.
fn make_timestamp() -> String {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", duration.as_secs())
}

/// Create a backup of the current proxy configuration.
///
/// Reads the nginx configuration directory, Caddyfile, and any other
/// managed files. Returns a snapshot that can be used for restoration.
///
/// # Errors
///
/// Returns an error if the backup directory cannot be created.
/// Individual file read failures are captured as `None` in the snapshot.
pub fn create_backup(paths: &ProxyPaths) -> Result<BackupSnapshot> {
    let timestamp = make_timestamp();

    // Read main nginx.conf
    let nginx_conf = std::fs::read_to_string(&paths.nginx_conf).ok();

    // Read all nginx site configs
    let mut nginx_sites = Vec::new();
    if paths.nginx_sites_available.is_dir()
        && let Ok(entries) = std::fs::read_dir(&paths.nginx_sites_available)
    {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let name = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                if let Ok(content) = std::fs::read_to_string(&path) {
                    nginx_sites.push((name, content));
                }
            }
        }
    }

    // Sort sites for deterministic output
    nginx_sites.sort_by(|a, b| a.0.cmp(&b.0));

    // Read Caddyfile
    let caddyfile = std::fs::read_to_string(&paths.caddyfile).ok();

    tracing::info!(
        "backup: created snapshot with {} nginx sites",
        nginx_sites.len()
    );

    Ok(BackupSnapshot {
        timestamp,
        nginx_conf,
        nginx_sites,
        caddyfile,
    })
}

/// Restore proxy configuration from a backup snapshot.
///
/// Writes back the nginx.conf, all site configs, and the Caddyfile.
///
/// # Errors
///
/// Returns an error if any file cannot be written.
pub fn restore_backup(paths: &ProxyPaths, snapshot: &BackupSnapshot) -> Result<()> {
    // Restored files are live, daemon-readable configs — write them 0o644 to
    // match how they are originally written (not the 0o600 atomic_write default).
    // Restore main nginx.conf
    if let Some(content) = &snapshot.nginx_conf {
        toride_fs::atomic_write_with_perms(&paths.nginx_conf, content, 0o644)?;
        tracing::info!("backup: restored {}", paths.nginx_conf.display());
    }

    // Ensure sites-available directory exists
    std::fs::create_dir_all(&paths.nginx_sites_available)?;

    // Restore nginx site configs
    for (name, content) in &snapshot.nginx_sites {
        let path = paths.nginx_sites_available.join(name);
        toride_fs::atomic_write_with_perms(&path, content, 0o644)?;
        tracing::info!("backup: restored {}", path.display());
    }

    // Restore Caddyfile
    if let Some(content) = &snapshot.caddyfile {
        if let Some(parent) = paths.caddyfile.parent() {
            std::fs::create_dir_all(parent)?;
        }
        toride_fs::atomic_write_with_perms(&paths.caddyfile, content, 0o644)?;
        tracing::info!("backup: restored {}", paths.caddyfile.display());
    }

    tracing::info!("backup: restoration complete");
    Ok(())
}

/// Persist a backup snapshot to disk.
///
/// Writes the snapshot as a text file in the backup directory.
///
/// # Errors
///
/// Returns an error if the backup directory cannot be created or the
/// file cannot be written.
pub fn save_backup_to_disk(paths: &ProxyPaths, snapshot: &BackupSnapshot) -> Result<()> {
    std::fs::create_dir_all(&paths.backup_dir)?;

    let filename = format!("proxy-backup-{}.txt", snapshot.timestamp);
    let path = paths.backup_dir.join(&filename);

    let mut content = String::new();
    let _ = writeln!(content, "# Backup created: {}\n", snapshot.timestamp);

    if let Some(conf) = &snapshot.nginx_conf {
        content.push_str("# === nginx.conf ===\n");
        content.push_str(conf);
        content.push_str("\n\n");
    }

    for (name, file_content) in &snapshot.nginx_sites {
        let _ = writeln!(content, "# === site: {name} ===");
        content.push_str(file_content);
        content.push_str("\n\n");
    }

    if let Some(caddyfile_content) = &snapshot.caddyfile {
        content.push_str("# === Caddyfile ===\n");
        content.push_str(caddyfile_content);
        content.push_str("\n\n");
    }

    toride_fs::atomic_write(&path, &content)?;
    tracing::info!("backup: saved to {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_captures_nginx_sites() {
        let dir = assert_fs::TempDir::new().unwrap();
        let root = dir.path();

        // Create test files
        std::fs::create_dir_all(root.join("etc/nginx/sites-available")).unwrap();
        std::fs::create_dir_all(root.join("etc/caddy")).unwrap();
        std::fs::write(
            root.join("etc/nginx/nginx.conf"),
            "worker_processes auto;\n",
        )
        .unwrap();
        std::fs::write(
            root.join("etc/nginx/sites-available/example.com"),
            "server { listen 80; }\n",
        )
        .unwrap();
        std::fs::write(root.join("etc/caddy/Caddyfile"), "localhost { }\n").unwrap();

        let paths = ProxyPaths::with_root(root);
        let snapshot = create_backup(&paths).unwrap();

        assert!(snapshot.nginx_conf.is_some());
        assert_eq!(snapshot.nginx_sites.len(), 1);
        assert_eq!(snapshot.nginx_sites[0].0, "example.com");
        assert!(snapshot.caddyfile.is_some());
    }

    #[test]
    fn restore_writes_files_back() {
        let dir = assert_fs::TempDir::new().unwrap();
        let root = dir.path();

        std::fs::create_dir_all(root.join("etc/nginx/sites-available")).unwrap();
        std::fs::create_dir_all(root.join("etc/caddy")).unwrap();

        let paths = ProxyPaths::with_root(root);
        let snapshot = BackupSnapshot {
            timestamp: "12345".into(),
            nginx_conf: Some("worker_processes auto;\n".into()),
            nginx_sites: vec![("example.com".into(), "server { listen 80; }\n".into())],
            caddyfile: Some("localhost { }\n".into()),
        };

        restore_backup(&paths, &snapshot).unwrap();

        let content = std::fs::read_to_string(root.join("etc/nginx/nginx.conf")).unwrap();
        assert!(content.contains("worker_processes auto"));
        let site =
            std::fs::read_to_string(root.join("etc/nginx/sites-available/example.com")).unwrap();
        assert!(site.contains("listen 80"));
    }
}
