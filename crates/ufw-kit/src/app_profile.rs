//! Application profile management.
//!
//! Handles writing, updating, and removing UFW application profiles
//! in `/etc/ufw/applications.d/`.

use std::fs::File;
use std::path::Path;

use fs2::FileExt;

use crate::backup;
use crate::error::{Error, Result};
use crate::paths::UfwPaths;
use crate::spec::AppProfileSpec;

/// Acquire an exclusive lock on a lock file derived from `path`.
///
/// The lock file uses a `.lock` extension alongside the target file so the
/// actual app profile file is never corrupted by lock metadata.
/// Returns the locked file handle — the lock is held until it is dropped.
fn acquire_lock(path: &Path) -> Result<File> {
    let lock_path = path.with_extension("lock");
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = File::create(&lock_path)?;
    file.lock_exclusive()
        .map_err(|e| Error::Io(format!("failed to acquire lock on {}: {e}", lock_path.display())))?;
    Ok(file)
}

/// Ensure an application profile exists and is up to date.
///
/// If the file exists with different content, it is updated.
/// If `backup_dir` is provided, a backup is created before any write.
pub fn ensure_app_profile(
    paths: &UfwPaths,
    spec: &AppProfileSpec,
    namespace: &str,
    backup_dir: Option<&Path>,
) -> Result<bool> {
    spec.validate()?;

    let path = paths.app_profile_path(namespace, &spec.name);
    let new_content = spec.render();

    let _lock = acquire_lock(&path)?;

    // Check if already exists with same content
    if path.exists() {
        let existing = std::fs::read_to_string(&path)
            .map_err(|e| Error::AppProfileWriteFailed(format!("read existing: {e}")))?;
        if existing == new_content {
            return Ok(false); // Already up to date
        }
    }

    // Backup before write if requested
    if let Some(dir) = backup_dir {
        let bundle = backup::create_backup(paths)
            .map_err(|e| Error::BackupFailed(format!("pre-write backup: {e}")))?;
        backup::write_backup(&bundle, dir)
            .map_err(|e| Error::BackupFailed(format!("write backup: {e}")))?;
    }

    // Ensure directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::AppProfileWriteFailed(format!("create dir: {e}")))?;
    }

    // Atomic write
    atomic_write(&path, &new_content)?;

    Ok(true)
}

/// Remove an application profile.
pub fn remove_app_profile(
    paths: &UfwPaths,
    name: &str,
    namespace: &str,
) -> Result<bool> {
    let path = paths.app_profile_path(namespace, name);

    if !path.exists() {
        return Ok(false);
    }

    // Check that it's a managed file
    let content = std::fs::read_to_string(&path)
        .map_err(|e| Error::AppProfileWriteFailed(format!("read for removal: {e}")))?;

    if !content.contains("Managed by ufw-kit") {
        return Err(Error::AppProfileWriteFailed(
            "refusing to remove non-managed app profile".into(),
        ));
    }

    std::fs::remove_file(&path)
        .map_err(|e| Error::AppProfileWriteFailed(format!("remove: {e}")))?;

    Ok(true)
}

/// Render an app profile to string without writing.
#[must_use]
pub fn render_profile(spec: &AppProfileSpec) -> String {
    spec.render()
}

/// Parse an app profile from INI content.
pub fn parse_profile(name: &str, content: &str) -> Result<AppProfileSpec> {
    let mut title = String::new();
    let mut description = String::new();
    let mut ports_str = String::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip comments and section headers
        if trimmed.starts_with('#') || trimmed.starts_with('[') || trimmed.is_empty() {
            continue;
        }

        if let Some(val) = trimmed.strip_prefix("title=") {
            title = val.trim().to_string();
        } else if let Some(val) = trimmed.strip_prefix("description=") {
            description = val.trim().to_string();
        } else if let Some(val) = trimmed.strip_prefix("ports=") {
            ports_str = val.trim().to_string();
        }
    }

    let ports = parse_ports(&ports_str)?;

    Ok(AppProfileSpec {
        name: name.to_string(),
        title,
        description,
        ports,
    })
}

fn parse_ports(s: &str) -> Result<Vec<crate::spec::AppPort>> {
    let mut ports = Vec::new();

    for part in s.split('|') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        // Format: "80/tcp" or "8000:9000/tcp" or "3000,3001,3002/tcp"
        let (port_str, proto) = if let Some(idx) = part.rfind('/') {
            (&part[..idx], &part[idx + 1..])
        } else {
            return Err(Error::Validation(format!(
                "app port must have protocol: {part}"
            )));
        };

        ports.push(crate::spec::AppPort {
            port: port_str.to_string(),
            protocol: proto.to_string(),
        });
    }

    Ok(ports)
}

/// Atomic write using a temporary file.
fn atomic_write(path: &Path, content: &str) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| Error::AppProfileWriteFailed("no parent directory".into()))?;

    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .map_err(|e| Error::AppProfileWriteFailed(format!("create temp: {e}")))?;

    std::io::Write::write_all(&mut tmp, content.as_bytes())
        .map_err(|e| Error::AppProfileWriteFailed(format!("write temp: {e}")))?;

    tmp.persist(path)
        .map_err(|e| Error::AppProfileWriteFailed(format!("persist: {e}")))?;

    Ok(())
}

#[cfg(test)]
#[path = "app_profile.test.rs"]
mod tests;
