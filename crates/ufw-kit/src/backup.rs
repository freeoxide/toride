//! Backup and restore for UFW configuration files.

use std::path::Path;

use crate::error::{Error, Result};
use crate::paths::UfwPaths;
use crate::spec::BackupBundle;

/// Create a backup bundle of UFW configuration.
pub fn create_backup(paths: &UfwPaths) -> Result<BackupBundle> {
    let default_ufw = read_optional(&paths.default_ufw)?;
    let ufw_conf = read_optional(&paths.ufw_conf)?;
    let sysctl_conf = read_optional(&paths.sysctl_conf)?;

    let mut app_profiles = Vec::new();
    if paths.app_profiles_dir.exists() {
        for entry in std::fs::read_dir(&paths.app_profiles_dir)
            .map_err(|e| Error::BackupFailed(format!("read applications.d: {e}")))?
        {
            let entry = entry.map_err(|e| Error::BackupFailed(format!("read entry: {e}")))?;
            let path = entry.path();
            if path.extension().is_some() || path.is_file() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    let name = path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned();
                    app_profiles.push((name, content));
                }
            }
        }
    }

    let mut framework_files = Vec::new();
    for (name, path) in [
        ("before.rules", &paths.before_rules),
        ("after.rules", &paths.after_rules),
        ("before6.rules", &paths.before6_rules),
        ("after6.rules", &paths.after6_rules),
    ] {
        if let Some(content) = read_optional(path)? {
            framework_files.push((name.to_string(), content));
        }
    }

    Ok(BackupBundle {
        timestamp: chrono_timestamp(),
        default_ufw,
        ufw_conf,
        sysctl_conf,
        app_profiles,
        framework_files,
    })
}

/// Write a backup bundle to a directory.
pub fn write_backup(bundle: &BackupBundle, dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)
        .map_err(|e| Error::BackupFailed(format!("create backup dir: {e}")))?;

    if let Some(content) = &bundle.default_ufw {
        std::fs::write(dir.join("default-ufw"), content)
            .map_err(|e| Error::BackupFailed(format!("write default-ufw: {e}")))?;
    }

    if let Some(content) = &bundle.ufw_conf {
        std::fs::write(dir.join("ufw.conf"), content)
            .map_err(|e| Error::BackupFailed(format!("write ufw.conf: {e}")))?;
    }

    if let Some(content) = &bundle.sysctl_conf {
        std::fs::write(dir.join("sysctl.conf"), content)
            .map_err(|e| Error::BackupFailed(format!("write sysctl.conf: {e}")))?;
    }

    let app_dir = dir.join("applications.d");
    for (name, content) in &bundle.app_profiles {
        std::fs::create_dir_all(&app_dir)
            .map_err(|e| Error::BackupFailed(format!("create applications.d: {e}")))?;
        std::fs::write(app_dir.join(name), content)
            .map_err(|e| Error::BackupFailed(format!("write app profile {name}: {e}")))?;
    }

    let fw_dir = dir.join("framework");
    for (name, content) in &bundle.framework_files {
        std::fs::create_dir_all(&fw_dir)
            .map_err(|e| Error::BackupFailed(format!("create framework dir: {e}")))?;
        std::fs::write(fw_dir.join(name), content)
            .map_err(|e| Error::BackupFailed(format!("write framework {name}: {e}")))?;
    }

    Ok(())
}

/// Restore files from a backup bundle to their original locations.
///
/// This is used for rollback when a file-backed operation fails.
/// Only restores files that have content in the bundle.
pub fn restore_backup(bundle: &BackupBundle, paths: &UfwPaths) -> Result<()> {
    if let Some(content) = &bundle.default_ufw {
        std::fs::write(&paths.default_ufw, content)
            .map_err(|e| Error::RestoreFailed(format!("restore default_ufw: {e}")))?;
    }
    if let Some(content) = &bundle.ufw_conf {
        std::fs::write(&paths.ufw_conf, content)
            .map_err(|e| Error::RestoreFailed(format!("restore ufw.conf: {e}")))?;
    }
    if let Some(content) = &bundle.sysctl_conf {
        std::fs::write(&paths.sysctl_conf, content)
            .map_err(|e| Error::RestoreFailed(format!("restore sysctl.conf: {e}")))?;
    }

    let app_dir = &paths.app_profiles_dir;
    for (name, content) in &bundle.app_profiles {
        std::fs::create_dir_all(app_dir)
            .map_err(|e| Error::RestoreFailed(format!("create applications.d: {e}")))?;
        std::fs::write(app_dir.join(name), content)
            .map_err(|e| Error::RestoreFailed(format!("restore app profile {name}: {e}")))?;
    }

    let framework_files = [
        ("before.rules", &paths.before_rules),
        ("after.rules", &paths.after_rules),
        ("before6.rules", &paths.before6_rules),
        ("after6.rules", &paths.after6_rules),
    ];
    for (name, path) in &framework_files {
        if let Some((_, content)) = bundle.framework_files.iter().find(|(n, _)| n == name) {
            std::fs::write(path, content)
                .map_err(|e| Error::RestoreFailed(format!("restore {name}: {e}")))?;
        }
    }

    Ok(())
}

fn read_optional(path: &Path) -> Result<Option<String>> {
    if path.exists() {
        std::fs::read_to_string(path)
            .map(Some)
            .map_err(|e| Error::BackupFailed(format!("read {}: {e}", path.display())))
    } else {
        Ok(None)
    }
}

fn chrono_timestamp() -> String {
    // Use a simple timestamp without external dependency
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or_else(|_| "unknown".to_string(), |d| d.as_secs().to_string())
}

#[cfg(test)]
#[path = "backup.test.rs"]
mod tests;
