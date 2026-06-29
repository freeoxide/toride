//! sysctl.d drop-in file parsing and writing.
//!
//! Manages individual `/etc/sysctl.d/<name>.conf` drop-in files for
//! persistent sysctl configuration.

use crate::error::{Error, Result};
use crate::parse::parse_sysctl_conf;
use crate::paths::HardenPaths;
use crate::render::render_sysctl_d_dropin;
use crate::spec::SysctlParam;

/// Read a sysctl.d drop-in file and parse its contents.
///
/// # Errors
///
/// Returns [`Error::ConfigParse`] if the file cannot be read.
pub fn read_dropin(paths: &HardenPaths, name: &str) -> Result<Vec<SysctlParam>> {
    let path = paths
        .dropin_path(name)
        .ok_or_else(|| Error::ConfigParse(format!("invalid drop-in name: {name}")))?;

    let content = std::fs::read_to_string(&path)
        .map_err(|e| Error::ConfigParse(format!("cannot read {}: {e}", path.display())))?;

    Ok(parse_sysctl_conf(&content))
}

/// Write a sysctl.d drop-in file with the given parameters.
///
/// Creates the parent directory if it does not exist.
///
/// # Errors
///
/// Returns [`Error::ConfigWrite`] if the file cannot be written.
pub fn write_dropin(paths: &HardenPaths, name: &str, params: &[SysctlParam]) -> Result<()> {
    let path = paths
        .dropin_path(name)
        .ok_or_else(|| Error::ConfigWrite(format!("invalid drop-in name: {name}")))?;

    // Ensure directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::ConfigWrite(format!("cannot create {}: {e}", parent.display())))?;
    }

    let content = render_sysctl_d_dropin(name, params);
    toride_fs::atomic_write_with_perms(&path, &content, 0o644)
        .map_err(|e| Error::ConfigWrite(format!("cannot write {}: {e}", path.display())))?;

    tracing::info!("config: wrote drop-in {}", path.display());
    Ok(())
}

/// List all sysctl.d drop-in files.
///
/// Returns a sorted list of drop-in names (without the `.conf` suffix).
///
/// # Errors
///
/// Returns [`Error::ConfigParse`] if the directory cannot be read.
pub fn list_dropins(paths: &HardenPaths) -> Result<Vec<String>> {
    let mut names = Vec::new();

    if !paths.sysctl_d.is_dir() {
        return Ok(names);
    }

    let entries = std::fs::read_dir(&paths.sysctl_d).map_err(|e| {
        Error::ConfigParse(format!("cannot read {}: {e}", paths.sysctl_d.display()))
    })?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "conf") {
            if let Some(stem) = path.file_stem() {
                names.push(stem.to_string_lossy().to_string());
            }
        }
    }

    names.sort();
    Ok(names)
}

/// Read all drop-in files and merge their parameters.
///
/// Later drop-ins (alphabetically) override earlier ones for duplicate keys.
///
/// # Errors
///
/// Returns an error if any drop-in file cannot be read.
pub fn read_all_dropins(paths: &HardenPaths) -> Result<Vec<SysctlParam>> {
    let names = list_dropins(paths)?;
    let mut merged: Vec<SysctlParam> = Vec::new();
    let mut seen_keys = std::collections::HashSet::new();

    // Process in reverse alphabetical order so that later files win
    for name in names.into_iter().rev() {
        let params = read_dropin(paths, &name)?;
        for param in params {
            if seen_keys.insert(param.key.clone()) {
                merged.push(param);
            }
        }
    }

    merged.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn write_and_read_dropin() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = HardenPaths::with_root(dir.path());

        let params = vec![
            SysctlParam::new("kernel.kptr_restrict", "1", "Restrict kptr"),
            SysctlParam::new("kernel.aslr", "2", "ASLR"),
        ];

        write_dropin(&paths, "99-hardening", &params).unwrap();
        let read_params = read_dropin(&paths, "99-hardening").unwrap();

        assert_eq!(read_params.len(), 2);
        assert_eq!(read_params[0].key, "kernel.kptr_restrict");
    }

    #[test]
    fn list_dropins_returns_sorted_names() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = HardenPaths::with_root(dir.path());

        std::fs::create_dir_all(&paths.sysctl_d).unwrap();
        std::fs::write(paths.sysctl_d.join("20-first.conf"), "a = 1\n").unwrap();
        std::fs::write(paths.sysctl_d.join("99-last.conf"), "b = 2\n").unwrap();

        let names = list_dropins(&paths).unwrap();
        assert_eq!(names, vec!["20-first", "99-last"]);
    }

    #[test]
    fn read_dropin_rejects_traversal() {
        let paths = HardenPaths::default();
        assert!(read_dropin(&paths, "../evil").is_err());
    }
}
