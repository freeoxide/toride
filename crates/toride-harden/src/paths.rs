//! Filesystem paths for sysctl and hardening configuration.
//!
//! Centralizes all paths that toride-harden manages, with a `with_root` override
//! for testing.

use std::path::{Path, PathBuf};

/// Filesystem paths used by toride-harden.
#[derive(Debug, Clone)]
pub struct HardenPaths {
    /// `/etc/sysctl.d/` — drop-in directory for sysctl configuration.
    pub sysctl_d: PathBuf,
    /// `/etc/sysctl.conf` — main sysctl configuration file.
    pub sysctl_conf: PathBuf,
    /// `/proc/sys/` — runtime kernel parameter tree.
    pub proc_sys: PathBuf,
    /// `/etc/fstab` — filesystem table (for shm mount entries).
    pub fstab: PathBuf,
    /// `/run/sysctl.d/` — runtime sysctl drop-in directory.
    pub run_sysctl_d: PathBuf,
    /// `/usr/lib/sysctl.d/` — vendor-provided sysctl drop-ins.
    pub usr_sysctl_d: PathBuf,
    /// Backup directory for pre-mutation snapshots.
    pub backup_dir: PathBuf,
}

impl Default for HardenPaths {
    fn default() -> Self {
        Self {
            sysctl_d: PathBuf::from("/etc/sysctl.d"),
            sysctl_conf: PathBuf::from("/etc/sysctl.conf"),
            proc_sys: PathBuf::from("/proc/sys"),
            fstab: PathBuf::from("/etc/fstab"),
            run_sysctl_d: PathBuf::from("/run/sysctl.d"),
            usr_sysctl_d: PathBuf::from("/usr/lib/sysctl.d"),
            backup_dir: PathBuf::from("/var/lib/toride/harden/backups"),
        }
    }
}

impl HardenPaths {
    /// Create paths with a custom root (for testing).
    ///
    /// All standard paths are rebased under `root`, e.g.
    /// `root.join("etc/sysctl.conf")`.
    pub fn with_root(root: &Path) -> Self {
        Self {
            sysctl_d: root.join("etc/sysctl.d"),
            sysctl_conf: root.join("etc/sysctl.conf"),
            proc_sys: root.join("proc/sys"),
            fstab: root.join("etc/fstab"),
            run_sysctl_d: root.join("run/sysctl.d"),
            usr_sysctl_d: root.join("usr/lib/sysctl.d"),
            backup_dir: root.join("var/lib/toride/harden/backups"),
        }
    }

    /// Return the sysctl.d drop-in path for a named config.
    ///
    /// The name should not contain path separators or `..`.
    pub fn dropin_path(&self, name: &str) -> Option<PathBuf> {
        if name.contains('/') || name.contains("..") || name.is_empty() {
            return None;
        }
        Some(self.sysctl_d.join(format!("{name}.conf")))
    }

    /// Check if a path is a toride-harden managed path (safe to write).
    pub fn is_managed_path(&self, path: &Path) -> bool {
        let managed = [&self.sysctl_d, &self.sysctl_conf, &self.backup_dir];

        managed
            .iter()
            .any(|m| path == m.as_path() || path.starts_with(m))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_paths_are_absolute() {
        let paths = HardenPaths::default();
        assert!(paths.sysctl_conf.is_absolute());
        assert!(paths.sysctl_d.is_absolute());
        assert!(paths.proc_sys.is_absolute());
    }

    #[test]
    fn with_root_rebases_all_paths() {
        let paths = HardenPaths::with_root(Path::new("/tmp/test-root"));
        assert_eq!(
            paths.sysctl_conf,
            PathBuf::from("/tmp/test-root/etc/sysctl.conf")
        );
        assert_eq!(paths.sysctl_d, PathBuf::from("/tmp/test-root/etc/sysctl.d"));
    }

    #[test]
    fn dropin_path_rejects_traversal() {
        let paths = HardenPaths::default();
        assert!(paths.dropin_path("").is_none());
        assert!(paths.dropin_path("../evil").is_none());
        assert!(paths.dropin_path("sub/file").is_none());
        assert_eq!(
            paths.dropin_path("99-hardening"),
            Some(PathBuf::from("/etc/sysctl.d/99-hardening.conf"))
        );
    }
}
