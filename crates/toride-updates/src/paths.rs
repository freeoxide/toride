//! Resolved filesystem paths for automatic update configuration files.
//!
//! [`UpdatePaths`] centralizes all paths that the updates subsystem reads from
//! or writes to, including APT's `50unattended-upgrades`, `20auto-upgrades`,
//! DNF's `automatic.conf`, and their parent directories.

use std::path::PathBuf;

use crate::detect::{PackageManager, detect_package_manager};

// ---------------------------------------------------------------------------
// UpdatePaths
// ---------------------------------------------------------------------------

/// Resolved paths to automatic update configuration files on the host.
///
/// On Debian/Ubuntu systems, paths point into `/etc/apt/apt.conf.d/`.
/// On Fedora/RHEL systems, paths point to `/etc/dnf/automatic.conf` and
/// related systemd timer units.
///
/// Use [`UpdatePaths::detect`] to auto-select paths based on the detected
/// package manager, or [`UpdatePaths::new`] for a sensible default.
#[derive(Debug, Clone)]
pub struct UpdatePaths {
    /// Path to `50unattended-upgrades` (Debian/Ubuntu).
    pub auto_upgrades_conf: PathBuf,
    /// Path to `/etc/apt/apt.conf.d/` directory.
    pub apt_conf_d: PathBuf,
    /// Path to `/etc/apt/apt.conf.d/20auto-upgrades`.
    pub auto_upgrades_enabled: PathBuf,
    /// Path to `/etc/dnf/automatic.conf` (Fedora/RHEL).
    pub dnf_automatic_conf: PathBuf,
    /// Path to `/etc/dnf/` directory.
    pub dnf_conf_d: PathBuf,
    /// Path to the parent directory under which per-unit systemd timer
    /// drop-in directories (`<unit>.d/`) are created.
    ///
    /// Defaults to `/etc/systemd/system`. The concrete drop-in path for a
    /// given unit is `<systemd_timer_d>/<unit>.d/toride.conf`.
    pub systemd_timer_d: PathBuf,
    /// Path to the log file for update operations.
    pub log_file: PathBuf,
    /// The package manager these paths are tailored to.
    pub package_manager: PackageManager,
}

impl UpdatePaths {
    /// Create an `UpdatePaths` with default Linux VPS paths.
    ///
    /// This sets up paths for both APT and DNF backends. The caller should
    /// use [`detect`](Self::detect) to auto-select the correct backend paths.
    #[must_use]
    pub fn new() -> Self {
        Self {
            auto_upgrades_conf: PathBuf::from("/etc/apt/apt.conf.d/50unattended-upgrades"),
            apt_conf_d: PathBuf::from("/etc/apt/apt.conf.d"),
            auto_upgrades_enabled: PathBuf::from("/etc/apt/apt.conf.d/20auto-upgrades"),
            dnf_automatic_conf: PathBuf::from("/etc/dnf/automatic.conf"),
            dnf_conf_d: PathBuf::from("/etc/dnf"),
            // Parent of per-unit drop-in dirs; the drop-in itself is
            // `<this>/<unit>.d/toride.conf`.
            systemd_timer_d: PathBuf::from("/etc/systemd/system"),
            log_file: PathBuf::from("/var/log/unattended-upgrades/unattended-upgrades.log"),
            package_manager: PackageManager::Unknown,
        }
    }

    /// Detect the active package manager and return paths tailored to it.
    ///
    /// Probes for `apt-get` and `dnf` on `$PATH` and records which backend the
    /// paths are intended for. The returned paths always include both backend
    /// locations (callers read the one matching [`Self::package_manager`]).
    ///
    /// On DNF hosts the canonical unattended-upgrades log path does not apply,
    /// so the log file is repointed at the dnf-automatic journal location
    /// (a sentinel; the status query uses `journalctl` directly).
    #[must_use]
    pub fn detect() -> Self {
        let mut paths = Self::new();
        paths.package_manager = detect_package_manager();
        if paths.package_manager == PackageManager::Dnf {
            // dnf-automatic has no unattended-upgrades log; the status backend
            // consults the journal instead. Keep a dnf-flavoured sentinel so
            // callers can distinguish.
            paths.log_file = PathBuf::from("/var/log/dnf.log");
        }
        paths
    }

    /// Returns `true` if the APT (Debian/Ubuntu) backend paths exist on disk.
    pub fn is_apt_available(&self) -> bool {
        self.apt_conf_d.is_dir()
    }

    /// Returns `true` if the DNF (Fedora/RHEL) backend paths exist on disk.
    pub fn is_dnf_available(&self) -> bool {
        self.dnf_conf_d.is_dir()
    }
}

impl Default for UpdatePaths {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_has_unknown_package_manager() {
        let paths = UpdatePaths::new();
        assert_eq!(paths.package_manager, PackageManager::Unknown);
    }

    #[test]
    fn detect_records_host_package_manager() {
        let paths = UpdatePaths::detect();
        let detected = detect_package_manager();
        assert_eq!(paths.package_manager, detected);
    }

    #[test]
    fn detect_repoints_log_for_dnf() {
        let paths = UpdatePaths::detect();
        if paths.package_manager == PackageManager::Dnf {
            assert_eq!(paths.log_file, PathBuf::from("/var/log/dnf.log"));
        } else {
            assert_eq!(
                paths.log_file,
                PathBuf::from("/var/log/unattended-upgrades/unattended-upgrades.log")
            );
        }
    }

    #[test]
    fn systemd_timer_d_is_parent_directory() {
        let paths = UpdatePaths::new();
        assert_eq!(paths.systemd_timer_d, PathBuf::from("/etc/systemd/system"));
    }
}
