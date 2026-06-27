//! Path resolution for the `toride-monitor` crate.
//!
//! Provides [`MonitorPaths`] which resolves standard system paths used by
//! iptables, conntrack, and related monitoring tools.

use std::path::PathBuf;

/// Resolved paths to system binaries and directories used for outbound
/// traffic monitoring.
///
/// Default construction points at standard Linux system locations. Override
/// individual fields for testing or non-standard installations.
#[derive(Debug, Clone)]
pub struct MonitorPaths {
    /// Path to the `iptables` binary (e.g. `/usr/sbin/iptables`).
    pub iptables: PathBuf,
    /// Path to the `iptables-save` binary (e.g. `/usr/sbin/iptables-save`).
    pub iptables_save: PathBuf,
    /// Path to the `conntrack` binary (e.g. `/usr/sbin/conntrack`).
    pub conntrack: PathBuf,
    /// Path to the `ss` binary (e.g. `/usr/bin/ss`).
    pub ss: PathBuf,
    /// Path to the `journalctl` binary (e.g. `/usr/bin/journalctl`).
    pub journalctl: PathBuf,
    /// Path to the `systemd-cat` binary (e.g. `/usr/bin/systemd-cat`), the
    /// journal *writer* used to submit log entries.
    pub systemd_cat: PathBuf,
}

impl MonitorPaths {
    /// Create a `MonitorPaths` with standard Linux system defaults.
    ///
    /// Does not verify that binaries actually exist on disk.
    #[must_use]
    pub fn default_paths() -> Self {
        Self {
            iptables: PathBuf::from("/usr/sbin/iptables"),
            iptables_save: PathBuf::from("/usr/sbin/iptables-save"),
            conntrack: PathBuf::from("/usr/sbin/conntrack"),
            ss: PathBuf::from("/usr/bin/ss"),
            journalctl: PathBuf::from("/usr/bin/journalctl"),
            systemd_cat: PathBuf::from("/usr/bin/systemd-cat"),
        }
    }

    /// Resolve binary paths by searching `$PATH` via the `which` crate.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::BinaryNotFound`] if any required binary cannot
    /// be located.
    pub fn resolve_from_path() -> crate::Result<Self> {
        Ok(Self {
            iptables: which::which("iptables")
                .map_err(|_| crate::Error::BinaryNotFound("iptables".into()))?,
            iptables_save: which::which("iptables-save")
                .map_err(|_| crate::Error::BinaryNotFound("iptables-save".into()))?,
            conntrack: which::which("conntrack")
                .map_err(|_| crate::Error::BinaryNotFound("conntrack".into()))?,
            ss: which::which("ss")
                .map_err(|_| crate::Error::BinaryNotFound("ss".into()))?,
            journalctl: which::which("journalctl")
                .map_err(|_| crate::Error::BinaryNotFound("journalctl".into()))?,
            systemd_cat: which::which("systemd-cat")
                .map_err(|_| crate::Error::BinaryNotFound("systemd-cat".into()))?,
        })
    }
}

impl Default for MonitorPaths {
    fn default() -> Self {
        Self::default_paths()
    }
}
