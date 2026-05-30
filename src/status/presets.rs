//! Collection presets for different use cases.
//!
//! Presets control which metrics are collected, allowing callers to
//! optimize for their specific needs (minimal overhead vs full diagnostics).

use serde::Serialize;

/// Collection preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub enum Preset {
    /// Minimal: CPU, memory, disk, network, uptime.
    Minimal,
    /// Task manager: CPU, memory, disks, network, processes, sensors.
    TaskManager,
    /// Full diagnostics: everything except secrets.
    #[default]
    Diagnostics,
    /// Server monitoring: CPU, memory, disk I/O, network I/O, uptime.
    ServerMonitoring,
    /// Privacy-safe bug report: OS, CPU family, memory total, GPU model.
    PrivacySafeBugReport,
}

impl Preset {
    /// Whether this preset includes per-core CPU data.
    pub fn includes_per_core_cpu(self) -> bool {
        matches!(self, Self::TaskManager | Self::Diagnostics)
    }

    /// Whether this preset includes swap data.
    pub fn includes_swap(self) -> bool {
        matches!(self, Self::Diagnostics | Self::ServerMonitoring)
    }

    /// Whether this preset includes sensor data.
    pub fn includes_sensors(self) -> bool {
        matches!(self, Self::TaskManager | Self::Diagnostics)
    }

    /// Whether this preset includes process data.
    pub fn includes_processes(self) -> bool {
        matches!(self, Self::TaskManager | Self::Diagnostics)
    }

    /// Whether this preset includes network interface details.
    pub fn includes_network_interfaces(self) -> bool {
        matches!(self, Self::Diagnostics | Self::ServerMonitoring)
    }

    /// Whether this preset includes all disk partitions.
    pub fn includes_all_disks(self) -> bool {
        matches!(self, Self::Diagnostics | Self::TaskManager)
    }

    /// Whether this preset includes OS info.
    pub fn includes_os_info(self) -> bool {
        true // always useful
    }

    /// The human-readable name of this preset.
    pub fn name(self) -> &'static str {
        match self {
            Self::Minimal => "Minimal",
            Self::TaskManager => "Task Manager",
            Self::Diagnostics => "Diagnostics",
            Self::ServerMonitoring => "Server Monitoring",
            Self::PrivacySafeBugReport => "Privacy-Safe Bug Report",
        }
    }
}

use std::fmt;

impl fmt::Display for Preset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_diagnostics() {
        assert_eq!(Preset::default(), Preset::Diagnostics);
    }

    #[test]
    fn minimal_excludes_per_core_cpu() {
        assert!(!Preset::Minimal.includes_per_core_cpu());
    }

    #[test]
    fn task_manager_includes_processes() {
        assert!(Preset::TaskManager.includes_processes());
    }

    #[test]
    fn diagnostics_includes_everything() {
        let p = Preset::Diagnostics;
        assert!(p.includes_per_core_cpu());
        assert!(p.includes_swap());
        assert!(p.includes_sensors());
        assert!(p.includes_processes());
        assert!(p.includes_network_interfaces());
        assert!(p.includes_all_disks());
        assert!(p.includes_os_info());
    }

    #[test]
    fn preset_names() {
        assert_eq!(Preset::Minimal.name(), "Minimal");
        assert_eq!(Preset::TaskManager.name(), "Task Manager");
    }

    #[test]
    fn preset_display() {
        assert_eq!(format!("{}", Preset::Minimal), "Minimal");
    }

    #[test]
    fn serialize_to_json() {
        assert!(serde_json::to_string(&Preset::Diagnostics).is_ok());
    }
}
