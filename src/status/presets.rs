//! Collection presets for different use cases.
//!
//! Presets control which metrics are collected, allowing callers to
//! optimize for their specific needs (minimal overhead vs full diagnostics).
//!
//! # Preset comparison
//!
//! | Feature            | Minimal | `TaskManager` | Diagnostics | `ServerMonitoring` | `PrivacySafe` |
//! |--------------------|:-------:|:-------------:|:-----------:|:------------------:|:-------------:|
//! | CPU usage          | Yes     | Yes         | Yes         | Yes              | Yes         |
//! | Per-core CPU       | No      | Yes         | Yes         | No               | No          |
//! | Memory             | Yes     | Yes         | Yes         | Yes              | Yes         |
//! | Swap               | No      | No          | Yes         | Yes              | No          |
//! | Disk (root)        | Yes     | Yes         | Yes         | Yes              | No          |
//! | All disks          | No      | Yes         | Yes         | No               | No          |
//! | Network            | Yes     | Yes         | Yes         | Yes              | No          |
//! | Network interfaces | No      | No          | Yes         | Yes              | No          |
//! | Load average       | Yes     | Yes         | Yes         | Yes              | No          |
//! | Uptime             | Yes     | Yes         | Yes         | Yes              | No          |
//! | Hostname           | Yes     | Yes         | Yes         | Yes              | No          |
//! | OS info            | Yes     | Yes         | Yes         | Yes              | Yes         |
//! | Sensors            | No      | Yes         | Yes         | No               | No          |
//! | Processes          | No      | Yes         | Yes         | No               | No          |
//! | GPU                | No      | No          | Yes         | No               | Yes         |
//! | Battery            | No      | No          | Yes         | No               | No          |
//!
//! # Choosing a preset
//!
//! - **Minimal**: Lightweight monitoring with basic resource usage. Best for
//!   dashboards that only need CPU, memory, disk, and network totals.
//! - **Task Manager**: Interactive process monitoring. Includes per-core CPU,
//!   all disks, sensors, and process lists.
//! - **Diagnostics**: Full system report. Includes everything except secrets.
//!   This is the default preset.
//! - **`ServerMonitoring`**: Headless server monitoring. Includes network
//!   interfaces and swap, but omits sensors and processes for lower overhead.
//! - **`PrivacySafeBugReport`**: Redacted data safe for sharing in bug reports.
//!   Only includes OS info, CPU family, memory total, and GPU model.
//!
//! # Examples
//!
//! ```no_run
//! use toride::status::presets::Preset;
//!
//! let preset = Preset::TaskManager;
//! println!("Preset: {preset}");
//!
//! if preset.includes_processes() {
//!     println!("Process monitoring enabled");
//! }
//! ```

use std::fmt;

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
    /// Hardware inventory: static info, sensors, GPU, battery, all disks.
    HardwareInventory,
}

impl Preset {
    /// Whether this preset includes per-core CPU data.
    ///
    /// Returns `true` for `TaskManager` and `Diagnostics` presets.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride::status::presets::Preset;
    ///
    /// assert!(Preset::TaskManager.includes_per_core_cpu());
    /// assert!(!Preset::Minimal.includes_per_core_cpu());
    /// ```
    #[must_use]
    pub const fn includes_per_core_cpu(self) -> bool {
        matches!(self, Self::TaskManager | Self::Diagnostics | Self::HardwareInventory)
    }

    /// Whether this preset includes swap data.
    ///
    /// Returns `true` for `Diagnostics` and `ServerMonitoring` presets.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride::status::presets::Preset;
    ///
    /// assert!(Preset::Diagnostics.includes_swap());
    /// assert!(!Preset::Minimal.includes_swap());
    /// ```
    #[must_use]
    pub const fn includes_swap(self) -> bool {
        matches!(self, Self::Diagnostics | Self::ServerMonitoring)
    }

    /// Whether this preset includes sensor data.
    ///
    /// Returns `true` for `TaskManager` and `Diagnostics` presets.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride::status::presets::Preset;
    ///
    /// assert!(Preset::Diagnostics.includes_sensors());
    /// assert!(!Preset::ServerMonitoring.includes_sensors());
    /// ```
    #[must_use]
    pub const fn includes_sensors(self) -> bool {
        matches!(self, Self::TaskManager | Self::Diagnostics | Self::HardwareInventory)
    }

    /// Whether this preset includes process data.
    ///
    /// Returns `true` for `TaskManager` and `Diagnostics` presets.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride::status::presets::Preset;
    ///
    /// assert!(Preset::TaskManager.includes_processes());
    /// assert!(!Preset::Minimal.includes_processes());
    /// ```
    #[must_use]
    pub const fn includes_processes(self) -> bool {
        matches!(self, Self::TaskManager | Self::Diagnostics)
    }

    /// Whether this preset includes network interface details.
    ///
    /// Returns `true` for `Diagnostics` and `ServerMonitoring` presets.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride::status::presets::Preset;
    ///
    /// assert!(Preset::ServerMonitoring.includes_network_interfaces());
    /// assert!(!Preset::Minimal.includes_network_interfaces());
    /// ```
    #[must_use]
    pub const fn includes_network_interfaces(self) -> bool {
        matches!(self, Self::Diagnostics | Self::ServerMonitoring)
    }

    /// Whether this preset includes all disk partitions.
    ///
    /// Returns `true` for `Diagnostics` and `TaskManager` presets.
    /// When `false`, only the root disk is included.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride::status::presets::Preset;
    ///
    /// assert!(Preset::Diagnostics.includes_all_disks());
    /// assert!(!Preset::ServerMonitoring.includes_all_disks());
    /// ```
    #[must_use]
    pub const fn includes_all_disks(self) -> bool {
        matches!(self, Self::Diagnostics | Self::TaskManager | Self::HardwareInventory)
    }

    /// Whether this preset includes GPU information.
    ///
    /// Returns `true` for `Diagnostics` and `PrivacySafeBugReport` presets.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride::status::presets::Preset;
    ///
    /// assert!(Preset::Diagnostics.includes_gpu());
    /// assert!(!Preset::Minimal.includes_gpu());
    /// ```
    #[must_use]
    pub const fn includes_gpu(self) -> bool {
        matches!(self, Self::Diagnostics | Self::PrivacySafeBugReport | Self::HardwareInventory)
    }

    /// Whether this preset includes battery status.
    ///
    /// Returns `true` for `Diagnostics` only.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride::status::presets::Preset;
    ///
    /// assert!(Preset::Diagnostics.includes_battery());
    /// assert!(!Preset::Minimal.includes_battery());
    /// ```
    #[must_use]
    pub const fn includes_battery(self) -> bool {
        matches!(self, Self::Diagnostics | Self::HardwareInventory)
    }

    /// Whether this preset includes OS info.
    ///
    /// Always returns `true` — OS information is useful in every context.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride::status::presets::Preset;
    ///
    /// assert!(Preset::Minimal.includes_os_info());
    /// assert!(Preset::Diagnostics.includes_os_info());
    /// ```
    #[must_use]
    pub const fn includes_os_info(self) -> bool {
        true // always useful
    }

    /// Whether this preset includes hardware inventory info.
    ///
    /// Returns `true` for `Diagnostics` and `HardwareInventory` presets.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride::status::presets::Preset;
    ///
    /// assert!(Preset::Diagnostics.includes_hardware_inventory());
    /// assert!(!Preset::Minimal.includes_hardware_inventory());
    /// ```
    #[must_use]
    pub const fn includes_hardware_inventory(self) -> bool {
        matches!(self, Self::Diagnostics | Self::HardwareInventory)
    }

    /// Whether this preset includes virtualization info.
    ///
    /// Returns `true` for `Diagnostics` and `ServerMonitoring` presets.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride::status::presets::Preset;
    ///
    /// assert!(Preset::Diagnostics.includes_virtualization());
    /// assert!(!Preset::Minimal.includes_virtualization());
    /// ```
    #[must_use]
    pub const fn includes_virtualization(self) -> bool {
        matches!(self, Self::Diagnostics | Self::ServerMonitoring)
    }

    /// Whether this preset includes disk I/O info.
    ///
    /// Returns `true` for `Diagnostics`, `ServerMonitoring`, and `TaskManager` presets.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride::status::presets::Preset;
    ///
    /// assert!(Preset::Diagnostics.includes_disk_io());
    /// assert!(!Preset::Minimal.includes_disk_io());
    /// ```
    #[must_use]
    pub const fn includes_disk_io(self) -> bool {
        matches!(
            self,
            Self::Diagnostics | Self::ServerMonitoring | Self::TaskManager
        )
    }

    /// Whether this preset includes static info.
    ///
    /// Returns `true` for `Diagnostics`, `HardwareInventory`, and `PrivacySafeBugReport` presets.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride::status::presets::Preset;
    ///
    /// assert!(Preset::Diagnostics.includes_static_info());
    /// assert!(!Preset::Minimal.includes_static_info());
    /// ```
    #[must_use]
    pub const fn includes_static_info(self) -> bool {
        matches!(
            self,
            Self::Diagnostics | Self::HardwareInventory | Self::PrivacySafeBugReport
        )
    }

    /// Whether this preset includes network addresses.
    ///
    /// Returns `true` for `Diagnostics` only.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride::status::presets::Preset;
    ///
    /// assert!(Preset::Diagnostics.includes_network_addresses());
    /// assert!(!Preset::Minimal.includes_network_addresses());
    /// ```
    #[must_use]
    pub const fn includes_network_addresses(self) -> bool {
        matches!(self, Self::Diagnostics)
    }

    /// Whether this preset includes per-process disk I/O.
    ///
    /// Returns `true` for `Diagnostics` and `TaskManager` presets.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride::status::presets::Preset;
    ///
    /// assert!(Preset::Diagnostics.includes_process_disk_io());
    /// assert!(!Preset::Minimal.includes_process_disk_io());
    /// ```
    #[must_use]
    pub const fn includes_process_disk_io(self) -> bool {
        matches!(self, Self::Diagnostics | Self::TaskManager)
    }

    /// The human-readable name of this preset.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride::status::presets::Preset;
    ///
    /// assert_eq!(Preset::Minimal.name(), "Minimal");
    /// assert_eq!(Preset::Diagnostics.name(), "Diagnostics");
    /// assert_eq!(Preset::ServerMonitoring.name(), "Server Monitoring");
    /// ```
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Minimal => "Minimal",
            Self::TaskManager => "Task Manager",
            Self::Diagnostics => "Diagnostics",
            Self::ServerMonitoring => "Server Monitoring",
            Self::PrivacySafeBugReport => "Privacy-Safe Bug Report",
            Self::HardwareInventory => "Hardware Inventory",
        }
    }
}

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
        assert!(p.includes_hardware_inventory());
        assert!(p.includes_virtualization());
        assert!(p.includes_disk_io());
        assert!(p.includes_static_info());
        assert!(p.includes_network_addresses());
        assert!(p.includes_process_disk_io());
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

    // --- Comprehensive preset coverage ---

    #[test]
    fn minimal_includes_per_core_cpu() {
        assert!(!Preset::Minimal.includes_per_core_cpu());
    }

    #[test]
    fn minimal_includes_swap() {
        assert!(!Preset::Minimal.includes_swap());
    }

    #[test]
    fn minimal_includes_sensors() {
        assert!(!Preset::Minimal.includes_sensors());
    }

    #[test]
    fn minimal_includes_processes() {
        assert!(!Preset::Minimal.includes_processes());
    }

    #[test]
    fn minimal_includes_network_interfaces() {
        assert!(!Preset::Minimal.includes_network_interfaces());
    }

    #[test]
    fn minimal_includes_all_disks() {
        assert!(!Preset::Minimal.includes_all_disks());
    }

    #[test]
    fn minimal_includes_os_info() {
        assert!(Preset::Minimal.includes_os_info());
    }

    #[test]
    fn task_manager_includes_per_core_cpu() {
        assert!(Preset::TaskManager.includes_per_core_cpu());
    }

    #[test]
    fn task_manager_includes_swap() {
        assert!(!Preset::TaskManager.includes_swap());
    }

    #[test]
    fn task_manager_includes_sensors() {
        assert!(Preset::TaskManager.includes_sensors());
    }

    #[test]
    fn task_manager_includes_network_interfaces() {
        assert!(!Preset::TaskManager.includes_network_interfaces());
    }

    #[test]
    fn task_manager_includes_all_disks() {
        assert!(Preset::TaskManager.includes_all_disks());
    }

    #[test]
    fn task_manager_includes_os_info() {
        assert!(Preset::TaskManager.includes_os_info());
    }

    #[test]
    fn diagnostics_includes_per_core_cpu() {
        assert!(Preset::Diagnostics.includes_per_core_cpu());
    }

    #[test]
    fn diagnostics_includes_swap() {
        assert!(Preset::Diagnostics.includes_swap());
    }

    #[test]
    fn diagnostics_includes_sensors() {
        assert!(Preset::Diagnostics.includes_sensors());
    }

    #[test]
    fn diagnostics_includes_network_interfaces() {
        assert!(Preset::Diagnostics.includes_network_interfaces());
    }

    #[test]
    fn diagnostics_includes_all_disks() {
        assert!(Preset::Diagnostics.includes_all_disks());
    }

    #[test]
    fn diagnostics_includes_os_info() {
        assert!(Preset::Diagnostics.includes_os_info());
    }

    #[test]
    fn server_monitoring_includes_per_core_cpu() {
        assert!(!Preset::ServerMonitoring.includes_per_core_cpu());
    }

    #[test]
    fn server_monitoring_includes_swap() {
        assert!(Preset::ServerMonitoring.includes_swap());
    }

    #[test]
    fn server_monitoring_includes_sensors() {
        assert!(!Preset::ServerMonitoring.includes_sensors());
    }

    #[test]
    fn server_monitoring_includes_processes() {
        assert!(!Preset::ServerMonitoring.includes_processes());
    }

    #[test]
    fn server_monitoring_includes_network_interfaces() {
        assert!(Preset::ServerMonitoring.includes_network_interfaces());
    }

    #[test]
    fn server_monitoring_includes_all_disks() {
        assert!(!Preset::ServerMonitoring.includes_all_disks());
    }

    #[test]
    fn server_monitoring_includes_os_info() {
        assert!(Preset::ServerMonitoring.includes_os_info());
    }

    #[test]
    fn privacy_safe_bug_report_includes_per_core_cpu() {
        assert!(!Preset::PrivacySafeBugReport.includes_per_core_cpu());
    }

    #[test]
    fn privacy_safe_bug_report_includes_swap() {
        assert!(!Preset::PrivacySafeBugReport.includes_swap());
    }

    #[test]
    fn privacy_safe_bug_report_includes_sensors() {
        assert!(!Preset::PrivacySafeBugReport.includes_sensors());
    }

    #[test]
    fn privacy_safe_bug_report_includes_processes() {
        assert!(!Preset::PrivacySafeBugReport.includes_processes());
    }

    #[test]
    fn privacy_safe_bug_report_includes_network_interfaces() {
        assert!(!Preset::PrivacySafeBugReport.includes_network_interfaces());
    }

    #[test]
    fn privacy_safe_bug_report_includes_all_disks() {
        assert!(!Preset::PrivacySafeBugReport.includes_all_disks());
    }

    #[test]
    fn privacy_safe_bug_report_includes_os_info() {
        assert!(Preset::PrivacySafeBugReport.includes_os_info());
    }

    // --- HardwareInventory (existing methods) ---

    #[test]
    fn hardware_inventory_includes_per_core_cpu() {
        assert!(Preset::HardwareInventory.includes_per_core_cpu());
    }

    #[test]
    fn hardware_inventory_excludes_swap() {
        assert!(!Preset::HardwareInventory.includes_swap());
    }

    #[test]
    fn hardware_inventory_includes_sensors() {
        assert!(Preset::HardwareInventory.includes_sensors());
    }

    #[test]
    fn hardware_inventory_excludes_processes() {
        assert!(!Preset::HardwareInventory.includes_processes());
    }

    #[test]
    fn hardware_inventory_excludes_network_interfaces() {
        assert!(!Preset::HardwareInventory.includes_network_interfaces());
    }

    #[test]
    fn hardware_inventory_includes_all_disks() {
        assert!(Preset::HardwareInventory.includes_all_disks());
    }

    #[test]
    fn hardware_inventory_includes_os_info() {
        assert!(Preset::HardwareInventory.includes_os_info());
    }

    // --- GPU ---

    #[test]
    fn minimal_excludes_gpu() {
        assert!(!Preset::Minimal.includes_gpu());
    }

    #[test]
    fn task_manager_excludes_gpu() {
        assert!(!Preset::TaskManager.includes_gpu());
    }

    #[test]
    fn diagnostics_includes_gpu() {
        assert!(Preset::Diagnostics.includes_gpu());
    }

    #[test]
    fn server_monitoring_excludes_gpu() {
        assert!(!Preset::ServerMonitoring.includes_gpu());
    }

    #[test]
    fn privacy_safe_includes_gpu() {
        assert!(Preset::PrivacySafeBugReport.includes_gpu());
    }

    #[test]
    fn hardware_inventory_includes_gpu() {
        assert!(Preset::HardwareInventory.includes_gpu());
    }

    // --- Battery ---

    #[test]
    fn minimal_excludes_battery() {
        assert!(!Preset::Minimal.includes_battery());
    }

    #[test]
    fn task_manager_excludes_battery() {
        assert!(!Preset::TaskManager.includes_battery());
    }

    #[test]
    fn diagnostics_includes_battery() {
        assert!(Preset::Diagnostics.includes_battery());
    }

    #[test]
    fn server_monitoring_excludes_battery() {
        assert!(!Preset::ServerMonitoring.includes_battery());
    }

    #[test]
    fn privacy_safe_excludes_battery() {
        assert!(!Preset::PrivacySafeBugReport.includes_battery());
    }

    #[test]
    fn hardware_inventory_includes_battery() {
        assert!(Preset::HardwareInventory.includes_battery());
    }

    // --- Preset name edge cases ---

    #[test]
    fn all_presets_have_unique_names() {
        let presets = [
            Preset::Minimal,
            Preset::TaskManager,
            Preset::Diagnostics,
            Preset::ServerMonitoring,
            Preset::PrivacySafeBugReport,
            Preset::HardwareInventory,
        ];
        let names: Vec<&str> = presets.iter().map(|p| p.name()).collect();
        let unique: std::collections::HashSet<&str> = names.iter().copied().collect();
        assert_eq!(names.len(), unique.len(), "preset names must be unique");
    }

    #[test]
    fn all_presets_have_non_empty_names() {
        let presets = [
            Preset::Minimal,
            Preset::TaskManager,
            Preset::Diagnostics,
            Preset::ServerMonitoring,
            Preset::PrivacySafeBugReport,
            Preset::HardwareInventory,
        ];
        for preset in presets {
            assert!(
                !preset.name().is_empty(),
                "{preset:?} has an empty name"
            );
        }
    }

    // --- Display edge cases ---

    #[test]
    fn all_presets_display_correctly() {
        let cases = [
            (Preset::Minimal, "Minimal"),
            (Preset::TaskManager, "Task Manager"),
            (Preset::Diagnostics, "Diagnostics"),
            (Preset::ServerMonitoring, "Server Monitoring"),
            (Preset::PrivacySafeBugReport, "Privacy-Safe Bug Report"),
            (Preset::HardwareInventory, "Hardware Inventory"),
        ];
        for (preset, expected) in cases {
            assert_eq!(format!("{preset}"), expected);
        }
    }

    // --- Hardware Inventory ---

    #[test]
    fn minimal_excludes_hardware_inventory() {
        assert!(!Preset::Minimal.includes_hardware_inventory());
    }

    #[test]
    fn task_manager_excludes_hardware_inventory() {
        assert!(!Preset::TaskManager.includes_hardware_inventory());
    }

    #[test]
    fn diagnostics_includes_hardware_inventory() {
        assert!(Preset::Diagnostics.includes_hardware_inventory());
    }

    #[test]
    fn server_monitoring_excludes_hardware_inventory() {
        assert!(!Preset::ServerMonitoring.includes_hardware_inventory());
    }

    #[test]
    fn privacy_safe_excludes_hardware_inventory() {
        assert!(!Preset::PrivacySafeBugReport.includes_hardware_inventory());
    }

    #[test]
    fn hardware_inventory_includes_hardware_inventory() {
        assert!(Preset::HardwareInventory.includes_hardware_inventory());
    }

    // --- Virtualization ---

    #[test]
    fn minimal_excludes_virtualization() {
        assert!(!Preset::Minimal.includes_virtualization());
    }

    #[test]
    fn task_manager_excludes_virtualization() {
        assert!(!Preset::TaskManager.includes_virtualization());
    }

    #[test]
    fn diagnostics_includes_virtualization() {
        assert!(Preset::Diagnostics.includes_virtualization());
    }

    #[test]
    fn server_monitoring_includes_virtualization() {
        assert!(Preset::ServerMonitoring.includes_virtualization());
    }

    #[test]
    fn privacy_safe_excludes_virtualization() {
        assert!(!Preset::PrivacySafeBugReport.includes_virtualization());
    }

    #[test]
    fn hardware_inventory_excludes_virtualization() {
        assert!(!Preset::HardwareInventory.includes_virtualization());
    }

    // --- Disk I/O ---

    #[test]
    fn minimal_excludes_disk_io() {
        assert!(!Preset::Minimal.includes_disk_io());
    }

    #[test]
    fn task_manager_includes_disk_io() {
        assert!(Preset::TaskManager.includes_disk_io());
    }

    #[test]
    fn diagnostics_includes_disk_io() {
        assert!(Preset::Diagnostics.includes_disk_io());
    }

    #[test]
    fn server_monitoring_includes_disk_io() {
        assert!(Preset::ServerMonitoring.includes_disk_io());
    }

    #[test]
    fn privacy_safe_excludes_disk_io() {
        assert!(!Preset::PrivacySafeBugReport.includes_disk_io());
    }

    #[test]
    fn hardware_inventory_excludes_disk_io() {
        assert!(!Preset::HardwareInventory.includes_disk_io());
    }

    // --- Static Info ---

    #[test]
    fn minimal_excludes_static_info() {
        assert!(!Preset::Minimal.includes_static_info());
    }

    #[test]
    fn task_manager_excludes_static_info() {
        assert!(!Preset::TaskManager.includes_static_info());
    }

    #[test]
    fn diagnostics_includes_static_info() {
        assert!(Preset::Diagnostics.includes_static_info());
    }

    #[test]
    fn server_monitoring_excludes_static_info() {
        assert!(!Preset::ServerMonitoring.includes_static_info());
    }

    #[test]
    fn privacy_safe_includes_static_info() {
        assert!(Preset::PrivacySafeBugReport.includes_static_info());
    }

    #[test]
    fn hardware_inventory_includes_static_info() {
        assert!(Preset::HardwareInventory.includes_static_info());
    }

    // --- Network Addresses ---

    #[test]
    fn minimal_excludes_network_addresses() {
        assert!(!Preset::Minimal.includes_network_addresses());
    }

    #[test]
    fn task_manager_excludes_network_addresses() {
        assert!(!Preset::TaskManager.includes_network_addresses());
    }

    #[test]
    fn diagnostics_includes_network_addresses() {
        assert!(Preset::Diagnostics.includes_network_addresses());
    }

    #[test]
    fn server_monitoring_excludes_network_addresses() {
        assert!(!Preset::ServerMonitoring.includes_network_addresses());
    }

    #[test]
    fn privacy_safe_excludes_network_addresses() {
        assert!(!Preset::PrivacySafeBugReport.includes_network_addresses());
    }

    #[test]
    fn hardware_inventory_excludes_network_addresses() {
        assert!(!Preset::HardwareInventory.includes_network_addresses());
    }

    // --- Per-process Disk I/O ---

    #[test]
    fn minimal_excludes_process_disk_io() {
        assert!(!Preset::Minimal.includes_process_disk_io());
    }

    #[test]
    fn task_manager_includes_process_disk_io() {
        assert!(Preset::TaskManager.includes_process_disk_io());
    }

    #[test]
    fn diagnostics_includes_process_disk_io() {
        assert!(Preset::Diagnostics.includes_process_disk_io());
    }

    #[test]
    fn server_monitoring_excludes_process_disk_io() {
        assert!(!Preset::ServerMonitoring.includes_process_disk_io());
    }

    #[test]
    fn privacy_safe_excludes_process_disk_io() {
        assert!(!Preset::PrivacySafeBugReport.includes_process_disk_io());
    }

    #[test]
    fn hardware_inventory_excludes_process_disk_io() {
        assert!(!Preset::HardwareInventory.includes_process_disk_io());
    }
}
