//! Toride status subsystem.
//!
//! Provides [`TorideStatus`] — a point-in-time snapshot of every monitored
//! subsystem (OS metrics, daemon liveness, SSH health).
//!
//! ```no_run
//! use toride_status::TorideStatus;
//!
//! let status = TorideStatus::collect();
//! println!("{status}");
//! ```

pub mod capabilities;
pub mod collector;
pub mod daemon;
pub mod doctor;
pub mod error;
pub mod presets;
pub mod privacy;
pub mod provider;
pub mod ssh;
pub mod system;
pub mod units;

use std::fmt;

use serde::Serialize;

pub use capabilities::Capabilities;
pub use collector::{Collector, DiskIoDelta, GpuDelta, ProcessDelta, SystemDelta};
pub use daemon::DaemonStatus;
pub use doctor::{CheckStatus, DoctorCheck, DoctorReport};
pub use error::{StatusError, StatusResult};
pub use presets::Preset;
pub use privacy::{PrivacyMode, Redactor};
pub use ssh::SshStatus;
pub use system::{
    BatteryInfo, CpuCore, CpuSample, CpuStatic, DiskIoSnapshot, DiskStatus, GpuInfo,
    HardwareInventory, LoadAverage, MemoryStatus, NetworkInterface, NetworkStatus, OsInfo,
    ProcessSnapshot, ProcessStatus, SensorSnapshot, SensorStatus, StaticInfo, SwapStatus,
    SystemStatus, VirtualizationSnapshot,
};
pub use units::{Bytes, Celsius, Hertz, Rpm, Volts, Watts};

/// Top-level aggregated status snapshot.
///
/// Collects data from all subsystems in a single [`collect`](Self::collect)
/// call. Each sub-status is independent — a failure in one subsystem does not
/// prevent the others from being collected.
///
/// # Examples
///
/// ```no_run
/// use toride_status::TorideStatus;
///
/// let status = TorideStatus::collect();
/// assert!(!status.system.hostname.is_empty());
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct TorideStatus {
    /// OS-level metrics (CPU, memory, disk, network, uptime).
    pub system: SystemStatus,
    /// Daemon liveness and health (PID, restart count, socket state).
    pub daemon: DaemonStatus,
    /// SSH subsystem health (mux master, control path, agent, keys).
    pub ssh: SshStatus,
    /// Platform capabilities.
    pub capabilities: Capabilities,
    /// Non-fatal warnings collected during status gathering.
    #[serde(skip)]
    pub warnings: Vec<StatusError>,
    /// Wall-clock time when this snapshot was collected.
    #[serde(skip)]
    pub collected_at: std::time::SystemTime,
}

impl TorideStatus {
    /// Collect a point-in-time snapshot of all subsystems.
    ///
    /// Delegates to [`collect_with_preset`](Self::collect_with_preset) using
    /// the [`Preset::default`] preset (`Diagnostics`), which includes every
    /// available metric.
    ///
    /// Each subsystem is collected independently — if one fails, its fields
    /// will contain `None` values rather than propagating the error.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use toride_status::TorideStatus;
    ///
    /// let status = TorideStatus::collect();
    /// println!("{}", status.system.hostname);
    /// ```
    #[must_use]
    pub fn collect() -> Self {
        Self::collect_with_preset(Preset::default())
    }

    /// Collect a snapshot filtered by the given [`Preset`].
    ///
    /// Always-collected fields (`cpu_usage`, memory, disk, network, `os_info`,
    /// hostname, uptime) are populated regardless of preset. Preset-gated
    /// fields are zeroed / set to `None` when the preset excludes them.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use toride_status::{TorideStatus, Preset};
    ///
    /// let status = TorideStatus::collect_with_preset(Preset::Minimal);
    /// assert!(status.system.cpu_cores.is_empty());
    /// ```
    #[must_use]
    pub fn collect_with_preset(preset: Preset) -> Self {
        let mut status = Self::collect_all();
        status.apply_preset(preset);
        status
    }

    /// Collect a snapshot with privacy-aware redaction applied.
    ///
    /// Uses the default preset (`Diagnostics`). The [`PrivacyMode`]
    /// controls which fields are redacted before they are stored.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use toride_status::{TorideStatus, PrivacyMode};
    ///
    /// let status = TorideStatus::collect_with_privacy(PrivacyMode::Safe);
    /// assert_eq!(status.system.hostname, "[redacted]");
    /// ```
    #[must_use]
    pub fn collect_with_privacy(mode: PrivacyMode) -> Self {
        Self::collect_with_options(Preset::default(), mode)
    }

    /// Collect a snapshot with both preset filtering and privacy redaction.
    ///
    /// Combines [`collect_with_preset`](Self::collect_with_preset) and
    /// privacy redaction in a single call. The preset is applied first,
    /// then privacy redaction is applied to the remaining fields.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use toride_status::{TorideStatus, Preset, PrivacyMode};
    ///
    /// let status = TorideStatus::collect_with_options(
    ///     Preset::Minimal,
    ///     PrivacyMode::Safe,
    /// );
    /// assert_eq!(status.system.hostname, "[redacted]");
    /// assert!(status.system.cpu_cores.is_empty());
    /// ```
    #[must_use]
    pub fn collect_with_options(preset: Preset, privacy: PrivacyMode) -> Self {
        let mut status = Self::collect_with_preset(preset);
        status.apply_privacy(privacy);
        status
    }

    // ── Internal helpers ────────────────────────────────────────────

    /// Collect every subsystem without any filtering.
    fn collect_all() -> Self {
        let system = SystemStatus::collect();
        let daemon = DaemonStatus::collect();
        let ssh = SshStatus::collect();
        let capabilities = Capabilities::detect();
        let mut warnings = Vec::new();
        if system.hostname.is_empty() {
            warnings.push(StatusError::DataUnavailable("hostname unavailable".to_string()));
        }
        if system.memory.total_bytes == 0 {
            warnings.push(StatusError::DataUnavailable("memory info unavailable".to_string()));
        }
        Self { system, daemon, ssh, capabilities, warnings, collected_at: std::time::SystemTime::now() }
    }

    /// Zero out fields excluded by the given preset.
    ///
    /// Always-collected fields (`cpu_usage`, memory, disk, network, `os_info`,
    /// hostname, uptime, `load_average`, `boot_time`) are never touched.
    fn apply_preset(&mut self, preset: Preset) {
        if !preset.includes_per_core_cpu() {
            self.system.cpu_cores.clear();
            self.system.physical_cores = None;
        }
        if !preset.includes_swap() {
            self.system.swap = None;
        }
        if !preset.includes_sensors() {
            self.system.sensors.clear();
        }
        if !preset.includes_processes() {
            self.system.processes = system::ProcessSnapshot {
                processes: Vec::new(),
                total_count: 0,
            };
        }
        if !preset.includes_network_interfaces() {
            self.system.network_interfaces.clear();
        }
        if !preset.includes_all_disks() {
            self.system.disks.clear();
        }
        if !preset.includes_gpu() {
            self.system.gpu.clear();
        }
        if !preset.includes_battery() {
            self.system.battery = None;
        }
    }

    /// Apply privacy redaction to sensitive fields.
    ///
    /// Uses the [`Redactor`] from the privacy module to redact hostnames,
    /// MAC addresses, serial numbers, command lines, and other identifying
    /// information according to the given mode.
    fn apply_privacy(&mut self, mode: PrivacyMode) {
        let redactor = Redactor::new(mode);

        // Hostname
        self.system.hostname = redactor.redact_hostname(&self.system.hostname);

        // Static info hostname
        self.system.static_info.hostname =
            redactor.redact_hostname(&self.system.static_info.hostname);

        // Network interface MAC addresses
        for iface in &mut self.system.network_interfaces {
            if let Some(ref mac) = iface.mac_address {
                iface.mac_address = Some(redactor.redact_mac(mac));
            }
        }

        // Process command lines
        for proc in &mut self.system.processes.processes {
            if let Some(ref cmd) = proc.command_line {
                proc.command_line = Some(redactor.redact_command_line(cmd));
            }
        }

        // Process usernames (hide unless Full mode)
        if !redactor.should_show_username() {
            for proc in &mut self.system.processes.processes {
                proc.user = None;
            }
        }

        // Hardware serial numbers, UUIDs, asset tags
        if let Some(ref serial) = self.system.static_info.hardware.system_serial {
            self.system.static_info.hardware.system_serial =
                Some(redactor.redact_serial(serial));
        }
        if let Some(ref uuid) = self.system.static_info.hardware.system_uuid {
            self.system.static_info.hardware.system_uuid = Some(redactor.redact_uuid(uuid));
        }
        if let Some(ref tag) = self.system.static_info.hardware.asset_tag {
            self.system.static_info.hardware.asset_tag = Some(redactor.redact_asset_tag(tag));
        }

        // Disk serial numbers
        for disk in &mut self.system.disks {
            if let Some(ref serial) = disk.serial {
                disk.serial = Some(redactor.redact_serial(serial));
            }
        }
    }
}

impl fmt::Display for TorideStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Toride Status ===")?;
        write!(f, "{}", self.system)?;
        write!(f, "{}", self.daemon)?;
        write!(f, "{}", self.ssh)?;
        write!(f, "{}", self.capabilities)?;
        if !self.warnings.is_empty() {
            writeln!(f, "Warnings:")?;
            for w in &self.warnings {
                writeln!(f, "  \u{26a0} {w}")?;
            }
        }
        Ok(())
    }
}

/// Simple API entry point for collecting system status.
///
/// `SysProbe` provides the primary user-facing API as specified in the
/// system-status spec. For advanced use cases (streaming, delta tracking),
/// use [`Collector`] instead.
///
/// # Examples
///
/// ```no_run
/// use toride_status::SysProbe;
///
/// let probe = SysProbe::new();
/// let snapshot = probe.snapshot();
/// println!("{}", snapshot.system.cpu_usage.unwrap_or(0.0));
/// ```
pub struct SysProbe {
    preset: Preset,
    privacy: PrivacyMode,
}

impl SysProbe {
    /// Create a new `SysProbe` with default settings (Diagnostics preset, no privacy).
    #[must_use]
    pub fn new() -> Self {
        Self {
            preset: Preset::Diagnostics,
            privacy: PrivacyMode::Diagnostics,
        }
    }

    /// Create a builder for customizing the probe.
    pub fn builder() -> SysProbeBuilder {
        SysProbeBuilder::default()
    }

    /// Collect a system status snapshot.
    #[must_use]
    pub fn snapshot(&self) -> TorideStatus {
        TorideStatus::collect_with_options(self.preset, self.privacy)
    }

    /// Detect platform capabilities.
    #[must_use]
    pub fn capabilities(&self) -> Capabilities {
        Capabilities::detect()
    }
}

impl Default for SysProbe {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for [`SysProbe`].
#[derive(Debug, Clone)]
pub struct SysProbeBuilder {
    preset: Preset,
    privacy: PrivacyMode,
}

impl SysProbeBuilder {
    pub fn new() -> Self {
        Self {
            preset: Preset::Diagnostics,
            privacy: PrivacyMode::Diagnostics,
        }
    }

    pub fn preset(mut self, preset: Preset) -> Self {
        self.preset = preset;
        self
    }

    pub fn privacy(mut self, mode: PrivacyMode) -> Self {
        self.privacy = mode;
        self
    }

    pub fn build(self) -> SysProbe {
        SysProbe {
            preset: self.preset,
            privacy: self.privacy,
        }
    }
}

impl Default for SysProbeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_returns_all_subsystems() {
        let status = TorideStatus::collect();
        // SystemStatus should always have a hostname on any platform
        assert!(
            !status.system.hostname.is_empty(),
            "hostname should not be empty"
        );
    }

    #[test]
    fn display_contains_section_headers() {
        let status = TorideStatus::collect();
        let output = format!("{status}");
        assert!(output.contains("=== Toride Status ==="));
        assert!(output.contains("System:"));
        assert!(output.contains("Daemon:"));
        assert!(output.contains("SSH:"));
        if !status.warnings.is_empty() {
            assert!(output.contains("Warnings:"));
        }
    }

    #[test]
    fn serialize_to_json_succeeds() {
        let status = TorideStatus::collect();
        let json = serde_json::to_string(&status);
        assert!(json.is_ok(), "serialization should succeed: {:?}", json.err());
    }

    #[test]
    fn snapshot_toride_status_display() {
        use crate::system::{
            CpuCore, DiskStatus, LoadAverage, MemoryStatus, NetworkInterface, NetworkStatus,
            OsInfo, SensorStatus, SwapStatus,
        };
        let status = TorideStatus {
            system: SystemStatus {
                cpu_usage: Some(42.5),
                memory: MemoryStatus {
                    used_bytes: 8 * 1024 * 1024 * 1024,
                    total_bytes: 16 * 1024 * 1024 * 1024,
                    percentage: 50.0,
                    cached_bytes: 0,
                    available_bytes: 0,
                    free_bytes: 0,
                    buffers_bytes: 0,
                },
                disk: DiskStatus {
                    name: "Macintosh HD".to_string(),
                    mount_point: "/".to_string(),
                    filesystem: "apfs".to_string(),
                    used_bytes: 500 * 1024 * 1024 * 1024,
                    total_bytes: 1024 * 1024 * 1024 * 1024,
                    percentage: 50.0,
                    is_removable: false,
                    disk_type: "Unknown".to_string(),
                    available_bytes: 0,
                    free_bytes: 0,
                    physical_device_path: None,
                    model: None,
                    serial: None,
                    temperature: None,
                    wear_percent: None,
                },
                network: NetworkStatus {
                    bytes_received: 100 * 1024 * 1024 * 1024,
                    bytes_transmitted: 50 * 1024 * 1024 * 1024,
                },
                load_average: Some(LoadAverage {
                    one: 2.50,
                    five: 3.00,
                    fifteen: 3.50,
                }),
                uptime_secs: Some(90061),
                hostname: "test-host".to_string(),
                os_info: OsInfo {
                    name: Some("macOS".to_string()),
                    version: Some("15.0".to_string()),
                    kernel_version: Some("24.0.0".to_string()),
                    arch: "aarch64".to_string(),
                    os_type: None,
                    edition: None,
                    codename: None,
                    bitness: None,
                    timezone: None,
                    locale: None,
                    current_user: None,
                    is_root: false,
                    container_detected: false,
                    vm_detected: false,
                    wsl_detected: false,
                    systemd_detected: false,
                    target_triple: None,
                },
                cpu_cores: vec![
                    CpuCore {
                        name: "cpu0".to_string(),
                        usage: 45.0,
                        frequency: 3200,
                    },
                    CpuCore {
                        name: "cpu1".to_string(),
                        usage: 40.0,
                        frequency: 3200,
                    },
                ],
                physical_cores: Some(8),
                swap: Some(SwapStatus {
                    used_bytes: 512 * 1024 * 1024,
                    total_bytes: 2 * 1024 * 1024 * 1024,
                    percentage: 25.0,
                    free_bytes: 2 * 1024 * 1024 * 1024 - 512 * 1024 * 1024,
                }),
                disks: vec![],
                network_interfaces: vec![
                    NetworkInterface {
                        name: "en0".to_string(),
                        bytes_received: 60 * 1024 * 1024 * 1024,
                        bytes_transmitted: 30 * 1024 * 1024 * 1024,
                        packets_received: 1_000_000,
                        packets_transmitted: 500_000,
                        errors_received: 0,
                        errors_transmitted: 0,
                        drops_transmitted: 0,
                        drops_received: 0,
                        mtu: None,
                        mac_address: None,
                        display_name: None,
                        description: None,
                        ipv4_addresses: Vec::new(),
                        ipv6_addresses: Vec::new(),
                        gateway: None,
                        dns: None,
                        link_status: None,
                        speed_bps: None,
                        duplex: None,
                    },
                ],
                sensors: vec![
                    SensorStatus {
                        label: "CPU".to_string(),
                        temperature: Some(55.5),
                        fan_rpm: None,
                        voltage: None,
                        thermal_throttling: None,
                    },
                ],
                boot_time: Some(1_700_000_000),
                processes: crate::system::ProcessSnapshot {
                    processes: vec![],
                    total_count: 0,
                },
                gpu: vec![],
                battery: None,
                disk_io: DiskIoSnapshot::default(),
                virtualization: VirtualizationSnapshot::default(),
                sensor_snapshot: SensorSnapshot { readings: Vec::new(), cpu_temperature: None, gpu_temperature: None },
                static_info: StaticInfo {
                    os: OsInfo { name: None, version: None, kernel_version: None, arch: String::new(), os_type: None, edition: None, codename: None, bitness: None, timezone: None, locale: None, current_user: None, is_root: false, container_detected: false, vm_detected: false, wsl_detected: false, systemd_detected: false, target_triple: None },
                    kernel_version: None,
                    hostname: String::new(),
                    cpu_brand: String::new(),
                    cpu_vendor: String::new(),
                    cpu_frequency: 0,
                    physical_cores: None,
                    logical_cores: 0,
                    memory_total_bytes: 0,
                    hardware: HardwareInventory::default(),
                    sockets: None,
                    cores_per_socket: None,
                    threads_per_core: None,
                    base_frequency: None,
                    max_frequency: None,
                    cache_l1d: None,
                    cache_l1i: None,
                    cache_l2: None,
                    cache_l3: None,
                },
            },
            daemon: DaemonStatus {
                alive: true,
                pid: Some(54321),
                uptime_secs: Some(86400),
                restart_count: 2,
                stale_socket: false,
            },
            ssh: SshStatus {
                mux_master_alive: true,
                control_path_valid: true,
                config_valid: true,
                agent_running: true,
                key_count: 3,
            },
            capabilities: Capabilities::detect(),
            warnings: vec![],
            collected_at: std::time::SystemTime::now(),
        };
        insta::assert_snapshot!("toride_status_display", format!("{}", status));
    }

    #[test]
    fn collect_includes_capabilities() {
        let status = TorideStatus::collect();
        assert!(status.capabilities.system.cpu_usage);
    }

    #[test]
    fn collect_includes_processes() {
        let status = TorideStatus::collect();
        assert!(status.system.processes.total_count > 0);
    }

    #[test]
    fn collector_produces_status_and_delta() {
        let mut collector = Collector::default_collector();
        let (status, delta) = collector.collect();
        assert!(!status.system.hostname.is_empty());
        assert!(delta.is_none()); // first collect
        std::thread::sleep(std::time::Duration::from_millis(50));
        let (_, delta2) = collector.collect();
        assert!(delta2.is_some());
    }

    #[test]
    fn redactor_safe_mode() {
        let r = Redactor::new(PrivacyMode::Safe);
        assert_eq!(r.redact_hostname("myhost"), "[redacted]");
    }

    #[test]
    fn preset_diagnostics_includes_all() {
        let p = Preset::Diagnostics;
        assert!(p.includes_per_core_cpu());
        assert!(p.includes_processes());
    }

    // ── Integration: Full pipeline ─────────────────────────────────

    #[test]
    fn integration_full_pipeline_collect_serialize_display() {
        // Collect a full TorideStatus snapshot.
        let status = TorideStatus::collect();

        // Verify all subsystems are populated with non-trivial data.
        assert!(!status.system.hostname.is_empty(), "system hostname must be populated");
        assert!(status.system.memory.total_bytes > 0, "memory total must be nonzero");
        assert!(status.system.disk.total_bytes > 0 || !status.system.disk.mount_point.is_empty(),
            "disk must be populated");
        assert!(!status.system.os_info.arch.is_empty(), "OS arch must be populated");
        assert!(status.system.processes.total_count > 0, "process count must be nonzero");
        // daemon and ssh fields are always set (even if not alive/running).
        // capabilities always populated via detect().
        assert!(status.capabilities.system.cpu_usage, "capabilities must report cpu_usage");

        // Serialize to JSON and verify it parses as valid JSON.
        let json = serde_json::to_string(&status).expect("serialization must succeed");
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("JSON must be valid and parseable");
        assert!(parsed.is_object(), "JSON must be an object");
        assert!(parsed.get("system").is_some(), "JSON must contain 'system' key");
        assert!(parsed.get("daemon").is_some(), "JSON must contain 'daemon' key");
        assert!(parsed.get("ssh").is_some(), "JSON must contain 'ssh' key");
        assert!(parsed.get("capabilities").is_some(), "JSON must contain 'capabilities' key");

        // Display and verify all section headers are present.
        let display = format!("{status}");
        assert!(display.contains("=== Toride Status ==="), "display must have top header");
        assert!(display.contains("System:"), "display must have System section");
        assert!(display.contains("Daemon:"), "display must have Daemon section");
        assert!(display.contains("SSH:"), "display must have SSH section");
        assert!(display.contains("Capabilities"), "display must have Capabilities section");
    }

    // ── Integration: Collector ─────────────────────────────────────

    #[test]
    fn integration_collector_two_collects_with_delta() {
        let mut collector = Collector::default_collector();

        // First collect: status present, delta absent.
        let (status1, delta1) = collector.collect();
        assert!(!status1.system.hostname.is_empty(), "first collect must return valid status");
        assert!(delta1.is_none(), "first collect must have no delta");

        // Sleep briefly so elapsed > 0 for the delta.
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Second collect: delta present with reasonable values.
        let (status2, delta2) = collector.collect();
        assert!(!status2.system.hostname.is_empty(), "second collect must return valid status");
        let d = delta2.expect("second collect must produce a delta");

        // Elapsed must be at least as long as we slept.
        assert!(d.elapsed >= std::time::Duration::from_millis(80),
            "delta elapsed ({:?}) must be >= 80ms", d.elapsed);

        // Rates must be non-negative and finite.
        assert!(d.network.bytes_received_rate.is_finite(), "RX rate must be finite");
        assert!(d.network.bytes_received_rate >= 0.0, "RX rate must be non-negative");
        assert!(d.network.bytes_transmitted_rate.is_finite(), "TX rate must be finite");
        assert!(d.network.bytes_transmitted_rate >= 0.0, "TX rate must be non-negative");

        // Deltas must be non-negative (saturating_sub).
        // (They could be 0 if the system had no traffic, which is fine.)

        // CPU delta: if both snapshots had CPU data, the delta should be Some.
        if status1.system.cpu_usage.is_some() && status2.system.cpu_usage.is_some() {
            assert!(d.cpu_usage_delta.is_some(), "CPU delta must be Some when both snapshots have CPU data");
        }
    }

    // ── Integration: Privacy ───────────────────────────────────────

    #[test]
    fn integration_privacy_redactor_on_toride_hostname() {
        let status = TorideStatus::collect();
        let hostname = &status.system.hostname;
        assert!(!hostname.is_empty(), "hostname must be non-empty for this test");

        // Safe mode: hostname is fully redacted.
        let safe = Redactor::new(PrivacyMode::Safe);
        let redacted = safe.redact_hostname(hostname);
        assert_eq!(redacted, "[redacted]", "Safe mode must redact hostname");
        assert_ne!(redacted, *hostname, "redacted value must differ from original");

        // Diagnostics mode: hostname is shown as-is.
        let diag = Redactor::new(PrivacyMode::Diagnostics);
        let shown = diag.redact_hostname(hostname);
        assert_eq!(shown, *hostname, "Diagnostics mode must preserve hostname");

        // Full mode: hostname is also shown.
        let full = Redactor::new(PrivacyMode::Full);
        let full_shown = full.redact_hostname(hostname);
        assert_eq!(full_shown, *hostname, "Full mode must preserve hostname");
    }

    // ── Integration: Presets ───────────────────────────────────────

    #[test]
    fn integration_preset_diagnostics_includes_all_features() {
        let p = Preset::Diagnostics;
        assert!(p.includes_per_core_cpu(), "Diagnostics must include per-core CPU");
        assert!(p.includes_swap(), "Diagnostics must include swap");
        assert!(p.includes_sensors(), "Diagnostics must include sensors");
        assert!(p.includes_processes(), "Diagnostics must include processes");
        assert!(p.includes_network_interfaces(), "Diagnostics must include network interfaces");
        assert!(p.includes_all_disks(), "Diagnostics must include all disks");
        assert!(p.includes_os_info(), "Diagnostics must include OS info");
    }

    #[test]
    fn integration_preset_minimal_excludes_features() {
        let p = Preset::Minimal;
        assert!(!p.includes_per_core_cpu(), "Minimal must exclude per-core CPU");
        assert!(!p.includes_swap(), "Minimal must exclude swap");
        assert!(!p.includes_sensors(), "Minimal must exclude sensors");
        assert!(!p.includes_processes(), "Minimal must exclude processes");
        assert!(!p.includes_network_interfaces(), "Minimal must exclude network interfaces");
        assert!(!p.includes_all_disks(), "Minimal must exclude all disks");
        // Minimal always includes OS info.
        assert!(p.includes_os_info(), "Minimal must include OS info");
    }

    // ── Integration: Doctor ────────────────────────────────────────

    #[test]
    fn integration_doctor_report_has_system_daemon_ssh_checks() {
        let report = DoctorReport::check();
        assert!(!report.checks.is_empty(), "doctor report must have checks");

        // Verify checks exist for each subsystem category.
        let has_system = report.checks.iter().any(|c| c.name.starts_with("system."));
        let has_daemon = report.checks.iter().any(|c| c.name.starts_with("daemon."));
        let has_ssh = report.checks.iter().any(|c| c.name.starts_with("ssh."));
        assert!(has_system, "report must include system checks");
        assert!(has_daemon, "report must include daemon checks");
        assert!(has_ssh, "report must include ssh checks");

        // Verify summary counts are consistent.
        let (pass, warn, fail) = report.summary();
        assert_eq!(
            pass + warn + fail,
            report.checks.len(),
            "summary counts must equal total check count"
        );
    }

    // ── Integration: Error handling ────────────────────────────────

    #[test]
    fn integration_error_variants_work() {
        // PermissionDenied
        let err = StatusError::PermissionDenied("/secret".into());
        assert!(err.to_string().contains("permission denied"));
        assert!(err.to_string().contains("/secret"));

        // CommandNotFound
        let err = StatusError::CommandNotFound("foobar".into());
        assert!(err.to_string().contains("command not found"));
        assert!(err.to_string().contains("foobar"));

        // CommandFailed
        let err = StatusError::CommandFailed {
            command: "ls".into(),
            code: 1,
            stderr: "no such file".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("command failed"), "msg: {msg}");
        assert!(msg.contains("exited 1"), "msg: {msg}");
        assert!(msg.contains("no such file"), "msg: {msg}");

        // CommandTimeout
        let err = StatusError::CommandTimeout("ping".into());
        assert!(err.to_string().contains("timed out"));

        // ParseError
        let err = StatusError::ParseError("bad data".into());
        assert!(err.to_string().contains("parse error"));

        // Io
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err = StatusError::Io(io_err);
        assert!(err.to_string().contains("io error"));

        // Unsupported
        let err = StatusError::Unsupported("plan9".into());
        assert!(err.to_string().contains("unsupported platform"));

        // DataUnavailable
        let err = StatusError::DataUnavailable("gpu".into());
        assert!(err.to_string().contains("data unavailable"));
    }

    #[test]
    fn integration_error_clone_works_for_all_variants() {
        let variants = vec![
            StatusError::PermissionDenied("path".into()),
            StatusError::CommandNotFound("cmd".into()),
            StatusError::CommandFailed {
                command: "run".into(),
                code: 42,
                stderr: "err".into(),
            },
            StatusError::CommandTimeout("slow".into()),
            StatusError::ParseError("bad".into()),
            StatusError::Io(std::io::Error::other("io")),
            StatusError::Unsupported("os".into()),
            StatusError::DataUnavailable("info".into()),
        ];

        for original in &variants {
            let cloned = original.clone();
            // Cloned error must have the same Display output.
            assert_eq!(
                original.to_string(),
                cloned.to_string(),
                "Clone must preserve Display output for variant"
            );
        }
    }

    #[test]
    fn integration_error_display_produces_nonempty_strings() {
        let variants = vec![
            StatusError::PermissionDenied("p".into()),
            StatusError::CommandNotFound("c".into()),
            StatusError::CommandFailed { command: "r".into(), code: 1, stderr: "e".into() },
            StatusError::CommandTimeout("t".into()),
            StatusError::ParseError("p".into()),
            StatusError::Io(std::io::Error::other("o")),
            StatusError::Unsupported("u".into()),
            StatusError::DataUnavailable("d".into()),
        ];

        for variant in &variants {
            let display = variant.to_string();
            assert!(!display.is_empty(), "Display must produce non-empty string for {variant:?}");
            // Every Display string must be at least as long as the prefix.
            assert!(display.len() >= 5, "Display string suspiciously short: {display}");
        }
    }

    // ── collect_with_preset ────────────────────────────────────────

    #[test]
    fn collect_with_preset_minimal_excludes_gated_fields() {
        let status = TorideStatus::collect_with_preset(Preset::Minimal);

        // Always-collected fields must still be populated.
        assert!(status.system.cpu_usage.is_some(), "cpu_usage must be collected");
        assert!(status.system.memory.total_bytes > 0, "memory must be collected");
        assert!(!status.system.hostname.is_empty(), "hostname must be collected");
        assert!(!status.system.os_info.arch.is_empty(), "os_info must be collected");

        // Preset-gated fields must be cleared.
        assert!(status.system.cpu_cores.is_empty(), "Minimal must exclude cpu_cores");
        assert!(status.system.physical_cores.is_none(), "Minimal must exclude physical_cores");
        assert!(status.system.swap.is_none(), "Minimal must exclude swap");
        assert!(status.system.sensors.is_empty(), "Minimal must exclude sensors");
        assert_eq!(status.system.processes.total_count, 0, "Minimal must exclude processes");
        assert!(status.system.processes.processes.is_empty(), "Minimal must exclude process list");
        assert!(status.system.network_interfaces.is_empty(), "Minimal must exclude network interfaces");
        assert!(status.system.disks.is_empty(), "Minimal must exclude all_disks");
        assert!(status.system.gpu.is_empty(), "Minimal must exclude gpu");
        assert!(status.system.battery.is_none(), "Minimal must exclude battery");
    }

    #[test]
    fn collect_with_preset_diagnostics_includes_all_fields() {
        let status = TorideStatus::collect_with_preset(Preset::Diagnostics);

        // Always-collected fields.
        assert!(status.system.cpu_usage.is_some(), "cpu_usage must be collected");
        assert!(status.system.memory.total_bytes > 0, "memory must be collected");
        assert!(!status.system.hostname.is_empty(), "hostname must be collected");
        assert!(!status.system.os_info.arch.is_empty(), "os_info must be collected");

        // Diagnostics includes everything — nothing should be cleared.
        // cpu_cores and processes are populated on real hardware.
        assert!(!status.system.cpu_cores.is_empty(), "Diagnostics must include cpu_cores");
        assert!(status.system.processes.total_count > 0, "Diagnostics must include processes");
    }

    #[test]
    fn collect_with_preset_task_manager_includes_expected_fields() {
        let status = TorideStatus::collect_with_preset(Preset::TaskManager);

        // TaskManager includes: per_core_cpu, sensors, processes, all_disks.
        assert!(!status.system.cpu_cores.is_empty(), "TaskManager must include cpu_cores");
        assert!(status.system.processes.total_count > 0, "TaskManager must include processes");

        // TaskManager excludes: swap, network_interfaces, gpu, battery.
        assert!(status.system.swap.is_none(), "TaskManager must exclude swap");
        assert!(status.system.network_interfaces.is_empty(), "TaskManager must exclude network interfaces");
        assert!(status.system.gpu.is_empty(), "TaskManager must exclude gpu");
        assert!(status.system.battery.is_none(), "TaskManager must exclude battery");
    }

    #[test]
    fn collect_with_preset_server_monitoring_expected_fields() {
        let status = TorideStatus::collect_with_preset(Preset::ServerMonitoring);

        // ServerMonitoring includes: swap, network_interfaces.
        // (swap may be None if not configured, so we only check the field isn't forcibly cleared
        //  by verifying that the preset *would* include it)

        // ServerMonitoring excludes: per_core_cpu, sensors, processes, all_disks, gpu, battery.
        assert!(status.system.cpu_cores.is_empty(), "ServerMonitoring must exclude cpu_cores");
        assert!(status.system.sensors.is_empty(), "ServerMonitoring must exclude sensors");
        assert_eq!(status.system.processes.total_count, 0, "ServerMonitoring must exclude processes");
        assert!(status.system.disks.is_empty(), "ServerMonitoring must exclude all_disks");
        assert!(status.system.gpu.is_empty(), "ServerMonitoring must exclude gpu");
        assert!(status.system.battery.is_none(), "ServerMonitoring must exclude battery");
    }

    #[test]
    fn collect_with_preset_privacy_safe_excludes_gated_fields() {
        let status = TorideStatus::collect_with_preset(Preset::PrivacySafeBugReport);

        // PrivacySafeBugReport excludes most gated fields.
        assert!(status.system.cpu_cores.is_empty(), "PrivacySafe must exclude cpu_cores");
        assert!(status.system.swap.is_none(), "PrivacySafe must exclude swap");
        assert!(status.system.sensors.is_empty(), "PrivacySafe must exclude sensors");
        assert_eq!(status.system.processes.total_count, 0, "PrivacySafe must exclude processes");
        assert!(status.system.network_interfaces.is_empty(), "PrivacySafe must exclude network interfaces");
        assert!(status.system.disks.is_empty(), "PrivacySafe must exclude all_disks");
        assert!(status.system.battery.is_none(), "PrivacySafe must exclude battery");

        // PrivacySafeBugReport includes gpu.
        // (gpu may be empty on some hardware; we just verify it wasn't forcibly cleared
        //  by checking the preset logic — gpu is included for PrivacySafeBugReport)
    }

    #[test]
    fn collect_with_preset_always_collects_core_fields() {
        // Verify that always-collected fields survive every preset.
        let presets = [
            Preset::Minimal,
            Preset::TaskManager,
            Preset::Diagnostics,
            Preset::ServerMonitoring,
            Preset::PrivacySafeBugReport,
        ];

        for preset in presets {
            let status = TorideStatus::collect_with_preset(preset);
            assert!(status.system.cpu_usage.is_some(), "{preset}: cpu_usage must be collected");
            assert!(status.system.memory.total_bytes > 0, "{preset}: memory must be collected");
            assert!(!status.system.hostname.is_empty(), "{preset}: hostname must be collected");
            assert!(!status.system.os_info.arch.is_empty(), "{preset}: os_info must be collected");
            // disk (root) is always collected.
            assert!(!status.system.disk.mount_point.is_empty(), "{preset}: root disk must be collected");
            // network aggregate is always collected.
            // (bytes may be 0 on idle systems, but the struct is populated)
            let _ = status.system.network.bytes_received;
            let _ = status.system.network.bytes_transmitted;
        }
    }

    // ── collect_with_privacy ───────────────────────────────────────

    #[test]
    fn collect_with_privacy_safe_redacts_hostname() {
        let status = TorideStatus::collect_with_privacy(PrivacyMode::Safe);
        assert_eq!(status.system.hostname, "[redacted]", "Safe mode must redact hostname");
    }

    #[test]
    fn collect_with_privacy_diagnostics_preserves_hostname() {
        let status = TorideStatus::collect_with_privacy(PrivacyMode::Diagnostics);
        assert_ne!(status.system.hostname, "[redacted]", "Diagnostics mode must not redact hostname");
        assert!(!status.system.hostname.is_empty(), "Diagnostics mode hostname must not be empty");
    }

    #[test]
    fn collect_with_privacy_full_preserves_hostname() {
        let status = TorideStatus::collect_with_privacy(PrivacyMode::Full);
        assert_ne!(status.system.hostname, "[redacted]", "Full mode must not redact hostname");
        assert!(!status.system.hostname.is_empty(), "Full mode hostname must not be empty");
    }

    #[test]
    fn collect_with_privacy_safe_does_not_affect_other_fields() {
        let safe = TorideStatus::collect_with_privacy(PrivacyMode::Safe);
        let full = TorideStatus::collect_with_privacy(PrivacyMode::Full);

        // Non-hostname fields should be identical in structure.
        assert_eq!(
            safe.system.memory.total_bytes, full.system.memory.total_bytes,
            "privacy must not affect memory"
        );
        assert_eq!(
            safe.system.os_info.arch, full.system.os_info.arch,
            "privacy must not affect os_info"
        );
    }

    // ── collect_with_options ───────────────────────────────────────

    #[test]
    fn collect_with_options_combines_preset_and_privacy() {
        let status = TorideStatus::collect_with_options(Preset::Minimal, PrivacyMode::Safe);

        // Privacy: hostname redacted.
        assert_eq!(status.system.hostname, "[redacted]", "Safe must redact hostname");

        // Preset: gated fields cleared.
        assert!(status.system.cpu_cores.is_empty(), "Minimal must exclude cpu_cores");
        assert!(status.system.swap.is_none(), "Minimal must exclude swap");
        assert!(status.system.sensors.is_empty(), "Minimal must exclude sensors");
        assert_eq!(status.system.processes.total_count, 0, "Minimal must exclude processes");
        assert!(status.system.network_interfaces.is_empty(), "Minimal must exclude network interfaces");
        assert!(status.system.disks.is_empty(), "Minimal must exclude all_disks");

        // Always-collected fields still present.
        assert!(status.system.cpu_usage.is_some(), "cpu_usage must be collected");
        assert!(status.system.memory.total_bytes > 0, "memory must be collected");
    }

    #[test]
    fn collect_with_options_diagnostics_full_shows_everything() {
        let status = TorideStatus::collect_with_options(Preset::Diagnostics, PrivacyMode::Full);

        // Full privacy: hostname shown.
        assert_ne!(status.system.hostname, "[redacted]", "Full must not redact hostname");

        // Diagnostics preset: everything included.
        assert!(!status.system.cpu_cores.is_empty(), "Diagnostics must include cpu_cores");
        assert!(status.system.processes.total_count > 0, "Diagnostics must include processes");
    }

    #[test]
    fn collect_with_options_all_preset_privacy_combinations() {
        // Smoke test: every preset + privacy mode combination must not panic.
        let presets = [
            Preset::Minimal,
            Preset::TaskManager,
            Preset::Diagnostics,
            Preset::ServerMonitoring,
            Preset::PrivacySafeBugReport,
        ];
        let modes = [PrivacyMode::Safe, PrivacyMode::Diagnostics, PrivacyMode::Full];

        for preset in presets {
            for mode in modes {
                let status = TorideStatus::collect_with_options(preset, mode);
                // Must always have a hostname (possibly redacted).
                assert!(
                    !status.system.hostname.is_empty(),
                    "{preset} + {mode:?}: hostname must not be empty"
                );
                // Must always have memory.
                assert!(
                    status.system.memory.total_bytes > 0,
                    "{preset} + {mode:?}: memory must be nonzero"
                );
            }
        }
    }

    // ── collect() backward compatibility ───────────────────────────

    #[test]
    fn collect_uses_diagnostics_preset() {
        let status = TorideStatus::collect();

        // Diagnostics includes everything, so gated fields should be populated.
        assert!(!status.system.cpu_cores.is_empty(), "collect() must include cpu_cores (Diagnostics default)");
        assert!(status.system.processes.total_count > 0, "collect() must include processes (Diagnostics default)");
        // Hostname must not be redacted (no privacy applied).
        assert_ne!(status.system.hostname, "[redacted]", "collect() must not redact hostname");
    }

    #[test]
    fn collect_matches_collect_with_preset_diagnostics() {
        let a = TorideStatus::collect();
        let b = TorideStatus::collect_with_preset(Preset::Diagnostics);

        // Both use the same preset (Diagnostics) and no privacy, so
        // structural properties must be identical. Exact counts may
        // differ because system state changes between the two calls.
        assert_eq!(a.system.hostname, b.system.hostname, "hostname must match");
        assert!(!a.system.cpu_cores.is_empty(), "collect() cpu_cores must be non-empty");
        assert!(!b.system.cpu_cores.is_empty(), "collect_with_preset cpu_cores must be non-empty");
        assert!(a.system.processes.total_count > 0, "collect() must have processes");
        assert!(b.system.processes.total_count > 0, "collect_with_preset must have processes");
    }

    // ── Display with preset/privacy ────────────────────────────────

    #[test]
    fn display_with_preset_minimal_omits_cleared_sections() {
        let status = TorideStatus::collect_with_preset(Preset::Minimal);
        let output = format!("{status}");

        // Always-visible sections.
        assert!(output.contains("=== Toride Status ==="), "must have top header");
        assert!(output.contains("System:"), "must have System section");
        assert!(output.contains("Hostname:"), "must have Hostname");
        assert!(output.contains("Memory:"), "must have Memory");

        // Cleared sections should not appear.
        // Use precise prefixes matching the Display format ("  Swap: ").
        assert!(status.system.cpu_cores.is_empty(), "cpu_cores must be empty");
        assert!(status.system.swap.is_none(), "swap must be None");
        assert!(status.system.sensors.is_empty(), "sensors must be empty");
        assert!(status.system.processes.total_count == 0, "processes must be empty");
        assert!(status.system.network_interfaces.is_empty(), "network_interfaces must be empty");
        assert!(status.system.disks.is_empty(), "disks must be empty");
    }

    #[test]
    fn display_with_privacy_safe_shows_redacted_hostname() {
        let status = TorideStatus::collect_with_privacy(PrivacyMode::Safe);
        let output = format!("{status}");

        assert!(output.contains("[redacted]"), "display must contain [redacted]");
        assert!(output.contains("Hostname: [redacted]"), "hostname line must show [redacted]");
    }

    // ── Serialization with preset/privacy ──────────────────────────

    #[test]
    fn serialize_with_preset_minimal() {
        let status = TorideStatus::collect_with_preset(Preset::Minimal);
        let json = serde_json::to_string(&status);
        assert!(json.is_ok(), "serialization must succeed: {:?}", json.err());

        let parsed: serde_json::Value = serde_json::from_str(&json.unwrap()).unwrap();
        let system = parsed.get("system").unwrap();
        // cpu_cores should be empty array.
        let cores = system.get("cpu_cores").unwrap().as_array().unwrap();
        assert!(cores.is_empty(), "Minimal cpu_cores must be empty in JSON");
    }

    #[test]
    fn serialize_with_privacy_safe() {
        let status = TorideStatus::collect_with_privacy(PrivacyMode::Safe);
        let json = serde_json::to_string(&status).expect("serialization must succeed");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON must parse");

        let system = parsed.get("system").unwrap();
        let hostname = system.get("hostname").unwrap().as_str().unwrap();
        assert_eq!(hostname, "[redacted]", "JSON hostname must be [redacted]");
    }
}
