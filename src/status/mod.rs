//! Toride status subsystem.
//!
//! Provides [`TorideStatus`] — a point-in-time snapshot of every monitored
//! subsystem (OS metrics, daemon liveness, SSH health).
//!
//! ```no_run
//! use toride::status::TorideStatus;
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

use std::fmt;

use serde::Serialize;

pub use capabilities::Capabilities;
pub use collector::{Collector, SystemDelta};
pub use daemon::DaemonStatus;
pub use doctor::{CheckStatus, DoctorCheck, DoctorReport};
pub use error::{StatusError, StatusResult};
pub use presets::Preset;
pub use privacy::{PrivacyMode, Redactor};
pub use ssh::SshStatus;
pub use system::SystemStatus;

/// Top-level aggregated status snapshot.
///
/// Collects data from all subsystems in a single [`collect`](Self::collect)
/// call. Each sub-status is independent — a failure in one subsystem does not
/// prevent the others from being collected.
///
/// # Examples
///
/// ```no_run
/// use toride::status::TorideStatus;
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
}

impl TorideStatus {
    /// Collect a point-in-time snapshot of all subsystems.
    ///
    /// Each subsystem is collected independently — if one fails, its fields
    /// will contain `None` values rather than propagating the error.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use toride::status::TorideStatus;
    ///
    /// let status = TorideStatus::collect();
    /// println!("{}", status.system.hostname);
    /// ```
    pub fn collect() -> Self {
        let system = SystemStatus::collect();
        let daemon = DaemonStatus::collect();
        let ssh = SshStatus::collect();
        let capabilities = Capabilities::detect();
        let mut warnings = Vec::new();
        if system.hostname.is_empty() {
            warnings.push(StatusError::Unsupported("hostname unavailable".to_string()));
        }
        if system.memory.total_bytes == 0 {
            warnings.push(StatusError::Unsupported("memory info unavailable".to_string()));
        }
        Self { system, daemon, ssh, capabilities, warnings }
    }
}

impl fmt::Display for TorideStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Toride Status ===")?;
        write!(f, "{}", self.system)?;
        write!(f, "{}", self.daemon)?;
        write!(f, "{}", self.ssh)?;
        if !self.warnings.is_empty() {
            write!(f, "{}", self.capabilities)?;
            writeln!(f, "Warnings:")?;
            for w in &self.warnings {
                writeln!(f, "  \u{26a0} {}", w)?;
            }
        }
        Ok(())
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
        use crate::status::system::{
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
                },
                disk: DiskStatus {
                    name: "Macintosh HD".to_string(),
                    mount_point: "/".to_string(),
                    filesystem: "apfs".to_string(),
                    used_bytes: 500 * 1024 * 1024 * 1024,
                    total_bytes: 1024 * 1024 * 1024 * 1024,
                    percentage: 50.0,
                    is_removable: false,
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
                }),
                disks: vec![],
                network_interfaces: vec![
                    NetworkInterface {
                        name: "en0".to_string(),
                        bytes_received: 60 * 1024 * 1024 * 1024,
                        bytes_transmitted: 30 * 1024 * 1024 * 1024,
                        packets_received: 1000000,
                        packets_transmitted: 500000,
                        errors_received: 0,
                        errors_transmitted: 0,
                    },
                ],
                sensors: vec![
                    SensorStatus {
                        label: "CPU".to_string(),
                        temperature: Some(55.5),
                    },
                ],
                boot_time: Some(1700000000),
                processes: crate::status::system::ProcessSnapshot {
                    processes: vec![],
                    total_count: 0,
                },
                gpu: vec![],
                battery: None,
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
}
