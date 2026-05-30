//! Health checks for the toride status subsystem.
//!
//! [`DoctorReport`] runs a series of checks against system, daemon, and SSH
//! subsystems and reports pass/warn/fail status for each.
//!
//! ```no_run
//! use toride::status::doctor::DoctorReport;
//!
//! let report = DoctorReport::check();
//! for check in &report.checks {
//!     println!("{:?}: {} - {}", check.status, check.name, check.message);
//! }
//! ```

use std::fmt;

use serde::Serialize;
use which::which;

use crate::status::daemon::DaemonStatus;
use crate::status::ssh::SshStatus;
use crate::status::system::SystemStatus;

/// A collection of health checks.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    /// Individual check results.
    pub checks: Vec<DoctorCheck>,
}

/// A single health check result.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorCheck {
    /// Check name (e.g., "system.hostname").
    pub name: String,
    /// Check result status.
    pub status: CheckStatus,
    /// Human-readable message.
    pub message: String,
}

/// Status of a single health check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CheckStatus {
    /// Check passed.
    Pass,
    /// Check produced a warning.
    Warn,
    /// Check failed.
    Fail,
}

impl DoctorReport {
    /// Run all health checks and return a report.
    pub fn check() -> Self {
        let system = SystemStatus::collect();
        let daemon = DaemonStatus::collect();
        let ssh = SshStatus::collect();
        Self::check_with(&system, &daemon, &ssh)
    }

    /// Run health checks against provided status snapshots.
    pub fn check_with(system: &SystemStatus, daemon: &DaemonStatus, ssh: &SshStatus) -> Self {
        let mut checks = Vec::new();
        checks.extend(check_system(system));
        checks.extend(check_daemon(daemon));
        checks.extend(check_ssh(ssh));
        Self { checks }
    }

    /// Returns true if all checks passed (no failures).
    pub fn all_passed(&self) -> bool {
        self.checks.iter().all(|c| c.status != CheckStatus::Fail)
    }

    /// Count checks by status.
    pub fn summary(&self) -> (usize, usize, usize) {
        let mut pass = 0;
        let mut warn = 0;
        let mut fail = 0;
        for c in &self.checks {
            match c.status {
                CheckStatus::Pass => pass += 1,
                CheckStatus::Warn => warn += 1,
                CheckStatus::Fail => fail += 1,
            }
        }
        (pass, warn, fail)
    }
}

impl fmt::Display for DoctorReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Doctor Report ===")?;
        for check in &self.checks {
            let icon = match check.status {
                CheckStatus::Pass => "\u{2713}",
                CheckStatus::Warn => "\u{26A0}",
                CheckStatus::Fail => "\u{2717}",
            };
            writeln!(f, "  {} {}: {}", icon, check.name, check.message)?;
        }
        let (pass, warn, fail) = self.summary();
        writeln!(f, "--- {} passed, {} warnings, {} failures", pass, warn, fail)?;
        Ok(())
    }
}

fn check_system(system: &SystemStatus) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    // Hostname
    checks.push(DoctorCheck {
        name: "system.hostname".to_string(),
        status: if system.hostname.is_empty() {
            CheckStatus::Fail
        } else {
            CheckStatus::Pass
        },
        message: if system.hostname.is_empty() {
            "hostname is empty".to_string()
        } else {
            format!("hostname: {}", system.hostname)
        },
    });
    // CPU
    checks.push(DoctorCheck {
        name: "system.cpu".to_string(),
        status: if system.cpu_usage.is_some() {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        message: match system.cpu_usage {
            Some(u) => format!("CPU usage: {:.1}%", u),
            None => "CPU usage unavailable".to_string(),
        },
    });
    // Memory
    checks.push(DoctorCheck {
        name: "system.memory".to_string(),
        status: if system.memory.total_bytes > 0 {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        },
        message: format!(
            "memory: {} used / {} total",
            system.memory.used_bytes, system.memory.total_bytes
        ),
    });
    // Disks
    checks.push(DoctorCheck {
        name: "system.disks".to_string(),
        status: if system.disks.is_empty() {
            CheckStatus::Warn
        } else {
            CheckStatus::Pass
        },
        message: format!("{} disk(s) found", system.disks.len()),
    });
    // OS info
    checks.push(DoctorCheck {
        name: "system.os_info".to_string(),
        status: if system.os_info.name.is_some() {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        message: match &system.os_info.name {
            Some(n) => format!(
                "OS: {} {}",
                n,
                system.os_info.version.as_deref().unwrap_or("unknown")
            ),
            None => "OS info unavailable".to_string(),
        },
    });
    checks
}

fn check_daemon(daemon: &DaemonStatus) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    checks.push(DoctorCheck {
        name: "daemon.alive".to_string(),
        status: if daemon.alive {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        message: if daemon.alive {
            format!("daemon alive (PID {:?})", daemon.pid)
        } else {
            "daemon not running".to_string()
        },
    });
    checks.push(DoctorCheck {
        name: "daemon.socket".to_string(),
        status: if daemon.stale_socket {
            CheckStatus::Fail
        } else {
            CheckStatus::Pass
        },
        message: if daemon.stale_socket {
            "stale socket detected".to_string()
        } else {
            "socket ok".to_string()
        },
    });
    checks
}

fn check_ssh(ssh: &SshStatus) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    // ssh binary
    let ssh_available = which("ssh").is_ok();
    checks.push(DoctorCheck {
        name: "ssh.binary".to_string(),
        status: if ssh_available {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        },
        message: if ssh_available {
            "ssh found".to_string()
        } else {
            "ssh not on PATH".to_string()
        },
    });
    // ssh-add binary
    let ssh_add_available = which("ssh-add").is_ok();
    checks.push(DoctorCheck {
        name: "ssh.agent_binary".to_string(),
        status: if ssh_add_available {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        message: if ssh_add_available {
            "ssh-add found".to_string()
        } else {
            "ssh-add not on PATH".to_string()
        },
    });
    // config
    checks.push(DoctorCheck {
        name: "ssh.config".to_string(),
        status: if ssh.config_valid {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        message: if ssh.config_valid {
            "config valid".to_string()
        } else {
            "config invalid or missing".to_string()
        },
    });
    // agent
    checks.push(DoctorCheck {
        name: "ssh.agent".to_string(),
        status: if ssh.agent_running {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        message: if ssh.agent_running {
            format!("agent running ({} key(s))", ssh.key_count)
        } else {
            "agent not running".to_string()
        },
    });
    checks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_returns_non_empty_report() {
        let report = DoctorReport::check();
        assert!(!report.checks.is_empty(), "report should have checks");
    }

    #[test]
    fn all_passed_reflects_check_statuses() {
        let report = DoctorReport::check();
        let has_failure = report.checks.iter().any(|c| c.status == CheckStatus::Fail);
        assert_eq!(report.all_passed(), !has_failure);
    }

    #[test]
    fn summary_counts_match() {
        let report = DoctorReport::check();
        let (pass, warn, fail) = report.summary();
        assert_eq!(pass + warn + fail, report.checks.len());
    }

    #[test]
    fn display_contains_header() {
        let report = DoctorReport::check();
        let output = format!("{}", report);
        assert!(output.contains("Doctor Report"));
    }

    #[test]
    fn check_with_custom_statuses() {
        use crate::status::system::{DiskStatus, MemoryStatus, NetworkStatus, OsInfo};
        let system = SystemStatus {
            cpu_usage: Some(50.0),
            memory: MemoryStatus {
                used_bytes: 100,
                total_bytes: 200,
                percentage: 50.0,
            },
            disk: DiskStatus {
                name: "test".to_string(),
                mount_point: "/".to_string(),
                filesystem: "ext4".to_string(),
                used_bytes: 100,
                total_bytes: 200,
                percentage: 50.0,
                is_removable: false,
            },
            network: NetworkStatus {
                bytes_received: 0,
                bytes_transmitted: 0,
            },
            load_average: None,
            uptime_secs: Some(100),
            hostname: "test-host".to_string(),
            os_info: OsInfo {
                name: Some("TestOS".to_string()),
                version: Some("1.0".to_string()),
                kernel_version: None,
                arch: "x86_64".to_string(),
            },
            cpu_cores: vec![],
            physical_cores: Some(4),
            swap: None,
            disks: vec![],
            network_interfaces: vec![],
            sensors: vec![],
            boot_time: None,
            processes: crate::status::system::ProcessSnapshot {
                processes: vec![],
                total_count: 0,
            },
            gpu: vec![],
            battery: None,
        };
        let daemon = DaemonStatus {
            alive: true,
            pid: Some(123),
            uptime_secs: Some(100),
            restart_count: 0,
            stale_socket: false,
        };
        let ssh = SshStatus {
            mux_master_alive: false,
            control_path_valid: false,
            config_valid: true,
            agent_running: false,
            key_count: 0,
        };
        let report = DoctorReport::check_with(&system, &daemon, &ssh);
        assert!(report.all_passed());
    }

    #[test]
    fn serialize_to_json_succeeds() {
        let report = DoctorReport::check();
        let json = serde_json::to_string(&report);
        assert!(
            json.is_ok(),
            "serialization should succeed: {:?}",
            json.err()
        );
    }

    #[test]
    fn snapshot_doctor_report_display() {
        use crate::status::system::{DiskStatus, MemoryStatus, NetworkStatus, OsInfo};
        let system = SystemStatus {
            cpu_usage: Some(42.5),
            memory: MemoryStatus {
                used_bytes: 8_000_000_000,
                total_bytes: 16_000_000_000,
                percentage: 50.0,
            },
            disk: DiskStatus {
                name: "Macintosh HD".to_string(),
                mount_point: "/".to_string(),
                filesystem: "apfs".to_string(),
                used_bytes: 500_000_000_000,
                total_bytes: 1_000_000_000_000,
                percentage: 50.0,
                is_removable: false,
            },
            network: NetworkStatus {
                bytes_received: 100_000_000_000,
                bytes_transmitted: 50_000_000_000,
            },
            load_average: Some(crate::status::system::LoadAverage {
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
            cpu_cores: vec![],
            physical_cores: Some(8),
            swap: None,
            disks: vec![],
            network_interfaces: vec![],
            sensors: vec![],
            boot_time: Some(1700000000),
            processes: crate::status::system::ProcessSnapshot {
                processes: vec![],
                total_count: 0,
            },
            gpu: vec![],
            battery: None,
        };
        let daemon = DaemonStatus {
            alive: true,
            pid: Some(54321),
            uptime_secs: Some(86400),
            restart_count: 0,
            stale_socket: false,
        };
        let ssh = SshStatus {
            mux_master_alive: true,
            control_path_valid: true,
            config_valid: true,
            agent_running: true,
            key_count: 3,
        };
        let report = DoctorReport::check_with(&system, &daemon, &ssh);
        insta::assert_snapshot!("doctor_report_display", format!("{}", report));
    }
}
