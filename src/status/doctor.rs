//! Health checks for the toride status subsystem.
//!
//! [`DoctorReport`] runs a series of checks against system, daemon, and SSH
//! subsystems and reports pass/warn/fail status for each.
//!
//! # Check categories
//!
//! The doctor report includes checks from three categories:
//!
//! ## System checks
//!
//! | Check              | Pass condition                     | Fail condition        |
//! |--------------------|------------------------------------|-----------------------|
//! | `system.hostname`  | Hostname is non-empty              | Hostname is empty     |
//! | `system.cpu`       | CPU usage is available             | (warn if unavailable) |
//! | `system.memory`    | Total memory > 0                   | Total memory is 0     |
//! | `system.disks`     | At least one disk found            | (warn if none found)  |
//! | `system.os_info`   | OS name is available               | (warn if unavailable) |
//!
//! ## Daemon checks
//!
//! | Check              | Pass condition                     | Fail condition        |
//! |--------------------|------------------------------------|-----------------------|
//! | `daemon.alive`     | Daemon process is alive            | (warn if not running) |
//! | `daemon.socket`    | Socket is connectable              | Stale socket detected |
//!
//! ## SSH checks
//!
//! | Check              | Pass condition                     | Fail condition        |
//! |--------------------|------------------------------------|-----------------------|
//! | `ssh.binary`       | `ssh` found on PATH                | `ssh` not on PATH     |
//! | `ssh.agent_binary` | `ssh-add` found on PATH            | (warn if not found)   |
//! | `ssh.config`       | Config parses without errors       | (warn if invalid)     |
//! | `ssh.agent`        | Agent is running                   | (warn if not running) |
//!
//! # Examples
//!
//! Run all checks and print the report:
//!
//! ```no_run
//! use toride::status::doctor::DoctorReport;
//!
//! let report = DoctorReport::check();
//! println!("{report}");
//!
//! if !report.all_passed() {
//!     let (pass, warn, fail) = report.summary();
//!     eprintln!("Issues found: {warn} warnings, {fail} failures");
//! }
//! ```
//!
//! Run checks against pre-collected snapshots:
//!
//! ```no_run
//! use toride::status::daemon::DaemonStatus;
//! use toride::status::doctor::DoctorReport;
//! use toride::status::ssh::SshStatus;
//! use toride::status::system::SystemStatus;
//!
//! let system = SystemStatus::collect();
//! let daemon = DaemonStatus::collect();
//! let ssh = SshStatus::collect();
//! let report = DoctorReport::check_with(&system, &daemon, &ssh);
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
    ///
    /// Collects fresh snapshots from all subsystems and runs the full
    /// set of health checks. Use [`check_with`](Self::check_with) to
    /// run checks against pre-collected snapshots.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use toride::status::doctor::DoctorReport;
    ///
    /// let report = DoctorReport::check();
    /// for check in &report.checks {
    ///     println!("{:?}: {} - {}", check.status, check.name, check.message);
    /// }
    /// ```
    #[must_use]
    pub fn check() -> Self {
        let system = SystemStatus::collect();
        let daemon = DaemonStatus::collect();
        let ssh = SshStatus::collect();
        Self::check_with(&system, &daemon, &ssh)
    }

    /// Run health checks against provided status snapshots.
    ///
    /// This is the testable entry point — all subsystem data is provided
    /// via parameters rather than collected fresh. Use this for testing
    /// or when you already have snapshots available.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride::status::daemon::DaemonStatus;
    /// use toride::status::doctor::DoctorReport;
    /// use toride::status::ssh::SshStatus;
    /// use toride::status::system::SystemStatus;
    ///
    /// let system = SystemStatus::collect();
    /// let daemon = DaemonStatus::collect();
    /// let ssh = SshStatus::collect();
    /// let report = DoctorReport::check_with(&system, &daemon, &ssh);
    /// assert!(!report.checks.is_empty());
    /// ```
    #[must_use]
    pub fn check_with(system: &SystemStatus, daemon: &DaemonStatus, ssh: &SshStatus) -> Self {
        let mut checks = Vec::new();
        checks.extend(check_system(system));
        checks.extend(check_daemon(*daemon));
        checks.extend(check_ssh(*ssh));
        Self { checks }
    }

    /// Returns `true` if all checks passed (no failures).
    ///
    /// Warnings are not considered failures. Only [`CheckStatus::Fail`]
    /// causes this method to return `false`.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride::status::doctor::DoctorReport;
    ///
    /// let report = DoctorReport::check();
    /// if report.all_passed() {
    ///     println!("All checks passed!");
    /// }
    /// ```
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.checks.iter().all(|c| c.status != CheckStatus::Fail)
    }

    /// Count checks by status.
    ///
    /// Returns a tuple of `(pass_count, warn_count, fail_count)`. The
    /// sum of all three equals the total number of checks.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride::status::doctor::DoctorReport;
    ///
    /// let report = DoctorReport::check();
    /// let (pass, warn, fail) = report.summary();
    /// println!("{pass} passed, {warn} warnings, {fail} failures");
    /// assert_eq!(pass + warn + fail, report.checks.len());
    /// ```
    #[must_use]
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
            writeln!(f, "  {icon} {}: {}", check.name, check.message)?;
        }
        let (pass, warn, fail) = self.summary();
        writeln!(f, "--- {pass} passed, {warn} warnings, {fail} failures")?;
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
        message: system.cpu_usage.map_or_else(
            || "CPU usage unavailable".to_string(),
            |u| format!("CPU usage: {u:.1}%"),
        ),
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
        message: system.os_info.name.as_ref().map_or_else(
            || "OS info unavailable".to_string(),
            |n| format!(
                "OS: {n} {}",
                system.os_info.version.as_deref().unwrap_or("unknown")
            ),
        ),
    });
    checks
}

fn check_daemon(daemon: DaemonStatus) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    checks.push(DoctorCheck {
        name: "daemon.alive".to_string(),
        status: if daemon.alive {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        message: if daemon.alive {
            format!("daemon alive (PID {})", daemon.pid.unwrap_or(0))
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

fn check_ssh(ssh: SshStatus) -> Vec<DoctorCheck> {
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
        let output = format!("{report}");
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
    fn check_system_hostname_empty_fails() {
        use crate::status::system::{DiskStatus, MemoryStatus, NetworkStatus, OsInfo};
        let system = SystemStatus {
            cpu_usage: Some(50.0),
            memory: MemoryStatus { used_bytes: 100, total_bytes: 200, percentage: 50.0 },
            disk: DiskStatus { name: "test".to_string(), mount_point: "/".to_string(), filesystem: "ext4".to_string(), used_bytes: 100, total_bytes: 200, percentage: 50.0, is_removable: false },
            network: NetworkStatus { bytes_received: 0, bytes_transmitted: 0 },
            load_average: None, uptime_secs: Some(100), hostname: String::new(),
            os_info: OsInfo { name: Some("TestOS".to_string()), version: Some("1.0".to_string()), kernel_version: None, arch: "x86_64".to_string() },
            cpu_cores: vec![], physical_cores: Some(4), swap: None, disks: vec![],
            network_interfaces: vec![], sensors: vec![], boot_time: None,
            processes: crate::status::system::ProcessSnapshot { processes: vec![], total_count: 0 },
            gpu: vec![], battery: None,
        };
        let daemon = DaemonStatus { alive: false, pid: None, uptime_secs: None, restart_count: 0, stale_socket: false };
        let ssh = SshStatus { mux_master_alive: false, control_path_valid: false, config_valid: false, agent_running: false, key_count: 0 };
        let report = DoctorReport::check_with(&system, &daemon, &ssh);
        let hostname_check = report.checks.iter().find(|c| c.name == "system.hostname").unwrap();
        assert_eq!(hostname_check.status, crate::status::doctor::CheckStatus::Fail);
    }

    // --- Helpers ---

    fn happy_system() -> SystemStatus {
        use crate::status::system::{DiskStatus, MemoryStatus, NetworkStatus, OsInfo};
        SystemStatus {
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
            disks: vec![DiskStatus {
                name: "test".to_string(),
                mount_point: "/".to_string(),
                filesystem: "ext4".to_string(),
                used_bytes: 100,
                total_bytes: 200,
                percentage: 50.0,
                is_removable: false,
            }],
            network_interfaces: vec![],
            sensors: vec![],
            boot_time: None,
            processes: crate::status::system::ProcessSnapshot {
                processes: vec![],
                total_count: 0,
            },
            gpu: vec![],
            battery: None,
        }
    }

    fn happy_daemon() -> DaemonStatus {
        DaemonStatus {
            alive: true,
            pid: Some(123),
            uptime_secs: Some(100),
            restart_count: 0,
            stale_socket: false,
        }
    }

    fn happy_ssh() -> SshStatus {
        SshStatus {
            mux_master_alive: false,
            control_path_valid: false,
            config_valid: true,
            agent_running: false,
            key_count: 0,
        }
    }

    fn find_check<'a>(report: &'a DoctorReport, name: &str) -> &'a DoctorCheck {
        report
            .checks
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("check '{name}' not found"))
    }

    // --- check_with edge cases ---

    #[test]
    fn check_with_empty_hostname_produces_fail() {
        let mut system = happy_system();
        system.hostname = String::new();
        let report = DoctorReport::check_with(&system, &happy_daemon(), &happy_ssh());
        assert_eq!(find_check(&report, "system.hostname").status, CheckStatus::Fail);
    }

    #[test]
    fn check_with_zero_memory_produces_fail() {
        let mut system = happy_system();
        system.memory = crate::status::system::MemoryStatus {
            used_bytes: 0,
            total_bytes: 0,
            percentage: 0.0,
        };
        let report = DoctorReport::check_with(&system, &happy_daemon(), &happy_ssh());
        assert_eq!(find_check(&report, "system.memory").status, CheckStatus::Fail);
    }

    #[test]
    fn check_with_no_disks_produces_warn() {
        let mut system = happy_system();
        system.disks = vec![];
        let report = DoctorReport::check_with(&system, &happy_daemon(), &happy_ssh());
        assert_eq!(find_check(&report, "system.disks").status, CheckStatus::Warn);
    }

    #[test]
    fn check_with_no_os_info_produces_warn() {
        let mut system = happy_system();
        system.os_info.name = None;
        let report = DoctorReport::check_with(&system, &happy_daemon(), &happy_ssh());
        assert_eq!(find_check(&report, "system.os_info").status, CheckStatus::Warn);
    }

    #[test]
    fn check_with_stale_socket_produces_fail() {
        let mut daemon = happy_daemon();
        daemon.stale_socket = true;
        let report = DoctorReport::check_with(&happy_system(), &daemon, &happy_ssh());
        assert_eq!(find_check(&report, "daemon.socket").status, CheckStatus::Fail);
    }

    #[test]
    fn check_with_no_ssh_binary_produces_fail() {
        // Save and clear PATH so `which("ssh")` cannot find the binary.
        let original_path = std::env::var("PATH").unwrap_or_default();
        // SAFETY: test-only env mutation; single-threaded test runner.
        unsafe { std::env::set_var("PATH", "") };

        let report = DoctorReport::check_with(&happy_system(), &happy_daemon(), &happy_ssh());
        assert_eq!(find_check(&report, "ssh.binary").status, CheckStatus::Fail);

        // Restore PATH.
        // SAFETY: test-only env mutation; single-threaded test runner.
        unsafe { std::env::set_var("PATH", &original_path) };
    }

    // --- all_passed edge cases ---

    #[test]
    fn all_pass_report_returns_true() {
        let report = DoctorReport {
            checks: vec![
                DoctorCheck { name: "a".into(), status: CheckStatus::Pass, message: "ok".into() },
                DoctorCheck { name: "b".into(), status: CheckStatus::Pass, message: "ok".into() },
            ],
        };
        assert!(report.all_passed());
    }

    #[test]
    fn mixed_pass_and_warn_returns_true() {
        let report = DoctorReport {
            checks: vec![
                DoctorCheck { name: "a".into(), status: CheckStatus::Pass, message: "ok".into() },
                DoctorCheck { name: "b".into(), status: CheckStatus::Warn, message: "warn".into() },
            ],
        };
        assert!(report.all_passed());
    }

    #[test]
    fn any_fail_returns_false() {
        let report = DoctorReport {
            checks: vec![
                DoctorCheck { name: "a".into(), status: CheckStatus::Pass, message: "ok".into() },
                DoctorCheck { name: "b".into(), status: CheckStatus::Fail, message: "bad".into() },
                DoctorCheck { name: "c".into(), status: CheckStatus::Warn, message: "warn".into() },
            ],
        };
        assert!(!report.all_passed());
    }

    // --- summary edge cases ---

    #[test]
    fn summary_empty_checks() {
        let report = DoctorReport { checks: vec![] };
        assert_eq!(report.summary(), (0, 0, 0));
    }

    #[test]
    fn summary_all_pass() {
        let report = DoctorReport {
            checks: vec![
                DoctorCheck { name: "a".into(), status: CheckStatus::Pass, message: "ok".into() },
                DoctorCheck { name: "b".into(), status: CheckStatus::Pass, message: "ok".into() },
            ],
        };
        assert_eq!(report.summary(), (2, 0, 0));
    }

    #[test]
    fn summary_all_warn() {
        let report = DoctorReport {
            checks: vec![
                DoctorCheck { name: "a".into(), status: CheckStatus::Warn, message: "w".into() },
                DoctorCheck { name: "b".into(), status: CheckStatus::Warn, message: "w".into() },
            ],
        };
        assert_eq!(report.summary(), (0, 2, 0));
    }

    #[test]
    fn summary_all_fail() {
        let report = DoctorReport {
            checks: vec![
                DoctorCheck { name: "a".into(), status: CheckStatus::Fail, message: "f".into() },
            ],
        };
        assert_eq!(report.summary(), (0, 0, 1));
    }

    #[test]
    fn summary_mixed_statuses() {
        let report = DoctorReport {
            checks: vec![
                DoctorCheck { name: "a".into(), status: CheckStatus::Pass, message: "ok".into() },
                DoctorCheck { name: "b".into(), status: CheckStatus::Warn, message: "w".into() },
                DoctorCheck { name: "c".into(), status: CheckStatus::Fail, message: "f".into() },
                DoctorCheck { name: "d".into(), status: CheckStatus::Pass, message: "ok".into() },
            ],
        };
        assert_eq!(report.summary(), (2, 1, 1));
    }

    // --- Display edge cases ---

    #[test]
    fn display_all_pass() {
        let report = DoctorReport {
            checks: vec![
                DoctorCheck { name: "a".into(), status: CheckStatus::Pass, message: "ok".into() },
                DoctorCheck { name: "b".into(), status: CheckStatus::Pass, message: "fine".into() },
            ],
        };
        let output = format!("{report}");
        assert!(output.contains("Doctor Report"));
        assert!(output.contains("2 passed, 0 warnings, 0 failures"));
    }

    #[test]
    fn display_all_fail() {
        let report = DoctorReport {
            checks: vec![
                DoctorCheck { name: "a".into(), status: CheckStatus::Fail, message: "bad".into() },
            ],
        };
        let output = format!("{report}");
        assert!(output.contains("0 passed, 0 warnings, 1 failures"));
    }

    #[test]
    fn display_mixed_statuses() {
        let report = DoctorReport {
            checks: vec![
                DoctorCheck { name: "a".into(), status: CheckStatus::Pass, message: "ok".into() },
                DoctorCheck { name: "b".into(), status: CheckStatus::Warn, message: "w".into() },
                DoctorCheck { name: "c".into(), status: CheckStatus::Fail, message: "f".into() },
            ],
        };
        let output = format!("{report}");
        assert!(output.contains("1 passed, 1 warnings, 1 failures"));
        // Verify each icon appears.
        assert!(output.contains('\u{2713}')); // Pass
        assert!(output.contains('\u{26A0}')); // Warn
        assert!(output.contains('\u{2717}')); // Fail
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
            boot_time: Some(1_700_000_000),
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
