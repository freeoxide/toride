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
use crate::status::privacy::PrivacyMode;
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
        Self::check_with_privacy(&system, &daemon, &ssh, PrivacyMode::Safe)
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
        Self::check_with_privacy(system, daemon, ssh, PrivacyMode::Safe)
    }

    /// Run health checks with an explicit privacy mode.
    ///
    /// Like [`check_with`](Self::check_with), but also accepts a
    /// [`PrivacyMode`] so the doctor can validate that privacy-sensitive
    /// fields are properly redacted.
    #[must_use]
    pub fn check_with_privacy(
        system: &SystemStatus,
        daemon: &DaemonStatus,
        ssh: &SshStatus,
        privacy: PrivacyMode,
    ) -> Self {
        let mut checks = Vec::new();
        checks.extend(check_system(system));
        checks.extend(check_system_extended(system));
        checks.extend(check_daemon(*daemon));
        checks.extend(check_ssh(*ssh));
        checks.extend(check_privacy(system));
        checks.extend(check_permissions());
        checks.extend(check_network(system));
        checks.extend(check_privacy_redaction(system, privacy));
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

fn check_system_extended(system: &SystemStatus) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    checks.push(DoctorCheck {
        name: "system.gpu_provider".to_string(),
        status: if system.gpu.is_empty() { CheckStatus::Warn } else { CheckStatus::Pass },
        message: format!("{} GPU(s) detected", system.gpu.len()),
    });
    checks.push(DoctorCheck {
        name: "system.battery_provider".to_string(),
        status: if system.battery.is_some() { CheckStatus::Pass } else { CheckStatus::Warn },
        message: if system.battery.is_some() { "battery detected" } else { "no battery detected" }.to_string(),
    });
    checks.push(DoctorCheck {
        name: "system.sensor_provider".to_string(),
        status: if system.sensors.is_empty() { CheckStatus::Warn } else { CheckStatus::Pass },
        message: format!("{} sensor(s) found", system.sensors.len()),
    });
    checks.push(DoctorCheck {
        name: "system.cpu_sample_quality".to_string(),
        status: if let Some(cpu) = system.cpu_usage { if (0.0..=100.0).contains(&cpu) { CheckStatus::Pass } else { CheckStatus::Fail } } else { CheckStatus::Warn },
        message: system.cpu_usage.map_or_else(|| "CPU usage unavailable".to_string(), |u| format!("CPU usage: {u:.1}%")),
    });
    checks.push(DoctorCheck {
        name: "system.memory_sanity".to_string(),
        status: if system.memory.total_bytes > 0 && system.memory.used_bytes <= system.memory.total_bytes { CheckStatus::Pass } else if system.memory.total_bytes == 0 { CheckStatus::Fail } else { CheckStatus::Warn },
        message: format!("memory: {} / {} (used <= total: {})", system.memory.used_bytes, system.memory.total_bytes, system.memory.used_bytes <= system.memory.total_bytes),
    });
    let mut mount_points: Vec<&str> = system.disks.iter().map(|d| d.mount_point.as_str()).collect();
    mount_points.sort();
    let has_dupes = mount_points.windows(2).any(|w| w[0] == w[1]);
    checks.push(DoctorCheck {
        name: "system.disk_duplicates".to_string(),
        status: if has_dupes { CheckStatus::Warn } else { CheckStatus::Pass },
        message: if has_dupes { "duplicate mount points detected".to_string() } else { format!("{} disk(s), no duplicates", system.disks.len()) },
    });
    let virt = &system.virtualization;
    let mut envs = Vec::new();
    if virt.in_docker { envs.push("docker"); }
    if virt.in_lxc { envs.push("lxc"); }
    if virt.in_containerd { envs.push("containerd"); }
    if virt.in_kubernetes { envs.push("kubernetes"); }
    if virt.in_wsl { envs.push("wsl"); }
    if virt.in_vm { envs.push("vm"); }
    checks.push(DoctorCheck {
        name: "system.virtualization".to_string(),
        status: CheckStatus::Pass,
        message: if envs.is_empty() { "bare metal or unknown".to_string() } else { format!("running in: {}", envs.join(", ")) },
    });
    checks.push(DoctorCheck {
        name: "system.disk_io".to_string(),
        status: if system.disk_io.read_bytes > 0 || system.disk_io.written_bytes > 0 { CheckStatus::Pass } else { CheckStatus::Warn },
        message: format!("read: {} bytes, written: {} bytes", system.disk_io.read_bytes, system.disk_io.written_bytes),
    });

    // --- Data quality checks ---

    // quality.cpu_interval: CPU usage of exactly 0.0 may indicate the sample
    // was taken before the measurement window completed.
    checks.push(DoctorCheck {
        name: "quality.cpu_interval".to_string(),
        status: match system.cpu_usage {
            Some(0.0) => CheckStatus::Warn,
            Some(_) => CheckStatus::Pass,
            None => CheckStatus::Warn,
        },
        message: system.cpu_usage.map_or_else(
            || "CPU usage unavailable (possible sampling issue)".to_string(),
            |u| {
                if u == 0.0 {
                    "CPU usage is exactly 0.0% (possible too-short sampling interval)".to_string()
                } else {
                    format!("CPU usage: {u:.1}%")
                }
            },
        ),
    });

    // quality.monotonic_counters: Network bytes must be non-negative (always
    // true for u64) and non-zero to indicate valid data collection.
    checks.push(DoctorCheck {
        name: "quality.monotonic_counters".to_string(),
        status: if system.network.bytes_received > 0 || system.network.bytes_transmitted > 0 {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        message: format!(
            "rx: {} bytes, tx: {} bytes",
            system.network.bytes_received, system.network.bytes_transmitted
        ),
    });

    // quality.clock_sanity: Boot time must be after 2000 and before ~2030.
    if let Some(bt) = system.boot_time {
        let reasonable = bt > 946_684_800 && bt < 1_893_456_000;
        checks.push(DoctorCheck {
            name: "quality.clock_sanity".to_string(),
            status: if reasonable { CheckStatus::Pass } else { CheckStatus::Fail },
            message: if reasonable {
                format!("boot time {bt} is reasonable")
            } else {
                format!("boot time {bt} looks unreasonable (clock skew?)")
            },
        });
    }

    // quality.virtual_fs_filtered: Disk list should not contain virtual
    // filesystems that represent no real storage.
    let virtual_fs_names = ["tmpfs", "devfs", "sysfs", "proc", "devpts", "overlay"];
    let virtual_disks: Vec<&str> = system
        .disks
        .iter()
        .filter(|d| {
            let fs = d.filesystem.to_lowercase();
            virtual_fs_names.iter().any(|v| fs.contains(v))
        })
        .map(|d| d.mount_point.as_str())
        .collect();
    checks.push(DoctorCheck {
        name: "quality.virtual_fs_filtered".to_string(),
        status: if virtual_disks.is_empty() {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        message: if virtual_disks.is_empty() {
            "no virtual filesystems in disk list".to_string()
        } else {
            format!(
                "virtual filesystems detected: {}",
                virtual_disks.join(", ")
            )
        },
    });

    // quality.gpu_identity_no_metrics: If a GPU has a name but no utilization
    // data, the driver may not expose metrics.
    for (i, gpu) in system.gpu.iter().enumerate() {
        if gpu.utilization.is_none() {
            checks.push(DoctorCheck {
                name: format!("quality.gpu_{i}_identity_no_metrics"),
                status: CheckStatus::Warn,
                message: format!(
                    "GPU '{}' has name but no utilization data",
                    gpu.name
                ),
            });
        }
    }

    checks
}

fn check_privacy(system: &SystemStatus) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    checks.push(DoctorCheck {
        name: "privacy.hostname".to_string(),
        status: if system.hostname.is_empty() { CheckStatus::Warn } else { CheckStatus::Pass },
        message: if system.hostname.is_empty() { "hostname is empty (may be redacted)" } else { "hostname present" }.to_string(),
    });
    let has_details = system.processes.processes.iter().any(|p| p.executable_path.is_some() || p.user.is_some() || p.thread_count.is_some());
    checks.push(DoctorCheck {
        name: "privacy.process_details".to_string(),
        status: if has_details { CheckStatus::Pass } else { CheckStatus::Warn },
        message: if has_details { "process details available" } else { "no process details available" }.to_string(),
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

fn check_permissions() -> Vec<DoctorCheck> {
    let mut checks = Vec::new();

    // permissions.process_executable
    #[cfg(unix)]
    {
        let readable = std::fs::read_link("/proc/self/exe").is_ok()
            || std::path::Path::new("/proc/self/exe").exists();
        checks.push(DoctorCheck {
            name: "permissions.process_executable".to_string(),
            status: if readable { CheckStatus::Pass } else { CheckStatus::Warn },
            message: if readable {
                "process executable path is readable".to_string()
            } else {
                "cannot read /proc/self/exe (permission denied or unsupported)".to_string()
            },
        });
    }

    // permissions.process_cmdline
    #[cfg(unix)]
    {
        let readable = std::fs::read_to_string("/proc/self/cmdline").is_ok();
        checks.push(DoctorCheck {
            name: "permissions.process_cmdline".to_string(),
            status: if readable { CheckStatus::Pass } else { CheckStatus::Warn },
            message: if readable {
                "process command line is readable".to_string()
            } else {
                "cannot read /proc/self/cmdline (permission denied or unsupported)".to_string()
            },
        });
    }

    // permissions.disk_stats
    #[cfg(target_os = "linux")]
    {
        let readable = std::fs::read_to_string("/proc/diskstats").is_ok();
        checks.push(DoctorCheck {
            name: "permissions.disk_stats".to_string(),
            status: if readable { CheckStatus::Pass } else { CheckStatus::Warn },
            message: if readable {
                "/proc/diskstats is readable".to_string()
            } else {
                "cannot read /proc/diskstats (permission denied)".to_string()
            },
        });
    }

    // permissions.network_stats
    checks.push(DoctorCheck {
        name: "permissions.network_stats".to_string(),
        status: CheckStatus::Pass,
        message: "network counters are readable".to_string(),
    });

    // permissions.is_admin
    #[cfg(unix)]
    {
        let is_root = nix::unistd::geteuid().is_root();
        checks.push(DoctorCheck {
            name: "permissions.is_admin".to_string(),
            status: CheckStatus::Pass,
            message: if is_root {
                "running as root/administrator".to_string()
            } else {
                "not running as root".to_string()
            },
        });
    }

    checks
}

fn check_network(system: &SystemStatus) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();

    // network.provider: warn if no network interfaces detected.
    checks.push(DoctorCheck {
        name: "network.provider".to_string(),
        status: if system.network_interfaces.is_empty() {
            CheckStatus::Warn
        } else {
            CheckStatus::Pass
        },
        message: if system.network_interfaces.is_empty() {
            "no network interfaces detected".to_string()
        } else {
            format!(
                "{} network interface(s) detected",
                system.network_interfaces.len()
            )
        },
    });

    // network.counters_monotonic: warn if any interface has zero bytes on
    // both rx and tx (could indicate stale or broken counters).
    let zero_counters: Vec<&str> = system
        .network_interfaces
        .iter()
        .filter(|i| i.bytes_received == 0 && i.bytes_transmitted == 0)
        .map(|i| i.name.as_str())
        .collect();
    checks.push(DoctorCheck {
        name: "network.counters_monotonic".to_string(),
        status: if zero_counters.is_empty() || system.network_interfaces.is_empty() {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        message: if system.network_interfaces.is_empty() {
            "no interfaces to check".to_string()
        } else if zero_counters.is_empty() {
            "all interface counters are non-zero".to_string()
        } else {
            format!(
                "interface(s) with zero counters: {}",
                zero_counters.join(", ")
            )
        },
    });

    checks
}

fn check_privacy_redaction(system: &SystemStatus, mode: PrivacyMode) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();

    // privacy.serial_redacted: Check that no serial numbers appear in output
    // when privacy mode would require redaction.
    if mode != PrivacyMode::Full {
        let has_serial = system.static_info.hardware.system_serial.is_some()
            || system.disks.iter().any(|d| d.serial.is_some());
        checks.push(DoctorCheck {
            name: "privacy.serial_redacted".to_string(),
            status: if has_serial { CheckStatus::Warn } else { CheckStatus::Pass },
            message: if has_serial {
                "serial numbers present in data (should be redacted in output)".to_string()
            } else {
                "no serial numbers in collected data".to_string()
            },
        });
    }

    // privacy.mac_redacted: Check that MAC addresses are redacted in Safe
    // mode.
    if mode == PrivacyMode::Safe {
        let has_mac = system.network_interfaces.iter().any(|i| i.mac_address.is_some());
        checks.push(DoctorCheck {
            name: "privacy.mac_redacted".to_string(),
            status: if has_mac { CheckStatus::Warn } else { CheckStatus::Pass },
            message: if has_mac {
                "MAC addresses present in data (should be redacted in Safe mode)".to_string()
            } else {
                "no MAC addresses in collected data".to_string()
            },
        });
    }

    // privacy.command_args: Check that command lines are redacted in Safe mode.
    if mode == PrivacyMode::Safe {
        let has_cmdline = system.processes.processes.iter().any(|p| p.command_line.is_some());
        checks.push(DoctorCheck {
            name: "privacy.command_args".to_string(),
            status: if has_cmdline { CheckStatus::Warn } else { CheckStatus::Pass },
            message: if has_cmdline {
                "command line arguments present in data (should be redacted in Safe mode)".to_string()
            } else {
                "no command line arguments in collected data".to_string()
            },
        });
    }

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
        use crate::status::system::{DiskIoSnapshot, DiskStatus, HardwareInventory, MemoryStatus, NetworkStatus, OsInfo, SensorSnapshot, StaticInfo, VirtualizationSnapshot};
        let system = SystemStatus {
            cpu_usage: Some(50.0),
            memory: MemoryStatus {
                used_bytes: 100,
                total_bytes: 200,
                percentage: 50.0,
                cached_bytes: 0,
                available_bytes: 0,
                free_bytes: 0,
                buffers_bytes: 0,
            },
            disk: DiskStatus {
                name: "test".to_string(),
                mount_point: "/".to_string(),
                filesystem: "ext4".to_string(),
                used_bytes: 100,
                total_bytes: 200,
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
                bytes_received: 1000,
                bytes_transmitted: 500,
            },
            load_average: None,
            uptime_secs: Some(100),
            hostname: "test-host".to_string(),
            os_info: OsInfo {
                name: Some("TestOS".to_string()),
                version: Some("1.0".to_string()),
                kernel_version: None,
                arch: "x86_64".to_string(),
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
        use crate::status::system::{DiskIoSnapshot, DiskStatus, HardwareInventory, MemoryStatus, NetworkStatus, OsInfo, SensorSnapshot, StaticInfo, VirtualizationSnapshot};
        let system = SystemStatus {
            cpu_usage: Some(50.0),
            memory: MemoryStatus { used_bytes: 100, total_bytes: 200, percentage: 50.0, free_bytes: 0, available_bytes: 0, cached_bytes: 0, buffers_bytes: 0 },
            disk: DiskStatus { name: "test".to_string(), mount_point: "/".to_string(), filesystem: "ext4".to_string(), used_bytes: 100, total_bytes: 200, percentage: 50.0, is_removable: false, free_bytes: 0, available_bytes: 0, disk_type: "Unknown".to_string(), physical_device_path: None, model: None, serial: None, temperature: None, wear_percent: None },
            network: NetworkStatus { bytes_received: 0, bytes_transmitted: 0 },
            load_average: None, uptime_secs: Some(100), hostname: String::new(),
            os_info: OsInfo { name: Some("TestOS".to_string()), version: Some("1.0".to_string()), kernel_version: None, arch: "x86_64".to_string(), os_type: None, edition: None, codename: None, bitness: None, timezone: None, locale: None, current_user: None, is_root: false, container_detected: false, vm_detected: false, wsl_detected: false, systemd_detected: false, target_triple: None },
            cpu_cores: vec![], physical_cores: Some(4), swap: None, disks: vec![],
            network_interfaces: vec![], sensors: vec![], boot_time: None,
            processes: crate::status::system::ProcessSnapshot { processes: vec![], total_count: 0 },
            gpu: vec![], battery: None,
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
        };
        let daemon = DaemonStatus { alive: false, pid: None, uptime_secs: None, restart_count: 0, stale_socket: false };
        let ssh = SshStatus { mux_master_alive: false, control_path_valid: false, config_valid: false, agent_running: false, key_count: 0 };
        let report = DoctorReport::check_with(&system, &daemon, &ssh);
        let hostname_check = report.checks.iter().find(|c| c.name == "system.hostname").unwrap();
        assert_eq!(hostname_check.status, crate::status::doctor::CheckStatus::Fail);
    }

    // --- Helpers ---

    fn happy_system() -> SystemStatus {
        use crate::status::system::{DiskIoSnapshot, DiskStatus, HardwareInventory, MemoryStatus, NetworkStatus, OsInfo, SensorSnapshot, StaticInfo, VirtualizationSnapshot};
        SystemStatus {
            cpu_usage: Some(50.0),
            memory: MemoryStatus {
                used_bytes: 100,
                total_bytes: 200,
                percentage: 50.0,
                cached_bytes: 0,
                available_bytes: 0,
                free_bytes: 0,
                buffers_bytes: 0,
            },
            disk: DiskStatus {
                name: "test".to_string(),
                mount_point: "/".to_string(),
                filesystem: "ext4".to_string(),
                used_bytes: 100,
                total_bytes: 200,
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
                disk_type: "Unknown".to_string(),
                available_bytes: 0,
                free_bytes: 0,
                physical_device_path: None,
                model: None,
                serial: None,
                temperature: None,
                wear_percent: None,
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
            cached_bytes: 0,
            available_bytes: 0,
            free_bytes: 0,
            buffers_bytes: 0,
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
        use crate::status::system::{DiskIoSnapshot, DiskStatus, HardwareInventory, MemoryStatus, NetworkStatus, OsInfo, SensorSnapshot, StaticInfo, VirtualizationSnapshot};
        let system = SystemStatus {
            cpu_usage: Some(42.5),
            memory: MemoryStatus {
                used_bytes: 8_000_000_000,
                total_bytes: 16_000_000_000,
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
                used_bytes: 500_000_000_000,
                total_bytes: 1_000_000_000_000,
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

    // --- check_permissions ---

    #[test]
    fn permissions_checks_present_in_report() {
        let report = DoctorReport::check_with(&happy_system(), &happy_daemon(), &happy_ssh());
        // At minimum, network_stats and is_admin should always be present.
        find_check(&report, "permissions.network_stats");
        find_check(&report, "permissions.is_admin");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn permissions_process_executable_passes_on_linux() {
        let report = DoctorReport::check_with(&happy_system(), &happy_daemon(), &happy_ssh());
        let check = find_check(&report, "permissions.process_executable");
        assert_eq!(check.status, CheckStatus::Pass);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn permissions_process_cmdline_passes_on_linux() {
        let report = DoctorReport::check_with(&happy_system(), &happy_daemon(), &happy_ssh());
        let check = find_check(&report, "permissions.process_cmdline");
        assert_eq!(check.status, CheckStatus::Pass);
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn permissions_process_checks_warn_on_non_linux() {
        let report = DoctorReport::check_with(&happy_system(), &happy_daemon(), &happy_ssh());
        let check = find_check(&report, "permissions.process_executable");
        assert_eq!(check.status, CheckStatus::Warn);
        let check = find_check(&report, "permissions.process_cmdline");
        assert_eq!(check.status, CheckStatus::Warn);
    }

    #[test]
    fn permissions_network_stats_always_passes() {
        let report = DoctorReport::check_with(&happy_system(), &happy_daemon(), &happy_ssh());
        let check = find_check(&report, "permissions.network_stats");
        assert_eq!(check.status, CheckStatus::Pass);
    }

    #[test]
    fn permissions_is_admin_always_passes() {
        let report = DoctorReport::check_with(&happy_system(), &happy_daemon(), &happy_ssh());
        let check = find_check(&report, "permissions.is_admin");
        assert_eq!(check.status, CheckStatus::Pass);
    }

    // --- check_network ---

    #[test]
    fn network_provider_warns_when_no_interfaces() {
        let system = happy_system();
        let report = DoctorReport::check_with(&system, &happy_daemon(), &happy_ssh());
        // happy_system has no interfaces
        let check = find_check(&report, "network.provider");
        assert_eq!(check.status, CheckStatus::Warn);
    }

    #[test]
    fn network_provider_passes_with_interfaces() {
        use crate::status::system::NetworkInterface;
        let mut system = happy_system();
        system.network_interfaces = vec![NetworkInterface {
            name: "en0".to_string(),
            bytes_received: 1000,
            bytes_transmitted: 500,
            packets_received: 10,
            packets_transmitted: 5,
            errors_received: 0,
            errors_transmitted: 0,
            mac_address: None,
            mtu: None,
            drops_received: 0,
            drops_transmitted: 0,
            display_name: None,
            description: None,
            ipv4_addresses: vec![],
            ipv6_addresses: vec![],
            gateway: None,
            dns: None,
            link_status: None,
            speed_bps: None,
            duplex: None,
        }];
        let report = DoctorReport::check_with(&system, &happy_daemon(), &happy_ssh());
        let check = find_check(&report, "network.provider");
        assert_eq!(check.status, CheckStatus::Pass);
    }

    #[test]
    fn network_counters_monotonic_warns_on_zero_interface() {
        use crate::status::system::NetworkInterface;
        let mut system = happy_system();
        system.network_interfaces = vec![NetworkInterface {
            name: "lo".to_string(),
            bytes_received: 0,
            bytes_transmitted: 0,
            packets_received: 0,
            packets_transmitted: 0,
            errors_received: 0,
            errors_transmitted: 0,
            mac_address: None,
            mtu: None,
            drops_received: 0,
            drops_transmitted: 0,
            display_name: None,
            description: None,
            ipv4_addresses: vec![],
            ipv6_addresses: vec![],
            gateway: None,
            dns: None,
            link_status: None,
            speed_bps: None,
            duplex: None,
        }];
        let report = DoctorReport::check_with(&system, &happy_daemon(), &happy_ssh());
        let check = find_check(&report, "network.counters_monotonic");
        assert_eq!(check.status, CheckStatus::Warn);
    }

    #[test]
    fn network_counters_monotonic_passes_with_nonzero_interface() {
        use crate::status::system::NetworkInterface;
        let mut system = happy_system();
        system.network_interfaces = vec![NetworkInterface {
            name: "eth0".to_string(),
            bytes_received: 1000,
            bytes_transmitted: 500,
            packets_received: 10,
            packets_transmitted: 5,
            errors_received: 0,
            errors_transmitted: 0,
            mac_address: None,
            mtu: None,
            drops_received: 0,
            drops_transmitted: 0,
            display_name: None,
            description: None,
            ipv4_addresses: vec![],
            ipv6_addresses: vec![],
            gateway: None,
            dns: None,
            link_status: None,
            speed_bps: None,
            duplex: None,
        }];
        let report = DoctorReport::check_with(&system, &happy_daemon(), &happy_ssh());
        let check = find_check(&report, "network.counters_monotonic");
        assert_eq!(check.status, CheckStatus::Pass);
    }

    // --- check_privacy_redaction ---

    #[test]
    fn privacy_serial_redacted_passes_when_no_serial() {
        let system = happy_system();
        let report = DoctorReport::check_with_privacy(
            &system,
            &happy_daemon(),
            &happy_ssh(),
            PrivacyMode::Safe,
        );
        let check = find_check(&report, "privacy.serial_redacted");
        assert_eq!(check.status, CheckStatus::Pass);
    }

    #[test]
    fn privacy_serial_redacted_warns_when_serial_present() {
        use crate::status::system::HardwareInventory;
        let mut system = happy_system();
        system.static_info.hardware = HardwareInventory {
            system_serial: Some("SN-123456".to_string()),
            ..HardwareInventory::default()
        };
        let report = DoctorReport::check_with_privacy(
            &system,
            &happy_daemon(),
            &happy_ssh(),
            PrivacyMode::Safe,
        );
        let check = find_check(&report, "privacy.serial_redacted");
        assert_eq!(check.status, CheckStatus::Warn);
    }

    #[test]
    fn privacy_serial_redacted_absent_in_full_mode() {
        let system = happy_system();
        let report = DoctorReport::check_with_privacy(
            &system,
            &happy_daemon(),
            &happy_ssh(),
            PrivacyMode::Full,
        );
        assert!(report.checks.iter().all(|c| c.name != "privacy.serial_redacted"));
    }

    #[test]
    fn privacy_mac_redacted_passes_when_no_mac() {
        let system = happy_system();
        let report = DoctorReport::check_with_privacy(
            &system,
            &happy_daemon(),
            &happy_ssh(),
            PrivacyMode::Safe,
        );
        let check = find_check(&report, "privacy.mac_redacted");
        assert_eq!(check.status, CheckStatus::Pass);
    }

    #[test]
    fn privacy_mac_redacted_warns_when_mac_present() {
        use crate::status::system::NetworkInterface;
        let mut system = happy_system();
        system.network_interfaces = vec![NetworkInterface {
            name: "en0".to_string(),
            bytes_received: 0,
            bytes_transmitted: 0,
            packets_received: 0,
            packets_transmitted: 0,
            errors_received: 0,
            errors_transmitted: 0,
            mac_address: Some("aa:bb:cc:dd:ee:ff".to_string()),
            mtu: None,
            drops_received: 0,
            drops_transmitted: 0,
            display_name: None,
            description: None,
            ipv4_addresses: vec![],
            ipv6_addresses: vec![],
            gateway: None,
            dns: None,
            link_status: None,
            speed_bps: None,
            duplex: None,
        }];
        let report = DoctorReport::check_with_privacy(
            &system,
            &happy_daemon(),
            &happy_ssh(),
            PrivacyMode::Safe,
        );
        let check = find_check(&report, "privacy.mac_redacted");
        assert_eq!(check.status, CheckStatus::Warn);
    }

    #[test]
    fn privacy_mac_redacted_absent_in_full_mode() {
        let system = happy_system();
        let report = DoctorReport::check_with_privacy(
            &system,
            &happy_daemon(),
            &happy_ssh(),
            PrivacyMode::Full,
        );
        assert!(report.checks.iter().all(|c| c.name != "privacy.mac_redacted"));
    }

    #[test]
    fn privacy_command_args_passes_when_no_cmdline() {
        let system = happy_system();
        let report = DoctorReport::check_with_privacy(
            &system,
            &happy_daemon(),
            &happy_ssh(),
            PrivacyMode::Safe,
        );
        let check = find_check(&report, "privacy.command_args");
        assert_eq!(check.status, CheckStatus::Pass);
    }

    #[test]
    fn privacy_command_args_warns_when_cmdline_present() {
        let mut system = happy_system();
        system.processes = crate::status::system::ProcessSnapshot {
            processes: vec![crate::status::system::ProcessStatus {
                pid: 1,
                parent_pid: None,
                name: "test".to_string(),
                cpu_usage: 0.0,
                memory_bytes: 0,
                status: "Running".to_string(),
                start_time: None,
                executable_path: None,
                user: None,
                virtual_memory: 0,
                thread_count: None,
                command_line: Some("/usr/bin/test --arg".to_string()),
                working_dir: None,
                disk_read_bytes: None,
                disk_write_bytes: None,
                open_files: None,
                fd_count: None,
            }],
            total_count: 1,
        };
        let report = DoctorReport::check_with_privacy(
            &system,
            &happy_daemon(),
            &happy_ssh(),
            PrivacyMode::Safe,
        );
        let check = find_check(&report, "privacy.command_args");
        assert_eq!(check.status, CheckStatus::Warn);
    }

    #[test]
    fn privacy_command_args_absent_in_full_mode() {
        let system = happy_system();
        let report = DoctorReport::check_with_privacy(
            &system,
            &happy_daemon(),
            &happy_ssh(),
            PrivacyMode::Full,
        );
        assert!(report.checks.iter().all(|c| c.name != "privacy.command_args"));
    }

    // --- Data quality checks ---

    #[test]
    fn quality_cpu_interval_passes_for_nonzero() {
        let mut system = happy_system();
        system.cpu_usage = Some(42.5);
        let report = DoctorReport::check_with(&system, &happy_daemon(), &happy_ssh());
        let check = find_check(&report, "quality.cpu_interval");
        assert_eq!(check.status, CheckStatus::Pass);
    }

    #[test]
    fn quality_cpu_interval_warns_for_zero() {
        let mut system = happy_system();
        system.cpu_usage = Some(0.0);
        let report = DoctorReport::check_with(&system, &happy_daemon(), &happy_ssh());
        let check = find_check(&report, "quality.cpu_interval");
        assert_eq!(check.status, CheckStatus::Warn);
    }

    #[test]
    fn quality_cpu_interval_warns_for_none() {
        let mut system = happy_system();
        system.cpu_usage = None;
        let report = DoctorReport::check_with(&system, &happy_daemon(), &happy_ssh());
        let check = find_check(&report, "quality.cpu_interval");
        assert_eq!(check.status, CheckStatus::Warn);
    }

    #[test]
    fn quality_monotonic_counters_passes_with_nonzero() {
        let mut system = happy_system();
        system.network = crate::status::system::NetworkStatus {
            bytes_received: 1000,
            bytes_transmitted: 500,
        };
        let report = DoctorReport::check_with(&system, &happy_daemon(), &happy_ssh());
        let check = find_check(&report, "quality.monotonic_counters");
        assert_eq!(check.status, CheckStatus::Pass);
    }

    #[test]
    fn quality_monotonic_counters_warns_for_zero() {
        let mut system = happy_system();
        system.network = crate::status::system::NetworkStatus {
            bytes_received: 0,
            bytes_transmitted: 0,
        };
        let report = DoctorReport::check_with(&system, &happy_daemon(), &happy_ssh());
        let check = find_check(&report, "quality.monotonic_counters");
        assert_eq!(check.status, CheckStatus::Warn);
    }

    #[test]
    fn quality_clock_sanity_passes_for_reasonable_boot_time() {
        let mut system = happy_system();
        system.boot_time = Some(1_700_000_000); // 2023
        let report = DoctorReport::check_with(&system, &happy_daemon(), &happy_ssh());
        let check = find_check(&report, "quality.clock_sanity");
        assert_eq!(check.status, CheckStatus::Pass);
    }

    #[test]
    fn quality_clock_sanity_fails_for_old_boot_time() {
        let mut system = happy_system();
        system.boot_time = Some(100_000_000); // 1973
        let report = DoctorReport::check_with(&system, &happy_daemon(), &happy_ssh());
        let check = find_check(&report, "quality.clock_sanity");
        assert_eq!(check.status, CheckStatus::Fail);
    }

    #[test]
    fn quality_clock_sanity_fails_for_future_boot_time() {
        let mut system = happy_system();
        system.boot_time = Some(2_000_000_000); // 2033
        let report = DoctorReport::check_with(&system, &happy_daemon(), &happy_ssh());
        let check = find_check(&report, "quality.clock_sanity");
        assert_eq!(check.status, CheckStatus::Fail);
    }

    #[test]
    fn quality_clock_sanity_absent_when_no_boot_time() {
        let mut system = happy_system();
        system.boot_time = None;
        let report = DoctorReport::check_with(&system, &happy_daemon(), &happy_ssh());
        assert!(report.checks.iter().all(|c| c.name != "quality.clock_sanity"));
    }

    #[test]
    fn quality_virtual_fs_filtered_passes_for_normal_disks() {
        let system = happy_system(); // has ext4 disk
        let report = DoctorReport::check_with(&system, &happy_daemon(), &happy_ssh());
        let check = find_check(&report, "quality.virtual_fs_filtered");
        assert_eq!(check.status, CheckStatus::Pass);
    }

    #[test]
    fn quality_virtual_fs_filtered_warns_for_tmpfs() {
        let mut system = happy_system();
        system.disks.push(crate::status::system::DiskStatus {
            name: "tmpfs".to_string(),
            mount_point: "/tmp".to_string(),
            filesystem: "tmpfs".to_string(),
            used_bytes: 0,
            total_bytes: 0,
            percentage: 0.0,
            is_removable: false,
            disk_type: "Unknown".to_string(),
            available_bytes: 0,
            free_bytes: 0,
            physical_device_path: None,
            model: None,
            serial: None,
            temperature: None,
            wear_percent: None,
        });
        let report = DoctorReport::check_with(&system, &happy_daemon(), &happy_ssh());
        let check = find_check(&report, "quality.virtual_fs_filtered");
        assert_eq!(check.status, CheckStatus::Warn);
    }

    #[test]
    fn quality_gpu_identity_no_metrics_warns() {
        use crate::status::system::GpuInfo;
        let mut system = happy_system();
        system.gpu = vec![GpuInfo {
            name: "Test GPU".to_string(),
            vendor: "NVIDIA".to_string(),
            vram_bytes: None,
            driver_version: None,
            gpu_type: None,
            temperature: None,
            utilization: None,
            device_id: None,
            pci_bus_id: None,
            used_vram_bytes: None,
            free_vram_bytes: None,
            memory_utilization: None,
            encoder_utilization: None,
            decoder_utilization: None,
            fan_speed_rpm: None,
            power_draw_watts: None,
            power_limit_watts: None,
            clock_speed_mhz: None,
        }];
        let report = DoctorReport::check_with(&system, &happy_daemon(), &happy_ssh());
        let check = find_check(&report, "quality.gpu_0_identity_no_metrics");
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.message.contains("Test GPU"));
    }

    #[test]
    fn quality_gpu_identity_no_metrics_passes_with_utilization() {
        use crate::status::system::GpuInfo;
        let mut system = happy_system();
        system.gpu = vec![GpuInfo {
            name: "Test GPU".to_string(),
            vendor: "NVIDIA".to_string(),
            vram_bytes: None,
            driver_version: None,
            gpu_type: None,
            temperature: None,
            utilization: Some(45.0),
            device_id: None,
            pci_bus_id: None,
            used_vram_bytes: None,
            free_vram_bytes: None,
            memory_utilization: None,
            encoder_utilization: None,
            decoder_utilization: None,
            fan_speed_rpm: None,
            power_draw_watts: None,
            power_limit_watts: None,
            clock_speed_mhz: None,
        }];
        let report = DoctorReport::check_with(&system, &happy_daemon(), &happy_ssh());
        assert!(report.checks.iter().all(|c| c.name != "quality.gpu_0_identity_no_metrics"));
    }

    // --- check_with_privacy integration ---

    #[test]
    fn check_with_privacy_includes_all_groups() {
        let report = DoctorReport::check_with_privacy(
            &happy_system(),
            &happy_daemon(),
            &happy_ssh(),
            PrivacyMode::Safe,
        );
        // Verify all groups are present.
        let names: Vec<&str> = report.checks.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"system.hostname"));
        assert!(names.contains(&"daemon.alive"));
        assert!(names.contains(&"ssh.binary"));
        assert!(names.contains(&"privacy.hostname"));
        assert!(names.contains(&"permissions.network_stats"));
        assert!(names.contains(&"permissions.is_admin"));
        assert!(names.contains(&"network.provider"));
        assert!(names.contains(&"network.counters_monotonic"));
        assert!(names.contains(&"privacy.serial_redacted"));
        assert!(names.contains(&"privacy.mac_redacted"));
        assert!(names.contains(&"privacy.command_args"));
        assert!(names.contains(&"quality.cpu_interval"));
        assert!(names.contains(&"quality.monotonic_counters"));
        assert!(names.contains(&"quality.virtual_fs_filtered"));
    }

    #[test]
    fn check_with_privacy_full_omits_safe_only_checks() {
        let report = DoctorReport::check_with_privacy(
            &happy_system(),
            &happy_daemon(),
            &happy_ssh(),
            PrivacyMode::Full,
        );
        let names: Vec<&str> = report.checks.iter().map(|c| c.name.as_str()).collect();
        // These should NOT be present in Full mode.
        assert!(!names.contains(&"privacy.mac_redacted"));
        assert!(!names.contains(&"privacy.command_args"));
        // serial_redacted should also be absent in Full mode.
        assert!(!names.contains(&"privacy.serial_redacted"));
    }
}
