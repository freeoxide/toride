//! Capability detection for the status subsystem.
//!
//! Reports which metrics are available on the current platform. Use
//! [`Capabilities::detect`] to determine which features are supported
//! before attempting to collect them.
//!
//! # Capability detection explanation
//!
//! Capabilities are detected using compile-time `cfg!` macros for
//! platform-dependent features (e.g., `cfg!(unix)` for PID checks)
//! and runtime binary detection for external tools (e.g., checking
//! if `ssh` is on PATH via the `which` crate).
//!
//! ## System capabilities
//!
//! Most system capabilities are available on all platforms. Exceptions:
//! - **Swap**: Only available on Unix systems.
//! - **Load average**: Only available on Unix systems.
//! - **Sensors**: Available on Linux, macOS, and Windows.
//!
//! ## Daemon capabilities
//!
//! - **PID check**: Requires `kill(0, 0)` on Unix or `OpenProcess` on Windows.
//! - **Uptime for PID**: Requires `/proc` on Linux or `ps` on macOS.
//! - **Stale socket detection**: Requires Unix socket support.
//!
//! ## SSH capabilities
//!
//! SSH capabilities depend on the presence of `ssh` and `ssh-add` binaries
//! on the system PATH. These are detected at runtime.
//!
//! # Examples
//!
//! ```no_run
//! use toride::status::capabilities::Capabilities;
//!
//! let caps = Capabilities::detect();
//! if caps.system.load_average {
//!     println!("Load average is available");
//! } else {
//!     println!("Load average not supported on this platform");
//! }
//!
//! if !caps.ssh.mux_check {
//!     eprintln!("Warning: ssh not found on PATH");
//! }
//! ```
//!
//! Check capabilities before collecting:
//!
//! ```no_run
//! use toride::status::capabilities::Capabilities;
//! use toride::status::system::SystemStatus;
//!
//! let caps = Capabilities::detect();
//! let status = SystemStatus::collect();
//!
//! if caps.system.load_average && status.load_average.is_some() {
//!     let load = status.load_average.unwrap();
//!     println!("Load: {:.2} / {:.2} / {:.2}", load.one, load.five, load.fifteen);
//! }
//! ```

use std::fmt;

use serde::Serialize;

/// Top-level capabilities report.
///
/// Contains capability flags for all subsystems. Use [`detect`](Self::detect)
/// to determine which features are supported on the current platform.
///
/// # Examples
///
/// ```no_run
/// use toride::status::capabilities::Capabilities;
///
/// let caps = Capabilities::detect();
/// println!("{}", caps);
/// ```
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Capabilities {
    /// System metric capabilities (CPU, memory, disk, etc.).
    pub system: SystemCapabilities,
    /// Daemon check capabilities (PID, uptime, socket detection).
    pub daemon: DaemonCapabilities,
    /// SSH check capabilities (mux, config, agent, keys).
    pub ssh: SshCapabilities,
}

/// System metric capabilities.
///
/// Indicates which system metrics are available on the current platform.
#[derive(Debug, Clone, Copy, Serialize)]
#[allow(clippy::struct_excessive_bools)] // Capabilities are inherently boolean flags
pub struct SystemCapabilities {
    /// Aggregate CPU usage is available.
    pub cpu_usage: bool,
    /// Per-core CPU data is available.
    pub per_core_cpu: bool,
    /// Memory usage data is available.
    pub memory: bool,
    /// Swap usage data is available (Unix only).
    pub swap: bool,
    /// Disk usage data is available.
    pub disk: bool,
    /// Network I/O counters are available.
    pub network: bool,
    /// Load average is available (Unix only).
    pub load_average: bool,
    /// System uptime is available.
    pub uptime: bool,
    /// Hostname is available.
    pub hostname: bool,
    /// OS information is available.
    pub os_info: bool,
    /// Temperature sensor data is available.
    pub sensors: bool,
}

/// Daemon check capabilities.
///
/// Indicates which daemon health checks are available on the current platform.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct DaemonCapabilities {
    /// PID liveness check is available (Unix: `kill(0, 0)`, Windows: `OpenProcess`).
    pub pid_check: bool,
    /// Process uptime calculation is available (Linux: `/proc`, macOS: `ps`).
    pub uptime_for_pid: bool,
    /// Stale Unix socket detection is available.
    pub stale_socket_detection: bool,
}

/// SSH check capabilities.
///
/// Indicates which SSH health checks are available. Depends on the
/// presence of `ssh` and `ssh-add` on the system PATH.
#[derive(Debug, Clone, Copy, Serialize)]
#[allow(clippy::struct_excessive_bools)] // Capabilities are inherently boolean flags
pub struct SshCapabilities {
    /// SSH mux master check is available (`ssh` on PATH).
    pub mux_check: bool,
    /// SSH config validation is available (`ssh` on PATH).
    pub config_validation: bool,
    /// SSH agent check is available (`ssh-add` on PATH).
    pub agent_check: bool,
    /// SSH key counting is available (`ssh-add` on PATH).
    pub key_counting: bool,
}

impl Capabilities {
    /// Detect capabilities of the current platform.
    ///
    /// Uses compile-time `cfg!` macros for platform features and runtime
    /// binary detection for external tools.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride::status::capabilities::Capabilities;
    ///
    /// let caps = Capabilities::detect();
    /// assert!(caps.system.cpu_usage); // Always available.
    /// ```
    #[must_use]
    pub fn detect() -> Self {
        Self {
            system: SystemCapabilities::detect(),
            daemon: DaemonCapabilities::detect(),
            ssh: SshCapabilities::detect(),
        }
    }
}

impl SystemCapabilities {
    const fn detect() -> Self {
        Self {
            cpu_usage: true,
            per_core_cpu: true,
            memory: true,
            swap: cfg!(unix),
            disk: true,
            network: true,
            load_average: cfg!(unix),
            uptime: true,
            hostname: true,
            os_info: true,
            sensors: cfg!(target_os = "linux") || cfg!(target_os = "macos") || cfg!(target_os = "windows"),
        }
    }
}

impl DaemonCapabilities {
    const fn detect() -> Self {
        Self {
            pid_check: cfg!(unix),
            uptime_for_pid: cfg!(target_os = "macos") || cfg!(target_os = "linux"),
            stale_socket_detection: cfg!(unix),
        }
    }
}

impl SshCapabilities {
    fn detect() -> Self {
        use which::which;
        let ssh_available = which("ssh").is_ok();
        let ssh_add_available = which("ssh-add").is_ok();
        Self {
            mux_check: ssh_available,
            config_validation: ssh_available,
            agent_check: ssh_add_available,
            key_counting: ssh_add_available,
        }
    }
}

impl fmt::Display for Capabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Capabilities ===")?;
        writeln!(f, "System:")?;
        writeln!(f, "  CPU usage: {}", yn(self.system.cpu_usage))?;
        writeln!(f, "  Per-core CPU: {}", yn(self.system.per_core_cpu))?;
        writeln!(f, "  Memory: {}", yn(self.system.memory))?;
        writeln!(f, "  Swap: {}", yn(self.system.swap))?;
        writeln!(f, "  Disk: {}", yn(self.system.disk))?;
        writeln!(f, "  Network: {}", yn(self.system.network))?;
        writeln!(f, "  Load average: {}", yn(self.system.load_average))?;
        writeln!(f, "  Uptime: {}", yn(self.system.uptime))?;
        writeln!(f, "  Hostname: {}", yn(self.system.hostname))?;
        writeln!(f, "  OS info: {}", yn(self.system.os_info))?;
        writeln!(f, "  Sensors: {}", yn(self.system.sensors))?;
        writeln!(f, "Daemon:")?;
        writeln!(f, "  PID check: {}", yn(self.daemon.pid_check))?;
        writeln!(f, "  Uptime for PID: {}", yn(self.daemon.uptime_for_pid))?;
        writeln!(f, "  Stale socket: {}", yn(self.daemon.stale_socket_detection))?;
        writeln!(f, "SSH:")?;
        writeln!(f, "  Mux check: {}", yn(self.ssh.mux_check))?;
        writeln!(f, "  Config validation: {}", yn(self.ssh.config_validation))?;
        writeln!(f, "  Agent check: {}", yn(self.ssh.agent_check))?;
        writeln!(f, "  Key counting: {}", yn(self.ssh.key_counting))
    }
}

const fn yn(v: bool) -> &'static str { if v { "yes" } else { "no" } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_capabilities() {
        let caps = Capabilities::detect();
        assert!(caps.system.cpu_usage);
        assert!(caps.system.memory);
        assert!(caps.system.hostname);
    }

    #[test]
    fn display_contains_all_sections() {
        let caps = Capabilities::detect();
        let output = format!("{caps}");
        assert!(output.contains("Capabilities"));
        assert!(output.contains("System:"));
        assert!(output.contains("Daemon:"));
        assert!(output.contains("SSH:"));
    }

    #[test]
    fn serialize_to_json() {
        let caps = Capabilities::detect();
        assert!(serde_json::to_string(&caps).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn unix_has_pid_check() {
        let caps = Capabilities::detect();
        assert!(caps.daemon.pid_check);
    }

    // --- SystemCapabilities edge cases ---

    #[test]
    fn system_cpu_usage_always_true() {
        let caps = SystemCapabilities::detect();
        assert!(caps.cpu_usage);
    }

    #[test]
    fn system_per_core_cpu_always_true() {
        let caps = SystemCapabilities::detect();
        assert!(caps.per_core_cpu);
    }

    #[test]
    fn system_memory_always_true() {
        let caps = SystemCapabilities::detect();
        assert!(caps.memory);
    }

    #[test]
    fn system_disk_always_true() {
        let caps = SystemCapabilities::detect();
        assert!(caps.disk);
    }

    #[test]
    fn system_network_always_true() {
        let caps = SystemCapabilities::detect();
        assert!(caps.network);
    }

    #[test]
    fn system_hostname_always_true() {
        let caps = SystemCapabilities::detect();
        assert!(caps.hostname);
    }

    #[test]
    fn system_os_info_always_true() {
        let caps = SystemCapabilities::detect();
        assert!(caps.os_info);
    }

    #[cfg(unix)]
    #[test]
    fn system_swap_true_on_unix() {
        let caps = SystemCapabilities::detect();
        assert!(caps.swap);
    }

    #[cfg(not(unix))]
    #[test]
    fn system_swap_false_on_non_unix() {
        let caps = SystemCapabilities::detect();
        assert!(!caps.swap);
    }

    #[cfg(unix)]
    #[test]
    fn system_load_average_true_on_unix() {
        let caps = SystemCapabilities::detect();
        assert!(caps.load_average);
    }

    #[cfg(not(unix))]
    #[test]
    fn system_load_average_false_on_non_unix() {
        let caps = SystemCapabilities::detect();
        assert!(!caps.load_average);
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn system_sensors_true_on_supported_platforms() {
        let caps = SystemCapabilities::detect();
        assert!(caps.sensors);
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    #[test]
    fn system_sensors_false_on_unsupported_platforms() {
        let caps = SystemCapabilities::detect();
        assert!(!caps.sensors);
    }

    // --- DaemonCapabilities edge cases ---

    #[cfg(unix)]
    #[test]
    fn daemon_pid_check_true_on_unix() {
        let caps = DaemonCapabilities::detect();
        assert!(caps.pid_check);
    }

    #[cfg(not(unix))]
    #[test]
    fn daemon_pid_check_false_on_non_unix() {
        let caps = DaemonCapabilities::detect();
        assert!(!caps.pid_check);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn daemon_uptime_for_pid_true_on_macos_linux() {
        let caps = DaemonCapabilities::detect();
        assert!(caps.uptime_for_pid);
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn daemon_uptime_for_pid_false_on_other() {
        let caps = DaemonCapabilities::detect();
        assert!(!caps.uptime_for_pid);
    }

    #[cfg(unix)]
    #[test]
    fn daemon_stale_socket_detection_true_on_unix() {
        let caps = DaemonCapabilities::detect();
        assert!(caps.stale_socket_detection);
    }

    #[cfg(not(unix))]
    #[test]
    fn daemon_stale_socket_detection_false_on_non_unix() {
        let caps = DaemonCapabilities::detect();
        assert!(!caps.stale_socket_detection);
    }

    // --- SshCapabilities edge cases ---

    #[test]
    fn ssh_mux_check_depends_on_ssh_on_path() {
        let caps = SshCapabilities::detect();
        let ssh_on_path = which::which("ssh").is_ok();
        assert_eq!(caps.mux_check, ssh_on_path);
    }

    #[test]
    fn ssh_config_validation_depends_on_ssh_on_path() {
        let caps = SshCapabilities::detect();
        let ssh_on_path = which::which("ssh").is_ok();
        assert_eq!(caps.config_validation, ssh_on_path);
    }

    #[test]
    fn ssh_agent_check_depends_on_ssh_add_on_path() {
        let caps = SshCapabilities::detect();
        let ssh_add_on_path = which::which("ssh-add").is_ok();
        assert_eq!(caps.agent_check, ssh_add_on_path);
    }

    #[test]
    fn ssh_key_counting_depends_on_ssh_add_on_path() {
        let caps = SshCapabilities::detect();
        let ssh_add_on_path = which::which("ssh-add").is_ok();
        assert_eq!(caps.key_counting, ssh_add_on_path);
    }

    // --- Display edge cases ---

    #[test]
    fn display_shows_all_capabilities() {
        let caps = Capabilities::detect();
        let output = format!("{caps}");
        assert!(output.contains("CPU usage:"));
        assert!(output.contains("Per-core CPU:"));
        assert!(output.contains("Memory:"));
        assert!(output.contains("Swap:"));
        assert!(output.contains("Disk:"));
        assert!(output.contains("Network:"));
        assert!(output.contains("Load average:"));
        assert!(output.contains("Uptime:"));
        assert!(output.contains("Hostname:"));
        assert!(output.contains("OS info:"));
        assert!(output.contains("Sensors:"));
        assert!(output.contains("PID check:"));
        assert!(output.contains("Uptime for PID:"));
        assert!(output.contains("Stale socket:"));
        assert!(output.contains("Mux check:"));
        assert!(output.contains("Config validation:"));
        assert!(output.contains("Agent check:"));
        assert!(output.contains("Key counting:"));
    }

    #[test]
    fn display_values_are_yes_or_no() {
        let caps = Capabilities::detect();
        let output = format!("{caps}");
        for line in output.lines() {
            if line.contains(':') && !line.starts_with("===") && !line.ends_with(':') {
                let trimmed = line.trim();
                assert!(
                    trimmed.ends_with("yes") || trimmed.ends_with("no"),
                    "unexpected value in display line: {trimmed}"
                );
            }
        }
    }
}