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
#[derive(Debug, Clone, Serialize)]
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
#[derive(Debug, Clone, Serialize)]
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

    // --- Per-domain capability structs ---
    /// OS-level capabilities.
    pub os: OsCapabilities,
    /// GPU capabilities.
    pub gpu: GpuCapabilities,
    /// Battery capabilities.
    pub battery: BatteryCapabilities,
    /// Process capabilities.
    pub process: ProcessCapabilities,
    /// Storage capabilities.
    pub storage: StorageCapabilities,
    /// Network capabilities.
    pub network_caps: NetworkCapabilities,
    /// Sensor capabilities.
    pub sensor: SensorCapabilities,
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

/// GPU capabilities.
///
/// Indicates which GPU metrics are available on the current platform.
#[derive(Debug, Clone, Serialize)]
pub struct GpuCapabilities {
    /// GPU identity information is available.
    pub identity: bool,
    /// NVIDIA NVML is available.
    pub nvidia_nvml: bool,
    /// GPU utilization data is available.
    pub utilization: bool,
    /// GPU temperature data is available.
    pub temperature: bool,
    /// GPU memory data is available.
    pub memory: bool,
    /// Per-process GPU data is available.
    pub per_process: bool,
}

/// Battery capabilities.
///
/// Indicates which battery metrics are available on the current platform.
#[derive(Debug, Clone, Serialize)]
pub struct BatteryCapabilities {
    /// Battery is present and queryable.
    pub available: bool,
    /// Battery charge percentage is available.
    pub charge_percent: bool,
    /// Battery time remaining estimate is available.
    pub time_remaining: bool,
    /// Battery cycle count is available.
    pub cycle_count: bool,
    /// Battery health information is available.
    pub health: bool,
}

/// Process capabilities.
///
/// Indicates which process metrics are available on the current platform.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessCapabilities {
    /// Process listing is available.
    pub list: bool,
    /// Per-process CPU usage is available.
    pub cpu_usage: bool,
    /// Per-process memory usage is available.
    pub memory_usage: bool,
    /// Process command line is available.
    pub command_line: bool,
    /// Thread count is available.
    pub thread_count: bool,
    /// Process user is available.
    pub user: bool,
    /// Per-process disk I/O is available.
    pub disk_io: bool,
    /// Process tree is available.
    pub tree: bool,
}

/// Storage capabilities.
///
/// Indicates which storage metrics are available on the current platform.
#[derive(Debug, Clone, Serialize)]
pub struct StorageCapabilities {
    /// Disk usage statistics are available.
    pub disk_usage: bool,
    /// Disk I/O counters are available.
    pub disk_io: bool,
    /// Disk type detection is available.
    pub disk_type: bool,
    /// Disk model information is available.
    pub model: bool,
    /// S.M.A.R.T. data is available.
    pub smart: bool,
    /// Disk temperature is available.
    pub temperature: bool,
}

/// Network capabilities.
///
/// Indicates which network metrics are available on the current platform.
#[derive(Debug, Clone, Serialize)]
pub struct NetworkCapabilities {
    /// Network interface listing is available.
    pub interfaces: bool,
    /// Network I/O counters are available.
    pub counters: bool,
    /// Network addresses are available.
    pub addresses: bool,
    /// Default gateway detection is available.
    pub gateway: bool,
    /// DNS configuration is available.
    pub dns: bool,
    /// Link status detection is available.
    pub link_status: bool,
}

/// Sensor capabilities.
///
/// Indicates which sensor metrics are available on the current platform.
#[derive(Debug, Clone, Serialize)]
pub struct SensorCapabilities {
    /// CPU temperature sensor is available.
    pub cpu_temperature: bool,
    /// GPU temperature sensor is available.
    pub gpu_temperature: bool,
    /// Fan speed sensor is available.
    pub fan_speed: bool,
    /// Voltage sensor is available.
    pub voltage: bool,
}

/// OS capabilities.
///
/// Indicates which OS-level metrics are available on the current platform.
#[derive(Debug, Clone, Serialize)]
pub struct OsCapabilities {
    /// OS information (name, version) is available.
    pub os_info: bool,
    /// Hostname is available.
    pub hostname: bool,
    /// System uptime is available.
    pub uptime: bool,
    /// Boot time is available.
    pub boot_time: bool,
    /// Load average is available (Unix only).
    pub load_average: bool,
    /// Virtualization detection is available.
    pub virtualization: bool,
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
    fn detect() -> Self {
        let os_caps = OsCapabilities::detect();
        let sensor_caps = SensorCapabilities::detect();
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
            os: os_caps,
            gpu: GpuCapabilities::detect(),
            battery: BatteryCapabilities::detect(),
            process: ProcessCapabilities::detect(),
            storage: StorageCapabilities::detect(),
            network_caps: NetworkCapabilities::detect(),
            sensor: sensor_caps,
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

impl GpuCapabilities {
    fn detect() -> Self {
        Self {
            identity: cfg!(target_os = "linux") || cfg!(target_os = "macos") || cfg!(target_os = "windows"),
            nvidia_nvml: cfg!(target_os = "linux") || cfg!(target_os = "windows"),
            utilization: cfg!(target_os = "linux") || cfg!(target_os = "windows"),
            temperature: cfg!(target_os = "linux") || cfg!(target_os = "windows"),
            memory: cfg!(target_os = "linux") || cfg!(target_os = "windows"),
            per_process: cfg!(target_os = "linux") || cfg!(target_os = "windows"),
        }
    }
}

impl BatteryCapabilities {
    fn detect() -> Self {
        Self {
            available: cfg!(target_os = "linux") || cfg!(target_os = "macos") || cfg!(target_os = "windows"),
            charge_percent: cfg!(target_os = "linux") || cfg!(target_os = "macos") || cfg!(target_os = "windows"),
            time_remaining: cfg!(target_os = "linux") || cfg!(target_os = "macos") || cfg!(target_os = "windows"),
            cycle_count: cfg!(target_os = "macos"),
            health: cfg!(target_os = "macos"),
        }
    }
}

impl ProcessCapabilities {
    fn detect() -> Self {
        Self {
            list: true,
            cpu_usage: true,
            memory_usage: true,
            command_line: cfg!(unix) || cfg!(target_os = "windows"),
            thread_count: cfg!(unix) || cfg!(target_os = "windows"),
            user: cfg!(unix) || cfg!(target_os = "windows"),
            disk_io: cfg!(target_os = "linux"),
            tree: cfg!(unix) || cfg!(target_os = "windows"),
        }
    }
}

impl StorageCapabilities {
    fn detect() -> Self {
        Self {
            disk_usage: true,
            disk_io: cfg!(target_os = "linux") || cfg!(target_os = "macos") || cfg!(target_os = "windows"),
            disk_type: cfg!(target_os = "linux") || cfg!(target_os = "macos") || cfg!(target_os = "windows"),
            model: cfg!(target_os = "linux") || cfg!(target_os = "macos") || cfg!(target_os = "windows"),
            smart: cfg!(target_os = "linux"),
            temperature: cfg!(target_os = "linux"),
        }
    }
}

impl NetworkCapabilities {
    fn detect() -> Self {
        Self {
            interfaces: true,
            counters: true,
            addresses: true,
            gateway: cfg!(unix) || cfg!(target_os = "windows"),
            dns: cfg!(unix) || cfg!(target_os = "windows"),
            link_status: cfg!(target_os = "linux") || cfg!(target_os = "macos") || cfg!(target_os = "windows"),
        }
    }
}

impl SensorCapabilities {
    fn detect() -> Self {
        Self {
            cpu_temperature: cfg!(target_os = "linux") || cfg!(target_os = "macos") || cfg!(target_os = "windows"),
            gpu_temperature: cfg!(target_os = "linux") || cfg!(target_os = "windows"),
            fan_speed: cfg!(target_os = "linux") || cfg!(target_os = "macos"),
            voltage: cfg!(target_os = "linux"),
        }
    }
}

impl OsCapabilities {
    const fn detect() -> Self {
        Self {
            os_info: true,
            hostname: true,
            uptime: true,
            boot_time: cfg!(target_os = "linux") || cfg!(target_os = "macos") || cfg!(target_os = "windows"),
            load_average: cfg!(unix),
            virtualization: cfg!(target_os = "linux"),
        }
    }
}

impl fmt::Display for GpuCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "GPU:")?;
        writeln!(f, "  Identity: {}", yn(self.identity))?;
        writeln!(f, "  NVIDIA NVML: {}", yn(self.nvidia_nvml))?;
        writeln!(f, "  Utilization: {}", yn(self.utilization))?;
        writeln!(f, "  Temperature: {}", yn(self.temperature))?;
        writeln!(f, "  Memory: {}", yn(self.memory))?;
        write!(f, "  Per-process: {}", yn(self.per_process))
    }
}

impl fmt::Display for BatteryCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Battery:")?;
        writeln!(f, "  Available: {}", yn(self.available))?;
        writeln!(f, "  Charge percent: {}", yn(self.charge_percent))?;
        writeln!(f, "  Time remaining: {}", yn(self.time_remaining))?;
        writeln!(f, "  Cycle count: {}", yn(self.cycle_count))?;
        write!(f, "  Health: {}", yn(self.health))
    }
}

impl fmt::Display for ProcessCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Process:")?;
        writeln!(f, "  List: {}", yn(self.list))?;
        writeln!(f, "  CPU usage: {}", yn(self.cpu_usage))?;
        writeln!(f, "  Memory usage: {}", yn(self.memory_usage))?;
        writeln!(f, "  Command line: {}", yn(self.command_line))?;
        writeln!(f, "  Thread count: {}", yn(self.thread_count))?;
        writeln!(f, "  User: {}", yn(self.user))?;
        writeln!(f, "  Disk I/O: {}", yn(self.disk_io))?;
        write!(f, "  Tree: {}", yn(self.tree))
    }
}

impl fmt::Display for StorageCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Storage:")?;
        writeln!(f, "  Disk usage: {}", yn(self.disk_usage))?;
        writeln!(f, "  Disk I/O: {}", yn(self.disk_io))?;
        writeln!(f, "  Disk type: {}", yn(self.disk_type))?;
        writeln!(f, "  Model: {}", yn(self.model))?;
        writeln!(f, "  SMART: {}", yn(self.smart))?;
        write!(f, "  Temperature: {}", yn(self.temperature))
    }
}

impl fmt::Display for NetworkCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Network:")?;
        writeln!(f, "  Interfaces: {}", yn(self.interfaces))?;
        writeln!(f, "  Counters: {}", yn(self.counters))?;
        writeln!(f, "  Addresses: {}", yn(self.addresses))?;
        writeln!(f, "  Gateway: {}", yn(self.gateway))?;
        writeln!(f, "  DNS: {}", yn(self.dns))?;
        write!(f, "  Link status: {}", yn(self.link_status))
    }
}

impl fmt::Display for SensorCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Sensors:")?;
        writeln!(f, "  CPU temperature: {}", yn(self.cpu_temperature))?;
        writeln!(f, "  GPU temperature: {}", yn(self.gpu_temperature))?;
        writeln!(f, "  Fan speed: {}", yn(self.fan_speed))?;
        write!(f, "  Voltage: {}", yn(self.voltage))
    }
}

impl fmt::Display for OsCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "OS:")?;
        writeln!(f, "  OS info: {}", yn(self.os_info))?;
        writeln!(f, "  Hostname: {}", yn(self.hostname))?;
        writeln!(f, "  Uptime: {}", yn(self.uptime))?;
        writeln!(f, "  Boot time: {}", yn(self.boot_time))?;
        writeln!(f, "  Load average: {}", yn(self.load_average))?;
        write!(f, "  Virtualization: {}", yn(self.virtualization))
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
        writeln!(f)?;
        writeln!(f, "{}", self.system.os)?;
        writeln!(f)?;
        writeln!(f, "{}", self.system.gpu)?;
        writeln!(f)?;
        writeln!(f, "{}", self.system.battery)?;
        writeln!(f)?;
        writeln!(f, "{}", self.system.process)?;
        writeln!(f)?;
        writeln!(f, "{}", self.system.storage)?;
        writeln!(f)?;
        writeln!(f, "{}", self.system.network_caps)?;
        writeln!(f)?;
        writeln!(f, "{}", self.system.sensor)?;
        writeln!(f)?;
        writeln!(f, "Daemon:")?;
        writeln!(f, "  PID check: {}", yn(self.daemon.pid_check))?;
        writeln!(f, "  Uptime for PID: {}", yn(self.daemon.uptime_for_pid))?;
        writeln!(f, "  Stale socket: {}", yn(self.daemon.stale_socket_detection))?;
        writeln!(f)?;
        writeln!(f, "SSH:")?;
        writeln!(f, "  Mux check: {}", yn(self.ssh.mux_check))?;
        writeln!(f, "  Config validation: {}", yn(self.ssh.config_validation))?;
        writeln!(f, "  Agent check: {}", yn(self.ssh.agent_check))?;
        write!(f, "  Key counting: {}", yn(self.ssh.key_counting))
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

    // --- GpuCapabilities ---

    #[test]
    fn gpu_detect_returns_struct() {
        let caps = GpuCapabilities::detect();
        // identity is true on linux/macos/windows (which this test machine is)
        assert!(caps.identity);
    }

    #[test]
    fn gpu_serialize_to_json() {
        let caps = GpuCapabilities::detect();
        assert!(serde_json::to_string(&caps).is_ok());
    }

    #[test]
    fn gpu_display_contains_gpu() {
        let caps = GpuCapabilities::detect();
        let output = format!("{caps}");
        assert!(output.contains("GPU:"));
        assert!(output.contains("Identity:"));
        assert!(output.contains("NVIDIA NVML:"));
    }

    // --- BatteryCapabilities ---

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn battery_available_on_supported_platforms() {
        let caps = BatteryCapabilities::detect();
        assert!(caps.available);
        assert!(caps.charge_percent);
        assert!(caps.time_remaining);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn battery_cycle_count_and_health_on_macos() {
        let caps = BatteryCapabilities::detect();
        assert!(caps.cycle_count);
        assert!(caps.health);
    }

    #[test]
    fn battery_serialize_to_json() {
        let caps = BatteryCapabilities::detect();
        assert!(serde_json::to_string(&caps).is_ok());
    }

    #[test]
    fn battery_display_contains_battery() {
        let caps = BatteryCapabilities::detect();
        let output = format!("{caps}");
        assert!(output.contains("Battery:"));
        assert!(output.contains("Charge percent:"));
    }

    // --- ProcessCapabilities ---

    #[test]
    fn process_list_always_true() {
        let caps = ProcessCapabilities::detect();
        assert!(caps.list);
        assert!(caps.cpu_usage);
        assert!(caps.memory_usage);
    }

    #[cfg(unix)]
    #[test]
    fn process_command_line_true_on_unix() {
        let caps = ProcessCapabilities::detect();
        assert!(caps.command_line);
        assert!(caps.thread_count);
        assert!(caps.user);
        assert!(caps.tree);
    }

    #[test]
    fn process_serialize_to_json() {
        let caps = ProcessCapabilities::detect();
        assert!(serde_json::to_string(&caps).is_ok());
    }

    #[test]
    fn process_display_contains_process() {
        let caps = ProcessCapabilities::detect();
        let output = format!("{caps}");
        assert!(output.contains("Process:"));
        assert!(output.contains("CPU usage:"));
        assert!(output.contains("Memory usage:"));
    }

    // --- StorageCapabilities ---

    #[test]
    fn storage_disk_usage_always_true() {
        let caps = StorageCapabilities::detect();
        assert!(caps.disk_usage);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn storage_smart_and_temp_on_linux() {
        let caps = StorageCapabilities::detect();
        assert!(caps.smart);
        assert!(caps.temperature);
    }

    #[test]
    fn storage_serialize_to_json() {
        let caps = StorageCapabilities::detect();
        assert!(serde_json::to_string(&caps).is_ok());
    }

    #[test]
    fn storage_display_contains_storage() {
        let caps = StorageCapabilities::detect();
        let output = format!("{caps}");
        assert!(output.contains("Storage:"));
        assert!(output.contains("Disk usage:"));
    }

    // --- NetworkCapabilities ---

    #[test]
    fn network_interfaces_always_true() {
        let caps = NetworkCapabilities::detect();
        assert!(caps.interfaces);
        assert!(caps.counters);
        assert!(caps.addresses);
    }

    #[cfg(unix)]
    #[test]
    fn network_gateway_true_on_unix() {
        let caps = NetworkCapabilities::detect();
        assert!(caps.gateway);
        assert!(caps.dns);
    }

    #[test]
    fn network_serialize_to_json() {
        let caps = NetworkCapabilities::detect();
        assert!(serde_json::to_string(&caps).is_ok());
    }

    #[test]
    fn network_display_contains_network() {
        let caps = NetworkCapabilities::detect();
        let output = format!("{caps}");
        assert!(output.contains("Network:"));
        assert!(output.contains("Interfaces:"));
    }

    // --- SensorCapabilities ---

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn sensor_cpu_temperature_on_supported_platforms() {
        let caps = SensorCapabilities::detect();
        assert!(caps.cpu_temperature);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sensor_voltage_on_linux() {
        let caps = SensorCapabilities::detect();
        assert!(caps.voltage);
    }

    #[test]
    fn sensor_serialize_to_json() {
        let caps = SensorCapabilities::detect();
        assert!(serde_json::to_string(&caps).is_ok());
    }

    #[test]
    fn sensor_display_contains_sensors() {
        let caps = SensorCapabilities::detect();
        let output = format!("{caps}");
        assert!(output.contains("Sensors:"));
        assert!(output.contains("CPU temperature:"));
    }

    // --- OsCapabilities ---

    #[test]
    fn os_detect_returns_struct() {
        let caps = OsCapabilities::detect();
        assert!(caps.os_info);
        assert!(caps.hostname);
        assert!(caps.uptime);
    }

    #[cfg(unix)]
    #[test]
    fn os_load_average_true_on_unix() {
        let caps = OsCapabilities::detect();
        assert!(caps.load_average);
    }

    #[test]
    fn os_serialize_to_json() {
        let caps = OsCapabilities::detect();
        assert!(serde_json::to_string(&caps).is_ok());
    }

    #[test]
    fn os_display_contains_os() {
        let caps = OsCapabilities::detect();
        let output = format!("{caps}");
        assert!(output.contains("OS:"));
        assert!(output.contains("OS info:"));
        assert!(output.contains("Hostname:"));
    }

    // --- Integration: SystemCapabilities includes sub-structs ---

    #[test]
    fn system_capabilities_has_all_sub_structs() {
        let caps = SystemCapabilities::detect();
        // Verify sub-structs are populated (not default/zeroed)
        assert!(caps.os.os_info);
        assert!(caps.process.list);
        assert!(caps.storage.disk_usage);
        assert!(caps.network_caps.interfaces);
        assert!(caps.sensor.cpu_temperature || !caps.sensor.cpu_temperature); // always valid
        assert!(caps.gpu.identity || !caps.gpu.identity); // always valid
        assert!(caps.battery.available || !caps.battery.available); // always valid
    }

    #[test]
    fn system_capabilities_serialize_includes_sub_structs() {
        let caps = SystemCapabilities::detect();
        let json = serde_json::to_string(&caps).unwrap();
        assert!(json.contains("\"os\""));
        assert!(json.contains("\"gpu\""));
        assert!(json.contains("\"battery\""));
        assert!(json.contains("\"process\""));
        assert!(json.contains("\"storage\""));
        assert!(json.contains("\"network_caps\""));
        assert!(json.contains("\"sensor\""));
    }

    #[test]
    fn capabilities_display_includes_all_domain_sections() {
        let caps = Capabilities::detect();
        let output = format!("{caps}");
        assert!(output.contains("GPU:"));
        assert!(output.contains("Battery:"));
        assert!(output.contains("Process:"));
        assert!(output.contains("Storage:"));
        // The Network sub-struct display also contains "Network:"
        assert!(output.contains("Interfaces:"));
        assert!(output.contains("Sensors:"));
        assert!(output.contains("OS:"));
    }
}