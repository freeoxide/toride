//! Capability detection for the status subsystem.
//!
//! Reports which metrics are available on the current platform.

use serde::Serialize;

/// Top-level capabilities report.
#[derive(Debug, Clone, Serialize)]
pub struct Capabilities {
    pub system: SystemCapabilities,
    pub daemon: DaemonCapabilities,
    pub ssh: SshCapabilities,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemCapabilities {
    pub cpu_usage: bool,
    pub per_core_cpu: bool,
    pub memory: bool,
    pub swap: bool,
    pub disk: bool,
    pub network: bool,
    pub load_average: bool,
    pub uptime: bool,
    pub hostname: bool,
    pub os_info: bool,
    pub sensors: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DaemonCapabilities {
    pub pid_check: bool,
    pub uptime_for_pid: bool,
    pub stale_socket_detection: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SshCapabilities {
    pub mux_check: bool,
    pub config_validation: bool,
    pub agent_check: bool,
    pub key_counting: bool,
}

impl Capabilities {
    /// Detect capabilities of the current platform.
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
            sensors: cfg!(target_os = "linux"),
        }
    }
}

impl DaemonCapabilities {
    fn detect() -> Self {
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

fn yn(v: bool) -> &'static str { if v { "yes" } else { "no" } }

use std::fmt;

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
        let output = format!("{}", caps);
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
}