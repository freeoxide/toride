//! Domain types shared across the fail2ban crate.

use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Ban entry representing a banned IP address.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BanEntry {
    /// The banned IP address.
    pub ip: IpAddr,
    /// CIDR prefix length (e.g., 32 for IPv4, 128 for IPv6).
    pub prefix: u8,
    /// Timestamp when the ban was applied.
    pub banned_at: DateTime<Utc>,
    /// Timestamp when the ban expires, if applicable.
    pub expires_at: Option<DateTime<Utc>>,
    /// Name of the jail that triggered this ban.
    pub jail_name: String,
    /// Number of failures that triggered the ban.
    pub fail_count: u32,
    /// Last failure timestamp.
    pub last_fail_at: DateTime<Utc>,
    /// Optional reason/description.
    pub reason: Option<String>,
}

/// Platform command definition for different operating systems.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlatformCommands {
    /// Commands used on Linux (iptables/nftables).
    pub linux: Vec<String>,
    /// Commands used on macOS (pf).
    pub macos: Vec<String>,
    /// Commands used on FreeBSD (pf/ipfw).
    pub freebsd: Vec<String>,
}

impl PlatformCommands {
    /// Create a new platform commands definition.
    #[must_use]
    pub const fn new(linux: Vec<String>, macos: Vec<String>, freebsd: Vec<String>) -> Self {
        Self {
            linux,
            macos,
            freebsd,
        }
    }

    /// Get the commands for the current platform.
    ///
    /// Returns an empty slice for unsupported platforms instead of falling back
    /// to the Linux commands.
    #[must_use]
    pub fn for_current_platform(&self) -> &[String] {
        if cfg!(target_os = "linux") {
            &self.linux
        } else if cfg!(target_os = "macos") {
            &self.macos
        } else if cfg!(target_os = "freebsd") {
            &self.freebsd
        } else {
            &[]
        }
    }
}

/// Result of scanning a log file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    /// New ban entries generated from this scan.
    pub new_bans: Vec<BanEntry>,
    /// Total lines scanned.
    pub lines_scanned: u64,
    /// Total matches found.
    pub matches_found: u32,
    /// Time taken for the scan.
    pub scan_duration: std::time::Duration,
}

/// Status information for a single jail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JailStatus {
    /// Name of the jail.
    pub name: String,
    /// Whether the jail is currently active.
    pub active: bool,
    /// List of currently banned IPs.
    pub banned_ips: Vec<BanEntry>,
    /// Total number of bans performed.
    pub total_bans: u64,
    /// Path to the log file being monitored.
    pub log_path: PathBuf,
    /// Current filter pattern.
    pub pattern: String,
}

/// Overall fail2ban status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fail2BanStatus {
    /// Whether the fail2ban daemon is running.
    pub running: bool,
    /// Status of each configured jail.
    pub jails: Vec<JailStatus>,
    /// Path to the configuration file.
    pub config_path: PathBuf,
}

impl fmt::Display for Fail2BanStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Fail2Ban Status: {}", if self.running { "running" } else { "stopped" })?;
        writeln!(f, "Config: {}", self.config_path.display())?;
        writeln!(f, "Jails: {}", self.jails.len())?;
        for jail in &self.jails {
            writeln!(f, "  - {}: {} banned IPs", jail.name, jail.banned_ips.len())?;
        }
        Ok(())
    }
}

/// Execution mode for ban/unban operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionMode {
    /// Execute the action (actually run commands).
    Execute,
    /// Dry run - log what would happen without executing.
    DryRun,
}

impl ExecutionMode {
    /// Returns true if this is a dry run.
    #[must_use]
    pub const fn is_dry_run(self) -> bool {
        matches!(self, Self::DryRun)
    }
}

/// Get the default CIDR prefix length for an IP address.
/// Returns 32 for IPv4, 128 for IPv6.
#[must_use]
pub const fn default_prefix(ip: std::net::IpAddr) -> u8 {
    match ip {
        std::net::IpAddr::V4(_) => 32,
        std::net::IpAddr::V6(_) => 128,
    }
}

#[cfg(test)]
#[path = "types.test.rs"]
mod tests;
