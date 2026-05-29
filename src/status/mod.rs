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

pub mod daemon;
pub mod ssh;
pub mod system;

use std::fmt;

pub use daemon::DaemonStatus;
use serde::Serialize;
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
    pub system: SystemStatus,
    pub daemon: DaemonStatus,
    pub ssh: SshStatus,
}

impl TorideStatus {
    /// Collect a point-in-time snapshot of all subsystems.
    ///
    /// Each subsystem is collected independently — if one fails, its fields
    /// will contain `None` values rather than propagating the error.
    pub fn collect() -> Self {
        Self {
            system: SystemStatus::collect(),
            daemon: DaemonStatus::collect(),
            ssh: SshStatus::collect(),
        }
    }
}

impl fmt::Display for TorideStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Toride Status ===")?;
        write!(f, "{}", self.system)?;
        write!(f, "{}", self.daemon)?;
        write!(f, "{}", self.ssh)?;
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
    }

    #[test]
    fn serialize_to_json_succeeds() {
        let status = TorideStatus::collect();
        let json = serde_json::to_string(&status);
        assert!(json.is_ok(), "serialization should succeed: {:?}", json.err());
    }
}
