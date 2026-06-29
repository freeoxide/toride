//! Structured report types for monitoring snapshots, anomalies, and alerts.
//!
//! Every monitoring workflow returns one of these report types so callers
//! can inspect results programmatically.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::SystemTime;

// ---------------------------------------------------------------------------
// ConnectionInfo
// ---------------------------------------------------------------------------

/// Information about a single observed outbound connection.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ConnectionInfo {
    /// Source IP address.
    pub src: IpAddr,
    /// Source port.
    pub src_port: u16,
    /// Destination IP address.
    pub dst: IpAddr,
    /// Destination port.
    pub dst_port: u16,
    /// Protocol (e.g. `"tcp"`, `"udp"`).
    pub protocol: String,
    /// Connection state (e.g. `"ESTABLISHED"`, `"TIME_WAIT"`).
    pub state: String,
    /// Bytes transferred (if available from conntrack).
    pub bytes: Option<u64>,
    /// Packets transferred (if available from conntrack).
    pub packets: Option<u64>,
}

// ---------------------------------------------------------------------------
// MonitorReport
// ---------------------------------------------------------------------------

/// A snapshot of current outbound connection state.
///
/// Contains parsed connection data from `ss`, `conntrack`, and iptables logs,
/// along with aggregated statistics.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MonitorReport {
    /// Timestamp when the snapshot was taken.
    pub timestamp: SystemTime,
    /// All observed outbound connections.
    pub connections: Vec<ConnectionInfo>,
    /// Total number of connections observed.
    pub total_connections: u64,
    /// Number of unique destination IPs.
    pub unique_destinations: u64,
    /// Connection count grouped by protocol.
    pub by_protocol: HashMap<String, u64>,
    /// Connection count grouped by destination port.
    pub by_port: HashMap<u16, u64>,
    /// Connection count grouped by state.
    pub by_state: HashMap<String, u64>,
    /// Total bytes transferred (if available).
    pub total_bytes: Option<u64>,
    /// Total packets transferred (if available).
    pub total_packets: Option<u64>,
}

impl MonitorReport {
    /// Create an empty report with the current timestamp.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            timestamp: SystemTime::now(),
            connections: Vec::new(),
            total_connections: 0,
            unique_destinations: 0,
            by_protocol: HashMap::new(),
            by_port: HashMap::new(),
            by_state: HashMap::new(),
            total_bytes: None,
            total_packets: None,
        }
    }

    /// Returns `true` if no connections were observed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }
}

// ---------------------------------------------------------------------------
// AnomalyReport
// ---------------------------------------------------------------------------

/// Report of detected anomalies in outbound traffic.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AnomalyReport {
    /// Timestamp when the anomaly detection was performed.
    pub timestamp: SystemTime,
    /// Individual anomaly findings.
    pub findings: Vec<AnomalyFinding>,
    /// The monitoring snapshot that was analysed.
    pub snapshot: MonitorReport,
}

impl AnomalyReport {
    /// Create an anomaly report with no findings.
    #[must_use]
    pub fn empty(snapshot: MonitorReport) -> Self {
        Self {
            timestamp: SystemTime::now(),
            findings: Vec::new(),
            snapshot,
        }
    }

    /// Returns `true` if no anomalies were detected.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// Returns `true` if any anomaly has critical severity.
    #[must_use]
    pub fn has_critical(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == AnomalySeverity::Critical)
    }
}

// ---------------------------------------------------------------------------
// AnomalySeverity
// ---------------------------------------------------------------------------

/// Severity level for anomaly findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AnomalySeverity {
    /// Informational; within normal variance.
    Info,
    /// Slightly above threshold; worth monitoring.
    Warning,
    /// Significantly above threshold; investigate.
    Error,
    /// Critical anomaly; immediate action recommended.
    Critical,
}

impl std::fmt::Display for AnomalySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARNING"),
            Self::Error => write!(f, "ERROR"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ---------------------------------------------------------------------------
// AnomalyFinding
// ---------------------------------------------------------------------------

/// A single anomaly detected in outbound traffic.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AnomalyFinding {
    /// Machine-readable identifier (e.g. `"anomaly.connection-volume"`).
    pub id: String,
    /// Severity of the anomaly.
    pub severity: AnomalySeverity,
    /// Short human-readable description.
    pub title: String,
    /// Observed value that triggered the anomaly.
    pub observed_value: String,
    /// Threshold that was exceeded.
    pub threshold: String,
    /// Suggested remediation, if applicable.
    pub fix: Option<String>,
}

impl AnomalyFinding {
    /// Create a new anomaly finding.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        severity: AnomalySeverity,
        title: impl Into<String>,
        observed_value: impl Into<String>,
        threshold: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            severity,
            title: title.into(),
            observed_value: observed_value.into(),
            threshold: threshold.into(),
            fix: None,
        }
    }

    /// Attach a suggested fix action.
    #[must_use]
    pub fn fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
}

// ---------------------------------------------------------------------------
// AlertReport
// ---------------------------------------------------------------------------

/// Report of an alert that was dispatched.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AlertReport {
    /// The anomaly finding that triggered the alert.
    pub finding: AnomalyFinding,
    /// Target to which the alert was dispatched.
    pub target: String,
    /// Whether the alert was successfully sent.
    pub dispatched: bool,
    /// Error message if dispatch failed.
    pub error: Option<String>,
}
