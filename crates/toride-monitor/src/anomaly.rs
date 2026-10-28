//! Anomaly detection heuristics for outbound traffic.
//!
//! Provides [`AnomalyDetector`] which evaluates a [`MonitorReport`] against
//! configured thresholds and produces an [`AnomalyReport`] with findings.

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::SystemTime;

use crate::Result;
use crate::report::{
    AnomalyFinding, AnomalyReport, AnomalySeverity, ConnectionInfo, MonitorReport,
};
use crate::spec::AnomalyThreshold;

/// Anomaly detector for outbound traffic.
///
/// Evaluates connection data against configured thresholds and produces
/// findings when thresholds are exceeded.
pub struct AnomalyDetector {
    /// Thresholds to evaluate against.
    thresholds: AnomalyThreshold,
}

impl AnomalyDetector {
    /// Create a new detector with the given thresholds.
    #[must_use]
    pub fn new(thresholds: AnomalyThreshold) -> Self {
        Self { thresholds }
    }

    /// Create a detector with default thresholds.
    #[must_use]
    pub fn default_detector() -> Self {
        Self {
            thresholds: AnomalyThreshold::default(),
        }
    }

    /// Analyse a monitoring snapshot and produce an anomaly report.
    ///
    /// Checks for:
    /// - **Connection volume**: total connections exceeding threshold.
    /// - **Destination diversity**: unique destination IPs exceeding threshold.
    /// - **Bandwidth**: total bytes transferred exceeding threshold.
    /// - **Packet rate**: estimated packets per second exceeding threshold.
    /// - **Port scan pattern**: unusually many unique destination ports from
    ///   a single source.
    ///
    /// Deep-clones the report into the returned [`AnomalyReport`]; use
    /// [`detect_into`](Self::detect_into) to move an owned snapshot instead.
    ///
    /// # Errors
    ///
    /// This method does not return errors; anomaly detection is designed to
    /// be resilient and always produce a report. The `Result` wrapper is kept
    /// for API consistency with future extensions.
    pub fn detect(&self, report: &MonitorReport) -> Result<AnomalyReport> {
        self.detect_into(report.clone())
    }

    /// Analyse an owned monitoring snapshot, moving it behind the report's
    /// shared [`Arc`](std::sync::Arc) instead of cloning it.
    ///
    /// Runs the same checks as [`detect`](Self::detect).
    ///
    /// # Errors
    ///
    /// This method does not return errors; detection always produces a report.
    pub fn detect_into(&self, report: MonitorReport) -> Result<AnomalyReport> {
        let mut findings = Vec::new();

        // Check total connection volume.
        if report.total_connections > self.thresholds.max_connections {
            let severity =
                severity_ratio(report.total_connections, self.thresholds.max_connections);
            findings.push(
                AnomalyFinding::new(
                    "anomaly.connection-volume",
                    severity,
                    "Outbound connection volume exceeds threshold",
                    format!("{} connections", report.total_connections),
                    format!("{} connections", self.thresholds.max_connections),
                )
                .fix("Investigate processes with high outbound connection counts."),
            );
        }

        // Check destination diversity.
        if report.unique_destinations > self.thresholds.max_unique_destinations {
            let severity = severity_ratio(
                report.unique_destinations,
                self.thresholds.max_unique_destinations,
            );
            findings.push(
                AnomalyFinding::new(
                    "anomaly.destination-diversity",
                    severity,
                    "Number of unique destination IPs exceeds threshold",
                    format!("{} unique destinations", report.unique_destinations),
                    format!(
                        "{} unique destinations",
                        self.thresholds.max_unique_destinations
                    ),
                )
                .fix("Check for DNS tunneling, C2 callbacks, or data exfiltration."),
            );
        }

        // Check bandwidth.
        if let Some(total_bytes) = report.total_bytes
            && total_bytes > self.thresholds.max_bytes
        {
            let severity = severity_ratio(total_bytes, self.thresholds.max_bytes);
            findings.push(
                AnomalyFinding::new(
                    "anomaly.bandwidth",
                    severity,
                    "Outbound bandwidth exceeds threshold",
                    format_bytes(total_bytes),
                    format_bytes(self.thresholds.max_bytes),
                )
                .fix("Identify processes consuming the most bandwidth."),
            );
        }

        // Check packet rate.
        if let Some(total_packets) = report.total_packets {
            let window_secs = self.thresholds.window.as_secs().max(1);
            let pps = total_packets / window_secs;
            if pps > self.thresholds.max_packets_per_second {
                let severity = severity_ratio(pps, self.thresholds.max_packets_per_second);
                findings.push(
                    AnomalyFinding::new(
                        "anomaly.packet-rate",
                        severity,
                        "Outbound packet rate exceeds threshold",
                        format!("{pps} packets/sec"),
                        format!("{} packets/sec", self.thresholds.max_packets_per_second),
                    )
                    .fix("Investigate processes generating high packet rates."),
                );
            }
        }

        // Check for port scan patterns.
        let max_ports = self.thresholds.max_unique_dest_ports_per_source;
        if let Some((src_ip, port_count)) = detect_port_scan(&report.connections, max_ports) {
            findings.push(
                AnomalyFinding::new(
                    "anomaly.port-scan-pattern",
                    AnomalySeverity::Error,
                    "Potential port scan detected",
                    format!("{port_count} unique ports from {src_ip}"),
                    format!("{max_ports} unique ports per source"),
                )
                .fix("Investigate the source process and verify legitimate activity."),
            );
        }

        Ok(AnomalyReport {
            timestamp: SystemTime::now(),
            findings,
            snapshot: std::sync::Arc::new(report),
        })
    }
}

/// Determine severity based on how far the observed value exceeds the threshold.
#[expect(
    clippy::cast_precision_loss,
    reason = "ratio comparison tolerates f64 mantissa loss; values are connection/byte counts far below 2^52"
)]
fn severity_ratio(observed: u64, threshold: u64) -> AnomalySeverity {
    let ratio = observed as f64 / threshold as f64;
    if ratio >= 3.0 {
        AnomalySeverity::Critical
    } else if ratio >= 2.0 {
        AnomalySeverity::Error
    } else {
        AnomalySeverity::Warning
    }
}

/// Detect a port scan pattern: a single source IP connecting to more than
/// `max_unique_ports` unique destination ports.
fn detect_port_scan(
    connections: &[ConnectionInfo],
    max_unique_ports: usize,
) -> Option<(IpAddr, usize)> {
    use std::collections::HashMap;

    let mut src_ports: HashMap<IpAddr, HashSet<u16>> = HashMap::new();
    for conn in connections {
        src_ports.entry(conn.src).or_default().insert(conn.dst_port);
    }

    src_ports
        .into_iter()
        .find(|(_, ports)| ports.len() > max_unique_ports)
        .map(|(ip, ports)| (ip, ports.len()))
}

/// Format a byte count as a human-readable string.
#[expect(
    clippy::cast_precision_loss,
    reason = "human-readable byte formatting only needs ~3 significant digits; values below 2^52 are exact"
)]
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_report_produces_no_findings() {
        let detector = AnomalyDetector::default_detector();
        let report = MonitorReport::empty();
        let result = detector.detect(&report).unwrap();
        assert!(result.is_clean());
    }

    #[test]
    fn port_scan_threshold_is_tunable() {
        let connections: Vec<ConnectionInfo> = (1..=5)
            .map(|i| ConnectionInfo {
                src: "10.0.0.1".parse().expect("src ip"),
                src_port: 40_000,
                dst: "192.0.2.1".parse().expect("dst ip"),
                dst_port: 1000 + i,
                protocol: "tcp".to_owned(),
                state: "SYN_SENT".to_owned(),
                bytes: None,
                packets: None,
            })
            .collect();
        let mut report = MonitorReport::empty();
        report.connections = connections;
        report.total_connections = 5;

        let default = AnomalyDetector::default_detector();
        assert!(
            default.detect(&report).unwrap().is_clean(),
            "5 ports is under the default 100 threshold"
        );

        let tuned = AnomalyDetector::new(crate::spec::AnomalyThreshold {
            max_unique_dest_ports_per_source: 3,
            ..crate::spec::AnomalyThreshold::default()
        });
        let report = tuned.detect(&report).unwrap();
        let finding = report
            .findings
            .iter()
            .find(|f| f.id == "anomaly.port-scan-pattern")
            .expect("tuned threshold must flag 5 ports");
        assert_eq!(finding.threshold, "3 unique ports per source");
    }

    #[test]
    fn detect_into_shares_the_snapshot() {
        let detector = AnomalyDetector::default_detector();
        let report = MonitorReport::empty();
        let result = detector.detect_into(report).unwrap();
        assert!(std::sync::Arc::strong_count(&result.snapshot) >= 1);
        assert!(result.is_clean());
    }

    #[test]
    fn format_bytes_units() {
        assert!(format_bytes(500).ends_with('B'));
        assert!(format_bytes(2048).contains("KB"));
        assert!(format_bytes(5 * 1024 * 1024).contains("MB"));
        assert!(format_bytes(3 * 1024 * 1024 * 1024).contains("GB"));
    }
}
