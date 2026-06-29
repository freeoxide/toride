//! Convert `toride-monitor` library types to UI presentation types.
//!
//! This is the ONLY module in the `toride` crate that imports
//! `toride_monitor` types — mirroring `fail2ban_convert.rs`'s role as the
//! single boundary between backend and presentation. Each function handles
//! errors gracefully: malformed input is skipped with a `tracing::warn!` and a
//! placeholder, never propagated (the read-only section must never crash the
//! TUI).

use crate::ui::screens::toride_monitor::{
    AnomalyEntry, ConnectionEntry, FindingEntry, PortEntry, SnapshotSummary,
};

/// Map a backend [`toride_monitor::report::AnomalySeverity`] to a lowercase
/// string used by the presentation layer: `"info" | "warning" | "error" |
/// "critical"`. Kept here so the TUI never imports the Severity enum directly.
fn severity_str(s: toride_monitor::report::AnomalySeverity) -> &'static str {
    use toride_monitor::report::AnomalySeverity;
    match s {
        AnomalySeverity::Info => "info",
        AnomalySeverity::Warning => "warning",
        AnomalySeverity::Error => "error",
        AnomalySeverity::Critical => "critical",
    }
}

/// Convert a backend snapshot [`toride_monitor::report::MonitorReport`] into
/// the presentation [`SnapshotSummary`].
///
/// Connection / destination counts are taken directly from the backend's
/// aggregated fields. Bytes/packets are forwarded as-is (already `Option`).
pub fn convert_snapshot(report: &toride_monitor::report::MonitorReport) -> SnapshotSummary {
    SnapshotSummary {
        total_connections: report.total_connections,
        unique_destinations: report.unique_destinations,
        total_bytes: report.total_bytes,
        total_packets: report.total_packets,
    }
}

/// Convert backend outbound connections into presentation rows.
///
/// Each [`ConnectionInfo`] maps 1:1. Source/destination are formatted as
/// `ip:port`; an unset port renders as just the IP. Protocol/state are cloned
/// verbatim (the backend already lower-cases protocol and upper-cases state).
pub fn convert_connections(
    conns: &[toride_monitor::report::ConnectionInfo],
) -> Vec<ConnectionEntry> {
    conns
        .iter()
        .map(|c| ConnectionEntry {
            protocol: if c.protocol.is_empty() {
                "?".into()
            } else {
                c.protocol.clone()
            },
            src: format_addr_port(c.src, c.src_port),
            dst: format_addr_port(c.dst, c.dst_port),
            state: if c.state.is_empty() {
                "—".into()
            } else {
                c.state.clone()
            },
            bytes: c.bytes,
        })
        .collect()
}

/// Format an `IpAddr:port` pair, mirroring the backend's own `format_addr`
/// (IPv6 wrapped in brackets). A zero port renders without a port suffix so a
/// UDP socket with no remote peer doesn't show a misleading `:0`.
fn format_addr_port(addr: std::net::IpAddr, port: u16) -> String {
    if port == 0 {
        addr.to_string()
    } else {
        match addr {
            std::net::IpAddr::V6(_) => format!("[{addr}]:{port}"),
            std::net::IpAddr::V4(_) => format!("{addr}:{port}"),
        }
    }
}

/// Convert backend port entries into presentation rows.
///
/// Each backend [`toride_monitor::ports::PortEntry`] maps 1:1. Protocol / IP
/// version / state become lowercase / `IPv4`/`IPv6` / upper-case labels via the
/// backend's own `Display` impls (rendered through `to_string`). Process name
/// and PID are forwarded as-is.
pub fn convert_ports(ports: &[toride_monitor::ports::PortEntry]) -> Vec<PortEntry> {
    ports
        .iter()
        .map(|p| PortEntry {
            protocol: p.protocol.to_string(),
            ip_version: p.ip_version.to_string(),
            local_addr: p.local_addr.to_string(),
            local_port: p.local_port,
            state: p.state.to_string(),
            process_name: p.process_name.clone(),
            pid: p.pid,
        })
        .collect()
}

/// Convert backend anomaly findings to UI entries (from `detect()`).
///
/// Every finding maps 1:1. An empty `id` or `title` is logged and the entry is
/// still produced with a placeholder so the row count matches the backend.
pub fn convert_anomalies(
    findings: Vec<toride_monitor::report::AnomalyFinding>,
) -> Vec<AnomalyEntry> {
    findings
        .into_iter()
        .map(|f| {
            if f.id.is_empty() || f.title.is_empty() {
                tracing::warn!(
                    "monitor anomaly with empty id/title: id={:?} title={:?}",
                    f.id,
                    f.title
                );
            }
            AnomalyEntry {
                id: if f.id.is_empty() {
                    "(unknown)".into()
                } else {
                    f.id
                },
                severity: severity_str(f.severity).to_string(),
                title: if f.title.is_empty() {
                    "(no title)".into()
                } else {
                    f.title
                },
                observed: f.observed_value,
                threshold: f.threshold,
                fix: f.fix,
            }
        })
        .collect()
}

/// Convert backend doctor findings (the same `AnomalyFinding` type) to UI
/// finding entries.
///
/// Every finding maps 1:1. The doctor's `observed_value` / `threshold` fields
/// carry the contextual detail (e.g. "Expected at: /usr/sbin/iptables"), so
/// they are merged into the `detail` string. An empty `id` or `title` is
/// logged and the entry is still produced with a placeholder.
pub fn convert_findings(
    findings: Vec<toride_monitor::report::AnomalyFinding>,
) -> Vec<FindingEntry> {
    findings
        .into_iter()
        .map(|f| {
            if f.id.is_empty() || f.title.is_empty() {
                tracing::warn!(
                    "monitor finding with empty id/title: id={:?} title={:?}",
                    f.id,
                    f.title
                );
            }
            // Merge observed/threshold into a single detail line, eliding
            // empty halves so we don't render a bare separator.
            let detail = match (f.observed_value.as_str(), f.threshold.as_str()) {
                ("", "") => String::new(),
                ("", t) => format!("threshold: {t}"),
                (o, "") => o.to_string(),
                (o, t) => format!("{o}  ·  threshold: {t}"),
            };
            FindingEntry {
                id: if f.id.is_empty() {
                    "(unknown)".into()
                } else {
                    f.id
                },
                severity: severity_str(f.severity).to_string(),
                title: if f.title.is_empty() {
                    "(no title)".into()
                } else {
                    f.title
                },
                detail,
                fix: f.fix,
            }
        })
        .collect()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use toride_monitor::ports::{IpVersion, PortProtocol, PortState};
    use toride_monitor::report::{AnomalyFinding, AnomalySeverity, ConnectionInfo, MonitorReport};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // ── convert_snapshot ──────────────────────────────────────────────────────

    #[test]
    fn convert_snapshot_empty_report() {
        let report = MonitorReport::empty();
        let summary = convert_snapshot(&report);
        assert_eq!(summary.total_connections, 0);
        assert_eq!(summary.unique_destinations, 0);
        assert!(summary.total_bytes.is_none());
        assert!(summary.total_packets.is_none());
    }

    #[test]
    fn convert_snapshot_forwards_counts() {
        let mut report = MonitorReport::empty();
        report.total_connections = 7;
        report.unique_destinations = 4;
        report.total_bytes = Some(1234);
        report.total_packets = Some(56);
        let summary = convert_snapshot(&report);
        assert_eq!(summary.total_connections, 7);
        assert_eq!(summary.unique_destinations, 4);
        assert_eq!(summary.total_bytes, Some(1234));
        assert_eq!(summary.total_packets, Some(56));
    }

    // ── convert_connections ───────────────────────────────────────────────────

    #[test]
    fn convert_connections_empty() {
        assert!(convert_connections(&[]).is_empty());
    }

    #[test]
    fn convert_connections_maps_ipv4_and_ipv6() {
        let conns = vec![
            ConnectionInfo {
                src: ip("10.0.0.2"),
                src_port: 54321,
                dst: ip("93.184.216.34"),
                dst_port: 443,
                protocol: "tcp".into(),
                state: "ESTABLISHED".into(),
                bytes: Some(100),
                packets: Some(2),
            },
            ConnectionInfo {
                src: ip("::1"),
                src_port: 0,
                dst: ip("2001:db8::1"),
                dst_port: 53,
                protocol: "udp".into(),
                state: String::new(),
                bytes: None,
                packets: None,
            },
        ];
        let rows = convert_connections(&conns);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].src, "10.0.0.2:54321");
        assert_eq!(rows[0].dst, "93.184.216.34:443");
        assert_eq!(rows[0].state, "ESTABLISHED");
        assert_eq!(rows[0].bytes, Some(100));
        // IPv6: zero src port renders without suffix, IPv6 dst wrapped in [].
        assert_eq!(rows[1].src, "::1");
        assert_eq!(rows[1].dst, "[2001:db8::1]:53");
        // Empty state renders as a placeholder dash (never blank).
        assert_eq!(rows[1].state, "—");
    }

    #[test]
    fn convert_connections_empty_protocol_becomes_placeholder() {
        let conn = ConnectionInfo {
            src: ip("1.2.3.4"),
            src_port: 1,
            dst: ip("5.6.7.8"),
            dst_port: 2,
            protocol: String::new(),
            state: "X".into(),
            bytes: None,
            packets: None,
        };
        let rows = convert_connections(&[conn]);
        assert_eq!(rows[0].protocol, "?");
    }

    #[test]
    fn convert_connections_zero_dst_port_renders_bare_ip() {
        // A zero dst_port (e.g. a UDP socket with no remote peer) must render
        // the destination WITHOUT a misleading `:0` suffix. The port is no
        // longer carried as a separate field — it lives only inside the `dst`
        // string — so this pins the bare-IP contract directly.
        let conn = ConnectionInfo {
            src: ip("10.0.0.2"),
            src_port: 54321,
            dst: ip("0.0.0.0"),
            dst_port: 0,
            protocol: "udp".into(),
            state: "ESTABLISHED".into(),
            bytes: None,
            packets: None,
        };
        let rows = convert_connections(&[conn]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].dst, "0.0.0.0", "zero port must drop the suffix");
        assert!(!rows[0].dst.ends_with(":0"));
        assert!(!rows[0].dst.ends_with("]:0"));
    }

    // ── convert_ports ─────────────────────────────────────────────────────────

    #[test]
    fn convert_ports_maps_protocol_and_state_labels() {
        let ports = vec![toride_monitor::ports::PortEntry {
            protocol: PortProtocol::Tcp,
            ip_version: IpVersion::V4,
            local_addr: ip("0.0.0.0"),
            local_port: 22,
            remote_addr: ip("0.0.0.0"),
            remote_port: 0,
            state: PortState::Listen,
            process_name: Some("sshd".into()),
            pid: Some(842),
        }];
        let rows = convert_ports(&ports);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].protocol, "tcp");
        assert_eq!(rows[0].ip_version, "IPv4");
        assert_eq!(rows[0].local_addr, "0.0.0.0");
        assert_eq!(rows[0].local_port, 22);
        assert_eq!(rows[0].state, "LISTEN");
        assert_eq!(rows[0].process_name.as_deref(), Some("sshd"));
        assert_eq!(rows[0].pid, Some(842));
    }

    #[test]
    fn convert_ports_empty() {
        assert!(convert_ports(&[]).is_empty());
    }

    #[test]
    fn convert_ports_maps_one_to_one_no_filter() {
        // Pins the documented contract: convert_ports maps every backend
        // PortEntry 1:1 with NO defensive filter, mirroring the fail2ban
        // convert. This is safe because `PortEntry.local_addr` is a typed
        // `IpAddr` whose `Display` is always well-formed (no placeholder/empty
        // rows are possible from the structured netstat2 source). A row count
        // mismatch would be a regression of that contract.
        let ports = vec![
            toride_monitor::ports::PortEntry {
                protocol: PortProtocol::Tcp,
                ip_version: IpVersion::V4,
                local_addr: ip("0.0.0.0"),
                local_port: 22,
                remote_addr: ip("0.0.0.0"),
                remote_port: 0,
                state: PortState::Listen,
                process_name: Some("sshd".into()),
                pid: Some(842),
            },
            toride_monitor::ports::PortEntry {
                protocol: PortProtocol::Udp,
                ip_version: IpVersion::V6,
                local_addr: ip("::"),
                local_port: 5353,
                remote_addr: ip("::"),
                remote_port: 0,
                state: PortState::Unknown("UDP".into()),
                process_name: None,
                pid: None,
            },
        ];
        let rows = convert_ports(&ports);
        assert_eq!(rows.len(), ports.len(), "1:1 mapping — no rows filtered");
        // IPv6 local_addr Display is well-formed (no brackets, no port) — the
        // asymmetry with convert_connections (which guards empty
        // protocol/state) is harmless because the typed IpAddr cannot be empty.
        assert_eq!(rows[1].local_addr, "::");
        assert_eq!(rows[1].ip_version, "IPv6");
    }

    // ── convert_anomalies ─────────────────────────────────────────────────────

    #[test]
    fn convert_anomalies_empty() {
        assert!(convert_anomalies(Vec::new()).is_empty());
    }

    #[test]
    fn convert_anomalies_maps_severity() {
        let findings = vec![
            AnomalyFinding::new("a", AnomalySeverity::Critical, "t1", "o", "th"),
            AnomalyFinding::new("b", AnomalySeverity::Error, "t2", "o", "th"),
            AnomalyFinding::new("c", AnomalySeverity::Warning, "t3", "o", "th"),
            AnomalyFinding::new("d", AnomalySeverity::Info, "t4", "o", "th"),
        ];
        let entries = convert_anomalies(findings);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].severity, "critical");
        assert_eq!(entries[1].severity, "error");
        assert_eq!(entries[2].severity, "warning");
        assert_eq!(entries[3].severity, "info");
    }

    #[test]
    fn convert_anomalies_preserves_observed_threshold_fix() {
        let f = AnomalyFinding::new("id", AnomalySeverity::Warning, "title", "obs", "thr")
            .fix("the fix");
        let entries = convert_anomalies(vec![f]);
        assert_eq!(entries[0].observed, "obs");
        assert_eq!(entries[0].threshold, "thr");
        assert_eq!(entries[0].fix.as_deref(), Some("the fix"));
    }

    #[test]
    fn convert_anomalies_placeholder_for_empty_fields() {
        let f = AnomalyFinding::new("", AnomalySeverity::Info, "", "o", "th");
        let entries = convert_anomalies(vec![f]);
        assert_eq!(entries[0].id, "(unknown)");
        assert_eq!(entries[0].title, "(no title)");
    }

    // ── convert_findings ──────────────────────────────────────────────────────

    #[test]
    fn convert_findings_empty() {
        assert!(convert_findings(Vec::new()).is_empty());
    }

    #[test]
    fn convert_findings_merges_observed_and_threshold_into_detail() {
        let f = AnomalyFinding::new(
            "id",
            AnomalySeverity::Critical,
            "title",
            "observed",
            "thresh",
        )
        .fix("fix it");
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].severity, "critical");
        assert_eq!(entries[0].detail, "observed  ·  threshold: thresh");
        assert_eq!(entries[0].fix.as_deref(), Some("fix it"));
    }

    #[test]
    fn convert_findings_detail_omits_empty_halves() {
        // Only observed, no threshold.
        let f = AnomalyFinding::new("id", AnomalySeverity::Info, "title", "observed", "");
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].detail, "observed");

        // Only threshold, no observed.
        let f = AnomalyFinding::new("id", AnomalySeverity::Info, "title", "", "thresh");
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].detail, "threshold: thresh");

        // Neither.
        let f = AnomalyFinding::new("id", AnomalySeverity::Info, "title", "", "");
        let entries = convert_findings(vec![f]);
        assert!(entries[0].detail.is_empty());
    }

    #[test]
    fn convert_findings_placeholder_for_empty_fields() {
        let f = AnomalyFinding::new("", AnomalySeverity::Info, "", "", "");
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].id, "(unknown)");
        assert_eq!(entries[0].title, "(no title)");
    }

    // ── format_addr_port ──────────────────────────────────────────────────────

    #[test]
    fn format_addr_port_zero_port_omits_suffix() {
        assert_eq!(format_addr_port(ip("1.2.3.4"), 0), "1.2.3.4");
        assert_eq!(format_addr_port(ip("::1"), 0), "::1");
    }

    #[test]
    fn format_addr_port_wraps_ipv6() {
        assert_eq!(
            format_addr_port(ip("2001:db8::1"), 443),
            "[2001:db8::1]:443"
        );
        assert_eq!(format_addr_port(ip("10.0.0.1"), 443), "10.0.0.1:443");
    }
}
