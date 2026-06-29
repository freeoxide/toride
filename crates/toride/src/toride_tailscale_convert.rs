//! Convert `toride-tailscale` library types to UI presentation types.
//!
//! This is the ONLY module in the `toride` crate that imports
//! `toride_tailscale` types — mirroring [`fail2ban_convert`](crate::fail2ban_convert)'s
//! role as the single boundary between backend and presentation. Each function handles
//! errors gracefully: malformed input (empty ids / messages, unparseable latencies) is
//! skipped with a `tracing::warn!` and a placeholder, never propagated (the read-only
//! Tailscale section must never crash the TUI).

use crate::ui::screens::toride_tailscale::{
    DerpLatencyEntry, DnsInfo, PeerEntry, PortMapEntry, TailscaleFindingEntry,
};

/// Map a backend [`toride_tailscale::doctor::Severity`] to a lowercase string used by
/// the presentation layer: `"ok" | "info" | "warning" | "critical"`.
///
/// Kept here so the TUI never imports the Severity enum directly (mirrors
/// `fail2ban_convert::severity_str`). Note the Tailscale backend only has four severity
/// levels (no `error` — its `Severity` is `Ok | Info | Warning | Critical`), unlike
/// fail2ban/cloud which also have `Error`.
fn severity_str(s: toride_tailscale::doctor::Severity) -> &'static str {
    use toride_tailscale::doctor::Severity;
    match s {
        Severity::Ok => "ok",
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Critical => "critical",
    }
}

// ── Status / report ─────────────────────────────────────────────────────────

/// Presentation-level view of the local node's status, derived from a
/// [`toride_tailscale::report::TailscaleReport`]. Owns all strings so it crosses the
/// collection-task boundary cleanly.
#[derive(Clone, Debug)]
pub struct NodeStatusInfo {
    /// Whether the node is connected to the tailnet.
    pub connected: bool,
    /// Hostname as seen in the tailnet.
    pub node_name: String,
    /// Tailnet name (e.g. `example.com`).
    pub tailnet: String,
    /// Tailscale IP addresses assigned to this node.
    pub ip_addresses: Vec<String>,
    /// The exit node this node is using, if any.
    pub exit_node: Option<String>,
    /// Whether `MagicDNS` is enabled.
    pub dns_enabled: bool,
}

/// Convert a backend [`TailscaleReport`] into presentation [`NodeStatusInfo`].
///
/// Empty `node_name` / `tailnet` get a placeholder so the status panel always shows
/// something. IPs are passed through unchanged (the backend already filtered them).
///
/// [`TailscaleReport`]: toride_tailscale::report::TailscaleReport
pub fn convert_status(report: toride_tailscale::report::TailscaleReport) -> NodeStatusInfo {
    NodeStatusInfo {
        connected: report.connected,
        node_name: if report.node_name.is_empty() {
            tracing::warn!("tailscale status: empty node_name");
            "(unknown)".into()
        } else {
            report.node_name
        },
        tailnet: if report.tailnet.is_empty() {
            tracing::warn!("tailscale status: empty tailnet");
            "(unknown)".into()
        } else {
            report.tailnet
        },
        ip_addresses: report.ip_addresses,
        exit_node: report.exit_node,
        dns_enabled: report.dns_enabled,
    }
}

// ── Peers ───────────────────────────────────────────────────────────────────

/// Convert the backend peer list into UI rows.
///
/// Every [`PeerInfo`] maps 1:1. An empty peer name is logged and given a placeholder so
/// the row is still rendered. IPs are joined for display by the content layer.
///
/// [`PeerInfo`]: toride_tailscale::report::PeerInfo
pub fn convert_peers(peers: &[toride_tailscale::report::PeerInfo]) -> Vec<PeerEntry> {
    peers
        .iter()
        .map(|p| {
            if p.name.is_empty() {
                tracing::warn!("tailscale peer with empty name");
            }
            PeerEntry {
                name: if p.name.is_empty() {
                    "(unknown)".into()
                } else {
                    p.name.clone()
                },
                ip_addresses: p.ip_addresses.clone(),
                online: p.online,
                exit_node: p.exit_node,
            }
        })
        .collect()
}

// ── Netcheck ────────────────────────────────────────────────────────────────

/// Presentation-level view of a netcheck, derived from a
/// [`NetcheckReport`].
///
/// [`NetcheckReport`]: toride_tailscale::report::NetcheckReport
#[derive(Clone, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "mirrors the backend NetcheckReport capability flags"
)]
pub struct NetcheckInfo {
    /// Whether the node can reach the coordination server (backend
    /// `MappingVariesByDestIP` flag). This tracks NAT behavior, NOT whether the daemon
    /// was reachable — a probe that reaches the daemon can still report `false`.
    pub connectivity: bool,
    /// Preferred DERP relay region.
    pub derp_region: Option<String>,
    /// Per-region DERP latencies, sorted by latency ascending (lowest first) so the
    /// content panel shows the best relay at the top.
    pub derp_latency: Vec<DerpLatencyEntry>,
    /// Whether UDP is available.
    pub udp: bool,
    /// Whether IPv6 is available.
    pub ipv6: bool,
    /// Whether Hairpin NAT is working.
    pub hairpin: bool,
    /// Port-mapping probe results.
    pub port_mapping: Vec<PortMapEntry>,
}

/// Convert a backend [`NetcheckReport`] into presentation [`NetcheckInfo`].
///
/// Latencies are sorted ascending and NaN/inf/negative values are dropped (a stray parse
/// artifact from the local API must never produce a "NaN ms" or "-5 ms" row in the TUI;
/// a negative value would otherwise sort to the top as the "best" relay and render green).
///
/// [`NetcheckReport`]: toride_tailscale::report::NetcheckReport
pub fn convert_netcheck(report: toride_tailscale::report::NetcheckReport) -> NetcheckInfo {
    let mut derp_latency: Vec<DerpLatencyEntry> = report
        .derp_latency
        .into_iter()
        .filter(|(_, ms)| ms.is_finite() && *ms >= 0.0)
        .map(|(region, ms)| DerpLatencyEntry {
            region: if region.is_empty() {
                "(unknown)".into()
            } else {
                region
            },
            latency_ms: ms,
        })
        .collect();
    // Lowest latency first — the preferred relay floats to the top.
    derp_latency.sort_by(|a, b| {
        a.latency_ms
            .partial_cmp(&b.latency_ms)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let port_mapping = report
        .port_mapping
        .into_iter()
        .map(|(name, open)| PortMapEntry {
            name: if name.is_empty() {
                "(unknown)".into()
            } else {
                name
            },
            open,
        })
        .collect();

    NetcheckInfo {
        connectivity: report.connectivity,
        derp_region: report.derp_region,
        derp_latency,
        udp: report.udp,
        ipv6: report.ipv6,
        hairpin: report.hairpin,
        port_mapping,
    }
}

// ── DNS ─────────────────────────────────────────────────────────────────────

/// Convert a backend [`DnsConfigInfo`] into presentation [`DnsInfo`].
///
/// [`DnsConfigInfo`]: toride_tailscale::dns::DnsConfigInfo
pub fn convert_dns(config: toride_tailscale::dns::DnsConfigInfo) -> DnsInfo {
    DnsInfo {
        magic_dns: config.magic_dns,
        nameservers: config.nameservers,
        search_domains: config.search_domains,
        split_dns: config.split_dns,
    }
}

// ── Doctor findings ─────────────────────────────────────────────────────────

/// Convert backend doctor findings to UI entries.
///
/// Every finding maps 1:1. The Tailscale backend [`Finding`] carries a single `message`
/// string (unlike fail2ban/cloud which split title+detail), so it maps to `title` and
/// leaves `detail` empty. An empty `id` or `message` is logged and the entry is still
/// produced with a placeholder so the row count matches the backend (the operator can
/// see "something" even if the finding is malformed). Mirrors
/// `fail2ban_convert::convert_findings` exactly modulo the `message` field.
///
/// [`Finding`]: toride_tailscale::doctor::Finding
pub fn convert_findings(
    findings: Vec<toride_tailscale::doctor::Finding>,
) -> Vec<TailscaleFindingEntry> {
    findings
        .into_iter()
        .map(|f| {
            if f.id.is_empty() || f.message.is_empty() {
                tracing::warn!(
                    "tailscale finding with empty id/message: id={:?} message={:?}",
                    f.id,
                    f.message
                );
            }
            TailscaleFindingEntry {
                id: if f.id.is_empty() {
                    "(unknown)".into()
                } else {
                    f.id
                },
                severity: severity_str(f.severity).to_string(),
                title: if f.message.is_empty() {
                    "(no message)".into()
                } else {
                    f.message
                },
                fix: f.fix,
            }
        })
        .collect()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use toride_tailscale::doctor::{Finding, Severity};
    use toride_tailscale::report::{NetcheckReport, PeerInfo, TailscaleReport};

    // ── convert_findings ─────────────────────────────────────────────────────

    #[test]
    fn convert_findings_empty() {
        assert!(convert_findings(Vec::new()).is_empty());
    }

    #[test]
    fn convert_findings_maps_severity() {
        let findings = vec![
            Finding::new("a", Severity::Critical, "m1"),
            Finding::new("b", Severity::Warning, "m2"),
            Finding::new("c", Severity::Info, "m3"),
            Finding::new("d", Severity::Ok, "m4"),
        ];
        let entries = convert_findings(findings);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].severity, "critical");
        assert_eq!(entries[1].severity, "warning");
        assert_eq!(entries[2].severity, "info");
        assert_eq!(entries[3].severity, "ok");
    }

    #[test]
    fn convert_findings_preserves_message_and_fix() {
        let f = Finding::new("id", Severity::Warning, "the message").with_fix("the fix");
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].title, "the message");
        assert_eq!(entries[0].fix.as_deref(), Some("the fix"));
    }

    #[test]
    fn convert_findings_placeholder_for_empty_fields() {
        let f = Finding::new("", Severity::Ok, "");
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].id, "(unknown)");
        assert_eq!(entries[0].title, "(no message)");
    }

    // ── convert_status ───────────────────────────────────────────────────────

    #[test]
    fn convert_status_basic() {
        let report = TailscaleReport {
            connected: true,
            node_name: "my-host".into(),
            tailnet: "example.com".into(),
            ip_addresses: vec!["100.64.0.1".into()],
            exit_node: Some("100.64.0.2".into()),
            dns_enabled: true,
        };
        let info = convert_status(report);
        assert!(info.connected);
        assert_eq!(info.node_name, "my-host");
        assert_eq!(info.tailnet, "example.com");
        assert_eq!(info.ip_addresses, vec!["100.64.0.1".to_string()]);
        assert_eq!(info.exit_node.as_deref(), Some("100.64.0.2"));
        assert!(info.dns_enabled);
    }

    #[test]
    fn convert_status_placeholder_for_empty() {
        let report = TailscaleReport {
            connected: false,
            node_name: String::new(),
            tailnet: String::new(),
            ip_addresses: Vec::new(),
            exit_node: None,
            dns_enabled: false,
        };
        let info = convert_status(report);
        assert_eq!(info.node_name, "(unknown)");
        assert_eq!(info.tailnet, "(unknown)");
    }

    // ── convert_peers ────────────────────────────────────────────────────────

    #[test]
    fn convert_peers_empty() {
        assert!(convert_peers(&[]).is_empty());
    }

    #[test]
    fn convert_peers_maps_fields() {
        let peers = vec![PeerInfo {
            name: "peer1".into(),
            ip_addresses: vec!["100.64.0.3".into()],
            online: true,
            exit_node: false,
        }];
        let entries = convert_peers(&peers);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "peer1");
        assert!(entries[0].online);
        assert!(!entries[0].exit_node);
        assert_eq!(entries[0].ip_addresses, vec!["100.64.0.3".to_string()]);
    }

    #[test]
    fn convert_peers_placeholder_for_empty_name() {
        let peers = vec![PeerInfo {
            name: String::new(),
            ip_addresses: Vec::new(),
            online: false,
            exit_node: false,
        }];
        let entries = convert_peers(&peers);
        assert_eq!(entries[0].name, "(unknown)");
    }

    // ── convert_netcheck ─────────────────────────────────────────────────────

    #[test]
    fn convert_netcheck_sorts_by_latency() {
        let report = NetcheckReport {
            connectivity: true,
            derp_region: Some("DERP-3".into()),
            derp_latency: vec![
                ("tok".to_string(), 50.0),
                ("nyc".to_string(), 10.0),
                ("sf".to_string(), 30.0),
            ],
            udp: true,
            ipv6: false,
            hairpin: true,
            port_mapping: Vec::new(),
        };
        let info = convert_netcheck(report);
        assert_eq!(info.derp_latency.len(), 3);
        // Lowest latency (nyc 10ms) must be first after the sort.
        assert_eq!(info.derp_latency[0].region, "nyc");
        assert!(
            (info.derp_latency[0].latency_ms - 10.0).abs() < f64::EPSILON,
            "expected 10.0"
        );
        assert_eq!(info.derp_region.as_deref(), Some("DERP-3"));
        assert!(info.udp);
        assert!(info.hairpin);
        assert!(!info.ipv6);
    }

    #[test]
    fn convert_netcheck_drops_non_finite_latencies() {
        let report = NetcheckReport {
            connectivity: false,
            derp_region: None,
            derp_latency: vec![
                ("good".to_string(), 20.0),
                ("nan".to_string(), f64::NAN),
                ("inf".to_string(), f64::INFINITY),
            ],
            udp: false,
            ipv6: false,
            hairpin: false,
            port_mapping: Vec::new(),
        };
        let info = convert_netcheck(report);
        assert_eq!(info.derp_latency.len(), 1);
        assert_eq!(info.derp_latency[0].region, "good");
    }

    #[test]
    fn convert_netcheck_drops_negative_latencies() {
        // A malformed local-API parse artifact (e.g. -5.0 ms) must NOT survive the
        // filter: a negative value sorts to the top of the ascending sort as the
        // "best" relay and would render green (latency_ms < 50.0). Only the
        // legitimate finite, non-negative entries survive.
        let report = NetcheckReport {
            connectivity: false,
            derp_region: None,
            derp_latency: vec![("good".to_string(), 20.0), ("neg".to_string(), -5.0)],
            udp: false,
            ipv6: false,
            hairpin: false,
            port_mapping: Vec::new(),
        };
        let info = convert_netcheck(report);
        assert_eq!(info.derp_latency.len(), 1);
        assert_eq!(info.derp_latency[0].region, "good");
        assert!(
            (info.derp_latency[0].latency_ms - 20.0).abs() < f64::EPSILON,
            "expected 20.0"
        );
    }

    #[test]
    fn convert_netcheck_port_mapping() {
        let report = NetcheckReport {
            connectivity: true,
            derp_region: None,
            derp_latency: Vec::new(),
            udp: true,
            ipv6: true,
            hairpin: false,
            port_mapping: vec![("UPnP".to_string(), true), ("PMP".to_string(), false)],
        };
        let info = convert_netcheck(report);
        assert_eq!(info.port_mapping.len(), 2);
        assert_eq!(info.port_mapping[0].name, "UPnP");
        assert!(info.port_mapping[0].open);
        assert!(!info.port_mapping[1].open);
    }

    #[test]
    fn convert_netcheck_empty_region_placeholder() {
        // A malformed local-API payload (e.g. `{"": 42}` in the DERP latency map) must not
        // silently produce a row with an empty region string. The convert layer substitutes
        // "(unknown)" so the operator sees *something* instead of a blank row.
        let report = NetcheckReport {
            connectivity: true,
            derp_region: None,
            derp_latency: vec![(String::new(), 42.0), ("nyc".to_string(), 10.0)],
            udp: true,
            ipv6: false,
            hairpin: false,
            port_mapping: Vec::new(),
        };
        let info = convert_netcheck(report);
        assert_eq!(info.derp_latency.len(), 2);
        let empty_region = info
            .derp_latency
            .iter()
            .find(|e| (e.latency_ms - 42.0).abs() < f64::EPSILON)
            .expect("empty-region entry survived the filter");
        assert_eq!(empty_region.region, "(unknown)");
    }

    #[test]
    fn convert_netcheck_empty_portmap_name_placeholder() {
        // A malformed port-mapping probe with an empty name must surface as "(unknown)"
        // rather than a blank pill in the TUI.
        let report = NetcheckReport {
            connectivity: true,
            derp_region: None,
            derp_latency: Vec::new(),
            udp: true,
            ipv6: false,
            hairpin: false,
            port_mapping: vec![(String::new(), true), ("UPnP".to_string(), false)],
        };
        let info = convert_netcheck(report);
        assert_eq!(info.port_mapping.len(), 2);
        let empty_name = info
            .port_mapping
            .iter()
            .find(|e| e.open)
            .expect("empty-name entry preserved");
        assert_eq!(empty_name.name, "(unknown)");
    }

    // ── convert_dns ──────────────────────────────────────────────────────────

    #[test]
    fn convert_dns_basic() {
        let config = toride_tailscale::dns::DnsConfigInfo {
            magic_dns: true,
            nameservers: vec!["1.1.1.1".into()],
            search_domains: vec!["ts.example.com".into()],
            split_dns: Vec::new(),
        };
        let info = convert_dns(config);
        assert!(info.magic_dns);
        assert_eq!(info.nameservers, vec!["1.1.1.1".to_string()]);
        assert_eq!(info.search_domains, vec!["ts.example.com".to_string()]);
    }

    #[test]
    fn convert_dns_with_empty_fields() {
        // The DNS convert has no placeholder branch — empty fields must pass through as
        // empty Vecs without panicking or being substituted.
        let config = toride_tailscale::dns::DnsConfigInfo {
            magic_dns: false,
            nameservers: Vec::new(),
            search_domains: Vec::new(),
            split_dns: Vec::new(),
        };
        let info = convert_dns(config);
        assert!(!info.magic_dns);
        assert!(info.nameservers.is_empty());
        assert!(info.search_domains.is_empty());
        assert!(info.split_dns.is_empty());
    }
}
