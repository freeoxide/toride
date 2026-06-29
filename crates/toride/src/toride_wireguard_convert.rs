//! Convert `toride-wireguard` library types to UI presentation types.
//!
//! This is the ONLY module in the `toride` crate that imports
//! `toride_wireguard` types — mirroring `fail2ban_convert.rs`'s role as the
//! single boundary between backend and presentation. Each function handles
//! errors gracefully: malformed input is skipped with a `tracing::warn!` and a
//! placeholder, never propagated (the read-only section must never crash the
//! TUI).

use crate::ui::screens::toride_wireguard::{FindingEntry, InterfaceEntry, PeerEntry, ServiceEntry};

/// Map a backend [`toride_wireguard::report::Severity`] to a lowercase string
/// used by the presentation layer: `"info" | "warning" | "error"`. The backend
/// `Severity` enum has no `Ok` variant, so `"ok"` can never be produced here;
/// the UI's `severity_style` still defensively accepts `"ok"` as an input.
/// Kept here so the TUI never imports the Severity enum directly.
fn severity_str(s: toride_wireguard::report::Severity) -> &'static str {
    use toride_wireguard::report::Severity;
    match s {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

/// Convert a backend [`toride_wireguard::report::InterfaceReport`] to a UI
/// [`InterfaceEntry`].
///
/// The report carries aggregate peer counts and transfer totals, which are
/// surfaced directly. An empty name is replaced with a placeholder so the row
/// is still visible to the operator.
pub fn convert_interface(r: &toride_wireguard::report::InterfaceReport) -> InterfaceEntry {
    if r.name.is_empty() {
        tracing::warn!("wireguard interface report with empty name");
    }
    InterfaceEntry {
        name: if r.name.is_empty() {
            "(unknown)".into()
        } else {
            r.name.clone()
        },
        is_up: r.is_up,
        listen_port: r.listen_port,
        peer_count: Some(r.peer_count),
        active_peers: Some(r.active_peers),
        rx_bytes: Some(r.stats.received),
        tx_bytes: Some(r.stats.sent),
    }
}

/// Convert backend doctor findings to UI entries.
///
/// Every finding maps 1:1. An empty `check_id` or `message` is logged and the
/// entry is still produced with a placeholder so the row count matches the
/// backend (the operator can see "something" even if the finding is
/// malformed).
pub fn convert_findings(findings: Vec<toride_wireguard::report::Finding>) -> Vec<FindingEntry> {
    findings
        .into_iter()
        .map(|f| {
            if f.check_id.is_empty() || f.message.is_empty() {
                tracing::warn!(
                    "wireguard finding with empty check_id/message: id={:?} message={:?}",
                    f.check_id,
                    f.message
                );
            }
            FindingEntry {
                check_id: if f.check_id.is_empty() {
                    "(unknown)".into()
                } else {
                    f.check_id.to_string()
                },
                severity: severity_str(f.severity).to_string(),
                message: if f.message.is_empty() {
                    "(no message)".into()
                } else {
                    f.message
                },
                fix: f.fix,
            }
        })
        .collect()
}

/// Convert a parsed `wg show` interface entry into a UI [`InterfaceEntry`].
///
/// The `WgShowEntry` carries only the interface name, public key, and listen
/// port — it does NOT carry peer counts or transfer stats. Those fields are
/// therefore emitted as `None` sentinels so the UI renders "?" rather than a
/// misleading "peers 0/0  rx 0 B  tx 0 B" that would contradict the live Peers
/// table below the Interfaces table. When the backend is wired to real
/// `wg show` output carrying peer counts / transfer stats, the collection path
/// should switch to [`convert_interface`] (which maps the richer
/// `InterfaceReport` and emits `Some(_)`). An empty interface name is replaced
/// with a placeholder.
pub fn convert_show_entry(e: &toride_wireguard::parse::WgShowEntry) -> InterfaceEntry {
    if e.interface.is_empty() {
        tracing::warn!("wireguard show entry with empty interface name");
    }
    InterfaceEntry {
        name: if e.interface.is_empty() {
            "(unknown)".into()
        } else {
            e.interface.clone()
        },
        // `wg show` listing implies the interface is up (it is running in the
        // kernel). Peer counts / transfer stats are NOT available from this
        // entry — emit None so the UI renders "?" instead of a misleading 0.
        is_up: !e.interface.is_empty(),
        listen_port: e.listen_port,
        peer_count: None,
        active_peers: None,
        rx_bytes: None,
        tx_bytes: None,
    }
}

/// Convert a backend [`toride_wireguard::spec::PeerSpec`] to a UI
/// [`PeerEntry`].
///
/// Stats (rx/tx, handshake) are not carried by `PeerSpec` (the spec is
/// configuration, not runtime state), so they are left zeroed and the endpoint
/// / allowed-ips / keepalive are surfaced.
pub fn convert_peer(p: &toride_wireguard::spec::PeerSpec) -> PeerEntry {
    PeerEntry {
        public_key: p.public_key.clone(),
        allowed_ips: p.allowed_ips.clone(),
        endpoint: p.endpoint.clone(),
        persistent_keepalive: p.persistent_keepalive,
        rx_bytes: 0,
        tx_bytes: 0,
        latest_handshake: None,
    }
}

/// Convert a `wg-quick@<iface>` systemd service activity probe into a
/// [`ServiceEntry`].
///
/// `is_active` is the result of `WireguardService::is_active()`; `enabled` is
/// best-effort and left `None` when not probed.
pub fn convert_service(name: String, is_active: bool, enabled: Option<bool>) -> ServiceEntry {
    ServiceEntry {
        name,
        is_active,
        enabled,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use toride_wireguard::report::{Finding, InterfaceReport, Severity, TransferStats};
    use toride_wireguard::spec::PeerSpec;

    // ── convert_interface ─────────────────────────────────────────────────────

    #[test]
    fn convert_interface_maps_fields() {
        let r = InterfaceReport {
            name: "wg0".into(),
            is_up: true,
            peer_count: 3,
            active_peers: 2,
            listen_port: 51820,
            stats: TransferStats {
                received: 1000,
                sent: 2000,
            },
        };
        let e = convert_interface(&r);
        assert_eq!(e.name, "wg0");
        assert!(e.is_up);
        assert_eq!(e.peer_count, Some(3));
        assert_eq!(e.active_peers, Some(2));
        assert_eq!(e.listen_port, 51820);
        assert_eq!(e.rx_bytes, Some(1000));
        assert_eq!(e.tx_bytes, Some(2000));
    }

    #[test]
    fn convert_interface_placeholder_for_empty_name() {
        let r = InterfaceReport {
            name: String::new(),
            is_up: false,
            peer_count: 0,
            active_peers: 0,
            listen_port: 0,
            stats: TransferStats::default(),
        };
        let e = convert_interface(&r);
        assert_eq!(e.name, "(unknown)");
    }

    // ── convert_findings ──────────────────────────────────────────────────────

    #[test]
    fn convert_findings_empty() {
        assert!(convert_findings(Vec::new()).is_empty());
    }

    #[test]
    fn convert_findings_maps_severity() {
        let findings = vec![
            Finding::new("a", Severity::Error, "t1".into()),
            Finding::new("b", Severity::Warning, "t2".into()),
            Finding::new("c", Severity::Info, "t3".into()),
        ];
        let entries = convert_findings(findings);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].severity, "error");
        assert_eq!(entries[1].severity, "warning");
        assert_eq!(entries[2].severity, "info");
        // `Finding::new` defaults `fix` to None. Pin the None path explicitly
        // (only convert_findings_preserves_fix asserts the Some(_) value), so a
        // regression that accidentally fills `fix` on the default path is
        // caught here rather than silently rendering a bogus remediation hint.
        assert_eq!(entries[0].fix, None);
        assert_eq!(entries[1].fix, None);
        assert_eq!(entries[2].fix, None);
    }

    #[test]
    fn convert_findings_preserves_fix() {
        let f = Finding::new("id", Severity::Warning, "title".into())
            .with_fix("install wireguard-tools".into());
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].fix.as_deref(), Some("install wireguard-tools"));
    }

    #[test]
    fn convert_findings_placeholder_for_empty_fields() {
        let f = Finding::new("", Severity::Info, String::new());
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].check_id, "(unknown)");
        assert_eq!(entries[0].message, "(no message)");
    }

    // ── convert_show_entry ────────────────────────────────────────────────────

    #[test]
    fn convert_show_entry_maps_fields() {
        let e = toride_wireguard::parse::WgShowEntry {
            interface: "wg0".into(),
            public_key: "ABC==".into(),
            listen_port: 51820,
        };
        let entry = convert_show_entry(&e);
        assert_eq!(entry.name, "wg0");
        assert!(entry.is_up);
        assert_eq!(entry.listen_port, 51820);
    }

    #[test]
    fn convert_show_entry_empty_interface_is_down() {
        let e = toride_wireguard::parse::WgShowEntry {
            interface: String::new(),
            public_key: String::new(),
            listen_port: 0,
        };
        let entry = convert_show_entry(&e);
        assert_eq!(entry.name, "(unknown)");
        assert!(!entry.is_up);
    }

    /// `WgShowEntry` does not carry peer counts or transfer stats. The
    /// listing-path converter must emit `None` sentinels for those fields so
    /// the Interfaces table renders "?" rather than a misleading
    /// "peers 0/0  rx 0 B  tx 0 B" that would contradict the live Peers table.
    /// This guards against a regression to the old zeroed-defaults behaviour.
    #[test]
    fn convert_show_entry_stats_are_unknown_not_zero() {
        let e = toride_wireguard::parse::WgShowEntry {
            interface: "wg0".into(),
            public_key: "ABC==".into(),
            listen_port: 51820,
        };
        let entry = convert_show_entry(&e);
        assert_eq!(entry.peer_count, None, "peer_count must be unknown (None)");
        assert_eq!(
            entry.active_peers, None,
            "active_peers must be unknown (None)"
        );
        assert_eq!(entry.rx_bytes, None, "rx_bytes must be unknown (None)");
        assert_eq!(entry.tx_bytes, None, "tx_bytes must be unknown (None)");
    }

    // ── convert_peer ──────────────────────────────────────────────────────────

    #[test]
    fn convert_peer_maps_fields() {
        let p = PeerSpec::new("PUBKEY==".into(), vec!["10.0.0.2/32".into()])
            .with_endpoint("1.2.3.4:51820".into())
            .with_persistent_keepalive(25);
        let e = convert_peer(&p);
        assert_eq!(e.public_key, "PUBKEY==");
        assert_eq!(e.allowed_ips, vec!["10.0.0.2/32".to_string()]);
        assert_eq!(e.endpoint.as_deref(), Some("1.2.3.4:51820"));
        assert_eq!(e.persistent_keepalive, Some(25));
        // Stats are not carried by PeerSpec.
        assert_eq!(e.rx_bytes, 0);
        assert_eq!(e.tx_bytes, 0);
        assert!(e.latest_handshake.is_none());
    }

    /// Degenerate-input coverage: a `PeerSpec` with NO endpoint, an EMPTY
    /// allowed-ips list, and NO persistent keepalive. These Option pass-through
    /// fields are what the UI renders as "(none)"; this test pins that the
    /// converter surfaces them as `None`/empty rather than panicking or filling
    /// a default value. Mirrors the empty-input coverage on the sibling
    /// converters (`convert_findings_empty`, `convert_interface_placeholder_for_empty_name`,
    /// `convert_show_entry_empty_interface_is_down`).
    #[test]
    fn convert_peer_empty_fields_pass_through() {
        let p = PeerSpec::new("KEY".into(), Vec::new());
        let e = convert_peer(&p);
        assert_eq!(e.public_key, "KEY");
        assert_eq!(e.endpoint, None);
        assert!(e.allowed_ips.is_empty());
        assert_eq!(e.persistent_keepalive, None);
        assert_eq!(e.rx_bytes, 0);
        assert_eq!(e.tx_bytes, 0);
        assert!(e.latest_handshake.is_none());
    }

    // ── convert_service ───────────────────────────────────────────────────────

    #[test]
    fn convert_service_maps_fields() {
        let e = convert_service("wg-quick@wg0".into(), true, Some(true));
        assert_eq!(e.name, "wg-quick@wg0");
        assert!(e.is_active);
        assert_eq!(e.enabled, Some(true));
    }

    #[test]
    fn convert_service_enabled_none() {
        let e = convert_service("wg-quick@wg0".into(), false, None);
        assert!(!e.is_active);
        assert!(e.enabled.is_none());
    }

    // ── severity_str ──────────────────────────────────────────────────────────

    #[test]
    fn severity_str_covers_all_variants() {
        assert_eq!(severity_str(Severity::Info), "info");
        assert_eq!(severity_str(Severity::Warning), "warning");
        assert_eq!(severity_str(Severity::Error), "error");
    }

    /// The backend `Severity` enum has no `Ok` variant, so `severity_str` can
    /// never emit `"ok"`. This guards the doc claim against a future `Ok`
    /// variant being added to the backend enum silently: if one is added, the
    /// compiler will flag the non-exhaustive match in `severity_str` (good),
    /// and this test pins that the converter's output vocabulary is exactly
    /// {info, warning, error} — no `"ok"` leaks into the UI from this path.
    #[test]
    fn severity_str_never_emits_ok() {
        // Exhaust over every Severity variant; none may map to "ok".
        for s in [Severity::Info, Severity::Warning, Severity::Error] {
            let out = severity_str(s);
            assert_ne!(
                out, "ok",
                "severity_str emitted \"ok\" for {s:?} — the backend Severity enum is not expected to have an Ok variant"
            );
        }
    }
}
