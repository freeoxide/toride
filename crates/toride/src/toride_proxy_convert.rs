//! Convert `toride-proxy` library types to UI presentation types.
//!
//! This is the ONLY module in the `toride` crate that imports `toride_proxy`
//! types — mirroring `fail2ban_convert.rs`'s role as the single boundary
//! between backend and presentation. Each function handles errors gracefully:
//! malformed input is skipped with a `tracing::warn!` and a placeholder, never
//! propagated (the read-only section must never crash the TUI).
//!
//! Note: the `toride-proxy` crate is pulled in with its default features
//! (`client`, `doctor`, `nginx`). The `certs`, `caddy`, and `waf` features are
//! NOT enabled in the TUI's `Cargo.toml`, so `CertManager` / `CaddyManager` /
//! `WafManager` are unavailable here. Certificate and server-block data is
//! therefore derived from what the doctor surfaces plus the filesystem scan of
//! the certbot live directory, rather than from those feature-gated facades.

use crate::ui::screens::toride_proxy::{CertEntry, FindingEntry, ServerBlockEntry};

/// Map a backend [`toride_proxy::doctor::DoctorSeverity`] to a lowercase string
/// used by the presentation layer: `"ok" | "info" | "warning" | "error" |
/// "critical"`. Kept here so the TUI never imports the Severity enum directly.
///
/// The proxy doctor has no explicit `Ok` severity (it uses `Info` for healthy
/// checks), so `Ok` is mapped to `"ok"` defensively but is not expected in
/// practice — every emitted finding already maps through this function.
fn severity_str(s: toride_proxy::doctor::DoctorSeverity) -> &'static str {
    use toride_proxy::doctor::DoctorSeverity;
    match s {
        DoctorSeverity::Info => "info",
        DoctorSeverity::Warning => "warning",
        DoctorSeverity::Error => "error",
        DoctorSeverity::Critical => "critical",
    }
}

/// Convert backend doctor findings to UI entries.
///
/// Every finding maps 1:1. An empty `id` or `title` is logged and the entry is
/// still produced with a placeholder so the row count matches the backend (the
/// operator can see "something" even if the finding is malformed).
pub fn convert_findings(findings: Vec<toride_proxy::doctor::DoctorFinding>) -> Vec<FindingEntry> {
    findings
        .into_iter()
        .map(|f| {
            if f.id.is_empty() || f.title.is_empty() {
                tracing::warn!(
                    "proxy finding with empty id/title: id={:?} title={:?}",
                    f.id,
                    f.title
                );
            }
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
                detail: f.detail,
                fix: f.fix,
            }
        })
        .collect()
}

/// Convert backend server blocks to UI entries.
///
/// Each block carries its server name, listen port, upstream target, and
/// whether TLS is configured. A block with an empty `server_name` is logged
/// and still produced with a placeholder so the operator sees the row.
pub fn convert_server_blocks(
    blocks: Vec<toride_proxy::spec::ServerBlock>,
) -> Vec<ServerBlockEntry> {
    blocks
        .into_iter()
        .map(|b| {
            if b.server_name.is_empty() {
                tracing::warn!(
                    "proxy server block with empty server_name: port={} upstream={:?}",
                    b.listen_port,
                    b.upstream
                );
            }
            ServerBlockEntry {
                server_name: if b.server_name.is_empty() {
                    "(unnamed)".into()
                } else {
                    b.server_name
                },
                listen_port: b.listen_port,
                upstream: b.upstream,
                tls_enabled: b.tls.is_some(),
            }
        })
        .collect()
}

/// Convert backend certificate info to UI entries.
///
/// Each certificate maps 1:1 to a row carrying domain, issuer, expiry
/// timestamp, and days remaining. A certificate with an empty domain is logged
/// and produced with a placeholder so the operator sees the row.
pub fn convert_certificates(certs: Vec<toride_proxy::report::CertInfo>) -> Vec<CertEntry> {
    certs
        .into_iter()
        .map(|c| {
            if c.domain.is_empty() {
                tracing::warn!("proxy certificate with empty domain: issuer={:?}", c.issuer);
            }
            CertEntry {
                domain: if c.domain.is_empty() {
                    "(unknown)".into()
                } else {
                    c.domain
                },
                issuer: if c.issuer.is_empty() {
                    "(unknown)".into()
                } else {
                    c.issuer
                },
                not_after: c.not_after,
                days_remaining: c.days_remaining,
                is_valid: c.is_valid,
            }
        })
        .collect()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use toride_proxy::doctor::{DoctorFinding, DoctorSeverity};
    use toride_proxy::report::CertInfo;
    use toride_proxy::spec::ServerBlock;

    // ── convert_findings ──────────────────────────────────────────────────────

    #[test]
    fn convert_findings_empty() {
        assert!(convert_findings(Vec::new()).is_empty());
    }

    #[test]
    fn convert_findings_maps_severity() {
        let findings = vec![
            DoctorFinding::new("a", DoctorSeverity::Critical, "t1"),
            DoctorFinding::new("b", DoctorSeverity::Error, "t2"),
            DoctorFinding::new("c", DoctorSeverity::Warning, "t3"),
            DoctorFinding::new("d", DoctorSeverity::Info, "t4"),
        ];
        let entries = convert_findings(findings);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].severity, "critical");
        assert_eq!(entries[1].severity, "error");
        assert_eq!(entries[2].severity, "warning");
        assert_eq!(entries[3].severity, "info");
    }

    #[test]
    fn convert_findings_preserves_detail_and_fix() {
        let f = DoctorFinding::new("id", DoctorSeverity::Warning, "title")
            .detail("the detail")
            .fix("the fix");
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].detail, "the detail");
        assert_eq!(entries[0].fix.as_deref(), Some("the fix"));
    }

    #[test]
    fn convert_findings_placeholder_for_empty_fields() {
        let f = DoctorFinding::new("", DoctorSeverity::Info, "");
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].id, "(unknown)");
        assert_eq!(entries[0].title, "(no title)");
    }

    // ── convert_server_blocks ─────────────────────────────────────────────────

    #[test]
    fn convert_server_blocks_empty() {
        assert!(convert_server_blocks(Vec::new()).is_empty());
    }

    #[test]
    fn convert_server_blocks_maps_fields() {
        let blocks = vec![
            ServerBlock::new("example.com", 443, "127.0.0.1:3000"),
            ServerBlock::new("api.example.com", 80, "127.0.0.1:8080"),
        ];
        let entries = convert_server_blocks(blocks);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].server_name, "example.com");
        assert_eq!(entries[0].listen_port, 443);
        assert_eq!(entries[0].upstream, "127.0.0.1:3000");
        assert!(!entries[0].tls_enabled);
        assert_eq!(entries[1].listen_port, 80);
    }

    #[test]
    fn convert_server_blocks_placeholder_for_empty_name() {
        let blocks = vec![ServerBlock::new("", 443, "127.0.0.1:3000")];
        let entries = convert_server_blocks(blocks);
        assert_eq!(entries[0].server_name, "(unnamed)");
    }

    #[test]
    fn convert_server_blocks_tls_flag() {
        use toride_proxy::spec::TlsConfig;
        let block = ServerBlock::new("example.com", 443, "127.0.0.1:3000")
            .with_tls(TlsConfig::new("example.com", "/cert.pem", "/key.pem"));
        let entries = convert_server_blocks(vec![block]);
        assert!(entries[0].tls_enabled);
    }

    // ── convert_certificates ──────────────────────────────────────────────────

    #[test]
    fn convert_certificates_empty() {
        assert!(convert_certificates(Vec::new()).is_empty());
    }

    #[test]
    fn convert_certificates_maps_fields() {
        let certs = vec![
            CertInfo::new(
                "example.com",
                "Let's Encrypt",
                "2024-01-01",
                "2024-04-01",
                30,
            ),
            CertInfo::new(
                "expired.com",
                "Let's Encrypt",
                "2023-01-01",
                "2023-04-01",
                -5,
            ),
        ];
        let entries = convert_certificates(certs);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].domain, "example.com");
        assert_eq!(entries[0].issuer, "Let's Encrypt");
        assert_eq!(entries[0].not_after, "2024-04-01");
        assert_eq!(entries[0].days_remaining, 30);
        assert!(entries[0].is_valid);
        assert!(!entries[1].is_valid);
    }

    #[test]
    fn convert_certificates_placeholder_for_empty_domain() {
        let certs = vec![CertInfo::new("", "", "2024-01-01", "2024-04-01", 30)];
        let entries = convert_certificates(certs);
        assert_eq!(entries[0].domain, "(unknown)");
        assert_eq!(entries[0].issuer, "(unknown)");
    }
}
