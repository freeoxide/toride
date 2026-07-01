//! Reverse-proxy management content area (live READ-ONLY).
//!
//! Renders inside the dashboard's content region when
//! [`Section::Proxy`](crate::data::Section) is the active sidebar section.
//! Mirrors the fail2ban / backup reference MINUS the write path — every line
//! is read-only.
//!
//! Layout (single scrollable pane, no sub-tab bar):
//! 1. Status panel — backend name + running/stopped status.
//! 2. Server blocks — virtual hosts (name, port, upstream, TLS flag).
//! 3. TLS certificates — domain, issuer, expiry, days remaining.
//! 4. WAF card — Web Application Firewall status.
//! 5. Doctor findings — grouped by severity (Critical > Error > Warning > Info).

use crossterm::event::{KeyCode, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
};

use crate::action::Action;
use crate::ui::responsive::truncate_str;
use crate::ui::theme::Palette;
use crate::ui::widgets::render_titled_panel;

// ── Presentation types ──────────────────────────────────────────────────────

/// A single server block (virtual host) row.
#[derive(Clone, Debug)]
pub struct ServerBlockEntry {
    /// Server name (domain) for this block.
    pub server_name: String,
    /// Port the block listens on.
    pub listen_port: u16,
    /// Upstream (backend) address, e.g. `127.0.0.1:3000`.
    pub upstream: String,
    /// Whether TLS is configured for this block.
    pub tls_enabled: bool,
}

/// A single TLS certificate row.
#[derive(Clone, Debug)]
pub struct CertEntry {
    /// Domain name the certificate is issued for.
    pub domain: String,
    /// Issuer of the certificate (e.g. "Let's Encrypt").
    pub issuer: String,
    /// ISO 8601 timestamp of when the certificate expires (may be empty when
    /// the `certs` feature is off and only the certbot dir was scanned).
    pub not_after: String,
    /// Number of days until the certificate expires (0 when unknown).
    pub days_remaining: i64,
    /// Whether the certificate is valid (not expired).
    pub is_valid: bool,
}

/// A single doctor finding.
#[derive(Clone, Debug)]
pub struct FindingEntry {
    /// Machine-readable dot-separated id (e.g. "nginx.service.not-running").
    pub id: String,
    /// Severity as a lowercase string: "info" | "warning" | "error" | "critical".
    pub severity: String,
    /// Short human-readable title.
    pub title: String,
    /// Longer description (may be empty).
    pub detail: String,
    /// Suggested remediation, if any.
    pub fix: Option<String>,
}

// ── ProxyContent ────────────────────────────────────────────────────────────

/// Reverse-proxy management content rendered inside the dashboard content area.
///
/// READ-ONLY: there are no write operations, no optimistic updates, no loading
/// spinner, no cooldown. Data arrives via [`ProxyContent::set_*`] setters
/// driven by [`ProxyCollector`](crate::toride_proxy_data::ProxyCollector).
pub struct ProxyContent {
    /// Whether the proxy backend was reachable at all (binaries present,
    /// doctor queryable). `false` means the section renders a degraded
    /// "unavailable" panel instead of live data.
    available: bool,
    /// Which proxy backend the report is for (e.g. "nginx"). Empty when the
    /// backend could not be determined.
    backend: String,
    /// Proxy server status string ("running" | "stopped" | "unknown: …").
    status: String,
    /// Configured server blocks.
    server_blocks: Vec<ServerBlockEntry>,
    /// TLS certificates.
    certificates: Vec<CertEntry>,
    /// Whether any certificate is expired or invalid.
    has_expired_certs: bool,
    /// WAF (Web Application Firewall) status. The `waf` feature is OFF, so this
    /// is always `None` (status unknown / not configured).
    waf_available: Option<bool>,
    /// Doctor findings.
    findings: Vec<FindingEntry>,
    /// Human-readable reason the backend was unreachable, surfaced in the
    /// degraded panel. Populated only when a collection task panicked or
    /// construction returned a hard error.
    unavailable_reason: Option<String>,
    /// Vertical scroll offset over the whole pane.
    scroll: usize,
}

impl Default for ProxyContent {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyContent {
    /// Create a new empty content area.
    #[must_use]
    pub fn new() -> Self {
        Self {
            available: false,
            backend: String::new(),
            status: String::new(),
            server_blocks: Vec::new(),
            certificates: Vec::new(),
            has_expired_certs: false,
            waf_available: None,
            findings: Vec::new(),
            unavailable_reason: None,
            scroll: 0,
        }
    }

    /// Whether the section has a modal open. Read-only section → never.
    #[must_use]
    pub fn has_modal(&self) -> bool {
        false
    }

    /// Live server-block (virtual host) count for the sidebar badge. `None`
    /// when the backend is unavailable so the badge stays honestly empty.
    #[must_use]
    pub fn badge_count(&self) -> Option<usize> {
        if self.available {
            Some(self.server_blocks.len())
        } else {
            None
        }
    }

    // ── Data setters ─────────────────────────────────────────────────────────

    /// Replace the status fields (drives the status panel).
    pub fn set_status(&mut self, backend: String, status: String) {
        self.backend = backend;
        self.status = status;
    }

    /// Replace the server blocks list and clamp scroll.
    pub fn set_server_blocks(&mut self, blocks: Vec<ServerBlockEntry>) {
        self.server_blocks = blocks;
        self.clamp_scroll();
    }

    /// Replace the certificates list, expiry flag, and clamp scroll.
    pub fn set_certificates(&mut self, certs: Vec<CertEntry>, has_expired_certs: bool) {
        self.certificates = certs;
        self.has_expired_certs = has_expired_certs;
        self.clamp_scroll();
    }

    /// Replace the findings list and clamp scroll.
    pub fn set_findings(&mut self, findings: Vec<FindingEntry>) {
        self.findings = findings;
        self.clamp_scroll();
    }

    /// Replace WAF status.
    pub fn set_waf(&mut self, waf_available: Option<bool>) {
        self.waf_available = waf_available;
    }

    /// Set the overall availability flag (false → degraded panel).
    pub fn set_available(&mut self, available: bool) {
        self.available = available;
    }

    /// Set the human-readable reason the backend was unreachable. Cleared
    /// (`None`) whenever availability flips back to `true` so a stale panic
    /// message can't linger after recovery.
    pub fn set_unavailable_reason(&mut self, reason: Option<String>) {
        self.unavailable_reason = if self.available { None } else { reason };
    }

    /// Current scroll offset (used by dashboard tests).
    #[cfg(test)]
    pub(crate) fn scroll(&self) -> usize {
        self.scroll
    }

    // ── Input ────────────────────────────────────────────────────────────────

    /// Handle a key press. Returns `Some(Action)` only for navigation keys
    /// (Esc → Back); scroll keys are consumed here.
    pub fn handle_key(&mut self, code: KeyCode) -> Option<Action> {
        match code {
            KeyCode::Down | KeyCode::Char('j') => {
                self.scroll = self.scroll.saturating_add(1);
                None
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.scroll = self.scroll.saturating_sub(1);
                None
            }
            KeyCode::PageDown => {
                self.scroll = self.scroll.saturating_add(8);
                None
            }
            KeyCode::PageUp => {
                self.scroll = self.scroll.saturating_sub(8);
                None
            }
            KeyCode::Esc => Some(Action::Back),
            _ => None,
        }
    }

    /// Handle a mouse event (scroll wheel only — no click targets).
    pub fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action> {
        match mouse.kind {
            MouseEventKind::ScrollDown => {
                self.scroll = self.scroll.saturating_add(1);
                None
            }
            MouseEventKind::ScrollUp => {
                self.scroll = self.scroll.saturating_sub(1);
                None
            }
            _ => None,
        }
    }

    /// Clamp scroll against a (post-layout) max. Called by the render path
    /// once the visible row count is known.
    fn clamp_scroll_to(&mut self, max_scroll: usize) {
        if self.scroll > max_scroll {
            self.scroll = max_scroll;
        }
    }

    /// Generic clamp after a data setter (defensive — the real clamp happens
    /// at render time once the pane height is known).
    #[expect(
        clippy::unused_self,
        reason = "API symmetry with other scrollable panes"
    )]
    fn clamp_scroll(&mut self) {
        // No-op body: scroll is clamped against visible rows during render.
    }

    // ── Rendering ───────────────────────────────────────────────────────────

    /// Render the full proxy content area.
    pub fn view(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        if !self.available {
            self.render_unavailable(frame, area, p);
            return;
        }

        let inner = render_titled_panel(
            frame,
            area,
            p,
            &format!(
                " PROXY · {} block(s) · {} cert(s) · {} finding(s) ",
                self.server_blocks.len(),
                self.certificates.len(),
                self.findings.len(),
            ),
            p.accent,
            true,
        );

        if inner.height == 0 {
            return;
        }

        // Build the full content as a Vec<Line> then render only the visible
        // window (mirrors the SSH/fail2ban tabs' manual-scroll approach).
        let lines = self.build_lines(p);

        let visible = inner.height as usize;
        let max_scroll = lines.len().saturating_sub(visible);
        self.clamp_scroll_to(max_scroll);
        let start = self.scroll.min(max_scroll);

        for (row, line) in lines.iter().skip(start).take(visible).enumerate() {
            let y = inner.y + u16::try_from(row).unwrap_or(u16::MAX);
            if y >= inner.bottom() {
                break;
            }
            let row_area = Rect::new(inner.x, y, inner.width, 1);
            frame.render_widget(Paragraph::new(line.clone()), row_area);
        }
    }

    /// Render the degraded state when the proxy backend is unavailable.
    fn render_unavailable(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " PROXY ", p.text_dim, false);
        let msg = Line::from(vec![
            Span::styled("✦ ", Style::new().fg(p.warn)),
            Span::styled(
                "proxy unavailable",
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
        ]);
        let detail_text = self
            .unavailable_reason
            .clone()
            .unwrap_or_else(|| "proxy data could not be collected on this host".to_string());
        let detail = Line::from(Span::styled(detail_text, Style::new().fg(p.text_dim)));
        let centered_msg = Rect::new(
            inner.x,
            inner.y + inner.height.saturating_sub(3) / 2,
            inner.width,
            1,
        );
        let centered_detail = Rect::new(
            inner.x,
            inner.y + inner.height.saturating_sub(3) / 2 + 1,
            inner.width,
            1,
        );
        frame.render_widget(Paragraph::new(msg).centered(), centered_msg);
        frame.render_widget(
            Paragraph::new(detail).centered().wrap(Wrap { trim: false }),
            centered_detail,
        );
    }

    /// Build the complete content as a flat list of lines (status, server
    /// blocks, certificates, WAF, findings). Scrolling operates over this list.
    fn build_lines(&self, p: Palette) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();

        self.push_status_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_server_blocks_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_certificates_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_waf_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_findings_lines(&mut lines, p);

        lines
    }

    fn push_status_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "Service",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        // Backend name.
        let backend = if self.backend.is_empty() {
            "(unknown)".to_string()
        } else {
            self.backend.clone()
        };
        lines.push(Line::from(vec![
            Span::styled("  backend  ", Style::new().fg(p.text_muted)),
            Span::styled(backend, Style::new().fg(p.text)),
        ]));

        // Status (running/stopped/unknown). Derived by the toride-proxy doctor
        // from the parsed `systemctl status nginx` output: Running/Stopped when
        // the service state was observed, Unknown('errors found') otherwise
        // (e.g. missing systemctl binary → the doctor emits a Critical finding
        // and could not determine the state).
        let (status_label, status_color) = if self.status.starts_with("running") {
            ("● running", p.ok)
        } else if self.status.starts_with("stopped") {
            ("○ stopped", p.err)
        } else {
            ("? unknown", p.warn)
        };
        lines.push(Line::from(vec![
            Span::styled("  state    ", Style::new().fg(p.text_muted)),
            Span::styled(status_label, Style::new().fg(status_color)),
        ]));
    }

    fn push_server_blocks_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        let header = format!("Server Blocks ({})", self.server_blocks.len());
        lines.push(Line::from(Span::styled(
            header,
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        if self.server_blocks.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no server blocks configured",
                Style::new().fg(p.text_dim),
            )));
            return;
        }

        for block in &self.server_blocks {
            let name = truncate_str(&block.server_name, 28);
            let tls_icon = if block.tls_enabled { "🔒" } else { " " };
            let tls_color = if block.tls_enabled { p.ok } else { p.text_dim };
            lines.push(Line::from(vec![
                Span::styled(format!("{tls_icon} "), Style::new().fg(tls_color)),
                Span::styled(
                    format!("{name:<28}"),
                    Style::new().fg(p.text).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("  :{}  → {}", block.listen_port, block.upstream),
                    Style::new().fg(p.text_muted),
                ),
            ]));
        }
    }

    fn push_certificates_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        let header = format!("TLS Certificates ({})", self.certificates.len());
        lines.push(Line::from(Span::styled(
            header,
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        // Surface the aggregated has_expired_certs flag as an inline header
        // warning so the operator gets a clear signal without scanning every
        // row. Previously this field was plumbed through but never read.
        if self.has_expired_certs {
            lines.push(Line::from(Span::styled(
                "  ! expired or invalid certificate(s) present",
                Style::new().fg(p.warn),
            )));
        }

        if self.certificates.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no certificates found",
                Style::new().fg(p.text_dim),
            )));
            return;
        }

        for cert in &self.certificates {
            let domain = truncate_str(&cert.domain, 30);
            // Branch on not_after first so an unknown-expiry cert (empty
            // not_after — the certs-feature-off certbot-dir-scan case) NEVER
            // renders as a green ✓. Overloading is_valid for these would show
            // an actually-expired cert as healthy. The '?' icon + warn color
            // signal that expiry is UNVERIFIED, which is the honest state.
            let (icon, color, expiry) = if cert.not_after.is_empty() {
                ("?", p.warn, "expiry unknown".to_string())
            } else if !cert.is_valid {
                (
                    "✗",
                    p.err,
                    format!("{} ({} days)", cert.not_after, cert.days_remaining),
                )
            } else if cert.days_remaining <= 30 {
                (
                    "!",
                    p.warn,
                    format!("{} ({} days)", cert.not_after, cert.days_remaining),
                )
            } else {
                (
                    "✓",
                    p.ok,
                    format!("{} ({} days)", cert.not_after, cert.days_remaining),
                )
            };
            let issuer = if cert.issuer.is_empty() {
                "(unknown issuer)".to_string()
            } else {
                cert.issuer.clone()
            };
            lines.push(Line::from(vec![
                Span::styled(format!("{icon} "), Style::new().fg(color)),
                Span::styled(
                    format!("{domain:<30}"),
                    Style::new().fg(p.text).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("  {expiry}"), Style::new().fg(p.text_muted)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("    issuer ", Style::new().fg(p.text_dim)),
                Span::styled(issuer, Style::new().fg(p.text_dim)),
            ]));
        }
    }

    fn push_waf_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "Web Application Firewall",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));
        let (icon, text, color) = match self.waf_available {
            Some(true) => ("✓", "enabled", p.ok),
            Some(false) => ("✗", "disabled", p.warn),
            // The `waf` feature is OFF in the TUI, so status is always unknown.
            None => ("?", "status unknown (waf feature off)", p.text_dim),
        };
        lines.push(Line::from(vec![
            Span::styled("  waf      ", Style::new().fg(p.text_muted)),
            Span::styled(format!("{icon} {text}"), Style::new().fg(color)),
        ]));
    }

    fn push_findings_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        // Group by severity: Critical > Error > Warning > Info > Ok.
        const ORDER: &[&str] = &["critical", "error", "warning", "info", "ok"];
        crate::ui::screens::findings::push_findings_grouped(
            lines,
            p,
            &self.findings,
            ORDER,
            crate::ui::screens::findings::severity_style_full,
            crate::ui::screens::findings::FindingWidths::TITLE_60,
        );
    }
}

impl crate::ui::screens::section_overview::SectionOverview for ProxyContent {
    fn available(&self) -> bool {
        self.available
    }

    fn status_label(&self) -> &'static str {
        crate::ui::screens::section_overview::status_label_for(
            self.available,
            self.findings.iter().map(|f| f.severity.as_str()),
        )
    }

    fn detail(&self) -> Option<String> {
        if !self.available {
            return None;
        }
        Some(format!(
            "{} server(s) · {} cert(s){}",
            self.server_blocks.len(),
            self.certificates.len(),
            if self.has_expired_certs {
                " · expired!"
            } else {
                ""
            }
        ))
    }

    fn findings_count(&self) -> usize {
        self.findings.len()
    }
}

impl crate::ui::screens::findings::Finding for FindingEntry {
    fn severity(&self) -> &str {
        &self.severity
    }
    fn title(&self) -> &str {
        &self.title
    }
    fn detail(&self) -> Option<&str> {
        Some(&self.detail)
    }
    fn fix(&self) -> Option<&str> {
        self.fix.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::theme::CHARM;
    use ratatui::{Terminal, backend::TestBackend};

    fn sample_server_blocks() -> Vec<ServerBlockEntry> {
        vec![
            ServerBlockEntry {
                server_name: "example.com".into(),
                listen_port: 443,
                upstream: "127.0.0.1:3000".into(),
                tls_enabled: true,
            },
            ServerBlockEntry {
                server_name: "api.example.com".into(),
                listen_port: 80,
                upstream: "127.0.0.1:8080".into(),
                tls_enabled: false,
            },
        ]
    }

    fn sample_certs() -> Vec<CertEntry> {
        vec![
            CertEntry {
                domain: "example.com".into(),
                issuer: "Let's Encrypt".into(),
                not_after: "2024-09-01".into(),
                days_remaining: 30,
                is_valid: true,
            },
            CertEntry {
                domain: "expired.com".into(),
                issuer: "Let's Encrypt".into(),
                not_after: "2023-01-01".into(),
                days_remaining: -5,
                is_valid: false,
            },
        ]
    }

    fn sample_findings() -> Vec<FindingEntry> {
        vec![
            FindingEntry {
                id: "nginx.service.running".into(),
                severity: "info".into(),
                title: "Nginx service is running".into(),
                detail: "PID: 1234".into(),
                fix: None,
            },
            FindingEntry {
                id: "nginx.config.invalid".into(),
                severity: "critical".into(),
                title: "Nginx configuration has syntax errors".into(),
                detail: String::new(),
                fix: Some("Fix the syntax errors and run 'nginx -t'".into()),
            },
        ]
    }

    /// Render a content area to a string (snapshot pattern from ssh `keys_tab.rs`).
    fn render_to_string(content: &mut ProxyContent, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| content.view(f, f.area(), CHARM)).unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn new_is_unavailable_and_empty() {
        let c = ProxyContent::new();
        assert!(!c.available);
        assert!(c.server_blocks.is_empty());
        assert!(c.certificates.is_empty());
        assert!(c.findings.is_empty());
        assert!(!c.has_modal());
    }

    #[test]
    fn default_matches_new() {
        let from_new = ProxyContent::new();
        let from_default = ProxyContent::default();
        assert_eq!(from_new.available, from_default.available);
    }

    #[test]
    fn render_unavailable_when_not_available() {
        let mut c = ProxyContent::new();
        let out = render_to_string(&mut c, 100, 24);
        assert!(out.contains("proxy unavailable"), "degraded panel: {out}");
    }

    #[test]
    fn render_status_panel() {
        let mut c = ProxyContent::new();
        c.set_available(true);
        c.set_status("nginx".into(), "running".into());
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("nginx"), "backend name: {out}");
        assert!(out.contains("running"), "status: {out}");
    }

    #[test]
    fn render_server_blocks_table() {
        let mut c = ProxyContent::new();
        c.set_available(true);
        c.set_server_blocks(sample_server_blocks());
        let out = render_to_string(&mut c, 110, 36);
        assert!(out.contains("example.com"), "first block: {out}");
        assert!(out.contains("api.example.com"), "second block: {out}");
        assert!(out.contains("127.0.0.1:3000"), "upstream: {out}");
    }

    #[test]
    fn render_certificates_table() {
        let mut c = ProxyContent::new();
        c.set_available(true);
        c.set_certificates(sample_certs(), true);
        let out = render_to_string(&mut c, 110, 40);
        assert!(out.contains("example.com"), "cert domain: {out}");
        assert!(out.contains("Let's Encrypt"), "cert issuer: {out}");
        assert!(out.contains("expired.com"), "expired cert: {out}");
    }

    /// A scan-derived cert (empty `not_after` — the certs-feature-off certbot-
    /// dir-scan case) must NOT render as a green ✓. The honest state is that
    /// expiry is UNVERIFIED, so the row shows '?' + "expiry unknown" + the
    /// `has_expired_certs` header warning is absent (unknown != expired).
    /// Regression guard for the prior bug where such a cert rendered as a
    /// healthy green ✓ with no signal that expiry was unverified.
    #[test]
    fn unknown_expiry_cert_does_not_render_as_green_check() {
        let mut c = ProxyContent::new();
        c.set_available(true);
        c.set_certificates(
            vec![CertEntry {
                domain: "scanonly.com".into(),
                issuer: "(unknown)".into(),
                not_after: String::new(),
                days_remaining: 0,
                is_valid: true,
            }],
            // is_valid=true everywhere → has_expired_certs must be false even
            // though expiry is unknown; the header warning must NOT appear.
            false,
        );
        let out = render_to_string(&mut c, 110, 24);
        assert!(
            out.contains("scanonly.com"),
            "cert domain must render: {out}"
        );
        assert!(
            out.contains("expiry unknown"),
            "unknown-expiry label must render: {out}"
        );
        // The '?' icon is the honest signal; the green ✓ must NOT appear.
        assert!(
            out.contains('?'),
            "unknown-expiry cert must render with '?' icon, not a green check: {out}"
        );
        assert!(
            !out.contains('✓'),
            "unknown-expiry cert must NOT render as a green ✓: {out}"
        );
        assert!(
            !out.contains("expired or invalid"),
            "unknown expiry must NOT trigger the has_expired_certs header warning: {out}"
        );
    }

    #[test]
    fn render_waf_card() {
        let mut c = ProxyContent::new();
        c.set_available(true);
        c.set_waf(None);
        let out = render_to_string(&mut c, 100, 30);
        assert!(
            out.contains("Web Application Firewall"),
            "waf header: {out}"
        );
        assert!(out.contains("waf feature off"), "waf status: {out}");
    }

    #[test]
    fn render_findings_grouped_by_severity() {
        let mut c = ProxyContent::new();
        c.set_available(true);
        c.set_findings(sample_findings());
        let out = render_to_string(&mut c, 110, 44);
        assert!(out.contains("CRITICAL"), "severity group header: {out}");
        assert!(out.contains("syntax errors"), "finding title: {out}");
        assert!(out.contains("Fix the syntax errors"), "fix hint: {out}");
    }

    #[test]
    fn scroll_down_consumed_and_returns_none() {
        let mut c = ProxyContent::new();
        c.set_available(true);
        assert!(c.handle_key(KeyCode::Down).is_none());
        assert_eq!(c.scroll(), 1);
    }

    #[test]
    fn scroll_up_at_zero_stays_zero() {
        let mut c = ProxyContent::new();
        c.set_available(true);
        c.handle_key(KeyCode::Up);
        assert_eq!(c.scroll(), 0);
    }

    #[test]
    fn esc_returns_back_action() {
        let mut c = ProxyContent::new();
        assert_eq!(c.handle_key(KeyCode::Esc), Some(Action::Back));
    }

    #[test]
    fn mouse_scroll_wheel_adjusts_scroll() {
        let mut c = ProxyContent::new();
        let down = MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 0,
            row: 0,
            modifiers: crossterm::event::KeyModifiers::empty(),
        };
        c.handle_mouse(down);
        assert_eq!(c.scroll(), 1);
    }

    #[test]
    fn tiny_terminal_does_not_panic() {
        let mut c = ProxyContent::new();
        c.set_available(true);
        c.set_server_blocks(sample_server_blocks());
        c.set_certificates(sample_certs(), true);
        c.set_findings(sample_findings());
        // 20x5 — well below comfortable, must not panic.
        let _ = render_to_string(&mut c, 20, 5);
    }

    /// Coverage complement to `tiny_terminal_does_not_panic`: that test only
    /// exercises the `available=true` render path. This locks in the no-panic
    /// property of the degraded `render_unavailable` path (which uses only
    /// saturating ops + Rect clipping) at extreme small sizes.
    #[test]
    fn tiny_terminal_unavailable_does_not_panic() {
        // 20x3 — even tighter than the available-path test.
        let mut c = ProxyContent::new();
        let _ = render_to_string(&mut c, 20, 3);
        // 20x5 — matches the available-path test's height.
        let mut c2 = ProxyContent::new();
        let _ = render_to_string(&mut c2, 20, 5);
    }

    #[test]
    fn set_findings_replaces_and_keeps_scroll_finite() {
        let mut c = ProxyContent::new();
        c.scroll = 1_000_000;
        c.set_findings(sample_findings());
        // After a render the scroll is clamped to the visible window.
        let _ = render_to_string(&mut c, 100, 30);
        // scroll must not overflow; the important property is the render did
        // not panic.
    }

    #[test]
    fn empty_states_render_without_panic() {
        let mut c = ProxyContent::new();
        c.set_available(true);
        let out = render_to_string(&mut c, 100, 30);
        assert!(
            out.contains("no server blocks configured"),
            "empty blocks: {out}"
        );
        assert!(out.contains("no certificates found"), "empty certs: {out}");
        assert!(out.contains("no findings"), "empty findings: {out}");
    }
}
