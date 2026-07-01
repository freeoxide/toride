//! `WireGuard` management content area (live READ-ONLY).
//!
//! Renders inside the dashboard's content region when
//! [`Section::WireGuard`](crate::data::Section) is the active sidebar section.
//! This mirrors the fail2ban / harden read-only integrations but WITHOUT any
//! write path — every line is read-only.
//!
//! Layout (single scrollable pane, no sub-tab bar):
//! 1. Status panel — wg / wg-quick binary availability + config-dir presence.
//! 2. Interfaces table — name, listen-port, peer counts, rx/tx.
//! 3. Peers table — public-key, endpoint, allowed-ips, keepalive.
//! 4. Services card — per-interface `wg-quick@<iface>` systemd unit activity.
//! 5. Doctor findings — grouped by severity (Error > Warning > Info).

use crossterm::event::{KeyCode, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
};

use crate::action::Action;
use crate::ui::helpers::format_bytes;
use crate::ui::responsive::truncate_str;
use crate::ui::theme::Palette;
use crate::ui::widgets::render_titled_panel;

// ── Presentation types ──────────────────────────────────────────────────────

/// A single `WireGuard` interface row.
#[derive(Clone, Debug)]
pub struct InterfaceEntry {
    /// Interface name (e.g. "wg0").
    pub name: String,
    /// Whether the interface is up.
    pub is_up: bool,
    /// UDP listen port (0 = kernel-assigned).
    pub listen_port: u16,
    /// Number of configured peers. `None` when the data source does not carry
    /// peer counts (e.g. the `wg show` listing path), so the UI renders "?"
    /// instead of a misleading "0".
    pub peer_count: Option<usize>,
    /// Number of peers with established handshakes. `None` when unavailable —
    /// rendered as "?" by the UI.
    pub active_peers: Option<usize>,
    /// Total bytes received across the interface. `None` when unavailable —
    /// rendered as "?" by the UI.
    pub rx_bytes: Option<u64>,
    /// Total bytes sent across the interface. `None` when unavailable —
    /// rendered as "?" by the UI.
    pub tx_bytes: Option<u64>,
}

/// A single `WireGuard` peer row.
#[derive(Clone, Debug)]
pub struct PeerEntry {
    /// The peer's Base64-encoded public key.
    pub public_key: String,
    /// Allowed IP/CIDR ranges routed to this peer.
    pub allowed_ips: Vec<String>,
    /// Optional endpoint address (`host:port`).
    pub endpoint: Option<String>,
    /// Optional persistent keepalive interval in seconds.
    pub persistent_keepalive: Option<u32>,
    /// Bytes received from this peer (0 when runtime stats unavailable).
    pub rx_bytes: u64,
    /// Bytes sent to this peer (0 when runtime stats unavailable).
    pub tx_bytes: u64,
    /// Latest handshake timestamp label, if known.
    pub latest_handshake: Option<String>,
}

/// A single `wg-quick@<iface>` systemd service row.
#[derive(Clone, Debug)]
pub struct ServiceEntry {
    /// Systemd unit name (e.g. "wg-quick@wg0").
    pub name: String,
    /// Whether the unit is currently active (running).
    pub is_active: bool,
    /// Whether the unit is enabled at boot (`None` if not probed).
    pub enabled: Option<bool>,
}

/// A single doctor finding.
#[derive(Clone, Debug)]
pub struct FindingEntry {
    /// Machine-readable dot-separated check id (e.g. "wireguard.binary.wg").
    pub check_id: String,
    /// Severity as a lowercase string: "info" | "warning" | "error". (The
    /// backend `Severity` enum has no `Ok` variant; the UI's `severity_style`
    /// still defensively accepts `"ok"` as an input.)
    pub severity: String,
    /// Human-readable description.
    pub message: String,
    /// Suggested remediation, if any.
    pub fix: Option<String>,
}

// ── WireguardContent ────────────────────────────────────────────────────────

/// `WireGuard` management content rendered inside the dashboard content area.
///
/// READ-ONLY: there are no write operations, no optimistic updates, no loading
/// spinner, no cooldown. Data arrives via [`WireguardContent::set_*`] setters
/// driven by
/// [`WireguardCollector`](crate::toride_wireguard_data::WireguardCollector).
pub struct WireguardContent {
    /// Whether the `WireGuard` backend was reachable at all (`wg` binary present,
    /// client construction succeeded). `false` means the section renders a
    /// degraded "unavailable" panel instead of live data.
    available: bool,
    /// Active interfaces.
    interfaces: Vec<InterfaceEntry>,
    /// Peers across all interfaces.
    peers: Vec<PeerEntry>,
    /// Per-interface systemd service activity.
    services: Vec<ServiceEntry>,
    /// Whether the `wg` binary was found (`None` if the probe was skipped on a
    /// cache-hit poll).
    wg_binary_found: Option<bool>,
    /// Whether the `wg-quick` binary was found.
    wg_quick_binary_found: Option<bool>,
    /// Whether `/etc/wireguard` exists.
    config_dir_exists: Option<bool>,
    /// Doctor findings.
    findings: Vec<FindingEntry>,
    /// Human-readable reason the backend was unreachable, surfaced in the
    /// degraded panel. Populated only when construction failed or a collection
    /// task panicked.
    unavailable_reason: Option<String>,
    /// Vertical scroll offset over the whole pane.
    scroll: usize,
}

impl Default for WireguardContent {
    fn default() -> Self {
        Self::new()
    }
}

impl WireguardContent {
    /// Create a new empty content area.
    #[must_use]
    pub fn new() -> Self {
        Self {
            available: false,
            interfaces: Vec::new(),
            peers: Vec::new(),
            services: Vec::new(),
            wg_binary_found: None,
            wg_quick_binary_found: None,
            config_dir_exists: None,
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

    /// Live interface count for the sidebar badge. `None` when the backend is
    /// unavailable so the badge stays honestly empty at cold start rather than
    /// flashing a fabricated number.
    #[must_use]
    pub fn badge_count(&self) -> Option<usize> {
        if self.available {
            Some(self.interfaces.len())
        } else {
            None
        }
    }

    // ── Data setters ─────────────────────────────────────────────────────────

    /// Replace the interfaces list and clamp scroll.
    pub fn set_interfaces(&mut self, interfaces: Vec<InterfaceEntry>) {
        self.interfaces = interfaces;
        self.clamp_scroll();
    }

    /// Replace the peers list and clamp scroll.
    pub fn set_peers(&mut self, peers: Vec<PeerEntry>) {
        self.peers = peers;
        self.clamp_scroll();
    }

    /// Replace the services list and clamp scroll.
    pub fn set_services(&mut self, services: Vec<ServiceEntry>) {
        self.services = services;
        self.clamp_scroll();
    }

    /// Replace binary / config-dir availability probes.
    pub fn set_env(&mut self, wg: Option<bool>, wg_quick: Option<bool>, config_dir: Option<bool>) {
        self.wg_binary_found = wg;
        self.wg_quick_binary_found = wg_quick;
        self.config_dir_exists = config_dir;
    }

    /// Replace the findings list and clamp scroll.
    pub fn set_findings(&mut self, findings: Vec<FindingEntry>) {
        self.findings = findings;
        self.clamp_scroll();
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

    /// Current vertical scroll offset (crate-visible for dispatch tests).
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
    /// once the visible row count is known, since `view` is the only place
    /// that knows the inner pane height.
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

    /// Render the full `WireGuard` content area.
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
                " WIREGUARD · {} iface(s) · {} peer(s) · {} finding(s) ",
                self.interfaces.len(),
                self.peers.len(),
                self.findings.len(),
            ),
            p.accent,
            true,
        );

        if inner.height == 0 {
            return;
        }

        // Build the full content as a Vec<Line> then render only the visible
        // window (mirrors the fail2ban / harden manual-scroll approach).
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

    /// Render the degraded state when `WireGuard` is unavailable on this host.
    ///
    /// `available == false` is set when construction failed (`BinaryNotFound`
    /// on macOS) or when a collection task panicked. The reason string is
    /// surfaced here so the operator can see what went wrong; when no reason
    /// is known we fall back to a generic message.
    fn render_unavailable(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " WIREGUARD ", p.text_dim, false);
        let msg = Line::from(vec![
            Span::styled("✦ ", Style::new().fg(p.warn)),
            Span::styled(
                "wireguard unavailable",
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
        ]);
        let detail_text = self
            .unavailable_reason
            .clone()
            .unwrap_or_else(|| "WireGuard data could not be collected on this host".to_string());
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
        // Wrap so a long panic reason wraps within the panel instead of clipping.
        frame.render_widget(
            Paragraph::new(detail).centered().wrap(Wrap { trim: false }),
            centered_detail,
        );
    }

    /// Build the complete content as a flat list of lines (status, interfaces,
    /// peers, services, findings). Scrolling operates over this list.
    fn build_lines(&self, p: Palette) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();

        self.push_status_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_interfaces_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_peers_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_services_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_findings_lines(&mut lines, p);

        lines
    }

    fn push_status_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "Environment",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        Self::push_env_line(lines, p, "wg       ", self.wg_binary_found);
        Self::push_env_line(lines, p, "wg-quick ", self.wg_quick_binary_found);
        Self::push_env_line(lines, p, "conf dir ", self.config_dir_exists);
    }

    fn push_env_line(
        lines: &mut Vec<Line<'static>>,
        p: Palette,
        label: &str,
        present: Option<bool>,
    ) {
        let (icon, text, color) = match present {
            Some(true) => ("✓", "present", p.ok),
            Some(false) => ("✗", "absent", p.warn),
            None => ("?", "unknown", p.text_dim),
        };
        lines.push(Line::from(vec![
            Span::styled(format!("  {label}  "), Style::new().fg(p.text_muted)),
            Span::styled(format!("{icon} {text}"), Style::new().fg(color)),
        ]));
    }

    fn push_interfaces_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        let header = format!("Interfaces ({})", self.interfaces.len());
        lines.push(Line::from(Span::styled(
            header,
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        if self.interfaces.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no active interfaces",
                Style::new().fg(p.text_dim),
            )));
            return;
        }

        for iface in &self.interfaces {
            let state_icon = if iface.is_up { "●" } else { "○" };
            let state_color = if iface.is_up { p.ok } else { p.text_dim };
            let name = truncate_str(&iface.name, 12);
            let port = if iface.listen_port == 0 {
                "auto".to_string()
            } else {
                iface.listen_port.to_string()
            };
            // Peer counts / transfer stats are `Option`: `None` means the data
            // source (the `wg show` listing path) does not carry them, so we
            // render "?" rather than a misleading "0/0  rx 0 B  tx 0 B" that
            // would contradict the live Peers table below.
            let active_peers = iface
                .active_peers
                .map_or("?".to_string(), |n| n.to_string());
            let peer_count = iface.peer_count.map_or("?".to_string(), |n| n.to_string());
            let rx = iface.rx_bytes.map_or("?".to_string(), format_bytes);
            let tx = iface.tx_bytes.map_or("?".to_string(), format_bytes);
            lines.push(Line::from(vec![
                Span::styled(format!("{state_icon} "), Style::new().fg(state_color)),
                Span::styled(
                    format!("{name:<12}"),
                    Style::new().fg(p.text).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("  port {port}  peers {active_peers}/{peer_count}  rx {rx}  tx {tx}"),
                    Style::new().fg(p.text_muted),
                ),
            ]));
        }
    }

    fn push_peers_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        let header = format!("Peers ({})", self.peers.len());
        lines.push(Line::from(Span::styled(
            header,
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        if self.peers.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no peers",
                Style::new().fg(p.text_dim),
            )));
            return;
        }

        for peer in &self.peers {
            let key = truncate_str(&peer.public_key, 20);
            let endpoint = peer
                .endpoint
                .clone()
                .unwrap_or_else(|| "(none)".to_string());
            let endpoint = truncate_str(&endpoint, 24);
            let allowed = if peer.allowed_ips.is_empty() {
                "(none)".to_string()
            } else {
                peer.allowed_ips.join(",")
            };
            let allowed = truncate_str(&allowed, 24);
            let keepalive = peer
                .persistent_keepalive
                .map(|s| format!("  ka {s}s"))
                .unwrap_or_default();
            lines.push(Line::from(vec![
                Span::styled("  · ", Style::new().fg(p.text_dim)),
                Span::styled(format!("{key:<20}"), Style::new().fg(p.text)),
                Span::styled(format!("  {endpoint:<24}"), Style::new().fg(p.text_muted)),
                Span::styled(format!("  {allowed:<24}"), Style::new().fg(p.text_dim)),
                Span::styled(keepalive, Style::new().fg(p.text_muted)),
            ]));
        }
    }

    fn push_services_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        let header = format!("Services ({})", self.services.len());
        lines.push(Line::from(Span::styled(
            header,
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        if self.services.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no wg-quick services",
                Style::new().fg(p.text_dim),
            )));
            return;
        }

        for svc in &self.services {
            let (active_label, active_color) = if svc.is_active {
                ("● active", p.ok)
            } else {
                ("○ inactive", p.err)
            };
            let (enabled_label, enabled_color) = match svc.enabled {
                Some(true) => ("enabled", p.ok),
                Some(false) => ("disabled", p.warn),
                None => ("unknown", p.text_dim),
            };
            let name = truncate_str(&svc.name, 22);
            lines.push(Line::from(vec![
                Span::styled(format!("  {name:<22}"), Style::new().fg(p.text)),
                Span::styled(format!("  {active_label}"), Style::new().fg(active_color)),
                Span::styled(
                    format!("  · {enabled_label}"),
                    Style::new().fg(enabled_color),
                ),
            ]));
        }
    }

    fn push_findings_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        // Group by severity: Error > Warning > Info.
        const ORDER: &[&str] = &["error", "warning", "info"];
        crate::ui::screens::findings::push_findings_grouped(
            lines,
            p,
            &self.findings,
            ORDER,
            crate::ui::screens::findings::severity_style_full,
            crate::ui::screens::findings::FindingWidths::TITLE_70,
        );
    }
}

impl crate::ui::screens::section_overview::SectionOverview for WireguardContent {
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
            "{} interface(s) · {} peer(s)",
            self.interfaces.len(),
            self.peers.len()
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
        // The Wireguard backend exposes a single `message` field rendered in
        // the title slot.
        &self.message
    }
    fn detail(&self) -> Option<&str> {
        None
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

    fn sample_interfaces() -> Vec<InterfaceEntry> {
        vec![InterfaceEntry {
            name: "wg0".into(),
            is_up: true,
            listen_port: 51820,
            peer_count: Some(3),
            active_peers: Some(2),
            rx_bytes: Some(1_234_567),
            tx_bytes: Some(9_876_543),
        }]
    }

    fn sample_peers() -> Vec<PeerEntry> {
        vec![PeerEntry {
            public_key: "ABCDEF+ghijklmnopqrstuv==".into(),
            allowed_ips: vec!["10.0.0.2/32".into()],
            endpoint: Some("203.0.113.1:51820".into()),
            persistent_keepalive: Some(25),
            rx_bytes: 0,
            tx_bytes: 0,
            latest_handshake: None,
        }]
    }

    fn sample_services() -> Vec<ServiceEntry> {
        vec![ServiceEntry {
            name: "wg-quick@wg0".into(),
            is_active: true,
            enabled: Some(true),
        }]
    }

    fn sample_findings() -> Vec<FindingEntry> {
        vec![
            FindingEntry {
                check_id: "wireguard.binary.wg".into(),
                severity: "error".into(),
                message: "`wg` binary not found on $PATH".into(),
                fix: Some("Install wireguard-tools: apt install wireguard-tools".into()),
            },
            FindingEntry {
                check_id: "wireguard.config-dir".into(),
                severity: "warning".into(),
                message: "WireGuard config directory does not exist".into(),
                fix: None,
            },
        ]
    }

    /// Render a content area to a string (snapshot pattern from fail2ban / ssh).
    fn render_to_string(content: &mut WireguardContent, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| content.view(f, f.area(), CHARM)).unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn new_is_unavailable_and_empty() {
        let c = WireguardContent::new();
        assert!(!c.available);
        assert!(c.interfaces.is_empty());
        assert!(c.peers.is_empty());
        assert!(c.services.is_empty());
        assert!(c.findings.is_empty());
        assert!(!c.has_modal());
    }

    #[test]
    fn default_matches_new() {
        let from_new = WireguardContent::new();
        let from_default = WireguardContent::default();
        assert_eq!(from_new.available, from_default.available);
    }

    #[test]
    fn render_unavailable_when_not_available() {
        let mut c = WireguardContent::new();
        let out = render_to_string(&mut c, 100, 24);
        assert!(
            out.contains("wireguard unavailable"),
            "degraded panel: {out}"
        );
    }

    #[test]
    fn render_unavailable_shows_reason() {
        let mut c = WireguardContent::new();
        c.set_unavailable_reason(Some("boom".into()));
        let out = render_to_string(&mut c, 100, 24);
        assert!(out.contains("boom"), "reason surfaced: {out}");
    }

    #[test]
    fn render_status_panel() {
        let mut c = WireguardContent::new();
        c.set_available(true);
        c.set_env(Some(true), Some(false), Some(true));
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("wg"), "wg label: {out}");
        assert!(out.contains("wg-quick"), "wg-quick label: {out}");
        assert!(out.contains("present"), "present badge: {out}");
        assert!(out.contains("absent"), "absent badge: {out}");
    }

    #[test]
    fn render_interfaces_table() {
        let mut c = WireguardContent::new();
        c.set_available(true);
        c.set_interfaces(sample_interfaces());
        let out = render_to_string(&mut c, 110, 30);
        assert!(out.contains("wg0"), "interface name: {out}");
        assert!(out.contains("51820"), "listen port: {out}");
    }

    #[test]
    fn render_peers_table() {
        let mut c = WireguardContent::new();
        c.set_available(true);
        c.set_peers(sample_peers());
        let out = render_to_string(&mut c, 130, 30);
        assert!(out.contains("ABCDEF"), "peer pubkey: {out}");
        assert!(out.contains("203.0.113.1:51820"), "peer endpoint: {out}");
        assert!(out.contains("10.0.0.2/32"), "peer allowed ip: {out}");
        assert!(out.contains("ka 25s"), "peer keepalive: {out}");
    }

    #[test]
    fn render_services_card() {
        let mut c = WireguardContent::new();
        c.set_available(true);
        c.set_services(sample_services());
        let out = render_to_string(&mut c, 110, 30);
        assert!(out.contains("wg-quick@wg0"), "service name: {out}");
        assert!(out.contains("active"), "service active badge: {out}");
        assert!(out.contains("enabled"), "service enabled badge: {out}");
    }

    #[test]
    fn render_findings_grouped_by_severity() {
        let mut c = WireguardContent::new();
        c.set_available(true);
        c.set_findings(sample_findings());
        let out = render_to_string(&mut c, 110, 40);
        assert!(out.contains("ERROR"), "severity group header: {out}");
        assert!(out.contains("WARNING"), "severity group header: {out}");
        assert!(out.contains("Install wireguard-tools"), "fix hint: {out}");
    }

    #[test]
    fn scroll_down_consumed_and_returns_none() {
        let mut c = WireguardContent::new();
        c.set_available(true);
        assert!(c.handle_key(KeyCode::Down).is_none());
        assert_eq!(c.scroll, 1);
    }

    #[test]
    fn scroll_up_at_zero_stays_zero() {
        let mut c = WireguardContent::new();
        c.set_available(true);
        c.handle_key(KeyCode::Up);
        assert_eq!(c.scroll, 0);
    }

    #[test]
    fn esc_returns_back_action() {
        let mut c = WireguardContent::new();
        assert_eq!(c.handle_key(KeyCode::Esc), Some(Action::Back));
    }

    #[test]
    fn mouse_scroll_wheel_adjusts_scroll() {
        let mut c = WireguardContent::new();
        let down = MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 0,
            row: 0,
            modifiers: crossterm::event::KeyModifiers::empty(),
        };
        c.handle_mouse(down);
        assert_eq!(c.scroll, 1);
    }

    #[test]
    fn tiny_terminal_does_not_panic() {
        let mut c = WireguardContent::new();
        c.set_available(true);
        c.set_interfaces(sample_interfaces());
        c.set_peers(sample_peers());
        c.set_findings(sample_findings());
        // 20x5 — well below comfortable, must not panic.
        let _ = render_to_string(&mut c, 20, 5);
    }

    #[test]
    fn empty_states_render_without_panic() {
        let mut c = WireguardContent::new();
        c.set_available(true);
        let out = render_to_string(&mut c, 100, 30);
        assert!(
            out.contains("no active interfaces"),
            "empty interfaces: {out}"
        );
        assert!(out.contains("no peers"), "empty peers: {out}");
        assert!(
            out.contains("no wg-quick services"),
            "empty services: {out}"
        );
        assert!(out.contains("no findings"), "empty findings: {out}");
    }

    #[test]
    fn set_findings_replaces_and_keeps_scroll_finite() {
        let mut c = WireguardContent::new();
        c.scroll = 1_000_000;
        c.set_findings(sample_findings());
        // After a render the scroll is clamped to the visible window.
        let _ = render_to_string(&mut c, 100, 30);
        // The important property is the render did not panic.
    }
}
