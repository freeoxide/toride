//! Fail2ban management content area (live READ-ONLY).
//!
//! Renders inside the dashboard's content region when
//! [`Section::Fail2ban`](crate::data::Section) is the active sidebar section.
//! This is the TEMPLATE integration: it mirrors the SSH reference (`SshContent`
//! + sub-tabs) but WITHOUT any write path — every line is read-only.
//!
//! Layout (single scrollable pane, no sub-tab bar):
//! 1. Status panel — active/enabled badges + version.
//! 2. Jails table — name, banned count, file count.
//! 3. Bans list — currently banned IPs across jails.
//! 4. Doctor findings — grouped by severity (Critical > Error > Warning > Info).
//! 5. Firewall-backend card — nftables / iptables availability.

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

/// A single fail2ban jail row.
#[derive(Clone, Debug)]
pub struct JailEntry {
    /// Jail name (e.g. "sshd").
    pub name: String,
    /// Whether the jail is currently running.
    pub is_running: bool,
    /// Number of IPs currently banned in this jail.
    pub banned_count: usize,
    /// Total bans performed since jail start.
    pub total_bans: usize,
    /// Number of log files monitored.
    pub file_count: usize,
}

/// A single currently-banned IP.
#[derive(Clone, Debug)]
pub struct BanEntry {
    /// The banned IP address.
    pub ip: String,
    /// Jail(s) that banned this IP (best-effort — `fail2ban-client banned`
    /// groups by IP).
    pub jails: Vec<String>,
}

/// A single doctor finding.
#[derive(Clone, Debug)]
pub struct FindingEntry {
    /// Machine-readable dot-separated id (e.g. "binary.fail2ban-client.missing").
    pub id: String,
    /// Severity as a lowercase string: "ok" | "info" | "warning" | "error" | "critical".
    pub severity: String,
    /// Short human-readable title.
    pub title: String,
    /// Longer description (may be empty).
    pub detail: String,
    /// Suggested remediation, if any.
    pub fix: Option<String>,
}

// ── Fail2banContent ─────────────────────────────────────────────────────────

/// Fail2ban management content rendered inside the dashboard content area.
///
/// READ-ONLY: there are no write operations, no optimistic updates, no loading
/// spinner, no cooldown. Data arrives via [`Fail2banContent::set_*`] setters
/// driven by [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector).
pub struct Fail2banContent {
    /// Whether the fail2ban backend was reachable at all (binaries present,
    /// service queryable). `false` means the section renders a degraded
    /// "unavailable" panel instead of live data.
    available: bool,
    /// Service active (running).
    service_active: bool,
    /// Service enabled at boot.
    service_enabled: bool,
    /// Fail2ban version string, if detected.
    version: Option<String>,
    /// nftables backend availability.
    fw_nft_available: Option<bool>,
    /// iptables backend availability.
    fw_iptables_available: Option<bool>,
    /// Active jails.
    jails: Vec<JailEntry>,
    /// Currently banned IPs.
    bans: Vec<BanEntry>,
    /// Doctor findings.
    findings: Vec<FindingEntry>,
    /// Human-readable reason the backend was unreachable, surfaced in the
    /// degraded panel. Populated only when a collection task panicked.
    unavailable_reason: Option<String>,
    /// Vertical scroll offset over the whole pane.
    scroll: usize,
}

impl Default for Fail2banContent {
    fn default() -> Self {
        Self::new()
    }
}

impl Fail2banContent {
    /// Create a new empty content area.
    #[must_use]
    pub fn new() -> Self {
        Self {
            available: false,
            service_active: false,
            service_enabled: false,
            version: None,
            fw_nft_available: None,
            fw_iptables_available: None,
            jails: Vec::new(),
            bans: Vec::new(),
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

    // ── Data setters ─────────────────────────────────────────────────────────

    /// Replace service status fields (drives the status panel).
    pub fn set_service(&mut self, active: bool, enabled: bool, version: Option<String>) {
        self.service_active = active;
        self.service_enabled = enabled;
        self.version = version;
    }

    /// Replace the jails list and clamp scroll.
    pub fn set_jails(&mut self, jails: Vec<JailEntry>) {
        self.jails = jails;
        self.clamp_scroll();
    }

    /// Replace the bans list and clamp scroll.
    pub fn set_bans(&mut self, bans: Vec<BanEntry>) {
        self.bans = bans;
        self.clamp_scroll();
    }

    /// Replace the findings list and clamp scroll.
    pub fn set_findings(&mut self, findings: Vec<FindingEntry>) {
        self.findings = findings;
        self.clamp_scroll();
    }

    /// Replace firewall-backend availability.
    pub fn set_firewall(&mut self, nft: Option<bool>, iptables: Option<bool>) {
        self.fw_nft_available = nft;
        self.fw_iptables_available = iptables;
    }

    /// Set the overall availability flag (false → degraded panel).
    pub fn set_available(&mut self, available: bool) {
        self.available = available;
    }

    /// Total currently-banned IPs across all jails, surfaced as the sidebar
    /// badge for the fail2ban section. Falls back to the jail count when bans
    /// are not reported. `None` when the backend is unreachable
    /// (`available == false`) so the badge stays honestly empty.
    #[must_use]
    pub fn total_bans(&self) -> Option<usize> {
        if !self.available {
            return None;
        }
        // Count of distinct banned IPs (one per `BanEntry`), NOT the summed
        // byte-length of the IP strings — summing `b.ip.len()` previously
        // reported 25 for two bans ("203.0.113.42" + "198.51.100.7") and wildly
        // inflated the sidebar badge (worse for long IPv6 addresses).
        let banned = self.bans.len();
        if banned > 0 {
            Some(banned)
        } else {
            Some(self.jails.len())
        }
    }

    /// Set the human-readable reason the backend was unreachable. Cleared
    /// (`None`) whenever availability flips back to `true` so a stale panic
    /// message can't linger after recovery.
    pub fn set_unavailable_reason(&mut self, reason: Option<String>) {
        self.unavailable_reason = if self.available { None } else { reason };
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
    #[expect(clippy::unused_self, reason = "API symmetry with SSH tabs")]
    fn clamp_scroll(&mut self) {
        // No-op body: scroll is clamped against visible rows during render.
        // Kept for API symmetry with SSH tabs (which clamp on set).
    }

    // ── Rendering ───────────────────────────────────────────────────────────

    /// Render the full fail2ban content area.
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
                " FAIL2BAN · {} jail(s) · {} ban(s) · {} finding(s) ",
                self.jails.len(),
                self.bans.len(),
                self.findings.len(),
            ),
            p.accent,
            true,
        );

        if inner.height == 0 {
            return;
        }

        // Build the full content as a Vec<Line> then render only the visible
        // window (mirrors the SSH tabs' manual-scroll approach).
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

    /// Render the degraded state when fail2ban is unavailable on this host.
    ///
    /// `available == false` is only ever set when a collection task returned an
    /// empty bundle, which today happens exclusively when the `spawn_blocking`
    /// task PANICS (`JoinError`) — not when the binary is missing (a missing
    /// binary instead produces a Critical doctor finding, which keeps
    /// `available == true` so the operator sees the findings panel). The reason
    /// string is surfaced here so the operator can see what actually panicked;
    /// when no reason is known we fall back to a generic, accurate message
    /// rather than the misleading "binary not found" text (which describes a
    /// case that never reaches this code path).
    fn render_unavailable(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " FAIL2BAN ", p.text_dim, false);
        let msg = Line::from(vec![
            Span::styled("✦ ", Style::new().fg(p.warn)),
            Span::styled(
                "fail2ban unavailable",
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
        ]);
        // Prefer the panic reason from the bundle; otherwise a generic message
        // that is accurate for both the panic case and the pre-first-poll state.
        let detail_text = self
            .unavailable_reason
            .clone()
            .unwrap_or_else(|| "fail2ban data could not be collected on this host".to_string());
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

    /// Build the complete content as a flat list of lines (status, jails,
    /// bans, findings, firewall). Scrolling operates over this list.
    fn build_lines(&self, p: Palette) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();

        self.push_status_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_jails_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_bans_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_findings_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_firewall_lines(&mut lines, p);

        lines
    }

    fn push_status_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "Service",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        // Active badge.
        let (active_label, active_color) = if self.service_active {
            ("● active", p.ok)
        } else {
            ("○ inactive", p.err)
        };
        lines.push(Line::from(vec![
            Span::styled("  state    ", Style::new().fg(p.text_muted)),
            Span::styled(active_label, Style::new().fg(active_color)),
        ]));

        // Enabled badge.
        let (enabled_label, enabled_color) = if self.service_enabled {
            ("● enabled", p.ok)
        } else {
            ("○ disabled", p.warn)
        };
        lines.push(Line::from(vec![
            Span::styled("  boot     ", Style::new().fg(p.text_muted)),
            Span::styled(enabled_label, Style::new().fg(enabled_color)),
        ]));

        // Version.
        let version = self.version.clone().unwrap_or_else(|| "(unknown)".into());
        lines.push(Line::from(vec![
            Span::styled("  version  ", Style::new().fg(p.text_muted)),
            Span::styled(version, Style::new().fg(p.text)),
        ]));
    }

    fn push_jails_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        let header = format!("Jails ({})", self.jails.len());
        lines.push(Line::from(Span::styled(
            header,
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        if self.jails.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no active jails",
                Style::new().fg(p.text_dim),
            )));
            return;
        }

        for jail in &self.jails {
            let state_icon = if jail.is_running { "●" } else { "○" };
            let state_color = if jail.is_running { p.ok } else { p.text_dim };
            let name = truncate_str(&jail.name, 20);
            lines.push(Line::from(vec![
                Span::styled(format!("{state_icon} "), Style::new().fg(state_color)),
                Span::styled(
                    format!("{name:<20}"),
                    Style::new().fg(p.text).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(
                        "  banned {}  total {}  files {}",
                        jail.banned_count, jail.total_bans, jail.file_count
                    ),
                    Style::new().fg(p.text_muted),
                ),
            ]));
        }
    }

    fn push_bans_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        let header = format!("Banned IPs ({})", self.bans.len());
        lines.push(Line::from(Span::styled(
            header,
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        if self.bans.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no IPs currently banned",
                Style::new().fg(p.text_dim),
            )));
            return;
        }

        for ban in &self.bans {
            let ip = truncate_str(&ban.ip, 40);
            let jails_str = if ban.jails.is_empty() {
                String::new()
            } else {
                format!("  [{}]", ban.jails.join(","))
            };
            lines.push(Line::from(vec![
                Span::styled("  ✗ ", Style::new().fg(p.err)),
                Span::styled(ip, Style::new().fg(p.text)),
                Span::styled(jails_str, Style::new().fg(p.text_dim)),
            ]));
        }
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

    fn push_firewall_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "Firewall Backend",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));
        Self::push_fw_line(lines, p, "nftables", self.fw_nft_available);
        Self::push_fw_line(lines, p, "iptables ", self.fw_iptables_available);
    }

    fn push_fw_line(
        lines: &mut Vec<Line<'static>>,
        p: Palette,
        label: &str,
        available: Option<bool>,
    ) {
        let (icon, text, color) = match available {
            Some(true) => ("✓", "available", p.ok),
            Some(false) => ("✗", "not available", p.warn),
            None => ("?", "unknown", p.text_dim),
        };
        lines.push(Line::from(vec![
            Span::styled(format!("  {label}  "), Style::new().fg(p.text_muted)),
            Span::styled(format!("{icon} {text}"), Style::new().fg(color)),
        ]));
    }
}

impl crate::ui::screens::section_overview::SectionOverview for Fail2banContent {
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
            "{} jail(s) · {} ban(s)",
            self.jails.len(),
            self.bans.len()
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

    fn sample_jails() -> Vec<JailEntry> {
        vec![
            JailEntry {
                name: "sshd".into(),
                is_running: true,
                banned_count: 3,
                total_bans: 12,
                file_count: 1,
            },
            JailEntry {
                name: "nginx-limit-req".into(),
                is_running: false,
                banned_count: 0,
                total_bans: 0,
                file_count: 2,
            },
        ]
    }

    fn sample_bans() -> Vec<BanEntry> {
        vec![
            BanEntry {
                ip: "203.0.113.42".into(),
                jails: vec!["sshd".into()],
            },
            BanEntry {
                ip: "198.51.100.7".into(),
                jails: vec!["sshd".into()],
            },
        ]
    }

    fn sample_findings() -> Vec<FindingEntry> {
        vec![
            FindingEntry {
                id: "binary.fail2ban-client.found".into(),
                severity: "ok".into(),
                title: "fail2ban-client binary found".into(),
                detail: "Located at /usr/bin/fail2ban-client".into(),
                fix: None,
            },
            FindingEntry {
                id: "service.not-enabled".into(),
                severity: "warning".into(),
                title: "Fail2Ban service is not enabled at boot".into(),
                detail: String::new(),
                fix: Some("Enable the service: systemctl enable fail2ban".into()),
            },
        ]
    }

    /// Render a content area to a string (snapshot pattern from ssh `keys_tab.rs`).
    fn render_to_string(content: &mut Fail2banContent, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| content.view(f, f.area(), CHARM)).unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn new_is_unavailable_and_empty() {
        let c = Fail2banContent::new();
        assert!(!c.available);
        assert!(c.jails.is_empty());
        assert!(c.bans.is_empty());
        assert!(c.findings.is_empty());
        assert!(!c.has_modal());
    }

    #[test]
    fn default_matches_new() {
        let from_new = Fail2banContent::new();
        let from_default = Fail2banContent::default();
        assert_eq!(from_new.available, from_default.available);
    }

    #[test]
    fn render_unavailable_when_not_available() {
        let mut c = Fail2banContent::new();
        let out = render_to_string(&mut c, 100, 24);
        assert!(
            out.contains("fail2ban unavailable"),
            "degraded panel: {out}"
        );
    }

    #[test]
    fn total_bans_counts_entries_not_ip_byte_length() {
        // Two banned-IP entries ("203.0.113.42" + "198.51.100.7") must report
        // 2 — NOT 25, which the old `bans.iter().map(|b| b.ip.len()).sum()`
        // produced by summing the IP strings' byte lengths into the badge.
        let mut c = Fail2banContent::new();
        c.set_available(true);
        c.set_bans(sample_bans());
        assert_eq!(c.total_bans(), Some(2));

        // Falls back to the jail count when there are no bans at all.
        let mut c2 = Fail2banContent::new();
        c2.set_available(true);
        c2.set_jails(sample_jails());
        assert_eq!(c2.total_bans(), Some(2)); // two jails

        // Unavailable backend reports None (honestly empty badge).
        let mut c3 = Fail2banContent::new();
        c3.set_bans(sample_bans());
        assert_eq!(c3.total_bans(), None);
    }

    #[test]
    fn render_status_panel() {
        let mut c = Fail2banContent::new();
        c.set_available(true);
        c.set_service(true, true, Some("Fail2Ban v1.0.2".into()));
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("active"), "active badge: {out}");
        assert!(out.contains("enabled"), "enabled badge: {out}");
        assert!(out.contains("Fail2Ban v1.0.2"), "version: {out}");
    }

    #[test]
    fn render_jails_table() {
        let mut c = Fail2banContent::new();
        c.set_available(true);
        c.set_jails(sample_jails());
        let out = render_to_string(&mut c, 110, 36);
        assert!(out.contains("sshd"), "jail name: {out}");
        assert!(out.contains("nginx-limit-req"), "second jail: {out}");
    }

    #[test]
    fn render_bans_list() {
        let mut c = Fail2banContent::new();
        c.set_available(true);
        c.set_bans(sample_bans());
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("203.0.113.42"), "banned ip: {out}");
        assert!(out.contains("198.51.100.7"), "second ip: {out}");
    }

    #[test]
    fn render_findings_grouped_by_severity() {
        let mut c = Fail2banContent::new();
        c.set_available(true);
        c.set_findings(sample_findings());
        let out = render_to_string(&mut c, 110, 40);
        assert!(out.contains("WARNING"), "severity group header: {out}");
        assert!(out.contains("not enabled at boot"), "finding title: {out}");
        assert!(out.contains("Enable the service"), "fix hint: {out}");
    }

    #[test]
    fn render_firewall_backend_card() {
        let mut c = Fail2banContent::new();
        c.set_available(true);
        c.set_firewall(Some(true), Some(false));
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("nftables"), "nft label: {out}");
        assert!(out.contains("iptables"), "iptables label: {out}");
    }

    #[test]
    fn scroll_down_consumed_and_returns_none() {
        let mut c = Fail2banContent::new();
        c.set_available(true);
        assert!(c.handle_key(KeyCode::Down).is_none());
        assert_eq!(c.scroll, 1);
    }

    #[test]
    fn scroll_up_at_zero_stays_zero() {
        let mut c = Fail2banContent::new();
        c.set_available(true);
        c.handle_key(KeyCode::Up);
        assert_eq!(c.scroll, 0);
    }

    #[test]
    fn esc_returns_back_action() {
        let mut c = Fail2banContent::new();
        assert_eq!(c.handle_key(KeyCode::Esc), Some(Action::Back));
    }

    #[test]
    fn mouse_scroll_wheel_adjusts_scroll() {
        let mut c = Fail2banContent::new();
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
        let mut c = Fail2banContent::new();
        c.set_available(true);
        c.set_jails(sample_jails());
        c.set_findings(sample_findings());
        // 20x5 — well below comfortable, must not panic.
        let _ = render_to_string(&mut c, 20, 5);
    }

    #[test]
    fn set_findings_replaces_and_keeps_scroll_finite() {
        let mut c = Fail2banContent::new();
        c.scroll = 1_000_000;
        c.set_findings(sample_findings());
        // After a render the scroll is clamped to the visible window.
        let _ = render_to_string(&mut c, 100, 30);
        // scroll may still be large (no rows to show against) but must not
        // overflow; the important property is the render did not panic.
    }

    #[test]
    fn empty_states_render_without_panic() {
        let mut c = Fail2banContent::new();
        c.set_available(true);
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("no active jails"), "empty jails: {out}");
        assert!(out.contains("no IPs currently banned"), "empty bans: {out}");
        assert!(out.contains("no findings"), "empty findings: {out}");
    }
}
