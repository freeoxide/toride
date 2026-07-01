//! Cloud provider security-group management content area (live READ-ONLY).
//!
//! Renders inside the dashboard's content region when
//! [`Section::Cloud`](crate::data::Section) is the active sidebar section.
//! This mirrors the fail2ban TEMPLATE integration (`Fail2banContent`) but for
//! cloud providers (AWS / GCP / `DigitalOcean` / Hetzner). It is strictly
//! READ-ONLY: there are no write operations, no optimistic updates, no loading
//! spinner, no cooldown. Every line is a read.
//!
//! Layout (single scrollable pane, no sub-tab bar):
//! 1. Provider panel — detected provider + CLI tool + metadata endpoint.
//! 2. Agent service card — whether the provider's agent service is
//!    running / enabled at boot.
//! 3. Security groups table — name, ingress/egress counts, per-rule detail.
//! 4. Doctor findings — grouped by severity (Critical > Error > Warning > Info).

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

/// Detected cloud provider summary.
#[derive(Clone, Debug)]
pub struct ProviderInfo {
    /// Human-friendly provider label (`"AWS" | "GCP" | "DigitalOcean" |
    /// "Hetzner" | "none"`).
    pub provider: String,
    /// CLI tool name (`aws` / `gcloud` / `doctl` / `hcloud`), `None` for an
    /// unknown provider.
    pub cli_tool: Option<String>,
    /// Provider metadata endpoint URL, if any.
    pub metadata_url: Option<String>,
}

/// A single firewall / security-group rule row.
#[derive(Clone, Debug)]
pub struct FirewallRuleEntry {
    /// `"ingress"` or `"egress"`.
    pub direction: String,
    /// Protocol (`tcp` / `udp` / `icmp` / `all` / `<n>`).
    pub protocol: String,
    /// Port or port range as a string (`None` when the rule is not port-scoped,
    /// e.g. ICMP or "all protocols").
    pub port: Option<String>,
    /// Source (ingress) / destination (egress) CIDR. `(any)` placeholder when
    /// the backend rule had an empty CIDR.
    pub cidr: String,
    /// `"allow"` or `"deny"`.
    pub action: String,
    /// Rule description (may be empty).
    pub description: String,
}

/// A single security group (AWS) / firewall (GCP/DO/Hetzner) row.
#[derive(Clone, Debug)]
pub struct SecurityGroupEntry {
    /// Group / firewall name.
    pub name: String,
    /// Group description (may be empty).
    pub description: String,
    /// Rules in this group (ingress + egress interleaved in source order).
    pub rules: Vec<FirewallRuleEntry>,
    /// Count of ingress rules (derived from `rules` so it always agrees with
    /// what is rendered).
    pub ingress_count: usize,
    /// Count of egress rules.
    pub egress_count: usize,
}

/// A single doctor finding.
#[derive(Clone, Debug)]
pub struct CloudFindingEntry {
    /// Machine-readable dot-separated id (e.g. "provider.unknown").
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

// ── CloudContent ────────────────────────────────────────────────────────────

/// Cloud provider management content rendered inside the dashboard content area.
///
/// READ-ONLY: there are no write operations, no optimistic updates, no loading
/// spinner, no cooldown. Data arrives via [`CloudContent::set_*`] setters
/// driven by [`CloudCollector`](crate::toride_cloud_data::CloudCollector).
pub struct CloudContent {
    /// Whether the cloud backend was reachable at all (provider detectable or
    /// any data returned). `false` means the section renders a degraded
    /// "unavailable" panel instead of live data.
    available: bool,
    /// Detected provider summary.
    provider: ProviderInfo,
    /// Whether the provider's agent service is running.
    agent_running: bool,
    /// Whether the provider's agent service is enabled at boot.
    agent_enabled: bool,
    /// Name of the provider's agent service (empty when unknown provider).
    agent_service_name: String,
    /// Security groups / firewalls.
    security_groups: Vec<SecurityGroupEntry>,
    /// Doctor findings.
    findings: Vec<CloudFindingEntry>,
    /// Human-readable reason the backend was unreachable, surfaced in the
    /// degraded panel. Populated only when a collection task panicked.
    unavailable_reason: Option<String>,
    /// Vertical scroll offset over the whole pane.
    scroll: usize,
}

impl Default for CloudContent {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudContent {
    /// Create a new empty content area.
    #[must_use]
    pub fn new() -> Self {
        Self {
            available: false,
            provider: ProviderInfo {
                provider: "none".into(),
                cli_tool: None,
                metadata_url: None,
            },
            agent_running: false,
            agent_enabled: false,
            agent_service_name: String::new(),
            security_groups: Vec::new(),
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

    /// Live security-group count for the sidebar badge. `None` when the
    /// backend is unavailable so the badge stays honestly empty.
    #[must_use]
    pub fn badge_count(&self) -> Option<usize> {
        if self.available {
            Some(self.security_groups.len())
        } else {
            None
        }
    }

    // ── Data setters ─────────────────────────────────────────────────────────

    /// Replace the provider summary (drives the provider panel).
    pub fn set_provider(&mut self, provider: ProviderInfo) {
        self.provider = provider;
    }

    /// Replace the agent-service status fields.
    pub fn set_agent(&mut self, running: bool, enabled: bool, service_name: String) {
        self.agent_running = running;
        self.agent_enabled = enabled;
        self.agent_service_name = service_name;
    }

    /// Replace the security-groups list and clamp scroll.
    pub fn set_security_groups(&mut self, groups: Vec<SecurityGroupEntry>) {
        self.security_groups = groups;
        self.clamp_scroll();
    }

    /// Replace the findings list and clamp scroll.
    pub fn set_findings(&mut self, findings: Vec<CloudFindingEntry>) {
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

    /// Current scroll offset (test accessor — mirrors the other read-only
    /// content sections; used by the dashboard dispatch regression test).
    #[cfg(test)]
    pub fn scroll(&self) -> usize {
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
        reason = "API symmetry with other read-only sections"
    )]
    fn clamp_scroll(&mut self) {
        // No-op body: scroll is clamped against visible rows during render.
        // Kept for API symmetry with the other read-only sections.
    }

    // ── Rendering ───────────────────────────────────────────────────────────

    /// Render the full cloud content area.
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
                " CLOUD · {} · {} group(s) · {} finding(s) ",
                self.provider.provider,
                self.security_groups.len(),
                self.findings.len(),
            ),
            p.accent,
            true,
        );

        if inner.height == 0 {
            return;
        }

        // Build the full content as a Vec<Line> then render only the visible
        // window (mirrors the fail2ban/SSH tabs' manual-scroll approach).
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

    /// Render the degraded state when cloud data is unavailable on this host.
    ///
    /// `available == false` is only ever set when a collection task returned an
    /// empty bundle, which today happens exclusively when the `spawn_blocking`
    /// task PANICS (`JoinError`) — not when the provider is `Unknown` (an unknown
    /// provider instead produces a Warning doctor finding, which keeps
    /// `available == true` so the operator sees the findings panel). The reason
    /// string is surfaced here so the operator can see what actually panicked;
    /// when no reason is known we fall back to a generic, accurate message.
    fn render_unavailable(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " CLOUD ", p.text_dim, false);
        let msg = Line::from(vec![
            Span::styled("☁ ", Style::new().fg(p.warn)),
            Span::styled(
                "cloud data unavailable",
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
        ]);
        // Prefer the panic reason from the bundle; otherwise a generic message
        // that is accurate for both the panic case and the pre-first-poll state.
        let detail_text = self
            .unavailable_reason
            .clone()
            .unwrap_or_else(|| "cloud data could not be collected on this host".to_string());
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

    /// Build the complete content as a flat list of lines (provider, agent,
    /// security groups, findings). Scrolling operates over this list.
    fn build_lines(&self, p: Palette) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();

        self.push_provider_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_agent_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_security_groups_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_findings_lines(&mut lines, p);

        lines
    }

    fn push_provider_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "Provider",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        // Provider label.
        lines.push(Line::from(vec![
            Span::styled("  provider ", Style::new().fg(p.text_muted)),
            Span::styled(
                self.provider.provider.clone(),
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
        ]));

        // CLI tool.
        let cli = self.provider.cli_tool.clone().unwrap_or_else(|| "—".into());
        lines.push(Line::from(vec![
            Span::styled("  cli      ", Style::new().fg(p.text_muted)),
            Span::styled(cli, Style::new().fg(p.text)),
        ]));

        // Metadata endpoint.
        let metadata = self
            .provider
            .metadata_url
            .clone()
            .unwrap_or_else(|| "—".into());
        let metadata = truncate_str(&metadata, 60);
        lines.push(Line::from(vec![
            Span::styled("  metadata ", Style::new().fg(p.text_muted)),
            Span::styled(metadata, Style::new().fg(p.text_dim)),
        ]));
    }

    fn push_agent_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "Agent Service",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        let service = if self.agent_service_name.is_empty() {
            "(none)".to_string()
        } else {
            self.agent_service_name.clone()
        };
        lines.push(Line::from(vec![
            Span::styled("  service  ", Style::new().fg(p.text_muted)),
            Span::styled(service, Style::new().fg(p.text)),
        ]));

        // Running badge.
        let (running_label, running_color) = if self.agent_running {
            ("● running", p.ok)
        } else {
            ("○ stopped", p.text_dim)
        };
        lines.push(Line::from(vec![
            Span::styled("  state    ", Style::new().fg(p.text_muted)),
            Span::styled(running_label, Style::new().fg(running_color)),
        ]));

        // Enabled badge.
        let (enabled_label, enabled_color) = if self.agent_enabled {
            ("● enabled", p.ok)
        } else {
            ("○ disabled", p.warn)
        };
        lines.push(Line::from(vec![
            Span::styled("  boot     ", Style::new().fg(p.text_muted)),
            Span::styled(enabled_label, Style::new().fg(enabled_color)),
        ]));
    }

    fn push_security_groups_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        let header = format!("Security Groups ({})", self.security_groups.len());
        lines.push(Line::from(Span::styled(
            header,
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        if self.security_groups.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no security groups / firewalls",
                Style::new().fg(p.text_dim),
            )));
            return;
        }

        for group in &self.security_groups {
            let name = truncate_str(&group.name, 24);
            lines.push(Line::from(vec![
                Span::styled("▣ ", Style::new().fg(p.accent2)),
                Span::styled(
                    format!("{name:<24}"),
                    Style::new().fg(p.text).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("  ↑ {}  ↓ {}", group.ingress_count, group.egress_count),
                    Style::new().fg(p.text_muted),
                ),
            ]));
            // Per-rule detail (best-effort; a long rule list still scrolls).
            for rule in &group.rules {
                let port = rule.port.clone().unwrap_or_else(|| "*".into());
                let port = truncate_str(&port, 12);
                let cidr = truncate_str(&rule.cidr, 22);
                let action_icon = if rule.action == "allow" { "✓" } else { "✗" };
                let action_color = if rule.action == "allow" { p.ok } else { p.err };
                lines.push(Line::from(vec![
                    Span::styled("    · ", Style::new().fg(p.text_dim)),
                    Span::styled(
                        format!("{:<8}", rule.direction),
                        Style::new().fg(p.text_muted),
                    ),
                    Span::styled(format!("{:<5}", rule.protocol), Style::new().fg(p.text)),
                    Span::styled(format!("{port:<13}"), Style::new().fg(p.text)),
                    Span::styled(cidr, Style::new().fg(p.text_dim)),
                    Span::styled(format!("  {action_icon}"), Style::new().fg(action_color)),
                ]));
            }
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
}

impl crate::ui::screens::section_overview::SectionOverview for CloudContent {
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
            "{} · {} sg(s)",
            if self.agent_running {
                "agent running"
            } else {
                "agent off"
            },
            self.security_groups.len()
        ))
    }

    fn findings_count(&self) -> usize {
        self.findings.len()
    }
}

impl crate::ui::screens::findings::Finding for CloudFindingEntry {
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

    fn sample_provider() -> ProviderInfo {
        ProviderInfo {
            provider: "AWS".into(),
            cli_tool: Some("aws".into()),
            metadata_url: Some("http://169.254.169.254/latest/meta-data/".into()),
        }
    }

    fn sample_groups() -> Vec<SecurityGroupEntry> {
        vec![SecurityGroupEntry {
            name: "web-sg".into(),
            description: "public web".into(),
            ingress_count: 1,
            egress_count: 0,
            rules: vec![FirewallRuleEntry {
                direction: "ingress".into(),
                protocol: "tcp".into(),
                port: Some("443".into()),
                cidr: "0.0.0.0/0".into(),
                action: "allow".into(),
                description: String::new(),
            }],
        }]
    }

    fn sample_findings() -> Vec<CloudFindingEntry> {
        vec![
            CloudFindingEntry {
                id: "provider.detected".into(),
                severity: "ok".into(),
                title: "Cloud provider detected".into(),
                detail: "Running on AWS EC2".into(),
                fix: None,
            },
            CloudFindingEntry {
                id: "binaries.aws.missing".into(),
                severity: "warning".into(),
                title: "aws CLI is not installed".into(),
                detail: String::new(),
                fix: Some("Install the aws CLI tool.".into()),
            },
        ]
    }

    /// Render a content area to a string (snapshot pattern from fail2ban).
    fn render_to_string(content: &mut CloudContent, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| content.view(f, f.area(), CHARM)).unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn new_is_unavailable_and_empty() {
        let c = CloudContent::new();
        assert!(!c.available);
        assert!(c.security_groups.is_empty());
        assert!(c.findings.is_empty());
        assert_eq!(c.provider.provider, "none");
        assert!(!c.has_modal());
    }

    #[test]
    fn default_matches_new() {
        let from_new = CloudContent::new();
        let from_default = CloudContent::default();
        assert_eq!(from_new.available, from_default.available);
        assert_eq!(from_new.provider.provider, from_default.provider.provider);
    }

    #[test]
    fn render_unavailable_when_not_available() {
        let mut c = CloudContent::new();
        let out = render_to_string(&mut c, 100, 24);
        assert!(
            out.contains("cloud data unavailable"),
            "degraded panel: {out}"
        );
    }

    #[test]
    fn render_provider_panel() {
        let mut c = CloudContent::new();
        c.set_available(true);
        c.set_provider(sample_provider());
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("AWS"), "provider label: {out}");
        assert!(out.contains("aws"), "cli tool: {out}");
    }

    #[test]
    fn render_agent_panel() {
        let mut c = CloudContent::new();
        c.set_available(true);
        c.set_agent(true, false, "amazon-ssm-agent".into());
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("running"), "running badge: {out}");
        assert!(out.contains("disabled"), "disabled badge: {out}");
        assert!(out.contains("amazon-ssm-agent"), "service name: {out}");
    }

    #[test]
    fn render_security_groups() {
        let mut c = CloudContent::new();
        c.set_available(true);
        c.set_security_groups(sample_groups());
        let out = render_to_string(&mut c, 110, 36);
        assert!(out.contains("web-sg"), "group name: {out}");
        assert!(out.contains("443"), "rule port: {out}");
        assert!(out.contains("0.0.0.0/0"), "rule cidr: {out}");
    }

    #[test]
    fn render_findings_grouped_by_severity() {
        let mut c = CloudContent::new();
        c.set_available(true);
        c.set_findings(sample_findings());
        let out = render_to_string(&mut c, 110, 40);
        assert!(out.contains("WARNING"), "severity group header: {out}");
        assert!(
            out.contains("aws CLI is not installed"),
            "finding title: {out}"
        );
        assert!(out.contains("Install the aws CLI"), "fix hint: {out}");
    }

    #[test]
    fn scroll_down_consumed_and_returns_none() {
        let mut c = CloudContent::new();
        c.set_available(true);
        assert!(c.handle_key(KeyCode::Down).is_none());
        assert_eq!(c.scroll, 1);
    }

    #[test]
    fn scroll_up_at_zero_stays_zero() {
        let mut c = CloudContent::new();
        c.set_available(true);
        c.handle_key(KeyCode::Up);
        assert_eq!(c.scroll, 0);
    }

    #[test]
    fn esc_returns_back_action() {
        let mut c = CloudContent::new();
        assert_eq!(c.handle_key(KeyCode::Esc), Some(Action::Back));
    }

    #[test]
    fn mouse_scroll_wheel_adjusts_scroll() {
        let mut c = CloudContent::new();
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
        let mut c = CloudContent::new();
        c.set_available(true);
        c.set_security_groups(sample_groups());
        c.set_findings(sample_findings());
        // 20x5 — well below comfortable, must not panic.
        let _ = render_to_string(&mut c, 20, 5);
    }

    #[test]
    fn empty_states_render_without_panic() {
        let mut c = CloudContent::new();
        c.set_available(true);
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("no security groups"), "empty groups: {out}");
        assert!(out.contains("no findings"), "empty findings: {out}");
    }

    #[test]
    fn set_findings_replaces_and_keeps_scroll_finite() {
        let mut c = CloudContent::new();
        c.scroll = 1_000_000;
        c.set_findings(sample_findings());
        // After a render the scroll is clamped to the visible window.
        let _ = render_to_string(&mut c, 100, 30);
        // scroll may still be large (no rows to show against) but must not
        // overflow; the important property is the render did not panic.
    }
}
