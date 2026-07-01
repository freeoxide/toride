//! UFW firewall management content area (live READ-ONLY).
//!
//! Renders inside the dashboard's content region when
//! [`Section::Firewall`](crate::data::Section) is the active sidebar section.
//! This integration mirrors the fail2ban template (`Fail2banContent`) WITHOUT
//! any write path — every line is read-only.
//!
//! Layout (single scrollable pane, no sub-tab bar):
//! 1. Status panel — active badge, default policies, logging level, version.
//! 2. Rules table — parsed UFW rules (number, action, direction, raw text).
//! 3. Doctor findings — grouped by severity (Critical > Important > Warning > Info > Ok).

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

/// A single parsed UFW rule row.
#[derive(Clone, Debug)]
pub struct RuleEntry {
    /// Rule number from `ufw status numbered` (if available).
    pub number: Option<u32>,
    /// Action as a lowercase string: "allow" | "deny" | "reject" | "limit" | "(unknown)".
    pub action: String,
    /// Direction as a lowercase string: "in" | "out" | "routed" | "(unknown)".
    pub direction: String,
    /// Whether this is an IPv6 rule.
    pub ipv6: bool,
    /// Whether this is a route (forwarding) rule.
    pub is_route: bool,
    /// The raw rule text (canonical UFW output).
    pub raw: String,
}

/// A single doctor finding.
#[derive(Clone, Debug)]
pub struct FindingEntry {
    /// Machine-readable colon-separated id (e.g. "bin:ufw:missing").
    pub id: String,
    /// Severity as a lowercase string: "ok" | "info" | "warning" | "important" | "critical".
    pub severity: String,
    /// Short human-readable title.
    pub title: String,
    /// Longer description (may be empty).
    pub detail: String,
    /// Suggested remediation, if any.
    pub fix: Option<String>,
}

// ── FirewallContent ─────────────────────────────────────────────────────────

/// UFW firewall management content rendered inside the dashboard content area.
///
/// READ-ONLY: there are no write operations, no optimistic updates, no loading
/// spinner, no cooldown. Data arrives via [`FirewallContent::set_*`] setters
/// driven by [`FirewallCollector`](crate::ufw_kit_data::FirewallCollector).
pub struct FirewallContent {
    /// Whether the UFW backend was reachable at all (binary present, status
    /// queryable). `false` means the section renders a degraded "unavailable"
    /// panel instead of live data.
    available: bool,
    /// Whether UFW is active (running).
    active: bool,
    /// Default incoming policy label (e.g. "deny").
    default_incoming: Option<String>,
    /// Default outgoing policy label (e.g. "allow").
    default_outgoing: Option<String>,
    /// Default routed policy label (e.g. "deny" / "reject"). `None` when routed
    /// is off — UFW verbose prints "disabled" but the parser maps it to `None`,
    /// so the panel surfaces "(unset)" rather than a string.
    default_routed: Option<String>,
    /// Current logging level label (e.g. "low").
    logging_level: Option<String>,
    /// Detected UFW version, if any.
    version: Option<String>,
    /// Parsed rules.
    rules: Vec<RuleEntry>,
    /// Doctor findings.
    findings: Vec<FindingEntry>,
    /// Human-readable reason the backend was unreachable, surfaced in the
    /// degraded panel. Populated only when a collection task panicked.
    unavailable_reason: Option<String>,
    /// Vertical scroll offset over the whole pane.
    scroll: usize,
}

impl Default for FirewallContent {
    fn default() -> Self {
        Self::new()
    }
}

impl FirewallContent {
    /// Create a new empty content area.
    #[must_use]
    pub fn new() -> Self {
        Self {
            available: false,
            active: false,
            default_incoming: None,
            default_outgoing: None,
            default_routed: None,
            logging_level: None,
            version: None,
            rules: Vec::new(),
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

    /// Replace status fields (drives the status panel).
    pub fn set_status(
        &mut self,
        active: bool,
        default_incoming: Option<String>,
        default_outgoing: Option<String>,
        default_routed: Option<String>,
        logging_level: Option<String>,
        version: Option<String>,
    ) {
        self.active = active;
        self.default_incoming = default_incoming;
        self.default_outgoing = default_outgoing;
        self.default_routed = default_routed;
        self.logging_level = logging_level;
        self.version = version;
    }

    /// Replace the rules list and clamp scroll.
    pub fn set_rules(&mut self, rules: Vec<RuleEntry>) {
        self.rules = rules;
        self.clamp_scroll();
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

    /// Whether UFW is active (running), surfaced as the sidebar badge for the
    /// Firewall section. `None` when the backend is unreachable
    /// (`available == false`) so the badge stays honestly empty.
    #[must_use]
    pub fn is_active(&self) -> Option<bool> {
        if self.available {
            Some(self.active)
        } else {
            None
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
    #[expect(
        clippy::unused_self,
        reason = "API symmetry with other scrollable panes"
    )]
    fn clamp_scroll(&mut self) {
        // No-op body: scroll is clamped against visible rows during render.
        // Kept for API symmetry with SSH / fail2ban tabs (which clamp on set).
    }

    // ── Rendering ───────────────────────────────────────────────────────────

    /// Render the full firewall content area.
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
                " UFW · {} rule(s) · {} finding(s) ",
                self.rules.len(),
                self.findings.len(),
            ),
            p.accent,
            true,
        );

        if inner.height == 0 {
            return;
        }

        // Build the full content as a Vec<Line> then render only the visible
        // window (mirrors the SSH / fail2ban tabs' manual-scroll approach).
        let lines = self.build_lines(p, inner.width);

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

    /// Render the degraded state when UFW is unavailable on this host.
    ///
    /// `available == false` is only ever set when a collection task returned an
    /// empty bundle, which today happens when the `spawn_blocking` task PANICS
    /// (`JoinError`) or when `Ufw::system()` construction failed entirely (the
    /// spawn returned `Err`). A missing `ufw` binary instead surfaces as a
    /// Critical doctor finding, which keeps `available == true` so the operator
    /// sees the findings panel. The reason string is surfaced here so the
    /// operator can see what actually went wrong; when no reason is known we
    /// fall back to a generic, accurate message.
    fn render_unavailable(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " UFW ", p.text_dim, false);
        // Mirror the available-path guard in `view()`: on a degenerate panel
        // (border + insets → inner.height == 0, or a 1-row inner area), the
        // centering math below would paint on/outside the panel border. Bail
        // out before computing y-offsets so the unavailable branch is symmetric
        // with the available branch's early return.
        if inner.height < 2 {
            return;
        }
        let msg = Line::from(vec![
            Span::styled("✦ ", Style::new().fg(p.warn)),
            Span::styled(
                "UFW unavailable",
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
        ]);
        // Prefer the panic/construction reason from the bundle; otherwise a
        // generic message accurate for both the panic case and the pre-first-poll state.
        let detail_text = self
            .unavailable_reason
            .clone()
            .unwrap_or_else(|| "UFW data could not be collected on this host".to_string());
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
        // Wrap so a long reason wraps within the panel instead of clipping.
        frame.render_widget(
            Paragraph::new(detail).centered().wrap(Wrap { trim: false }),
            centered_detail,
        );
    }

    /// Build the complete content as a flat list of lines (status, rules,
    /// findings). Scrolling operates over this list. `inner_width` is the
    /// post-layout pane width, threaded in so the rules row can scale its raw
    /// text truncation to the viewport instead of a fixed 50-column cap.
    fn build_lines(&self, p: Palette, inner_width: u16) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();

        self.push_status_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_rules_lines(&mut lines, p, inner_width);
        lines.push(Line::raw(""));
        self.push_findings_lines(&mut lines, p);

        lines
    }

    fn push_status_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "Status",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        // Active badge.
        let (active_label, active_color) = if self.active {
            ("● active", p.ok)
        } else {
            ("○ inactive", p.err)
        };
        lines.push(Line::from(vec![
            Span::styled("  state    ", Style::new().fg(p.text_muted)),
            Span::styled(active_label, Style::new().fg(active_color)),
        ]));

        // Default policies.
        lines.push(Line::from(vec![
            Span::styled("  in       ", Style::new().fg(p.text_muted)),
            Span::styled(
                self.default_incoming
                    .clone()
                    .unwrap_or_else(|| "(unset)".into()),
                Style::new().fg(p.text),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  out      ", Style::new().fg(p.text_muted)),
            Span::styled(
                self.default_outgoing
                    .clone()
                    .unwrap_or_else(|| "(unset)".into()),
                Style::new().fg(p.text),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  routed   ", Style::new().fg(p.text_muted)),
            Span::styled(
                self.default_routed
                    .clone()
                    .unwrap_or_else(|| "(unset)".into()),
                Style::new().fg(p.text),
            ),
        ]));

        // Logging level.
        lines.push(Line::from(vec![
            Span::styled("  logging  ", Style::new().fg(p.text_muted)),
            Span::styled(
                self.logging_level
                    .clone()
                    .unwrap_or_else(|| "(unset)".into()),
                Style::new().fg(p.text),
            ),
        ]));

        // Version.
        let version = self.version.clone().unwrap_or_else(|| "(unknown)".into());
        lines.push(Line::from(vec![
            Span::styled("  version  ", Style::new().fg(p.text_muted)),
            Span::styled(version, Style::new().fg(p.text)),
        ]));
    }

    fn push_rules_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette, inner_width: u16) {
        // Fixed-width prefix for every rule row:
        //   "  " (2) + num(6) + action(6) + " "(1) + dir(3) + " "(1) = 19 cols.
        // The raw column fills the remainder, scaled to the viewport so wider
        // terminals reveal more of the raw text and narrower ones clip less
        // abruptly. Falls back to a 50-col cap when the pane is degenerate or
        // narrower than the prefix (saturating, never panics).
        const PREFIX_WIDTH: usize = 19;
        const FALLBACK_RAW: usize = 50;
        let header = format!("Rules ({})", self.rules.len());
        lines.push(Line::from(Span::styled(
            header,
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        if self.rules.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no rules configured",
                Style::new().fg(p.text_dim),
            )));
            return;
        }

        let raw_max = if inner_width as usize >= PREFIX_WIDTH {
            let scaled = inner_width as usize - PREFIX_WIDTH;
            if scaled >= 1 { scaled } else { FALLBACK_RAW }
        } else {
            FALLBACK_RAW
        };

        for rule in &self.rules {
            let action_color = match rule.action.as_str() {
                "allow" => p.ok,
                "deny" | "reject" => p.err,
                "limit" => p.warn,
                _ => p.text_dim,
            };
            let num = rule.number.map(|n| format!("[{n}] ")).unwrap_or_default();
            let num = truncate_str(&num, 6);
            let action = format!("{:<6}", rule.action);
            let dir = format!("{:<3}", rule.direction);
            let raw = truncate_str(&rule.raw, raw_max);
            lines.push(Line::from(vec![
                Span::styled(format!("  {num}"), Style::new().fg(p.text_dim)),
                Span::styled(
                    action,
                    Style::new().fg(action_color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!(" {dir} "), Style::new().fg(p.text_muted)),
                Span::styled(raw, Style::new().fg(p.text)),
            ]));
        }
    }

    fn push_findings_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        // Group by severity: Critical > Important > Warning > Info > Ok.
        const ORDER: &[&str] = &["critical", "important", "warning", "info", "ok"];
        crate::ui::screens::findings::push_findings_grouped(
            lines,
            p,
            &self.findings,
            ORDER,
            crate::ui::screens::findings::severity_style_with_important_err,
            crate::ui::screens::findings::FindingWidths::TITLE_60,
        );
    }
}

impl crate::ui::screens::section_overview::SectionOverview for FirewallContent {
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
            "{} · {} rule(s)",
            if self.active { "active" } else { "inactive" },
            self.rules.len()
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

    fn sample_rules() -> Vec<RuleEntry> {
        vec![
            RuleEntry {
                number: Some(1),
                action: "allow".into(),
                direction: "in".into(),
                ipv6: false,
                is_route: false,
                raw: "22/tcp ALLOW IN Anywhere".into(),
            },
            RuleEntry {
                number: Some(2),
                action: "deny".into(),
                direction: "out".into(),
                ipv6: true,
                is_route: false,
                raw: "53/udp DENY OUT Anywhere (v6)".into(),
            },
        ]
    }

    fn sample_findings() -> Vec<FindingEntry> {
        // Ids mirror the real ufw-kit backend (`crates/ufw-kit/src/doctor.rs`):
        // colon-separated, `bin:<tool>:<state>`. Keep these in sync so the
        // doc-comment contract on `FindingEntry::id` is exercised by fixtures.
        vec![
            FindingEntry {
                id: "bin:ufw:exists".into(),
                severity: "ok".into(),
                title: "UFW binary found".into(),
                detail: "The ufw binary is available on this system.".into(),
                fix: None,
            },
            FindingEntry {
                id: "bin:ufw:version-fail".into(),
                severity: "warning".into(),
                title: "Could not read UFW version".into(),
                detail: String::new(),
                fix: Some("Install ufw: sudo apt install ufw".into()),
            },
        ]
    }

    /// The `FindingEntry::id` doc-comment promises colon-separated ids that
    /// mirror the ufw-kit backend (`crates/ufw-kit/src/doctor.rs`). Pin that
    /// contract so a future edit that reverts to dot-separated ids (or drifts
    /// the fixture away from production data) fails loudly.
    #[test]
    fn finding_id_format_matches_ufw_kit_backend() {
        // Must be colon-separated, three fields: `<scope>:<tool>:<state>`.
        for f in sample_findings() {
            let parts: Vec<&str> = f.id.split(':').collect();
            assert_eq!(
                parts.len(),
                3,
                "id '{}' must be colon-separated with exactly 3 fields (got {})",
                f.id,
                parts.len()
            );
            assert!(
                !f.id.contains('.'),
                "id '{}' must NOT be dot-separated (backend emits colons)",
                f.id
            );
        }
        // Spot-check the exact real-backend ids are present in the fixture so a
        // silent rename in `doctor.rs` surfaces here too.
        let findings = sample_findings();
        let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
        assert!(
            ids.contains(&"bin:ufw:exists"),
            "missing bin:ufw:exists: {ids:?}"
        );
        assert!(
            ids.contains(&"bin:ufw:version-fail"),
            "missing bin:ufw:version-fail: {ids:?}"
        );
    }

    /// Render a content area to a string (snapshot pattern from ssh `keys_tab.rs`).
    fn render_to_string(content: &mut FirewallContent, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| content.view(f, f.area(), CHARM)).unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn new_is_unavailable_and_empty() {
        let c = FirewallContent::new();
        assert!(!c.available);
        assert!(c.rules.is_empty());
        assert!(c.findings.is_empty());
        assert!(!c.has_modal());
    }

    #[test]
    fn default_matches_new() {
        let from_new = FirewallContent::new();
        let from_default = FirewallContent::default();
        assert_eq!(from_new.available, from_default.available);
    }

    #[test]
    fn render_unavailable_when_not_available() {
        let mut c = FirewallContent::new();
        let out = render_to_string(&mut c, 100, 24);
        assert!(out.contains("UFW unavailable"), "degraded panel: {out}");
    }

    /// Lock the degraded-path centering arithmetic
    /// (`inner.height.saturating_sub(3) / 2`) against degenerate terminal
    /// heights. The arithmetic is saturating and will not panic, but it was
    /// previously only exercised at 100x24 — this mirrors
    /// `tiny_terminal_does_not_panic` for the `available = false` branch,
    /// guarding the unavailable panel at heights 0/1/2 where the centering
    /// math underflows. Also confirms an `unavailable_reason` is surfaced.
    #[test]
    fn render_unavailable_at_degenerate_height_does_not_panic() {
        let mut c = FirewallContent::new();
        c.set_unavailable_reason(Some("spawn_blocking panicked".into()));
        // 20x5 — below the saturating_sub(3) threshold for heights 0/1/2 once
        // the titled panel's border/insets are accounted for. The render path
        // wraps the reason within the panel (`Wrap { trim: false }`), so on a
        // 20-col terminal a long reason wraps across rows — assert the leading
        // token appears rather than the full (possibly-wrapped) string.
        let out = render_to_string(&mut c, 20, 5);
        assert!(
            out.contains("spawn_blocking"),
            "unavailable reason should surface: {out}"
        );
    }

    /// Pin the no-overflow property of `render_unavailable` at area heights
    /// 1 and 2 — where `render_titled_panel`'s border + insets collapse
    /// `inner.height` to 0 or 1. Before the `inner.height < 2` guard was
    /// added, the centering math (`inner.y + saturating_sub(3)/2`) would
    /// compute y-offsets that landed on or below the bottom border row,
    /// letting the message Paragraphs paint outside the panel (an asymmetry
    /// with `view()`, which early-returns on `inner.height == 0`). With the
    /// guard, the unavailable branch must early-return identically and emit
    /// neither the "UFW unavailable" header nor the reason detail.
    #[test]
    fn render_unavailable_skips_message_at_degenerate_inner_height() {
        let mut c = FirewallContent::new();
        c.set_unavailable_reason(Some("spawn_blocking panicked".into()));

        // Area height 1 → border consumes the only row → inner.height == 0.
        let out_h1 = render_to_string(&mut c, 40, 1);
        assert!(
            !out_h1.contains("UFW unavailable"),
            "inner.height == 0 must early-return before painting the header: {out_h1}"
        );
        assert!(
            !out_h1.contains("spawn_blocking"),
            "inner.height == 0 must early-return before painting the reason: {out_h1}"
        );

        // Area height 2 → one border row + one inner row → inner.height == 1.
        // Still below the `< 2` threshold, so the message must be skipped.
        let out_h2 = render_to_string(&mut c, 40, 2);
        assert!(
            !out_h2.contains("UFW unavailable"),
            "inner.height == 1 must early-return (cannot fit msg + detail): {out_h2}"
        );
        assert!(
            !out_h2.contains("spawn_blocking"),
            "inner.height == 1 must early-return before painting the reason: {out_h2}"
        );
    }

    #[test]
    fn render_status_panel() {
        // Realistic values only: the convert layer's `policy_to_string`
        // yields "allow"/"deny"/"reject" (never "disabled"). Routed-off maps
        // to `None`, surfaced as "(unset)" — see that case below.
        let mut c = FirewallContent::new();
        c.set_available(true);
        c.set_status(
            true,
            Some("deny".into()),
            Some("allow".into()),
            Some("reject".into()),
            Some("low".into()),
            Some("ufw 0.36.1".into()),
        );
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("active"), "active badge: {out}");
        assert!(out.contains("deny"), "incoming policy: {out}");
        assert!(out.contains("allow"), "outgoing policy: {out}");
        assert!(out.contains("reject"), "routed policy: {out}");
        assert!(out.contains("low"), "logging level: {out}");
        assert!(out.contains("ufw 0.36.1"), "version: {out}");
    }

    #[test]
    fn render_status_panel_routed_off_surfaces_unset() {
        // Edge case: routed-off. UFW verbose prints "disabled" for this state,
        // but the convert layer maps it to `None` (default_routed is parsed as
        // Option<Policy>). The panel must therefore surface "(unset)" rather
        // than the misleading "disabled" string the backend never emits.
        let mut c = FirewallContent::new();
        c.set_available(true);
        c.set_status(
            true,
            Some("deny".into()),
            Some("allow".into()),
            None,
            Some("low".into()),
            Some("ufw 0.36.1".into()),
        );
        let out = render_to_string(&mut c, 100, 30);
        assert!(
            out.contains("(unset)"),
            "routed-off should surface '(unset)', not 'disabled': {out}"
        );
        assert!(
            !out.contains("disabled"),
            "routed-off must NOT surface 'disabled' (parser never emits it): {out}"
        );
    }

    #[test]
    fn render_rules_table() {
        let mut c = FirewallContent::new();
        c.set_available(true);
        c.set_rules(sample_rules());
        let out = render_to_string(&mut c, 110, 36);
        assert!(out.contains("22/tcp"), "rule raw text: {out}");
        assert!(out.contains("53/udp"), "second rule raw: {out}");
    }

    #[test]
    fn render_findings_grouped_by_severity() {
        let mut c = FirewallContent::new();
        c.set_available(true);
        c.set_findings(sample_findings());
        let out = render_to_string(&mut c, 110, 40);
        assert!(out.contains("WARNING"), "severity group header: {out}");
        assert!(
            out.contains("Could not read UFW version"),
            "finding title: {out}"
        );
        assert!(out.contains("Install ufw"), "fix hint: {out}");
    }

    #[test]
    fn scroll_down_consumed_and_returns_none() {
        let mut c = FirewallContent::new();
        c.set_available(true);
        assert!(c.handle_key(KeyCode::Down).is_none());
        assert_eq!(c.scroll, 1);
    }

    #[test]
    fn scroll_up_at_zero_stays_zero() {
        let mut c = FirewallContent::new();
        c.set_available(true);
        c.handle_key(KeyCode::Up);
        assert_eq!(c.scroll, 0);
    }

    #[test]
    fn esc_returns_back_action() {
        let mut c = FirewallContent::new();
        assert_eq!(c.handle_key(KeyCode::Esc), Some(Action::Back));
    }

    #[test]
    fn mouse_scroll_wheel_adjusts_scroll() {
        let mut c = FirewallContent::new();
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
        let mut c = FirewallContent::new();
        c.set_available(true);
        c.set_rules(sample_rules());
        c.set_findings(sample_findings());
        // 20x5 — well below comfortable, must not panic.
        let _ = render_to_string(&mut c, 20, 5);
    }

    #[test]
    fn set_findings_replaces_and_keeps_scroll_finite() {
        let mut c = FirewallContent::new();
        c.scroll = 1_000_000;
        c.set_findings(sample_findings());
        // After a render the scroll is clamped to the visible window.
        let _ = render_to_string(&mut c, 100, 30);
        // scroll may still be large (no rows to show against) but must not
        // overflow; the important property is the render did not panic.
    }

    #[test]
    fn empty_states_render_without_panic() {
        let mut c = FirewallContent::new();
        c.set_available(true);
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("no rules configured"), "empty rules: {out}");
        assert!(out.contains("no findings"), "empty findings: {out}");
    }

    // ── Full-screen insta snapshots ─────────────────────────────────────────
    //
    // The contains-assertions above cover the documented contracts (badges,
    // policy labels, severity headers, fix hints), but a pixel-level layout
    // regression in the panel (column widths, severity-group indentation,
    // empty-state text, the titled-panel header counters) would slip past them
    // silently. These insta snapshots pin the full rendered output at fixed
    // terminal sizes, mirroring the welcome/help/dashboard snapshot tests in
    // `ui/screens/mod.rs` and bringing ufw-kit in line with the codebase-wide
    // insta convention documented in CLAUDE.md. Snapshots live alongside this
    // file in `screens/ufw_kit/mod.rs.snap`.

    #[test]
    fn firewall_content_snapshot_110x40() {
        let mut c = FirewallContent::new();
        c.set_available(true);
        c.set_status(
            true,
            Some("deny".into()),
            Some("allow".into()),
            Some("reject".into()),
            Some("low".into()),
            Some("ufw 0.36.1".into()),
        );
        c.set_rules(sample_rules());
        c.set_findings(sample_findings());
        let out = render_to_string(&mut c, 110, 40);
        insta::assert_snapshot!("firewall_content_110x40", out);
    }

    #[test]
    fn firewall_content_snapshot_unavailable_100x24() {
        let mut c = FirewallContent::new();
        c.set_unavailable_reason(Some("spawn_blocking panicked: JoinError".into()));
        let out = render_to_string(&mut c, 100, 24);
        insta::assert_snapshot!("firewall_content_unavailable_100x24", out);
    }
}
