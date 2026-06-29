//! Installed-tools catalogue content area (live READ-ONLY).
//!
//! Renders inside the dashboard's content region when
//! [`Section::Tools`](crate::data::Section) is the active sidebar section. This
//! integration mirrors the harden / mise templates (`HardenContent` /
//! `MiseContent`) WITHOUT any write path — every line is read-only.
//!
//! Layout (single scrollable pane, no sub-tab bar):
//! 1. Summary line — `N/M tools installed` + missing-expected count.
//! 2. Tool rows grouped by category (stable order): glyph (✓ installed, ✗
//!    missing), canonical name, version (or em-dash), resolved path (truncated).

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

/// A single tool row in the catalogue view.
#[derive(Clone, Debug)]
pub struct ToolEntry {
    /// Canonical name shown to the operator (e.g. `"fd"`).
    pub name: String,
    /// Category for grouping (e.g. `"Search/Files"`).
    pub category: String,
    /// Whether the binary resolved on PATH.
    pub installed: bool,
    /// First non-empty `--version` / `-V` line, if any.
    pub version: Option<String>,
    /// Resolved absolute path (the alias that resolved), if installed.
    pub path: Option<String>,
    /// Whether a missing tool is a warning finding.
    pub expected: bool,
}

/// A single doctor finding (missing-expected-tool warning).
#[derive(Clone, Debug)]
pub struct FindingEntry {
    /// Machine-readable id, e.g. `"tools.missing.vim"`.
    pub id: String,
    /// Severity as a lowercase string: always `"warning"` for the tools
    /// catalogue (only missing-expected-tool findings exist today).
    pub severity: String,
    /// Short human-readable title.
    pub title: String,
}

// ── ToolsContent ────────────────────────────────────────────────────────────

/// Installed-tools catalogue content rendered inside the dashboard content
/// area.
///
/// READ-ONLY: there are no write operations, no optimistic updates, no loading
/// spinner, no cooldown. Data arrives via [`ToolsContent::set_*`] setters
/// driven by [`ToolsCollector`](crate::tools_data::ToolsCollector).
pub struct ToolsContent {
    /// Whether the PATH scan ran at all. `false` means the section renders a
    /// degraded "unavailable" panel instead of live data.
    available: bool,
    /// Resolved tool rows (installed or missing), in catalogue order.
    tools: Vec<ToolEntry>,
    /// Count of installed tools across the catalogue.
    installed_count: usize,
    /// Total catalogue entries scanned.
    total_count: usize,
    /// Doctor findings (missing-expected-tool warnings).
    findings: Vec<FindingEntry>,
    /// Human-readable reason the backend was unreachable, surfaced in the
    /// degraded panel. Populated only when a collection task panicked.
    unavailable_reason: Option<String>,
    /// Vertical scroll offset over the whole pane.
    scroll: usize,
}

impl Default for ToolsContent {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolsContent {
    /// Create a new empty content area.
    #[must_use]
    pub fn new() -> Self {
        Self {
            available: false,
            tools: Vec::new(),
            installed_count: 0,
            total_count: 0,
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

    /// Replace the resolved tool rows and derived counts.
    pub fn set_tools(&mut self, tools: Vec<ToolEntry>) {
        self.total_count = tools.len();
        self.installed_count = tools.iter().filter(|t| t.installed).count();
        self.tools = tools;
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

    /// Count of installed tools across the catalogue, surfaced as the sidebar
    /// badge for the Tools section. `None` when no scan has run yet
    /// (`available == false`) so the badge stays honestly empty at cold start
    /// rather than flashing a fabricated number.
    #[must_use]
    pub fn installed_count(&self) -> Option<usize> {
        if self.available {
            Some(self.installed_count)
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
    /// (Esc → Back); scroll keys are consumed here. The Tools screen has no
    /// sub-selector, so Left/Right are NOT bound.
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
    #[allow(clippy::unused_self)]
    fn clamp_scroll(&mut self) {
        // No-op body: scroll is clamped against visible rows during render.
        // Kept for API symmetry with the harden / mise tabs.
    }

    // ── Rendering ───────────────────────────────────────────────────────────

    /// Render the full tools content area.
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
                " TOOLS · {}/{} installed · {} missing ",
                self.installed_count,
                self.total_count,
                self.total_count.saturating_sub(self.installed_count),
            ),
            p.accent,
            true,
        );

        if inner.height == 0 {
            return;
        }

        // Build the full content as a Vec<Line> then render only the visible
        // window (mirrors the harden / mise tabs' manual-scroll approach).
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

    /// Render the degraded state when the scan could not run on this host.
    ///
    /// `available == false` is set ONLY when a collection task panicked
    /// (`JoinError`) — the scan itself always runs otherwise. The degraded panel
    /// surfaces the panic reason (if any) so the operator sees what went wrong
    /// rather than a generic message.
    fn render_unavailable(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " TOOLS ", p.text_dim, false);
        if inner.height < 2 {
            return;
        }
        let msg = Line::from(vec![
            Span::styled("▣ ", Style::new().fg(p.warn)),
            Span::styled(
                "Tools unavailable",
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
        ]);
        // Prefer the panic reason from the bundle; otherwise a generic message.
        let detail_text = self
            .unavailable_reason
            .clone()
            .unwrap_or_else(|| "tool scan could not run on this host".to_string());
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

    /// Build the complete content as a flat list of lines (summary + per-
    /// category tool rows). Scrolling operates over this list.
    fn build_lines(&self, p: Palette, inner_width: u16) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();

        // ── Summary line ───────────────────────────────────────────────────
        let missing = self.total_count.saturating_sub(self.installed_count);
        let (summary_label, summary_color) = if self.total_count == 0 {
            ("—", p.text_dim)
        } else if missing == 0 {
            ("✓ fully equipped", p.ok)
        } else {
            ("! some tools missing", p.warn)
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{summary_label}  "), Style::new().fg(summary_color)),
            Span::styled(
                format!("{} / {} tools", self.installed_count, self.total_count),
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
        ]));
        // Findings hint line — only when there are missing-expected tools.
        let missing_expected = self
            .findings
            .iter()
            .filter(|f| f.id.starts_with("tools.missing."))
            .count();
        if missing_expected > 0 {
            lines.push(Line::from(Span::styled(
                format!("  {missing_expected} expected tool(s) missing — see findings"),
                Style::new().fg(p.warn),
            )));
        }
        lines.push(Line::raw(""));

        // ── Per-category tool rows ─────────────────────────────────────────
        // Group by category in stable first-seen order. The catalogue's
        // category order (Editors, Search/Files, ...) is preserved because
        // `self.tools` is already in catalogue order.
        let mut current_category: Option<&str> = None;
        for tool in &self.tools {
            if current_category != Some(tool.category.as_str()) {
                if current_category.is_some() {
                    // Blank line between categories for visual separation.
                    lines.push(Line::raw(""));
                }
                current_category = Some(tool.category.as_str());
                lines.push(Line::from(Span::styled(
                    tool.category.clone(),
                    Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
                )));
            }
            lines.push(Self::tool_line(tool, p, inner_width));
        }

        if self.tools.is_empty() {
            // Defensive: available == true but no tools (shouldn't happen — the
            // catalogue is non-empty — but render a placeholder rather than a
            // blank pane).
            lines.push(Line::from(Span::styled(
                "  no tools in catalogue",
                Style::new().fg(p.text_dim),
            )));
        }

        lines
    }

    /// Build a single tool row line: glyph + name + version + path.
    fn tool_line(tool: &ToolEntry, p: Palette, inner_width: u16) -> Line<'static> {
        // Path column: the resolved path truncated to the remainder of the row.
        // Fixed-width prefix keeps columns aligned: "  " (2) + glyph(1) + " "
        // (1) + name(16) + " " (1) + version(24) + " " (1) = 46.
        const PREFIX_WIDTH: usize = 46;
        let (icon, color) = if tool.installed {
            ("✓", p.ok)
        } else if tool.expected {
            ("✗", p.err)
        } else {
            ("·", p.text_dim)
        };
        let name = truncate_str(&tool.name, 16);
        // Version column: the resolved version string, or an em-dash when
        // installed-but-no-version, or an em-dash when missing.
        let version_text = tool
            .version
            .as_deref()
            .map_or_else(|| "—".to_string(), |v| truncate_str(v, 24));
        let path_text = match &tool.path {
            Some(path) => {
                let path_max = (inner_width as usize).saturating_sub(PREFIX_WIDTH);
                truncate_str(path, path_max)
            }
            None => String::new(),
        };
        Line::from(vec![
            Span::styled(format!("{icon} "), Style::new().fg(color)),
            Span::styled(format!("{name:<16}"), Style::new().fg(p.text)),
            Span::styled(format!(" {version_text:<24}"), Style::new().fg(p.text_dim)),
            Span::styled(format!(" {path_text}"), Style::new().fg(p.text_muted)),
        ])
    }
}

impl crate::ui::screens::section_overview::SectionOverview for ToolsContent {
    fn available(&self) -> bool {
        self.available
    }

    fn status_label(&self) -> &'static str {
        // The only findings the tools catalogue emits are `warning` severity
        // (missing-expected-tool), so the shared helper maps to `degraded`
        // whenever any are present. `available == false` always wins
        // (`offline`).
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
            "{}/{} tools",
            self.installed_count, self.total_count
        ))
    }

    fn findings_count(&self) -> usize {
        // Only missing-EXPECTED tools count as findings (mirrors the
        // convert layer, which never emits a finding for an unexpected tool).
        self.findings.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::screens::section_overview::SectionOverview;
    use crate::ui::theme::CHARM;
    use ratatui::{Terminal, backend::TestBackend};

    fn sample_tools() -> Vec<ToolEntry> {
        vec![
            ToolEntry {
                name: "vim".into(),
                category: "Editors".into(),
                installed: true,
                version: Some("VIM 9.0".into()),
                path: Some("/usr/bin/vim".into()),
                expected: true,
            },
            ToolEntry {
                name: "nano".into(),
                category: "Editors".into(),
                installed: false,
                version: None,
                path: None,
                expected: true,
            },
            ToolEntry {
                name: "rg".into(),
                category: "Search/Files".into(),
                installed: true,
                version: Some("ripgrep 13.0.0".into()),
                path: Some("/usr/bin/rg".into()),
                expected: true,
            },
            ToolEntry {
                name: "fd".into(),
                category: "Search/Files".into(),
                installed: false,
                version: None,
                path: None,
                expected: true,
            },
        ]
    }

    fn sample_findings() -> Vec<FindingEntry> {
        // Mirrors the ids the convert layer emits: `tools.missing.<name>`.
        vec![
            FindingEntry {
                id: "tools.missing.nano".into(),
                severity: "warning".into(),
                title: "missing expected tool: nano".into(),
            },
            FindingEntry {
                id: "tools.missing.fd".into(),
                severity: "warning".into(),
                title: "missing expected tool: fd".into(),
            },
        ]
    }

    /// The `FindingEntry::id` doc-comment promises `tools.missing.<name>`
    /// ids emitted by the convert layer. Pin that contract so a future edit
    /// that drifts the fixture away from production data fails loudly.
    #[test]
    fn finding_id_format_matches_convert_layer() {
        for f in sample_findings() {
            assert!(
                f.id.starts_with("tools.missing."),
                "id '{}' must start with tools.missing.",
                f.id
            );
        }
    }

    /// Render a content area to a string (snapshot pattern from harden/mise).
    fn render_to_string(content: &mut ToolsContent, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| content.view(f, f.area(), CHARM)).unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn new_is_unavailable_and_empty() {
        let c = ToolsContent::new();
        assert!(!c.available);
        assert!(c.tools.is_empty());
        assert!(c.findings.is_empty());
        assert_eq!(c.installed_count, 0);
        assert_eq!(c.total_count, 0);
        assert!(!c.has_modal());
    }

    #[test]
    fn default_matches_new() {
        let from_new = ToolsContent::new();
        let from_default = ToolsContent::default();
        assert_eq!(from_new.available, from_default.available);
    }

    #[test]
    fn render_unavailable_when_not_available() {
        let mut c = ToolsContent::new();
        let out = render_to_string(&mut c, 100, 24);
        assert!(out.contains("Tools unavailable"), "degraded panel: {out}");
    }

    #[test]
    fn render_unavailable_at_degenerate_height_does_not_panic() {
        let mut c = ToolsContent::new();
        c.set_unavailable_reason(Some("spawn_blocking panicked".into()));
        // 20x5 — below the saturating_sub(3) threshold once the titled panel's
        // border/insets are accounted for. The render path wraps the reason,
        // so assert the leading token appears rather than the full string.
        let out = render_to_string(&mut c, 20, 5);
        assert!(
            out.contains("spawn_blocking"),
            "unavailable reason should surface: {out}"
        );
    }

    #[test]
    fn render_unavailable_skips_message_at_degenerate_inner_height() {
        let mut c = ToolsContent::new();
        c.set_unavailable_reason(Some("spawn_blocking panicked".into()));
        // Area height 1 → border consumes the only row → inner.height == 0.
        let out_h1 = render_to_string(&mut c, 40, 1);
        assert!(
            !out_h1.contains("Tools unavailable"),
            "inner.height == 0 must early-return: {out_h1}"
        );
        // Area height 2 → inner.height == 1, still below the `< 2` threshold.
        let out_h2 = render_to_string(&mut c, 40, 2);
        assert!(
            !out_h2.contains("Tools unavailable"),
            "inner.height == 1 must early-return: {out_h2}"
        );
    }

    #[test]
    fn render_summary_line_with_installed_count() {
        let mut c = ToolsContent::new();
        c.set_available(true);
        c.set_tools(sample_tools());
        let out = render_to_string(&mut c, 110, 40);
        // 2 of 4 installed.
        assert!(out.contains("2 / 4 tools"), "summary count: {out}");
        assert!(out.contains("some tools missing"), "summary label: {out}");
    }

    #[test]
    fn render_fully_equipped_summary_when_nothing_missing() {
        let mut c = ToolsContent::new();
        c.set_available(true);
        c.set_tools(vec![ToolEntry {
            name: "vim".into(),
            category: "Editors".into(),
            installed: true,
            version: Some("9.0".into()),
            path: Some("/usr/bin/vim".into()),
            expected: true,
        }]);
        let out = render_to_string(&mut c, 110, 20);
        assert!(
            out.contains("fully equipped"),
            "summary when all present: {out}"
        );
        assert!(out.contains("1 / 1 tools"));
    }

    #[test]
    fn render_tool_rows_grouped_by_category() {
        let mut c = ToolsContent::new();
        c.set_available(true);
        c.set_tools(sample_tools());
        let out = render_to_string(&mut c, 120, 40);
        assert!(out.contains("Editors"), "category header: {out}");
        assert!(out.contains("Search/Files"), "category header: {out}");
        // Installed tool name + version surface.
        assert!(out.contains("vim"), "installed tool name: {out}");
        assert!(out.contains("ripgrep"), "version string: {out}");
    }

    #[test]
    fn render_findings_hint_when_missing_expected() {
        let mut c = ToolsContent::new();
        c.set_available(true);
        c.set_tools(sample_tools());
        c.set_findings(sample_findings());
        let out = render_to_string(&mut c, 120, 40);
        assert!(
            out.contains("expected tool(s) missing"),
            "findings hint: {out}"
        );
    }

    #[test]
    fn scroll_down_consumed_and_returns_none() {
        let mut c = ToolsContent::new();
        c.set_available(true);
        assert!(c.handle_key(KeyCode::Down).is_none());
        assert_eq!(c.scroll, 1);
    }

    #[test]
    fn scroll_up_at_zero_stays_zero() {
        let mut c = ToolsContent::new();
        c.set_available(true);
        c.handle_key(KeyCode::Up);
        assert_eq!(c.scroll, 0);
    }

    #[test]
    fn page_down_advances_by_eight() {
        let mut c = ToolsContent::new();
        c.set_available(true);
        c.handle_key(KeyCode::PageDown);
        assert_eq!(c.scroll, 8);
        c.handle_key(KeyCode::PageUp);
        assert_eq!(c.scroll, 0);
    }

    #[test]
    fn esc_returns_back_action() {
        let mut c = ToolsContent::new();
        assert_eq!(c.handle_key(KeyCode::Esc), Some(Action::Back));
    }

    #[test]
    fn left_right_are_not_bound() {
        // The Tools screen has no sub-selector, so Left/Right must fall through
        // to the catch-all `_ => None` (return None, no state change).
        let mut c = ToolsContent::new();
        c.set_available(true);
        let before = c.scroll;
        assert!(c.handle_key(KeyCode::Left).is_none());
        assert!(c.handle_key(KeyCode::Right).is_none());
        assert_eq!(c.scroll, before);
    }

    #[test]
    fn mouse_scroll_wheel_adjusts_scroll() {
        let mut c = ToolsContent::new();
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
    fn set_available_clears_unavailable_reason() {
        // set_unavailable_reason is a no-op (clears reason) when available.
        let mut c = ToolsContent::new();
        c.set_available(false);
        c.set_unavailable_reason(Some("boom".into()));
        assert_eq!(c.unavailable_reason.as_deref(), Some("boom"));
        c.set_available(true);
        c.set_unavailable_reason(Some("boom".into()));
        assert!(
            c.unavailable_reason.is_none(),
            "reason must clear when available"
        );
    }

    #[test]
    fn section_overview_offline_when_unavailable() {
        let mut c = ToolsContent::new();
        c.set_findings(sample_findings());
        // available == false → offline regardless of findings.
        assert_eq!(c.status_label(), "offline");
        assert_eq!(c.detail(), None);
    }

    #[test]
    fn section_overview_degraded_when_findings_present() {
        let mut c = ToolsContent::new();
        c.set_available(true);
        c.set_tools(sample_tools());
        c.set_findings(sample_findings());
        // Findings are all `warning` severity → degraded.
        assert_eq!(c.status_label(), "degraded");
        assert_eq!(c.detail().as_deref(), Some("2/4 tools"));
        assert_eq!(c.findings_count(), 2);
    }

    #[test]
    fn section_overview_active_when_no_findings() {
        let mut c = ToolsContent::new();
        c.set_available(true);
        c.set_tools(vec![ToolEntry {
            name: "vim".into(),
            category: "Editors".into(),
            installed: true,
            version: Some("9.0".into()),
            path: Some("/usr/bin/vim".into()),
            expected: true,
        }]);
        c.set_findings(Vec::new());
        assert_eq!(c.status_label(), "active");
        assert_eq!(c.detail().as_deref(), Some("1/1 tools"));
        assert_eq!(c.findings_count(), 0);
    }

    #[test]
    fn tiny_terminal_does_not_panic() {
        let mut c = ToolsContent::new();
        c.set_available(true);
        c.set_tools(sample_tools());
        c.set_findings(sample_findings());
        // 20x5 — well below comfortable, must not panic.
        let _ = render_to_string(&mut c, 20, 5);
    }

    #[test]
    fn set_tools_replaces_and_keeps_scroll_finite() {
        let mut c = ToolsContent::new();
        c.scroll = 1_000_000;
        c.set_tools(sample_tools());
        // After a render the scroll is clamped to the visible window.
        let _ = render_to_string(&mut c, 100, 30);
        // The important property is the render did not panic.
    }

    #[test]
    fn empty_states_render_without_panic() {
        let mut c = ToolsContent::new();
        c.set_available(true);
        let out = render_to_string(&mut c, 100, 30);
        // available == true but no tools → defensive placeholder.
        assert!(
            out.contains("no tools in catalogue"),
            "empty catalogue placeholder: {out}"
        );
    }

    // ── Full-screen insta snapshots ─────────────────────────────────────────
    //
    // Pin the full rendered output at fixed terminal sizes, mirroring the
    // harden / mise snapshot tests so a layout regression (column widths,
    // category-group indentation, summary text, the titled-panel header
    // counters) cannot slip past the contains-assertions silently.

    #[test]
    fn tools_content_snapshot_120x40() {
        let mut c = ToolsContent::new();
        c.set_available(true);
        c.set_tools(sample_tools());
        c.set_findings(sample_findings());
        let out = render_to_string(&mut c, 120, 40);
        insta::assert_snapshot!("tools_content_120x40", out);
    }

    #[test]
    fn tools_content_snapshot_unavailable_100x24() {
        let mut c = ToolsContent::new();
        c.set_unavailable_reason(Some("tools data collection panicked: boom".into()));
        let out = render_to_string(&mut c, 100, 24);
        insta::assert_snapshot!("tools_content_unavailable_100x24", out);
    }
}
