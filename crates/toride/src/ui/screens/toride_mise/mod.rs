//! Mise (runtime version manager) content area (live READ-ONLY).
//!
//! Renders inside the dashboard's content region when
//! [`Section::Mise`](crate::data::Section) is the active sidebar section.
//! Mirrors the fail2ban / Tailscale TEMPLATE read-only integrations — there is
//! no write path, no optimistic update, no cooldown, no loading spinner. Every
//! line rendered here comes from a live read of the local `mise` binary.
//!
//! Layout (single scrollable pane, no sub-tab bar):
//! 1. Status panel — version + config-file count.
//! 2. Installed tools table — tool, version, source, active/outdated flags.
//! 3. Outdated tools — tool, current → latest, backend.
//! 4. Config files — paths read by `mise config ls`.
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
use crate::ui::responsive::truncate_str;
use crate::ui::theme::Palette;
use crate::ui::widgets::render_titled_panel;

// ── Presentation types ──────────────────────────────────────────────────────

/// A single installed mise tool row.
#[derive(Clone, Debug)]
pub struct MiseToolEntry {
    /// Tool name (e.g. "node").
    pub name: String,
    /// Installed version, if known.
    pub version: Option<String>,
    /// Whether this is the currently-active version.
    pub active: bool,
    /// Whether a newer version is available.
    pub outdated: bool,
    /// Whether the tool is referenced in config but not yet installed.
    pub missing: bool,
    /// Source config path, if any (e.g. ".mise.toml").
    pub source: Option<String>,
}

/// A single outdated tool entry.
#[derive(Clone, Debug)]
pub struct MiseOutdatedEntry {
    /// Tool name.
    pub name: String,
    /// Currently installed version, if known.
    pub current: Option<String>,
    /// Latest available version, if known.
    pub latest: Option<String>,
    /// Backend / plugin providing the tool, if known.
    pub backend: Option<String>,
}

/// A single doctor finding.
#[derive(Clone, Debug)]
pub struct MiseFindingEntry {
    /// Lowercase severity: "ok" | "info" | "warning" | "error".
    pub severity: String,
    /// Short human-readable message.
    pub message: String,
    /// Optional remediation hint / detail.
    pub detail: Option<String>,
}

// ── MiseContent ─────────────────────────────────────────────────────────────

/// Mise management content rendered inside the dashboard content area.
///
/// READ-ONLY: there are no write operations, no optimistic updates, no loading
/// spinner, no cooldown. Data arrives via [`MiseContent::set_*`] setters driven
/// by [`MiseCollector`](crate::toride_mise_data::MiseCollector).
pub struct MiseContent {
    /// Whether the mise backend was reachable at all (binary present). `false`
    /// means the section renders a degraded "unavailable" panel.
    available: bool,
    /// Detected mise version string, if any.
    version: Option<String>,
    /// Installed tools.
    tools: Vec<MiseToolEntry>,
    /// Outdated tools.
    outdated: Vec<MiseOutdatedEntry>,
    /// Config files read by mise.
    config_files: Vec<String>,
    /// Doctor findings.
    findings: Vec<MiseFindingEntry>,
    /// Human-readable reason the backend was unreachable, surfaced in the
    /// degraded panel. Populated when the collector attached one: construction
    /// failure (`BinaryNotFound`), construction-OK-but-all-probes-failed, or a
    /// caught collection-task panic.
    unavailable_reason: Option<String>,
    /// Vertical scroll offset over the whole pane.
    scroll: usize,
}

impl Default for MiseContent {
    fn default() -> Self {
        Self::new()
    }
}

impl MiseContent {
    /// Create a new empty content area.
    #[must_use]
    pub fn new() -> Self {
        Self {
            available: false,
            version: None,
            tools: Vec::new(),
            outdated: Vec::new(),
            config_files: Vec::new(),
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

    /// Live installed-tool count for the sidebar badge. `None` when the
    /// backend is unavailable so the badge stays honestly empty.
    #[must_use]
    pub fn badge_count(&self) -> Option<usize> {
        if self.available {
            Some(self.tools.len())
        } else {
            None
        }
    }

    // ── Data setters ─────────────────────────────────────────────────────────

    /// Replace the version string (drives the status panel).
    pub fn set_version(&mut self, version: Option<String>) {
        self.version = version;
    }

    /// Replace the installed tools list and clamp scroll.
    pub fn set_tools(&mut self, tools: Vec<MiseToolEntry>) {
        self.tools = tools;
        self.clamp_scroll();
    }

    /// Replace the outdated tools list and clamp scroll.
    pub fn set_outdated(&mut self, outdated: Vec<MiseOutdatedEntry>) {
        self.outdated = outdated;
        self.clamp_scroll();
    }

    /// Replace the config files list and clamp scroll.
    pub fn set_config_files(&mut self, config_files: Vec<String>) {
        self.config_files = config_files;
        self.clamp_scroll();
    }

    /// Replace the findings list and clamp scroll.
    pub fn set_findings(&mut self, findings: Vec<MiseFindingEntry>) {
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
        // Kept for API symmetry with the other read-only content sections.
    }

    // ── Rendering ───────────────────────────────────────────────────────────

    /// Render the full mise content area.
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
                " MISE · {} tool(s) · {} outdated · {} config · {} finding(s) ",
                self.tools.len(),
                self.outdated.len(),
                self.config_files.len(),
                self.findings.len(),
            ),
            p.accent,
            true,
        );

        if inner.height == 0 {
            return;
        }

        // Build the full content as a Vec<Line> then render only the visible
        // window (mirrors the fail2ban / SSH tabs' manual-scroll approach).
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

    /// Render the degraded state when mise is unavailable on this host.
    ///
    /// `available == false` is reached in three cases: (1) `Mise::builder().build()`
    /// returned `BinaryNotFound` (mise not installed); (2) construction succeeded but
    /// every probe timed out or errored (mise exists but is unresponsive); (3) the
    /// collection task panicked and was caught by the collector's `JoinError`
    /// guard (the two-spawn guard in `MiseCollector::start` isolates the panic
    /// to the inner task and surfaces it to the outer awaiter as a `JoinError`,
    /// converted into an `empty_bundle_with_reason`). In all three cases
    /// the collector attaches a reason string surfaced here; the "mise binary not
    /// found" default below is reached only for a freshly-constructed empty bundle
    /// (no collection has run yet), NOT for the all-probes-failed case — the latter
    /// carries its own "did not respond" reason.
    fn render_unavailable(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " MISE ", p.text_dim, false);
        let msg = Line::from(vec![
            Span::styled("✦ ", Style::new().fg(p.warn)),
            Span::styled(
                "mise unavailable",
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
        ]);
        // Prefer the construction/panic reason from the bundle; otherwise the
        // accurate default for the common no-binary case.
        let detail_text = self.unavailable_reason.clone().unwrap_or_else(|| {
            "mise binary not found on $PATH / MISE_BIN / ~/.local/bin/mise".to_string()
        });
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

    /// Build the complete content as a flat list of lines (status, tools,
    /// outdated, config, findings). Scrolling operates over this list.
    fn build_lines(&self, p: Palette) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();

        self.push_status_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_tools_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_outdated_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_config_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_findings_lines(&mut lines, p);

        lines
    }

    fn push_status_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "mise",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        let version = self.version.clone().unwrap_or_else(|| "(unknown)".into());
        lines.push(Line::from(vec![
            Span::styled("  version  ", Style::new().fg(p.text_muted)),
            Span::styled(version, Style::new().fg(p.text)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  configs  ", Style::new().fg(p.text_muted)),
            Span::styled(
                format!("{}", self.config_files.len()),
                Style::new().fg(p.text),
            ),
        ]));
    }

    fn push_tools_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        let header = format!("Installed Tools ({})", self.tools.len());
        lines.push(Line::from(Span::styled(
            header,
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        if self.tools.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no tools installed",
                Style::new().fg(p.text_dim),
            )));
            return;
        }

        for tool in &self.tools {
            let state_icon = if tool.missing {
                "○"
            } else if tool.active {
                "●"
            } else {
                "·"
            };
            let state_color = if tool.missing {
                p.warn
            } else if tool.active {
                p.ok
            } else {
                p.text_dim
            };
            let name = truncate_str(&tool.name, 20);
            let version = tool.version.clone().unwrap_or_else(|| "(none)".into());
            let version = truncate_str(&version, 16);
            let mut spans = vec![
                Span::styled(format!("{state_icon} "), Style::new().fg(state_color)),
                Span::styled(
                    format!("{name:<20}"),
                    Style::new().fg(p.text).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("  {version:<16}"), Style::new().fg(p.text_muted)),
            ];
            if tool.outdated {
                spans.push(Span::styled("  ↑outdated", Style::new().fg(p.warn)));
            }
            if let Some(ref src) = tool.source {
                let src = truncate_str(src, 30);
                spans.push(Span::styled(
                    format!("  [{src}]"),
                    Style::new().fg(p.text_dim),
                ));
            }
            lines.push(Line::from(spans));
        }
    }

    fn push_outdated_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        let header = format!("Outdated ({})", self.outdated.len());
        lines.push(Line::from(Span::styled(
            header,
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        if self.outdated.is_empty() {
            lines.push(Line::from(Span::styled(
                "  all tools up to date",
                Style::new().fg(p.text_dim),
            )));
            return;
        }

        for o in &self.outdated {
            let name = truncate_str(&o.name, 20);
            let current = o.current.clone().unwrap_or_else(|| "?".into());
            let latest = o.latest.clone().unwrap_or_else(|| "?".into());
            let mut spans = vec![
                Span::styled("  ↑ ", Style::new().fg(p.warn)),
                Span::styled(
                    format!("{name:<20}"),
                    Style::new().fg(p.text).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("  {current} → {latest}"), Style::new().fg(p.warn)),
            ];
            if let Some(ref backend) = o.backend {
                let backend = truncate_str(backend, 16);
                spans.push(Span::styled(
                    format!("  [{backend}]"),
                    Style::new().fg(p.text_dim),
                ));
            }
            lines.push(Line::from(spans));
        }
    }

    fn push_config_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        let header = format!("Config Files ({})", self.config_files.len());
        lines.push(Line::from(Span::styled(
            header,
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        if self.config_files.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no config files detected",
                Style::new().fg(p.text_dim),
            )));
            return;
        }

        for path in &self.config_files {
            let path = truncate_str(path, 70);
            lines.push(Line::from(vec![
                Span::styled("  ◆ ", Style::new().fg(p.accent2)),
                Span::styled(path, Style::new().fg(p.text)),
            ]));
        }
    }

    fn push_findings_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        // Group by severity: Error > Warning > Info > Ok.
        const ORDER: &[&str] = &["error", "warning", "info", "ok"];
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

impl crate::ui::screens::section_overview::SectionOverview for MiseContent {
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
            "{} tool(s) · {} outdated",
            self.tools.len(),
            self.outdated.len()
        ))
    }

    fn findings_count(&self) -> usize {
        self.findings.len()
    }
}

impl crate::ui::screens::findings::Finding for MiseFindingEntry {
    fn severity(&self) -> &str {
        &self.severity
    }
    fn title(&self) -> &str {
        &self.message
    }
    fn detail(&self) -> Option<&str> {
        None
    }
    fn fix(&self) -> Option<&str> {
        // Mise's optional `detail` is rendered in the accent `→ fix` slot.
        self.detail.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::theme::CHARM;
    use ratatui::{Terminal, backend::TestBackend};

    fn sample_tools() -> Vec<MiseToolEntry> {
        vec![
            MiseToolEntry {
                name: "node".into(),
                version: Some("22.1.0".into()),
                active: true,
                outdated: false,
                missing: false,
                source: Some(".mise.toml".into()),
            },
            MiseToolEntry {
                name: "python".into(),
                version: Some("3.12.4".into()),
                active: false,
                outdated: true,
                missing: false,
                source: None,
            },
            MiseToolEntry {
                name: "go".into(),
                version: None,
                active: false,
                outdated: false,
                missing: true,
                source: Some("mise.toml".into()),
            },
        ]
    }

    fn sample_outdated() -> Vec<MiseOutdatedEntry> {
        vec![MiseOutdatedEntry {
            name: "python".into(),
            current: Some("3.12.4".into()),
            latest: Some("3.13.0".into()),
            backend: Some("core".into()),
        }]
    }

    fn sample_findings() -> Vec<MiseFindingEntry> {
        vec![
            MiseFindingEntry {
                severity: "warning".into(),
                message: "tool `go` is referenced but not installed".into(),
                detail: Some("Run `mise install`".into()),
            },
            MiseFindingEntry {
                severity: "ok".into(),
                message: "mise binary found".into(),
                detail: None,
            },
        ]
    }

    /// Render a content area to a string (snapshot pattern from fail2ban/ssh).
    fn render_to_string(content: &mut MiseContent, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| content.view(f, f.area(), CHARM)).unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn new_is_unavailable_and_empty() {
        let c = MiseContent::new();
        assert!(!c.available);
        assert!(c.tools.is_empty());
        assert!(c.outdated.is_empty());
        assert!(c.findings.is_empty());
        assert!(c.config_files.is_empty());
        assert!(!c.has_modal());
    }

    #[test]
    fn default_matches_new() {
        let from_new = MiseContent::new();
        let from_default = MiseContent::default();
        assert_eq!(from_new.available, from_default.available);
    }

    #[test]
    fn render_unavailable_when_not_available() {
        let mut c = MiseContent::new();
        let out = render_to_string(&mut c, 100, 24);
        assert!(out.contains("mise unavailable"), "degraded panel: {out}");
    }

    #[test]
    fn render_status_panel() {
        let mut c = MiseContent::new();
        c.set_available(true);
        c.set_version(Some("mise 2024.12.4".into()));
        c.set_config_files(vec!["/home/u/.config/mise/config.toml".into()]);
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("mise 2024.12.4"), "version: {out}");
        assert!(out.contains("configs"), "configs label: {out}");
    }

    #[test]
    fn render_tools_table() {
        let mut c = MiseContent::new();
        c.set_available(true);
        c.set_tools(sample_tools());
        let out = render_to_string(&mut c, 110, 36);
        assert!(out.contains("node"), "tool name: {out}");
        assert!(out.contains("python"), "second tool: {out}");
        assert!(out.contains("↑outdated"), "outdated flag: {out}");
    }

    #[test]
    fn render_outdated_list() {
        let mut c = MiseContent::new();
        c.set_available(true);
        c.set_outdated(sample_outdated());
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("python"), "outdated tool: {out}");
        assert!(out.contains("3.12.4 → 3.13.0"), "version transition: {out}");
    }

    #[test]
    fn render_config_files() {
        let mut c = MiseContent::new();
        c.set_available(true);
        c.set_config_files(vec![".mise.toml".into(), "mise.toml".into()]);
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains(".mise.toml"), "config file: {out}");
        assert!(out.contains("mise.toml"), "second config: {out}");
    }

    #[test]
    fn render_findings_grouped_by_severity() {
        let mut c = MiseContent::new();
        c.set_available(true);
        c.set_findings(sample_findings());
        let out = render_to_string(&mut c, 110, 40);
        assert!(out.contains("WARNING"), "severity group header: {out}");
        assert!(
            out.contains("referenced but not installed"),
            "finding msg: {out}"
        );
        assert!(out.contains("Run `mise install`"), "detail hint: {out}");
    }

    #[test]
    fn scroll_down_consumed_and_returns_none() {
        let mut c = MiseContent::new();
        c.set_available(true);
        assert!(c.handle_key(KeyCode::Down).is_none());
        assert_eq!(c.scroll, 1);
    }

    #[test]
    fn scroll_up_at_zero_stays_zero() {
        let mut c = MiseContent::new();
        c.set_available(true);
        c.handle_key(KeyCode::Up);
        assert_eq!(c.scroll, 0);
    }

    #[test]
    fn esc_returns_back_action() {
        let mut c = MiseContent::new();
        assert_eq!(c.handle_key(KeyCode::Esc), Some(Action::Back));
    }

    #[test]
    fn mouse_scroll_wheel_adjusts_scroll() {
        let mut c = MiseContent::new();
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
        let mut c = MiseContent::new();
        c.set_available(true);
        c.set_tools(sample_tools());
        c.set_findings(sample_findings());
        // 20x5 — well below comfortable, must not panic.
        let _ = render_to_string(&mut c, 20, 5);
    }

    #[test]
    fn tiny_terminal_unavailable_path_does_not_panic() {
        // Pins the no-panic guarantee on the degraded/unavailable render path
        // (render_unavailable) at degenerate sizes, mirroring
        // tiny_terminal_does_not_panic which only drives the available==true
        // branch. render_unavailable is structurally panic-safe (every
        // arithmetic op uses saturating_sub; ratatui's block.inner() clamps to
        // zero), but the tiny-size path was previously unverified.
        let mut c = MiseContent::new();
        // available stays false -> view() routes to render_unavailable.
        c.set_unavailable_reason(Some("mise did not respond".into()));
        // 20x5 — degenerate; must not panic. (At this width the "mise
        // unavailable" text is truncated, so assert on the panel border which
        // fits; the load-bearing claim is "did not panic".)
        let out_20x5 = render_to_string(&mut c, 20, 5);
        assert!(
            out_20x5.contains("MISE"),
            "degraded panel border 20x5: {out_20x5}"
        );
        // 1x1 — the most degenerate possible terminal; must not panic.
        let _ = render_to_string(&mut c, 1, 1);
        // At a comfortable size the panel renders the unavailable text + the
        // reason surfaced by the collector (the "did not respond" path).
        let out_100x24 = render_to_string(&mut c, 100, 24);
        assert!(
            out_100x24.contains("mise unavailable"),
            "degraded text at 100x24: {out_100x24}"
        );
        assert!(
            out_100x24.contains("mise did not respond"),
            "reason at 100x24: {out_100x24}"
        );
    }

    #[test]
    fn empty_states_render_without_panic() {
        let mut c = MiseContent::new();
        c.set_available(true);
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("no tools installed"), "empty tools: {out}");
        assert!(
            out.contains("all tools up to date"),
            "empty outdated: {out}"
        );
        assert!(out.contains("no config files"), "empty config: {out}");
        assert!(out.contains("no findings"), "empty findings: {out}");
    }
}
