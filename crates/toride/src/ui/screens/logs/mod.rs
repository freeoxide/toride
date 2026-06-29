//! Logs viewer content area (live READ-ONLY tail).
//!
//! Renders inside the dashboard's content region when
//! [`Section::Logs`](crate::data::Section) is the active sidebar section. This
//! integration mirrors the fail2ban / ufw-kit / harden templates
//! (`Fail2banContent` / `FirewallContent` / `HardenContent`) WITHOUT any write
//! path — every line is read-only.
//!
//! This is the most "live" read-only section: the collector re-reads every
//! source's tail on each 2s refresh tick, so the displayed lines change in
//! real time. The operator cycles the active source with Left/Right and
//! scrolls the tail with j/k / ↑/↓ / PageUp/PageDown / the mouse wheel.
//!
//! Layout (single scrollable pane, no sub-tab bar):
//! 1. Header — active source name + path + size + mtime, plus the
//!    `← → cycle source` hint.
//! 2. The active source's tail as plain lines (lossy-UTF-8, never crashes).

use crossterm::event::{KeyCode, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
};

use crate::action::Action;
use crate::logs_convert::{LogSource, convert_source};
use crate::ui::responsive::truncate_str;
use crate::ui::theme::Palette;
use crate::ui::widgets::render_titled_panel;

// ── LogsContent ─────────────────────────────────────────────────────────────

/// Logs viewer content rendered inside the dashboard content area.
///
/// READ-ONLY: there are no write operations, no optimistic updates, no loading
/// spinner, no cooldown. Data arrives via [`LogsContent::set_logs`] driven by
/// [`LogsCollector`](crate::logs_data::LogsCollector).
///
/// The active source is selected by index ([`LogsContent::selected_source`]);
/// Left/Right cycle it (wrapping). Scroll is a manual `usize` offset over the
/// active source's `lines`, clamped against the visible row count during
/// render (mirrors every other scrollable pane in the app — no ratatui
/// `Scrollbar` widget is used).
pub struct LogsContent {
    /// Whether the logs collector ran at all. `false` (only on a collection
    /// panic) means the section renders a degraded "unavailable" panel.
    available: bool,
    /// Per-source tails. Empty on a host with NO log sources — in that case
    /// `available` stays `true` and the viewer surfaces the honest
    /// `"no log sources found on this host"` line (NOT a fake "coming soon").
    sources: Vec<LogSource>,
    /// Human-readable reason the collector panicked, surfaced in the degraded
    /// panel. Populated only when `available == false`.
    unavailable_reason: Option<String>,
    /// Index into `sources` of the currently selected (displayed) source.
    selected_source: usize,
    /// Vertical scroll offset over the active source's lines. Clamped against
    /// the visible row count during render.
    scroll: usize,
}

impl Default for LogsContent {
    fn default() -> Self {
        Self::new()
    }
}

impl LogsContent {
    /// Create a new empty content area.
    #[must_use]
    pub fn new() -> Self {
        Self {
            available: false,
            sources: Vec::new(),
            unavailable_reason: None,
            selected_source: 0,
            scroll: 0,
        }
    }

    /// Whether the section has a modal open. Read-only section → never.
    #[must_use]
    pub fn has_modal(&self) -> bool {
        false
    }

    // ── Data setters ─────────────────────────────────────────────────────────

    /// Replace the source list. [`LogsContent::selected_source`] is PRESERVED
    /// when possible (clamped to the new `sources.len()` so it never points
    /// past the end), and `scroll` is clamped to the new active source's line
    /// count. This is what makes Left/Right + the 2s refresh tick feel stable:
    /// a refresh does not snap the operator back to source 0 / scroll 0.
    pub fn set_logs(&mut self, sources: Vec<LogSource>) {
        // Clamp selection FIRST so the scroll clamp below reads the NEWLY
        // active source's line count, not the previous one.
        if self.selected_source >= sources.len() {
            self.selected_source = if sources.is_empty() {
                0
            } else {
                sources.len() - 1
            };
        }
        self.sources = sources;
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

    /// The currently-selected source, or `None` when `sources` is empty.
    fn active_source(&self) -> Option<&LogSource> {
        self.sources.get(self.selected_source)
    }

    /// Select the next source (wraps). Resets scroll to the top so the
    /// operator sees the newly-selected source from its first line rather
    /// than a mid-tail view of a different-length tail.
    fn source_next(&mut self) {
        if self.sources.is_empty() {
            return;
        }
        self.selected_source = (self.selected_source + 1) % self.sources.len();
        self.scroll = 0;
    }

    /// Select the previous source (wraps). Resets scroll to the top (see
    /// [`Self::source_next`]).
    fn source_prev(&mut self) {
        if self.sources.is_empty() {
            return;
        }
        let len = self.sources.len();
        self.selected_source = (self.selected_source + len - 1) % len;
        self.scroll = 0;
    }

    // ── Input ────────────────────────────────────────────────────────────────

    /// Handle a key press. Returns `Some(Action)` only for navigation keys
    /// (Esc → Back); scroll keys and Left/Right source cycling are consumed
    /// here.
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
            // Left/Right cycle the source selector (mirrors a sub-tab bar).
            KeyCode::Right | KeyCode::Char('l') => {
                self.source_next();
                None
            }
            KeyCode::Left | KeyCode::Char('h') => {
                self.source_prev();
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
        // Kept for API symmetry with the other scrollable panes.
    }

    // ── Rendering ───────────────────────────────────────────────────────────

    /// Render the full logs content area.
    pub fn view(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        if !self.available {
            self.render_unavailable(frame, area, p);
            return;
        }

        let inner = render_titled_panel(
            frame,
            area,
            p,
            &format!(" LOGS . {} source(s) ", self.sources.len()),
            p.accent,
            true,
        );

        if inner.height == 0 {
            return;
        }

        if self.sources.is_empty() {
            // Honest empty state: NO log sources exist on this host. This is
            // NOT a "coming soon" placeholder — it is the literal truth
            // surfaced so the operator knows the section is wired and simply
            // has nothing to show.
            let msg = Line::from(vec![
                Span::styled("· ", Style::new().fg(p.text_dim)),
                Span::styled(
                    "no log sources found on this host",
                    Style::new().fg(p.text).add_modifier(Modifier::BOLD),
                ),
            ]);
            let centered = Rect::new(
                inner.x,
                inner.y + inner.height.saturating_sub(1) / 2,
                inner.width,
                1,
            );
            frame.render_widget(Paragraph::new(msg).centered(), centered);
            return;
        }

        // Build the full content (header + tail) as a Vec<Line> then render
        // only the visible window (manual scroll — no ratatui Scrollbar).
        let active = self.active_source().map_or_else(
            || LogSource {
                name: "(none)".into(),
                path: String::new(),
                exists: false,
                size_bytes: 0,
                mtime: None,
                line_count: 0,
                lines: Vec::new(),
            },
            |s| convert_source(s.clone()),
        );

        let lines = self.build_lines(&active, p, inner.width);

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

    /// Render the degraded state when the logs collector itself panicked
    /// (`available == false`). The normal empty-host case (zero sources,
    /// `available == true`) is handled inside [`Self::view`] with the honest
    /// "no log sources found on this host" line, NOT here.
    fn render_unavailable(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " LOGS ", p.text_dim, false);
        if inner.height < 2 {
            return;
        }
        let msg = Line::from(vec![
            Span::styled("✦ ", Style::new().fg(p.warn)),
            Span::styled(
                "Logs unavailable",
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
        ]);
        // Prefer the panic reason from the bundle; otherwise a generic
        // message accurate for the pre-first-poll state.
        let detail_text = self
            .unavailable_reason
            .clone()
            .unwrap_or_else(|| "log collection could not run on this host".to_string());
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

    /// Build the complete content as a flat list of lines: a one-line header
    /// (active source name + path + size + mtime + cycle hint), then the
    /// active source's tail. Scrolling operates over this list.
    fn build_lines(&self, active: &LogSource, p: Palette, inner_width: u16) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();

        // ── Header: name + path + size + mtime ──────────────────────────────
        let sel = self.selected_source + 1;
        let total = self.sources.len();
        let header_name = if active.name.is_empty() {
            "(unknown)"
        } else {
            active.name.as_str()
        };
        lines.push(Line::from(vec![
            Span::styled(format!("[{sel}/{total}] "), Style::new().fg(p.text_muted)),
            Span::styled(
                header_name.to_string(),
                Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
            ),
        ]));

        // Path line (truncated to the viewport width so a long path does not
        // wrap and steal a tail row).
        let path_label = if active.path.is_empty() {
            "(no path)"
        } else {
            active.path.as_str()
        };
        let path = truncate_str(path_label, inner_width.saturating_sub(2) as usize);
        lines.push(Line::from(vec![
            Span::styled("  path   ", Style::new().fg(p.text_muted)),
            Span::styled(path, Style::new().fg(p.text_dim)),
        ]));

        // Size + mtime line.
        let size_str = format_bytes_human(active.size_bytes);
        let mtime_str = active.mtime.clone().unwrap_or_else(|| "—".to_string());
        // Extract to locals — format-string field access (`{active.line_count}`)
        // is not supported, so bind first.
        let line_count = active.line_count;
        lines.push(Line::from(vec![
            Span::styled("  size   ", Style::new().fg(p.text_muted)),
            Span::styled(
                format!("{size_str}  ·  {line_count} line(s)"),
                Style::new().fg(p.text_dim),
            ),
            Span::styled(
                format!("   ·   mtime {mtime_str}"),
                Style::new().fg(p.text_muted),
            ),
        ]));

        // Hint line.
        lines.push(Line::from(vec![
            Span::styled("  hint   ", Style::new().fg(p.text_muted)),
            Span::styled(
                "← → cycle source  ·  j/k scroll",
                Style::new().fg(p.text_dim),
            ),
        ]));

        // Blank separator between header and the tail.
        lines.push(Line::raw(""));

        // ── Tail lines ──────────────────────────────────────────────────────
        if active.lines.is_empty() {
            lines.push(Line::from(Span::styled(
                "  (empty log — no lines yet)",
                Style::new().fg(p.text_dim),
            )));
        } else {
            for raw in &active.lines {
                let truncated = truncate_str(raw, inner_width as usize);
                lines.push(Line::from(Span::styled(truncated, Style::new().fg(p.text))));
            }
        }

        lines
    }
}

/// Format a byte count as a short human string (KiB / MiB / GiB).
///
/// Kept local (rather than reaching for `crate::ui::helpers::format_bytes`)
/// because the logs header wants a compact `123 B` / `4 KiB` style without
/// the helpers' coloring / trailing-unit conventions; a divergence here is
/// cheaper than threading a new helper signature through the format module.
#[expect(clippy::cast_precision_loss, reason = "display-only")]
fn format_bytes_human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if bytes == 0 {
        return "0 B".into();
    }
    let mut value = bytes as f64;
    let mut unit_idx = 0;
    while value >= 1024.0 && unit_idx < UNITS.len() - 1 {
        value /= 1024.0;
        unit_idx += 1;
    }
    // Drop the decimal for the B unit (it is already an integer); keep one
    // decimal place for the scaled units so `1.5 KiB` reads naturally.
    if unit_idx == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit_idx])
    }
}

impl crate::ui::screens::section_overview::SectionOverview for LogsContent {
    fn available(&self) -> bool {
        self.available
    }

    fn status_label(&self) -> &'static str {
        // The Logs section has no findings; pass an empty severity iterator so
        // status_label_for collapses to active/offline purely on `available`.
        // The `as [&str; 0]` annotation pins the iterator's item type —
        // without it the compiler cannot infer the `AsRef<str>` bound.
        crate::ui::screens::section_overview::status_label_for(self.available, [] as [&str; 0])
    }

    fn detail(&self) -> Option<String> {
        if !self.available {
            return None;
        }
        Some(format!("{} source(s)", self.sources.len()))
    }

    fn findings_count(&self) -> usize {
        // The Logs section is a passive viewer — it surfaces no findings.
        0
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::theme::CHARM;
    use ratatui::{Terminal, backend::TestBackend};

    fn sample_source(name: &str, n_lines: usize) -> LogSource {
        LogSource {
            name: name.into(),
            path: format!("/var/log/{name}"),
            exists: true,
            size_bytes: 4096,
            mtime: Some("2021-01-01 00:00".into()),
            line_count: n_lines,
            lines: (0..n_lines)
                .map(|i| format!("2021-01-01T00:00:{i:02}Z sample log line number {i}"))
                .collect(),
        }
    }

    /// Render a content area to a string (snapshot pattern from
    /// fail2ban / `ufw_kit` / harden).
    fn render_to_string(content: &mut LogsContent, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| content.view(f, f.area(), CHARM)).unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn new_is_unavailable_and_empty() {
        let c = LogsContent::new();
        assert!(!c.available);
        assert!(c.sources.is_empty());
        assert!(!c.has_modal());
    }

    #[test]
    fn default_matches_new() {
        let from_new = LogsContent::new();
        let from_default = LogsContent::default();
        assert_eq!(from_new.available, from_default.available);
        assert_eq!(from_new.sources.len(), from_default.sources.len());
    }

    #[test]
    fn render_unavailable_when_not_available() {
        let mut c = LogsContent::new();
        let out = render_to_string(&mut c, 100, 24);
        assert!(out.contains("Logs unavailable"), "degraded panel: {out}");
    }

    #[test]
    fn scroll_down_consumed_and_returns_none() {
        let mut c = LogsContent::new();
        c.set_available(true);
        c.set_logs(vec![sample_source("auth", 5)]);
        assert!(c.handle_key(KeyCode::Down).is_none());
        assert_eq!(c.scroll, 1);
    }

    #[test]
    fn scroll_up_at_zero_stays_zero() {
        let mut c = LogsContent::new();
        c.set_available(true);
        c.set_logs(vec![sample_source("auth", 5)]);
        c.handle_key(KeyCode::Up);
        assert_eq!(c.scroll, 0);
    }

    #[test]
    fn page_down_adds_eight() {
        let mut c = LogsContent::new();
        c.set_available(true);
        c.set_logs(vec![sample_source("auth", 50)]);
        c.handle_key(KeyCode::PageDown);
        assert_eq!(c.scroll, 8);
    }

    #[test]
    fn left_right_cycle_sources() {
        let mut c = LogsContent::new();
        c.set_available(true);
        c.set_logs(vec![
            sample_source("auth", 1),
            sample_source("syslog", 1),
            sample_source("kern", 1),
        ]);
        assert_eq!(c.selected_source, 0);
        c.handle_key(KeyCode::Right);
        assert_eq!(c.selected_source, 1);
        c.handle_key(KeyCode::Right);
        assert_eq!(c.selected_source, 2);
        c.handle_key(KeyCode::Right); // wraps to 0
        assert_eq!(c.selected_source, 0);
        c.handle_key(KeyCode::Left); // wraps back to 2
        assert_eq!(c.selected_source, 2);
    }

    #[test]
    fn h_l_aliases_cycle_sources() {
        let mut c = LogsContent::new();
        c.set_available(true);
        c.set_logs(vec![sample_source("auth", 1), sample_source("syslog", 1)]);
        assert_eq!(c.selected_source, 0);
        c.handle_key(KeyCode::Char('l'));
        assert_eq!(c.selected_source, 1);
        c.handle_key(KeyCode::Char('h'));
        assert_eq!(c.selected_source, 0);
    }

    #[test]
    fn cycling_resets_scroll_to_top() {
        let mut c = LogsContent::new();
        c.set_available(true);
        c.set_logs(vec![sample_source("auth", 50), sample_source("syslog", 50)]);
        c.scroll = 10;
        c.handle_key(KeyCode::Right);
        assert_eq!(c.selected_source, 1);
        assert_eq!(c.scroll, 0, "cycle must reset scroll to the top");
    }

    #[test]
    fn esc_returns_back_action() {
        let mut c = LogsContent::new();
        assert_eq!(c.handle_key(KeyCode::Esc), Some(Action::Back));
    }

    #[test]
    fn mouse_scroll_wheel_adjusts_scroll() {
        let mut c = LogsContent::new();
        c.set_available(true);
        c.set_logs(vec![sample_source("auth", 5)]);
        let down = MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 0,
            row: 0,
            modifiers: crossterm::event::KeyModifiers::empty(),
        };
        c.handle_mouse(down);
        assert_eq!(c.scroll, 1);
        let up = MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: 0,
            row: 0,
            modifiers: crossterm::event::KeyModifiers::empty(),
        };
        c.handle_mouse(up);
        assert_eq!(c.scroll, 0);
    }

    #[test]
    fn tiny_terminal_does_not_panic() {
        let mut c = LogsContent::new();
        c.set_available(true);
        c.set_logs(vec![sample_source("auth", 20)]);
        // 20x5 — well below comfortable, must not panic.
        let _ = render_to_string(&mut c, 20, 5);
    }

    #[test]
    fn empty_sources_shows_honest_no_sources_message() {
        let mut c = LogsContent::new();
        c.set_available(true);
        c.set_logs(Vec::new());
        let out = render_to_string(&mut c, 100, 24);
        assert!(
            out.contains("no log sources found on this host"),
            "honest empty-host message: {out}"
        );
        // And NOT the degraded "Logs unavailable" message — that path is for
        // collection panics only.
        assert!(
            !out.contains("Logs unavailable"),
            "empty-host must not render the degraded panel: {out}"
        );
    }

    #[test]
    fn populated_source_renders_its_lines() {
        let mut c = LogsContent::new();
        c.set_available(true);
        c.set_logs(vec![sample_source("auth", 3)]);
        let out = render_to_string(&mut c, 120, 30);
        assert!(out.contains("auth"), "source name in header: {out}");
        assert!(out.contains("/var/log/auth"), "source path: {out}");
        assert!(
            out.contains("sample log line number 0"),
            "first tail line: {out}"
        );
        assert!(
            out.contains("sample log line number 2"),
            "last tail line: {out}"
        );
        assert!(out.contains("cycle source"), "cycle hint: {out}");
    }

    #[test]
    fn set_logs_preserves_selected_source_when_possible() {
        let mut c = LogsContent::new();
        c.set_available(true);
        c.set_logs(vec![
            sample_source("auth", 1),
            sample_source("syslog", 1),
            sample_source("kern", 1),
        ]);
        c.selected_source = 1; // syslog
        // Refresh tick delivers a NEW Vec (same sources, refreshed tails).
        c.set_logs(vec![
            sample_source("auth", 2),
            sample_source("syslog", 2),
            sample_source("kern", 2),
        ]);
        assert_eq!(
            c.selected_source, 1,
            "selected_source must survive a refresh tick"
        );
        assert_eq!(
            c.active_source().unwrap().name,
            "syslog",
            "the active source must still be syslog"
        );
    }

    #[test]
    fn set_logs_clamps_selected_source_when_source_disappears() {
        let mut c = LogsContent::new();
        c.set_available(true);
        c.set_logs(vec![
            sample_source("auth", 1),
            sample_source("syslog", 1),
            sample_source("kern", 1),
        ]);
        c.selected_source = 2; // kern
        // Refresh tick where kern has vanished (e.g. file deleted).
        c.set_logs(vec![sample_source("auth", 1), sample_source("syslog", 1)]);
        assert_eq!(
            c.selected_source, 1,
            "selection must clamp to the last valid index, not point past the end"
        );
    }

    #[test]
    fn set_logs_clamps_selection_to_zero_when_all_sources_vanish() {
        let mut c = LogsContent::new();
        c.set_available(true);
        c.set_logs(vec![sample_source("auth", 1)]);
        c.set_logs(Vec::new());
        assert_eq!(c.selected_source, 0);
    }

    #[test]
    fn unavailable_reason_is_cleared_when_available_flips_true() {
        let mut c = LogsContent::new();
        c.set_unavailable_reason(Some("panic".into()));
        assert_eq!(c.unavailable_reason.as_deref(), Some("panic"));
        c.set_available(true);
        c.set_unavailable_reason(Some("panic".into()));
        assert!(
            c.unavailable_reason.is_none(),
            "reason must clear once available flips true"
        );
    }

    #[test]
    fn section_overview_reports_active_with_no_findings() {
        use crate::ui::screens::section_overview::SectionOverview;
        let mut c = LogsContent::new();
        c.set_available(true);
        c.set_logs(vec![sample_source("auth", 1), sample_source("syslog", 1)]);
        assert!(c.available());
        assert_eq!(c.status_label(), "active");
        assert_eq!(c.findings_count(), 0);
        assert_eq!(c.detail().as_deref(), Some("2 source(s)"));
    }

    #[test]
    fn section_overview_reports_offline_when_unavailable() {
        use crate::ui::screens::section_overview::SectionOverview;
        let c = LogsContent::new();
        assert!(!c.available());
        assert_eq!(c.status_label(), "offline");
        assert!(c.detail().is_none());
    }

    #[test]
    fn format_bytes_human_formats_units() {
        assert_eq!(format_bytes_human(0), "0 B");
        assert_eq!(format_bytes_human(512), "512 B");
        assert_eq!(format_bytes_human(1024), "1.0 KiB");
        assert_eq!(format_bytes_human(1536), "1.5 KiB");
        assert_eq!(format_bytes_human(1_048_576), "1.0 MiB");
    }

    #[test]
    fn empty_source_lines_render_placeholder() {
        let mut c = LogsContent::new();
        c.set_available(true);
        // A source that exists but has zero lines (e.g. a freshly-rotated
        // log file).
        c.set_logs(vec![sample_source("empty", 0)]);
        let out = render_to_string(&mut c, 100, 24);
        assert!(
            out.contains("empty log"),
            "an existing-but-empty source must show a placeholder: {out}"
        );
    }

    // ── Full-screen insta snapshots ─────────────────────────────────────────
    //
    // Pin the full rendered output at fixed terminal sizes, mirroring the
    // fail2ban / ufw-kit / harden snapshot tests so a layout regression
    // (header layout, cycle-hint text, empty-state message) cannot slip past
    // the contains-assertions silently.

    #[test]
    fn logs_content_snapshot_populated_120x30() {
        let mut c = LogsContent::new();
        c.set_available(true);
        c.set_logs(vec![sample_source("auth", 10)]);
        let out = render_to_string(&mut c, 120, 30);
        insta::assert_snapshot!("logs_content_populated_120x30", out);
    }

    #[test]
    fn logs_content_snapshot_no_sources_100x24() {
        let mut c = LogsContent::new();
        c.set_available(true);
        c.set_logs(Vec::new());
        let out = render_to_string(&mut c, 100, 24);
        insta::assert_snapshot!("logs_content_no_sources_100x24", out);
    }

    #[test]
    fn logs_content_snapshot_unavailable_100x24() {
        let mut c = LogsContent::new();
        c.set_unavailable_reason(Some("logs data collection panicked: JoinError".into()));
        let out = render_to_string(&mut c, 100, 24);
        insta::assert_snapshot!("logs_content_unavailable_100x24", out);
    }
}
