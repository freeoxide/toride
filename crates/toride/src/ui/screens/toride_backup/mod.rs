//! Backup management content area (live READ-ONLY).
//!
//! Renders inside the dashboard's content region when
//! [`Section::Backup`](crate::data::Section) is the active sidebar section.
//! Mirrors the SSH / fail2ban reference MINUS the write path — every line is
//! read-only.
//!
//! Layout (single scrollable pane, no sub-tab bar):
//! 1. Status panel — dry-run flag, resolved paths.
//! 2. Binaries card — restic / borg availability inferred from doctor findings.
//! 3. Schedule card — whether a schedule is installed and the timer is active.
//! 4. Doctor findings — grouped by severity (Critical > Error > Warning > Info > Ok).

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

/// A single doctor finding (presentation mirror of the backend finding).
#[derive(Clone, Debug)]
pub struct FindingEntry {
    /// Machine-readable dot-separated id (e.g. "binary.restic.missing").
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

// ── BackupContent ───────────────────────────────────────────────────────────

/// Backup management content rendered inside the dashboard content area.
///
/// READ-ONLY: there are no write operations, no optimistic updates, no loading
/// spinner, no cooldown. Data arrives via [`BackupContent::set_*`] setters
/// driven by [`BackupCollector`](crate::toride_backup_data::BackupCollector).
pub struct BackupContent {
    /// Whether the backup backend was reachable at all. `false` means the
    /// section renders a degraded "unavailable" panel instead of live data.
    available: bool,
    /// Whether dry-run mode is active.
    dry_run: bool,
    /// Resolved config directory, if known.
    config_dir: Option<String>,
    /// Resolved data directory, if known.
    data_dir: Option<String>,
    /// Resolved schedule directory, if known.
    schedule_dir: Option<String>,
    /// restic binary availability.
    restic_available: Option<bool>,
    /// borg binary availability.
    borg_available: Option<bool>,
    /// Whether the default schedule is installed.
    schedule_installed: Option<bool>,
    /// Whether the default timer is active.
    timer_active: Option<bool>,
    /// Informational note explaining a negative schedule reading (e.g.
    /// "systemd not detected" on a non-systemd host). Rendered as a dim hint
    /// line under the schedule panel so the operator can tell "systemd absent"
    /// apart from "no schedule configured".
    schedule_note: Option<String>,
    /// Doctor findings.
    findings: Vec<FindingEntry>,
    /// Human-readable reason the backend was unreachable, surfaced in the
    /// degraded panel. Populated only when a collection task panicked.
    unavailable_reason: Option<String>,
    /// Vertical scroll offset over the whole pane.
    scroll: usize,
}

impl Default for BackupContent {
    fn default() -> Self {
        Self::new()
    }
}

impl BackupContent {
    /// Create a new empty content area.
    #[must_use]
    pub fn new() -> Self {
        Self {
            available: false,
            dry_run: false,
            config_dir: None,
            data_dir: None,
            schedule_dir: None,
            restic_available: None,
            borg_available: None,
            schedule_installed: None,
            timer_active: None,
            schedule_note: None,
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

    /// Live timer status for the sidebar badge. The Backup section has no
    /// natural "item count" (it surfaces scalar booleans), so the badge
    /// reflects the timer state: `Some("active")` / `Some("inactive")` when
    /// the backend is available and a timer reading exists, `None` otherwise.
    /// Never fabricates a status — `None` stays empty at cold start.
    #[must_use]
    pub fn badge_status(&self) -> Option<&'static str> {
        if self.available {
            self.timer_active
                .map(|active| if active { "active" } else { "inactive" })
        } else {
            None
        }
    }

    // ── Data setters ─────────────────────────────────────────────────────────

    /// Replace the status fields (dry-run + resolved paths).
    pub fn set_status(
        &mut self,
        dry_run: bool,
        config_dir: Option<String>,
        data_dir: Option<String>,
        schedule_dir: Option<String>,
    ) {
        self.dry_run = dry_run;
        self.config_dir = config_dir;
        self.data_dir = data_dir;
        self.schedule_dir = schedule_dir;
    }

    /// Replace binary availability.
    pub fn set_binaries(&mut self, restic: Option<bool>, borg: Option<bool>) {
        self.restic_available = restic;
        self.borg_available = borg;
    }

    /// Replace schedule/timer status.
    pub fn set_schedule(
        &mut self,
        installed: Option<bool>,
        active: Option<bool>,
        note: Option<String>,
    ) {
        self.schedule_installed = installed;
        self.timer_active = active;
        self.schedule_note = note;
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

    /// Current scroll offset (test accessor).
    #[cfg(test)]
    pub fn scroll(&self) -> usize {
        self.scroll
    }

    /// Current unavailable reason (test accessor).
    #[cfg(test)]
    pub fn unavailable_reason(&self) -> Option<&str> {
        self.unavailable_reason.as_deref()
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

    /// Render the full backup content area.
    pub fn view(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        if !self.available {
            self.render_unavailable(frame, area, p);
            return;
        }

        let inner = render_titled_panel(
            frame,
            area,
            p,
            &format!(" BACKUP · {} finding(s) ", self.findings.len()),
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

    /// Render the degraded state when the backup backend is unavailable.
    ///
    /// `available == false` is only ever set when a collection task returned an
    /// empty bundle, which today happens exclusively when the `spawn_blocking`
    /// task PANICS (`JoinError`) — not when restic/borg are missing (missing
    /// binaries produce Critical doctor findings, keeping `available == true`
    /// so the operator sees the findings panel).
    fn render_unavailable(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " BACKUP ", p.text_dim, false);
        // Degrade gracefully on very small terminals: a panel shorter than 3
        // rows (border + 1 content + border) has no room to vertically center
        // both the message and the detail line without one rendering on the
        // bottom border or the two collapsing onto the same row.
        if inner.height < 3 {
            return;
        }
        let msg = Line::from(vec![
            Span::styled("✦ ", Style::new().fg(p.warn)),
            Span::styled(
                "backup unavailable",
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
        ]);
        let detail_text = self
            .unavailable_reason
            .clone()
            .unwrap_or_else(|| "backup data could not be collected on this host".to_string());
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

    /// Build the complete content as a flat list of lines (status, binaries,
    /// schedule, findings). Scrolling operates over this list.
    fn build_lines(&self, p: Palette) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();

        self.push_status_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_binaries_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_schedule_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_findings_lines(&mut lines, p);

        lines
    }

    fn push_status_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "Status",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        // Dry-run badge.
        let (dry_label, dry_color) = if self.dry_run {
            ("● dry-run", p.warn)
        } else {
            ("● live", p.ok)
        };
        lines.push(Line::from(vec![
            Span::styled("  mode     ", Style::new().fg(p.text_muted)),
            Span::styled(dry_label, Style::new().fg(dry_color)),
        ]));

        // Resolved paths.
        let config = self
            .config_dir
            .clone()
            .unwrap_or_else(|| "(unresolved)".into());
        lines.push(Line::from(vec![
            Span::styled("  config   ", Style::new().fg(p.text_muted)),
            Span::styled(truncate_str(&config, 60), Style::new().fg(p.text)),
        ]));
        let data = self
            .data_dir
            .clone()
            .unwrap_or_else(|| "(unresolved)".into());
        lines.push(Line::from(vec![
            Span::styled("  data     ", Style::new().fg(p.text_muted)),
            Span::styled(truncate_str(&data, 60), Style::new().fg(p.text)),
        ]));
        let sched = self
            .schedule_dir
            .clone()
            .unwrap_or_else(|| "(unresolved)".into());
        lines.push(Line::from(vec![
            Span::styled("  schedule ", Style::new().fg(p.text_muted)),
            Span::styled(truncate_str(&sched, 60), Style::new().fg(p.text)),
        ]));
    }

    fn push_binaries_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "Backup Binaries",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));
        Self::push_binary_line(lines, p, "restic", self.restic_available);
        Self::push_binary_line(lines, p, "borg   ", self.borg_available);
    }

    fn push_binary_line(
        lines: &mut Vec<Line<'static>>,
        p: Palette,
        label: &str,
        available: Option<bool>,
    ) {
        let (icon, text, color) = match available {
            Some(true) => ("✓", "available", p.ok),
            Some(false) => ("✗", "not installed", p.err),
            None => ("?", "unknown", p.text_dim),
        };
        lines.push(Line::from(vec![
            Span::styled(format!("  {label}  "), Style::new().fg(p.text_muted)),
            Span::styled(format!("{icon} {text}"), Style::new().fg(color)),
        ]));
    }

    fn push_schedule_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "Schedule (toride-backup)",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        // Installed?
        let (inst_icon, inst_text, inst_color) = match self.schedule_installed {
            Some(true) => ("●", "installed", p.ok),
            Some(false) => ("○", "not installed", p.text_dim),
            None => ("?", "unknown", p.text_dim),
        };
        lines.push(Line::from(vec![
            Span::styled("  unit     ", Style::new().fg(p.text_muted)),
            Span::styled(
                format!("{inst_icon} {inst_text}"),
                Style::new().fg(inst_color),
            ),
        ]));

        // Timer active?
        let (tmr_icon, tmr_text, tmr_color) = match self.timer_active {
            Some(true) => ("●", "active", p.ok),
            Some(false) => ("○", "inactive", p.warn),
            None => ("?", "unknown", p.text_dim),
        };
        lines.push(Line::from(vec![
            Span::styled("  timer    ", Style::new().fg(p.text_muted)),
            Span::styled(format!("{tmr_icon} {tmr_text}"), Style::new().fg(tmr_color)),
        ]));

        // Informational note explaining a negative reading (e.g. "systemd not
        // detected" on macOS / non-systemd hosts). Rendered as a dim hint so
        // the operator can tell "systemd absent" apart from "no schedule
        // configured" — previously this note was computed by the backend but
        // never surfaced, so a false reading was ambiguous.
        if let Some(note) = &self.schedule_note
            && !note.is_empty()
        {
            lines.push(Line::from(Span::styled(
                format!("  note     {note}"),
                Style::new().fg(p.text_dim),
            )));
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

impl crate::ui::screens::section_overview::SectionOverview for BackupContent {
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
        let mut bits = Vec::new();
        match (self.restic_available, self.borg_available) {
            (Some(true), _) => bits.push("restic".to_string()),
            (_, Some(true)) => bits.push("borg".to_string()),
            _ => bits.push("no engine".to_string()),
        }
        if self.dry_run {
            bits.push("dry-run".to_string());
        }
        Some(bits.join(" · "))
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
        // Match the prior inlined guard: an empty fix string is treated as
        // "no fix" so no stray `→ ` line is emitted.
        self.fix.as_deref().filter(|fix| !fix.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::theme::CHARM;
    use ratatui::{Terminal, backend::TestBackend};

    fn sample_findings() -> Vec<FindingEntry> {
        vec![
            FindingEntry {
                id: "binary.restic.found".into(),
                severity: "ok".into(),
                title: "restic binary found on $PATH".into(),
                detail: "Located at /usr/bin/restic".into(),
                fix: None,
            },
            FindingEntry {
                id: "binary.borg.missing".into(),
                severity: "info".into(),
                title: "borg binary not found".into(),
                detail: String::new(),
                fix: Some("Install borg: apt install borgbackup".into()),
            },
            FindingEntry {
                id: "binary.none-available".into(),
                severity: "critical".into(),
                title: "No backup binary available".into(),
                detail: "Neither restic nor borg was found.".into(),
                fix: Some("Install restic or borg backup.".into()),
            },
        ]
    }

    /// Render a content area to a string (snapshot pattern from ssh `keys_tab.rs`).
    fn render_to_string(content: &mut BackupContent, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| content.view(f, f.area(), CHARM)).unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn new_is_unavailable_and_empty() {
        let c = BackupContent::new();
        assert!(!c.available);
        assert!(c.findings.is_empty());
        assert!(!c.has_modal());
    }

    #[test]
    fn default_matches_new() {
        let from_new = BackupContent::new();
        let from_default = BackupContent::default();
        assert_eq!(from_new.available, from_default.available);
    }

    #[test]
    fn render_unavailable_when_not_available() {
        let mut c = BackupContent::new();
        let out = render_to_string(&mut c, 100, 24);
        assert!(out.contains("backup unavailable"), "degraded panel: {out}");
    }

    #[test]
    fn render_status_panel() {
        let mut c = BackupContent::new();
        c.set_available(true);
        c.set_status(
            false,
            Some("/home/user/.config/toride/backup".into()),
            Some("/home/user/.local/share/toride/backup".into()),
            Some("/home/user/.config/toride/backup/schedules".into()),
        );
        let out = render_to_string(&mut c, 120, 30);
        assert!(out.contains("live"), "live badge: {out}");
        assert!(out.contains("toride/backup"), "config path rendered: {out}");
    }

    #[test]
    fn render_dry_run_badge() {
        let mut c = BackupContent::new();
        c.set_available(true);
        c.set_status(true, None, None, None);
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("dry-run"), "dry-run badge: {out}");
    }

    #[test]
    fn render_binaries_card() {
        let mut c = BackupContent::new();
        c.set_available(true);
        c.set_binaries(Some(true), Some(false));
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("restic"), "restic label: {out}");
        assert!(out.contains("borg"), "borg label: {out}");
        assert!(out.contains("available"), "available text: {out}");
        assert!(out.contains("not installed"), "missing text: {out}");
    }

    #[test]
    fn render_schedule_card() {
        let mut c = BackupContent::new();
        c.set_available(true);
        c.set_schedule(Some(true), Some(false), None);
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("Schedule"), "schedule header: {out}");
        assert!(out.contains("installed"), "installed text: {out}");
        assert!(out.contains("inactive"), "inactive text: {out}");
    }

    #[test]
    fn render_findings_grouped_by_severity() {
        let mut c = BackupContent::new();
        c.set_available(true);
        c.set_findings(sample_findings());
        let out = render_to_string(&mut c, 110, 40);
        assert!(out.contains("CRITICAL"), "severity group header: {out}");
        assert!(
            out.contains("No backup binary available"),
            "finding title: {out}"
        );
        assert!(out.contains("Install restic or borg"), "fix hint: {out}");
    }

    #[test]
    fn render_findings_empty_fix_no_dangling_arrow() {
        // A finding with `fix: Some("")` (empty fix string) must NOT render a
        // dangling `→ ` arrow with an empty trailing span. The render path
        // guards `!fix.is_empty()` so no misleading fix hint is shown even if a
        // non-converted entry (or a future backend change) reaches the UI with
        // an empty fix string.
        let mut c = BackupContent::new();
        c.set_available(true);
        c.set_findings(vec![FindingEntry {
            id: "edge.empty-fix".into(),
            severity: "warning".into(),
            title: "edge: empty fix string".into(),
            detail: String::new(),
            fix: Some(String::new()),
        }]);
        let out = render_to_string(&mut c, 110, 30);
        assert!(
            out.contains("edge: empty fix string"),
            "title rendered: {out}"
        );
        // Count `→` arrows — there must be none, since the empty fix is suppressed.
        let arrow_count = out.matches('→').count();
        assert_eq!(arrow_count, 0, "no dangling arrow for empty fix: {out}");
    }

    #[test]
    fn scroll_down_consumed_and_returns_none() {
        let mut c = BackupContent::new();
        c.set_available(true);
        assert!(c.handle_key(KeyCode::Down).is_none());
        assert_eq!(c.scroll(), 1);
    }

    #[test]
    fn scroll_up_at_zero_stays_zero() {
        let mut c = BackupContent::new();
        c.set_available(true);
        c.handle_key(KeyCode::Up);
        assert_eq!(c.scroll(), 0);
    }

    #[test]
    fn esc_returns_back_action() {
        let mut c = BackupContent::new();
        assert_eq!(c.handle_key(KeyCode::Esc), Some(Action::Back));
    }

    #[test]
    fn mouse_scroll_wheel_adjusts_scroll() {
        let mut c = BackupContent::new();
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
        let mut c = BackupContent::new();
        c.set_available(true);
        c.set_binaries(Some(true), Some(false));
        c.set_findings(sample_findings());
        // 20x5 — well below comfortable, must not panic.
        let _ = render_to_string(&mut c, 20, 5);
    }

    #[test]
    fn tiny_unavailable_panel_does_not_panic() {
        // Degraded panel on a terminal too short to vertically center both
        // the message and detail (height < 3 inside the bordered panel). The
        // inner.height < 3 guard must short-circuit before any centered rect
        // math collapses rows onto the border. Must not panic.
        let mut c = BackupContent::new();
        // available == false is the default, so the unavailable path renders.
        c.set_unavailable_reason(Some("panic".into()));
        let _ = render_to_string(&mut c, 30, 3);
    }

    #[test]
    fn set_unavailable_reason_clears_on_recovery() {
        // The spine (dashboard.rs) always calls set_available BEFORE
        // set_unavailable_reason. When availability flips back to true, any
        // stale panic message must be cleared so it can't linger after a
        // recovery. This guards the clearing-on-recovery branch that the
        // other tests don't exercise (they run with available == false).
        let mut c = BackupContent::new();
        // Degraded: reason sticks while unavailable.
        c.set_available(false);
        c.set_unavailable_reason(Some("backend panic".into()));
        assert_eq!(c.unavailable_reason(), Some("backend panic"));

        // Recovery: available flips to true first, then a new reason is set —
        // the setter must clear it to None regardless of the passed value.
        c.set_available(true);
        c.set_unavailable_reason(Some("x".into()));
        assert_eq!(c.unavailable_reason(), None);
    }

    #[test]
    fn empty_states_render_without_panic() {
        let mut c = BackupContent::new();
        c.set_available(true);
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("no findings"), "empty findings: {out}");
    }
}
