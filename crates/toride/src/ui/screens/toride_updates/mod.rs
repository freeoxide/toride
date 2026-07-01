//! Updates management content area (live READ-ONLY).
//!
//! Renders inside the dashboard's content region when
//! [`Section::Updates`](crate::data::Section) is the active sidebar section.
//! Mirrors the SSH / fail2ban reference but WITHOUT any write path — every line
//! is read-only.
//!
//! Layout (single scrollable pane, no sub-tab bar):
//! 1. Status panel — package-manager badge, auto-update enabled/active badges,
//!    last-run timestamp.
//! 2. Pending updates summary — security / total counts.
//! 3. Schedule card — detected schedule (daily/weekly/monthly/custom).
//! 4. Service / timer card — systemd unit activity.
//! 5. Doctor findings — grouped by severity
//!    (Critical > Important > Warning > Info > Ok).

use crossterm::event::{KeyCode, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
};

use crate::action::Action;
use crate::ui::theme::Palette;
use crate::ui::widgets::render_titled_panel;

// ── Presentation types ──────────────────────────────────────────────────────

/// A single doctor finding (mirrors the shared toride-diagnostic-types shape).
#[derive(Clone, Debug)]
pub struct FindingEntry {
    /// Machine-readable dot-separated id (e.g. "binary.unattended-upgrades.missing").
    pub id: String,
    /// Severity as a lowercase string: "ok" | "info" | "warning" | "important" | "critical".
    pub severity: String,
    /// Short human-readable summary.
    pub title: String,
    /// Longer description (may be empty).
    pub detail: String,
    /// Suggested remediation, if any.
    pub fix: Option<String>,
}

// ── UpdatesContent ──────────────────────────────────────────────────────────

/// Updates management content rendered inside the dashboard content area.
///
/// READ-ONLY: there are no write operations, no optimistic updates, no loading
/// spinner, no cooldown. Data arrives via [`UpdatesContent::set_*`] setters
/// driven by [`UpdatesCollector`](crate::toride_updates_data::UpdatesCollector).
pub struct UpdatesContent {
    /// Whether the updates backend was reachable at all (package manager
    /// detected, client constructed). `false` means the section renders a
    /// degraded "unavailable" panel instead of live data.
    available: bool,
    /// Detected package manager label (e.g. "apt", "dnf", "unknown").
    package_manager: String,
    /// Whether automatic updates are enabled.
    auto_updates_enabled: bool,
    /// Whether the update service (unattended-upgrades / dnf-automatic) is active.
    service_active: bool,
    /// Number of pending security updates.
    pending_security: usize,
    /// Total number of pending updates.
    pending_total: usize,
    /// Timestamp of the last successful update run (ISO 8601), if available.
    last_run: Option<String>,
    /// Detected schedule label, if any (e.g. "daily", "weekly").
    schedule: Option<String>,
    /// Whether the systemd timer/service unit is active, if known.
    timer_active: Option<bool>,
    /// Doctor findings.
    findings: Vec<FindingEntry>,
    /// Human-readable reason the backend was unreachable, surfaced in the
    /// degraded panel. Populated only when construction failed (e.g.
    /// `PackageDetection` on macOS) or a collection task panicked.
    unavailable_reason: Option<String>,
    /// Vertical scroll offset over the whole pane.
    scroll: usize,
}

impl Default for UpdatesContent {
    fn default() -> Self {
        Self::new()
    }
}

impl UpdatesContent {
    /// Create a new empty content area.
    #[must_use]
    pub fn new() -> Self {
        Self {
            available: false,
            package_manager: String::new(),
            auto_updates_enabled: false,
            service_active: false,
            pending_security: 0,
            pending_total: 0,
            last_run: None,
            schedule: None,
            timer_active: None,
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

    /// Current scroll offset (test hook).
    #[must_use]
    pub fn scroll(&self) -> usize {
        self.scroll
    }

    /// Total number of pending updates (drives the Dashboard UPDATES stat card).
    #[must_use]
    pub fn pending_total(&self) -> usize {
        self.pending_total
    }

    /// Number of pending security updates.
    #[must_use]
    pub fn pending_security(&self) -> usize {
        self.pending_security
    }

    /// Detected package-manager label (e.g. `"apt"`, `"dnf"`, empty if unknown).
    #[must_use]
    pub fn package_manager(&self) -> &str {
        &self.package_manager
    }

    // ── Data setters ─────────────────────────────────────────────────────────

    /// Set the overall availability flag (false → degraded panel).
    pub fn set_available(&mut self, available: bool) {
        self.available = available;
    }

    /// Set the human-readable reason the backend was unreachable. Cleared
    /// (`None`) whenever availability flips back to `true` so a stale reason
    /// can't linger after recovery.
    pub fn set_unavailable_reason(&mut self, reason: Option<String>) {
        self.unavailable_reason = if self.available { None } else { reason };
    }

    /// Replace the package-manager + status fields (drives the status panel).
    pub fn set_status(
        &mut self,
        package_manager: String,
        auto_updates_enabled: bool,
        service_active: bool,
        pending_security: usize,
        pending_total: usize,
        last_run: Option<String>,
    ) {
        self.package_manager = package_manager;
        self.auto_updates_enabled = auto_updates_enabled;
        self.service_active = service_active;
        self.pending_security = pending_security;
        self.pending_total = pending_total;
        self.last_run = last_run;
    }

    /// Replace the detected schedule.
    pub fn set_schedule(&mut self, schedule: Option<String>) {
        self.schedule = schedule;
    }

    /// Replace the systemd timer/service activity probe.
    pub fn set_timer_active(&mut self, timer_active: Option<bool>) {
        self.timer_active = timer_active;
    }

    /// Replace the findings list and clamp scroll.
    pub fn set_findings(&mut self, findings: Vec<FindingEntry>) {
        self.findings = findings;
        self.clamp_scroll();
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
        // Kept for API symmetry with the other read-only sections.
    }

    // ── Rendering ───────────────────────────────────────────────────────────

    /// Render the full updates content area.
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
                " UPDATES · {} pending · {} security · {} finding(s) ",
                self.pending_total,
                self.pending_security,
                self.findings.len(),
            ),
            p.accent,
            true,
        );

        if inner.height == 0 {
            return;
        }

        // Build the full content as a Vec<Line> then render only the visible
        // window (mirrors the other read-only sections' manual-scroll approach).
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

    /// Render the degraded state when the updates backend is unavailable on
    /// this host.
    ///
    /// `available == false` is set when construction failed (e.g.
    /// `PackageDetection` on macOS where neither `apt-get` nor `dnf` is on
    /// `$PATH`) OR when the `spawn_blocking` task panicked (`JoinError`). The
    /// reason string is surfaced here so the operator can see what actually
    /// went wrong.
    fn render_unavailable(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " UPDATES ", p.text_dim, false);
        let msg = Line::from(vec![
            Span::styled("✦ ", Style::new().fg(p.warn)),
            Span::styled(
                "updates unavailable",
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
        ]);
        // Prefer the construction / panic reason from the bundle; otherwise a
        // generic message accurate for both the macOS no-package-manager case
        // and the pre-first-poll state.
        let detail_text = self.unavailable_reason.clone().unwrap_or_else(|| {
            "no supported package manager (apt-get or dnf) detected on this host".to_string()
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

    /// Build the complete content as a flat list of lines (status, pending,
    /// schedule, timer, findings). Scrolling operates over this list.
    fn build_lines(&self, p: Palette) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();

        self.push_status_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_pending_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_schedule_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_timer_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_findings_lines(&mut lines, p);

        lines
    }

    fn push_status_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "Service",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        // Package manager badge. Owned so the Span outlives the borrow of self.
        let pm: String = if self.package_manager.is_empty() {
            "(unknown)".to_string()
        } else {
            self.package_manager.clone()
        };
        lines.push(Line::from(vec![
            Span::styled("  manager  ", Style::new().fg(p.text_muted)),
            Span::styled(pm, Style::new().fg(p.accent2)),
        ]));

        // Auto-updates enabled badge.
        let (enabled_label, enabled_color) = if self.auto_updates_enabled {
            ("● enabled", p.ok)
        } else {
            ("○ disabled", p.warn)
        };
        lines.push(Line::from(vec![
            Span::styled("  auto     ", Style::new().fg(p.text_muted)),
            Span::styled(enabled_label, Style::new().fg(enabled_color)),
        ]));

        // Service active badge.
        let (active_label, active_color) = if self.service_active {
            ("● active", p.ok)
        } else {
            ("○ inactive", p.err)
        };
        lines.push(Line::from(vec![
            Span::styled("  state    ", Style::new().fg(p.text_muted)),
            Span::styled(active_label, Style::new().fg(active_color)),
        ]));

        // Last run.
        let last_run = self.last_run.clone().unwrap_or_else(|| "(unknown)".into());
        lines.push(Line::from(vec![
            Span::styled("  last run ", Style::new().fg(p.text_muted)),
            Span::styled(last_run, Style::new().fg(p.text)),
        ]));
    }

    fn push_pending_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "Pending Updates",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        let security_color = if self.pending_security > 0 {
            p.err
        } else {
            p.ok
        };
        let total_color = if self.pending_total > 0 { p.warn } else { p.ok };

        lines.push(Line::from(vec![
            Span::styled("  security ", Style::new().fg(p.text_muted)),
            Span::styled(
                format!("{}", self.pending_security),
                Style::new().fg(security_color).add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  total    ", Style::new().fg(p.text_muted)),
            Span::styled(
                format!("{}", self.pending_total),
                Style::new().fg(total_color).add_modifier(Modifier::BOLD),
            ),
        ]));

        if self.pending_total == 0 {
            lines.push(Line::from(Span::styled(
                "  system is up to date",
                Style::new().fg(p.ok),
            )));
        }
    }

    fn push_schedule_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "Schedule",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        let schedule = self
            .schedule
            .clone()
            .unwrap_or_else(|| "(not configured)".into());
        let sched_color = if self.schedule.is_some() {
            p.ok
        } else {
            p.text_dim
        };
        lines.push(Line::from(vec![
            Span::styled("  cadence  ", Style::new().fg(p.text_muted)),
            Span::styled(schedule, Style::new().fg(sched_color)),
        ]));
    }

    fn push_timer_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "Timer / Service Unit",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));
        let (icon, text, color) = match self.timer_active {
            Some(true) => ("✓", "active", p.ok),
            Some(false) => ("✗", "inactive", p.warn),
            None => ("?", "unknown", p.text_dim),
        };
        lines.push(Line::from(vec![
            Span::styled("  systemd  ", Style::new().fg(p.text_muted)),
            Span::styled(format!("{icon} {text}"), Style::new().fg(color)),
        ]));
    }

    fn push_findings_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        // Group by severity: Critical > Important > Warning > Info > Ok.
        const ORDER: &[&str] = &["critical", "important", "warning", "info", "ok"];
        crate::ui::screens::findings::push_findings_grouped(
            lines,
            p,
            &self.findings,
            ORDER,
            crate::ui::screens::findings::severity_style_with_important_warn,
            crate::ui::screens::findings::FindingWidths::TITLE_60,
        );
    }
}

impl crate::ui::screens::section_overview::SectionOverview for UpdatesContent {
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
        if self.pending_total == 0 {
            Some("up to date".to_string())
        } else {
            Some(format!(
                "{} pending{}",
                self.pending_total,
                if self.pending_security > 0 {
                    format!(" · {} security", self.pending_security)
                } else {
                    String::new()
                }
            ))
        }
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

    fn sample_findings() -> Vec<FindingEntry> {
        vec![
            FindingEntry {
                id: "binary.unattended-upgrades.found".into(),
                severity: "ok".into(),
                title: "unattended-upgrades binary available".into(),
                detail: "Located on $PATH".into(),
                fix: None,
            },
            FindingEntry {
                id: "config.auto-updates.disabled".into(),
                severity: "warning".into(),
                title: "Automatic updates are disabled".into(),
                detail: String::new(),
                fix: Some("Enable auto-updates via toride configure".into()),
            },
            FindingEntry {
                id: "binary.dnf-automatic.missing".into(),
                severity: "critical".into(),
                title: "dnf-automatic not found".into(),
                detail: "The dnf-automatic binary could not be located on $PATH.".into(),
                fix: Some("Install dnf-automatic: dnf install dnf-automatic".into()),
            },
        ]
    }

    /// Render a content area to a string (snapshot pattern from ssh `keys_tab.rs`).
    fn render_to_string(content: &mut UpdatesContent, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| content.view(f, f.area(), CHARM)).unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn new_is_unavailable_and_empty() {
        let c = UpdatesContent::new();
        assert!(!c.available);
        assert!(c.findings.is_empty());
        assert!(c.package_manager.is_empty());
        assert!(!c.has_modal());
        assert_eq!(c.scroll(), 0);
    }

    #[test]
    fn default_matches_new() {
        let from_new = UpdatesContent::new();
        let from_default = UpdatesContent::default();
        assert_eq!(from_new.available, from_default.available);
    }

    #[test]
    fn render_unavailable_when_not_available() {
        let mut c = UpdatesContent::new();
        let out = render_to_string(&mut c, 100, 24);
        assert!(out.contains("updates unavailable"), "degraded panel: {out}");
    }

    #[test]
    fn render_unavailable_shows_reason() {
        let mut c = UpdatesContent::new();
        c.set_unavailable_reason(Some("package detection failed: no apt-get".into()));
        let out = render_to_string(&mut c, 120, 24);
        assert!(out.contains("package detection failed"), "reason: {out}");
    }

    #[test]
    fn render_status_panel() {
        let mut c = UpdatesContent::new();
        c.set_available(true);
        c.set_status(
            "apt".into(),
            true,
            true,
            2,
            5,
            Some("2026-06-18T03:00:00Z".into()),
        );
        let out = render_to_string(&mut c, 110, 30);
        assert!(out.contains("apt"), "package manager badge: {out}");
        assert!(out.contains("enabled"), "auto-updates badge: {out}");
        assert!(out.contains("active"), "service active badge: {out}");
        assert!(out.contains("2026-06-18"), "last run: {out}");
    }

    #[test]
    fn render_pending_updates_summary() {
        let mut c = UpdatesContent::new();
        c.set_available(true);
        c.set_status("apt".into(), true, true, 3, 7, None);
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("Pending Updates"), "header: {out}");
        assert!(out.contains("security"), "security label: {out}");
        assert!(out.contains("total"), "total label: {out}");
    }

    #[test]
    fn render_up_to_date_message_when_zero() {
        let mut c = UpdatesContent::new();
        c.set_available(true);
        c.set_status("apt".into(), true, true, 0, 0, None);
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("up to date"), "up-to-date message: {out}");
    }

    #[test]
    fn render_schedule_and_timer_cards() {
        let mut c = UpdatesContent::new();
        c.set_available(true);
        c.set_status("apt".into(), true, true, 0, 0, None);
        c.set_schedule(Some("daily".into()));
        c.set_timer_active(Some(true));
        let out = render_to_string(&mut c, 100, 36);
        assert!(out.contains("Schedule"), "schedule header: {out}");
        assert!(out.contains("daily"), "schedule cadence: {out}");
        assert!(out.contains("Timer"), "timer header: {out}");
        assert!(out.contains("active"), "timer state: {out}");
    }

    #[test]
    fn render_schedule_unconfigured() {
        let mut c = UpdatesContent::new();
        c.set_available(true);
        c.set_status("apt".into(), true, true, 0, 0, None);
        c.set_schedule(None);
        let out = render_to_string(&mut c, 100, 36);
        assert!(
            out.contains("not configured"),
            "unconfigured schedule: {out}"
        );
    }

    #[test]
    fn render_timer_unknown() {
        let mut c = UpdatesContent::new();
        c.set_available(true);
        c.set_status("apt".into(), true, true, 0, 0, None);
        c.set_timer_active(None);
        let out = render_to_string(&mut c, 100, 36);
        assert!(out.contains("unknown"), "timer unknown: {out}");
    }

    #[test]
    fn render_findings_grouped_by_severity() {
        let mut c = UpdatesContent::new();
        c.set_available(true);
        c.set_status("apt".into(), true, true, 0, 0, None);
        c.set_findings(sample_findings());
        let out = render_to_string(&mut c, 120, 50);
        assert!(out.contains("CRITICAL"), "severity group header: {out}");
        assert!(out.contains("WARNING"), "warning group: {out}");
        assert!(
            out.contains("dnf-automatic not found"),
            "finding title: {out}"
        );
        assert!(out.contains("Install dnf-automatic"), "fix hint: {out}");
    }

    #[test]
    fn scroll_down_consumed_and_returns_none() {
        let mut c = UpdatesContent::new();
        c.set_available(true);
        assert!(c.handle_key(KeyCode::Down).is_none());
        assert_eq!(c.scroll(), 1);
    }

    #[test]
    fn scroll_up_at_zero_stays_zero() {
        let mut c = UpdatesContent::new();
        c.set_available(true);
        c.handle_key(KeyCode::Up);
        assert_eq!(c.scroll(), 0);
    }

    #[test]
    fn page_down_jumps_by_eight() {
        let mut c = UpdatesContent::new();
        c.set_available(true);
        c.handle_key(KeyCode::PageDown);
        assert_eq!(c.scroll(), 8);
    }

    #[test]
    fn esc_returns_back_action() {
        let mut c = UpdatesContent::new();
        assert_eq!(c.handle_key(KeyCode::Esc), Some(Action::Back));
    }

    #[test]
    fn mouse_scroll_wheel_adjusts_scroll() {
        let mut c = UpdatesContent::new();
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
        let mut c = UpdatesContent::new();
        c.set_available(true);
        c.set_status("apt".into(), true, true, 1, 2, None);
        c.set_findings(sample_findings());
        // 20x5 — well below comfortable, must not panic.
        let _ = render_to_string(&mut c, 20, 5);
    }

    #[test]
    fn tiny_terminal_unavailable_panel_does_not_panic() {
        // Mirrors tiny_terminal_does_not_panic but exercises the
        // `available == false` degraded panel (render_unavailable). That path
        // computes centered rects via `inner.height.saturating_sub(3) / 2` and
        // `+ 1`; the layout is unverified at tiny heights, where the detail
        // rect y lands at/below the panel. Also feed a long reason to exercise
        // the Wrap { trim: false } path instead of clipping.
        let mut c = UpdatesContent::new();
        c.set_unavailable_reason(Some(
            "updates data collection timed out after 30s because the network probe exceeded its deadline".into(),
        ));
        // height=3 is the extreme: inner pane is 1 row tall, so the centered
        // msg and the wrapped detail both collapse onto the single inner row /
        // bleed onto the border. The load-bearing property is no panic.
        let _ = render_to_string(&mut c, 20, 3);
        // At 28x5 the inner pane is wide enough that the centered
        // "✦ updates unavailable" message fits without clipping, and tall
        // enough for the msg + a wrapped detail line.
        let out = render_to_string(&mut c, 28, 5);
        assert!(
            out.contains("updates unavailable"),
            "degraded panel must render at 28x5: {out}"
        );
    }

    #[test]
    fn empty_states_render_without_panic() {
        let mut c = UpdatesContent::new();
        c.set_available(true);
        c.set_status(String::new(), false, false, 0, 0, None);
        let out = render_to_string(&mut c, 100, 40);
        assert!(out.contains("no findings"), "empty findings: {out}");
        assert!(out.contains("disabled"), "disabled auto-updates: {out}");
        assert!(out.contains("inactive"), "inactive service: {out}");
    }

    #[test]
    fn set_findings_replaces_and_keeps_scroll_finite() {
        let mut c = UpdatesContent::new();
        c.set_available(true);
        c.set_status("apt".into(), true, true, 0, 0, None);
        c.scroll = 1_000_000;
        c.set_findings(sample_findings());
        // After a render the scroll is clamped to the visible window. Capture
        // the exact max the render path will clamp to: lines.len() minus the
        // inner pane height (which is the area height minus the titled-panel
        // chrome). build_lines() is the same Vec the view renders.
        let _ = render_to_string(&mut c, 100, 30);
        // The clamp must have fired: scroll can never exceed the line count.
        let line_count = c.build_lines(CHARM).len();
        assert!(
            c.scroll() < 1_000_000,
            "render-path clamp_scroll_to must have fired; got scroll = {}",
            c.scroll()
        );
        assert!(
            c.scroll() <= line_count,
            "scroll ({}) must not exceed total line count ({})",
            c.scroll(),
            line_count
        );
    }

    #[test]
    fn unavailable_reason_cleared_on_available() {
        let mut c = UpdatesContent::new();
        c.set_unavailable_reason(Some("boom".into()));
        assert_eq!(c.unavailable_reason.as_deref(), Some("boom"));
        c.set_available(true);
        c.set_unavailable_reason(Some("boom".into()));
        assert!(
            c.unavailable_reason.is_none(),
            "reason must clear when available"
        );
    }
}
