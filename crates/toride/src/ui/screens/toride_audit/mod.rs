//! Audit management content area (live READ-ONLY).
//!
//! Renders inside the dashboard's content region when
//! [`Section::Audit`](crate::data::Section) is the active sidebar section. This
//! mirrors the read-only fail2ban/users template: there is no write path, no
//! optimistic update, no cooldown, and no loading spinner — every line is a
//! pure read.
//!
//! Layout (single scrollable pane, no sub-tab bar):
//! 1. auditd status card — running badge + raw `auditctl -s` status text.
//! 2. Integrity (AIDE) — database initialized, file count, last check.
//! 3. Audit rules — per-file rule counts from `/etc/audit/rules.d`.
//! 4. Log sources — `/var/log/audit/*` files + rsyslog/journald backends.
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

/// A single doctor finding produced by the audit doctor suite.
#[derive(Clone, Debug)]
pub struct AuditFindingEntry {
    /// Machine-readable dot-separated id (e.g. `binary.auditctl.missing`).
    pub id: String,
    /// Severity as a lowercase string: `"ok" | "info" | "warning" | "error" | "critical"`.
    pub severity: String,
    /// Short human-readable title.
    pub title: String,
    /// Longer description (may be empty).
    pub detail: String,
    /// Suggested remediation, if any.
    pub fix: Option<String>,
}

/// AIDE file-integrity status summary.
#[derive(Clone, Debug)]
pub struct IntegrityStateEntry {
    /// Whether the AIDE database is initialized.
    pub database_initialized: bool,
    /// Number of files in the AIDE database, if known.
    pub file_count: Option<usize>,
    /// Whether the last integrity check passed, if known.
    pub last_check_passed: Option<bool>,
    /// Output from the last check, if any.
    pub last_check_output: Option<String>,
}

/// A parsed audit rules file (from `/etc/audit/rules.d`).
#[derive(Clone, Debug)]
pub struct AuditRuleEntry {
    /// File name stem (without directory or `.rules` extension).
    pub name: String,
    /// Number of active rule lines (comments/blanks filtered out).
    pub rule_count: usize,
    /// The active rule lines themselves.
    pub rules: Vec<String>,
}

/// An audit log source file (typically under `/var/log/audit`).
#[derive(Clone, Debug)]
pub struct AuditLogSourceEntry {
    /// Basename label (e.g. `audit.log`).
    pub label: String,
    /// Full path.
    pub path: String,
}

// ── AuditContent ────────────────────────────────────────────────────────────

/// Audit management content rendered inside the dashboard content area.
///
/// READ-ONLY: there are no write operations, no optimistic updates, no loading
/// spinner, no cooldown. Data arrives via [`AuditContent::set_*`] setters
/// driven by [`AuditCollector`](crate::toride_audit_data::AuditCollector).
pub struct AuditContent {
    /// Whether the audit backend produced any data at all. `false` only when a
    /// collection task panicked (`JoinError`) — a missing binary surfaces as a
    /// Critical finding and keeps `available == true` so the operator sees the
    /// findings panel.
    available: bool,
    /// Whether the auditd service is running.
    auditd_running: bool,
    /// Raw `auditctl -s` status text (best-effort; empty on failure).
    auditd_status: String,
    /// AIDE integrity status.
    integrity: IntegrityStateEntry,
    /// Parsed audit rule files.
    rules: Vec<AuditRuleEntry>,
    /// Audit log file sources.
    log_sources: Vec<AuditLogSourceEntry>,
    /// Whether rsyslog is available (`None` if the probe failed).
    rsyslog_available: Option<bool>,
    /// Whether systemd-journald is available (`None` if the probe failed).
    journald_available: Option<bool>,
    /// Doctor findings (cached for 60s between collections).
    findings: Vec<AuditFindingEntry>,
    /// Human-readable reason the backend was unreachable, surfaced in the
    /// degraded panel. Populated only when a collection task panicked.
    unavailable_reason: Option<String>,
    /// Vertical scroll offset over the whole pane.
    scroll: usize,
}

impl Default for AuditContent {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditContent {
    /// Create a new empty content area.
    #[must_use]
    pub fn new() -> Self {
        Self {
            available: false,
            auditd_running: false,
            auditd_status: String::new(),
            integrity: IntegrityStateEntry {
                database_initialized: false,
                file_count: None,
                last_check_passed: None,
                last_check_output: None,
            },
            rules: Vec::new(),
            log_sources: Vec::new(),
            rsyslog_available: None,
            journald_available: None,
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

    /// Live audit rule-file count for the sidebar badge. `None` when the
    /// backend is unavailable so the badge stays honestly empty.
    #[must_use]
    pub fn badge_count(&self) -> Option<usize> {
        if self.available {
            Some(self.rules.len())
        } else {
            None
        }
    }

    // ── Data setters ─────────────────────────────────────────────────────────

    /// Replace auditd status fields (drives the auditd card).
    pub fn set_auditd(&mut self, running: bool, status: String) {
        self.auditd_running = running;
        self.auditd_status = status;
    }

    /// Replace the AIDE integrity status.
    pub fn set_integrity(&mut self, integrity: IntegrityStateEntry) {
        self.integrity = integrity;
        self.clamp_scroll();
    }

    /// Replace the rules list and clamp scroll.
    pub fn set_rules(&mut self, rules: Vec<AuditRuleEntry>) {
        self.rules = rules;
        self.clamp_scroll();
    }

    /// Replace the log sources list and clamp scroll.
    pub fn set_log_sources(&mut self, log_sources: Vec<AuditLogSourceEntry>) {
        self.log_sources = log_sources;
        self.clamp_scroll();
    }

    /// Replace log-backend availability.
    pub fn set_log_backends(&mut self, rsyslog: Option<bool>, journald: Option<bool>) {
        self.rsyslog_available = rsyslog;
        self.journald_available = journald;
    }

    /// Replace the findings list and clamp scroll.
    pub fn set_findings(&mut self, findings: Vec<AuditFindingEntry>) {
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
        // Kept for API symmetry with the other read-only sections.
    }

    // ── Rendering ───────────────────────────────────────────────────────────

    /// Render the full audit content area.
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
                " AUDIT · {} rule(s) · {} log(s) · {} finding(s) ",
                self.rules.iter().map(|r| r.rule_count).sum::<usize>(),
                self.log_sources.len(),
                self.findings.len(),
            ),
            p.accent,
            true,
        );

        if inner.height == 0 {
            return;
        }

        // Build the full content as a Vec<Line> then render only the visible
        // window (mirrors the fail2ban/users tabs' manual-scroll approach).
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

    /// Render the degraded state when the audit backend panicked.
    ///
    /// `available == false` is only ever set when a collection task returned an
    /// empty bundle, which today happens exclusively when the `spawn_blocking`
    /// task PANICS (`JoinError`) — not when a binary is missing (a missing
    /// binary instead produces a Critical doctor finding, which keeps
    /// `available == true` so the operator sees the findings panel). The reason
    /// string is surfaced here so the operator can see what actually panicked;
    /// when no reason is known we fall back to a generic, accurate message.
    fn render_unavailable(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " AUDIT ", p.text_dim, false);
        let msg = Line::from(vec![
            Span::styled("✦ ", Style::new().fg(p.warn)),
            Span::styled(
                "audit unavailable",
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
        ]);
        let detail_text = self
            .unavailable_reason
            .clone()
            .unwrap_or_else(|| "audit data could not be collected on this host".to_string());
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

    /// Build the complete content as a flat list of lines (auditd, integrity,
    /// rules, logs, findings). Scrolling operates over this list.
    fn build_lines(&self, p: Palette) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();

        self.push_auditd_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_integrity_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_rules_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_logs_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_findings_lines(&mut lines, p);

        lines
    }

    fn push_auditd_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "auditd",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        // Running badge.
        let (run_label, run_color) = if self.auditd_running {
            ("● running", p.ok)
        } else {
            ("○ inactive", p.err)
        };
        lines.push(Line::from(vec![
            Span::styled("  state    ", Style::new().fg(p.text_muted)),
            Span::styled(run_label, Style::new().fg(run_color)),
        ]));

        // Raw `auditctl -s` status text, one line per status line. Empty on
        // failure (or when auditctl is missing).
        if self.auditd_status.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no status output",
                Style::new().fg(p.text_dim),
            )));
        } else {
            for raw in self.auditd_status.lines().take(8) {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    continue;
                }
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::new().fg(p.text_muted)),
                    Span::styled(truncate_str(trimmed, 70), Style::new().fg(p.text_dim)),
                ]));
            }
        }
    }

    fn push_integrity_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "Integrity (AIDE)",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        // DB initialized badge.
        let (init_label, init_color) = if self.integrity.database_initialized {
            ("● initialized", p.ok)
        } else {
            ("○ uninitialized", p.warn)
        };
        lines.push(Line::from(vec![
            Span::styled("  database ", Style::new().fg(p.text_muted)),
            Span::styled(init_label, Style::new().fg(init_color)),
        ]));

        // The backend `IntegrityManager::status()` ALWAYS produces a one-line
        // human-readable status (`last_check_output`) covering install state,
        // database state, and change count (e.g. "AIDE not installed",
        // "AIDE 0.18.8 · db not initialized", "0 changes", "7 changes"). Render
        // it as the primary, authoritative "check" signal — it is the honest,
        // complete picture and never a stale "not implemented" placeholder.
        let status_line = self
            .integrity
            .last_check_output
            .clone()
            .unwrap_or_else(|| "no status available".to_string());
        // Colour by the strength of evidence: changes detected (file_count > 0)
        // is an error; a clean check (last_check_passed) is green; anything
        // without a real check (not installed, no database) is a neutral warn.
        let status_color = if self.integrity.file_count.is_some_and(|n| n > 0) {
            p.err
        } else if self.integrity.last_check_passed == Some(true) {
            p.ok
        } else {
            p.warn
        };
        lines.push(Line::from(vec![
            Span::styled("  check    ", Style::new().fg(p.text_muted)),
            Span::styled(status_line, Style::new().fg(status_color)),
        ]));

        // Numeric detail (files + verdict) ONLY when a real `aide --check`
        // actually ran: a passed check, or a check that found changes. When
        // AIDE is not installed / no database exists, the status line above is
        // the complete and honest picture — extra rows would only mislead (e.g.
        // a spurious "✗ failed" for a check that never ran).
        let show_numeric = self.integrity.last_check_passed == Some(true)
            || self.integrity.file_count.is_some_and(|n| n > 0);
        if show_numeric {
            let files = self
                .integrity
                .file_count
                .map_or_else(|| "(unknown)".into(), |n| n.to_string());
            lines.push(Line::from(vec![
                Span::styled("  files    ", Style::new().fg(p.text_muted)),
                Span::styled(files, Style::new().fg(p.text)),
            ]));

            let (check_label, check_color) = match self.integrity.last_check_passed {
                Some(true) => ("✓ passed", p.ok),
                Some(false) => ("✗ failed", p.err),
                None => ("? unknown", p.text_dim),
            };
            lines.push(Line::from(vec![
                Span::styled("  last     ", Style::new().fg(p.text_muted)),
                Span::styled(check_label, Style::new().fg(check_color)),
            ]));
        }
    }

    fn push_rules_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        let total: usize = self.rules.iter().map(|r| r.rule_count).sum();
        let header = format!("Audit Rules ({}) [{} line(s)]", self.rules.len(), total);
        lines.push(Line::from(Span::styled(
            header,
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        if self.rules.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no rule files",
                Style::new().fg(p.text_dim),
            )));
            return;
        }

        for rule in &self.rules {
            let name = truncate_str(&rule.name, 20);
            lines.push(Line::from(vec![
                Span::styled("  ▸ ", Style::new().fg(p.accent2)),
                Span::styled(
                    format!("{name:<20}"),
                    Style::new().fg(p.text).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("  {} rule(s)", rule.rule_count),
                    Style::new().fg(p.text_muted),
                ),
            ]));
            // Show up to the first few rule lines so the panel stays scannable.
            for raw in rule.rules.iter().take(3) {
                let line = truncate_str(raw, 66);
                lines.push(Line::from(vec![
                    Span::styled("      · ", Style::new().fg(p.text_dim)),
                    Span::styled(line, Style::new().fg(p.text_dim)),
                ]));
            }
            if rule.rules.len() > 3 {
                lines.push(Line::from(Span::styled(
                    format!("      … +{} more", rule.rules.len() - 3),
                    Style::new().fg(p.text_dim),
                )));
            }
        }
    }

    fn push_logs_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        let header = format!("Log Sources ({})", self.log_sources.len());
        lines.push(Line::from(Span::styled(
            header,
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        // Backend availability.
        Self::push_backend_line(lines, p, "rsyslog ", self.rsyslog_available);
        Self::push_backend_line(lines, p, "journald", self.journald_available);

        if self.log_sources.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no log files found",
                Style::new().fg(p.text_dim),
            )));
            return;
        }

        for src in &self.log_sources {
            let label = truncate_str(&src.label, 22);
            let path = truncate_str(&src.path, 40);
            lines.push(Line::from(vec![
                Span::styled("  ≡ ", Style::new().fg(p.accent2)),
                Span::styled(
                    format!("{label:<22}"),
                    Style::new().fg(p.text).add_modifier(Modifier::BOLD),
                ),
                Span::styled(path, Style::new().fg(p.text_dim)),
            ]));
        }
    }

    fn push_backend_line(
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

impl crate::ui::screens::section_overview::SectionOverview for AuditContent {
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
            if self.auditd_running {
                "auditd running"
            } else {
                "auditd stopped"
            },
            self.rules.len()
        ))
    }

    fn findings_count(&self) -> usize {
        self.findings.len()
    }
}

impl crate::ui::screens::findings::Finding for AuditFindingEntry {
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

    fn sample_integrity() -> IntegrityStateEntry {
        // Coherent degraded demo state: a real `aide --check` ran and detected
        // 42 133 changed files (so the check did not pass). `last_check_output`
        // is the one-line human-readable summary the backend always produces.
        IntegrityStateEntry {
            database_initialized: true,
            file_count: Some(42_133),
            last_check_passed: Some(false),
            last_check_output: Some("42133 changes".into()),
        }
    }

    fn sample_rules() -> Vec<AuditRuleEntry> {
        vec![AuditRuleEntry {
            name: "hardening".into(),
            rule_count: 2,
            rules: vec![
                "-w /etc/passwd -p wa -k identity".into(),
                "-a always,exit -S open".into(),
            ],
        }]
    }

    fn sample_log_sources() -> Vec<AuditLogSourceEntry> {
        vec![AuditLogSourceEntry {
            label: "audit.log".into(),
            path: "/var/log/audit/audit.log".into(),
        }]
    }

    fn sample_findings() -> Vec<AuditFindingEntry> {
        vec![
            AuditFindingEntry {
                id: "binary.auditctl.missing".into(),
                severity: "critical".into(),
                title: "auditctl not found".into(),
                detail: "The auditctl binary could not be located on $PATH.".into(),
                fix: Some("Install auditd: apt install auditd".into()),
            },
            AuditFindingEntry {
                id: "config.rules-d.missing".into(),
                severity: "warning".into(),
                title: "Audit rules directory does not exist".into(),
                detail: String::new(),
                fix: None,
            },
        ]
    }

    /// Render a content area to a string (snapshot pattern from fail2ban/users).
    fn render_to_string(content: &mut AuditContent, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| content.view(f, f.area(), CHARM)).unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn new_is_unavailable_and_empty() {
        let c = AuditContent::new();
        assert!(!c.available);
        assert!(c.rules.is_empty());
        assert!(c.log_sources.is_empty());
        assert!(c.findings.is_empty());
        assert!(!c.has_modal());
    }

    #[test]
    fn default_matches_new() {
        let from_new = AuditContent::new();
        let from_default = AuditContent::default();
        assert_eq!(from_new.available, from_default.available);
    }

    #[test]
    fn render_unavailable_when_not_available() {
        let mut c = AuditContent::new();
        let out = render_to_string(&mut c, 100, 24);
        assert!(out.contains("audit unavailable"), "degraded panel: {out}");
    }

    #[test]
    fn render_auditd_status_card() {
        let mut c = AuditContent::new();
        c.set_available(true);
        c.set_auditd(true, "enabled 1\npid 4242\nrate_limit 0".into());
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("running"), "running badge: {out}");
        assert!(out.contains("pid 4242"), "raw status: {out}");
    }

    #[test]
    fn render_integrity_card() {
        let mut c = AuditContent::new();
        c.set_available(true);
        c.set_integrity(sample_integrity());
        let out = render_to_string(&mut c, 110, 30);
        assert!(out.contains("initialized"), "db init badge: {out}");
        assert!(out.contains("42133 changes"), "honest status line: {out}");
        assert!(out.contains("42133"), "file count: {out}");
        assert!(out.contains("failed"), "last check verdict: {out}");
    }

    /// Regression guard for the misleading-rendering finding. The backend
    /// [`toride_audit::integrity::IntegrityManager::status()`] is the SOLE
    /// producer of `IntegrityStatus` in production and now ALWAYS populates
    /// `last_check_passed` and `last_check_output` (a one-line human-readable
    /// status) — it never hands the panel a bare `None` that would render as a
    /// perpetual "(unknown)" / "? unknown" placeholder. Because the backend is
    /// the source of truth, `sample_integrity()` alone cannot catch a regression
    /// on the real-backend path. This test runs the REAL backend output through
    /// the exact integration pipeline the data layer uses
    /// (`Audit::with_paths(...)` → `.integrity().status()` →
    /// `convert_integrity` → renderer) and asserts the panel surfaces the
    /// honest status line verbatim and never a misleading placeholder row.
    #[test]
    fn render_integrity_real_backend_output_is_not_misleading() {
        use crate::toride_audit_convert::convert_integrity;

        // `Audit::with_paths` wires its own runner; `status()` only probes the
        // `aide` binary + config/db paths (and best-effort shells out to
        // `aide --version`/`--check`), so this is safe on any host. On the test
        // host (and CI) the `aide` binary is not installed, so the real backend
        // returns the honest `not_installed()` shape: { initialized: false,
        // file_count: Some(0), last_check_passed: Some(false),
        // last_check_output: Some("AIDE not installed") } — never `None`.
        let audit = toride_audit::Audit::with_paths(toride_audit::AuditPaths::default_system())
            .expect("Audit::with_paths only allocates a runner and paths");
        let real_status = audit
            .integrity()
            .status()
            .expect("status() only stats a path and cannot fail on a readable fs");

        // Pin the backend's honest contract: status() ALWAYS populates
        // `last_check_passed` and `last_check_output` (a human-readable status
        // line). `file_count` is `Some(0)` when AIDE is not installed, `Some(n)`
        // after a real `aide --check`. None of the secondary fields are
        // hardcoded `None` anymore — the old "not implemented" render branch
        // has retired in favour of rendering the status line verbatim.
        assert!(
            real_status.last_check_passed.is_some(),
            "backend status() must always populate last_check_passed, got: {:?}",
            real_status.last_check_passed,
        );
        let status_line = real_status
            .last_check_output
            .clone()
            .expect("backend status() must always populate last_check_output");

        // Drive the real-backend output through the same converter the data
        // layer uses, then render — exactly the production integration path.
        let entry = convert_integrity(real_status);
        let mut c = AuditContent::new();
        c.set_available(true);
        c.set_integrity(entry);
        let out = render_to_string(&mut c, 110, 30);

        // Slice out just the Integrity card so the negative assertions below
        // are not tripped by the Log Sources card's legitimate `? unknown`
        // rsyslog/journald rows (those are real probes that genuinely have no
        // answer on this host — accurate, not misleading).
        let integrity_card: String = out
            .lines()
            .skip_while(|l| !l.contains("Integrity (AIDE)"))
            .take_while(|l| !l.contains("Audit Rules") && !l.contains("Log Sources"))
            .collect::<Vec<_>>()
            .join("\n");

        // The honest status line must be surfaced verbatim — not a placeholder.
        assert!(
            integrity_card.contains(status_line.as_str()),
            "real-backend output must render the status line {status_line:?}, got: {integrity_card}",
        );
        assert!(
            !integrity_card.contains("(unknown)"),
            "real-backend output must NOT render the misleading '(unknown)' placeholder, got: {integrity_card}",
        );
        assert!(
            !integrity_card.contains("? unknown"),
            "real-backend output must NOT render the misleading '? unknown' row, got: {integrity_card}",
        );
        assert!(
            !integrity_card.contains("not implemented"),
            "the retired 'not implemented' placeholder must not render, got: {integrity_card}",
        );
    }

    #[test]
    fn render_rules_list() {
        let mut c = AuditContent::new();
        c.set_available(true);
        c.set_rules(sample_rules());
        let out = render_to_string(&mut c, 110, 36);
        assert!(out.contains("hardening"), "rule file name: {out}");
        assert!(out.contains("/etc/passwd"), "rule line: {out}");
    }

    #[test]
    fn render_log_sources_and_backends() {
        let mut c = AuditContent::new();
        c.set_available(true);
        c.set_log_sources(sample_log_sources());
        c.set_log_backends(Some(true), Some(false));
        let out = render_to_string(&mut c, 110, 36);
        assert!(out.contains("audit.log"), "log label: {out}");
        assert!(out.contains("rsyslog"), "rsyslog backend: {out}");
        assert!(out.contains("journald"), "journald backend: {out}");
    }

    #[test]
    fn render_findings_grouped_by_severity() {
        let mut c = AuditContent::new();
        c.set_available(true);
        c.set_findings(sample_findings());
        let out = render_to_string(&mut c, 110, 44);
        assert!(out.contains("CRITICAL"), "severity group header: {out}");
        assert!(out.contains("auditctl not found"), "finding title: {out}");
        assert!(out.contains("Install auditd"), "fix hint: {out}");
    }

    #[test]
    fn scroll_down_consumed_and_returns_none() {
        let mut c = AuditContent::new();
        c.set_available(true);
        assert!(c.handle_key(KeyCode::Down).is_none());
        assert_eq!(c.scroll, 1);
    }

    #[test]
    fn scroll_up_at_zero_stays_zero() {
        let mut c = AuditContent::new();
        c.set_available(true);
        c.handle_key(KeyCode::Up);
        assert_eq!(c.scroll, 0);
    }

    #[test]
    fn esc_returns_back_action() {
        let mut c = AuditContent::new();
        assert_eq!(c.handle_key(KeyCode::Esc), Some(Action::Back));
    }

    #[test]
    fn mouse_scroll_wheel_adjusts_scroll() {
        let mut c = AuditContent::new();
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
        let mut c = AuditContent::new();
        c.set_available(true);
        c.set_rules(sample_rules());
        c.set_findings(sample_findings());
        // 20x5 — well below comfortable, must not panic.
        let _ = render_to_string(&mut c, 20, 5);
    }

    #[test]
    fn tiny_terminal_unavailable_does_not_panic() {
        // Lock the degraded render_unavailable path against tiny dimensions too.
        let mut c = AuditContent::new();
        c.set_available(false);
        c.set_unavailable_reason(Some("collector task panicked".into()));
        let _ = render_to_string(&mut c, 20, 5);
    }

    #[test]
    fn empty_states_render_without_panic() {
        let mut c = AuditContent::new();
        c.set_available(true);
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("no rule files"), "empty rules: {out}");
        assert!(out.contains("no log files found"), "empty logs: {out}");
        assert!(out.contains("no findings"), "empty findings: {out}");
    }

    #[test]
    fn set_findings_replaces_and_keeps_scroll_finite() {
        let mut c = AuditContent::new();
        c.scroll = 1_000_000;
        c.set_findings(sample_findings());
        // After a render the scroll is clamped to the visible window.
        let _ = render_to_string(&mut c, 100, 30);
        // The render did not panic.
    }

    #[test]
    fn page_down_advances_by_eight() {
        let mut c = AuditContent::new();
        c.set_available(true);
        c.handle_key(KeyCode::PageDown);
        assert_eq!(c.scroll, 8);
        c.handle_key(KeyCode::PageUp);
        assert_eq!(c.scroll, 0);
    }

    // ── Full-screen insta snapshots ─────────────────────────────────────────
    //
    // Pin the full rendered output at fixed terminal sizes, mirroring the
    // toride_harden / ufw_kit snapshot tests so a layout regression (column
    // widths, severity-group indentation, empty-state text, the titled-panel
    // header counters) cannot slip past the contains-assertions silently.

    #[test]
    fn audit_content_snapshot_110x40() {
        let mut c = AuditContent::new();
        c.set_available(true);
        c.set_auditd(true, "enabled 1\npid 4242\nrate_limit 0".into());
        c.set_integrity(sample_integrity());
        c.set_rules(sample_rules());
        c.set_log_sources(sample_log_sources());
        c.set_log_backends(Some(true), Some(false));
        c.set_findings(sample_findings());
        let out = render_to_string(&mut c, 110, 40);
        insta::assert_snapshot!("audit_content_110x40", out);
    }

    #[test]
    fn audit_content_snapshot_unavailable_100x24() {
        let mut c = AuditContent::new();
        // set_unavailable_reason only retains the reason when available == false.
        c.set_unavailable_reason(Some("audit data collection panicked: JoinError".into()));
        let out = render_to_string(&mut c, 100, 24);
        insta::assert_snapshot!("audit_content_unavailable_100x24", out);
    }

    #[test]
    fn audit_content_snapshot_empty_state_110x40() {
        // Available but no data: every card shows its empty-state line. Locks
        // the "no rule files / no log files found / no findings" wording and
        // the `? unknown` backend fallbacks.
        let mut c = AuditContent::new();
        c.set_available(true);
        let out = render_to_string(&mut c, 110, 40);
        insta::assert_snapshot!("audit_content_empty_110x40", out);
    }
}
