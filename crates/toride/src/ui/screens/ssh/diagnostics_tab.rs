//! Diagnostics sub-tab for the SSH management screen.
//!
//! Displays diagnostic check results (SSH directory permissions, config issues,
//! agent status, etc.) as a scrollable list with severity icons, messages, and
//! module badges. Supports keyboard navigation, selection, and a detail modal.

use crossterm::event::{KeyCode, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::action::Action;
use crate::ssh_data::SshOp;
use crate::ui::components::{ButtonRow, interactive_button::InteractiveButton};
use crate::ui::responsive::{Viewport, truncate_str};
use crate::ui::theme::Palette;
use crate::ui::widgets::{
    ConfirmModal, ConfirmResult, Dropdown, FormModal, FormResult, Modal, TextInput,
    render_titled_panel,
};

use super::{DiagnosticEntry, SshTab, char_to_keycode};

// ── ActionModal ───────────────────────────────────────────────────────────────

/// Which action modal is currently open (if any).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActionModal {
    /// Run diagnostic checks form.
    Run,
    /// Fix all auto-fixable issues confirmation.
    FixAll,
}

// ── DiagnosticsTab ────────────────────────────────────────────────────────────

/// State for the Diagnostics sub-tab.
pub struct DiagnosticsTab {
    /// Diagnostic entries to display.
    entries: Vec<DiagnosticEntry>,
    /// Index of the currently selected entry.
    selected: usize,
    /// Vertical scroll offset.
    scroll: usize,
    /// Whether the detail modal is open, and for which entry index.
    detail_open: Option<usize>,
    /// Rendered rect of the detail modal (for click-outside detection).
    detail_modal_rect: Option<Rect>,
    /// Hitbox rects for list rows (rebuilt each frame).
    row_hitboxes: Vec<Rect>,
    /// Which row is hovered by the mouse.
    hovered_row: Option<usize>,
    /// Interactive footer shortcut buttons.
    buttons: ButtonRow<char>,
    /// Which action modal is open (if any).
    action_modal: Option<ActionModal>,
    /// Form modal for run checks operation.
    form: FormModal,
    /// Confirm modal for fix all operation.
    confirm: ConfirmModal,
    /// Pending write operations to be drained by the parent `SshContent`.
    pending_ops: Vec<SshOp>,
}

impl DiagnosticsTab {
    /// Create a new empty diagnostics tab.
    #[must_use]
    pub fn new() -> Self {
        let buttons = ButtonRow::new(
            vec![
                InteractiveButton::new("↵ detail", "↵", '\r'),
                InteractiveButton::new("r run", "r", 'r'),
                InteractiveButton::new("f fix all", "f", 'f'),
            ],
            vec![1, 1, 1],
        );
        Self {
            entries: Vec::new(),
            selected: 0,
            scroll: 0,
            detail_open: None,
            detail_modal_rect: None,
            row_hitboxes: Vec::new(),
            hovered_row: None,
            buttons,
            action_modal: None,
            form: FormModal::new(40),
            confirm: ConfirmModal::new(""),
            pending_ops: Vec::new(),
        }
    }

    /// Replace the diagnostic entries with new data.
    pub fn set_entries(&mut self, entries: Vec<DiagnosticEntry>) {
        self.entries = entries;
        if self.selected >= self.entries.len() && !self.entries.is_empty() {
            self.selected = self.entries.len() - 1;
        }
        self.clamp_scroll();
    }

    /// Whether a modal is currently open.
    #[must_use]
    pub fn has_modal(&self) -> bool {
        self.detail_open.is_some() || self.action_modal.is_some()
    }

    /// Clamp scroll so the selected item is visible.
    fn clamp_scroll(&mut self) {
        if self.entries.is_empty() {
            self.scroll = 0;
            return;
        }
        // Ensure selected is within bounds
        if self.selected >= self.entries.len() {
            self.selected = self.entries.len() - 1;
        }
    }

    /// Close the detail modal (if open).
    pub fn close_modal(&mut self) {
        self.detail_open = None;
    }

    /// Handle a mouse event for the diagnostic entry list.
    fn handle_mouse_impl(&mut self, mouse: MouseEvent) -> Option<Action> {
        // Action modal open: block background input.
        if self.action_modal.is_some() {
            return None;
        }

        // Detail modal open: block background, only close on click outside.
        if self.detail_open.is_some() {
            if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left))
                && let Some(mr) = self.detail_modal_rect
            {
                let col = mouse.column;
                let row = mouse.row;
                if col < mr.x || col >= mr.right() || row < mr.y || row >= mr.bottom() {
                    self.detail_open = None;
                    self.detail_modal_rect = None;
                }
            }
            return None;
        }

        // Footer buttons (always process for hover tracking).
        if let Some(c) = self.buttons.handle_mouse(&mouse) {
            return self.handle_key(char_to_keycode(c));
        }

        match mouse.kind {
            MouseEventKind::Moved | MouseEventKind::Drag(_) => {
                self.hovered_row = self.row_at(mouse.column, mouse.row);
            }
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some(idx) = self.row_at(mouse.column, mouse.row) {
                    self.selected = idx;
                    self.detail_open = Some(idx);
                }
            }
            MouseEventKind::ScrollDown => {
                if self.selected < self.entries.len().saturating_sub(1) {
                    self.selected += 1;
                    self.clamp_scroll();
                }
            }
            MouseEventKind::ScrollUp if self.selected > 0 => {
                self.selected -= 1;
                self.clamp_scroll();
            }
            _ => {}
        }
        None
    }

    /// Check if a screen coordinate falls within a list row hitbox.
    fn row_at(&self, col: u16, row: u16) -> Option<usize> {
        self.row_hitboxes.iter().position(|rect| {
            col >= rect.x && col < rect.right() && row >= rect.y && row < rect.bottom()
        })
    }
}

impl Default for DiagnosticsTab {
    fn default() -> Self {
        Self::new()
    }
}

impl SshTab for DiagnosticsTab {
    fn handle_key(&mut self, code: KeyCode) -> Option<Action> {
        // If detail modal is open, handle modal keys
        if self.detail_open.is_some() {
            match code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                    self.detail_open = None;
                    None
                }
                _ => None,
            }
        } else if let Some(action) = self.action_modal {
            // Action modal is open: delegate to it.
            match action {
                ActionModal::Run => match self.form.handle_key(code) {
                    FormResult::Submitted => {
                        self.pending_ops.push(SshOp::DoctorRunChecks);
                        self.action_modal = None;
                    }
                    FormResult::Cancelled => {
                        self.action_modal = None;
                    }
                    FormResult::Pending => {}
                },
                ActionModal::FixAll => {
                    match self.confirm.handle_key(code) {
                        Some(ConfirmResult::Confirmed) => {
                            // Fix all auto-fixable issues
                            self.pending_ops.push(SshOp::DoctorRunChecks);
                            self.action_modal = None;
                        }
                        Some(ConfirmResult::Cancelled) => {
                            self.action_modal = None;
                        }
                        None => {}
                    }
                }
            }
            None
        } else {
            match code {
                KeyCode::Up | KeyCode::Char('k') => {
                    if self.selected > 0 {
                        self.selected -= 1;
                        self.clamp_scroll();
                    }
                    None
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if !self.entries.is_empty() && self.selected < self.entries.len() - 1 {
                        self.selected += 1;
                        self.clamp_scroll();
                    }
                    None
                }
                KeyCode::Enter => {
                    if !self.entries.is_empty() {
                        self.detail_open = Some(self.selected);
                    }
                    None
                }
                // CRUD shortcuts
                KeyCode::Char('r') => {
                    self.form = FormModal::new(40)
                        .text_field(TextInput::new("Filter", 30).placeholder("check id or module"))
                        .select_field(Dropdown::new(
                            "Scope",
                            vec!["All", "Local", "Config", "Agent", "Known Hosts"],
                            16,
                        ));
                    self.action_modal = Some(ActionModal::Run);
                    None
                }
                KeyCode::Char('f') => {
                    let fixable_count = self.entries.iter().filter(|e| e.hint.is_some()).count();
                    self.confirm =
                        ConfirmModal::new(format!("Fix {fixable_count} auto-fixable issue(s)?"));
                    self.action_modal = Some(ActionModal::FixAll);
                    None
                }
                _ => None,
            }
        }
    }

    fn view(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        self.row_hitboxes.clear();
        if self.entries.is_empty() {
            Self::render_empty(frame, area, p);
        } else {
            self.render_list(frame, area, p);
        }

        // Render detail modal if open
        if let Some(idx) = self.detail_open
            && let Some(entry) = self.entries.get(idx).cloned()
        {
            self.render_detail_modal(frame, p, &entry);
        }

        // Render action modal on top
        match self.action_modal {
            Some(ActionModal::Run) => {
                self.form.render_in_modal_with_hint(
                    frame,
                    p,
                    "Run Diagnostics",
                    52,
                    16,
                    "Tab to cycle fields, Enter to run, Esc to cancel",
                );
            }
            Some(ActionModal::FixAll) => {
                self.confirm.render(frame, p, "Fix All Issues");
            }
            None => {}
        }
    }

    fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action> {
        self.handle_mouse_impl(mouse)
    }

    fn has_modal(&self) -> bool {
        self.detail_open.is_some() || self.action_modal.is_some()
    }

    fn close_modal(&mut self) {
        self.detail_open = None;
        self.detail_modal_rect = None;
        self.action_modal = None;
    }

    fn drain_ops(&mut self) -> Vec<SshOp> {
        std::mem::take(&mut self.pending_ops)
    }
}

// ── Rendering ─────────────────────────────────────────────────────────────────

impl DiagnosticsTab {
    fn render_empty(frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " DIAGNOSTICS ", p.text, false);
        let msg = Line::from(vec![
            Span::styled("No diagnostic findings", Style::new().fg(p.text_dim)),
            Span::styled(
                "  r",
                Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" run checks", Style::new().fg(p.text_muted)),
        ]);
        let centered = Rect::new(inner.x, inner.y + inner.height / 2, inner.width, 1);
        frame.render_widget(Paragraph::new(msg).centered(), centered);
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "terminal cols/rows are bounded < u16::MAX"
    )]
    fn render_list(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(
            frame,
            area,
            p,
            &format!(" DIAGNOSTICS ({}) ", self.entries.len()),
            p.text,
            false,
        );

        if inner.height == 0 {
            return;
        }

        let visible = inner.height as usize;
        let max_scroll = self.entries.len().saturating_sub(visible);
        if self.scroll > max_scroll {
            self.scroll = max_scroll;
        }
        // Ensure selected item is visible
        if self.selected < self.scroll {
            self.scroll = self.selected;
        } else if self.selected >= self.scroll + visible {
            self.scroll = self.selected - visible + 1;
        }

        for row in 0..visible {
            let idx = self.scroll + row;
            if idx >= self.entries.len() {
                break;
            }
            let entry = &self.entries[idx];
            let is_selected = idx == self.selected;
            let is_hovered = self.hovered_row == Some(idx);
            let y = inner.y + row as u16;
            let row_area = Rect::new(inner.x, y, inner.width, 1);

            // Store hitbox for mouse detection.
            self.row_hitboxes.push(row_area);

            // Selection or hover highlight.
            if is_selected || is_hovered {
                for x in row_area.x..row_area.right() {
                    if let Some(cell) = frame.buffer_mut().cell_mut((x, y)) {
                        cell.set_bg(if is_selected { p.sel_bg } else { p.bg_alt });
                    }
                }
            }

            let mut spans = Vec::new();

            // Severity icon and color
            let (icon, icon_color) = match entry.severity.as_str() {
                "ok" => ("✓", p.ok),
                "info" => ("ℹ", p.info),
                "warning" => ("⚠", p.warn),
                "error" => ("✗", p.err),
                _ => ("·", p.text_dim),
            };

            // Icon
            spans.push(Span::styled(
                format!("{icon} "),
                Style::new().fg(icon_color),
            ));

            // Message (truncated to fit)
            let msg_w = inner.width.saturating_sub(20) as usize;
            let msg = truncate_str(&entry.message, msg_w);
            let msg_style = match entry.severity.as_str() {
                "warning" | "error" => Style::new().fg(icon_color),
                _ => Style::new().fg(p.text),
            };
            spans.push(Span::styled(&msg, msg_style));

            // Right-align module badge — pad to end of row
            let module_badge = format!(" {}", entry.module);
            let used: usize = 2 + msg.len() + module_badge.len(); // icon+space + msg + badge
            let avail = inner.width as usize;
            if used < avail {
                let padding = avail - used;
                spans.push(Span::styled(
                    format!("{:width$}", "", width = padding),
                    Style::new(),
                ));
            }
            spans.push(Span::styled(module_badge, Style::new().fg(p.text_dim)));

            let line = Line::from(spans);
            frame.render_widget(Paragraph::new(line), row_area);
        }

        // Footer with key count and action hints
        self.render_footer(frame, area, p);
    }

    fn render_footer(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        let footer_y = area.y + area.height.saturating_sub(1);
        let footer_area = Rect::new(area.x + 1, footer_y, area.width.saturating_sub(2), 1);
        let viewport = Viewport::from_area(area);
        self.buttons
            .render(frame.buffer_mut(), footer_area, p, viewport);
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "terminal cols/rows are bounded < u16::MAX"
    )]
    fn render_detail_modal(&mut self, frame: &mut Frame, p: Palette, entry: &DiagnosticEntry) {
        let modal = Modal::new("Diagnostic Detail").dimensions(56, 10);
        self.detail_modal_rect = Some(modal.rect(frame.area()));
        modal.render(frame, p, |frame, content_area| {
            let (icon, icon_color) = match entry.severity.as_str() {
                "ok" => ("✓", p.ok),
                "info" => ("ℹ", p.info),
                "warning" => ("⚠", p.warn),
                "error" => ("✗", p.err),
                _ => ("·", p.text_dim),
            };

            let mut lines = vec![
                Line::from(vec![
                    Span::styled("Check:   ", Style::new().fg(p.text_dim)),
                    Span::styled(&entry.id, Style::new().fg(p.text)),
                ]),
                Line::from(vec![
                    Span::styled("Status:  ", Style::new().fg(p.text_dim)),
                    Span::styled(
                        format!("{icon} {}", entry.severity),
                        Style::new().fg(icon_color),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Module:  ", Style::new().fg(p.text_dim)),
                    Span::styled(&entry.module, Style::new().fg(p.text)),
                ]),
                Line::from(vec![
                    Span::styled("Message: ", Style::new().fg(p.text_dim)),
                    Span::styled(&entry.message, Style::new().fg(p.text)),
                ]),
            ];

            if let Some(hint) = &entry.hint {
                lines.push(Line::from(vec![
                    Span::styled("Hint:    ", Style::new().fg(p.text_dim)),
                    Span::styled(hint, Style::new().fg(p.accent)),
                ]));
            }

            lines.push(Line::raw(""));
            lines.push(Line::from(Span::styled(
                "Press Esc to close",
                Style::new().fg(p.text_muted),
            )));

            for (i, line) in lines.into_iter().enumerate() {
                let y = content_area.y + i as u16;
                if y < content_area.bottom() {
                    let row_area = Rect::new(content_area.x, y, content_area.width, 1);
                    frame.render_widget(Paragraph::new(line), row_area);
                }
            }
        });
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────
// (truncate_str is imported from crate::ui::responsive)

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entries() -> Vec<DiagnosticEntry> {
        vec![
            DiagnosticEntry {
                id: "ssh_dir_permissions".into(),
                severity: "ok".into(),
                module: "local".into(),
                message: "~/.ssh permissions are correct (0700)".into(),
                hint: None,
            },
            DiagnosticEntry {
                id: "config_syntax".into(),
                severity: "warning".into(),
                module: "config".into(),
                message: "Duplicate Host pattern in config".into(),
                hint: Some("Remove duplicate Host block".into()),
            },
            DiagnosticEntry {
                id: "agent_reachable".into(),
                severity: "error".into(),
                module: "agent".into(),
                message: "SSH agent is not running".into(),
                hint: Some("Start agent with eval $(ssh-agent)".into()),
            },
        ]
    }

    #[test]
    fn new_is_empty() {
        let tab = DiagnosticsTab::new();
        assert!(tab.entries.is_empty());
        assert!(!tab.has_modal());
    }

    #[test]
    fn set_entries_updates_list() {
        let mut tab = DiagnosticsTab::new();
        tab.set_entries(sample_entries());
        assert_eq!(tab.entries.len(), 3);
    }

    #[test]
    fn scroll_up_decrements_selected() {
        let mut tab = DiagnosticsTab::new();
        tab.set_entries(sample_entries());
        tab.selected = 1;
        tab.handle_key(KeyCode::Up);
        assert_eq!(tab.selected, 0);
    }

    #[test]
    fn scroll_down_increments_selected() {
        let mut tab = DiagnosticsTab::new();
        tab.set_entries(sample_entries());
        tab.selected = 0;
        tab.handle_key(KeyCode::Down);
        assert_eq!(tab.selected, 1);
    }

    #[test]
    fn scroll_up_at_zero_stays() {
        let mut tab = DiagnosticsTab::new();
        tab.set_entries(sample_entries());
        tab.selected = 0;
        tab.handle_key(KeyCode::Up);
        assert_eq!(tab.selected, 0);
    }

    #[test]
    fn scroll_down_at_end_stays() {
        let mut tab = DiagnosticsTab::new();
        tab.set_entries(sample_entries());
        tab.selected = 2;
        tab.handle_key(KeyCode::Down);
        assert_eq!(tab.selected, 2);
    }

    #[test]
    fn enter_opens_detail_modal() {
        let mut tab = DiagnosticsTab::new();
        tab.set_entries(sample_entries());
        tab.handle_key(KeyCode::Enter);
        assert!(tab.has_modal());
        assert_eq!(tab.detail_open, Some(0));
    }

    #[test]
    fn esc_closes_detail_modal() {
        let mut tab = DiagnosticsTab::new();
        tab.set_entries(sample_entries());
        tab.detail_open = Some(0);
        tab.handle_key(KeyCode::Esc);
        assert!(!tab.has_modal());
    }

    #[test]
    fn render_empty_state() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = DiagnosticsTab::new();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("No diagnostic findings"),
            "empty state: {output}"
        );
    }

    #[test]
    fn render_with_entries() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = DiagnosticsTab::new();
        tab.set_entries(sample_entries());
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains("permissions"), "entry message: {output}");
    }

    #[test]
    fn render_detail_modal() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = DiagnosticsTab::new();
        tab.set_entries(sample_entries());
        tab.detail_open = Some(1); // warning entry with hint
        let mut terminal = Terminal::new(TestBackend::new(80, 30)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("Diagnostic Detail"),
            "modal title: {output}"
        );
        assert!(output.contains("Duplicate"), "message in modal: {output}");
    }

    #[test]
    fn truncate_str_short() {
        assert_eq!(truncate_str("abc", 5), "abc");
    }

    #[test]
    fn truncate_str_exact() {
        assert_eq!(truncate_str("abcde", 5), "abcde");
    }

    #[test]
    fn truncate_str_long() {
        assert_eq!(truncate_str("abcdefgh", 5), "abc..");
    }

    #[test]
    fn truncate_str_zero() {
        assert_eq!(truncate_str("abc", 0), "");
    }

    #[test]
    fn set_entries_clamps_selected() {
        let mut tab = DiagnosticsTab::new();
        tab.selected = 10;
        tab.set_entries(sample_entries()); // 3 items
        assert!(tab.selected < 3);
    }
}
