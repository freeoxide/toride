//! Agent sub-tab for the SSH management screen.
//!
//! Displays the SSH agent connection status and all keys loaded in the agent
//! as a scrollable list with type, fingerprint, lock status, and constraint
//! indicators. Supports keyboard navigation, selection, and a detail modal.

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
    ConfirmModal, ConfirmResult, FormModal, FormResult, Modal, TextInput, render_titled_panel,
};

use super::{AgentKeyEntry, AgentStatus, SshTab, char_to_keycode};

// ── ActionModal ───────────────────────────────────────────────────────────────

/// Which action modal is currently open (if any).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActionModal {
    /// Add key to agent form.
    Add,
    /// Remove key from agent confirmation.
    Remove,
    /// Remove all keys from agent confirmation.
    RemoveAll,
}

// ── AgentTab ─────────────────────────────────────────────────────────────────

/// State for the Agent sub-tab.
pub struct AgentTab {
    /// Agent connection status.
    status: AgentStatus,
    /// Key entries loaded in the agent.
    keys: Vec<AgentKeyEntry>,
    /// Index of the currently selected key.
    selected: usize,
    /// Vertical scroll offset.
    scroll: usize,
    /// Whether the detail modal is open, and for which key index.
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
    /// Form modal for add key operation.
    form: FormModal,
    /// Confirm modal for remove key operation.
    confirm: ConfirmModal,
    /// Pending write operations to be forwarded to `SshContent`.
    pending_ops: Vec<SshOp>,
}

impl AgentTab {
    /// Create a new empty agent tab.
    #[must_use]
    pub fn new() -> Self {
        let buttons = ButtonRow::new(
            vec![
                InteractiveButton::new("↵ detail", "↵", '\r'),
                InteractiveButton::new("a add", "a", 'a'),
                InteractiveButton::new("d remove", "d", 'd'),
                InteractiveButton::new("D clear", "D", 'D'),
            ],
            vec![1, 1, 1, 1],
        );
        Self {
            status: AgentStatus {
                reachable: false,
                socket_path: None,
                key_count: 0,
            },
            keys: Vec::new(),
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

    /// Replace the agent status and key list with new data.
    pub fn set_data(&mut self, status: AgentStatus, keys: Vec<AgentKeyEntry>) {
        self.status = status;
        self.keys = keys;
        if self.selected >= self.keys.len() && !self.keys.is_empty() {
            self.selected = self.keys.len() - 1;
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
        if self.keys.is_empty() {
            self.scroll = 0;
            return;
        }
        // Ensure selected is within bounds
        if self.selected >= self.keys.len() {
            self.selected = self.keys.len() - 1;
        }
    }

    /// Close the detail modal (if open).
    pub fn close_modal(&mut self) {
        self.detail_open = None;
    }

    /// Handle a mouse event for the agent key list.
    fn handle_mouse_impl(&mut self, mouse: MouseEvent) -> Option<Action> {
        // Confirm modal open: delegate mouse clicks to its buttons.
        if self.action_modal == Some(ActionModal::Remove)
            || self.action_modal == Some(ActionModal::RemoveAll)
        {
            if let Some(result) = self.confirm.handle_mouse(&mouse) {
                return match result {
                    ConfirmResult::Confirmed => self.handle_key(KeyCode::Enter),
                    ConfirmResult::Cancelled => {
                        self.action_modal = None;
                        None
                    }
                };
            }
            return None;
        }
        // Form modal open: delegate mouse to form buttons.
        if self.action_modal.is_some() {
            if let Some(result) = self.form.handle_mouse(&mouse) {
                return match result {
                    FormResult::Submitted => self.handle_key(KeyCode::Enter),
                    FormResult::Cancelled => {
                        self.action_modal = None;
                        None
                    }
                    FormResult::Pending => None,
                };
            }
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
                if self.selected < self.keys.len().saturating_sub(1) {
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

impl Default for AgentTab {
    fn default() -> Self {
        Self::new()
    }
}

impl SshTab for AgentTab {
    #[expect(
        clippy::too_many_lines,
        reason = "keyboard dispatch table kept whole for clarity"
    )]
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
                ActionModal::Add => {
                    match self.form.handle_key(code) {
                        FormResult::Submitted => {
                            let path = self
                                .form
                                .text_value(0)
                                .map(std::string::ToString::to_string)
                                .unwrap_or_default();
                            let display_name = if path.is_empty() {
                                "unknown".to_string()
                            } else {
                                // Extract filename from path
                                std::path::Path::new(&path).file_name().map_or_else(
                                    || path.clone(),
                                    |f| f.to_string_lossy().to_string(),
                                )
                            };
                            // Persist to disk
                            if !path.is_empty() {
                                self.pending_ops
                                    .push(SshOp::AgentAddKey { path: path.clone() });
                            }
                            // Optimistic in-memory update
                            self.keys.push(AgentKeyEntry {
                                name: display_name,
                                key_type: "Unknown".into(),
                                fingerprint: String::new(),
                                is_locked: false,
                                has_constraints: false,
                            });
                            self.selected = self.keys.len() - 1;
                            self.clamp_scroll();
                            self.action_modal = None;
                        }
                        FormResult::Cancelled => {
                            self.action_modal = None;
                        }
                        FormResult::Pending => {}
                    }
                }
                ActionModal::Remove => {
                    match self.confirm.handle_key(code) {
                        Some(ConfirmResult::Confirmed) => {
                            if !self.keys.is_empty() {
                                let name = self.keys[self.selected].name.clone();
                                // Persist to disk — derive absolute key path
                                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
                                let path = format!("{home}/.ssh/{name}");
                                self.pending_ops.push(SshOp::AgentRemoveKey { path });
                                // Optimistic in-memory update
                                self.keys.remove(self.selected);
                                if self.selected >= self.keys.len() && !self.keys.is_empty() {
                                    self.selected = self.keys.len() - 1;
                                }
                                self.clamp_scroll();
                            }
                            self.action_modal = None;
                        }
                        Some(ConfirmResult::Cancelled) => self.action_modal = None,
                        None => {}
                    }
                }
                ActionModal::RemoveAll => {
                    match self.confirm.handle_key(code) {
                        Some(ConfirmResult::Confirmed) => {
                            self.pending_ops.push(SshOp::AgentRemoveAll);
                            // Optimistic in-memory update
                            self.keys.clear();
                            self.selected = 0;
                            self.scroll = 0;
                            self.action_modal = None;
                        }
                        Some(ConfirmResult::Cancelled) => self.action_modal = None,
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
                    if !self.keys.is_empty() && self.selected < self.keys.len() - 1 {
                        self.selected += 1;
                        self.clamp_scroll();
                    }
                    None
                }
                KeyCode::Enter => {
                    if !self.keys.is_empty() {
                        self.detail_open = Some(self.selected);
                    }
                    None
                }
                // CRUD shortcuts
                KeyCode::Char('a') => {
                    self.form = FormModal::new(40).text_field(
                        TextInput::new("Key Path", 40)
                            .placeholder("~/.ssh/id_ed25519")
                            .required(),
                    );
                    self.action_modal = Some(ActionModal::Add);
                    None
                }
                KeyCode::Char('d') => {
                    if !self.keys.is_empty() {
                        let name = self.keys[self.selected].name.clone();
                        self.confirm =
                            ConfirmModal::new(format!("Remove key \"{name}\" from agent?"));
                        self.action_modal = Some(ActionModal::Remove);
                    }
                    None
                }
                KeyCode::Char('D') => {
                    if !self.keys.is_empty() {
                        self.confirm = ConfirmModal::new("Remove all keys from SSH agent?");
                        self.action_modal = Some(ActionModal::RemoveAll);
                    }
                    None
                }
                _ => None,
            }
        }
    }

    fn view(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        self.row_hitboxes.clear();

        // Render status header + key list or empty state
        if !self.status.reachable || self.keys.is_empty() {
            self.render_empty(frame, area, p);
        } else {
            self.render_list(frame, area, p);
        }

        // Render detail modal if open
        if let Some(idx) = self.detail_open
            && let Some(key) = self.keys.get(idx).cloned()
        {
            self.render_detail_modal(frame, p, &key);
        }

        // Render action modal on top
        match self.action_modal {
            Some(ActionModal::Add) => {
                self.form.render_in_modal_with_hint(
                    frame,
                    p,
                    "Add Key to Agent",
                    52,
                    13,
                    "Enter key path, Esc to cancel",
                );
            }
            Some(ActionModal::Remove) => {
                self.confirm.render(frame, p, "Remove Key");
            }
            Some(ActionModal::RemoveAll) => {
                self.confirm.render(frame, p, "Remove All Keys");
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

// ── Rendering ────────────────────────────────────────────────────────────────

impl AgentTab {
    fn render_empty(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " SSH AGENT ", p.text, false);

        let msg = if self.status.reachable {
            Line::from(vec![
                Span::styled("Agent running, no keys loaded", Style::new().fg(p.text_dim)),
                Span::styled(
                    "  a",
                    Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" add", Style::new().fg(p.text_muted)),
            ])
        } else {
            Line::from(vec![Span::styled(
                "SSH agent not running",
                Style::new().fg(p.text_dim),
            )])
        };
        let centered = Rect::new(inner.x, inner.y + inner.height / 2, inner.width, 1);
        frame.render_widget(Paragraph::new(msg).centered(), centered);
    }

    #[expect(
        clippy::too_many_lines,
        reason = "render routine kept whole for clarity"
    )]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "terminal cols/rows are bounded < u16::MAX"
    )]
    fn render_list(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " SSH AGENT ", p.text, false);

        if inner.height == 0 {
            return;
        }

        // ── Status header (3 lines) ─────────────────────────────────────────
        let socket_display = self.status.socket_path.as_deref().unwrap_or("unknown");

        // Line 1: agent running status
        let status_line = if self.status.reachable {
            Line::from(vec![
                Span::styled("● ", Style::new().fg(p.ok)),
                Span::styled(
                    format!("Agent running at {socket_display}"),
                    Style::new().fg(p.text),
                ),
            ])
        } else {
            Line::from(vec![Span::styled(
                "○ Agent not running",
                Style::new().fg(p.err),
            )])
        };
        let line1_area = Rect::new(inner.x, inner.y, inner.width, 1);
        frame.render_widget(Paragraph::new(status_line), line1_area);

        // Line 2: key count — show both agent-reported count and displayed count
        let count_display = if self.keys.len() == self.status.key_count {
            format!("{} keys loaded", self.keys.len())
        } else {
            format!(
                "{} keys loaded ({} reported)",
                self.keys.len(),
                self.status.key_count
            )
        };
        let count_line = Line::from(vec![Span::styled(
            count_display,
            Style::new().fg(p.text_dim),
        )]);
        let line2_area = Rect::new(inner.x, inner.y + 1, inner.width, 1);
        frame.render_widget(Paragraph::new(count_line), line2_area);

        // Line 3: separator
        let separator = "─".repeat(inner.width as usize);
        let sep_line = Line::from(Span::styled(separator, Style::new().fg(p.text_dim)));
        let line3_area = Rect::new(inner.x, inner.y + 2, inner.width, 1);
        frame.render_widget(Paragraph::new(sep_line), line3_area);

        // ── Key list below header ───────────────────────────────────────────
        let header_height: u16 = 3;
        let list_y = inner.y + header_height;
        let list_height = inner.height.saturating_sub(header_height);

        if list_height == 0 {
            self.render_footer(frame, area, p);
            return;
        }

        let visible = list_height as usize;
        let max_scroll = self.keys.len().saturating_sub(visible);
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
            if idx >= self.keys.len() {
                break;
            }
            let key = &self.keys[idx];
            let is_selected = idx == self.selected;
            let is_hovered = self.hovered_row == Some(idx);
            let y = list_y + row as u16;
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

            // Icon — accent when selected or hovered.
            spans.push(Span::styled(
                "◆ ",
                Style::new().fg(if is_selected || is_hovered {
                    p.accent
                } else {
                    p.text_dim
                }),
            ));

            // Key name (truncated to fit)
            let name_w = 18.min(inner.width.saturating_sub(4) as usize);
            let name = truncate_str(&key.name, name_w);
            let name_chars = name.chars().count();
            spans.push(Span::styled(
                name,
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ));

            // Padding
            let padded = format!("{:width$}", "", width = name_w.saturating_sub(name_chars));
            spans.push(Span::raw(padded));

            // Key type
            spans.push(Span::styled(
                format!(" {} ", key.key_type),
                Style::new().fg(p.info),
            ));

            // Fingerprint (truncated)
            let fp_w = 16.min(inner.width.saturating_sub(40) as usize);
            let fp = truncate_str(&key.fingerprint, fp_w);
            spans.push(Span::styled(fp, Style::new().fg(p.text_dim)));

            // Locked badge
            if key.is_locked {
                spans.push(Span::styled(" 🔒", Style::new().fg(p.warn)));
            }

            // Constraints badge
            if key.has_constraints {
                spans.push(Span::styled(" const", Style::new().fg(p.text_muted)));
            }

            let line = Line::from(spans);
            frame.render_widget(Paragraph::new(line), row_area);
        }

        // Footer with action hints
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
    fn render_detail_modal(&mut self, frame: &mut Frame, p: Palette, key: &AgentKeyEntry) {
        let modal = Modal::new("Agent Key Detail").dimensions(54, 10);
        self.detail_modal_rect = Some(modal.rect(frame.area()));
        modal.render(frame, p, |frame, content_area| {
            let lines = vec![
                Line::from(vec![
                    Span::styled("Name:        ", Style::new().fg(p.text_dim)),
                    Span::styled(&key.name, Style::new().fg(p.text).bold()),
                ]),
                Line::from(vec![
                    Span::styled("Type:        ", Style::new().fg(p.text_dim)),
                    Span::styled(&key.key_type, Style::new().fg(p.info)),
                ]),
                Line::from(vec![
                    Span::styled("FP:          ", Style::new().fg(p.text_dim)),
                    Span::styled(&key.fingerprint, Style::new().fg(p.text)),
                ]),
                Line::from(vec![
                    Span::styled("Locked:      ", Style::new().fg(p.text_dim)),
                    Span::styled(
                        if key.is_locked { "yes" } else { "no" },
                        Style::new().fg(if key.is_locked { p.warn } else { p.ok }),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Constraints: ", Style::new().fg(p.text_dim)),
                    Span::styled(
                        if key.has_constraints {
                            "various"
                        } else {
                            "none"
                        },
                        Style::new().fg(if key.has_constraints {
                            p.text
                        } else {
                            p.text_muted
                        }),
                    ),
                ]),
                Line::raw(""),
                Line::from(Span::styled(
                    "Press Esc to close",
                    Style::new().fg(p.text_muted),
                )),
            ];

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

// ── Helpers ──────────────────────────────────────────────────────────────────
// (truncate_str is imported from crate::ui::responsive)

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_status() -> AgentStatus {
        AgentStatus {
            reachable: true,
            socket_path: Some("/tmp/ssh-agent.sock".into()),
            key_count: 2,
        }
    }

    fn sample_keys() -> Vec<AgentKeyEntry> {
        vec![
            AgentKeyEntry {
                name: "id_ed25519".into(),
                key_type: "Ed25519".into(),
                fingerprint: "SHA256:abc123def456".into(),
                is_locked: false,
                has_constraints: false,
            },
            AgentKeyEntry {
                name: "id_rsa".into(),
                key_type: "RSA 4096".into(),
                fingerprint: "SHA256:xyz789".into(),
                is_locked: true,
                has_constraints: true,
            },
        ]
    }

    #[test]
    fn new_is_empty() {
        let tab = AgentTab::new();
        assert!(tab.keys.is_empty());
        assert!(!tab.status.reachable);
        assert!(!tab.has_modal());
    }

    #[test]
    fn set_data_updates_list() {
        let mut tab = AgentTab::new();
        tab.set_data(sample_status(), sample_keys());
        assert_eq!(tab.keys.len(), 2);
        assert!(tab.status.reachable);
    }

    #[test]
    fn scroll_up_decrements_selected() {
        let mut tab = AgentTab::new();
        tab.set_data(sample_status(), sample_keys());
        tab.selected = 1;
        tab.handle_key(KeyCode::Up);
        assert_eq!(tab.selected, 0);
    }

    #[test]
    fn scroll_down_increments_selected() {
        let mut tab = AgentTab::new();
        tab.set_data(sample_status(), sample_keys());
        tab.selected = 0;
        tab.handle_key(KeyCode::Down);
        assert_eq!(tab.selected, 1);
    }

    #[test]
    fn scroll_up_at_zero_stays() {
        let mut tab = AgentTab::new();
        tab.set_data(sample_status(), sample_keys());
        tab.selected = 0;
        tab.handle_key(KeyCode::Up);
        assert_eq!(tab.selected, 0);
    }

    #[test]
    fn scroll_down_at_end_stays() {
        let mut tab = AgentTab::new();
        tab.set_data(sample_status(), sample_keys());
        tab.selected = 1;
        tab.handle_key(KeyCode::Down);
        assert_eq!(tab.selected, 1);
    }

    #[test]
    fn enter_opens_detail_modal() {
        let mut tab = AgentTab::new();
        tab.set_data(sample_status(), sample_keys());
        tab.handle_key(KeyCode::Enter);
        assert!(tab.has_modal());
        assert_eq!(tab.detail_open, Some(0));
    }

    #[test]
    fn esc_closes_detail_modal() {
        let mut tab = AgentTab::new();
        tab.set_data(sample_status(), sample_keys());
        tab.detail_open = Some(0);
        tab.handle_key(KeyCode::Esc);
        assert!(!tab.has_modal());
    }

    #[test]
    fn render_empty_state_not_running() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = AgentTab::new();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("SSH agent not running"),
            "empty state: {output}"
        );
    }

    #[test]
    fn render_empty_state_no_keys() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = AgentTab::new();
        tab.set_data(
            AgentStatus {
                reachable: true,
                socket_path: Some("/tmp/agent.sock".into()),
                key_count: 0,
            },
            vec![],
        );
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains("no keys loaded"), "empty state: {output}");
    }

    #[test]
    fn render_with_keys() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = AgentTab::new();
        tab.set_data(sample_status(), sample_keys());
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains("id_ed25519"), "key name: {output}");
        assert!(output.contains("Ed25519"), "key type: {output}");
    }

    #[test]
    fn render_detail_modal() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = AgentTab::new();
        tab.set_data(sample_status(), sample_keys());
        tab.detail_open = Some(0);
        let mut terminal = Terminal::new(TestBackend::new(80, 30)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains("Agent Key Detail"), "modal title: {output}");
        assert!(output.contains("Ed25519"), "key type in modal: {output}");
    }

    #[test]
    fn render_status_header() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = AgentTab::new();
        tab.set_data(sample_status(), sample_keys());
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains("Agent running"), "status header: {output}");
        assert!(
            output.contains("/tmp/ssh-agent.sock"),
            "socket path: {output}"
        );
        assert!(output.contains("keys loaded"), "key count: {output}");
    }

    #[test]
    fn set_data_clamps_selected() {
        let mut tab = AgentTab::new();
        tab.selected = 5;
        tab.set_data(sample_status(), sample_keys()); // 2 items
        assert!(tab.selected < 2);
    }
}
