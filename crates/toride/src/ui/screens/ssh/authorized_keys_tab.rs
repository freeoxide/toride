//! Authorized Keys sub-tab for the SSH management screen.
//!
//! Displays entries from `~/.ssh/authorized_keys` as a scrollable list with key
//! type, fingerprint, comment, options badge, and line number. Supports keyboard
//! navigation, selection, and a detail modal.

use crossterm::event::{KeyCode, MouseEvent, MouseEventKind};
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
    ConfirmModal, ConfirmResult, FormModal, FormResult, InteractiveModal, ModalEvent, TextInput,
    render_titled_panel,
};

use super::{AuthorizedKeyEntry, SshTab, char_to_keycode};

// ── ActionModal ───────────────────────────────────────────────────────────────

/// Which action modal is currently open (if any).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActionModal {
    /// Add authorized key form.
    Add,
    /// Remove authorized key confirmation.
    Remove,
}

// ── AuthorizedKeysTab ─────────────────────────────────────────────────────────

/// State for the Authorized Keys sub-tab.
pub struct AuthorizedKeysTab {
    /// Key entries to display.
    entries: Vec<AuthorizedKeyEntry>,
    /// Index of the currently selected entry.
    selected: usize,
    /// Vertical scroll offset.
    scroll: usize,
    /// Which entry index is shown in the detail modal (if open).
    detail_entry_idx: Option<usize>,
    /// Interactive detail modal (manages visibility + rect + click-outside).
    detail_modal: InteractiveModal<Action>,
    /// Hitbox rects for list rows (rebuilt each frame).
    row_hitboxes: Vec<Rect>,
    /// Which row is hovered by the mouse.
    hovered_row: Option<usize>,
    /// Interactive footer shortcut buttons.
    buttons: ButtonRow<char>,
    /// Which action modal is open (if any).
    action_modal: Option<ActionModal>,
    /// Form modal for add operation.
    form: FormModal,
    /// Confirm modal for remove operation.
    confirm: ConfirmModal,
    /// Pending write operations to be forwarded to `SshContent`.
    pending_ops: Vec<SshOp>,
}

impl AuthorizedKeysTab {
    /// Create a new empty authorized keys tab.
    #[must_use]
    pub fn new() -> Self {
        let buttons = ButtonRow::new(
            vec![
                InteractiveButton::new("↵ detail", "↵", '\r'),
                InteractiveButton::new("a add", "a", 'a'),
                InteractiveButton::new("d remove", "d", 'd'),
            ],
            vec![1, 1, 1],
        );
        Self {
            entries: Vec::new(),
            selected: 0,
            scroll: 0,
            detail_entry_idx: None,
            detail_modal: InteractiveModal::display("Authorized Key Detail").dimensions(54, 12),
            row_hitboxes: Vec::new(),
            hovered_row: None,
            buttons,
            action_modal: None,
            form: FormModal::new(40),
            confirm: ConfirmModal::new(""),
            pending_ops: Vec::new(),
        }
    }

    /// Replace the entry list with new data.
    pub fn set_entries(&mut self, entries: Vec<AuthorizedKeyEntry>) {
        self.entries = entries;
        if self.selected >= self.entries.len() && !self.entries.is_empty() {
            self.selected = self.entries.len() - 1;
        }
        self.clamp_scroll();
    }

    /// Whether a modal is currently open.
    #[must_use]
    pub fn has_modal(&self) -> bool {
        self.detail_modal.is_visible() || self.action_modal.is_some()
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

    /// Handle a mouse event for the authorized keys list.
    fn handle_mouse_impl(&mut self, mouse: MouseEvent) -> Option<Action> {
        // Confirm modal open: delegate mouse clicks to its buttons.
        if self.action_modal == Some(ActionModal::Remove) {
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
        if self.action_modal.is_some() && self.action_modal != Some(ActionModal::Remove) {
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

        // Detail modal open: delegate to InteractiveModal for click-outside.
        if self.detail_modal.is_visible() {
            if let ModalEvent::Closed = self.detail_modal.handle_mouse(&mouse) {
                self.detail_entry_idx = None;
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
            MouseEventKind::Down(crossterm::event::MouseButton::Left) => {
                if let Some(idx) = self.row_at(mouse.column, mouse.row) {
                    self.selected = idx;
                    self.detail_entry_idx = Some(idx);
                    self.detail_modal.open();
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

impl Default for AuthorizedKeysTab {
    fn default() -> Self {
        Self::new()
    }
}

impl SshTab for AuthorizedKeysTab {
    #[expect(
        clippy::too_many_lines,
        reason = "keyboard dispatch table kept whole for clarity"
    )]
    fn handle_key(&mut self, code: KeyCode) -> Option<Action> {
        // If detail modal is open, delegate to InteractiveModal.
        if self.detail_modal.is_visible() {
            match self.detail_modal.handle_key(code) {
                ModalEvent::Closed => self.detail_entry_idx = None,
                ModalEvent::Consumed | ModalEvent::Button(_) => {}
            }
            return None;
        }

        // If an action modal is open, delegate to it.
        if let Some(action) = self.action_modal {
            match action {
                ActionModal::Add => {
                    match self.form.handle_key(code) {
                        FormResult::Submitted => {
                            let key_string = self
                                .form
                                .text_value(0)
                                .map(std::string::ToString::to_string)
                                .unwrap_or_default();
                            if key_string.is_empty() {
                                self.action_modal = None;
                                return None;
                            }
                            // Parse the pasted key: "key-type base64-data [comment]"
                            let parts: Vec<&str> = key_string.splitn(3, ' ').collect();
                            let key_type = parts.first().copied().unwrap_or("unknown");
                            let base64_key = parts.get(1).copied().unwrap_or("");
                            let comment = parts.get(2).map(std::string::ToString::to_string);
                            // Compute fingerprint for Remove support
                            let openssh_line = if parts.len() >= 2 {
                                format!("{key_type} {base64_key}")
                            } else {
                                key_string.clone()
                            };
                            let fingerprint = ssh_key::PublicKey::from_openssh(&openssh_line)
                                .ok()
                                .map(|pk| pk.fingerprint(ssh_key::HashAlg::Sha256).to_string())
                                .unwrap_or_default();
                            // Persist to disk
                            self.pending_ops.push(SshOp::AuthorizedKeyAdd {
                                public_key: key_string.clone(),
                                comment: comment.clone(),
                                options: None,
                            });
                            // Optimistic in-memory update
                            self.entries.push(AuthorizedKeyEntry {
                                key_type: key_type.to_string(),
                                public_key: base64_key.to_string(),
                                comment,
                                fingerprint,
                                options: None,
                                line: self.entries.len() + 1,
                            });
                            self.selected = self.entries.len() - 1;
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
                            if !self.entries.is_empty() {
                                let fingerprint = self.entries[self.selected].fingerprint.clone();
                                // Persist to disk
                                if !fingerprint.is_empty() {
                                    self.pending_ops
                                        .push(SshOp::AuthorizedKeyRemove { fingerprint });
                                }
                                // Optimistic in-memory update
                                self.entries.remove(self.selected);
                                if self.selected >= self.entries.len() && !self.entries.is_empty() {
                                    self.selected = self.entries.len() - 1;
                                }
                                self.clamp_scroll();
                            }
                            self.action_modal = None;
                        }
                        Some(ConfirmResult::Cancelled) => self.action_modal = None,
                        None => {}
                    }
                }
            }
            return None;
        }

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
                    self.detail_entry_idx = Some(self.selected);
                    self.detail_modal.open();
                }
                None
            }
            // CRUD shortcuts
            KeyCode::Char('a') => {
                self.form = FormModal::new(40).text_field(
                    TextInput::new("Key", 40)
                        .placeholder("ssh-ed25519 AAAA... user@host")
                        .required(),
                );
                self.action_modal = Some(ActionModal::Add);
                None
            }
            KeyCode::Char('d') => {
                if !self.entries.is_empty() {
                    let label = self.entries[self.selected]
                        .comment
                        .as_deref()
                        .unwrap_or(&self.entries[self.selected].public_key);
                    let display_label = if label.chars().count() > 30 {
                        let truncated: String = label.chars().take(27).collect();
                        format!("{truncated}...")
                    } else {
                        label.to_string()
                    };
                    self.confirm = ConfirmModal::new(format!("Remove key \"{display_label}\"?"));
                    self.action_modal = Some(ActionModal::Remove);
                }
                None
            }
            _ => None,
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
        if let Some(idx) = self.detail_entry_idx
            && let Some(entry) = self.entries.get(idx).cloned()
        {
            self.render_detail_modal(frame, p, &entry);
        }

        // Render action modal on top
        match self.action_modal {
            Some(ActionModal::Add) => {
                self.form.render_in_modal_with_hint(
                    frame,
                    p,
                    "Add Authorized Key",
                    56,
                    13,
                    "Paste public key string, Esc to cancel",
                );
            }
            Some(ActionModal::Remove) => {
                self.confirm.render(frame, p, "Remove Key");
            }
            None => {}
        }
    }

    fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action> {
        self.handle_mouse_impl(mouse)
    }

    fn has_modal(&self) -> bool {
        self.detail_modal.is_visible() || self.action_modal.is_some()
    }

    fn close_modal(&mut self) {
        self.detail_modal.close();
        self.detail_entry_idx = None;
        self.action_modal = None;
    }

    fn drain_ops(&mut self) -> Vec<SshOp> {
        std::mem::take(&mut self.pending_ops)
    }
}

// ── Rendering ────────────────────────────────────────────────────────────────

impl AuthorizedKeysTab {
    fn render_empty(frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " AUTHORIZED KEYS ", p.text, false);
        let msg = Line::from(vec![
            Span::styled("No authorized keys found", Style::new().fg(p.text_dim)),
            Span::styled(
                "  a",
                Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" add", Style::new().fg(p.text_muted)),
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
            &format!(" AUTHORIZED KEYS ({}) ", self.entries.len()),
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

            // Icon — accent when selected or hovered.
            spans.push(Span::styled(
                "◆ ",
                Style::new().fg(if is_selected || is_hovered {
                    p.accent
                } else {
                    p.text_dim
                }),
            ));

            // Comment or truncated public key (20 chars bold)
            let label_text = entry.comment.as_deref().unwrap_or(&entry.public_key);
            let label_w = 20.min(inner.width.saturating_sub(4) as usize);
            let label = truncate_str(label_text, label_w);
            let label_chars = label.chars().count();
            spans.push(Span::styled(
                label,
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ));

            // Padding
            let padded = format!("{:width$}", "", width = label_w.saturating_sub(label_chars));
            spans.push(Span::raw(padded));

            // Key type
            spans.push(Span::styled(
                format!(" {} ", entry.key_type),
                Style::new().fg(p.info),
            ));

            // Fingerprint (truncated to 16 chars)
            let fp_w = 16.min(inner.width.saturating_sub(40) as usize);
            let fp = truncate_str(&entry.fingerprint, fp_w);
            spans.push(Span::styled(fp, Style::new().fg(p.text_dim)));

            // Options badge
            if entry.options.is_some() {
                spans.push(Span::styled(" 🔒opts", Style::new().fg(p.warn)));
            }

            // Line number badge
            spans.push(Span::styled(
                format!(" L:{}", entry.line),
                Style::new().fg(p.text_muted),
            ));

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
    fn render_detail_modal(&mut self, frame: &mut Frame, p: Palette, entry: &AuthorizedKeyEntry) {
        self.detail_modal.render(frame, p, |frame, content_area| {
            let key_display = truncate_str(
                &entry.public_key,
                content_area.width.saturating_sub(6) as usize,
            );
            let lines = vec![
                Line::from(vec![
                    Span::styled("Type:    ", Style::new().fg(p.text_dim)),
                    Span::styled(&entry.key_type, Style::new().fg(p.info)),
                ]),
                Line::from(vec![
                    Span::styled("Comment: ", Style::new().fg(p.text_dim)),
                    Span::styled(
                        entry.comment.as_deref().unwrap_or("—"),
                        Style::new().fg(p.text),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("FP:      ", Style::new().fg(p.text_dim)),
                    Span::styled(&entry.fingerprint, Style::new().fg(p.text)),
                ]),
                Line::from(vec![
                    Span::styled("Options: ", Style::new().fg(p.text_dim)),
                    Span::styled(
                        entry.options.as_deref().unwrap_or("none"),
                        Style::new().fg(if entry.options.is_some() {
                            p.warn
                        } else {
                            p.text_muted
                        }),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Line:    ", Style::new().fg(p.text_dim)),
                    Span::styled(format!("{}", entry.line), Style::new().fg(p.text)),
                ]),
                Line::from(vec![
                    Span::styled("Key:     ", Style::new().fg(p.text_dim)),
                    Span::styled(key_display, Style::new().fg(p.text_dim)),
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

    fn sample_entries() -> Vec<AuthorizedKeyEntry> {
        vec![
            AuthorizedKeyEntry {
                key_type: "ssh-ed25519".into(),
                public_key: "AAAAC3NzaC1lZDI1NTE5AAAAI1234567890abcdef".into(),
                comment: Some("user@host".into()),
                fingerprint: "SHA256:abc123def456".into(),
                options: Some("command=\"sync\",no-port-forwarding".into()),
                line: 1,
            },
            AuthorizedKeyEntry {
                key_type: "ssh-rsa".into(),
                public_key: "AAAAB3NzaC1yc2EAAAADAQABAAABgQC...longkey".into(),
                comment: None,
                fingerprint: "SHA256:xyz789".into(),
                options: None,
                line: 5,
            },
        ]
    }

    #[test]
    fn new_is_empty() {
        let tab = AuthorizedKeysTab::new();
        assert!(tab.entries.is_empty());
        assert!(!tab.has_modal());
    }

    #[test]
    fn set_entries_updates_list() {
        let mut tab = AuthorizedKeysTab::new();
        tab.set_entries(sample_entries());
        assert_eq!(tab.entries.len(), 2);
    }

    #[test]
    fn scroll_up_decrements_selected() {
        let mut tab = AuthorizedKeysTab::new();
        tab.set_entries(sample_entries());
        tab.selected = 1;
        tab.handle_key(KeyCode::Up);
        assert_eq!(tab.selected, 0);
    }

    #[test]
    fn scroll_down_increments_selected() {
        let mut tab = AuthorizedKeysTab::new();
        tab.set_entries(sample_entries());
        tab.selected = 0;
        tab.handle_key(KeyCode::Down);
        assert_eq!(tab.selected, 1);
    }

    #[test]
    fn scroll_up_at_zero_stays() {
        let mut tab = AuthorizedKeysTab::new();
        tab.set_entries(sample_entries());
        tab.selected = 0;
        tab.handle_key(KeyCode::Up);
        assert_eq!(tab.selected, 0);
    }

    #[test]
    fn scroll_down_at_end_stays() {
        let mut tab = AuthorizedKeysTab::new();
        tab.set_entries(sample_entries());
        tab.selected = 1;
        tab.handle_key(KeyCode::Down);
        assert_eq!(tab.selected, 1);
    }

    #[test]
    fn enter_opens_detail_modal() {
        let mut tab = AuthorizedKeysTab::new();
        tab.set_entries(sample_entries());
        tab.handle_key(KeyCode::Enter);
        assert!(tab.has_modal());
        assert_eq!(tab.detail_entry_idx, Some(0));
    }

    #[test]
    fn esc_closes_detail_modal() {
        let mut tab = AuthorizedKeysTab::new();
        tab.set_entries(sample_entries());
        tab.detail_entry_idx = Some(0);
        tab.detail_modal.open();
        tab.handle_key(KeyCode::Esc);
        assert!(!tab.has_modal());
    }

    #[test]
    fn render_empty_state() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = AuthorizedKeysTab::new();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("No authorized keys found"),
            "empty state: {output}"
        );
    }

    #[test]
    fn render_with_entries() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = AuthorizedKeysTab::new();
        tab.set_entries(sample_entries());
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains("user@host"), "comment: {output}");
        assert!(output.contains("ssh-ed25519"), "key type: {output}");
    }

    #[test]
    fn render_detail_modal() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = AuthorizedKeysTab::new();
        tab.set_entries(sample_entries());
        tab.detail_entry_idx = Some(0);
        tab.detail_modal.open();
        let mut terminal = Terminal::new(TestBackend::new(80, 30)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("Authorized Key Detail"),
            "modal title: {output}"
        );
        assert!(
            output.contains("ssh-ed25519"),
            "key type in modal: {output}"
        );
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
        // responsive::truncate_str reserves 2 chars for ".." suffix
        assert_eq!(truncate_str("abcdefgh", 5), "abc..");
    }

    #[test]
    fn truncate_str_zero() {
        assert_eq!(truncate_str("abc", 0), "");
    }

    #[test]
    fn set_entries_clamps_selected() {
        let mut tab = AuthorizedKeysTab::new();
        tab.selected = 5;
        tab.set_entries(sample_entries()); // 2 items
        assert!(tab.selected < 2);
    }
}
