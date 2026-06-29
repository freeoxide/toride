//! Keys sub-tab for the SSH management screen.
//!
//! Displays all SSH keys found in `~/.ssh/` as a scrollable list with type,
//! fingerprint, encryption status, permissions, and badge indicators. Supports
//! keyboard navigation, selection, and a detail modal.

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
    ConfirmModal, ConfirmResult, Dropdown, FormModal, FormResult, InteractiveModal, Modal,
    ModalEvent, TextInput, render_titled_panel,
};

use super::{SshKeyEntry, SshTab, char_to_keycode};

// ── ActionModal ──────────────────────────────────────────────────────────────

/// Which action modal is currently open (if any).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActionModal {
    /// Generate new key form.
    New,
    /// Delete confirmation.
    Delete,
    /// Rename key form.
    Rename,
    /// Test passphrase form.
    TestPassphrase,
    /// Install public key to remote host form.
    Install,
}

// ── KeysTab ──────────────────────────────────────────────────────────────────

/// State for the Keys sub-tab.
pub struct KeysTab {
    /// Key entries to display.
    keys: Vec<SshKeyEntry>,
    /// Index of the currently selected key.
    selected: usize,
    /// Vertical scroll offset.
    scroll: usize,
    /// Which key index is shown in the detail modal (if open).
    detail_key_idx: Option<usize>,
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
    /// Form modal for new key / rename / passphrase test operations.
    form: FormModal,
    /// Confirm modal for delete operations.
    confirm: ConfirmModal,
    /// Pending write operations to be forwarded to `SshContent`.
    pending_ops: Vec<SshOp>,
    /// Key name being tested for passphrase (set when `TestPassphrase` modal opens).
    test_passphrase_key: Option<String>,
    /// Result of the last passphrase test: Ok(label) or Err(msg).
    passphrase_test_result: Option<Result<String, String>>,
    /// Reference instant for spinner animation (keys still generating).
    anim_start: std::time::Instant,
    /// Key name for the install-to-remote operation (set when Install modal opens).
    install_key_name: Option<String>,
}

impl KeysTab {
    /// Create a new empty keys tab.
    #[must_use]
    pub fn new() -> Self {
        let buttons = ButtonRow::new(
            vec![
                InteractiveButton::new("↵ detail", "↵", '\r'),
                InteractiveButton::new("n new", "n", 'n'),
                InteractiveButton::new("d del", "d", 'd'),
                InteractiveButton::new("r rename", "r", 'r'),
                InteractiveButton::new("p passphrase", "p", 'p'),
                InteractiveButton::new("i install", "i", 'i'),
                InteractiveButton::new("x chmod", "x", 'x'),
            ],
            vec![1, 1, 1, 1, 1, 1, 1],
        );
        Self {
            keys: Vec::new(),
            selected: 0,
            scroll: 0,
            detail_key_idx: None,
            detail_modal: InteractiveModal::display("Key Detail").dimensions(54, 16),
            row_hitboxes: Vec::new(),
            hovered_row: None,
            buttons,
            action_modal: None,
            form: FormModal::new(40),
            confirm: ConfirmModal::new(""),
            pending_ops: Vec::new(),
            test_passphrase_key: None,
            passphrase_test_result: None,
            anim_start: std::time::Instant::now(),
            install_key_name: None,
        }
    }

    /// Replace the key list with new data.
    pub fn set_keys(&mut self, keys: Vec<SshKeyEntry>) {
        self.keys = keys;
        if self.selected >= self.keys.len() && !self.keys.is_empty() {
            self.selected = self.keys.len() - 1;
        }
        self.clamp_scroll();
    }

    /// Whether a modal is currently open.
    #[must_use]
    pub fn has_modal(&self) -> bool {
        self.detail_modal.is_visible()
            || self.action_modal.is_some()
            || self.passphrase_test_result.is_some()
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

    /// Handle a mouse event for the key list.
    fn handle_mouse_impl(&mut self, mouse: MouseEvent) -> Option<Action> {
        // Passphrase test result banner: click anywhere to dismiss.
        if self.passphrase_test_result.is_some() {
            self.passphrase_test_result = None;
            return None;
        }

        // Confirm modal open: delegate mouse clicks to its buttons.
        if self.action_modal == Some(ActionModal::Delete) {
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
        if self.action_modal.is_some() && self.action_modal != Some(ActionModal::Delete) {
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
                self.detail_key_idx = None;
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
                    self.detail_key_idx = Some(idx);
                    self.detail_modal.open();
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

impl Default for KeysTab {
    fn default() -> Self {
        Self::new()
    }
}

impl SshTab for KeysTab {
    #[expect(
        clippy::too_many_lines,
        reason = "keyboard dispatch table kept whole for clarity"
    )]
    fn handle_key(&mut self, code: KeyCode) -> Option<Action> {
        // If detail modal is open, delegate to InteractiveModal.
        if self.detail_modal.is_visible() {
            match self.detail_modal.handle_key(code) {
                ModalEvent::Closed => self.detail_key_idx = None,
                ModalEvent::Consumed | ModalEvent::Button(_) => {}
            }
            return None;
        }

        // If passphrase test result banner is showing, dismiss on any key.
        if self.passphrase_test_result.is_some() {
            self.passphrase_test_result = None;
            return None;
        }

        // If an action modal is open, delegate to it.
        if let Some(action) = self.action_modal {
            match action {
                ActionModal::New => {
                    match self.form.handle_key(code) {
                        FormResult::Submitted => {
                            let name = self
                                .form
                                .text_value(0)
                                .map(std::string::ToString::to_string)
                                .unwrap_or_default();
                            let key_type = self.form.select_value(1).unwrap_or("Ed25519");
                            let comment = self
                                .form
                                .text_value(2)
                                .map(std::string::ToString::to_string)
                                .unwrap_or_default();
                            let passphrase = self.form.text_value(3).and_then(|s| {
                                if s.is_empty() {
                                    None
                                } else {
                                    Some(s.to_string())
                                }
                            });
                            let has_passphrase = passphrase.is_some();
                            let display_name = if name.is_empty() {
                                "id_new".to_string()
                            } else if name.starts_with("id_") {
                                name.clone()
                            } else {
                                format!("id_{name}")
                            };
                            // Persist to disk
                            self.pending_ops.push(SshOp::KeyCreate {
                                name: display_name.clone(),
                                key_type: key_type.to_string(),
                                comment,
                                passphrase,
                            });
                            // Optimistic in-memory update
                            self.keys.push(SshKeyEntry {
                                name: display_name,
                                key_type: key_type.to_string(),
                                fingerprint: String::new(),
                                encrypted: has_passphrase,
                                permissions: "0600".into(),
                                has_public: false,
                                has_cert: false,
                                used_by_hosts: vec![],
                            });
                            // Select the newly added key
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
                ActionModal::Delete => {
                    match self.confirm.handle_key(code) {
                        Some(ConfirmResult::Confirmed) => {
                            if !self.keys.is_empty() {
                                let name = self.keys[self.selected].name.clone();
                                // Persist to disk
                                self.pending_ops.push(SshOp::KeyDelete { name });
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
                ActionModal::Rename => {
                    match self.form.handle_key(code) {
                        FormResult::Submitted => {
                            if let Some(key) = self.keys.get_mut(self.selected) {
                                let old_name = key.name.clone();
                                let raw_name = self
                                    .form
                                    .text_value(0)
                                    .map(std::string::ToString::to_string)
                                    .unwrap_or_default();
                                let new_name = if raw_name.starts_with("id_") {
                                    raw_name
                                } else {
                                    format!("id_{raw_name}")
                                };
                                if !new_name.is_empty() && new_name != old_name {
                                    // Persist to disk
                                    self.pending_ops.push(SshOp::KeyRename {
                                        old_name,
                                        new_name: new_name.clone(),
                                    });
                                    // Optimistic in-memory update
                                    key.name = new_name;
                                }
                            }
                            self.action_modal = None;
                        }
                        FormResult::Cancelled => {
                            self.action_modal = None;
                        }
                        FormResult::Pending => {}
                    }
                }
                ActionModal::TestPassphrase => {
                    match self.form.handle_key(code) {
                        FormResult::Submitted => {
                            let passphrase = self
                                .form
                                .text_value(0)
                                .map(std::string::ToString::to_string)
                                .unwrap_or_default();
                            if let Some(name) = self.test_passphrase_key.take() {
                                self.pending_ops.push(SshOp::KeyTestPassphrase {
                                    name: name.clone(),
                                    passphrase,
                                });
                                // Show a pending result that will be replaced by the async pipeline
                                self.passphrase_test_result =
                                    Some(Ok(format!("testing '{name}'...")));
                            }
                            self.action_modal = None;
                        }
                        FormResult::Cancelled => {
                            self.action_modal = None;
                            self.test_passphrase_key = None;
                        }
                        FormResult::Pending => {}
                    }
                }
                ActionModal::Install => match self.form.handle_key(code) {
                    FormResult::Submitted => {
                        let key_name = self.install_key_name.take().unwrap_or_default();
                        let dest = self
                            .form
                            .text_value(1)
                            .map(std::string::ToString::to_string)
                            .unwrap_or_default();
                        if !key_name.is_empty() && !dest.is_empty() {
                            self.pending_ops
                                .push(SshOp::KeyInstallToRemote { key_name, dest });
                        }
                        self.action_modal = None;
                    }
                    FormResult::Cancelled => {
                        self.install_key_name = None;
                        self.action_modal = None;
                    }
                    FormResult::Pending => {}
                },
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
                if !self.keys.is_empty() && self.selected < self.keys.len() - 1 {
                    self.selected += 1;
                    self.clamp_scroll();
                }
                None
            }
            KeyCode::Enter => {
                if !self.keys.is_empty() {
                    self.detail_key_idx = Some(self.selected);
                    self.detail_modal.open();
                }
                None
            }
            // CRUD shortcuts
            KeyCode::Char('n') => {
                self.form = FormModal::new(40)
                    .text_field(
                        TextInput::new("Name", 30)
                            .placeholder("id_ed25519")
                            .required(),
                    )
                    .select_field(Dropdown::new(
                        "Type",
                        vec!["Ed25519", "RSA 4096", "ECDSA P-256"],
                        16,
                    ))
                    .text_field(TextInput::new("Comment", 30).placeholder("user@host"))
                    .text_field(
                        TextInput::new("Passphrase", 30)
                            .placeholder("(optional, leave empty for none)")
                            .secret(true),
                    );
                self.action_modal = Some(ActionModal::New);
                None
            }
            KeyCode::Char('d') => {
                if !self.keys.is_empty() {
                    let name = self.keys[self.selected].name.clone();
                    self.confirm = ConfirmModal::new(format!("Delete key \"{name}\"?"));
                    self.action_modal = Some(ActionModal::Delete);
                }
                None
            }
            KeyCode::Char('r') => {
                if !self.keys.is_empty() {
                    let current_name = self.keys[self.selected].name.clone();
                    self.form = FormModal::new(40).text_field(
                        TextInput::new("New Name", 30)
                            .value(&current_name)
                            .required(),
                    );
                    self.action_modal = Some(ActionModal::Rename);
                }
                None
            }
            KeyCode::Char('p') => {
                if !self.keys.is_empty() {
                    let name = self.keys[self.selected].name.clone();
                    self.form = FormModal::new(40).text_field(
                        TextInput::new("Passphrase", 30)
                            .placeholder("enter passphrase to test")
                            .secret(true),
                    );
                    self.test_passphrase_key = Some(name);
                    self.action_modal = Some(ActionModal::TestPassphrase);
                }
                None
            }
            KeyCode::Char('i') => {
                if !self.keys.is_empty()
                    && self.action_modal.is_none()
                    && !self.detail_modal.is_visible()
                {
                    let key_name = self.keys[self.selected].name.clone();
                    self.form = FormModal::new(40)
                        .text_field(TextInput::new("Key", 40).placeholder("current key name"))
                        .text_field(
                            TextInput::new("Destination (user@host)", 40)
                                .placeholder("user@host")
                                .required(),
                        );
                    self.install_key_name = Some(key_name);
                    self.action_modal = Some(ActionModal::Install);
                }
                None
            }
            KeyCode::Char('x') => {
                if !self.keys.is_empty()
                    && self.action_modal.is_none()
                    && !self.detail_modal.is_visible()
                {
                    let name = self.keys[self.selected].name.clone();
                    self.pending_ops.push(SshOp::KeyChmodFix { name });
                    self.keys[self.selected].permissions = "0600".into();
                }
                None
            }
            _ => None,
        }
    }

    fn view(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        self.row_hitboxes.clear();
        if self.keys.is_empty() {
            Self::render_empty(frame, area, p);
        } else {
            self.render_list(frame, area, p);
        }

        // Render detail modal if open
        if let Some(idx) = self.detail_key_idx
            && let Some(key) = self.keys.get(idx).cloned()
        {
            self.render_detail_modal(frame, p, &key);
        }

        // Render action modal on top of everything
        match self.action_modal {
            Some(ActionModal::New) => {
                self.form.render_in_modal_with_hint(
                    frame,
                    p,
                    "Generate New Key",
                    52,
                    22,
                    "Tab to cycle fields, Enter to submit, Esc to cancel",
                );
            }
            Some(ActionModal::Delete) => {
                self.confirm.render(frame, p, "Delete Key");
            }
            Some(ActionModal::Rename) => {
                self.form.render_in_modal_with_hint(
                    frame,
                    p,
                    "Rename Key",
                    52,
                    13,
                    "Enter to confirm, Esc to cancel",
                );
            }
            Some(ActionModal::TestPassphrase) => {
                self.form.render_in_modal_with_hint(
                    frame,
                    p,
                    "Test Passphrase",
                    48,
                    11,
                    "Enter passphrase and press Enter to verify",
                );
            }
            Some(ActionModal::Install) => {
                self.form.render_in_modal_with_hint(
                    frame,
                    p,
                    "Install Key to Remote",
                    52,
                    13,
                    "Enter user@host, Esc to cancel",
                );
            }
            None => {
                // Show passphrase test result as a temporary banner
                let result_copy = self.passphrase_test_result.clone();
                if let Some(ref result) = result_copy {
                    Self::render_passphrase_result(frame, area, p, result);
                }
            }
        }
    }

    fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action> {
        self.handle_mouse_impl(mouse)
    }

    fn has_modal(&self) -> bool {
        self.detail_modal.is_visible()
            || self.action_modal.is_some()
            || self.passphrase_test_result.is_some()
    }

    fn close_modal(&mut self) {
        self.detail_modal.close();
        self.detail_key_idx = None;
        self.action_modal = None;
    }

    fn drain_ops(&mut self) -> Vec<SshOp> {
        std::mem::take(&mut self.pending_ops)
    }
}

// ── Rendering ────────────────────────────────────────────────────────────────

impl KeysTab {
    fn render_empty(frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " SSH KEYS ", p.text, false);
        let msg = Line::from(vec![
            Span::styled("No SSH keys found", Style::new().fg(p.text_dim)),
            Span::styled(
                "  n",
                Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" generate", Style::new().fg(p.text_muted)),
        ]);
        let centered = Rect::new(inner.x, inner.y + inner.height / 2, inner.width, 1);
        frame.render_widget(Paragraph::new(msg).centered(), centered);
    }

    #[expect(
        clippy::too_many_lines,
        reason = "render routine kept whole for clarity"
    )]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "terminal cols/rows are bounded < u16::MAX; spinner arithmetic bounded"
    )]
    #[expect(
        clippy::cast_sign_loss,
        reason = "elapsed spinner product is non-negative"
    )]
    fn render_list(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(
            frame,
            area,
            p,
            &format!(" SSH KEYS ({}) ", self.keys.len()),
            p.text,
            false,
        );

        if inner.height == 0 {
            return;
        }

        let visible = inner.height as usize;
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

            // Fingerprint — show braille spinner while generating
            let fp_w = 16.min(inner.width.saturating_sub(40) as usize);
            if key.fingerprint.is_empty() {
                use rattles::Rattle;
                use rattles::presets::braille::WaveRows;
                let frames = WaveRows::FRAMES;
                let interval_ms = WaveRows::INTERVAL.as_millis() as u32;
                let elapsed = self.anim_start.elapsed().as_secs_f32();
                let idx = (elapsed * 1000.0) as u32 / interval_ms.max(1);
                let frame = frames[idx as usize % frames.len()];
                let spinner = frame.first().map_or("·", |s| *s);
                spans.push(Span::styled(
                    format!(" {spinner} generating…"),
                    Style::new().fg(p.accent),
                ));
            } else {
                let fp = truncate_str(&key.fingerprint, fp_w);
                spans.push(Span::styled(fp, Style::new().fg(p.text_dim)));
            }

            // Encrypted badge
            if key.encrypted {
                spans.push(Span::styled(" 🔒", Style::new().fg(p.warn)));
            }

            // Permissions
            spans.push(Span::styled(
                format!(" {} ", key.permissions),
                Style::new().fg(if key.permissions == "0600" || key.permissions == "0400" {
                    p.text_muted
                } else {
                    p.err
                }),
            ));

            // Public key — show spinner while generating, then badge
            if key.fingerprint.is_empty() {
                // Still generating, skip the pub badge
            } else if key.has_public {
                spans.push(Span::styled("✓pub ", Style::new().fg(p.ok)));
            }

            // Certificate check
            if key.has_cert {
                spans.push(Span::styled("✓cert", Style::new().fg(p.accent2)));
            }

            // Host count badge
            if key.host_count() > 0 {
                spans.push(Span::styled(
                    format!(" →{}", key.host_count()),
                    Style::new().fg(p.text_muted),
                ));
            }

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
        clippy::too_many_lines,
        reason = "render routine kept whole for clarity"
    )]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "terminal cols/rows are bounded < u16::MAX"
    )]
    fn render_detail_modal(&mut self, frame: &mut Frame, p: Palette, key: &SshKeyEntry) {
        self.detail_modal.render(frame, p, |frame, content_area| {
            let mut lines: Vec<Line> = vec![
                Line::from(vec![
                    Span::styled("Name:  ", Style::new().fg(p.text_dim)),
                    Span::styled(&key.name, Style::new().fg(p.text).bold()),
                ]),
                Line::from(vec![
                    Span::styled("Type:  ", Style::new().fg(p.text_dim)),
                    Span::styled(&key.key_type, Style::new().fg(p.info)),
                ]),
                Line::from(vec![
                    Span::styled("FP:    ", Style::new().fg(p.text_dim)),
                    if key.fingerprint.is_empty() {
                        Span::styled("generating…", Style::new().fg(p.accent))
                    } else {
                        Span::styled(&key.fingerprint, Style::new().fg(p.text))
                    },
                ]),
                Line::from(vec![
                    Span::styled("Enc:   ", Style::new().fg(p.text_dim)),
                    Span::styled(
                        if key.encrypted {
                            "encrypted"
                        } else {
                            "unencrypted"
                        },
                        Style::new().fg(if key.encrypted { p.ok } else { p.warn }),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Perms: ", Style::new().fg(p.text_dim)),
                    Span::styled(&key.permissions, Style::new().fg(p.text)),
                ]),
                Line::from(vec![
                    Span::styled("Pub:   ", Style::new().fg(p.text_dim)),
                    Span::styled(
                        if key.fingerprint.is_empty() {
                            "generating…"
                        } else if key.has_public {
                            "✓ present"
                        } else {
                            "✗ missing"
                        },
                        Style::new().fg(if key.fingerprint.is_empty() {
                            p.accent
                        } else if key.has_public {
                            p.ok
                        } else {
                            p.err
                        }),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Cert:  ", Style::new().fg(p.text_dim)),
                    Span::styled(
                        if key.has_cert {
                            "✓ attached"
                        } else {
                            "— none"
                        },
                        Style::new().fg(if key.has_cert {
                            p.accent2
                        } else {
                            p.text_muted
                        }),
                    ),
                ]),
            ];

            // Host referencing section
            if key.used_by_hosts.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("Hosts: ", Style::new().fg(p.text_dim)),
                    Span::styled(
                        "Not referenced in any host config",
                        Style::new().fg(p.text_dim),
                    ),
                ]));
            } else {
                lines.push(Line::from(vec![Span::styled(
                    "◆ Referenced by",
                    p.label_style(),
                )]));
                if key.used_by_hosts.len() <= 5 {
                    let hosts_str = format!("  {}", key.used_by_hosts.join(", "));
                    let hosts_display = truncate_str(&hosts_str, content_area.width as usize);
                    lines.push(Line::from(vec![Span::styled(
                        hosts_display,
                        Style::new().fg(p.text),
                    )]));
                } else {
                    let display: Vec<&str> = key
                        .used_by_hosts
                        .iter()
                        .take(5)
                        .map(std::string::String::as_str)
                        .collect();
                    let remaining = key.used_by_hosts.len() - 5;
                    let overflow_suffix = format!(" +{remaining} more");
                    let overflow_w = overflow_suffix.chars().count();
                    let max_hosts_w = content_area.width.saturating_sub(overflow_w as u16) as usize;
                    let hosts_str = format!("  {}", display.join(", "));
                    let hosts_display = truncate_str(&hosts_str, max_hosts_w);
                    lines.push(Line::from(vec![
                        Span::styled(hosts_display, Style::new().fg(p.text)),
                        Span::styled(overflow_suffix, Style::new().fg(p.text_dim)),
                    ]));
                }
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

// ── Helpers ──────────────────────────────────────────────────────────────────
// (truncate_str is imported from crate::ui::responsive)

impl KeysTab {
    /// Render the passphrase test result as a small overlay banner.
    fn render_passphrase_result(
        frame: &mut Frame,
        _area: Rect,
        p: Palette,
        result: &Result<String, String>,
    ) {
        let (icon, msg, color) = match result {
            Ok(label) => ("✓", label.as_str(), p.ok),
            Err(msg) => ("✗", msg.as_str(), p.err),
        };
        let modal = Modal::new("Passphrase Test").dimensions(42, 7);
        modal.render(frame, p, |frame, content_area| {
            let result_line = Line::from(vec![
                Span::styled(
                    format!("{icon} "),
                    Style::new().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(msg, Style::new().fg(color)),
            ]);
            let hint_line = Line::from(Span::styled(
                "press any key to close",
                Style::new().fg(p.text_muted),
            ));
            let y = content_area.y + content_area.height.saturating_sub(4) / 2;
            let row1 = Rect::new(content_area.x, y, content_area.width, 1);
            let row2 = Rect::new(content_area.x, y + 2, content_area.width, 1);
            frame.render_widget(Paragraph::new(result_line).centered(), row1);
            frame.render_widget(Paragraph::new(hint_line).centered(), row2);
        });
    }

    /// Update the passphrase test result from the async pipeline.
    pub fn set_passphrase_result(&mut self, result: Result<String, String>) {
        self.passphrase_test_result = Some(result);
    }

    /// Clear the passphrase test result banner.
    pub fn clear_passphrase_result(&mut self) {
        self.passphrase_test_result = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_keys() -> Vec<SshKeyEntry> {
        vec![
            SshKeyEntry {
                name: "id_ed25519".into(),
                key_type: "Ed25519".into(),
                fingerprint: "SHA256:abc123def456".into(),
                encrypted: true,
                permissions: "0600".into(),
                has_public: true,
                has_cert: false,
                used_by_hosts: vec!["github.com".into(), "gh.com".into()],
            },
            SshKeyEntry {
                name: "id_rsa".into(),
                key_type: "RSA 4096".into(),
                fingerprint: "SHA256:xyz789".into(),
                encrypted: false,
                permissions: "0644".into(),
                has_public: true,
                has_cert: true,
                used_by_hosts: vec![],
            },
        ]
    }

    #[test]
    fn new_is_empty() {
        let tab = KeysTab::new();
        assert!(tab.keys.is_empty());
        assert!(!tab.has_modal());
    }

    #[test]
    fn set_keys_updates_list() {
        let mut tab = KeysTab::new();
        tab.set_keys(sample_keys());
        assert_eq!(tab.keys.len(), 2);
    }

    #[test]
    fn scroll_up_decrements_selected() {
        let mut tab = KeysTab::new();
        tab.set_keys(sample_keys());
        tab.selected = 1;
        tab.handle_key(KeyCode::Up);
        assert_eq!(tab.selected, 0);
    }

    #[test]
    fn scroll_down_increments_selected() {
        let mut tab = KeysTab::new();
        tab.set_keys(sample_keys());
        tab.selected = 0;
        tab.handle_key(KeyCode::Down);
        assert_eq!(tab.selected, 1);
    }

    #[test]
    fn scroll_up_at_zero_stays() {
        let mut tab = KeysTab::new();
        tab.set_keys(sample_keys());
        tab.selected = 0;
        tab.handle_key(KeyCode::Up);
        assert_eq!(tab.selected, 0);
    }

    #[test]
    fn scroll_down_at_end_stays() {
        let mut tab = KeysTab::new();
        tab.set_keys(sample_keys());
        tab.selected = 1;
        tab.handle_key(KeyCode::Down);
        assert_eq!(tab.selected, 1);
    }

    #[test]
    fn enter_opens_detail_modal() {
        let mut tab = KeysTab::new();
        tab.set_keys(sample_keys());
        tab.handle_key(KeyCode::Enter);
        assert!(tab.has_modal());
        assert_eq!(tab.detail_key_idx, Some(0));
    }

    #[test]
    fn esc_closes_detail_modal() {
        let mut tab = KeysTab::new();
        tab.set_keys(sample_keys());
        tab.detail_key_idx = Some(0);
        tab.detail_modal.open();
        tab.handle_key(KeyCode::Esc);
        assert!(!tab.has_modal());
    }

    #[test]
    fn render_empty_state() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = KeysTab::new();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("No SSH keys found"),
            "empty state: {output}"
        );
    }

    #[test]
    fn render_with_keys() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = KeysTab::new();
        tab.set_keys(sample_keys());
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

        let mut tab = KeysTab::new();
        tab.set_keys(sample_keys());
        tab.detail_key_idx = Some(0);
        tab.detail_modal.open();
        let mut terminal = Terminal::new(TestBackend::new(80, 30)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains("Key Detail"), "modal title: {output}");
        assert!(output.contains("encrypted"), "encryption status: {output}");
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
    fn set_keys_clamps_selected() {
        let mut tab = KeysTab::new();
        tab.selected = 5;
        tab.set_keys(sample_keys()); // 2 items
        assert!(tab.selected < 2);
    }

    #[test]
    fn render_new_key_form() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = KeysTab::new();
        // Open the "New Key" form by pressing 'n'
        tab.handle_key(KeyCode::Char('n'));
        assert!(tab.action_modal == Some(ActionModal::New));

        let mut terminal = Terminal::new(TestBackend::new(80, 30)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        eprintln!("=== NEW KEY FORM RENDER ===\n{output}\n===");
        assert!(output.contains("Generate New Key"), "modal title: {output}");
        assert!(output.contains("Name"), "name label: {output}");
        assert!(output.contains("Type"), "type label: {output}");
        assert!(output.contains("Comment"), "comment label: {output}");
        assert!(output.contains("Passphrase"), "passphrase label: {output}");
    }

    #[test]
    fn render_detail_modal_with_hosts_shows_referenced_by() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = KeysTab::new();
        tab.set_keys(sample_keys());
        tab.detail_key_idx = Some(0);
        tab.detail_modal.open();
        let mut terminal = Terminal::new(TestBackend::new(80, 30)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("Referenced by"),
            "should show Referenced by header: {output}"
        );
        assert!(
            output.contains("github.com"),
            "should show host name github.com: {output}"
        );
    }

    #[test]
    fn render_detail_modal_with_many_hosts_shows_overflow() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = KeysTab::new();
        let keys = vec![SshKeyEntry {
            name: "id_many_hosts".into(),
            key_type: "Ed25519".into(),
            fingerprint: "SHA256:abc123".into(),
            encrypted: false,
            permissions: "0600".into(),
            has_public: true,
            has_cert: false,
            used_by_hosts: vec![
                "host1".into(),
                "host2".into(),
                "host3".into(),
                "host4".into(),
                "host5".into(),
                "host6".into(),
                "host7".into(),
            ],
        }];
        tab.set_keys(keys);
        tab.detail_key_idx = Some(0);
        tab.detail_modal.open();
        let mut terminal = Terminal::new(TestBackend::new(80, 30)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("+2 more"),
            "should show +N more overflow for 7 hosts: {output}"
        );
    }

    #[test]
    fn render_list_shows_host_count_badge() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = KeysTab::new();
        tab.set_keys(sample_keys());
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("→2"),
            "should show host count badge ->2 for first key: {output}"
        );
    }
}
