//! Config sub-tab for the SSH management screen.
//!
//! Displays all SSH config Host blocks found in `~/.ssh/config` as a scrollable
//! list with name, user, port, hostname, directive count, identity file, and
//! diagnostic indicators. Supports keyboard navigation, selection, and a detail
//! modal.

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
    ConfirmModal, ConfirmResult, FormModal, FormResult, Modal, Port, TextInput, render_titled_panel,
};

use super::{ConfigHostEntry, SshTab, char_to_keycode};

// ── ActionModal ───────────────────────────────────────────────────────────────

/// Which action modal is currently open (if any).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActionModal {
    /// Add host form.
    Add,
    /// Remove host confirmation.
    Remove,
    /// Edit host form.
    Edit,
}

// ── ConfigTab ─────────────────────────────────────────────────────────────────

/// State for the Config sub-tab.
pub struct ConfigTab {
    /// Config host entries to display.
    hosts: Vec<ConfigHostEntry>,
    /// Index of the currently selected host.
    selected: usize,
    /// Vertical scroll offset.
    scroll: usize,
    /// Whether the detail modal is open, and for which host index.
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
    /// Form modal for add/edit operations.
    form: FormModal,
    /// Confirm modal for remove operations.
    confirm: ConfirmModal,
    /// Pending write operations to be forwarded to `SshContent`.
    pending_ops: Vec<SshOp>,
}

impl ConfigTab {
    /// Create a new empty config tab.
    #[must_use]
    pub fn new() -> Self {
        let buttons = ButtonRow::new(
            vec![
                InteractiveButton::new("↵ detail", "↵", '\r'),
                InteractiveButton::new("a add", "a", 'a'),
                InteractiveButton::new("d remove", "d", 'd'),
                InteractiveButton::new("e edit", "e", 'e'),
            ],
            vec![1, 1, 1, 1],
        );
        Self {
            hosts: Vec::new(),
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

    /// Replace the host list with new data.
    pub fn set_hosts(&mut self, hosts: Vec<ConfigHostEntry>) {
        self.hosts = hosts;
        if self.selected >= self.hosts.len() && !self.hosts.is_empty() {
            self.selected = self.hosts.len() - 1;
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
        if self.hosts.is_empty() {
            self.scroll = 0;
            return;
        }
        // Ensure selected is within bounds
        if self.selected >= self.hosts.len() {
            self.selected = self.hosts.len() - 1;
        }
    }

    /// Close the detail modal (if open).
    pub fn close_modal(&mut self) {
        self.detail_open = None;
    }

    /// Handle a mouse event for the host list.
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
                if self.selected < self.hosts.len().saturating_sub(1) {
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

impl Default for ConfigTab {
    fn default() -> Self {
        Self::new()
    }
}

impl SshTab for ConfigTab {
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
                            let name = self
                                .form
                                .text_value(0)
                                .map(std::string::ToString::to_string)
                                .unwrap_or_default();
                            let host_name = self.form.text_value(1).and_then(|s| {
                                if s.is_empty() {
                                    None
                                } else {
                                    Some(s.to_string())
                                }
                            });
                            let user = self.form.text_value(2).and_then(|s| {
                                if s.is_empty() {
                                    None
                                } else {
                                    Some(s.to_string())
                                }
                            });
                            let port_str = self.form.text_value(3).unwrap_or("");
                            let port = port_str.parse::<u16>().ok();
                            let display_name = if name.is_empty() {
                                "new-host".to_string()
                            } else {
                                name.clone()
                            };
                            // Persist to disk
                            self.pending_ops.push(SshOp::ConfigAddHost {
                                name: display_name.clone(),
                                host_name: host_name.clone(),
                                user: user.clone(),
                                port,
                            });
                            // Optimistic in-memory update
                            self.hosts.push(ConfigHostEntry {
                                name: display_name.clone(),
                                patterns: vec![display_name],
                                host_name,
                                user,
                                port,
                                identity_file: None,
                                proxy_jump: None,
                                directive_count: 1,
                                has_diagnostic: false,
                            });
                            self.selected = self.hosts.len() - 1;
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
                            if !self.hosts.is_empty() {
                                let name = self.hosts[self.selected].name.clone();
                                // Persist to disk
                                self.pending_ops.push(SshOp::ConfigRemoveHost { name });
                                // Optimistic in-memory update
                                self.hosts.remove(self.selected);
                                if self.selected >= self.hosts.len() && !self.hosts.is_empty() {
                                    self.selected = self.hosts.len() - 1;
                                }
                                self.clamp_scroll();
                            }
                            self.action_modal = None;
                        }
                        Some(ConfirmResult::Cancelled) => self.action_modal = None,
                        None => {}
                    }
                }
                ActionModal::Edit => {
                    match self.form.handle_key(code) {
                        FormResult::Submitted => {
                            if let Some(host) = self.hosts.get_mut(self.selected) {
                                let old_name = host.name.clone();
                                let name = self
                                    .form
                                    .text_value(0)
                                    .map(std::string::ToString::to_string)
                                    .unwrap_or_default();
                                let host_name = self.form.text_value(1).and_then(|s| {
                                    if s.is_empty() {
                                        None
                                    } else {
                                        Some(s.to_string())
                                    }
                                });
                                let user = self.form.text_value(2).and_then(|s| {
                                    if s.is_empty() {
                                        None
                                    } else {
                                        Some(s.to_string())
                                    }
                                });
                                let port_str = self.form.text_value(3).unwrap_or("");
                                let port = port_str.parse::<u16>().ok();
                                let new_name = if name.is_empty() {
                                    old_name.clone()
                                } else {
                                    name.clone()
                                };
                                // Persist to disk
                                self.pending_ops.push(SshOp::ConfigEditHost {
                                    old_name,
                                    new_name: new_name.clone(),
                                    host_name: host_name.clone(),
                                    user: user.clone(),
                                    port,
                                });
                                // Optimistic in-memory update
                                host.name.clone_from(&new_name);
                                host.patterns = vec![new_name];
                                host.host_name = host_name;
                                host.user = user;
                                host.port = port;
                            }
                            self.action_modal = None;
                        }
                        FormResult::Cancelled => {
                            self.action_modal = None;
                        }
                        FormResult::Pending => {}
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
                    if !self.hosts.is_empty() && self.selected < self.hosts.len() - 1 {
                        self.selected += 1;
                        self.clamp_scroll();
                    }
                    None
                }
                KeyCode::Enter => {
                    if !self.hosts.is_empty() {
                        self.detail_open = Some(self.selected);
                    }
                    None
                }
                // CRUD shortcuts
                KeyCode::Char('a') => {
                    self.form = FormModal::new(40)
                        .text_field(
                            TextInput::new("Host", 30)
                                .placeholder("myserver")
                                .required(),
                        )
                        .text_field(TextInput::new("HostName", 30).placeholder("192.168.1.1"))
                        .text_field(TextInput::new("User", 30).placeholder("user"))
                        .text_field_validated(
                            TextInput::new("Port", 30).placeholder("22"),
                            Box::new(Port),
                        );
                    self.action_modal = Some(ActionModal::Add);
                    None
                }
                KeyCode::Char('d') => {
                    if !self.hosts.is_empty() {
                        let name = self.hosts[self.selected].name.clone();
                        self.confirm = ConfirmModal::new(format!("Remove host \"{name}\"?"));
                        self.action_modal = Some(ActionModal::Remove);
                    }
                    None
                }
                KeyCode::Char('e') => {
                    if !self.hosts.is_empty() {
                        let host = &self.hosts[self.selected];
                        self.form = FormModal::new(40)
                            .text_field(TextInput::new("Host", 30).value(&host.name).required())
                            .text_field(
                                TextInput::new("HostName", 30)
                                    .value(host.host_name.as_deref().unwrap_or("")),
                            )
                            .text_field(
                                TextInput::new("User", 30)
                                    .value(host.user.as_deref().unwrap_or("")),
                            )
                            .text_field_validated(
                                TextInput::new("Port", 30)
                                    .value(host.port.map_or(String::new(), |p| p.to_string())),
                                Box::new(Port),
                            );
                        self.action_modal = Some(ActionModal::Edit);
                    }
                    None
                }
                _ => None,
            }
        }
    }

    fn view(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        self.row_hitboxes.clear();
        if self.hosts.is_empty() {
            Self::render_empty(frame, area, p);
        } else {
            self.render_list(frame, area, p);
        }

        // Render detail modal if open
        if let Some(idx) = self.detail_open
            && let Some(host) = self.hosts.get(idx).cloned()
        {
            self.render_detail_modal(frame, p, &host);
        }

        // Render action modal on top
        match self.action_modal {
            Some(ActionModal::Add) => {
                self.form.render_in_modal_with_hint(
                    frame,
                    p,
                    "Add Host",
                    52,
                    22,
                    "Tab to cycle fields, Enter to submit, Esc to cancel",
                );
            }
            Some(ActionModal::Remove) => {
                self.confirm.render(frame, p, "Remove Host");
            }
            Some(ActionModal::Edit) => {
                self.form.render_in_modal_with_hint(
                    frame,
                    p,
                    "Edit Host",
                    52,
                    22,
                    "Tab to cycle fields, Enter to submit, Esc to cancel",
                );
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

impl ConfigTab {
    fn render_empty(frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " SSH CONFIG ", p.text, false);
        let msg = Line::from(vec![
            Span::styled("No SSH config hosts found", Style::new().fg(p.text_dim)),
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
            &format!(" SSH CONFIG ({}) ", self.hosts.len()),
            p.text,
            false,
        );

        if inner.height == 0 {
            return;
        }

        let visible = inner.height as usize;
        let max_scroll = self.hosts.len().saturating_sub(visible);
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
            if idx >= self.hosts.len() {
                break;
            }
            let host = &self.hosts[idx];
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

            // Host name (truncated to 18 chars)
            let name_w = 18.min(inner.width.saturating_sub(4) as usize);
            let name = truncate_str(&host.name, name_w);
            let name_chars = name.chars().count();
            spans.push(Span::styled(
                name,
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ));

            // Padding
            let padded = format!("{:width$}", "", width = name_w.saturating_sub(name_chars));
            spans.push(Span::raw(padded));

            // User
            if let Some(ref user) = host.user {
                spans.push(Span::styled(" User:", Style::new().fg(p.text_dim)));
                spans.push(Span::styled(user.clone(), Style::new().fg(p.info)));
            } else {
                spans.push(Span::styled(" ·", Style::new().fg(p.text_dim)));
            }

            // Port (skip if default 22)
            if let Some(port) = host.port
                && port != 22
            {
                spans.push(Span::styled(
                    format!(" Port:{port}"),
                    Style::new().fg(p.accent3),
                ));
            }

            // HostName
            if let Some(ref hn) = host.host_name {
                let hn_w = 20.min(inner.width.saturating_sub(50) as usize);
                let hn_display = truncate_str(hn, hn_w);
                spans.push(Span::styled(
                    format!(" →{hn_display}"),
                    Style::new().fg(p.text_muted),
                ));
            }

            // Directive count
            spans.push(Span::styled(
                format!(" {} dirs", host.directive_count),
                Style::new().fg(p.text_dim),
            ));

            // Identity file
            if host.identity_file.is_some() {
                spans.push(Span::styled(" ✓id", Style::new().fg(p.ok)));
            }

            // Diagnostic
            if host.has_diagnostic {
                spans.push(Span::styled(" ⚠", Style::new().fg(p.warn)));
            }

            let line = Line::from(spans);
            frame.render_widget(Paragraph::new(line), row_area);
        }

        // Footer with host count and action hints
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
    fn render_detail_modal(&mut self, frame: &mut Frame, p: Palette, host: &ConfigHostEntry) {
        let modal = Modal::new("Host Config").dimensions(56, 14);
        self.detail_modal_rect = Some(modal.rect(frame.area()));
        modal.render(frame, p, |frame, content_area| {
            let lines = vec![
                Line::from(vec![
                    Span::styled("Name:    ", Style::new().fg(p.text_dim)),
                    Span::styled(&host.name, Style::new().fg(p.text).bold()),
                ]),
                Line::from(vec![
                    Span::styled("Match:   ", Style::new().fg(p.text_dim)),
                    Span::styled(host.patterns.join(", "), Style::new().fg(p.text)),
                ]),
                Line::from(vec![
                    Span::styled("HostName:", Style::new().fg(p.text_dim)),
                    Span::styled(
                        host.host_name.as_deref().unwrap_or("—"),
                        Style::new().fg(p.text),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("User:    ", Style::new().fg(p.text_dim)),
                    Span::styled(host.user.as_deref().unwrap_or("—"), Style::new().fg(p.info)),
                ]),
                Line::from(vec![
                    Span::styled("Port:    ", Style::new().fg(p.text_dim)),
                    Span::styled(
                        host.port.map_or("—".into(), |p| p.to_string()),
                        Style::new().fg(p.text),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Key:     ", Style::new().fg(p.text_dim)),
                    Span::styled(
                        host.identity_file.as_deref().unwrap_or("—"),
                        Style::new().fg(p.text),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Proxy:   ", Style::new().fg(p.text_dim)),
                    Span::styled(
                        host.proxy_jump.as_deref().unwrap_or("—"),
                        Style::new().fg(p.text),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Dirs:    ", Style::new().fg(p.text_dim)),
                    Span::styled(
                        format!("{} directives", host.directive_count),
                        Style::new().fg(p.text),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Diag:    ", Style::new().fg(p.text_dim)),
                    Span::styled(
                        if host.has_diagnostic {
                            "⚠ flagged"
                        } else {
                            "✓ clean"
                        },
                        Style::new().fg(if host.has_diagnostic { p.warn } else { p.ok }),
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

    fn sample_hosts() -> Vec<ConfigHostEntry> {
        vec![
            ConfigHostEntry {
                name: "myserver".into(),
                patterns: vec!["myserver".into(), "srv".into()],
                host_name: Some("192.168.1.100".into()),
                user: Some("alice".into()),
                port: Some(2222),
                identity_file: Some("~/.ssh/id_ed25519".into()),
                proxy_jump: None,
                directive_count: 6,
                has_diagnostic: false,
            },
            ConfigHostEntry {
                name: "bastion".into(),
                patterns: vec!["bastion".into()],
                host_name: Some("bastion.example.com".into()),
                user: Some("deploy".into()),
                port: None,
                identity_file: None,
                proxy_jump: Some("jump-host".into()),
                directive_count: 3,
                has_diagnostic: true,
            },
        ]
    }

    #[test]
    fn new_is_empty() {
        let tab = ConfigTab::new();
        assert!(tab.hosts.is_empty());
        assert!(!tab.has_modal());
    }

    #[test]
    fn set_hosts_updates_list() {
        let mut tab = ConfigTab::new();
        tab.set_hosts(sample_hosts());
        assert_eq!(tab.hosts.len(), 2);
    }

    #[test]
    fn scroll_up_decrements_selected() {
        let mut tab = ConfigTab::new();
        tab.set_hosts(sample_hosts());
        tab.selected = 1;
        tab.handle_key(KeyCode::Up);
        assert_eq!(tab.selected, 0);
    }

    #[test]
    fn scroll_down_increments_selected() {
        let mut tab = ConfigTab::new();
        tab.set_hosts(sample_hosts());
        tab.selected = 0;
        tab.handle_key(KeyCode::Down);
        assert_eq!(tab.selected, 1);
    }

    #[test]
    fn scroll_up_at_zero_stays() {
        let mut tab = ConfigTab::new();
        tab.set_hosts(sample_hosts());
        tab.selected = 0;
        tab.handle_key(KeyCode::Up);
        assert_eq!(tab.selected, 0);
    }

    #[test]
    fn scroll_down_at_end_stays() {
        let mut tab = ConfigTab::new();
        tab.set_hosts(sample_hosts());
        tab.selected = 1;
        tab.handle_key(KeyCode::Down);
        assert_eq!(tab.selected, 1);
    }

    #[test]
    fn enter_opens_detail_modal() {
        let mut tab = ConfigTab::new();
        tab.set_hosts(sample_hosts());
        tab.handle_key(KeyCode::Enter);
        assert!(tab.has_modal());
        assert_eq!(tab.detail_open, Some(0));
    }

    #[test]
    fn esc_closes_detail_modal() {
        let mut tab = ConfigTab::new();
        tab.set_hosts(sample_hosts());
        tab.detail_open = Some(0);
        tab.handle_key(KeyCode::Esc);
        assert!(!tab.has_modal());
    }

    #[test]
    fn render_empty_state() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = ConfigTab::new();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("No SSH config hosts found"),
            "empty state: {output}"
        );
    }

    #[test]
    fn render_with_hosts() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = ConfigTab::new();
        tab.set_hosts(sample_hosts());
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains("myserver"), "host name: {output}");
        assert!(output.contains("alice"), "user: {output}");
    }

    #[test]
    fn render_detail_modal() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = ConfigTab::new();
        tab.set_hosts(sample_hosts());
        tab.detail_open = Some(0);
        let mut terminal = Terminal::new(TestBackend::new(80, 30)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains("Host Config"), "modal title: {output}");
        assert!(
            output.contains("192.168.1.100"),
            "hostname in modal: {output}"
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
        assert_eq!(truncate_str("abcdefgh", 5), "abc..");
    }

    #[test]
    fn truncate_str_zero() {
        assert_eq!(truncate_str("abc", 0), "");
    }

    #[test]
    fn set_hosts_clamps_selected() {
        let mut tab = ConfigTab::new();
        tab.selected = 5;
        tab.set_hosts(sample_hosts()); // 2 items
        assert!(tab.selected < 2);
    }
}
