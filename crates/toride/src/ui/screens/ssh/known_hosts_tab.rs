//! Known Hosts sub-tab for the SSH management screen.
//!
//! Displays all entries from `~/.ssh/known_hosts` as a scrollable list with host,
//! key type, fingerprint, and status badges. Supports keyboard navigation,
//! selection, and a detail modal.

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

use super::{KnownHostEntry, SshTab, char_to_keycode};

// ── ActionModal ───────────────────────────────────────────────────────────────

/// Which action modal is currently open (if any).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActionModal {
    /// Add known host form.
    Add,
    /// Remove known host confirmation.
    Remove,
    /// Hash all hostnames confirmation.
    HashAll,
}

// ── KnownHostsTab ────────────────────────────────────────────────────────────

/// State for the Known Hosts sub-tab.
pub struct KnownHostsTab {
    /// Known host entries to display.
    hosts: Vec<KnownHostEntry>,
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
    /// Form modal for add operation.
    form: FormModal,
    /// Confirm modal for remove operation.
    confirm: ConfirmModal,
    /// Pending write operations to be forwarded to `SshContent`.
    pending_ops: Vec<SshOp>,
}

impl KnownHostsTab {
    /// Create a new empty known hosts tab.
    #[must_use]
    pub fn new() -> Self {
        let buttons = ButtonRow::new(
            vec![
                InteractiveButton::new("↵ detail", "↵", '\r'),
                InteractiveButton::new("a add", "a", 'a'),
                InteractiveButton::new("d remove", "d", 'd'),
                InteractiveButton::new("s scan", "s", 's'),
                InteractiveButton::new("h hash", "h", 'h'),
            ],
            vec![1, 1, 1, 1, 1],
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
    pub fn set_hosts(&mut self, hosts: Vec<KnownHostEntry>) {
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
        if matches!(
            self.action_modal,
            Some(ActionModal::Remove | ActionModal::HashAll)
        ) {
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

impl Default for KnownHostsTab {
    fn default() -> Self {
        Self::new()
    }
}

impl SshTab for KnownHostsTab {
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
                            let hostname = self
                                .form
                                .text_value(0)
                                .map(std::string::ToString::to_string)
                                .unwrap_or_default();
                            let display_host = if hostname.is_empty() {
                                "example.com".to_string()
                            } else {
                                hostname.clone()
                            };
                            // Persist to disk
                            self.pending_ops.push(SshOp::KnownHostAdd {
                                host: display_host.clone(),
                            });
                            // Optimistic in-memory update
                            self.hosts.push(KnownHostEntry {
                                hosts: vec![display_host],
                                key_type: "unknown".into(),
                                key_types: vec!["unknown".into()],
                                fingerprint: String::new(),
                                fingerprints: vec![],
                                is_hashed: false,
                                marker: None,
                                comment: None,
                                line: self.hosts.len() + 1,
                                source: "user".into(),
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
                                let host = self.hosts[self.selected].primary_host().to_string();
                                // Persist to disk
                                self.pending_ops.push(SshOp::KnownHostRemove { host });
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
                ActionModal::HashAll => {
                    match self.confirm.handle_key(code) {
                        Some(ConfirmResult::Confirmed) => {
                            // Persist to disk
                            self.pending_ops.push(SshOp::KnownHostHashAll);
                            // Optimistic in-memory update: mark all hosts as hashed
                            for host in &mut self.hosts {
                                host.is_hashed = true;
                            }
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
                    self.form = FormModal::new(40).text_field(
                        TextInput::new("Hostname", 40)
                            .placeholder("example.com")
                            .required(),
                    );
                    self.action_modal = Some(ActionModal::Add);
                    None
                }
                KeyCode::Char('d') => {
                    if !self.hosts.is_empty() {
                        let host_name = self.hosts[self.selected].primary_host().to_string();
                        self.confirm = ConfirmModal::new(format!("Remove host \"{host_name}\"?"));
                        self.action_modal = Some(ActionModal::Remove);
                    }
                    None
                }
                KeyCode::Char('s') => {
                    if !self.hosts.is_empty() {
                        let host = self.hosts[self.selected].primary_host().to_string();
                        self.pending_ops.push(SshOp::KnownHostScan { host });
                    }
                    None
                }
                KeyCode::Char('h') => {
                    self.confirm = ConfirmModal::new(
                        "Hash all hostnames in known_hosts? This is irreversible.",
                    );
                    self.action_modal = Some(ActionModal::HashAll);
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
                    "Add Known Host",
                    52,
                    13,
                    "Enter hostname, Esc to cancel",
                );
            }
            Some(ActionModal::Remove) => {
                self.confirm.render(frame, p, "Remove Host");
            }
            Some(ActionModal::HashAll) => {
                self.confirm.render(frame, p, "Hash All Hostnames");
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

impl KnownHostsTab {
    fn render_empty(frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " KNOWN HOSTS ", p.text, false);
        let msg = Line::from(vec![
            Span::styled("No known hosts found", Style::new().fg(p.text_dim)),
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
            &format!(" KNOWN HOSTS ({}) ", self.hosts.len()),
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

            // Host name (truncated to 22 chars)
            let host_w = 22.min(inner.width.saturating_sub(4) as usize);
            let host_display = truncate_str(host.primary_host(), host_w);
            let host_chars = host_display.chars().count();
            spans.push(Span::styled(
                host_display,
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ));

            // "+N more" badge when multiple hosts
            if host.hosts.len() > 1 {
                spans.push(Span::styled(
                    format!(" +{}", host.hosts.len() - 1),
                    Style::new().fg(p.text_dim),
                ));
            }

            // Padding
            let padded = format!("{:width$}", "", width = host_w.saturating_sub(host_chars));
            spans.push(Span::raw(padded));

            // Key type — show primary or count when grouped
            if host.key_types.len() > 1 {
                spans.push(Span::styled(
                    format!(" {} ", host.key_type),
                    Style::new().fg(p.info),
                ));
                spans.push(Span::styled(
                    format!("+{}", host.key_types.len() - 1),
                    Style::new().fg(p.text_muted),
                ));
            } else {
                spans.push(Span::styled(
                    format!(" {} ", host.key_type),
                    Style::new().fg(p.info),
                ));
            }

            // Fingerprint (truncated to 16 chars)
            let fp_w = 16.min(inner.width.saturating_sub(40) as usize);
            let fp = truncate_str(&host.fingerprint, fp_w);
            spans.push(Span::styled(fp, Style::new().fg(p.text_dim)));

            // Status badges
            let is_revoked = host.marker.as_deref() == Some("@revoked");
            let is_ca = host.marker.as_deref() == Some("@cert-authority");

            if is_revoked {
                spans.push(Span::styled(" !", Style::new().fg(p.err)));
            } else if is_ca {
                spans.push(Span::styled(" CA", Style::new().fg(p.accent2)));
            } else {
                spans.push(Span::styled(" ✓", Style::new().fg(p.ok)));
            }

            if host.is_hashed {
                spans.push(Span::styled(" 🔒", Style::new().fg(p.warn)));
            }

            // Source badge
            if host.source == "global" {
                spans.push(Span::styled(" sys", Style::new().fg(p.accent2)));
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
        clippy::cast_possible_truncation,
        reason = "terminal cols/rows are bounded < u16::MAX"
    )]
    fn render_detail_modal(&mut self, frame: &mut Frame, p: Palette, host: &KnownHostEntry) {
        // Extra height for each additional key type
        let extra = host.key_types.len().saturating_sub(1) as u16;
        let modal_h = 16 + extra;
        let modal = Modal::new("Host Detail").dimensions(58, modal_h);
        self.detail_modal_rect = Some(modal.rect(frame.area()));
        modal.render(frame, p, |frame, content_area| {
            let marker_display = match host.marker.as_deref() {
                Some("@revoked") => "@revoked",
                Some("@cert-authority") => "@cert-authority",
                Some(other) => other,
                None => "none",
            };

            let hosts_display = host.hosts.join(", ");

            let mut lines = vec![Line::from(vec![
                Span::styled("Hosts:  ", Style::new().fg(p.text_dim)),
                Span::styled(&hosts_display, Style::new().fg(p.text).bold()),
            ])];

            // Show all key types with their fingerprints
            for (i, kt) in host.key_types.iter().enumerate() {
                let fp = host
                    .fingerprints
                    .get(i)
                    .map_or("(unknown)", std::string::String::as_str);
                let label = if i == 0 { "Keys:   " } else { "        " };
                lines.push(Line::from(vec![
                    Span::styled(label, Style::new().fg(p.text_dim)),
                    Span::styled(
                        format!("{kt}  {fp}"),
                        Style::new().fg(if i == 0 { p.info } else { p.text_dim }),
                    ),
                ]));
            }

            lines.push(Line::from(vec![
                Span::styled("Hashed: ", Style::new().fg(p.text_dim)),
                Span::styled(
                    if host.is_hashed { "yes" } else { "no" },
                    Style::new().fg(if host.is_hashed { p.ok } else { p.text_muted }),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Marker: ", Style::new().fg(p.text_dim)),
                Span::styled(
                    marker_display,
                    Style::new().fg(if host.marker.as_deref() == Some("@revoked") {
                        p.err
                    } else if host.marker.as_deref() == Some("@cert-authority") {
                        p.accent2
                    } else {
                        p.text
                    }),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Comment:", Style::new().fg(p.text_dim)),
                Span::styled(
                    host.comment.as_deref().unwrap_or("none"),
                    Style::new().fg(if host.comment.is_some() {
                        p.text
                    } else {
                        p.text_muted
                    }),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Line:   ", Style::new().fg(p.text_dim)),
                Span::styled(host.line.to_string(), Style::new().fg(p.text)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Source: ", Style::new().fg(p.text_dim)),
                Span::styled(&host.source, Style::new().fg(p.text)),
            ]));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hosts() -> Vec<KnownHostEntry> {
        vec![
            KnownHostEntry {
                hosts: vec!["github.com".into()],
                key_type: "ssh-ed25519".into(),
                key_types: vec!["ssh-ed25519".into()],
                fingerprint: "SHA256:abc123def456".into(),
                fingerprints: vec!["SHA256:abc123def456".into()],
                is_hashed: false,
                marker: None,
                comment: None,
                line: 1,
                source: "user".into(),
            },
            KnownHostEntry {
                hosts: vec!["gitlab.com".into()],
                key_type: "ssh-rsa".into(),
                key_types: vec!["ssh-rsa".into()],
                fingerprint: "SHA256:xyz789".into(),
                fingerprints: vec!["SHA256:xyz789".into()],
                is_hashed: true,
                marker: Some("@cert-authority".into()),
                comment: Some("work CA".into()),
                line: 5,
                source: "global".into(),
            },
            KnownHostEntry {
                hosts: vec!["revoked.example.com".into()],
                key_type: "ecdsa-sha2-nistp256".into(),
                key_types: vec!["ecdsa-sha2-nistp256".into()],
                fingerprint: "SHA256:revokedkey".into(),
                fingerprints: vec!["SHA256:revokedkey".into()],
                is_hashed: false,
                marker: Some("@revoked".into()),
                comment: None,
                line: 10,
                source: "user".into(),
            },
        ]
    }

    #[test]
    fn new_is_empty() {
        let tab = KnownHostsTab::new();
        assert!(tab.hosts.is_empty());
        assert!(!tab.has_modal());
    }

    #[test]
    fn set_hosts_updates_list() {
        let mut tab = KnownHostsTab::new();
        tab.set_hosts(sample_hosts());
        assert_eq!(tab.hosts.len(), 3);
    }

    #[test]
    fn scroll_up_decrements_selected() {
        let mut tab = KnownHostsTab::new();
        tab.set_hosts(sample_hosts());
        tab.selected = 1;
        tab.handle_key(KeyCode::Up);
        assert_eq!(tab.selected, 0);
    }

    #[test]
    fn scroll_down_increments_selected() {
        let mut tab = KnownHostsTab::new();
        tab.set_hosts(sample_hosts());
        tab.selected = 0;
        tab.handle_key(KeyCode::Down);
        assert_eq!(tab.selected, 1);
    }

    #[test]
    fn scroll_up_at_zero_stays() {
        let mut tab = KnownHostsTab::new();
        tab.set_hosts(sample_hosts());
        tab.selected = 0;
        tab.handle_key(KeyCode::Up);
        assert_eq!(tab.selected, 0);
    }

    #[test]
    fn scroll_down_at_end_stays() {
        let mut tab = KnownHostsTab::new();
        tab.set_hosts(sample_hosts());
        tab.selected = 2;
        tab.handle_key(KeyCode::Down);
        assert_eq!(tab.selected, 2);
    }

    #[test]
    fn enter_opens_detail_modal() {
        let mut tab = KnownHostsTab::new();
        tab.set_hosts(sample_hosts());
        tab.handle_key(KeyCode::Enter);
        assert!(tab.has_modal());
        assert_eq!(tab.detail_open, Some(0));
    }

    #[test]
    fn esc_closes_detail_modal() {
        let mut tab = KnownHostsTab::new();
        tab.set_hosts(sample_hosts());
        tab.detail_open = Some(0);
        tab.handle_key(KeyCode::Esc);
        assert!(!tab.has_modal());
    }

    #[test]
    fn render_empty_state() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = KnownHostsTab::new();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("No known hosts found"),
            "empty state: {output}"
        );
    }

    #[test]
    fn render_with_hosts() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = KnownHostsTab::new();
        tab.set_hosts(sample_hosts());
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains("github.com"), "host name: {output}");
        assert!(output.contains("ssh-ed25519"), "key type: {output}");
    }

    #[test]
    fn render_detail_modal() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = KnownHostsTab::new();
        tab.set_hosts(sample_hosts());
        tab.detail_open = Some(0);
        let mut terminal = Terminal::new(TestBackend::new(80, 30)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains("Host Detail"), "modal title: {output}");
        assert!(
            output.contains("github.com"),
            "host name in modal: {output}"
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
        let mut tab = KnownHostsTab::new();
        tab.selected = 5;
        tab.set_hosts(sample_hosts()); // 3 items
        assert!(tab.selected < 3);
    }
}
