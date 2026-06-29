//! Certificates sub-tab for the SSH management screen.
//!
//! Displays all SSH certificates as a scrollable list with type,
//! key ID, validity status, and principal badges. Supports keyboard
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
    ConfirmModal, ConfirmResult, InteractiveModal, ModalEvent, render_titled_panel,
};

use super::{CertificateEntry, SshTab, char_to_keycode};

// ── ActionModal ───────────────────────────────────────────────────────────────

/// Which action modal is currently open (if any).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActionModal {
    /// Revoke certificate confirmation.
    Revoke,
}

// ── CertificatesTab ───────────────────────────────────────────────────────────

/// State for the Certificates sub-tab.
pub struct CertificatesTab {
    /// Certificate entries to display.
    entries: Vec<CertificateEntry>,
    /// Index of the currently selected certificate.
    selected: usize,
    /// Vertical scroll offset.
    scroll: usize,
    /// Which certificate index is shown in the detail modal (if open).
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
    /// Confirm modal for revoke operations.
    confirm: ConfirmModal,
    /// Pending write operations to be collected by `SshContent`.
    pending_ops: Vec<SshOp>,
}

impl CertificatesTab {
    /// Create a new empty certificates tab.
    #[must_use]
    pub fn new() -> Self {
        let buttons = ButtonRow::new(
            vec![
                InteractiveButton::new("↵ detail", "↵", '\r'),
                InteractiveButton::new("i inspect", "i", 'i'),
                InteractiveButton::new("r revoke", "r", 'r'),
            ],
            vec![1, 1, 1],
        );
        Self {
            entries: Vec::new(),
            selected: 0,
            scroll: 0,
            detail_entry_idx: None,
            detail_modal: InteractiveModal::display("Certificate Detail").dimensions(58, 16),
            row_hitboxes: Vec::new(),
            hovered_row: None,
            buttons,
            action_modal: None,
            confirm: ConfirmModal::new(""),
            pending_ops: Vec::new(),
        }
    }

    /// Replace the certificate list with new data.
    pub fn set_entries(&mut self, entries: Vec<CertificateEntry>) {
        self.entries = entries;
        if self.selected >= self.entries.len() && !self.entries.is_empty() {
            self.selected = self.entries.len() - 1;
        }
        self.clamp_scroll();
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

    /// Handle a mouse event for the certificate list (inherent method).
    fn handle_mouse_impl(&mut self, mouse: MouseEvent) -> Option<Action> {
        // Action modal open: block background input.
        if self.action_modal.is_some() {
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

impl Default for CertificatesTab {
    fn default() -> Self {
        Self::new()
    }
}

impl SshTab for CertificatesTab {
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
                ActionModal::Revoke => match self.confirm.handle_key(code) {
                    Some(ConfirmResult::Confirmed) => {
                        if !self.entries.is_empty() {
                            let cert = &self.entries[self.selected];
                            self.pending_ops.push(SshOp::CertificateRevoke {
                                name: cert.name.clone(),
                            });
                            self.entries.remove(self.selected);
                            if self.selected >= self.entries.len() && !self.entries.is_empty() {
                                self.selected = self.entries.len() - 1;
                            }
                            self.clamp_scroll();
                        }
                        self.action_modal = None;
                    }
                    Some(ConfirmResult::Cancelled) => {
                        self.action_modal = None;
                    }
                    None => {}
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
                if !self.entries.is_empty() && self.selected < self.entries.len() - 1 {
                    self.selected += 1;
                    self.clamp_scroll();
                }
                None
            }
            // Enter and Inspect shortcut both open the detail modal.
            KeyCode::Enter | KeyCode::Char('i') => {
                if !self.entries.is_empty() {
                    self.detail_entry_idx = Some(self.selected);
                    self.detail_modal.open();
                }
                None
            }
            // Revoke certificate
            KeyCode::Char('r') => {
                if !self.entries.is_empty() {
                    let name = self.entries[self.selected].name.clone();
                    self.confirm = ConfirmModal::new(format!("Revoke certificate \"{name}\"?"));
                    self.action_modal = Some(ActionModal::Revoke);
                }
                None
            }
            _ => None,
        }
    }

    fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action> {
        self.handle_mouse_impl(mouse)
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

        // Render action modal on top of everything
        match self.action_modal {
            Some(ActionModal::Revoke) => {
                self.confirm.render(frame, p, "Revoke Certificate");
            }
            None => {}
        }
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

impl CertificatesTab {
    fn render_empty(frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " CERTIFICATES ", p.text, false);
        let msg = Line::from(vec![
            Span::styled("No SSH certificates found", Style::new().fg(p.text_dim)),
            Span::styled(
                "  i",
                Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" inspect", Style::new().fg(p.text_muted)),
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
            &format!(" CERTIFICATES ({}) ", self.entries.len()),
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

            // Certificate name (truncated to 18 chars, bold)
            let name_w = 18.min(inner.width.saturating_sub(4) as usize);
            let name = truncate_str(&entry.name, name_w);
            let name_chars = name.chars().count();
            spans.push(Span::styled(
                name,
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ));

            // Padding
            let padded = format!("{:width$}", "", width = name_w.saturating_sub(name_chars));
            spans.push(Span::raw(padded));

            // Cert type badge: "User" in p.info, "Host" in p.accent3
            let cert_type_color = if entry.cert_type == "User" {
                p.info
            } else {
                p.accent3
            };
            spans.push(Span::styled(
                format!(" {} ", entry.cert_type),
                Style::new().fg(cert_type_color),
            ));

            // Key ID (truncated to 16 chars, dim)
            let kid_w = 16.min(inner.width.saturating_sub(42) as usize);
            let key_id = truncate_str(&entry.key_id, kid_w);
            spans.push(Span::styled(key_id, Style::new().fg(p.text_dim)));

            // Validity badge
            if entry.is_valid {
                spans.push(Span::styled(" ✓valid", Style::new().fg(p.ok)));
            } else {
                spans.push(Span::styled(" ✗expired", Style::new().fg(p.err)));
            }

            // First principal (truncated, muted) if non-empty
            if let Some(principal) = entry.principals.first() {
                let prin_w = 12.min(inner.width.saturating_sub(60) as usize);
                let prin = truncate_str(principal, prin_w);
                spans.push(Span::styled(
                    format!(" {prin}"),
                    Style::new().fg(p.text_muted),
                ));
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
    fn render_detail_modal(&mut self, frame: &mut Frame, p: Palette, entry: &CertificateEntry) {
        self.detail_modal.render(frame, p, |frame, content_area| {
            let principals_str = if entry.principals.is_empty() {
                "—".to_string()
            } else {
                entry.principals.join(", ")
            };

            let key_type_display = truncate_str(&entry.key_type, 36);
            let ca_display = truncate_str(&entry.ca_fingerprint, 36);

            let lines = vec![
                Line::from(vec![
                    Span::styled("Name:       ", Style::new().fg(p.text_dim)),
                    Span::styled(&entry.name, Style::new().fg(p.text).bold()),
                ]),
                Line::from(vec![
                    Span::styled("Type:       ", Style::new().fg(p.text_dim)),
                    Span::styled(&entry.cert_type, Style::new().fg(p.info)),
                ]),
                Line::from(vec![
                    Span::styled("Key Type:   ", Style::new().fg(p.text_dim)),
                    Span::styled(key_type_display, Style::new().fg(p.text)),
                ]),
                Line::from(vec![
                    Span::styled("Serial:     ", Style::new().fg(p.text_dim)),
                    Span::styled(entry.serial.to_string(), Style::new().fg(p.text)),
                ]),
                Line::from(vec![
                    Span::styled("Valid From: ", Style::new().fg(p.text_dim)),
                    Span::styled(&entry.valid_from, Style::new().fg(p.text)),
                ]),
                Line::from(vec![
                    Span::styled("Valid To:   ", Style::new().fg(p.text_dim)),
                    Span::styled(&entry.valid_to, Style::new().fg(p.text)),
                ]),
                Line::from(vec![
                    Span::styled("Status:     ", Style::new().fg(p.text_dim)),
                    Span::styled(
                        if entry.is_valid {
                            "✓ valid"
                        } else {
                            "✗ expired"
                        },
                        Style::new().fg(if entry.is_valid { p.ok } else { p.err }),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("CA:         ", Style::new().fg(p.text_dim)),
                    Span::styled(ca_display, Style::new().fg(p.text)),
                ]),
                Line::from(vec![
                    Span::styled("Key ID:     ", Style::new().fg(p.text_dim)),
                    Span::styled(&entry.key_id, Style::new().fg(p.text)),
                ]),
                Line::from(vec![
                    Span::styled("Principals: ", Style::new().fg(p.text_dim)),
                    Span::styled(principals_str, Style::new().fg(p.text)),
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

    fn sample_entries() -> Vec<CertificateEntry> {
        vec![
            CertificateEntry {
                name: "id_ed25519-cert.pub".into(),
                cert_type: "User".into(),
                key_type: "ssh-ed25519-cert-v01@openssh.com".into(),
                serial: 42,
                valid_from: "2025-01-01T00:00:00".into(),
                valid_to: "2026-01-01T00:00:00".into(),
                is_valid: true,
                ca_fingerprint: "SHA256:abc123def456".into(),
                key_id: "user_host_key".into(),
                principals: vec!["root".into(), "admin".into()],
            },
            CertificateEntry {
                name: "host-cert.pub".into(),
                cert_type: "Host".into(),
                key_type: "ssh-rsa-cert-v01@openssh.com".into(),
                serial: 99,
                valid_from: "2024-06-01T00:00:00".into(),
                valid_to: "2025-06-01T00:00:00".into(),
                is_valid: false,
                ca_fingerprint: "SHA256:xyz789abc".into(),
                key_id: "host_server".into(),
                principals: vec!["web.example.com".into()],
            },
        ]
    }

    #[test]
    fn new_is_empty() {
        let tab = CertificatesTab::new();
        assert!(tab.entries.is_empty());
        assert!(!tab.has_modal());
    }

    #[test]
    fn set_entries_updates_list() {
        let mut tab = CertificatesTab::new();
        tab.set_entries(sample_entries());
        assert_eq!(tab.entries.len(), 2);
    }

    #[test]
    fn scroll_up_decrements_selected() {
        let mut tab = CertificatesTab::new();
        tab.set_entries(sample_entries());
        tab.selected = 1;
        tab.handle_key(KeyCode::Up);
        assert_eq!(tab.selected, 0);
    }

    #[test]
    fn scroll_down_increments_selected() {
        let mut tab = CertificatesTab::new();
        tab.set_entries(sample_entries());
        tab.selected = 0;
        tab.handle_key(KeyCode::Down);
        assert_eq!(tab.selected, 1);
    }

    #[test]
    fn scroll_up_at_zero_stays() {
        let mut tab = CertificatesTab::new();
        tab.set_entries(sample_entries());
        tab.selected = 0;
        tab.handle_key(KeyCode::Up);
        assert_eq!(tab.selected, 0);
    }

    #[test]
    fn scroll_down_at_end_stays() {
        let mut tab = CertificatesTab::new();
        tab.set_entries(sample_entries());
        tab.selected = 1;
        tab.handle_key(KeyCode::Down);
        assert_eq!(tab.selected, 1);
    }

    #[test]
    fn enter_opens_detail_modal() {
        let mut tab = CertificatesTab::new();
        tab.set_entries(sample_entries());
        tab.handle_key(KeyCode::Enter);
        assert!(tab.has_modal());
        assert_eq!(tab.detail_entry_idx, Some(0));
    }

    #[test]
    fn esc_closes_detail_modal() {
        let mut tab = CertificatesTab::new();
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

        let mut tab = CertificatesTab::new();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("No SSH certificates found"),
            "empty state: {output}"
        );
    }

    #[test]
    fn render_with_entries() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = CertificatesTab::new();
        tab.set_entries(sample_entries());
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains("id_ed25519"), "cert name: {output}");
        assert!(output.contains("User"), "cert type: {output}");
    }

    #[test]
    fn render_detail_modal() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = CertificatesTab::new();
        tab.set_entries(sample_entries());
        tab.detail_entry_idx = Some(0);
        tab.detail_modal.open();
        let mut terminal = Terminal::new(TestBackend::new(80, 30)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("Certificate Detail"),
            "modal title: {output}"
        );
        assert!(output.contains("User"), "cert type in modal: {output}");
        assert!(output.contains("42"), "serial in modal: {output}");
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
        let mut tab = CertificatesTab::new();
        tab.selected = 5;
        tab.set_entries(sample_entries()); // 2 items
        assert!(tab.selected < 2);
    }
}
