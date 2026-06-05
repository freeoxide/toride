//! Keys sub-tab for the SSH management screen.
//!
//! Displays all SSH keys found in `~/.ssh/` as a scrollable list with type,
//! fingerprint, encryption status, permissions, and badge indicators. Supports
//! keyboard navigation, selection, and a detail modal.

use crossterm::event::{KeyCode, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::action::Action;
use crate::ui::theme::Palette;
use crate::ui::widgets::{Modal, render_titled_panel};

use super::{SshKeyEntry, SshTab};

// ── KeysTab ──────────────────────────────────────────────────────────────────

/// State for the Keys sub-tab.
pub struct KeysTab {
    /// Key entries to display.
    keys: Vec<SshKeyEntry>,
    /// Index of the currently selected key.
    selected: usize,
    /// Vertical scroll offset.
    scroll: usize,
    /// Whether the detail modal is open, and for which key index.
    detail_open: Option<usize>,
    /// Hitbox rects for list rows (rebuilt each frame).
    row_hitboxes: Vec<Rect>,
    /// Which row is hovered by the mouse.
    hovered_row: Option<usize>,
}

impl KeysTab {
    /// Create a new empty keys tab.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            selected: 0,
            scroll: 0,
            detail_open: None,
            row_hitboxes: Vec::new(),
            hovered_row: None,
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
        self.detail_open.is_some()
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

    /// Handle a mouse event for the key list.
    pub fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action> {
        // Detail modal open: block background, click to close.
        if self.detail_open.is_some() {
            if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
                self.detail_open = None;
            }
            return None;
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
            MouseEventKind::ScrollUp => {
                if self.selected > 0 {
                    self.selected -= 1;
                    self.clamp_scroll();
                }
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
                // CRUD shortcuts — Phase 2
                KeyCode::Char('n') => {
                    // TODO: Open generate key modal
                    None
                }
                KeyCode::Char('d') => {
                    // TODO: Open delete confirm modal
                    None
                }
                KeyCode::Char('r') => {
                    // TODO: Open rename modal
                    None
                }
                KeyCode::Char('i') => {
                    // TODO: Open install to remote modal
                    None
                }
                KeyCode::Char('x') => {
                    // TODO: Fix permissions
                    None
                }
                _ => None,
            }
        }
    }

    fn view(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        self.row_hitboxes.clear();
        if self.keys.is_empty() {
            self.render_empty(frame, area, p);
        } else {
            self.render_list(frame, area, p);
        }

        // Render detail modal if open
        if let Some(idx) = self.detail_open {
            if let Some(key) = self.keys.get(idx) {
                self.render_detail_modal(frame, p, key);
            }
        }
    }
}

// ── Rendering ────────────────────────────────────────────────────────────────

impl KeysTab {
    fn render_empty(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " SSH KEYS ", p.text, false);
        let msg = Line::from(vec![
            Span::styled("No SSH keys found", Style::new().fg(p.text_dim)),
            Span::styled("  n", Style::new().fg(p.accent).add_modifier(Modifier::BOLD)),
            Span::styled(" generate", Style::new().fg(p.text_muted)),
        ]);
        let centered = Rect::new(inner.x, inner.y + inner.height / 2, inner.width, 1);
        frame.render_widget(Paragraph::new(msg).centered(), centered);
    }

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
                Style::new().fg(if is_selected || is_hovered { p.accent } else { p.text_dim }),
            ));

            // Key name (truncated to fit)
            let name_w = 18.min(inner.width.saturating_sub(4) as usize);
            let name = truncate_str(&key.name, name_w);
            let name_chars = name.chars().count();
            spans.push(Span::styled(
                name,
                Style::new()
                    .fg(p.text)
                    .add_modifier(Modifier::BOLD),
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

            // Public key check
            if key.has_public {
                spans.push(Span::styled("✓pub ", Style::new().fg(p.ok)));
            }

            // Certificate check
            if key.has_cert {
                spans.push(Span::styled("✓cert", Style::new().fg(p.accent2)));
            }

            // Host count badge
            if key.host_count > 0 {
                spans.push(Span::styled(
                    format!(" →{}", key.host_count),
                    Style::new().fg(p.text_muted),
                ));
            }

            let line = Line::from(spans);
            frame.render_widget(Paragraph::new(line), row_area);
        }

        // Footer with key count and action hints
        self.render_footer(frame, area, p);
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let footer_y = area.y + area.height.saturating_sub(1);
        let footer_area = Rect::new(area.x + 1, footer_y, area.width.saturating_sub(2), 1);

        let hints = Line::from(vec![
            Span::styled(" ↵ ", p.key_style()),
            Span::styled("detail ", p.label_style()),
            Span::styled(" n ", p.key_style()),
            Span::styled("new ", p.label_style()),
            Span::styled(" d ", p.key_style()),
            Span::styled("del ", p.label_style()),
            Span::styled(" r ", p.key_style()),
            Span::styled("rename ", p.label_style()),
            Span::styled(" i ", p.key_style()),
            Span::styled("install ", p.label_style()),
        ]);

        frame.render_widget(Paragraph::new(hints), footer_area);
    }

    fn render_detail_modal(&self, frame: &mut Frame, p: Palette, key: &SshKeyEntry) {
        Modal::new("Key Detail")
            .dimensions(54, 12)
            .render(frame, p, |frame, content_area| {
                let lines = vec![
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
                        Span::styled(&key.fingerprint, Style::new().fg(p.text)),
                    ]),
                    Line::from(vec![
                        Span::styled("Enc:   ", Style::new().fg(p.text_dim)),
                        Span::styled(
                            if key.encrypted { "encrypted" } else { "unencrypted" },
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
                            if key.has_public { "✓ present" } else { "✗ missing" },
                            Style::new().fg(if key.has_public { p.ok } else { p.err }),
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled("Cert:  ", Style::new().fg(p.text_dim)),
                        Span::styled(
                            if key.has_cert { "✓ attached" } else { "— none" },
                            Style::new().fg(if key.has_cert { p.accent2 } else { p.text_muted }),
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled("Hosts: ", Style::new().fg(p.text_dim)),
                        Span::styled(
                            format!("{} referencing", key.host_count),
                            Style::new().fg(p.text),
                        ),
                    ]),
                    Line::raw(""),
                    Line::from(
                        Span::styled("Press Esc to close", Style::new().fg(p.text_muted)),
                    ),
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

/// Truncate a string to `max_width` display columns, appending "…" if truncated.
fn truncate_str(s: &str, max_width: usize) -> String {
    if max_width == 0 {
        return String::new();
    }
    let width: usize = s.chars().count();
    if width <= max_width {
        return s.to_string();
    }
    let truncated: String = s.chars().take(max_width.saturating_sub(1)).collect();
    format!("{truncated}…")
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
                host_count: 2,
            },
            SshKeyEntry {
                name: "id_rsa".into(),
                key_type: "RSA 4096".into(),
                fingerprint: "SHA256:xyz789".into(),
                encrypted: false,
                permissions: "0644".into(),
                has_public: true,
                has_cert: true,
                host_count: 0,
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
        assert_eq!(tab.detail_open, Some(0));
    }

    #[test]
    fn esc_closes_detail_modal() {
        let mut tab = KeysTab::new();
        tab.set_keys(sample_keys());
        tab.detail_open = Some(0);
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
        assert!(output.contains("No SSH keys found"), "empty state: {output}");
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
        tab.detail_open = Some(0);
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
        assert_eq!(truncate_str("abcdefgh", 5), "abcd…");
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
}
