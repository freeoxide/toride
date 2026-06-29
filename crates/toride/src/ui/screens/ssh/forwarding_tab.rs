//! Forwarding sub-tab for the SSH management screen.
//!
//! Displays active SSH sessions with their port forwards as a grouped,
//! scrollable list. Each session is a selectable group consisting of a
//! header line plus indented forward lines. Supports keyboard navigation,
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
use crate::ui::widgets::{ConfirmModal, ConfirmResult, Modal, render_titled_panel};

use super::{ForwardSessionEntry, SshTab, char_to_keycode};

// ── ActionModal ────────────────────────────────────────────────────────────────

/// Which action modal is currently open (if any).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActionModal {
    /// Cancel selected forward confirmation.
    Cancel,
    /// Exit SSH session confirmation.
    Exit,
}

// ── ForwardingTab ─────────────────────────────────────────────────────────────

/// State for the Forwarding sub-tab.
pub struct ForwardingTab {
    /// Active forwarding sessions.
    sessions: Vec<ForwardSessionEntry>,
    /// Index of the currently selected session.
    selected: usize,
    /// Vertical scroll offset (in total-row space).
    scroll: usize,
    /// Whether the detail modal is open, and for which session index.
    detail_open: Option<usize>,
    /// Rendered rect of the detail modal (for click-outside detection).
    detail_modal_rect: Option<Rect>,
    /// Hitbox rects for list rows (rebuilt each frame).
    row_hitboxes: Vec<Rect>,
    /// Which row is hovered by the mouse (total-row index).
    hovered_row: Option<usize>,
    /// Interactive footer shortcut buttons.
    buttons: ButtonRow<char>,
    /// Which action modal is open (if any).
    action_modal: Option<ActionModal>,
    /// Confirm modal for cancel/exit operations.
    confirm: ConfirmModal,
    /// Pending SSH write operations to be drained by the parent `SshContent`.
    pending_ops: Vec<SshOp>,
}

impl ForwardingTab {
    /// Create a new empty forwarding tab.
    #[must_use]
    pub fn new() -> Self {
        let buttons = ButtonRow::new(
            vec![
                InteractiveButton::new("↵ detail", "↵", '\r'),
                InteractiveButton::new("x cancel", "x", 'x'),
                InteractiveButton::new("X exit", "X", 'X'),
            ],
            vec![1, 1, 1],
        );
        Self {
            sessions: Vec::new(),
            selected: 0,
            scroll: 0,
            detail_open: None,
            detail_modal_rect: None,
            row_hitboxes: Vec::new(),
            hovered_row: None,
            buttons,
            action_modal: None,
            confirm: ConfirmModal::new(""),
            pending_ops: Vec::new(),
        }
    }

    /// Replace the session list with new data.
    pub fn set_sessions(&mut self, sessions: Vec<ForwardSessionEntry>) {
        self.sessions = sessions;
        if self.selected >= self.sessions.len() && !self.sessions.is_empty() {
            self.selected = self.sessions.len() - 1;
        }
        self.clamp_scroll();
    }

    /// Whether a modal is currently open.
    #[must_use]
    pub fn has_modal(&self) -> bool {
        self.detail_open.is_some() || self.action_modal.is_some()
    }

    /// Clamp scroll so the selected session is visible.
    fn clamp_scroll(&mut self) {
        if self.sessions.is_empty() {
            self.scroll = 0;
            return;
        }
        if self.selected >= self.sessions.len() {
            self.selected = self.sessions.len() - 1;
        }
    }

    /// Close the detail modal (if open).
    pub fn close_modal(&mut self) {
        self.detail_open = None;
    }

    /// Compute the total number of rendered rows across all sessions.
    fn total_rows(&self) -> usize {
        self.sessions.iter().map(|s| 1 + s.forwards.len()).sum()
    }

    /// Compute the starting row offset for a given session index.
    fn session_row_offset(&self, session_idx: usize) -> usize {
        self.sessions
            .iter()
            .take(session_idx)
            .map(|s| 1 + s.forwards.len())
            .sum()
    }

    /// Compute the total row count for a given session (header + forwards).
    fn session_row_count(&self, session_idx: usize) -> usize {
        self.sessions
            .get(session_idx)
            .map_or(0, |s| 1 + s.forwards.len())
    }

    /// Find which session index a total-row index belongs to.
    fn session_at_row(&self, row: usize) -> Option<usize> {
        let mut cursor = 0usize;
        for (i, session) in self.sessions.iter().enumerate() {
            let span = 1 + session.forwards.len();
            if row >= cursor && row < cursor + span {
                return Some(i);
            }
            cursor += span;
        }
        None
    }

    /// Handle a mouse event for the forwarding list.
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
                if let Some(total_row) = self.row_at(mouse.column, mouse.row)
                    && let Some(session_idx) = self.session_at_row(total_row)
                {
                    self.selected = session_idx;
                    self.detail_open = Some(session_idx);
                }
            }
            MouseEventKind::ScrollDown => {
                if self.selected < self.sessions.len().saturating_sub(1) {
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

impl Default for ForwardingTab {
    fn default() -> Self {
        Self::new()
    }
}

impl SshTab for ForwardingTab {
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
                ActionModal::Cancel => {
                    if let Some(ConfirmResult::Confirmed) = self.confirm.handle_key(code) {
                        if !self.sessions.is_empty() {
                            let session = &self.sessions[self.selected];
                            for forward in &session.forwards {
                                self.pending_ops.push(SshOp::ForwardCancel {
                                    control_path: session.control_path.clone(),
                                    local_port: forward.local_port,
                                });
                            }
                            let session = &mut self.sessions[self.selected];
                            session.forwards.clear();
                            session.forward_count = 0;
                        }
                        self.action_modal = None;
                    }
                }
                ActionModal::Exit => {
                    if let Some(ConfirmResult::Confirmed) = self.confirm.handle_key(code) {
                        if !self.sessions.is_empty() {
                            let session = &self.sessions[self.selected];
                            self.pending_ops.push(SshOp::ForwardExitSession {
                                control_path: session.control_path.clone(),
                            });
                            self.sessions.remove(self.selected);
                            if self.selected >= self.sessions.len() && !self.sessions.is_empty() {
                                self.selected = self.sessions.len() - 1;
                            }
                            self.clamp_scroll();
                        }
                        self.action_modal = None;
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
                    if !self.sessions.is_empty() && self.selected < self.sessions.len() - 1 {
                        self.selected += 1;
                        self.clamp_scroll();
                    }
                    None
                }
                KeyCode::Enter => {
                    if !self.sessions.is_empty() {
                        self.detail_open = Some(self.selected);
                    }
                    None
                }
                // CRUD shortcuts
                KeyCode::Char('x') => {
                    if !self.sessions.is_empty() {
                        let host = self.sessions[self.selected].host.clone();
                        self.confirm =
                            ConfirmModal::new(format!("Cancel all forwards on \"{host}\"?"));
                        self.action_modal = Some(ActionModal::Cancel);
                    }
                    None
                }
                KeyCode::Char('X') => {
                    if !self.sessions.is_empty() {
                        let host = self.sessions[self.selected].host.clone();
                        self.confirm = ConfirmModal::new(format!("Exit SSH session \"{host}\"?"));
                        self.action_modal = Some(ActionModal::Exit);
                    }
                    None
                }
                _ => None,
            }
        }
    }

    fn view(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        self.row_hitboxes.clear();
        if self.sessions.is_empty() {
            Self::render_empty(frame, area, p);
        } else {
            self.render_list(frame, area, p);
        }

        // Render detail modal if open
        if let Some(idx) = self.detail_open
            && let Some(session) = self.sessions.get(idx).cloned()
        {
            self.render_detail_modal(frame, p, &session);
        }

        // Render action modal on top
        match self.action_modal {
            Some(ActionModal::Cancel) => {
                self.confirm.render(frame, p, "Cancel Forwards");
            }
            Some(ActionModal::Exit) => {
                self.confirm.render(frame, p, "Exit Session");
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

impl ForwardingTab {
    fn render_empty(frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " PORT FORWARDING ", p.text, false);
        let msg = Line::from(vec![
            Span::styled("No active SSH sessions", Style::new().fg(p.text_dim)),
            Span::styled(
                "  ?",
                Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" learn more", Style::new().fg(p.text_muted)),
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
        reason = "terminal cols/rows are bounded < u16::MAX"
    )]
    fn render_list(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        let title = if self.sessions.is_empty() {
            " PORT FORWARDING ".to_owned()
        } else {
            format!(
                " PORT FORWARDING ({} session{}) ",
                self.sessions.len(),
                if self.sessions.len() == 1 { "" } else { "s" }
            )
        };
        let inner = render_titled_panel(frame, area, p, &title, p.text, false);

        if inner.height == 0 {
            return;
        }

        let visible = inner.height as usize;
        let total_rows = self.total_rows();
        let max_scroll = total_rows.saturating_sub(visible);
        if self.scroll > max_scroll {
            self.scroll = max_scroll;
        }

        // Ensure the selected session's first row is visible.
        let sel_start = self.session_row_offset(self.selected);
        let sel_count = self.session_row_count(self.selected);
        if sel_start < self.scroll {
            self.scroll = sel_start;
        } else if sel_start + sel_count > self.scroll + visible {
            self.scroll = sel_start + sel_count - visible;
        }

        // Build flat row list: (session_idx, is_header, forward_idx_within_session)
        let mut flat_rows: Vec<(usize, bool, Option<usize>)> = Vec::new();
        for (si, session) in self.sessions.iter().enumerate() {
            flat_rows.push((si, true, None));
            for (fi, _forward) in session.forwards.iter().enumerate() {
                flat_rows.push((si, false, Some(fi)));
            }
        }

        let mut rendered_row = 0usize;
        for (total_row_idx, (session_idx, is_header, forward_idx)) in flat_rows.iter().enumerate() {
            if total_row_idx < self.scroll {
                continue;
            }
            if rendered_row >= visible {
                break;
            }

            let session = &self.sessions[*session_idx];
            let is_selected = *session_idx == self.selected;
            let is_hovered_session =
                self.hovered_row.and_then(|r| self.session_at_row(r)) == Some(*session_idx);
            let y = inner.y + rendered_row as u16;
            let row_area = Rect::new(inner.x, y, inner.width, 1);

            // Store hitbox for mouse detection.
            self.row_hitboxes.push(row_area);

            // Selection or hover highlight — covers all rows of the session.
            if is_selected || is_hovered_session {
                for x in row_area.x..row_area.right() {
                    if let Some(cell) = frame.buffer_mut().cell_mut((x, y)) {
                        cell.set_bg(if is_selected { p.sel_bg } else { p.bg_alt });
                    }
                }
            }

            let mut spans = Vec::new();

            if *is_header {
                // Session header line: "─ host (pid NNN, Xh Xm)"
                let host_w = 20.min(inner.width.saturating_sub(20) as usize);
                let host = truncate_str(&session.host, host_w);

                spans.push(Span::styled(
                    "─ ",
                    Style::new().fg(if is_selected || is_hovered_session {
                        p.accent
                    } else {
                        p.text_dim
                    }),
                ));
                spans.push(Span::styled(
                    host,
                    Style::new().fg(p.text).add_modifier(Modifier::BOLD),
                ));

                // PID
                if let Some(pid) = session.pid {
                    spans.push(Span::styled(
                        format!(" (pid {pid}"),
                        Style::new().fg(p.text_dim),
                    ));
                    // Uptime
                    spans.push(Span::styled(
                        format!(", {}", session.established_ago),
                        Style::new().fg(p.text_muted),
                    ));
                    spans.push(Span::styled(")", Style::new().fg(p.text_dim)));
                } else {
                    // No PID, just show uptime
                    spans.push(Span::styled(
                        format!(" ({})", session.established_ago),
                        Style::new().fg(p.text_muted),
                    ));
                }

                // Forward count badge
                if !session.forwards.is_empty() {
                    spans.push(Span::styled(
                        format!(" [{}]", session.forwards.len()),
                        Style::new().fg(p.info),
                    ));
                }
            } else {
                // Forward line indented by 2 spaces.
                let fi = forward_idx.unwrap();
                let forward = &session.forwards[fi];

                spans.push(Span::styled("  ", Style::new()));

                // Forward type badge
                let (badge, badge_color) = match forward.forward_type.as_str() {
                    "local" => ("L", p.info),
                    "remote" => ("R", p.accent2),
                    "dynamic" => ("D", p.accent3),
                    _ => ("?", p.text_dim),
                };
                spans.push(Span::styled(
                    format!(" {badge} "),
                    Style::new().fg(badge_color).add_modifier(Modifier::BOLD),
                ));

                spans.push(Span::raw(" "));

                // Local address
                let local = format!("{}:{}", forward.local_addr, forward.local_port);
                let local_w = 22.min(inner.width.saturating_sub(16) as usize);
                spans.push(Span::styled(
                    truncate_str(&local, local_w),
                    Style::new().fg(p.text),
                ));

                // Arrow
                spans.push(Span::styled(" → ", Style::new().fg(p.text_dim)));

                // Remote target
                if forward.forward_type == "dynamic" {
                    spans.push(Span::styled("SOCKS proxy", Style::new().fg(p.text_muted)));
                } else {
                    let remote = format!("{}:{}", forward.remote_addr, forward.remote_port);
                    let remote_w = 20.min(inner.width.saturating_sub(42) as usize);
                    spans.push(Span::styled(
                        truncate_str(&remote, remote_w),
                        Style::new().fg(p.text),
                    ));
                }
            }

            let line = Line::from(spans);
            frame.render_widget(Paragraph::new(line), row_area);
            rendered_row += 1;
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
    fn render_detail_modal(
        &mut self,
        frame: &mut Frame,
        p: Palette,
        session: &ForwardSessionEntry,
    ) {
        let forward_lines = session.forwards.len();
        // Base height: 7 fixed lines + 1 per forward + 1 blank + 1 esc hint
        let content_height = 7 + forward_lines + 2;
        let modal_h = (content_height + 4).min(30) as u16; // +4 for modal chrome
        let modal_w = 56u16;

        let modal = Modal::new("Forwarding Session").dimensions(modal_w, modal_h);
        self.detail_modal_rect = Some(modal.rect(frame.area()));
        let session_clone = session.clone();
        modal.render(frame, p, |frame, content_area| {
            let mut lines: Vec<Line> = Vec::new();

            lines.push(Line::from(vec![
                Span::styled("Host:   ", Style::new().fg(p.text_dim)),
                Span::styled(&session_clone.host, Style::new().fg(p.text).bold()),
            ]));

            lines.push(Line::from(vec![
                Span::styled("Socket: ", Style::new().fg(p.text_dim)),
                Span::styled(
                    truncate_str(&session_clone.control_path, 44),
                    Style::new().fg(p.text),
                ),
            ]));

            lines.push(Line::from(vec![
                Span::styled("PID:    ", Style::new().fg(p.text_dim)),
                Span::styled(
                    session_clone
                        .pid
                        .map_or_else(|| "—".to_owned(), |p| p.to_string()),
                    Style::new().fg(p.text),
                ),
            ]));

            lines.push(Line::from(vec![
                Span::styled("Uptime: ", Style::new().fg(p.text_dim)),
                Span::styled(&session_clone.established_ago, Style::new().fg(p.text)),
            ]));

            lines.push(Line::from(vec![
                Span::styled("Forwards: ", Style::new().fg(p.text_dim)),
                Span::styled(
                    format!("{}", session_clone.forward_count),
                    Style::new().fg(p.info),
                ),
            ]));

            lines.push(Line::raw(""));

            for forward in &session_clone.forwards {
                let (badge, badge_color) = match forward.forward_type.as_str() {
                    "local" => ("L", p.info),
                    "remote" => ("R", p.accent2),
                    "dynamic" => ("D", p.accent3),
                    _ => ("?", p.text_dim),
                };

                if forward.forward_type == "dynamic" {
                    lines.push(Line::from(vec![
                        Span::styled(
                            format!(" {badge} "),
                            Style::new().fg(badge_color).add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!(
                                "{}:{} → SOCKS proxy",
                                forward.local_addr, forward.local_port
                            ),
                            Style::new().fg(p.text),
                        ),
                    ]));
                } else {
                    lines.push(Line::from(vec![
                        Span::styled(
                            format!(" {badge} "),
                            Style::new().fg(badge_color).add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!(
                                "{}:{} → {}:{}",
                                forward.local_addr,
                                forward.local_port,
                                forward.remote_addr,
                                forward.remote_port
                            ),
                            Style::new().fg(p.text),
                        ),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_sessions() -> Vec<ForwardSessionEntry> {
        use super::super::ForwardEntry;
        vec![
            ForwardSessionEntry {
                host: "prod-web".into(),
                control_path: "/tmp/ssh-prod-web".into(),
                pid: Some(12345),
                established_ago: "2h 15m".into(),
                forwards: vec![
                    ForwardEntry {
                        forward_type: "local".into(),
                        local_addr: "127.0.0.1".into(),
                        local_port: 8080,
                        remote_addr: "localhost".into(),
                        remote_port: 80,
                    },
                    ForwardEntry {
                        forward_type: "remote".into(),
                        local_addr: "0.0.0.0".into(),
                        local_port: 9090,
                        remote_addr: "localhost".into(),
                        remote_port: 9090,
                    },
                ],
                forward_count: 2,
            },
            ForwardSessionEntry {
                host: "bastion".into(),
                control_path: "/tmp/ssh-bastion".into(),
                pid: Some(67890),
                established_ago: "45m".into(),
                forwards: vec![ForwardEntry {
                    forward_type: "dynamic".into(),
                    local_addr: "127.0.0.1".into(),
                    local_port: 1080,
                    remote_addr: "SOCKS".into(),
                    remote_port: 0,
                }],
                forward_count: 1,
            },
        ]
    }

    #[test]
    fn new_is_empty() {
        let tab = ForwardingTab::new();
        assert!(tab.sessions.is_empty());
        assert!(!tab.has_modal());
    }

    #[test]
    fn set_sessions_updates_list() {
        let mut tab = ForwardingTab::new();
        tab.set_sessions(sample_sessions());
        assert_eq!(tab.sessions.len(), 2);
    }

    #[test]
    fn scroll_up_decrements_selected() {
        let mut tab = ForwardingTab::new();
        tab.set_sessions(sample_sessions());
        tab.selected = 1;
        tab.handle_key(KeyCode::Up);
        assert_eq!(tab.selected, 0);
    }

    #[test]
    fn scroll_down_increments_selected() {
        let mut tab = ForwardingTab::new();
        tab.set_sessions(sample_sessions());
        tab.selected = 0;
        tab.handle_key(KeyCode::Down);
        assert_eq!(tab.selected, 1);
    }

    #[test]
    fn scroll_up_at_zero_stays() {
        let mut tab = ForwardingTab::new();
        tab.set_sessions(sample_sessions());
        tab.selected = 0;
        tab.handle_key(KeyCode::Up);
        assert_eq!(tab.selected, 0);
    }

    #[test]
    fn scroll_down_at_end_stays() {
        let mut tab = ForwardingTab::new();
        tab.set_sessions(sample_sessions());
        tab.selected = 1;
        tab.handle_key(KeyCode::Down);
        assert_eq!(tab.selected, 1);
    }

    #[test]
    fn enter_opens_detail_modal() {
        let mut tab = ForwardingTab::new();
        tab.set_sessions(sample_sessions());
        tab.handle_key(KeyCode::Enter);
        assert!(tab.has_modal());
        assert_eq!(tab.detail_open, Some(0));
    }

    #[test]
    fn esc_closes_detail_modal() {
        let mut tab = ForwardingTab::new();
        tab.set_sessions(sample_sessions());
        tab.detail_open = Some(0);
        tab.handle_key(KeyCode::Esc);
        assert!(!tab.has_modal());
    }

    #[test]
    fn render_empty_state() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = ForwardingTab::new();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("No active SSH sessions"),
            "empty state: {output}"
        );
    }

    #[test]
    fn render_with_sessions() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = ForwardingTab::new();
        tab.set_sessions(sample_sessions());
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains("prod-web"), "session host: {output}");
    }

    #[test]
    fn render_detail_modal() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = ForwardingTab::new();
        tab.set_sessions(sample_sessions());
        tab.detail_open = Some(0);
        let mut terminal = Terminal::new(TestBackend::new(80, 30)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("Forwarding Session"),
            "modal title: {output}"
        );
        assert!(output.contains("prod-web"), "host in modal: {output}");
    }

    #[test]
    fn set_sessions_clamps_selected() {
        let mut tab = ForwardingTab::new();
        tab.selected = 5;
        tab.set_sessions(sample_sessions()); // 2 items
        assert!(tab.selected < 2);
    }

    #[test]
    fn total_rows_counts_correctly() {
        let mut tab = ForwardingTab::new();
        tab.set_sessions(sample_sessions());
        // session 0: 1 header + 2 forwards = 3
        // session 1: 1 header + 1 forward = 2
        assert_eq!(tab.total_rows(), 5);
    }

    #[test]
    fn session_row_offset_computes_correctly() {
        let mut tab = ForwardingTab::new();
        tab.set_sessions(sample_sessions());
        assert_eq!(tab.session_row_offset(0), 0);
        assert_eq!(tab.session_row_offset(1), 3); // session 0 takes 3 rows
    }

    #[test]
    fn session_at_row_returns_correct_session() {
        let mut tab = ForwardingTab::new();
        tab.set_sessions(sample_sessions());
        assert_eq!(tab.session_at_row(0), Some(0)); // header of session 0
        assert_eq!(tab.session_at_row(1), Some(0)); // forward 0 of session 0
        assert_eq!(tab.session_at_row(2), Some(0)); // forward 1 of session 0
        assert_eq!(tab.session_at_row(3), Some(1)); // header of session 1
        assert_eq!(tab.session_at_row(4), Some(1)); // forward 0 of session 1
        assert_eq!(tab.session_at_row(5), None); // past end
    }
}
