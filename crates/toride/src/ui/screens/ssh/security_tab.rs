//! Security Overview sub-tab for the SSH management screen.
//!
//! A scrollable dashboard (security grade, server config checks, auth methods,
//! access summary, known hosts, warnings) plus an **interactive SSH USERS
//! list**. Each system user can be opened into a detail modal where their login
//! access can be toggled via `AllowUsers`/`DenyUsers` in `/etc/ssh/sshd_config`.
//!
//! Navigation:
//! - `j/k` or `↑/↓` move the SSH USERS selection (when users exist) and the
//!   view auto-scrolls to keep the selection visible. When there are no users
//!   (e.g. no readable `sshd_config`), the same keys scroll the dashboard.
//! - Mouse wheel scrolls the dashboard freely; clicking a user selects it and
//!   opens its detail modal.
//! - In the detail modal: `a` allow login, `d` deny (confirm), `r` reset
//!   (confirm), `Esc` close. Writes are applied optimistically in memory and
//!   forwarded to the app's SSH op pipeline.

use crossterm::event::{KeyCode, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use super::DiagnosticEntry;
use crate::action::Action;
use crate::ssh_data::{SshOp, SshSecurityData};
use crate::ui::responsive::truncate_str;
use crate::ui::theme::Palette;
use crate::ui::widgets::{
    ConfirmModal, ConfirmResult, InteractiveModal, ModalEvent, render_titled_panel,
};

use super::{SshAccessInfo, SshTab, SystemUserInfo};

// ── UserAction ────────────────────────────────────────────────────────────────

/// An access-control action the user can take on a system user from the detail
/// modal. Used as the (display-only) modal's action type and to track which
/// destructive action is awaiting confirmation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UserAction {
    /// Add to `AllowUsers` (and remove from `DenyUsers`).
    AllowLogin,
    /// Add to `DenyUsers`.
    DenyLogin,
    /// Remove from both `AllowUsers` and `DenyUsers`.
    ResetAccess,
}

// ── SecurityTab ────────────────────────────────────────────────────────────────

/// State for the Security Overview sub-tab.
pub struct SecurityTab {
    /// Security data to display.
    data: Option<SshSecurityData>,
    /// Vertical scroll offset of the dashboard.
    scroll: usize,
    /// Total content height (recalculated each frame).
    content_height: usize,
    /// Absolute line indices (within the built dashboard) of each displayed SSH
    /// USERS row, in display order. Populated each frame; empty when the
    /// section is hidden or has no users.
    user_row_line_indices: Vec<usize>,
    /// Hitbox rects for SSH USERS rows (rebuilt each frame).
    row_hitboxes: Vec<Rect>,
    /// Index of the currently selected SSH user (into `data.system_users`).
    selected_user: usize,
    /// Which row is hovered by the mouse (user-list index).
    hovered_row: Option<usize>,
    /// Username shown in the detail modal (if open). Tracked by name rather
    /// than positional index so a mid-modal refresh that reshapes the user
    /// list cannot silently flip the modal (and the a/d/r targets) onto a
    /// different user. Each frame the name is re-resolved to the current
    /// index in `data.system_users`; if the name is gone the modal closes.
    detail_user: Option<String>,
    /// Interactive detail modal (display-only; action keys are intercepted in
    /// `handle_key` so `a`/`d`/`r`/`Esc` get direct handling).
    detail_modal: InteractiveModal<UserAction>,
    /// Confirm modal for destructive actions (deny / reset).
    confirm: ConfirmModal,
    /// Which destructive action is awaiting confirmation, if any.
    pending_confirm: Option<UserAction>,
    /// Pending write operations to forward to `SshContent`.
    pending_ops: Vec<SshOp>,
}

impl SecurityTab {
    /// Create a new empty security tab.
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: None,
            scroll: 0,
            content_height: 0,
            user_row_line_indices: Vec::new(),
            row_hitboxes: Vec::new(),
            selected_user: 0,
            hovered_row: None,
            detail_user: None,
            detail_modal: InteractiveModal::display("User Access").dimensions(56, 18),
            confirm: ConfirmModal::new(""),
            pending_confirm: None,
            pending_ops: Vec::new(),
        }
    }

    /// Replace the security data with new data.
    pub fn set_data(&mut self, data: SshSecurityData) {
        let structurally_changed = match &self.data {
            None => true,
            Some(old) => {
                old.checks().len() != data.checks().len()
                    || old.system_users.len() != data.system_users.len()
            }
        };
        // Clamp the selection into the new user list.
        if data.system_users.is_empty() {
            self.selected_user = 0;
        } else if self.selected_user >= data.system_users.len() {
            self.selected_user = data.system_users.len() - 1;
        }
        // If the detail modal is open on a username that's gone, close it.
        // (Tracked by name, not index, so a reorder never flips the modal.)
        if let Some(name) = &self.detail_user
            && !data.system_users.iter().any(|u| &u.username == name)
        {
            self.detail_modal.close();
            self.detail_user = None;
        }
        self.data = Some(data);
        if structurally_changed {
            self.scroll = 0;
        }
        // Otherwise preserve scroll; the render path will clamp it.
    }

    /// Number of displayed SSH USERS rows (capped at 10 in the dashboard).
    fn displayed_user_count(data: &SshSecurityData) -> usize {
        data.system_users.len().min(10)
    }
}

impl Default for SecurityTab {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityTab {
    /// Number of selectable SSH USERS rows currently available.
    fn selectable_count(&self) -> usize {
        self.data.as_ref().map_or(0, Self::displayed_user_count)
    }

    /// Resolve a screen coordinate to a displayed SSH USERS row index.
    fn row_at(&self, col: u16, row: u16) -> Option<usize> {
        self.row_hitboxes.iter().position(|rect| {
            col >= rect.x && col < rect.right() && row >= rect.y && row < rect.bottom()
        })
    }

    /// Adjust `scroll` so the selected user's row stays within the viewport,
    /// using the last frame's recorded row positions.
    fn keep_selected_visible(&mut self, visible: usize) {
        let Some(&target) = self.user_row_line_indices.get(self.selected_user) else {
            return;
        };
        if self.scroll > target {
            self.scroll = target;
        } else if target >= self.scroll + visible {
            self.scroll = target - visible + 1;
        }
    }

    /// Move the SSH USERS selection by `delta`, clamping to the list.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "selection index is bounded by list length < i32::MAX"
    )]
    #[expect(
        clippy::cast_possible_wrap,
        reason = "selection index is bounded by list length < i32::MAX"
    )]
    #[expect(clippy::cast_sign_loss, reason = "clamped value is non-negative")]
    fn move_selection(&mut self, delta: i32, visible: usize) {
        let count = self.selectable_count();
        if count == 0 {
            return;
        }
        let cur = self.selected_user as i32;
        let next = cur + delta;
        self.selected_user = next.clamp(0, (count - 1) as i32) as usize;
        self.keep_selected_visible(visible);
    }

    /// Open the detail modal for the currently selected user.
    fn open_detail(&mut self) {
        if self.selectable_count() > 0
            && let Some(user) = self
                .data
                .as_ref()
                .and_then(|d| d.system_users.get(self.selected_user))
        {
            self.detail_user = Some(user.username.clone());
            self.detail_modal.open();
        }
    }

    /// Resolve the open detail modal's username to its current index in
    /// `data.system_users` (the list may have been reshaped by a refresh).
    /// Returns `None` if the modal isn't open or the user is no longer present.
    fn detail_index(&self) -> Option<usize> {
        let name = self.detail_user.as_ref()?;
        self.data
            .as_ref()
            .and_then(|d| d.system_users.iter().position(|u| &u.username == name))
    }

    // ── Access actions (optimistic in-memory + push SshOp) ──────────────────

    /// Apply a (confirmed) access action to the selected/detail user, updating
    /// `access_info` optimistically and queueing the matching `SshOp`.
    fn apply_action(&mut self, action: UserAction) {
        // Re-resolve the modal target by username each time: a refresh may
        // have reordered the user list, so the live index can differ from the
        // one captured when the modal was opened.
        let Some(idx) = self.detail_index().or_else(|| {
            if self.selectable_count() > 0 {
                Some(self.selected_user)
            } else {
                None
            }
        }) else {
            return;
        };
        let Some(data) = self.data.as_mut() else {
            return;
        };
        let Some(user) = data.system_users.get(idx).cloned() else {
            return;
        };
        let username = user.username.clone();
        let access = &mut data.access_info;
        match action {
            UserAction::AllowLogin => {
                if !access.allowed_users.iter().any(|u| u == &username) {
                    access.allowed_users.push(username.clone());
                }
                access.denied_users.retain(|u| u != &username);
                self.pending_ops.push(SshOp::SshdAllowUser { username });
            }
            UserAction::DenyLogin => {
                if !access.denied_users.iter().any(|u| u == &username) {
                    access.denied_users.push(username.clone());
                }
                // Mirror SshdDenyUser's edit() (and ResetAccess): a user being
                // denied is also removed from the allow list, so the in-memory
                // state matches the persisted config (no contradictory both-lists).
                access.allowed_users.retain(|u| u != &username);
                self.pending_ops.push(SshOp::SshdDenyUser { username });
            }
            UserAction::ResetAccess => {
                access.allowed_users.retain(|u| u != &username);
                access.denied_users.retain(|u| u != &username);
                self.pending_ops
                    .push(SshOp::SshdResetUserAccess { username });
            }
        }
    }

    /// Request confirmation for a destructive action (deny/reset), or apply it
    /// directly if non-destructive.
    fn trigger_action(&mut self, action: UserAction) {
        match action {
            UserAction::AllowLogin => self.apply_action(UserAction::AllowLogin),
            UserAction::DenyLogin | UserAction::ResetAccess => {
                let username = self
                    .detail_index()
                    .or_else(|| {
                        if self.selectable_count() > 0 {
                            Some(self.selected_user)
                        } else {
                            None
                        }
                    })
                    .and_then(|i| self.data.as_ref().and_then(|d| d.system_users.get(i)))
                    .map(|u| u.username.clone())
                    .unwrap_or_default();
                let verb = match action {
                    UserAction::DenyLogin => "deny SSH login for",
                    UserAction::ResetAccess => "reset SSH access for",
                    UserAction::AllowLogin => "allow",
                };
                self.confirm = ConfirmModal::new(format!(
                    "{verb} \"{username}\"?\nThis edits /etc/ssh/sshd_config."
                ));
                self.pending_confirm = Some(action);
            }
        }
    }
}

impl SshTab for SecurityTab {
    fn handle_key(&mut self, code: KeyCode) -> Option<Action> {
        let visible = self.content_height;

        // ── Confirm modal open: it sits on top of the detail modal, so it
        //     takes input priority (otherwise the detail modal underneath
        //     would swallow the y/n confirm keys). ──
        if self.pending_confirm.is_some() {
            if let Some(result) = self.confirm.handle_key(code) {
                match result {
                    ConfirmResult::Confirmed => {
                        if let Some(action) = self.pending_confirm.take() {
                            self.apply_action(action);
                        }
                    }
                    ConfirmResult::Cancelled => {
                        self.pending_confirm = None;
                    }
                }
            }
            return None;
        }

        // ── Detail modal open: intercept action shortcuts, else delegate. ──
        if self.detail_modal.is_visible() {
            match code {
                KeyCode::Char('a') => {
                    self.trigger_action(UserAction::AllowLogin);
                    return None;
                }
                KeyCode::Char('d') => {
                    self.trigger_action(UserAction::DenyLogin);
                    return None;
                }
                KeyCode::Char('r') => {
                    self.trigger_action(UserAction::ResetAccess);
                    return None;
                }
                _ => {}
            }
            match self.detail_modal.handle_key(code) {
                ModalEvent::Closed => self.detail_user = None,
                ModalEvent::Consumed | ModalEvent::Button(_) => {}
            }
            return None;
        }

        // ── Dashboard / user list navigation. ──
        match code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selectable_count() > 0 {
                    self.move_selection(-1, visible);
                } else if self.scroll > 0 {
                    self.scroll -= 1;
                }
                None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selectable_count() > 0 {
                    self.move_selection(1, visible);
                } else {
                    let max_scroll = self.content_height.saturating_sub(1);
                    if self.scroll < max_scroll {
                        self.scroll += 1;
                    }
                }
                None
            }
            KeyCode::Enter => {
                self.open_detail();
                None
            }
            _ => None,
        }
    }

    fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action> {
        // Confirm modal open: it sits on top of the detail modal, so it takes
        // input priority — a click on the confirm buttons must reach the
        // ConfirmModal, not be swallowed by the detail modal underneath.
        if self.pending_confirm.is_some() {
            if let Some(result) = self.confirm.handle_mouse(&mouse) {
                match result {
                    ConfirmResult::Confirmed => {
                        if let Some(action) = self.pending_confirm.take() {
                            self.apply_action(action);
                        }
                    }
                    ConfirmResult::Cancelled => {
                        self.pending_confirm = None;
                    }
                }
            }
            return None;
        }

        // Detail modal open: delegate for click-outside-to-close.
        if self.detail_modal.is_visible() {
            if let ModalEvent::Closed = self.detail_modal.handle_mouse(&mouse) {
                self.detail_user = None;
            }
            return None;
        }

        match mouse.kind {
            MouseEventKind::Moved | MouseEventKind::Drag(_) => {
                self.hovered_row = self.row_at(mouse.column, mouse.row);
            }
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some(idx) = self.row_at(mouse.column, mouse.row) {
                    self.selected_user = idx;
                    if let Some(user) = self.data.as_ref().and_then(|d| d.system_users.get(idx)) {
                        self.detail_user = Some(user.username.clone());
                        self.detail_modal.open();
                    }
                }
            }
            MouseEventKind::ScrollUp => {
                if self.scroll > 0 {
                    self.scroll -= 1;
                }
            }
            MouseEventKind::ScrollDown => {
                let max_scroll = self.content_height.saturating_sub(1);
                if self.scroll < max_scroll {
                    self.scroll += 1;
                }
            }
            _ => {}
        }
        None
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "terminal cols/rows are bounded < u16::MAX"
    )]
    fn view(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " SECURITY OVERVIEW ", p.text, false);

        if inner.height == 0 {
            return;
        }

        if self.data.is_none() {
            let msg = Line::from(Span::styled(
                "Loading security data..",
                Style::new().fg(p.text_dim),
            ));
            let centered = Rect::new(inner.x, inner.y + inner.height / 2, inner.width, 1);
            frame.render_widget(Paragraph::new(msg).centered(), centered);
            return;
        }

        // Build lines + the absolute line indices of SSH USERS rows.
        let data_ref = self.data.as_ref().unwrap();
        let (lines, user_indices) = Self::build_lines(data_ref, p, inner.width);
        self.content_height = lines.len();
        self.user_row_line_indices = user_indices;

        let visible = inner.height as usize;
        let max_scroll = self.content_height.saturating_sub(visible);
        if self.scroll > max_scroll {
            self.scroll = max_scroll;
        }

        let skip = self.scroll;
        let take = visible;
        let selected = self.selected_user;
        let hovered = self.hovered_row;
        let mut new_hitboxes: Vec<Rect> = Vec::new();

        for (row, line) in lines.into_iter().enumerate() {
            if row < skip {
                continue;
            }
            if row >= skip + take {
                break;
            }
            let y = inner.y + (row - skip) as u16;
            if y >= inner.bottom() {
                break;
            }
            let row_area = Rect::new(inner.x, y, inner.width, 1);

            // SSH USERS row: track hitbox + apply selection/hover highlight.
            if let Some(u) = self.user_row_line_indices.iter().position(|&r| r == row) {
                new_hitboxes.push(row_area);
                let is_selected = u == selected;
                let is_hovered = hovered == Some(u);
                if is_selected || is_hovered {
                    let bg = if is_selected { p.sel_bg } else { p.bg_alt };
                    for x in row_area.x..row_area.right() {
                        if let Some(cell) = frame.buffer_mut().cell_mut((x, y)) {
                            cell.set_bg(bg);
                        }
                    }
                }
            }

            frame.render_widget(Paragraph::new(line), row_area);
        }

        self.row_hitboxes = new_hitboxes;

        // Render the detail modal on top. Re-resolve the tracked username to
        // its current index; if the user disappeared (handled in set_data, but
        // guard again here for the no-refresh edge case) the modal is skipped.
        if let Some(idx) = self.detail_index()
            && let Some(user) = self
                .data
                .as_ref()
                .and_then(|d| d.system_users.get(idx))
                .cloned()
        {
            let access = self
                .data
                .as_ref()
                .map(|d| d.access_info.clone())
                .unwrap_or_default();
            let is_root = self.data.as_ref().is_some_and(|d| d.is_root);
            self.render_detail_modal(frame, p, &user, &access, is_root);
        }

        // Render the confirm modal above the detail modal.
        if self.pending_confirm.is_some() {
            self.confirm.render(frame, p, "Confirm");
        }
    }

    fn has_modal(&self) -> bool {
        self.detail_modal.is_visible() || self.pending_confirm.is_some()
    }

    fn close_modal(&mut self) {
        self.detail_modal.close();
        self.detail_user = None;
        self.pending_confirm = None;
    }

    fn drain_ops(&mut self) -> Vec<SshOp> {
        std::mem::take(&mut self.pending_ops)
    }
}

// ── Line builders ──────────────────────────────────────────────────────────────

impl SecurityTab {
    /// Build all dashboard lines from security data.
    ///
    /// Returns the lines plus the absolute line indices (within the returned
    /// vec) of each displayed SSH USERS row, in display order. Used by `view`
    /// to apply selection highlights and record mouse hitboxes.
    #[expect(
        clippy::too_many_lines,
        reason = "dashboard line builder kept whole for clarity"
    )]
    fn build_lines(
        data: &SshSecurityData,
        p: Palette,
        inner_width: u16,
    ) -> (Vec<Line<'static>>, Vec<usize>) {
        let mut lines = Vec::new();
        let mut user_indices: Vec<usize> = Vec::new();
        let checks = data.checks();
        let grade = data.grade();

        // 1. Grade banner
        lines.push(Line::from(vec![
            Span::styled("  Grade: ", Style::new().fg(p.text_dim)),
            Span::styled(
                grade.label(),
                Style::new().fg(grade.color(p)).add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::raw(""));

        // 2. Server config section header
        lines.push(Line::from(Span::styled(
            "SERVER CONFIG",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        // 3. Check rows (up to 8)
        let w = inner_width as usize;
        // label_col + detail_col + icon ≈ w; reserve 4 for indent and icon
        let label_col = 24.min(w.saturating_sub(4) / 2);
        let detail_col = 24.min(w.saturating_sub(label_col + 4));
        for check in &checks {
            let icon = if check.informational {
                Span::styled(" ·", Style::new().fg(p.text_muted))
            } else if check.passing {
                Span::styled(" ✓", Style::new().fg(p.ok))
            } else {
                Span::styled(" ✗", Style::new().fg(p.err))
            };

            let label_display = crate::ui::responsive::truncate_str(&check.label, label_col);
            let detail_display = crate::ui::responsive::truncate_str(&check.detail, detail_col);

            lines.push(Line::from(vec![
                Span::styled("  ", Style::new()),
                Span::styled(
                    format!("{label_display:label_col$}"),
                    Style::new().fg(p.text),
                ),
                Span::styled(
                    format!("{detail_display:detail_col$}"),
                    Style::new().fg(p.text_dim),
                ),
                icon,
            ]));
        }

        // 4. Empty line
        lines.push(Line::raw(""));

        // ── AUTH METHODS / USER ACCESS / SSH USERS sections ────────────
        // Only show these when sshd_config was readable on this machine.
        // Without it, we'd show misleading defaults (e.g. on macOS there
        // is no /etc/ssh/sshd_config and /etc/passwd is mostly daemons).
        if data.access_info.available {
            // Spacer
            lines.push(Line::raw(""));

            // ── AUTH METHODS section ──────────────────────────────────────
            lines.push(Line::from(Span::styled(
                "AUTH METHODS",
                Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
            )));

            // Password auth
            if data.access_info.password_auth {
                lines.push(Line::from(vec![Span::styled(
                    "  ✓ Password",
                    Style::new().fg(p.ok),
                )]));
            } else {
                lines.push(Line::from(vec![Span::styled(
                    "  ✗ Password",
                    Style::new().fg(p.err),
                )]));
            }

            // Key auth
            if data.access_info.pubkey_auth {
                lines.push(Line::from(vec![Span::styled(
                    "  ✓ Public Key",
                    Style::new().fg(p.ok),
                )]));
            } else {
                lines.push(Line::from(vec![Span::styled(
                    "  ✗ Public Key",
                    Style::new().fg(p.err),
                )]));
            }

            // Root login
            let root_login = &data.access_info.permit_root_login;
            let root_color = match root_login.as_str() {
                "yes" => p.warn,
                "no" => p.ok,
                _ => p.info, // "prohibit-password" or "forced-commands-only"
            };
            lines.push(Line::from(vec![
                Span::styled("  Root login: ", Style::new().fg(p.text)),
                Span::styled(root_login.clone(), Style::new().fg(root_color)),
            ]));

            // Auth methods
            if !data.access_info.auth_methods.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("  Methods: ", Style::new().fg(p.text)),
                    Span::styled(
                        data.access_info.auth_methods.join(", "),
                        Style::new().fg(p.text_dim),
                    ),
                ]));
            }

            // Spacer
            lines.push(Line::raw(""));

            // ── USER ACCESS section ───────────────────────────────────────
            lines.push(Line::from(Span::styled(
                "USER ACCESS",
                Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
            )));

            let access = &data.access_info;
            let all_empty = access.allowed_users.is_empty()
                && access.denied_users.is_empty()
                && access.allowed_groups.is_empty()
                && access.denied_groups.is_empty();

            if all_empty {
                lines.push(Line::from(vec![Span::styled(
                    "  All users allowed (no restrictions)",
                    Style::new().fg(p.text_dim),
                )]));
            } else {
                // Allowed users
                if access.allowed_users.is_empty() {
                    lines.push(Line::from(vec![
                        Span::styled("  Users: ", Style::new().fg(p.text)),
                        Span::styled("All users", Style::new().fg(p.text_dim)),
                    ]));
                } else {
                    let mut spans = vec![Span::styled("  Users: ", Style::new().fg(p.text))];
                    for (i, user) in access.allowed_users.iter().enumerate() {
                        if i > 0 {
                            spans.push(Span::styled(" ", Style::new()));
                        }
                        spans.push(Span::styled(format!(" {user} "), Style::new().fg(p.info)));
                    }
                    lines.push(Line::from(spans));
                }

                // Denied users
                if !access.denied_users.is_empty() {
                    let mut spans = vec![Span::styled("  Denied: ", Style::new().fg(p.text))];
                    for (i, user) in access.denied_users.iter().enumerate() {
                        if i > 0 {
                            spans.push(Span::styled(" ", Style::new()));
                        }
                        spans.push(Span::styled(format!(" {user} "), Style::new().fg(p.err)));
                    }
                    lines.push(Line::from(spans));
                }

                // Allowed groups
                if !access.allowed_groups.is_empty() {
                    let mut spans = vec![Span::styled("  Groups: ", Style::new().fg(p.text))];
                    for (i, group) in access.allowed_groups.iter().enumerate() {
                        if i > 0 {
                            spans.push(Span::styled(" ", Style::new()));
                        }
                        spans.push(Span::styled(format!(" @{group} "), Style::new().fg(p.info)));
                    }
                    lines.push(Line::from(spans));
                }

                // Denied groups
                if !access.denied_groups.is_empty() {
                    let mut spans =
                        vec![Span::styled("  Denied groups: ", Style::new().fg(p.text))];
                    for (i, group) in access.denied_groups.iter().enumerate() {
                        if i > 0 {
                            spans.push(Span::styled(" ", Style::new()));
                        }
                        spans.push(Span::styled(format!(" @{group} "), Style::new().fg(p.err)));
                    }
                    lines.push(Line::from(spans));
                }
            }

            // Spacer
            lines.push(Line::raw(""));

            // ── SSH USERS section ─────────────────────────────────────────
            lines.push(Line::from(Span::styled(
                "SSH USERS",
                Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
            )));

            if data.system_users.is_empty() {
                lines.push(Line::from(vec![Span::styled(
                    "  No SSH users with keys configured",
                    Style::new().fg(p.text_dim),
                )]));
            } else {
                let display_users: Vec<_> = data.system_users.iter().take(10).collect();
                let overflow = data.system_users.len().saturating_sub(10);

                for user in &display_users {
                    let key_status = if user.ssh_key_count > 0 || user.authorized_key_count > 0 {
                        let mut parts = Vec::new();
                        if user.ssh_key_count > 0 {
                            parts.push(format!(
                                "{} key{}",
                                user.ssh_key_count,
                                if user.ssh_key_count > 1 { "s" } else { "" }
                            ));
                        }
                        if user.authorized_key_count > 0 {
                            parts.push(format!(
                                "{} auth{}",
                                user.authorized_key_count,
                                if user.authorized_key_count > 1 {
                                    "s"
                                } else {
                                    ""
                                }
                            ));
                        }
                        Span::styled(parts.join(", "), Style::new().fg(p.accent))
                    } else {
                        Span::styled("No keys", Style::new().fg(p.text_dim))
                    };
                    // Dynamically size columns based on available width
                    let name_w = 16.min(w.saturating_sub(6) / 3);
                    let shell_w = 24.min(w.saturating_sub(name_w + 6) / 2);
                    let name_display = truncate_str(&user.username, name_w);
                    let shell_display = truncate_str(&user.shell, shell_w);
                    // Record this row's absolute line index before pushing it.
                    user_indices.push(lines.len());
                    lines.push(Line::from(vec![
                        Span::styled("  ", Style::new()),
                        Span::styled(format!("{name_display:name_w$}"), Style::new().fg(p.text)),
                        Span::styled(
                            format!("{shell_display:shell_w$}"),
                            Style::new().fg(p.text_dim),
                        ),
                        key_status,
                    ]));
                }

                if overflow > 0 {
                    lines.push(Line::from(vec![Span::styled(
                        format!("  +{overflow} more"),
                        Style::new().fg(p.text_dim),
                    )]));
                }
            }

            // Spacer
            lines.push(Line::raw(""));
        } // end available block

        // Spacer
        lines.push(Line::raw(""));

        // 5. Access section header
        lines.push(Line::from(Span::styled(
            "ACCESS",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        // 6. Authorized keys summary
        let key_count = data.authorized_key_count;
        let labels_joined = if data.authorized_key_labels.is_empty() {
            "none".to_string()
        } else {
            data.authorized_key_labels.join(" · ")
        };

        lines.push(Line::from(vec![Span::styled(
            format!("  {key_count} keys can access this machine"),
            Style::new().fg(p.text),
        )]));
        if !data.authorized_key_labels.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("  ", Style::new()),
                Span::styled(labels_joined, Style::new().fg(p.text_dim)),
            ]));
        }

        // 7. Empty line
        lines.push(Line::raw(""));

        // 8. Known hosts section header
        lines.push(Line::from(Span::styled(
            "KNOWN HOSTS",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        // 9. Known hosts summary
        let hosts_count = data.known_hosts_count;
        let hashed_count = data.known_hosts_hashed_count;
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {hosts_count} hosts trusted"),
                Style::new().fg(p.text),
            ),
            Span::styled(" · ", Style::new().fg(p.text_muted)),
            Span::styled(
                format!("{hashed_count} hashed"),
                Style::new().fg(p.text_dim),
            ),
        ]));

        // 10. Empty line
        lines.push(Line::raw(""));

        // 11. Warnings section
        let warnings: Vec<&DiagnosticEntry> = data
            .security_diagnostics
            .iter()
            .filter(|d| d.severity == "warning" || d.severity == "error")
            .collect();

        if warnings.is_empty() {
            lines.push(Line::from(Span::styled(
                "ALL CLEAR",
                Style::new().fg(p.ok).add_modifier(Modifier::BOLD),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                "WARNINGS",
                Style::new().fg(p.warn).add_modifier(Modifier::BOLD),
            )));
            for w in &warnings {
                lines.push(Line::from(vec![
                    Span::styled("  ! ", Style::new().fg(p.warn)),
                    Span::styled(w.message.clone(), Style::new().fg(p.text)),
                ]));
                if let Some(ref hint) = w.hint {
                    lines.push(Line::from(vec![
                        Span::styled("    → ", Style::new().fg(p.text_muted)),
                        Span::styled(hint.clone(), Style::new().fg(p.text_dim)),
                    ]));
                }
            }
        }

        // 12. Footer — context-aware key hints.
        lines.push(Line::raw(""));
        let footer_spans = if data.system_users.is_empty() {
            vec![
                Span::styled("  j/k ", p.key_style()),
                Span::styled("scroll", p.label_style()),
            ]
        } else {
            vec![
                Span::styled("  j/k ", p.key_style()),
                Span::styled("select user", p.label_style()),
                Span::styled("  ↵ ", p.key_style()),
                Span::styled("detail", p.label_style()),
                Span::styled("  wheel ", p.key_style()),
                Span::styled("scroll", p.label_style()),
            ]
        };
        lines.push(Line::from(footer_spans));

        (lines, user_indices)
    }
}

// ── Detail modal ──────────────────────────────────────────────────────────────

impl SecurityTab {
    /// Compute the login status of `username` against the current `sshd_config`
    /// access rules, returning (icon, label, color).
    ///
    /// Order matters: an explicit `DenyUsers` entry always wins; otherwise a
    /// non-empty `AllowUsers` list acts as a whitelist; group-based rules are
    /// reported as ambiguous (we can't resolve group membership here); and the
    /// default (no restrictions) is "allowed".
    fn login_status(username: &str, access: &SshAccessInfo, p: Palette) -> (String, String, Color) {
        if access.denied_users.iter().any(|u| u == username) {
            ("✗".into(), "denied (DenyUsers)".into(), p.err)
        } else if !access.allowed_users.is_empty()
            && !access.allowed_users.iter().any(|u| u == username)
        {
            ("✗".into(), "not in allowlist".into(), p.err)
        } else if !access.allowed_groups.is_empty() || !access.denied_groups.is_empty() {
            ("~".into(), "via group rules".into(), p.warn)
        } else {
            ("✓".into(), "allowed".into(), p.ok)
        }
    }

    /// Render the user detail modal: shell, home, computed login status, the
    /// user's authorized keys (read-only in Phase 1), and action key hints.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "terminal cols/rows are bounded < u16::MAX"
    )]
    fn render_detail_modal(
        &mut self,
        frame: &mut Frame,
        p: Palette,
        user: &SystemUserInfo,
        access: &SshAccessInfo,
        is_root: bool,
    ) {
        let (status_icon, status_label, status_color) =
            Self::login_status(&user.username, access, p);

        self.detail_modal.render(frame, p, |frame, content_area| {
            let mut lines: Vec<Line> = vec![
                Line::from(vec![
                    Span::styled("User:   ", Style::new().fg(p.text_dim)),
                    Span::styled(
                        &user.username,
                        Style::new().fg(p.text).add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Shell:  ", Style::new().fg(p.text_dim)),
                    Span::styled(&user.shell, Style::new().fg(p.text)),
                ]),
                Line::from(vec![
                    Span::styled("Home:   ", Style::new().fg(p.text_dim)),
                    Span::styled(&user.home_dir, Style::new().fg(p.text)),
                ]),
                Line::from(vec![
                    Span::styled("Login:  ", Style::new().fg(p.text_dim)),
                    Span::styled(
                        format!("{status_icon} {status_label}"),
                        Style::new().fg(status_color),
                    ),
                ]),
                Line::raw(""),
            ];

            // Authorized keys preview (read-only in Phase 1).
            let header = format!("AUTHORIZED KEYS ({})", user.authorized_key_count);
            lines.push(Line::from(Span::styled(
                header,
                Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
            )));
            if user.authorized_keys_preview.is_empty() {
                let note = if user.authorized_key_count == 0 {
                    "  (none)"
                } else {
                    "  (unreadable — run as root to view other users' keys)"
                };
                lines.push(Line::from(Span::styled(note, Style::new().fg(p.text_dim))));
            } else {
                for (i, key) in user.authorized_keys_preview.iter().take(6).enumerate() {
                    let comment = key
                        .comment
                        .clone()
                        .unwrap_or_else(|| truncate_str(&key.fingerprint, 20));
                    let comment_disp =
                        truncate_str(&comment, (content_area.width as usize).saturating_sub(16));
                    lines.push(Line::from(vec![
                        Span::styled(format!("  {}. ", i + 1), Style::new().fg(p.text_muted)),
                        Span::styled(format!("{:14}", key.key_type), Style::new().fg(p.info)),
                        Span::styled(comment_disp, Style::new().fg(p.text_dim)),
                    ]));
                }
                let hidden = user
                    .authorized_key_count
                    .saturating_sub(user.authorized_keys_preview.len());
                if hidden > 0 {
                    lines.push(Line::from(Span::styled(
                        format!("  +{hidden} more"),
                        Style::new().fg(p.text_muted),
                    )));
                }
            }

            lines.push(Line::raw(""));

            // Action hints. Non-root edits go through `sudo -n`; surface that.
            let priv_hint = if is_root { "" } else { "  (⚠ via sudo)" };
            lines.push(Line::from(vec![
                Span::styled("  a ", p.key_style()),
                Span::styled("allow", p.label_style()),
                Span::styled("  d ", p.key_style()),
                Span::styled("deny", p.label_style()),
                Span::styled("  r ", p.key_style()),
                Span::styled("reset", p.label_style()),
                Span::styled("  esc ", p.key_style()),
                Span::styled("close", p.label_style()),
            ]));
            if !priv_hint.is_empty() {
                lines.push(Line::from(Span::styled(priv_hint, Style::new().fg(p.warn))));
            }

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

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::screens::ssh::{SshAccessInfo, SystemUserInfo};
    use std::collections::HashMap;

    fn sample_data() -> SshSecurityData {
        let mut sshd_config = HashMap::new();
        sshd_config.insert("passwordauthentication".into(), "no".into());
        sshd_config.insert("permitrootlogin".into(), "prohibit-password".into());
        sshd_config.insert("port".into(), "22".into());
        sshd_config.insert("pubkeyauthentication".into(), "yes".into());
        sshd_config.insert("maxauthtries".into(), "3".into());
        sshd_config.insert("allowagentforwarding".into(), "no".into());
        sshd_config.insert("x11forwarding".into(), "no".into());
        sshd_config.insert("permitemptypasswords".into(), "no".into());

        SshSecurityData {
            sshd_config,
            authorized_key_count: 2,
            authorized_key_labels: vec!["alice@workstation".into(), "bob@laptop".into()],
            known_hosts_count: 5,
            known_hosts_hashed_count: 1,
            security_diagnostics: vec![],
            access_info: SshAccessInfo {
                available: true,
                allowed_users: vec![],
                denied_users: vec![],
                allowed_groups: vec!["ssh-users".into()],
                denied_groups: vec![],
                auth_methods: vec!["publickey".into()],
                password_auth: false,
                pubkey_auth: true,
                permit_root_login: "prohibit-password".into(),
            },
            is_root: false,
            system_users: vec![
                SystemUserInfo {
                    username: "alice".into(),
                    shell: "/bin/bash".into(),
                    home_dir: "/home/alice".into(),
                    ssh_key_count: 2,
                    authorized_key_count: 3,
                    authorized_keys_preview: Vec::new(),
                },
                SystemUserInfo {
                    username: "bob".into(),
                    shell: "/bin/zsh".into(),
                    home_dir: "/home/bob".into(),
                    ssh_key_count: 1,
                    authorized_key_count: 1,
                    authorized_keys_preview: Vec::new(),
                },
                SystemUserInfo {
                    username: "root".into(),
                    shell: "/bin/bash".into(),
                    home_dir: "/root".into(),
                    ssh_key_count: 0,
                    authorized_key_count: 0,
                    authorized_keys_preview: Vec::new(),
                },
            ],
        }
    }

    fn sample_data_with_warnings() -> SshSecurityData {
        let mut data = sample_data();
        data.security_diagnostics = vec![DiagnosticEntry {
            id: "key_permissions".into(),
            severity: "warning".into(),
            module: "local".into(),
            message: "Private key id_rsa has overly permissive mode (0644)".into(),
            hint: Some("Run chmod 600 ~/.ssh/id_rsa".into()),
        }];
        data
    }

    #[test]
    fn new_is_empty() {
        let mut tab = SecurityTab::new();
        assert!(tab.data.is_none());
        assert!(!tab.has_modal());
        assert_eq!(tab.scroll, 0);
        assert_eq!(tab.selected_user, 0);
        assert!(tab.drain_ops().is_empty());
    }

    #[test]
    fn set_data_updates() {
        let mut tab = SecurityTab::new();
        tab.set_data(sample_data());
        assert!(tab.data.is_some());
        assert_eq!(tab.scroll, 0);
    }

    #[test]
    fn render_empty_state() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("Loading security data"),
            "empty state should show loading message: {output}"
        );
    }

    #[test]
    fn render_with_data() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        tab.set_data(sample_data());
        let mut terminal = Terminal::new(TestBackend::new(100, 40)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains("Grade"), "grade banner: {output}");
        assert!(output.contains("SERVER CONFIG"), "server config: {output}");
        assert!(output.contains("AUTH METHODS"), "auth methods: {output}");
        assert!(output.contains("USER ACCESS"), "user access: {output}");
        assert!(output.contains("SSH USERS"), "ssh users: {output}");
        assert!(output.contains("ACCESS"), "access section: {output}");
        assert!(output.contains("KNOWN HOSTS"), "known hosts: {output}");
        assert!(output.contains("ALL CLEAR"), "all clear: {output}");
    }

    #[test]
    fn render_with_warnings() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        tab.set_data(sample_data_with_warnings());
        let mut terminal = Terminal::new(TestBackend::new(100, 40)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("WARNINGS"),
            "should show warnings header: {output}"
        );
    }

    #[test]
    fn selection_moves_and_clamps() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        tab.set_data(sample_data());

        // Render once so user row indices are populated.
        let mut terminal = Terminal::new(TestBackend::new(100, 40)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();

        assert_eq!(tab.selected_user, 0, "starts on first user");
        // Down moves the selection forward.
        tab.handle_key(KeyCode::Down);
        assert_eq!(tab.selected_user, 1);
        tab.handle_key(KeyCode::Down);
        assert_eq!(tab.selected_user, 2);

        // sample_data has 3 users (alice, bob, root) → clamps at last index.
        for _ in 0..50 {
            tab.handle_key(KeyCode::Down);
        }
        assert_eq!(
            tab.selected_user, 2,
            "selection clamps to last user, never panics"
        );

        // Up moves back and clamps at zero.
        tab.handle_key(KeyCode::Up);
        assert_eq!(tab.selected_user, 1);
        for _ in 0..50 {
            tab.handle_key(KeyCode::Up);
        }
        assert_eq!(tab.selected_user, 0, "selection clamps at first user");
    }

    #[test]
    fn selection_falls_back_to_scroll_without_users() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut data = sample_data();
        data.access_info = SshAccessInfo::default(); // available: false → no SSH USERS section
        data.system_users = vec![];
        tab.set_data(data);
        // Render to set content_height.
        let mut terminal = Terminal::new(TestBackend::new(100, 40)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();

        // With no users, j/k scroll the dashboard instead of moving selection.
        tab.handle_key(KeyCode::Down);
        assert_eq!(tab.scroll, 1, "Down scrolls dashboard when no users");
        tab.handle_key(KeyCode::Up);
        assert_eq!(tab.scroll, 0, "Up scrolls back");
    }

    #[test]
    fn scroll_mouse_scroll_up_down() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        tab.set_data(sample_data());

        // Render to set content_height so scrolling actually works.
        let mut terminal = Terminal::new(TestBackend::new(100, 40)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();

        let mouse_down = crossterm::event::MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 0,
            row: 0,
            modifiers: crossterm::event::KeyModifiers::NONE,
        };
        let mouse_up = crossterm::event::MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: 0,
            row: 0,
            modifiers: crossterm::event::KeyModifiers::NONE,
        };

        tab.handle_mouse(mouse_down);
        assert_eq!(tab.scroll, 1, "scroll down should increment");
        tab.handle_mouse(mouse_up);
        assert_eq!(tab.scroll, 0, "scroll up should decrement");
        tab.handle_mouse(mouse_up);
        assert_eq!(tab.scroll, 0, "scroll up at zero stays");
    }

    #[test]
    fn close_modal_is_noop() {
        let mut tab = SecurityTab::new();
        tab.close_modal();
        assert!(!tab.has_modal());
    }

    #[test]
    fn grade_banner_shows_correct_letter() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let data = sample_data();
        // Default mock config scores A.
        let mut tab = SecurityTab::new();
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(100, 40)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains('A'), "grade A for secure config: {output}");
    }

    #[test]
    fn render_auth_methods_section() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        tab.set_data(sample_data());
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("✗ Password"),
            "should show disabled password auth: {output}"
        );
        assert!(
            output.contains("✓ Public Key"),
            "should show enabled pubkey auth: {output}"
        );
        assert!(
            output.contains("prohibit-password"),
            "should show root login policy: {output}"
        );
        assert!(
            output.contains("Methods:"),
            "should show auth methods: {output}"
        );
    }

    #[test]
    fn render_user_access_section() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        tab.set_data(sample_data());
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("USER ACCESS"),
            "should show user access section: {output}"
        );
        assert!(
            output.contains("@ssh-users"),
            "should show allowed group: {output}"
        );
    }

    #[test]
    fn render_ssh_users_section() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        tab.set_data(sample_data());
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("SSH USERS"),
            "should show ssh users header: {output}"
        );
        assert!(output.contains("alice"), "should show user alice: {output}");
        assert!(output.contains("bob"), "should show user bob: {output}");
        assert!(output.contains("root"), "should show user root: {output}");
        assert!(
            output.contains("2 keys"),
            "should show key count for alice: {output}"
        );
        assert!(
            output.contains("No keys"),
            "should show no keys for root: {output}"
        );
    }

    #[test]
    fn render_user_access_hidden_when_no_sshd_config() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut data = sample_data();
        // Simulate no sshd_config on the machine (e.g. macOS).
        data.access_info = SshAccessInfo::default(); // available: false
        data.system_users = vec![];
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        // Sections should be HIDDEN when sshd_config is unavailable.
        assert!(
            !output.contains("AUTH METHODS"),
            "auth methods should be hidden without sshd_config: {output}"
        );
        assert!(
            !output.contains("USER ACCESS"),
            "user access should be hidden without sshd_config: {output}"
        );
        assert!(
            !output.contains("SSH USERS"),
            "ssh users should be hidden without sshd_config: {output}"
        );
    }

    #[test]
    fn render_user_access_all_users_allowed() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut data = sample_data();
        // sshd_config exists but has no AllowUsers/DenyUsers.
        data.access_info.allowed_users = vec![];
        data.access_info.denied_users = vec![];
        data.access_info.allowed_groups = vec![];
        data.access_info.denied_groups = vec![];
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("All users allowed"),
            "should show 'all users allowed' when no restrictions: {output}"
        );
    }

    #[test]
    fn render_ssh_users_overflow() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut data = sample_data();
        // Add enough users to trigger overflow
        for i in 0..12 {
            data.system_users.push(SystemUserInfo {
                username: format!("user{i}"),
                shell: "/bin/bash".into(),
                home_dir: format!("/home/user{i}"),
                ssh_key_count: 0,
                authorized_key_count: 0,
                authorized_keys_preview: Vec::new(),
            });
        }
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("+5 more"),
            "should show overflow count: {output}"
        );
    }

    #[test]
    fn render_password_auth_enabled() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut data = sample_data();
        data.access_info.password_auth = true;
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("✓ Password"),
            "should show enabled password auth: {output}"
        );
    }

    #[test]
    fn render_pubkey_auth_disabled() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut data = sample_data();
        data.access_info.pubkey_auth = false;
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("✗ Public Key"),
            "should show disabled pubkey auth: {output}"
        );
    }

    #[test]
    fn render_root_login_yes_shows_warning_color() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut data = sample_data();
        data.access_info.permit_root_login = "yes".into();
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("yes"),
            "should show root login yes: {output}"
        );
    }

    #[test]
    fn render_root_login_no_shows_ok_color() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut data = sample_data();
        data.access_info.permit_root_login = "no".into();
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains("no"), "should show root login no: {output}");
    }

    #[test]
    fn render_empty_auth_methods_hides_methods() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut data = sample_data();
        data.access_info.auth_methods = vec![];
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            !output.contains("Methods:"),
            "should not show Methods line when empty: {output}"
        );
    }

    #[test]
    fn render_allowed_users_with_badges() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut data = sample_data();
        data.access_info.allowed_users = vec!["alice".into(), "bob".into()];
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("alice"),
            "should show alice user badge: {output}"
        );
        assert!(
            output.contains("bob"),
            "should show bob user badge: {output}"
        );
    }

    #[test]
    fn render_denied_users_with_badges() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut data = sample_data();
        data.access_info.denied_users = vec!["guest".into()];
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("Denied:"),
            "should show Denied label: {output}"
        );
        assert!(
            output.contains("guest"),
            "should show denied user: {output}"
        );
    }

    #[test]
    fn render_denied_groups_with_badges() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut data = sample_data();
        data.access_info.denied_groups = vec!["no-ssh".into()];
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("Denied groups:"),
            "should show Denied groups label: {output}"
        );
        assert!(
            output.contains("no-ssh"),
            "should show denied group: {output}"
        );
    }

    #[test]
    fn render_empty_system_users_shows_message() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut data = sample_data();
        data.system_users = vec![];
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("No SSH users with keys configured"),
            "should show no ssh users message: {output}"
        );
    }

    #[test]
    fn render_warnings_with_hint() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        tab.set_data(sample_data_with_warnings());
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("WARNINGS"),
            "should show WARNINGS header: {output}"
        );
        assert!(
            output.contains("Run chmod 600 ~/.ssh/id_rsa"),
            "should show the hint text: {output}"
        );
    }

    // ── Interactive behavior ─────────────────────────────────────────────

    /// Helper: set sample data, render once, and open the detail modal on the
    /// given user index.
    fn open_modal(
        user_idx: usize,
    ) -> (
        SecurityTab,
        ratatui::Terminal<ratatui::backend::TestBackend>,
    ) {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};
        let mut tab = SecurityTab::new();
        tab.set_data(sample_data());
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        tab.selected_user = user_idx;
        tab.handle_key(KeyCode::Enter);
        (tab, terminal)
    }

    #[test]
    fn enter_opens_detail_modal() {
        let (tab, _) = open_modal(0);
        assert!(tab.has_modal(), "Enter should open the detail modal");
        assert_eq!(tab.detail_user.as_deref(), Some("alice"));
    }

    #[test]
    fn esc_closes_detail_modal() {
        let (mut tab, _) = open_modal(0);
        assert!(tab.has_modal());
        tab.handle_key(KeyCode::Esc);
        assert!(!tab.has_modal(), "Esc closes the detail modal");
        assert!(tab.detail_user.is_none());
    }

    #[test]
    fn allow_action_pushes_op_and_updates_optimistically() {
        let (mut tab, _) = open_modal(0); // alice

        // alice is currently not in any allow/deny list.
        tab.handle_key(KeyCode::Char('a'));

        let ops = tab.drain_ops();
        assert_eq!(ops.len(), 1, "'a' should queue exactly one op");
        match &ops[0] {
            SshOp::SshdAllowUser { username } => assert_eq!(username, "alice"),
            other => panic!("expected SshdAllowUser, got {other:?}"),
        }
        // Optimistic in-memory update: alice added to allow list.
        let access = &tab.data.as_ref().unwrap().access_info;
        assert!(access.allowed_users.iter().any(|u| u == "alice"));
        assert!(!access.denied_users.iter().any(|u| u == "alice"));
    }

    #[test]
    fn allow_action_removes_from_deny_optimistically() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut data = sample_data();
        data.access_info.denied_users = vec!["alice".into()];
        let mut tab = SecurityTab::new();
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        tab.selected_user = 0;
        tab.handle_key(KeyCode::Enter);
        tab.handle_key(KeyCode::Char('a'));

        let access = &tab.data.as_ref().unwrap().access_info;
        assert!(
            !access.denied_users.iter().any(|u| u == "alice"),
            "allow should remove from deny list"
        );
    }

    #[test]
    fn deny_action_requires_confirm_then_applies() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        // bob must START in the allow list so the L5 both-lists mirror
        // (`allowed_users.retain(|u| u != &username)`) has real work to do.
        // With allowed_users empty the retain is a no-op and deleting the
        // mirror line would still pass — exactly the false confidence F15 flags.
        let mut data = sample_data();
        data.access_info.allowed_users = vec!["bob".into()];
        let mut tab = SecurityTab::new();
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        tab.selected_user = 1; // bob
        tab.handle_key(KeyCode::Enter);

        // 'd' opens a confirm modal, does NOT apply yet.
        tab.handle_key(KeyCode::Char('d'));
        assert!(tab.pending_confirm.is_some(), "'d' should request confirm");
        assert!(tab.drain_ops().is_empty(), "no op before confirm");

        // Confirm with 'y'.
        tab.handle_key(KeyCode::Char('y'));
        assert!(
            tab.pending_confirm.is_none(),
            "confirm consumed the pending action"
        );

        let ops = tab.drain_ops();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            SshOp::SshdDenyUser { username } => assert_eq!(username, "bob"),
            other => panic!("expected SshdDenyUser, got {other:?}"),
        }
        let access = &tab.data.as_ref().unwrap().access_info;
        assert!(
            access.denied_users.iter().any(|u| u == "bob"),
            "deny should add bob to denied_users"
        );
        assert!(
            !access.allowed_users.iter().any(|u| u == "bob"),
            "deny must also remove bob from allowed_users (both-lists mirror); \
             this assertion fails if the retain on line ~225 is dropped"
        );
    }

    #[test]
    fn reset_action_requires_confirm_then_applies() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut data = sample_data();
        data.access_info.allowed_users = vec!["alice".into(), "bob".into()];
        data.access_info.denied_users = vec!["bob".into()]; // bob in both
        let mut tab = SecurityTab::new();
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        tab.selected_user = 1; // bob
        tab.handle_key(KeyCode::Enter);

        tab.handle_key(KeyCode::Char('r'));
        assert!(tab.pending_confirm.is_some(), "'r' should request confirm");
        assert!(tab.drain_ops().is_empty());

        // Cancel with 'n' — nothing applied.
        tab.handle_key(KeyCode::Char('n'));
        assert!(tab.pending_confirm.is_none());
        assert!(tab.drain_ops().is_empty());
        let access = &tab.data.as_ref().unwrap().access_info;
        assert!(
            access.allowed_users.iter().any(|u| u == "bob"),
            "cancel leaves state intact"
        );

        // Re-trigger and confirm this time.
        tab.handle_key(KeyCode::Char('r'));
        tab.handle_key(KeyCode::Char('y'));
        let ops = tab.drain_ops();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            SshOp::SshdResetUserAccess { username } => assert_eq!(username, "bob"),
            other => panic!("expected SshdResetUserAccess, got {other:?}"),
        }
        let access = &tab.data.as_ref().unwrap().access_info;
        assert!(!access.allowed_users.iter().any(|u| u == "bob"));
        assert!(!access.denied_users.iter().any(|u| u == "bob"));
    }

    #[test]
    fn close_modal_clears_confirm() {
        let (mut tab, _) = open_modal(0);
        tab.handle_key(KeyCode::Char('d'));
        assert!(tab.pending_confirm.is_some());
        tab.close_modal();
        assert!(tab.pending_confirm.is_none());
        assert!(!tab.has_modal());
    }

    #[test]
    fn login_status_logic() {
        use crate::ui::theme::CHARM;

        // Denied wins.
        let a = SshAccessInfo {
            denied_users: vec!["x".into()],
            ..Default::default()
        };
        let (icon, _, _) = SecurityTab::login_status("x", &a, CHARM);
        assert_eq!(icon, "✗");

        // Allowlist (non-empty) and user absent → not allowed.
        let a = SshAccessInfo {
            allowed_users: vec!["alice".into()],
            ..Default::default()
        };
        let (icon, label, _) = SecurityTab::login_status("bob", &a, CHARM);
        assert_eq!(icon, "✗");
        assert!(label.contains("allowlist"));

        // User in allowlist → allowed (falls through to default since no groups).
        let (icon, _, _) = SecurityTab::login_status("alice", &a, CHARM);
        assert_eq!(icon, "✓");

        // Group rules present (user not denied) → ambiguous.
        let a = SshAccessInfo {
            allowed_groups: vec!["ssh".into()],
            ..Default::default()
        };
        let (icon, _, _) = SecurityTab::login_status("alice", &a, CHARM);
        assert_eq!(icon, "~");

        // No restrictions → allowed.
        let a = SshAccessInfo::default();
        let (icon, _, _) = SecurityTab::login_status("anyone", &a, CHARM);
        assert_eq!(icon, "✓");
    }

    #[test]
    fn detail_modal_renders_user_and_actions() {
        use crate::ui::theme::CHARM;

        let (mut tab, mut terminal) = open_modal(0); // alice
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains("User:"), "modal shows user label: {output}");
        assert!(output.contains("alice"), "modal shows username: {output}");
        assert!(
            output.contains("Login:"),
            "modal shows login status: {output}"
        );
        assert!(output.contains("allow"), "modal shows allow hint: {output}");
        assert!(output.contains("deny"), "modal shows deny hint: {output}");
        assert!(output.contains("reset"), "modal shows reset hint: {output}");
    }

    #[test]
    fn non_root_modal_shows_sudo_hint() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut data = sample_data();
        data.is_root = false;
        let mut tab = SecurityTab::new();
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        tab.selected_user = 0;
        tab.handle_key(KeyCode::Enter);
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("sudo"),
            "non-root should show sudo hint: {output}"
        );
    }

    #[test]
    fn root_modal_hides_sudo_hint() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut data = sample_data();
        data.is_root = true;
        let mut tab = SecurityTab::new();
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        tab.selected_user = 0;
        tab.handle_key(KeyCode::Enter);
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            !output.contains("via sudo"),
            "root should hide sudo hint: {output}"
        );
    }

    #[test]
    fn set_data_clamps_selection_and_closes_stale_modal() {
        let mut tab = SecurityTab::new();
        tab.set_data(sample_data()); // 3 users
        tab.selected_user = 2;
        tab.handle_key(KeyCode::Enter); // open modal on user 2
        assert!(tab.has_modal());

        // Replace with data that has only 1 user: selection must clamp, modal on
        // the now-invalid index must close.
        let mut data = sample_data();
        data.system_users.truncate(1);
        tab.set_data(data);
        assert!(tab.selected_user == 0, "selection clamps into new list");
        assert!(!tab.has_modal(), "stale modal closed");
    }

    #[test]
    fn detail_modal_tracks_user_by_name_across_reorder() {
        // Open the detail modal on "bob" (index 1 in sample_data). A
        // mid-modal refresh that reshapes the user list must NOT silently flip
        // the modal target onto a different user.
        let (mut tab, _) = open_modal(1); // bob
        assert_eq!(tab.detail_user.as_deref(), Some("bob"));

        // Re-resolve now, before the reorder, to confirm the index is 1.
        assert_eq!(tab.detail_index(), Some(1));

        // Reorder: move bob from index 1 to index 0, push a new user after.
        // (Same length as before, so the old length-based guard in set_data
        // would NOT have caught this — the bug is precisely that a same-length
        // reorder flipped the index.)
        let mut data = sample_data();
        // Original order: alice(0), bob(1), root(2). Clone the keepers out so
        // we don't borrow `data.system_users` while reassigning it.
        let alice = data.system_users[0].clone();
        let root = data.system_users[2].clone();
        // New order: bob(0), alice(1), root(2), carol(3).
        data.system_users = vec![
            SystemUserInfo {
                username: "bob".into(),
                shell: "/bin/zsh".into(),
                home_dir: "/home/bob".into(),
                ssh_key_count: 1,
                authorized_key_count: 1,
                authorized_keys_preview: Vec::new(),
            },
            alice,
            root,
            SystemUserInfo {
                username: "carol".into(),
                shell: "/bin/bash".into(),
                home_dir: "/home/carol".into(),
                ssh_key_count: 0,
                authorized_key_count: 0,
                authorized_keys_preview: Vec::new(),
            },
        ];
        tab.set_data(data);

        // The modal is still open and STILL targets bob (by name), now at index 0.
        assert!(tab.has_modal(), "modal stays open across a reorder");
        assert_eq!(
            tab.detail_user.as_deref(),
            Some("bob"),
            "modal target is tracked by name, not position"
        );
        assert_eq!(
            tab.detail_index(),
            Some(0),
            "bob re-resolved to its new index 0 after the reorder"
        );

        // And a/d/r resolution follows bob, not the stale index 1 (which is now
        // alice). Deny must target bob, never alice.
        tab.handle_key(KeyCode::Char('d'));
        assert!(tab.pending_confirm.is_some());
        tab.handle_key(KeyCode::Char('y'));
        let ops = tab.drain_ops();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            SshOp::SshdDenyUser { username } => assert_eq!(username, "bob"),
            other => panic!("reorder must not flip the target; expected bob, got {other:?}"),
        }
        // The in-memory mirror also applied to bob, not alice.
        let access = &tab.data.as_ref().unwrap().access_info;
        assert!(access.denied_users.iter().any(|u| u == "bob"));
        assert!(!access.denied_users.iter().any(|u| u == "alice"));
    }

    #[test]
    fn detail_modal_closes_when_user_removed_not_just_reordered() {
        // Open on bob, then remove bob entirely. The modal must close.
        let (mut tab, _) = open_modal(1); // bob
        assert_eq!(tab.detail_user.as_deref(), Some("bob"));

        let mut data = sample_data();
        // Same length as before (3), so the length guard never fires: bob is
        // replaced by an unrelated user to force the name to be gone.
        data.system_users[1] = SystemUserInfo {
            username: "mallory".into(),
            shell: "/bin/bash".into(),
            home_dir: "/home/mallory".into(),
            ssh_key_count: 0,
            authorized_key_count: 0,
            authorized_keys_preview: Vec::new(),
        };
        tab.set_data(data);
        assert!(
            !tab.has_modal(),
            "modal closes when the tracked user is gone"
        );
        assert!(tab.detail_user.is_none());
    }
}
