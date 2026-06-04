//! The main Dashboard screen: a full-width shell (header / sidebar / footer)
//! wrapping stat cards, a module-card grid, an updates list and an activity log.
//!
//! Built on the reusable [`shell`](crate::ui::shell) chrome. The sidebar drives
//! an internal "active section"; only [`Section::Dashboard`] renders full
//! content for now, other sections show a placeholder.

use std::time::{SystemTime, UNIX_EPOCH};

use crossterm::event::{KeyCode, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Padding, Paragraph},
};

use crate::action::Action;
use crate::data::{ActivityEntry, DashboardData, Module, ModuleUpdate, Section};
use crate::status::TorideStatus;
use crate::ui::helpers::{format_bytes, format_duration};
use crate::ui::responsive::{self, truncate_str};
use crate::ui::screens::AppScreen;
use crate::ui::shell::{
    SIDEBAR_W, SIDEBAR_W_COLLAPSED, Sidebar, render_footer, render_header, shell_layout,
    header::HeaderData,
};
use crate::ui::theme::Palette;
use crate::ui::widgets::{Card, Modal, accent_badge, neutral_badge, tag_badge};
use crate::ui::widgets::gradient::GradientCache;

/// Below this frame width the sidebar auto-collapses to an icon rail.
const AUTO_COLLAPSE_W: u16 = 100;
/// Below this content width the dashboard drops to a single column.
const SINGLE_COL_W: u16 = 78;
/// Height of the top stat-card row.
const STAT_ROW_H: u16 = 6;
/// Height of a module card in the grid.
const MODULE_CARD_H: u16 = 5;
/// Number of columns in the module grid (used for keyboard navigation).
const GRID_COLS: usize = 2;

/// Which region currently has keyboard focus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Focus {
    Sidebar,
    Modules,
    Updates,
    Activity,
}

impl Focus {
    fn next(self) -> Self {
        match self {
            Focus::Sidebar => Focus::Modules,
            Focus::Modules => Focus::Updates,
            Focus::Updates => Focus::Activity,
            Focus::Activity => Focus::Sidebar,
        }
    }

    fn prev(self) -> Self {
        match self {
            Focus::Sidebar => Focus::Activity,
            Focus::Modules => Focus::Sidebar,
            Focus::Updates => Focus::Modules,
            Focus::Activity => Focus::Updates,
        }
    }
}

/// The dashboard screen state.
pub struct DashboardScreen {
    data: DashboardData,
    status: Option<TorideStatus>,
    sidebar: Sidebar,
    active: usize,
    focus: Focus,
    module_sel: usize,
    module_scroll: usize,
    updates_scroll: usize,
    activity_scroll: usize,
    open_module: Option<usize>,
    gradient_cache: GradientCache,
    clock: String,
}

impl Default for DashboardScreen {
    fn default() -> Self {
        Self::new()
    }
}

impl DashboardScreen {
    /// Create a new dashboard seeded with mock data.
    #[must_use]
    pub fn new() -> Self {
        let data = DashboardData::mock();
        let sidebar = Sidebar::new(data.sidebar.len());
        let clock = "09:17 PM".to_string();
        Self {
            data,
            status: None,
            sidebar,
            active: 0,
            focus: Focus::Sidebar,
            module_sel: 0,
            module_scroll: 0,
            updates_scroll: 0,
            activity_scroll: 0,
            open_module: None,
            gradient_cache: GradientCache::new(),
            clock,
        }
    }

    /// Store the latest collected system status (header gauges + system card).
    pub fn set_status(&mut self, status: TorideStatus) {
        self.status = Some(status);
    }

    /// Refresh the wall-clock label (called from the app refresh tick).
    pub fn tick_clock(&mut self) {
        self.clock = current_clock();
    }

    /// The currently active section.
    fn active_section(&self) -> Section {
        self.data.sidebar[self.active].section
    }

    // ── Input ────────────────────────────────────────────────────────────────

    fn module_left(&mut self) {
        self.module_sel = self.module_sel.saturating_sub(1);
    }

    fn module_right(&mut self) {
        if self.module_sel + 1 < self.data.modules.len() {
            self.module_sel += 1;
        }
    }

    fn module_up(&mut self) {
        if self.module_sel >= GRID_COLS {
            self.module_sel -= GRID_COLS;
        }
    }

    fn module_down(&mut self) {
        if self.module_sel + GRID_COLS < self.data.modules.len() {
            self.module_sel += GRID_COLS;
        }
    }

    /// Scroll/move within the currently focused region (used by the mouse wheel).
    fn scroll_focused(&mut self, down: bool) {
        match self.focus {
            Focus::Updates => {
                self.updates_scroll = if down {
                    self.updates_scroll + 1
                } else {
                    self.updates_scroll.saturating_sub(1)
                };
            }
            Focus::Activity => {
                self.activity_scroll = if down {
                    self.activity_scroll + 1
                } else {
                    self.activity_scroll.saturating_sub(1)
                };
            }
            Focus::Modules => {
                if down {
                    self.module_down();
                } else {
                    self.module_up();
                }
            }
            Focus::Sidebar => {
                if down {
                    self.sidebar.select_next();
                } else {
                    self.sidebar.select_prev();
                }
            }
        }
    }

    // ── Render ─────────────────────────────────────────────────────────────────

    fn render(&mut self, frame: &mut Frame, p: Palette, skip_bg: bool) {
        let area = frame.area();
        if responsive::render_too_small(frame, p) {
            return;
        }

        if !skip_bg {
            let buf = frame.buffer_mut();
            self.gradient_cache.render_or_copy(buf, area, p);
        }

        let collapsed = self.sidebar.is_collapsed() || area.width < AUTO_COLLAPSE_W;
        let sidebar_w = if collapsed {
            SIDEBAR_W_COLLAPSED
        } else {
            SIDEBAR_W
        };

        let shell = shell_layout(area, sidebar_w);

        // Header gauges from live status when available.
        let (cpu, ram, disk) = self.gauges();
        render_header(
            frame,
            shell.header,
            p,
            &HeaderData {
                cpu,
                ram,
                disk,
                clock: &self.clock,
            },
        );

        self.sidebar.render(
            frame,
            shell.sidebar,
            p,
            &self.data.sidebar,
            self.active,
            self.focus == Focus::Sidebar,
            collapsed,
            &self.data.ssh_target,
        );

        render_footer(
            frame,
            shell.footer,
            p,
            &[
                ("↑↓", "move"),
                ("↵", "open"),
                ("Tab", "focus"),
                ("\\", "collapse"),
                ("Esc", "back"),
            ],
        );

        // ── Content ──────────────────────────────────────────────────────────
        let content = shell.content;
        if self.active_section() == Section::Dashboard {
            self.render_dashboard_content(frame, content, p);
        } else {
            render_placeholder(frame, content, p, self.active_section());
        }

        // ── Module detail modal ───────────────────────────────────────────────
        if let Some(idx) = self.open_module
            && let Some(m) = self.data.modules.get(idx)
        {
            render_module_modal(frame, p, m);
        }
    }

    fn gauges(&self) -> (Option<f64>, Option<f64>, Option<f64>) {
        match &self.status {
            Some(s) => (
                s.system.cpu_usage,
                Some(s.system.memory.percentage),
                Some(s.system.disk.percentage),
            ),
            None => (Some(35.0), Some(23.0), Some(23.0)),
        }
    }

    fn render_dashboard_content(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        let [stat_area, _gap, body_area] = Layout::vertical([
            Constraint::Length(STAT_ROW_H),
            Constraint::Length(1),
            Constraint::Fill(1),
        ])
        .areas(pad(area));

        self.render_stat_cards(frame, stat_area, p);

        let single_col = body_area.width < SINGLE_COL_W;
        if single_col {
            // Stack: modules on top, then updates, then activity.
            let [mods, ups, acts] = Layout::vertical([
                Constraint::Fill(2),
                Constraint::Fill(1),
                Constraint::Fill(1),
            ])
            .spacing(1)
            .areas(body_area);
            self.render_modules_panel(frame, mods, p, 1);
            self.render_updates_panel(frame, ups, p);
            self.render_activity_panel(frame, acts, p);
        } else {
            let [left, right] =
                Layout::horizontal([Constraint::Fill(2), Constraint::Fill(1)])
                    .spacing(1)
                    .areas(body_area);
            self.render_modules_panel(frame, left, p, 2);

            let [ups, acts] = Layout::vertical([Constraint::Fill(1), Constraint::Fill(1)])
                .spacing(1)
                .areas(right);
            self.render_updates_panel(frame, ups, p);
            self.render_activity_panel(frame, acts, p);
        }
    }

    fn render_stat_cards(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let [a, b, c, d] = Layout::horizontal([
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Fill(2),
        ])
        .spacing(1)
        .areas(area);

        let modules_card = vec![
            Line::from(vec![
                Span::styled(self.data.modules_installed.to_string(), Style::new().fg(p.ok).bold()),
                Span::styled(format!(" / {}", self.data.modules_total), Style::new().fg(p.text_dim)),
            ]),
            Line::raw(""),
            Line::from(Span::styled("MODULES INSTALLED", Style::new().fg(p.text_muted))),
        ];
        Card::new(modules_card).render(frame, a, p);

        let updates_card = vec![
            Line::from(Span::styled(
                self.data.updates_count().to_string(),
                Style::new().fg(p.warn).bold(),
            )),
            Line::raw(""),
            Line::from(Span::styled("UPDATES AVAILABLE", Style::new().fg(p.text_muted))),
        ];
        Card::new(updates_card).render(frame, b, p);

        let staged_card = vec![
            Line::from(Span::styled(
                self.data.staged.to_string(),
                Style::new().fg(p.text_dim).bold(),
            )),
            Line::raw(""),
            Line::from(Span::styled("STAGED", Style::new().fg(p.text_muted))),
        ];
        Card::new(staged_card).render(frame, c, p);

        Card::new(self.system_card_lines(p)).render(frame, d, p);
    }

    fn system_card_lines(&self, p: Palette) -> Vec<Line<'static>> {
        let h = &self.data.host;
        let dim = Style::new().fg(p.text_dim);
        let muted = Style::new().fg(p.text_muted);
        let accent = Style::new().fg(p.accent3);

        // Prefer live status where available, fall back to mock host.
        let (hostname, os, cpu, mem_used, mem_total, uptime, load) = match &self.status {
            Some(s) => {
                let os = match (&s.system.os_info.name, &s.system.os_info.version) {
                    (Some(n), Some(v)) => format!("{n} {v}"),
                    (Some(n), None) => n.clone(),
                    _ => h.os.clone(),
                };
                let cores = s.system.cpu_cores.len();
                let cpu = if s.system.static_info.cpu_brand.is_empty() {
                    h.cpu.clone()
                } else {
                    s.system.static_info.cpu_brand.clone()
                };
                let mem_used = format_bytes(s.system.memory.used_bytes);
                let mem_total = format_bytes(s.system.memory.total_bytes);
                let uptime = s
                    .system
                    .uptime_secs
                    .map_or_else(|| h.uptime.clone(), format_duration);
                let load = s.system.load_average.map_or_else(
                    || h.load.clone(),
                    |l| format!("{:.2} {:.2} {:.2}", l.one, l.five, l.fifteen),
                );
                let vcpu = if cores > 0 {
                    format!("{cores} vCPU")
                } else {
                    h.vcpu.clone()
                };
                (s.system.hostname.clone(), os, format!("{cpu} · {vcpu}"), mem_used, mem_total, uptime, load)
            }
            None => (
                h.hostname.clone(),
                h.os.clone(),
                format!("{} · {}", h.cpu, h.vcpu),
                h.mem_used.clone(),
                h.mem_total.clone(),
                h.uptime.clone(),
                h.load.clone(),
            ),
        };

        vec![
            Line::from(vec![
                Span::styled(hostname, Style::new().fg(p.accent2).bold()),
                Span::styled(format!("   {os}"), dim),
            ]),
            Line::from(Span::styled(cpu, Style::new().fg(p.text))),
            Line::from(vec![
                Span::styled("mem ", muted),
                Span::styled(format!("{mem_used} / {mem_total}"), accent),
            ]),
            Line::from(vec![
                Span::styled(format!("uptime {uptime}"), muted),
                Span::styled(format!("  ·  load {load}"), muted),
            ]),
        ]
    }

    fn render_modules_panel(&mut self, frame: &mut Frame, area: Rect, p: Palette, cols: u16) {
        let focused = self.focus == Focus::Modules;
        let inner = render_panel(frame, area, p, " MODULES ", p.accent, focused);
        if inner.height == 0 {
            return;
        }

        let rows = inner.height / MODULE_CARD_H;
        if rows == 0 {
            return;
        }
        let per_row = usize::from(cols.max(1));

        // Clamp scroll so the selected module stays visible.
        let sel_row = self.module_sel / per_row;
        if sel_row < self.module_scroll {
            self.module_scroll = sel_row;
        } else if sel_row >= self.module_scroll + usize::from(rows) {
            self.module_scroll = sel_row - usize::from(rows) + 1;
        }
        let total_rows = (self.data.modules.len() + per_row - 1) / per_row;
        let max_scroll = total_rows.saturating_sub(usize::from(rows));
        self.module_scroll = self.module_scroll.min(max_scroll);

        let base = self.module_scroll * per_row;

        let row_rects = Layout::vertical(
            (0..rows)
                .map(|_| Constraint::Length(MODULE_CARD_H))
                .collect::<Vec<_>>(),
        )
        .split(inner);

        for (r, row_rect) in row_rects.iter().enumerate() {
            let cells = Layout::horizontal(
                (0..cols.max(1)).map(|_| Constraint::Fill(1)).collect::<Vec<_>>(),
            )
            .spacing(1)
            .split(*row_rect);
            for (c, cell) in cells.iter().enumerate() {
                let idx = base + r * per_row + c;
                if idx >= self.data.modules.len() {
                    continue;
                }
                let m = &self.data.modules[idx];
                let card_focused = focused && idx == self.module_sel;
                render_module_card(frame, *cell, p, m, card_focused);
            }
        }
    }

    fn render_updates_panel(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let focused = self.focus == Focus::Updates;
        let title = format!(" UPDATES AVAILABLE · {} ", self.data.updates_count());
        let inner = render_panel(frame, area, p, &title, p.warn, focused);
        for (i, row) in list_rows(inner, self.updates_scroll, self.data.updates.len()) {
            render_update_row(frame, row, p, &self.data.updates[i]);
        }
    }

    fn render_activity_panel(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let focused = self.focus == Focus::Activity;
        let inner = render_panel(frame, area, p, " RECENTLY INSTALLED ", p.accent3, focused);
        for (i, row) in list_rows(inner, self.activity_scroll, self.data.activity.len()) {
            render_activity_row(frame, row, p, &self.data.activity[i]);
        }
    }
}

impl AppScreen for DashboardScreen {
    fn handle_key(&mut self, code: KeyCode) -> Option<Action> {
        // Modal intercepts input while open.
        if self.open_module.is_some() {
            if matches!(code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('o')) {
                self.open_module = None;
            }
            return None;
        }

        match code {
            KeyCode::Char('q') => return Some(Action::Quit),
            KeyCode::Tab => {
                self.focus = self.focus.next();
                return None;
            }
            KeyCode::BackTab => {
                self.focus = self.focus.prev();
                return None;
            }
            KeyCode::Char('\\') => {
                self.sidebar.toggle_collapse();
                return None;
            }
            KeyCode::Esc => {
                if self.focus == Focus::Sidebar {
                    return Some(Action::Back);
                }
                self.focus = Focus::Sidebar;
                return None;
            }
            KeyCode::Char(d @ '1'..='9') => {
                let idx = (d as usize) - ('1' as usize);
                if idx < self.data.sidebar.len() {
                    self.sidebar.select_to(idx);
                    self.active = idx;
                    self.focus = Focus::Sidebar;
                }
                return None;
            }
            _ => {}
        }

        match self.focus {
            Focus::Sidebar => match code {
                KeyCode::Down | KeyCode::Char('j') => self.sidebar.select_next(),
                KeyCode::Up | KeyCode::Char('k') => self.sidebar.select_prev(),
                KeyCode::Enter => self.active = self.sidebar.selected(),
                _ => {}
            },
            Focus::Modules => match code {
                KeyCode::Down | KeyCode::Char('j') => self.module_down(),
                KeyCode::Up | KeyCode::Char('k') => self.module_up(),
                KeyCode::Right | KeyCode::Char('l') => self.module_right(),
                KeyCode::Left | KeyCode::Char('h') => self.module_left(),
                KeyCode::Enter => self.open_module = Some(self.module_sel),
                _ => {}
            },
            Focus::Updates => match code {
                KeyCode::Down | KeyCode::Char('j') => self.updates_scroll = self.updates_scroll.saturating_add(1),
                KeyCode::Up | KeyCode::Char('k') => self.updates_scroll = self.updates_scroll.saturating_sub(1),
                _ => {}
            },
            Focus::Activity => match code {
                KeyCode::Down | KeyCode::Char('j') => self.activity_scroll = self.activity_scroll.saturating_add(1),
                KeyCode::Up | KeyCode::Char('k') => self.activity_scroll = self.activity_scroll.saturating_sub(1),
                _ => {}
            },
        }
        None
    }

    fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action> {
        use crossterm::event::MouseButton;
        match mouse.kind {
            // Hover: highlight whatever sidebar item is under the cursor.
            MouseEventKind::Moved | MouseEventKind::Drag(_) => {
                let idx = self.sidebar.item_at(mouse.column, mouse.row);
                self.sidebar.set_hovered(idx);
            }
            // Click: select + activate the sidebar item, focus the sidebar.
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some(idx) = self.sidebar.item_at(mouse.column, mouse.row) {
                    self.sidebar.select_to(idx);
                    self.active = idx;
                    self.focus = Focus::Sidebar;
                }
            }
            MouseEventKind::ScrollDown => self.scroll_focused(true),
            MouseEventKind::ScrollUp => self.scroll_focused(false),
            _ => {}
        }
        None
    }

    fn view(&mut self, frame: &mut Frame, palette: Palette) {
        self.render(frame, palette, false);
    }

    fn view_foreground(&mut self, frame: &mut Frame, palette: Palette) {
        self.render(frame, palette, true);
    }

    fn invalidate_cache(&mut self) {
        self.gradient_cache.invalidate();
    }

    fn needs_animation(&self) -> bool {
        false
    }
}

// ── Free render helpers ───────────────────────────────────────────────────────

/// Inset an area by one column/row for breathing room inside the content region.
fn pad(area: Rect) -> Rect {
    Rect {
        x: area.x + 1,
        y: area.y,
        width: area.width.saturating_sub(2),
        height: area.height,
    }
}

/// Render a titled rounded panel and return its inner content area.
fn render_panel(
    frame: &mut Frame,
    area: Rect,
    p: Palette,
    title: &str,
    title_color: ratatui::style::Color,
    focused: bool,
) -> Rect {
    let border_color = if focused { p.border_hi } else { title_color };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(border_color))
        .title(Span::styled(
            title.to_string(),
            Style::new().fg(title_color).bold(),
        ))
        .style(Style::new().bg(p.bg))
        .padding(Padding::horizontal(1));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    inner
}

/// Compute the visible `(item_index, row_rect)` pairs for a scrollable list.
fn list_rows(inner: Rect, scroll: usize, len: usize) -> Vec<(usize, Rect)> {
    if inner.height == 0 {
        return Vec::new();
    }
    let visible = usize::from(inner.height);
    let max_scroll = len.saturating_sub(visible);
    let scroll = scroll.min(max_scroll);
    (scroll..len)
        .take(visible)
        .enumerate()
        .filter_map(|(row, i)| {
            let offset = u16::try_from(row).ok()?;
            Some((i, Rect::new(inner.x, inner.y + offset, inner.width, 1)))
        })
        .collect()
}

fn render_module_card(frame: &mut Frame, area: Rect, p: Palette, m: &Module, focused: bool) {
    let border = if focused { p.border_hi } else { p.border };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(border))
        .style(Style::new().bg(p.panel))
        .padding(Padding::horizontal(1));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height == 0 {
        return;
    }

    let title_row = Rect::new(inner.x, inner.y, inner.width, 1);
    let name_line = Line::from(vec![
        Span::styled(format!("{} ", m.icon), Style::new().fg(p.accent2)),
        Span::styled(m.name.clone(), Style::new().fg(p.text).bold()),
    ]);
    frame.render_widget(Paragraph::new(name_line), title_row);

    let status_line = Line::from(Span::styled(
        format!("{} {}", m.status.glyph(), m.status.label()),
        Style::new().fg(m.status.color(p)),
    ));
    frame.render_widget(Paragraph::new(status_line).right_aligned(), title_row);

    let w = inner.width as usize;
    if inner.height >= 2 {
        let summary = truncate_str(&m.summary, w);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(summary, Style::new().fg(p.text_dim)))),
            Rect::new(inner.x, inner.y + 1, inner.width, 1),
        );
    }
    if inner.height >= 3 {
        let detail = truncate_str(&m.detail, w);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(detail, Style::new().fg(p.text_muted)))),
            Rect::new(inner.x, inner.bottom() - 1, inner.width, 1),
        );
    }
}

fn render_update_row(frame: &mut Frame, row: Rect, p: Palette, u: &ModuleUpdate) {
    let name = Line::from(Span::styled(u.name.clone(), Style::new().fg(p.text)));
    frame.render_widget(Paragraph::new(name), row);

    let mut right = Vec::new();
    if let Some(from) = &u.from {
        right.push(Span::styled(from.clone(), Style::new().fg(p.text_muted)));
        right.push(Span::styled(" → ", Style::new().fg(p.text_dim)));
    } else {
        right.push(Span::styled("— → ", Style::new().fg(p.text_muted)));
    }
    right.push(Span::styled(u.to.clone(), Style::new().fg(p.accent2).bold()));
    right.push(Span::raw("  "));
    right.push(tag_badge(&u.badge, p.info, p));
    frame.render_widget(Paragraph::new(Line::from(right)).right_aligned(), row);
}

fn render_activity_row(frame: &mut Frame, row: Rect, p: Palette, e: &ActivityEntry) {
    let left = Line::from(vec![
        Span::styled(format!("{} ", e.time), Style::new().fg(p.text_muted)),
        Span::styled(format!("{} ", e.kind.glyph()), Style::new().fg(e.kind.color(p))),
        Span::styled(
            truncate_str(&e.message, row.width.saturating_sub(10) as usize),
            Style::new().fg(p.text_dim),
        ),
    ]);
    frame.render_widget(Paragraph::new(left), row);

    let dur = Line::from(Span::styled(e.duration.clone(), Style::new().fg(p.text_muted)));
    frame.render_widget(Paragraph::new(dur).right_aligned(), row);
}

fn render_placeholder(frame: &mut Frame, area: Rect, p: Palette, section: Section) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(p.border))
        .style(Style::new().bg(p.bg));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let msg = Line::from(vec![
        Span::styled(section.label(), Style::new().fg(p.accent).bold()),
        Span::styled(" — coming soon", Style::new().fg(p.text_dim)),
    ]);
    let centered = Rect::new(inner.x, inner.y + inner.height / 2, inner.width, 1);
    frame.render_widget(Paragraph::new(msg).centered(), centered);
}

fn render_module_modal(frame: &mut Frame, p: Palette, m: &Module) {
    Modal::new("module").dimensions(54, 10).render(frame, p, |frame, area| {
        let lines = vec![
            Line::from(vec![
                Span::styled(format!("{} ", m.icon), Style::new().fg(p.accent2)),
                Span::styled(m.name.clone(), Style::new().fg(p.text).bold()),
                Span::raw("   "),
                Span::styled(
                    format!("{} {}", m.status.glyph(), m.status.label()),
                    Style::new().fg(m.status.color(p)),
                ),
            ]),
            Line::raw(""),
            Line::from(Span::styled(m.summary.clone(), Style::new().fg(p.text_dim))),
            Line::from(Span::styled(m.detail.clone(), Style::new().fg(p.text_muted))),
            Line::raw(""),
            Line::from(vec![
                accent_badge("↵ open", p),
                Span::raw("   "),
                neutral_badge("esc close", p),
            ]),
        ];
        frame.render_widget(Paragraph::new(lines), area);
    });
}

// ── Clock ─────────────────────────────────────────────────────────────────────

/// Format the current wall-clock time as a 12-hour `HH:MM AM/PM` label (UTC).
fn current_clock() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let tod = secs % 86_400;
    let h24 = tod / 3600;
    let m = (tod % 3600) / 60;
    let (h12, ampm) = match h24 {
        0 => (12, "AM"),
        1..=11 => (h24, "AM"),
        12 => (12, "PM"),
        _ => (h24 - 12, "PM"),
    };
    format!("{h12:02}:{m:02} {ampm}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn focus_cycles_forward_and_back() {
        assert_eq!(Focus::Sidebar.next(), Focus::Modules);
        assert_eq!(Focus::Activity.next(), Focus::Sidebar);
        assert_eq!(Focus::Sidebar.prev(), Focus::Activity);
    }

    #[test]
    fn tab_cycles_focus() {
        let mut s = DashboardScreen::new();
        assert_eq!(s.focus, Focus::Sidebar);
        s.handle_key(KeyCode::Tab);
        assert_eq!(s.focus, Focus::Modules);
    }

    #[test]
    fn enter_on_module_opens_modal() {
        let mut s = DashboardScreen::new();
        s.handle_key(KeyCode::Tab); // -> Modules
        assert!(s.open_module.is_none());
        s.handle_key(KeyCode::Enter);
        assert_eq!(s.open_module, Some(0));
        // Esc closes it.
        s.handle_key(KeyCode::Esc);
        assert!(s.open_module.is_none());
    }

    #[test]
    fn esc_from_non_sidebar_returns_to_sidebar() {
        let mut s = DashboardScreen::new();
        s.handle_key(KeyCode::Tab); // Modules
        let action = s.handle_key(KeyCode::Esc);
        assert!(action.is_none());
        assert_eq!(s.focus, Focus::Sidebar);
    }

    #[test]
    fn esc_from_sidebar_goes_back() {
        let mut s = DashboardScreen::new();
        assert_eq!(s.handle_key(KeyCode::Esc), Some(Action::Back));
    }

    #[test]
    fn digit_jumps_section() {
        let mut s = DashboardScreen::new();
        s.handle_key(KeyCode::Char('2'));
        assert_eq!(s.active, 1);
        assert_eq!(s.active_section(), Section::Tools);
    }

    #[test]
    fn module_grid_navigation() {
        let mut s = DashboardScreen::new();
        s.handle_key(KeyCode::Tab); // Modules
        s.handle_key(KeyCode::Right);
        assert_eq!(s.module_sel, 1);
        s.handle_key(KeyCode::Down);
        assert_eq!(s.module_sel, 3); // +2 cols
        s.handle_key(KeyCode::Left);
        assert_eq!(s.module_sel, 2);
    }

    #[test]
    fn q_quits() {
        let mut s = DashboardScreen::new();
        assert_eq!(s.handle_key(KeyCode::Char('q')), Some(Action::Quit));
    }
}
