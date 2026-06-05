//! The main Dashboard screen: a full-width shell (header / sidebar / footer)
//! wrapping stat cards, a module-card grid, an updates list and an activity log.
//!
//! Built on the reusable [`shell`](crate::ui::shell) chrome. The sidebar drives
//! an internal "active section"; only [`Section::Dashboard`] renders full
//! content for now, other sections show a placeholder.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossterm::event::{KeyCode, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::action::Action;
use crate::data::{ActivityEntry, DashboardData, Module, ModuleUpdate, Section};
use crate::status::TorideStatus;
use crate::ui::helpers::{format_bytes, format_duration, percent_color};
use crate::ui::responsive::truncate_str;
use crate::ui::screens::AppScreen;
use crate::ui::screens::ssh::SshContent;
use crate::ui::shell::{
    SIDEBAR_W, SIDEBAR_W_COLLAPSED, Sidebar, gauge_hitboxes, render_footer, render_header,
    shell_layout, header::HeaderData,
};
use crate::ui::theme::Palette;
use crate::ui::widgets::{
    Card, Modal, Tooltip, accent_badge, kv, kv_with_suffix, neutral_badge,
    render_panel, render_titled_panel, tag_badge, title_line, title_line_with_detail,
};
use crate::ui::screens::base::ScreenBase;
use tachyonfx::{EffectManager, Interpolation, fx};

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

/// Which header gauge is currently hovered by the mouse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GaugeKind {
    Cpu,
    Ram,
    Disk,
    Net,
}

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
    gauge_hover: Option<GaugeKind>,
    gauge_hitboxes: [Rect; 4],
    /// Hitbox rects for module cards (rebuilt each frame).
    module_hitboxes: Vec<Rect>,
    /// Live network throughput (bytes/sec).
    net_rx_rate: Option<f64>,
    net_tx_rate: Option<f64>,
    /// Live disk I/O throughput (bytes/sec).
    disk_read_rate: Option<f64>,
    disk_write_rate: Option<f64>,
    base: ScreenBase,
    clock: String,
    shimmer_start: Instant,
    /// Tooltip fade-in effect manager.
    tooltip_fx: EffectManager<()>,
    /// Previous hover state for detecting transitions.
    prev_gauge_hover: Option<GaugeKind>,
    /// Timestamp of the last render call (for frame deltas).
    last_frame: Instant,
    /// SSH management content (rendered when Section::Ssh is active).
    ssh_content: SshContent,
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
            gauge_hover: None,
            gauge_hitboxes: [Rect::default(); 4],
            module_hitboxes: Vec::new(),
            net_rx_rate: None,
            net_tx_rate: None,
            disk_read_rate: None,
            disk_write_rate: None,
            base: ScreenBase::new(),
            clock,
            shimmer_start: Instant::now(),
            tooltip_fx: EffectManager::default(),
            prev_gauge_hover: None,
            last_frame: Instant::now(),
            ssh_content: SshContent::new(),
        }
    }

    /// Store the latest collected system status and compute live throughput rates.
    pub fn set_status(&mut self, status: TorideStatus) {
        if let Some(prev) = &self.status {
            let dt = (status.collected_at)
                .duration_since(prev.collected_at)
                .map_or(0.5, |d| d.as_secs_f64())
                .max(0.1);

            // Network throughput
            let rx = status.system.network.bytes_received as f64
                - prev.system.network.bytes_received as f64;
            let tx = status.system.network.bytes_transmitted as f64
                - prev.system.network.bytes_transmitted as f64;
            self.net_rx_rate = Some(rx.max(0.0) / dt);
            self.net_tx_rate = Some(tx.max(0.0) / dt);

            // Disk I/O throughput
            let dr = status.system.disk_io.read_bytes as f64
                - prev.system.disk_io.read_bytes as f64;
            let dw = status.system.disk_io.written_bytes as f64
                - prev.system.disk_io.written_bytes as f64;
            self.disk_read_rate = Some(dr.max(0.0) / dt);
            self.disk_write_rate = Some(dw.max(0.0) / dt);
        }
        self.status = Some(status);
    }

    /// Refresh the wall-clock label (called from the app refresh tick).
    pub fn tick_clock(&mut self) {
        self.clock = current_clock();
    }

    /// Provide live SSH key data (called from the SSH data collector).
    pub fn set_ssh_keys(&mut self, keys: Vec<crate::ui::screens::ssh::SshKeyEntry>) {
        self.ssh_content.set_keys(keys);
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
                self.sidebar.scroll(if down { 1 } else { -1 });
            }
        }
    }

    /// Check if a screen coordinate falls within a header gauge hitbox.
    fn gauge_at(&self, col: u16, row: u16) -> Option<GaugeKind> {
        let kinds = [GaugeKind::Cpu, GaugeKind::Ram, GaugeKind::Disk, GaugeKind::Net];
        for (i, rect) in self.gauge_hitboxes.iter().enumerate() {
            if col >= rect.x && col < rect.right() && row >= rect.y && row < rect.bottom() {
                return Some(kinds[i]);
            }
        }
        None
    }

    /// Check if a screen coordinate falls within a module card hitbox.
    fn module_at(&self, col: u16, row: u16) -> Option<usize> {
        self.module_hitboxes
            .iter()
            .position(|rect| col >= rect.x && col < rect.right() && row >= rect.y && row < rect.bottom())
    }

    // ── Render ─────────────────────────────────────────────────────────────────

    fn render(&mut self, frame: &mut Frame, p: Palette, skip_bg: bool) {
        let area = frame.area();
        if ScreenBase::guard_too_small(frame, p) {
            return;
        }

        self.base.render_bg(frame.buffer_mut(), area, p, skip_bg);

        let collapsed = self.sidebar.is_collapsed() || area.width < AUTO_COLLAPSE_W;
        let sidebar_w = if collapsed {
            SIDEBAR_W_COLLAPSED
        } else {
            SIDEBAR_W
        };

        let shell = shell_layout(area, sidebar_w);

        // Header gauges from live status when available.
        let (cpu, ram, disk_label, net_label) = self.gauges();
        let header_data = HeaderData {
            cpu,
            ram,
            disk: disk_label.as_deref(),
            net: net_label.as_deref(),
            clock: &self.clock,
            shimmer_start: self.shimmer_start,
        };
        render_header(
            frame,
            shell.header,
            p,
            &header_data,
        );

        // Refresh gauge hitboxes for hover detection.
        self.gauge_hitboxes = gauge_hitboxes(shell.header, &header_data);

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
        } else if self.active_section() == Section::Ssh {
            self.ssh_content.view(frame, content, p);
        } else {
            render_placeholder(frame, content, p, self.active_section());
        }

        // ── Module detail modal ───────────────────────────────────────────────
        if let Some(idx) = self.open_module
            && let Some(m) = self.data.modules.get(idx)
        {
            render_module_modal(frame, p, m);
        }

        // ── Header gauge tooltip overlay ────────────────────────────────────
        let dt = self.last_frame.elapsed();
        self.last_frame = Instant::now();

        // Detect hover transitions and manage fade-in effect.
        if self.gauge_hover != self.prev_gauge_hover {
            self.prev_gauge_hover = self.gauge_hover;
            if self.gauge_hover.is_some() {
                self.tooltip_fx = EffectManager::default();
                self.tooltip_fx.add_effect(
                    fx::fade_from_fg(p.panel, (300, Interpolation::SineOut))
                );
            } else {
                self.tooltip_fx = EffectManager::default();
            }
        }

        if let Some(gauge) = self.gauge_hover {
            if let Some(status) = &self.status {
                let rates = LiveRates {
                    net_rx: self.net_rx_rate,
                    net_tx: self.net_tx_rate,
                    disk_read: self.disk_read_rate,
                    disk_write: self.disk_write_rate,
                };
                if let Some(rect) = render_gauge_tooltip(
                    frame, p, gauge, &self.gauge_hitboxes,
                    shell.header, status, &rates,
                ) {
                    self.tooltip_fx.process_effects(
                        dt.into(), frame.buffer_mut(), rect,
                    );
                }
            }
        }
    }

    fn gauges(&self) -> (Option<f64>, Option<f64>, Option<String>, Option<String>) {
        let net_label = match (self.net_rx_rate, self.net_tx_rate) {
            (Some(rx), Some(tx)) => Some(format!("{}↓ {}↑", format_rate(rx), format_rate(tx))),
            _ => None,
        };
        let disk_label = match (self.disk_read_rate, self.disk_write_rate) {
            (Some(read), Some(write)) => Some(format!("{}↓ {}↑", format_rate(read), format_rate(write))),
            _ => None,
        };
        match &self.status {
            Some(s) => (
                s.system.cpu_usage,
                Some(s.system.memory.percentage),
                disk_label,
                net_label,
            ),
            None => (Some(35.0), Some(23.0), None, None),
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
        let inner = render_titled_panel(frame, area, p, " MODULES ", p.accent, focused);
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

        // Rebuild module hitboxes for click detection.
        self.module_hitboxes.clear();

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
                // Record hitbox — index matches position in the module data vec.
                while self.module_hitboxes.len() <= idx {
                    self.module_hitboxes.push(Rect::default());
                }
                self.module_hitboxes[idx] = *cell;
            }
        }
    }

    fn render_updates_panel(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let focused = self.focus == Focus::Updates;
        let title = format!(" UPDATES AVAILABLE · {} ", self.data.updates_count());
        let inner = render_titled_panel(frame, area, p, &title, p.warn, focused);
        for (i, row) in list_rows(inner, self.updates_scroll, self.data.updates.len()) {
            render_update_row(frame, row, p, &self.data.updates[i]);
        }
    }

    fn render_activity_panel(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let focused = self.focus == Focus::Activity;
        let inner = render_titled_panel(frame, area, p, " RECENTLY INSTALLED ", p.accent3, focused);
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

        // Route input to SSH content when that section is active and focus
        // is not on the sidebar. Sidebar navigation still works normally.
        if self.active_section() == Section::Ssh && self.focus != Focus::Sidebar {
            return self.ssh_content.handle_key(code);
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

        // Header gauge hover always works (even with modals open).
        if matches!(mouse.kind, MouseEventKind::Moved | MouseEventKind::Drag(_)) {
            self.gauge_hover = self.gauge_at(mouse.column, mouse.row);
        }

        // Module detail modal open: block all background interaction.
        if self.open_module.is_some() {
            if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
                self.open_module = None;
            }
            return None;
        }

        match mouse.kind {
            // Hover: highlight sidebar item under the cursor.
            MouseEventKind::Moved | MouseEventKind::Drag(_) => {
                let idx = self.sidebar.item_at(mouse.column, mouse.row);
                self.sidebar.set_hovered(idx);
                // Delegate hover to SSH content when that section is active.
                if self.active_section() == Section::Ssh {
                    self.ssh_content.handle_mouse(mouse);
                }
            }
            // Click: select + activate the clicked element.
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some(idx) = self.sidebar.item_at(mouse.column, mouse.row) {
                    self.sidebar.select_to(idx);
                    self.active = idx;
                    self.focus = Focus::Sidebar;
                } else if self.active_section() == Section::Dashboard {
                    // Module clicks only work in the Dashboard section.
                    if let Some(idx) = self.module_at(mouse.column, mouse.row) {
                        self.module_sel = idx;
                        self.focus = Focus::Modules;
                        self.open_module = Some(idx);
                    }
                } else if self.active_section() == Section::Ssh {
                    return self.ssh_content.handle_mouse(mouse);
                }
            }
            MouseEventKind::ScrollDown | MouseEventKind::ScrollUp => {
                let down = matches!(mouse.kind, MouseEventKind::ScrollDown);
                if self.active_section() == Section::Ssh && self.focus != Focus::Sidebar {
                    return self.ssh_content.handle_mouse(mouse);
                }
                self.scroll_focused(down);
            }
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
        self.base.invalidate();
    }

    fn needs_animation(&self) -> bool {
        self.sidebar.is_animating()
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
    let inner = render_panel(frame, area, None, p.text, border, p.panel);
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
    let inner = render_panel(frame, area, None, p.text, p.border, p.bg);
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

// ── Header gauge tooltip ─────────────────────────────────────────────────────

/// Live throughput rates passed to tooltip renderers.
struct LiveRates {
    net_rx: Option<f64>,
    net_tx: Option<f64>,
    disk_read: Option<f64>,
    disk_write: Option<f64>,
}

/// Render a floating popup card anchored below the hovered header gauge.
///
/// Returns `Some(rect)` if the tooltip was rendered, `None` if it didn't fit.
fn render_gauge_tooltip(
    frame: &mut Frame,
    p: Palette,
    gauge: GaugeKind,
    hitboxes: &[Rect; 4],
    header_area: Rect,
    status: &TorideStatus,
    rates: &LiveRates,
) -> Option<Rect> {
    let idx = match gauge {
        GaugeKind::Cpu => 0,
        GaugeKind::Ram => 1,
        GaugeKind::Disk => 2,
        GaugeKind::Net => 3,
    };
    let hitbox = hitboxes[idx];
    let lines = gauge_tooltip_lines(gauge, status, p, rates);

    // Construct an anchor whose `.bottom()` equals `header_area.bottom()` so the
    // tooltip appears just below the header, centered on the gauge hitbox.
    let anchor = Rect::new(
        hitbox.x,
        header_area.bottom().saturating_sub(1),
        hitbox.width,
        1,
    );
    Tooltip::new(&lines).anchor(anchor).render(frame, p)
}

/// Build tooltip content lines for a given gauge kind.
fn gauge_tooltip_lines(gauge: GaugeKind, status: &TorideStatus, p: Palette, rates: &LiveRates) -> Vec<Line<'static>> {
    match gauge {
        GaugeKind::Cpu => cpu_tooltip_lines(&status.system, p),
        GaugeKind::Ram => ram_tooltip_lines(&status.system, p),
        GaugeKind::Disk => disk_tooltip_lines(&status.system, p, rates),
        GaugeKind::Net => net_tooltip_lines(&status.system, p, rates),
    }
}

fn cpu_tooltip_lines(sys: &crate::status::SystemStatus, p: Palette) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    // Title
    lines.push(title_line_with_detail("CPU", &sys.static_info.cpu_brand, p));

    // Usage — kept manual because value uses `.bold()`, unique to CPU.
    if let Some(usage) = sys.cpu_usage {
        let color = percent_color(usage, p);
        lines.push(Line::from(vec![
            Span::styled(format!("{:<7}", "Usage"), Style::new().fg(p.text_muted)),
            Span::styled(format!("{usage:.0}%"), Style::new().fg(color).bold()),
        ]));
    }

    // Cores
    let phys = sys.physical_cores.map_or_else(|| "—".to_string(), |c| c.to_string());
    let log = sys.static_info.logical_cores;
    lines.push(kv("Cores", &format!("{phys} / {log}"), p));

    // Load average
    if let Some(load) = &sys.load_average {
        lines.push(kv("Load", &format!("{:.2} / {:.2} / {:.2}", load.one, load.five, load.fifteen), p));
    }

    // Per-core mini readout (dynamic multi-span — kept manual)
    if !sys.cpu_cores.is_empty() {
        let mut cores: Vec<Span<'static>> = Vec::new();
        for (i, c) in sys.cpu_cores.iter().enumerate() {
            if i > 0 {
                cores.push(Span::styled(" ", Style::new()));
            }
            let color = percent_color(c.usage, p);
            cores.push(Span::styled(format!("{:.0}", c.usage), Style::new().fg(color)));
        }
        let mut line = vec![Span::styled(format!("{:<7}", "Core"), Style::new().fg(p.text_muted))];
        line.append(&mut cores);
        lines.push(Line::from(line));
    }

    lines
}

fn ram_tooltip_lines(sys: &crate::status::SystemStatus, p: Palette) -> Vec<Line<'static>> {
    let m = &sys.memory;
    let mut lines = Vec::new();

    lines.push(title_line("Memory", p));

    let color = percent_color(m.percentage, p);
    lines.push(kv_with_suffix(
        "Used",
        &format!("{} / {}", format_bytes(m.used_bytes), format_bytes(m.total_bytes)),
        &format!("  ({:.0}%)", m.percentage),
        color, p,
    ));

    lines.push(kv("Free", &format_bytes(m.available_bytes), p));

    if m.cached_bytes > 0 {
        lines.push(kv("Cached", &format_bytes(m.cached_bytes), p));
    }

    if let Some(swap) = &sys.swap {
        let swap_color = percent_color(swap.percentage, p);
        lines.push(kv_with_suffix(
            "Swap",
            &format!("{} / {}", format_bytes(swap.used_bytes), format_bytes(swap.total_bytes)),
            &format!("  ({:.0}%)", swap.percentage),
            swap_color, p,
        ));
    }

    lines
}

fn disk_tooltip_lines(sys: &crate::status::SystemStatus, p: Palette, rates: &LiveRates) -> Vec<Line<'static>> {
    let d = &sys.disk;
    let mut lines = Vec::new();

    lines.push(title_line_with_detail("Disk", &d.name, p));
    lines.push(kv("Mount", &d.mount_point, p));
    lines.push(kv("FS", &d.filesystem, p));

    let color = percent_color(d.percentage, p);
    lines.push(kv_with_suffix(
        "Used",
        &format!("{} / {}", format_bytes(d.used_bytes), format_bytes(d.total_bytes)),
        &format!("  ({:.0}%)", d.percentage),
        color, p,
    ));

    lines.push(kv("Free", &format_bytes(d.available_bytes), p));
    lines.push(kv("Type", &d.disk_type, p));

    // Disk I/O — live throughput
    if rates.disk_read.is_some() || rates.disk_write.is_some() {
        let read_s = rates.disk_read.map_or_else(|| "—".to_string(), format_rate);
        let write_s = rates.disk_write.map_or_else(|| "—".to_string(), format_rate);
        lines.push(kv("Read", &format!("{read_s}/s"), p));
        lines.push(kv("Write", &format!("{write_s}/s"), p));
    }

    lines
}

fn net_tooltip_lines(sys: &crate::status::SystemStatus, p: Palette, rates: &LiveRates) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    lines.push(title_line("Network", p));

    let dl_rate = rates.net_rx.map_or_else(|| "—".to_string(), |r| format!("{}/s", format_rate(r)));
    let ul_rate = rates.net_tx.map_or_else(|| "—".to_string(), |r| format!("{}/s", format_rate(r)));

    lines.push(kv("Down", &dl_rate, p));
    lines.push(kv("Up", &ul_rate, p));

    lines.push(Line::raw(""));

    lines.push(kv("Total", &format!("{} ↓  {} ↑", format_bytes(sys.network.bytes_received), format_bytes(sys.network.bytes_transmitted)), p));

    lines
}

/// Format a bytes/sec rate as a human-readable string (e.g. `"12.3 KB"`).
fn format_rate(bytes_per_sec: f64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    if bytes_per_sec >= GB {
        format!("{:.1} GB", bytes_per_sec / GB)
    } else if bytes_per_sec >= MB {
        format!("{:.1} MB", bytes_per_sec / MB)
    } else if bytes_per_sec >= KB {
        format!("{:.1} KB", bytes_per_sec / KB)
    } else {
        format!("{:.0} B", bytes_per_sec)
    }
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
