use ratatui::{
    Frame,
    buffer::Buffer,
    layout::{Constraint, Flex, Layout, Position, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::action::Action;
use crate::ui::responsive::{self, Viewport};
use crate::ui::theme::{self, Palette};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const EDITION: &str = "SINGLE-HOST";

const KEY_BG: Color = Color::Rgb(32, 26, 50);

// ANSI Shadow figlet — matches screens.jsx LOGO constant exactly
const LOGO: &[&str] = &[
    "████████╗ ██████╗ ██████╗ ██╗██████╗ ███████╗",
    "╚══██╔══╝██╔═══██╗██╔══██╗██║██╔══██╗██╔════╝",
    "   ██║   ██║   ██║██████╔╝██║██║  ██║█████╗  ",
    "   ██║   ██║   ██║██╔══██╗██║██║  ██║██╔══╝  ",
    "   ██║   ╚██████╔╝██║  ██║██║██████╔╝███████╗",
    "   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝",
];

pub struct WelcomeScreen {
    gradient_cache: Option<(Rect, Buffer)>,
}

impl Default for WelcomeScreen {
    fn default() -> Self {
        Self::new()
    }
}

impl WelcomeScreen {
    pub fn new() -> Self {
        Self {
            gradient_cache: None,
        }
    }

    pub fn invalidate_cache(&mut self) {
        self.gradient_cache = None;
    }

    pub fn handle_key(&self, code: ratatui::crossterm::event::KeyCode) -> Option<Action> {
        use ratatui::crossterm::event::KeyCode;
        match code {
            KeyCode::Char('q') | KeyCode::Esc => Some(Action::Quit),
            KeyCode::Char('?') => Some(Action::Help),
            KeyCode::Enter | KeyCode::Char(' ') => Some(Action::Continue),
            _ => None,
        }
    }

    pub fn view(&mut self, frame: &mut Frame) {
        self.view_with_palette(frame, theme::CHARM);
    }

    fn view_with_palette(&mut self, frame: &mut Frame, p: Palette) {
        let area = frame.area();
        let viewport = Viewport::from_area(area);

        // Fallback for tiny terminals
        if responsive::render_too_small(frame, p) {
            return;
        }

        // Gradient background
        let buf = frame.buffer_mut();
        let needs_regen = !self
            .gradient_cache
            .as_ref()
            .is_some_and(|(cached_area, _)| *cached_area == area);
        if needs_regen {
            let mut gradient = Buffer::empty(area);
            render_gradient_bg(&mut gradient, area, p);
            copy_bg(&gradient, buf, area);
            self.gradient_cache = Some((area, gradient));
        } else if let Some((_, ref gradient)) = self.gradient_cache {
            copy_bg(gradient, buf, area);
        }

        // Adaptive center column
        let [_, center, _] = Layout::horizontal([
            Constraint::Fill(1),
            responsive::center_column(),
            Constraint::Fill(1),
        ])
        .flex(Flex::Center)
        .areas(area);

        // Vertical layout
        let [
            _top,
            logo_area,
            _g1,
            version_area,
            prompt_area,
            _g2,
            keys_area,
            _bottom,
        ] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(6),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Fill(1),
        ])
        .areas(center);

        // ── Logo ──────────────────────────────────────────────────────────
        let logo_style = Style::new().fg(p.accent).bold();
        let logo_lines = responsive::truncate_logo(LOGO, center.width, logo_style);
        frame.render_widget(Paragraph::new(logo_lines).centered(), logo_area);

        // ── Version ───────────────────────────────────────────────────────
        let version_line = Line::from(vec![
            Span::styled("砦", Style::new().fg(p.accent2).bold()),
            Span::styled("  ·  ", Style::new().fg(p.text_muted)),
            Span::styled(VERSION, Style::new().fg(p.accent2).bold()),
            Span::styled("  ·  ", Style::new().fg(p.text_muted)),
            Span::styled(EDITION, Style::new().fg(p.accent2).bold()),
        ]);
        frame.render_widget(Paragraph::new(version_line).centered(), version_area);

        // ── Prompt ────────────────────────────────────────────────────────
        let prompt_text = if viewport >= Viewport::Compact {
            "Press any key, or click anywhere, to enter."
        } else {
            "Press any key to enter."
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                prompt_text,
                Style::new().fg(p.text_dim),
            )))
            .centered(),
            prompt_area,
        );

        // ── Keybindings ───────────────────────────────────────────────────
        let key_style = Style::new().fg(p.text).bg(KEY_BG);
        let lbl_style = Style::new().fg(p.text_muted);

        let keys_line = if viewport >= Viewport::Compact {
            let gap = Span::raw("     ");
            Line::from(vec![
                Span::styled(" ↵ ", key_style),
                Span::raw(" "),
                Span::styled("continue", lbl_style),
                gap.clone(),
                Span::styled(" ? ", key_style),
                Span::raw(" "),
                Span::styled("help", lbl_style),
                gap.clone(),
                Span::styled(" q ", key_style),
                Span::raw(" "),
                Span::styled("quit", lbl_style),
            ])
        } else {
            // Minimal — badges only, no labels
            Line::from(vec![
                Span::styled(" ↵ ", key_style),
                Span::raw(" "),
                Span::styled(" ? ", key_style),
                Span::raw(" "),
                Span::styled(" q ", key_style),
            ])
        };
        frame.render_widget(Paragraph::new(keys_line).centered(), keys_area);
    }
}

// ── Gradient background ──────────────────────────────────────────────────────

fn render_gradient_bg(buf: &mut Buffer, area: Rect, p: Palette) {
    let (cr, cg, cb) = rgb_components(p.bg);
    let er = (cr as f64 * 0.6) as u8;
    let eg = (cg as f64 * 0.6) as u8;
    let eb = (cb as f64 * 0.6) as u8;

    let cx = (area.left() + area.right()) / 2;
    let cy = (area.top() + area.bottom()) / 2;
    let max_dist = ((cx.saturating_sub(area.left()) as f64)
        .hypot(cy.saturating_sub(area.top()) as f64))
    .max(1.0);

    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            let dx = (x as i32 - cx as i32).abs() as f64;
            let dy = (y as i32 - cy as i32).abs() as f64;
            let t = (dx.hypot(dy) / max_dist).min(1.0).powi(3);
            let r = lerp(cr as f64, er as f64, t) as u8;
            let g = lerp(cg as f64, eg as f64, t) as u8;
            let b = lerp(cb as f64, eb as f64, t) as u8;
            if let Some(cell) = buf.cell_mut(Position::new(x, y)) {
                cell.set_bg(Color::Rgb(r, g, b));
            }
        }
    }
}

fn rgb_components(color: Color) -> (u8, u8, u8) {
    match color {
        Color::Rgb(r, g, b) => (r, g, b),
        _ => (0, 0, 0),
    }
}

fn lerp(a: f64, b: f64, t: f64) -> f64 {
    a * (1.0 - t) + b * t
}

fn copy_bg(src: &Buffer, dst: &mut Buffer, area: Rect) {
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            if let Some(s) = src.cell(Position::new(x, y))
                && let Some(d) = dst.cell_mut(Position::new(x, y))
            {
                d.set_bg(s.bg);
            }
        }
    }
}
