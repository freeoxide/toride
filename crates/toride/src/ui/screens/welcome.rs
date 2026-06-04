use std::time::Instant;

use crossterm::event::{KeyCode, MouseEvent};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};
use ratatui_interact::state::FocusManager;

use crate::action::Action;
use crate::ui::components::interactive_button::InteractiveButton;
use crate::ui::responsive::{self, Viewport};
use crate::ui::screens::AppScreen;
use crate::ui::theme::Palette;
use crate::ui::widgets::gradient::{AnimatedBorder, GradientCache};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const EDITION: &str = "SINGLE-HOST";

// ANSI Shadow figlet — matches screens.jsx LOGO constant exactly
const LOGO: &[&str] = &[
    "████████╗ ██████╗ ██████╗ ██╗██████╗ ███████╗",
    "╚══██╔══╝██╔═══██╗██╔══██╗██║██╔══██╗██╔════╝",
    "   ██║   ██║   ██║██████╔╝██║██║  ██║█████╗  ",
    "   ██║   ██║   ██║██╔══██╗██║██║  ██║██╔══╝  ",
    "   ██║   ╚██████╔╝██║  ██║██║██████╔╝███████╗",
    "   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝",
];

/// Horizontal gaps between the three buttons (after btn 0, 1, 2).
const BTN_GAPS: &[u16] = &[0, 2, 2];

/// Actions associated with each button index.
const BTN_ACTIONS: &[Action] = &[Action::Continue, Action::Help, Action::Quit];

pub struct WelcomeScreen {
    gradient_cache: GradientCache,
    border: AnimatedBorder,
    buttons: [InteractiveButton<Action>; 3],
    focus: FocusManager<usize>,
    shimmer_start: Instant,
}

impl Default for WelcomeScreen {
    fn default() -> Self {
        Self::new()
    }
}

impl AppScreen for WelcomeScreen {
    fn handle_key(&mut self, code: KeyCode) -> Option<Action> {
        // Direct shortcuts always work
        match code {
            KeyCode::Char('q') | KeyCode::Esc => return Some(Action::Quit),
            KeyCode::Enter | KeyCode::Char(' ') => {
                let action = match self.focus.current() {
                    Some(&idx) => BTN_ACTIONS[idx],
                    None => Action::Continue,
                };
                return Some(action);
            }
            _ => {}
        }

        // Focus cycling
        match code {
            KeyCode::Tab | KeyCode::Right => self.focus.next(),
            KeyCode::BackTab | KeyCode::Left => self.focus.prev(),
            _ => {}
        }
        self.sync_focus_to_buttons();
        None
    }

    fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action> {
        self.buttons
            .iter_mut()
            .find_map(|btn| btn.handle_mouse(&mouse))
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
        true // shimmer always runs
    }
}

impl WelcomeScreen {
    #[must_use]
    pub fn new() -> Self {
        let buttons = [
            InteractiveButton::new("↵ continue", "↵", Action::Continue),
            InteractiveButton::new("? help", "?", Action::Help),
            InteractiveButton::new("q quit", "q", Action::Quit),
        ];

        let mut focus = FocusManager::new();
        focus.register_all([0, 1, 2]);

        let mut screen = Self {
            gradient_cache: GradientCache::new(),
            border: AnimatedBorder::new(Palette::default().accent),
            buttons,
            focus,
            shimmer_start: Instant::now(),
        };
        screen.sync_focus_to_buttons();
        screen
    }

    /// Update the animated border color (used when the theme changes).
    pub fn set_border_color(&mut self, color: ratatui::style::Color) {
        self.border = AnimatedBorder::new(color);
    }

    fn render(&mut self, frame: &mut Frame, p: Palette, skip_bg: bool) {
        let area = frame.area();
        let viewport = Viewport::from_area(area);

        // Fallback for tiny terminals
        if responsive::render_too_small(frame, p) {
            return;
        }

        // Gradient background
        if !skip_bg {
            let buf = frame.buffer_mut();
            self.gradient_cache.render_or_copy(buf, area, p);
        }

        // Adaptive center column
        let center = responsive::center_area(area);

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

        // ── Animated border ───────────────────────────────────────────────
        let border_rect = content_border_rect(logo_area, keys_area, area);
        let buf = frame.buffer_mut();
        self.border.draw(buf, border_rect);

        // ── Logo ──────────────────────────────────────────────────────────
        let logo_style = Style::new().fg(p.accent).bold();
        let logo_lines = responsive::truncate_logo(LOGO, center.width, logo_style);
        frame.render_widget(Paragraph::new(logo_lines).centered(), logo_area);

        // Shimmer sweep across logo
        let elapsed = self.shimmer_start.elapsed().as_secs_f32();
        let buf = frame.buffer_mut();
        apply_logo_shimmer(buf, logo_area, p.accent, elapsed);

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
            "Press any key, or click a button, to enter."
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

        // ── Interactive buttons ───────────────────────────────────────────
        let buf = frame.buffer_mut();
        self.render_buttons(buf, keys_area, p, viewport);
    }

    fn render_buttons(
        &mut self,
        buf: &mut ratatui::buffer::Buffer,
        keys_area: Rect,
        p: Palette,
        viewport: Viewport,
    ) {
        // Compute widths
        let btn_widths: [u16; 3] = std::array::from_fn(|i| self.buttons[i].min_width(viewport));

        let total_btn: u16 = btn_widths.iter().sum();
        let total_gap: u16 = BTN_GAPS.iter().sum();
        let total_width = total_btn + total_gap;

        // Centre the button row within keys_area
        let btn_row_x = keys_area.x.saturating_sub(total_width / 2) + keys_area.width / 2;

        let mut cursor_x = btn_row_x;
        for (i, &width) in btn_widths.iter().enumerate() {
            let btn_area = ratatui::layout::Rect::new(cursor_x, keys_area.y, width, 1);
            self.buttons[i].render(buf, btn_area, p, viewport);
            cursor_x += width + BTN_GAPS[i];
        }
    }

    fn sync_focus_to_buttons(&mut self) {
        let focused = self.focus.current().copied();
        for (i, btn) in self.buttons.iter_mut().enumerate() {
            btn.set_focused(focused == Some(i));
        }
    }
}

// ── Layout helpers ─────────────────────────────────────────────────────────────

/// Compute the border rect as the union of content areas expanded by 2 cells
/// of padding, clamped to the frame area.
fn content_border_rect(logo_area: Rect, keys_area: Rect, frame_area: Rect) -> Rect {
    let pad = 2u16;
    let x = logo_area.x.saturating_sub(pad).max(frame_area.x);
    let y = logo_area.y.saturating_sub(pad).max(frame_area.y);
    let right = (keys_area.right() + pad).min(frame_area.right());
    let bottom = (keys_area.bottom() + pad).min(frame_area.bottom());
    Rect {
        x,
        y,
        width: right.saturating_sub(x),
        height: bottom.saturating_sub(y),
    }
}

// ── Logo shimmer ───────────────────────────────────────────────────────────────

fn apply_logo_shimmer(
    buf: &mut ratatui::buffer::Buffer,
    logo_area: ratatui::layout::Rect,
    _accent: ratatui::style::Color,
    elapsed: f32,
) {
    use ratatui::layout::Position;
    use tachyonfx::ColorSpace;

    let sweep_period = 3.0f32;
    let sweep_pos = (elapsed % sweep_period) / sweep_period;
    let sigma = 0.06f32;

    for y in logo_area.top()..logo_area.bottom() {
        for x in logo_area.left()..logo_area.right() {
            let cell = &mut buf[Position::new(x, y)];
            if cell.symbol() == " " {
                continue;
            }

            let cell_norm = f32::from(x - logo_area.left()) / f32::from(logo_area.width.max(1));
            let dist = cell_norm - sweep_pos;
            let brightness = (-dist * dist / (2.0 * sigma * sigma)).exp();

            if brightness > 0.01 {
                let fg = cell.fg;
                let lightened = ColorSpace::Hsl.lighten(&fg, brightness * 0.4);
                cell.set_fg(lightened);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crossterm::event::KeyCode;

    use super::WelcomeScreen;
    use crate::action::Action;
    use crate::ui::screens::AppScreen;

    #[test]
    fn new_creates_screen_with_working_invalidate_cache() {
        let mut screen = WelcomeScreen::new();
        // invalidate_cache should run without panicking
        screen.invalidate_cache();
        // Screen should still be functional after invalidation
        assert_eq!(screen.needs_animation(), true);
    }

    #[test]
    fn handle_key_returns_quit_for_q() {
        let mut screen = WelcomeScreen::new();
        assert_eq!(screen.handle_key(KeyCode::Char('q')), Some(Action::Quit));
    }

    #[test]
    fn handle_key_returns_quit_for_esc() {
        let mut screen = WelcomeScreen::new();
        assert_eq!(screen.handle_key(KeyCode::Esc), Some(Action::Quit));
    }

    #[test]
    fn handle_key_returns_continue_for_enter() {
        let mut screen = WelcomeScreen::new();
        // Button 0 (Continue) is focused by default, so Enter yields Continue
        assert_eq!(screen.handle_key(KeyCode::Enter), Some(Action::Continue));
    }

    #[test]
    fn handle_key_returns_none_for_other_keys() {
        let mut screen = WelcomeScreen::new();
        assert_eq!(screen.handle_key(KeyCode::Char('a')), None);
        assert_eq!(screen.handle_key(KeyCode::Char('z')), None);
        assert_eq!(screen.handle_key(KeyCode::Up), None);
        assert_eq!(screen.handle_key(KeyCode::Down), None);
    }

    #[test]
    fn needs_animation_returns_true() {
        let screen = WelcomeScreen::new();
        assert!(screen.needs_animation());
    }
}
