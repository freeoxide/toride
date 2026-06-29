use std::time::Instant;

use crate::action::Action;
use crate::ui::components::{ButtonRow, interactive_button::InteractiveButton};
use crate::ui::responsive::{self, Viewport};
use crate::ui::screens::AppScreen;
use crate::ui::screens::base::ScreenBase;
use crate::ui::theme::Palette;
use crate::ui::widgets::gradient::AnimatedBorder;
use crate::version;
use crossterm::event::{KeyCode, MouseEvent};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};

// ANSI Shadow figlet — matches screens.jsx LOGO constant exactly
const LOGO: &[&str] = &[
    "████████╗ ██████╗ ██████╗ ██╗██████╗ ███████╗",
    "╚══██╔══╝██╔═══██╗██╔══██╗██║██╔══██╗██╔════╝",
    "   ██║   ██║   ██║██████╔╝██║██║  ██║█████╗  ",
    "   ██║   ██║   ██║██╔══██╗██║██║  ██║██╔══╝  ",
    "   ██║   ╚██████╔╝██║  ██║██║██████╔╝███████╗",
    "   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝",
];

/// Splash screen with an animated border, shimmer logo, and a button row.
pub struct WelcomeScreen {
    base: ScreenBase,
    border: AnimatedBorder,
    buttons: ButtonRow<Action>,
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
                return Some(self.buttons.activate_focused().unwrap_or(Action::Continue));
            }
            _ => {}
        }

        // Focus cycling
        match code {
            KeyCode::Tab | KeyCode::Right => self.buttons.cycle_focus_next(),
            KeyCode::BackTab | KeyCode::Left => self.buttons.cycle_focus_prev(),
            _ => {}
        }
        None
    }

    fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action> {
        self.buttons.handle_mouse(&mouse)
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
        true // shimmer always runs
    }
}

impl WelcomeScreen {
    /// Construct a new welcome screen with the default button row.
    #[must_use]
    pub fn new() -> Self {
        let buttons = vec![
            InteractiveButton::new("↵ continue", "↵", Action::Continue),
            InteractiveButton::new("? help", "?", Action::Help),
            InteractiveButton::new("q quit", "q", Action::Quit),
        ];

        Self {
            base: ScreenBase::new(),
            border: AnimatedBorder::new(Palette::default().accent),
            buttons: ButtonRow::new(buttons, vec![0, 2, 2]),
            shimmer_start: Instant::now(),
        }
    }

    /// Update the animated border color (used when the theme changes).
    pub fn set_border_color(&mut self, color: ratatui::style::Color) {
        self.border = AnimatedBorder::new(color);
    }

    fn render(&mut self, frame: &mut Frame, p: Palette, skip_bg: bool) {
        let area = frame.area();
        let viewport = Viewport::from_area(area);

        // Fallback for tiny terminals
        if ScreenBase::guard_too_small(frame, p) {
            return;
        }

        // Gradient background
        self.base.render_bg(frame.buffer_mut(), area, p, skip_bg);

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
        if p.reduced_motion {
            // Static single-colour outline — no per-frame colour flow.
            self.border.draw_static(buf, border_rect);
        } else {
            self.border.draw(buf, border_rect);
        }

        // ── Logo ──────────────────────────────────────────────────────────
        let logo_style = Style::new().fg(p.accent).bold();
        let logo_lines = responsive::truncate_logo(LOGO, center.width, logo_style);
        frame.render_widget(Paragraph::new(logo_lines).centered(), logo_area);

        // Shimmer sweep across logo — skipped under reduced motion (solid accent).
        if !p.reduced_motion {
            let elapsed = self.shimmer_start.elapsed().as_secs_f32();
            let buf = frame.buffer_mut();
            apply_logo_shimmer(buf, logo_area, p.accent, elapsed);
        }

        // ── Version ───────────────────────────────────────────────────────
        let version_line = Line::from(vec![
            Span::styled("砦", Style::new().fg(p.accent2).bold()),
            Span::styled("  ·  ", Style::new().fg(p.text_muted)),
            Span::styled(version::VERSION, Style::new().fg(p.accent2).bold()),
            Span::styled("  ·  ", Style::new().fg(p.text_muted)),
            Span::styled(version::EDITION, Style::new().fg(p.accent2).bold()),
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
        self.buttons.render(buf, keys_area, p, viewport);
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
        assert!(screen.needs_animation());
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
