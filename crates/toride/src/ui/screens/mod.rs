pub mod help;
pub mod status;
pub mod welcome;

pub use help::HelpScreen;
pub use status::StatusScreen;
pub use welcome::WelcomeScreen;

use crossterm::event::{KeyCode, MouseEvent};
use ratatui::Frame;

use crate::action::Action;
use crate::ui::theme::Palette;

/// Shared interface for all TUI screens.
///
/// Each screen implements this trait so that [`App`](crate::app::App) can
/// dispatch input events, rendering, and lifecycle calls through a single
/// consistent API instead of scattered `match` blocks.
///
/// The name `AppScreen` avoids collision with [`crate::navigation::Screen`]
/// (the routing enum).
pub trait AppScreen {
    /// Handle a key press, returning an [`Action`] if the screen requests
    /// navigation or a global behaviour.
    fn handle_key(&mut self, code: KeyCode) -> Option<Action>;

    /// Handle a mouse event. Default: ignore.
    fn handle_mouse(&mut self, _mouse: MouseEvent) -> Option<Action> {
        None
    }

    /// Handle an action that was *not* consumed by [`App::update`](crate::app::App::update).
    /// Screens use this to route internally-handled actions like [`Action::ScrollDown`]
    /// / [`Action::ScrollUp`]. Default: no-op.
    fn handle_action(&mut self, _action: Action) {}

    /// Render the full screen (background gradient + content).
    fn view(&mut self, frame: &mut Frame, palette: Palette);

    /// Render only the foreground layer (content over an existing background).
    /// Used during animated transitions.
    fn view_foreground(&mut self, frame: &mut Frame, palette: Palette);

    /// Invalidate cached rendering data (e.g. gradient background).
    fn invalidate_cache(&mut self);

    /// Whether this screen currently needs animation ticks.
    /// Return `true` when the screen has an active animation (shimmer,
    /// spinner, etc.). Default: `false`.
    fn needs_animation(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use crate::ui::screens::AppScreen;
    use crate::ui::theme::CHARM;

    /// Helper: create a test terminal with the given viewport size.
    fn test_terminal(w: u16, h: u16) -> Terminal<TestBackend> {
        let backend = TestBackend::new(w, h);
        Terminal::new(backend).unwrap()
    }

    /// Render a screen into a test terminal and return the buffer as a string.
    fn render_to_string<S: AppScreen>(screen: &mut S, w: u16, h: u16) -> String {
        let mut terminal = test_terminal(w, h);
        terminal.draw(|f| screen.view(f, CHARM)).unwrap();
        terminal.backend().to_string()
    }

    // ── WelcomeScreen snapshot ──────────────────────────────────────────────

    #[test]
    fn welcome_screen_snapshot() {
        let mut screen = super::welcome::WelcomeScreen::new();
        let output = render_to_string(&mut screen, 80, 24);
        insta::assert_snapshot!("welcome_screen_80x24", output);
    }

    #[test]
    fn welcome_screen_too_small() {
        let mut screen = super::welcome::WelcomeScreen::new();
        let output = render_to_string(&mut screen, 20, 8);
        // Should show "Terminal too small" message
        assert!(
            output.contains("too small"),
            "expected 'too small' message, got: {output}"
        );
    }

    #[test]
    fn welcome_screen_minimal_viewport() {
        let mut screen = super::welcome::WelcomeScreen::new();
        let output = render_to_string(&mut screen, 30, 10);
        insta::assert_snapshot!("welcome_screen_30x10", output);
    }

    // ── HelpScreen modal snapshot ────────────────────────────────────────────

    #[test]
    fn help_screen_snapshot() {
        use ratatui::layout::{Position, Rect};
        use ratatui::style::Style;
        use ratatui::widgets::Block;

        use crate::ui::responsive::Viewport;

        let mut terminal = test_terminal(80, 24);
        terminal
            .draw(|f| {
                let area = f.area();
                // Simulate in-place dimming (same as App::render_help_modal)
                let dimmed_bg = match CHARM.bg {
                    ratatui::style::Color::Rgb(r, g, b) => {
                        ratatui::style::Color::Rgb(r / 3, g / 3, b / 3)
                    }
                    other => other,
                };
                let buf = f.buffer_mut();
                for cell in buf.content.iter_mut() {
                    let bg = blend_cell_color(cell.bg, dimmed_bg, 0.55);
                    cell.set_bg(bg);
                    let fg = blend_cell_color(cell.fg, dimmed_bg, 0.45);
                    cell.set_fg(fg);
                }
                let modal = Rect::new(
                    (area.width.saturating_sub(52)) / 2,
                    (area.height.saturating_sub(16)) / 2,
                    52,
                    16,
                );
                let block = Block::bordered()
                    .border_style(Style::new().fg(CHARM.border_hi))
                    .style(Style::new().bg(CHARM.panel));
                let content = block.inner(modal);
                f.render_widget(block, modal);
                super::help::HelpScreen::render(f, content, CHARM, Viewport::from_area(area));
            })
            .unwrap();
        let output = terminal.backend().to_string();
        insta::assert_snapshot!("help_screen_80x24", output);
    }

    #[test]
    fn help_screen_minimal_viewport() {
        use ratatui::layout::Rect;
        use ratatui::style::Style;
        use ratatui::widgets::Block;

        use crate::ui::responsive::Viewport;

        let mut terminal = test_terminal(35, 12);
        terminal
            .draw(|f| {
                let area = f.area();
                let dimmed_bg = match CHARM.bg {
                    ratatui::style::Color::Rgb(r, g, b) => {
                        ratatui::style::Color::Rgb(r / 3, g / 3, b / 3)
                    }
                    other => other,
                };
                let buf = f.buffer_mut();
                for pos in buf.area().cells() {
                    let cell = &mut buf[pos];
                    let bg = blend_cell_color(cell.bg, dimmed_bg, 0.55);
                    cell.set_bg(bg);
                    let fg = blend_cell_color(cell.fg, dimmed_bg, 0.45);
                    cell.set_fg(fg);
                }
                let modal = Rect::new(
                    (area.width.saturating_sub(52)) / 2,
                    (area.height.saturating_sub(16)) / 2,
                    52.min(area.width),
                    16.min(area.height),
                );
                let block = Block::bordered()
                    .border_style(Style::new().fg(CHARM.border_hi))
                    .style(Style::new().bg(CHARM.panel));
                let content = block.inner(modal);
                f.render_widget(block, modal);
                super::help::HelpScreen::render(f, content, CHARM, Viewport::from_area(area));
            })
            .unwrap();
        let output = terminal.backend().to_string();
        insta::assert_snapshot!("help_screen_35x12", output);
    }

    /// Linearly interpolate a color toward a target (mirrors `blend_toward` in render.rs).
    fn blend_cell_color(
        color: ratatui::style::Color,
        target: ratatui::style::Color,
        t: f32,
    ) -> ratatui::style::Color {
        let ratatui::style::Color::Rgb(cr, cg, cb) = color else {
            return color;
        };
        let ratatui::style::Color::Rgb(tr, tg, tb) = target else {
            return color;
        };
        #[expect(clippy::cast_lossless, reason = "u8→f32 for blending math")]
        let r = (cr as f32 + (tr as f32 - cr as f32) * t).round() as u8;
        #[expect(clippy::cast_lossless, reason = "u8→f32 for blending math")]
        let g = (cg as f32 + (tg as f32 - cg as f32) * t).round() as u8;
        #[expect(clippy::cast_lossless, reason = "u8→f32 for blending math")]
        let b = (cb as f32 + (tb as f32 - cb as f32) * t).round() as u8;
        ratatui::style::Color::Rgb(r, g, b)
    }

    // ── StatusScreen loading snapshot ───────────────────────────────────────

    #[test]
    fn status_screen_loading_snapshot() {
        let mut screen = super::status::StatusScreen::new();
        // No status set -- shows loading spinner
        let output = render_to_string(&mut screen, 80, 24);
        insta::assert_snapshot!("status_screen_loading_80x24", output);
    }

    #[test]
    fn status_screen_with_mock_data_snapshot() {
        // Collect a real status snapshot to populate the screen.
        // This is an integration-style test that verifies rendering with
        // real system data. The snapshot will vary per machine but provides
        // a regression baseline.
        let status = toride_status::TorideStatus::collect();

        let mut screen = super::status::StatusScreen::new();
        screen.set_status(status);
        let output = render_to_string(&mut screen, 80, 24);
        // Verify key sections are rendered
        assert!(
            output.contains("System Status"),
            "header should contain 'System Status'"
        );
        assert!(output.contains("Hostname"), "should contain 'Hostname'");
    }

    #[test]
    fn status_screen_too_small() {
        let mut screen = super::status::StatusScreen::new();
        let output = render_to_string(&mut screen, 20, 8);
        assert!(
            output.contains("too small"),
            "expected 'too small' message, got: {output}"
        );
    }
}
