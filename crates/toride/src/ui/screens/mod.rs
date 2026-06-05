pub mod base;
pub mod dashboard;
pub mod help;
pub mod quit;
pub mod ssh;
pub mod welcome;

pub use base::ScreenBase;
pub use dashboard::DashboardScreen;
pub use help::HelpScreen;
pub use quit::QuitModal;
pub use ssh::{
    AgentKeyEntry, AgentStatus, AuthorizedKeyEntry, CertificateEntry, ConfigHostEntry,
    DiagnosticEntry, ForwardEntry, ForwardSessionEntry, KnownHostEntry, SshContent, SshKeyEntry,
};
pub use crate::ssh_data::{SecurityCheck, SecurityGrade, SshSecurityData};
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
        use crate::ui::responsive::Viewport;
        use crate::ui::widgets::Modal;

        let mut terminal = test_terminal(80, 24);
        terminal
            .draw(|f| {
                let viewport = Viewport::from_area(f.area());
                Modal::new("Help").render(f, CHARM, |f, content| {
                    super::help::HelpScreen::render(f, content, CHARM, viewport);
                });
            })
            .unwrap();
        let output = terminal.backend().to_string();
        insta::assert_snapshot!("help_screen_80x24", output);
    }

    #[test]
    fn help_screen_minimal_viewport() {
        use crate::ui::responsive::Viewport;
        use crate::ui::widgets::Modal;

        let mut terminal = test_terminal(35, 12);
        terminal
            .draw(|f| {
                let viewport = Viewport::from_area(f.area());
                Modal::new("Help").render(f, CHARM, |f, content| {
                    super::help::HelpScreen::render(f, content, CHARM, viewport);
                });
            })
            .unwrap();
        let output = terminal.backend().to_string();
        insta::assert_snapshot!("help_screen_35x12", output);
    }

    // ── DashboardScreen snapshots ───────────────────────────────────────────

    #[test]
    fn dashboard_screen_full_snapshot() {
        let mut screen = super::dashboard::DashboardScreen::new();
        let output = render_to_string(&mut screen, 160, 44);
        insta::assert_snapshot!("dashboard_screen_160x44", output);
    }

    #[test]
    fn dashboard_screen_compact_snapshot() {
        let mut screen = super::dashboard::DashboardScreen::new();
        let output = render_to_string(&mut screen, 90, 30);
        insta::assert_snapshot!("dashboard_screen_90x30", output);
    }

    #[test]
    fn dashboard_screen_has_chrome_and_content() {
        let mut screen = super::dashboard::DashboardScreen::new();
        let output = render_to_string(&mut screen, 160, 44);
        assert!(output.contains("toride"), "header logo: {output}");
        assert!(output.contains("MODULES"), "sidebar/panel label");
        assert!(output.contains("UPDATES AVAILABLE"), "updates panel");
        assert!(output.contains("RECENTLY INSTALLED"), "activity panel");
        assert!(output.contains("ssh hardening"), "module card");
    }

    #[test]
    fn dashboard_screen_too_small() {
        let mut screen = super::dashboard::DashboardScreen::new();
        let output = render_to_string(&mut screen, 20, 8);
        assert!(
            output.contains("too small"),
            "expected 'too small' message, got: {output}"
        );
    }
}
