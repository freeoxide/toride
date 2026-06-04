//! Application state, event loop, and update logic.
//!
//! The [`App`] struct is the top-level orchestrator that owns all screen
//! instances, navigation state, and drives the main event loop via tokio's
//! `select!`.

mod input;
mod render;

use color_eyre::eyre::Result;
use crossterm::event::{Event, EventStream, KeyEventKind};
use futures::StreamExt;
use ratatui::DefaultTerminal;
use tokio::select;

use crate::action::Action;
use crate::navigation::{Navigator, Screen};
use crate::status_collector::StatusCollector;
use crate::ui::screens::AppScreen;
use crate::ui::screens::help::HelpScreen;
use crate::ui::screens::status::StatusScreen;
use crate::ui::screens::welcome::WelcomeScreen;
use crate::ui::theme::Theme;
use crate::ui::transition::{TransitionCache, TransitionState};

/// Top-level application orchestrator.
///
/// Owns all screen instances, the navigation state, and drives the main
/// event loop via tokio's `select!`.
pub struct App {
    nav: Navigator,
    welcome: WelcomeScreen,
    status: StatusScreen,
    help: HelpScreen,
    help_visible: bool,
    active_theme: Theme,
    should_quit: bool,
    needs_redraw: bool,
    transition: Option<TransitionState>,
    transition_cache: TransitionCache,
    collector: StatusCollector,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    /// Create a new application starting at the welcome screen.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nav: Navigator::new(),
            welcome: WelcomeScreen::new(),
            status: StatusScreen::new(),
            help: HelpScreen::new(),
            help_visible: false,
            active_theme: Theme::default(),
            should_quit: false,
            needs_redraw: false,
            transition: None,
            transition_cache: TransitionCache::new(),
            collector: StatusCollector::new(),
        }
    }

    /// Return a mutable reference to the current screen as `dyn AppScreen`.
    fn current_screen(&mut self) -> &mut dyn AppScreen {
        match self.nav.current() {
            Screen::Welcome => &mut self.welcome,
            Screen::Status => &mut self.status,
        }
    }

    fn update(&mut self, action: Action) {
        if self.transition.is_some() {
            return;
        }

        match action {
            Action::Quit => self.should_quit = true,
            Action::Continue => self.start_forward(Screen::Status),
            Action::Help => {
                self.help_visible = !self.help_visible;
                self.needs_redraw = true;
            }
            Action::CloseHelp => {
                self.help_visible = false;
                self.needs_redraw = true;
            }
            Action::Back => self.go_back(),
            Action::CycleTheme => {
                let all = Theme::all();
                let idx = all
                    .iter()
                    .position(|&t| t == self.active_theme)
                    .unwrap_or(0);
                let next = all[(idx + 1) % all.len()];
                self.active_theme = next;
                self.welcome.set_border_color(next.palette().accent);
                self.welcome.invalidate_cache();
                self.status.invalidate_cache();
                self.needs_redraw = true;
            }
            // Scroll actions (and any future screen-local actions) are routed
            // to the current screen via `handle_action`.
            _ => self.current_screen().handle_action(action),
        }
    }

    fn start_forward(&mut self, to: Screen) {
        let state = self.nav.start_forward(to, &mut self.transition_cache);
        self.transition = Some(state);
    }

    fn go_back(&mut self) {
        if let Some(state) = self.nav.start_backward(&mut self.transition_cache) {
            self.transition = Some(state);
        }
    }

    /// Run the main event loop.
    ///
    /// # Errors
    ///
    /// Returns an error if the terminal draw fails or the event stream encounters an error.
    pub async fn run(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        let mut events = EventStream::new();
        let refresh_interval = tokio::time::interval(std::time::Duration::from_secs(2));
        let anim_tick = tokio::time::interval(std::time::Duration::from_millis(33)); // ~30fps
        tokio::pin!(refresh_interval);
        tokio::pin!(anim_tick);

        loop {
            terminal.draw(|f| self.view(f))?;
            self.needs_redraw = false;

            select! {
                // Prioritize terminal events and status results over timer
                biased;

                Some(Ok(event)) = events.next() => {
                    let action = match event {
                        Event::Key(key) if key.kind == KeyEventKind::Press => {
                            self.handle_key(key)
                        }
                        Event::Mouse(mouse) => self.handle_mouse(mouse),
                        Event::Resize(..) => {
                            self.welcome.invalidate_cache();
                            self.status.invalidate_cache();
                            self.needs_redraw = true;
                            None
                        }
                        _ => None,
                    };
                    if let Some(action) = action {
                        self.update(action);
                        self.needs_redraw = true;
                    }
                }

                // Receive collected status data
                Some(status) = self.collector.poll(), if self.collector.is_pending() => {
                    self.status.set_status(status);
                    self.needs_redraw = true;
                }

                // Periodic status refresh
                _ = refresh_interval.tick() => {
                    if matches!(self.nav.current(), Screen::Status) {
                        self.collector.start();
                    }
                }

                // Animation tick (~30fps for shimmer, border, spinner, and transitions)
                _ = anim_tick.tick(),
                    if self.transition.is_some()
                        || self.needs_redraw
                        || matches!(self.nav.current(), Screen::Welcome | Screen::Status) => {}
            }

            if self.should_quit {
                break;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::action::Action;
    use crate::app::App;
    use crate::navigation::Screen;
    use crate::ui::theme::Theme;

    #[test]
    fn new_creates_default_state() {
        let app = App::new();
        assert_eq!(app.active_theme, Theme::Charm);
        assert!(!app.should_quit);
        assert_eq!(app.nav.current(), Screen::Welcome);
    }

    #[test]
    fn default_equals_new() {
        let from_new = App::new();
        let from_default = App::default();
        assert_eq!(from_new.active_theme, from_default.active_theme);
        assert_eq!(from_new.should_quit, from_default.should_quit);
        assert_eq!(from_new.nav.current(), from_default.nav.current());
        assert!(from_new.transition.is_none());
        assert!(from_default.transition.is_none());
    }

    #[test]
    fn update_quit_sets_should_quit() {
        let mut app = App::new();
        assert!(!app.should_quit);
        app.update(Action::Quit);
        assert!(app.should_quit);
    }

    #[test]
    fn update_continue_starts_transition_to_status() {
        let mut app = App::new();
        assert!(app.transition.is_none());
        app.update(Action::Continue);
        assert!(app.transition.is_some());
    }

    #[test]
    fn update_help_toggles_modal() {
        let mut app = App::new();
        assert!(!app.help_visible);
        app.update(Action::Help);
        assert!(app.help_visible);
        app.update(Action::Help);
        assert!(!app.help_visible);
    }

    #[test]
    fn update_close_help_hides_modal() {
        let mut app = App::new();
        app.help_visible = true;
        app.update(Action::CloseHelp);
        assert!(!app.help_visible);
    }

    #[test]
    fn update_back_does_nothing_at_welcome() {
        let mut app = App::new();
        assert!(app.transition.is_none());
        app.update(Action::Back);
        assert!(app.transition.is_none());
        assert_eq!(app.nav.current(), Screen::Welcome);
        assert!(!app.should_quit);
    }
}
