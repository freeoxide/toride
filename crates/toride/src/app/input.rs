//! Input handling: keyboard and mouse dispatch.
//!
//! Routes key and mouse events to the active screen via the [`AppScreen`]
//! trait, returning an [`Action`] when the screen requests navigation or quit.
//! When the help modal is open, all input is intercepted by the modal.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent};

use crate::action::Action;
use crate::ui::screens::help::HelpScreen;

use super::App;

impl App {
    /// Handle a keyboard event, returning an [`Action`] if navigation is requested.
    pub(super) fn handle_key(&mut self, key: KeyEvent) -> Option<Action> {
        // Help modal intercepts all input when visible
        if self.help_visible {
            return HelpScreen::handle_key(key.code);
        }

        if self.transition.is_some() {
            return None;
        }

        // Global keybindings — work on every screen
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            if let KeyCode::Char('t') = key.code {
                return Some(Action::CycleTheme);
            }
            // Don't forward Ctrl+other to screens
            return None;
        }

        // Global `?` opens help from any screen
        if key.code == KeyCode::Char('?') {
            return Some(Action::Help);
        }

        self.current_screen().handle_key(key.code)
    }

    /// Handle a mouse event, returning an [`Action`] if navigation is requested.
    pub(super) fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action> {
        // Swallow all mouse events while modal is open
        if self.help_visible {
            return None;
        }

        if self.transition.is_some() {
            return None;
        }

        self.current_screen().handle_mouse(mouse)
    }
}
