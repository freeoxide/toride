//! Input handling: keyboard and mouse dispatch.
//!
//! Routes key and mouse events to the active screen via the [`AppScreen`]
//! trait, returning an [`Action`] when the screen requests navigation or quit.
//! When a modal is open, all input is intercepted by the modal.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent};

use crate::action::Action;
use crate::navigation::Screen;
use crate::ui::widgets::ModalEvent;

use super::App;

impl App {
    /// Handle a keyboard event, returning an [`Action`] if navigation is requested.
    pub(super) fn handle_key(&mut self, key: KeyEvent) -> Option<Action> {
        // Quit confirmation modal intercepts all input when visible
        if self.quit_visible {
            return self.quit_modal.handle_key(key.code);
        }

        // Help modal intercepts all input when visible.
        // Domain-specific keys (q, b, ?) handled first, then InteractiveModal.
        if self.help_modal.is_visible() {
            match key.code {
                KeyCode::Char('q') => return Some(Action::Quit),
                KeyCode::Char('b' | '?') | KeyCode::Esc => {
                    self.help_modal.close();
                    return Some(Action::CloseHelp);
                }
                other => {
                    self.help_modal.handle_key(other);
                    return None;
                }
            }
        }

        if self.transition.is_some() {
            return None;
        }

        // Global keybindings — work on every screen
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            if let KeyCode::Char('t') = key.code {
                return Some(Action::CycleTheme);
            }
            // Ctrl+Shift+A cycles the animation preference (Auto → On → Off).
            // Both casings are accepted (terminals deliver either). Legacy
            // terminals that collapse Ctrl+Shift+A onto Ctrl+A won't deliver
            // SHIFT, so this stays inert there — fall back to TORIDE_ANIM / config.
            if key.modifiers.contains(KeyModifiers::SHIFT)
                && matches!(key.code, KeyCode::Char('a' | 'A'))
            {
                return Some(Action::ToggleAnimations);
            }
            // Don't forward Ctrl+other to screens
            return None;
        }

        // Global `?` opens help from any screen — but not when a screen modal
        // is open (the user might be typing into a form).
        if key.code == KeyCode::Char('?') && !self.current_screen().has_modal() {
            return Some(Action::Help);
        }

        // On welcome screen, `q` quits immediately.
        // On all other screens, `q` shows the confirmation modal — UNLESS a
        // screen modal (form/confirm) is open, in which case let the screen
        // handle the key so the user can type 'q' into form fields.
        if key.code == KeyCode::Char('q')
            && self.nav.current() != Screen::Welcome
            && !self.current_screen().has_modal()
        {
            return Some(Action::ConfirmQuit);
        }

        self.current_screen().handle_key(key.code)
    }

    /// Handle a mouse event, returning an [`Action`] if navigation is requested.
    pub(super) fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action> {
        // Quit modal buttons get first dibs on mouse events
        if self.quit_visible {
            return self.quit_modal.handle_mouse(&mouse);
        }

        // Help modal: InteractiveModal handles click-outside.
        if self.help_modal.is_visible() {
            return match self.help_modal.handle_mouse(&mouse) {
                ModalEvent::Closed => {
                    self.needs_redraw = true;
                    Some(Action::CloseHelp)
                }
                _ => None,
            };
        }

        if self.transition.is_some() {
            return None;
        }

        self.current_screen().handle_mouse(mouse)
    }
}
