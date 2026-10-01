use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};

use crate::action::Action;
use crate::navigation::Screen;
use crate::ui::widgets::ModalEvent;

use super::App;

impl App {
    pub(super) fn handle_key(&mut self, key: KeyEvent) -> Option<Action> {
        if self.quit_visible {
            return self.quit_modal.handle_key(key.code);
        }

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

        if key.modifiers.contains(KeyModifiers::CONTROL) {
            if let KeyCode::Char('t') = key.code {
                return Some(Action::CycleTheme);
            }
            if key.modifiers.contains(KeyModifiers::SHIFT)
                && matches!(key.code, KeyCode::Char('a' | 'A'))
            {
                return Some(Action::ToggleAnimations);
            }
            return None;
        }

        if key.code == KeyCode::Char('?') && !self.current_screen().has_modal() {
            return Some(Action::Help);
        }

        if key.code == KeyCode::Char('q')
            && self.nav.current() != Screen::Welcome
            && !self.current_screen().has_modal()
        {
            return Some(Action::ConfirmQuit);
        }

        self.current_screen().handle_key(key.code)
    }

    pub(super) fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action> {
        if self.quit_visible {
            let action = self.quit_modal.handle_mouse(&mouse);
            if matches!(mouse.kind, MouseEventKind::Moved | MouseEventKind::Drag(_)) {
                self.needs_redraw = true;
            }
            return action;
        }

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
