//! Quit confirmation modal.
//!
//! A self-contained modal that asks the user to confirm before quitting.
//! Composes [`InteractiveModal`] for visibility, rect tracking, click-outside,
//! and button routing. Domain-specific shortcut keys (y/n) are handled here.

use crossterm::event::{KeyCode, MouseEvent};
use ratatui::{
    layout::{Constraint, Layout},
    widgets::Paragraph,
};

use crate::action::Action;
use crate::ui::components::{ButtonRow, interactive_button::InteractiveButton};
use crate::ui::responsive::Viewport;
use crate::ui::theme::Palette;
use crate::ui::widgets::{InteractiveModal, ModalEvent};

/// Horizontal gap between the two buttons.
const BTN_GAP: u16 = 4;

/// Self-contained quit confirmation modal.
///
/// Owns an [`InteractiveModal`] internally and adds domain-specific shortcut
/// key handling (y/n). Delegates focus cycling, button activation, mouse
/// hover/click, and click-outside to the composed modal.
pub struct QuitModal {
    modal: InteractiveModal<Action>,
}

impl Default for QuitModal {
    fn default() -> Self {
        Self::new()
    }
}

impl QuitModal {
    /// Construct a new quit confirmation modal with yes/no buttons.
    #[must_use]
    pub fn new() -> Self {
        let buttons = ButtonRow::new(
            vec![
                InteractiveButton::new("yes", "y", Action::Quit),
                InteractiveButton::new("no", "n", Action::DismissQuit),
            ],
            vec![BTN_GAP, 0],
        );
        Self {
            modal: InteractiveModal::with_buttons("Quit?", buttons)
                .dimensions(36, 7)
                .close_on_click_outside(false),
        }
    }

    /// Handle a key press while the quit modal is open.
    pub fn handle_key(&mut self, code: KeyCode) -> Option<Action> {
        // Domain-specific shortcuts first
        match code {
            KeyCode::Char('y') => return Some(Action::Quit),
            KeyCode::Char('n') | KeyCode::Esc => return Some(Action::DismissQuit),
            _ => {}
        }
        // Delegate focus cycling, Enter, etc. to InteractiveModal
        match self.modal.handle_key(code) {
            ModalEvent::Button(action) => Some(action),
            ModalEvent::Closed => Some(Action::DismissQuit),
            ModalEvent::Consumed => None,
        }
    }

    /// Handle a mouse event while the quit modal is open.
    pub fn handle_mouse(&mut self, mouse: &MouseEvent) -> Option<Action> {
        match self.modal.handle_mouse(mouse) {
            ModalEvent::Button(action) => Some(action),
            ModalEvent::Closed => Some(Action::DismissQuit),
            ModalEvent::Consumed => None,
        }
    }

    /// Render the quit modal overlay.
    pub fn render(&mut self, frame: &mut ratatui::Frame, p: Palette) {
        self.modal
            .render_with_extracted_buttons(frame, p, |frame, area, buttons| {
                let [_, msg_area, _, keys_area, _] = Layout::vertical([
                    Constraint::Fill(1),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Fill(1),
                ])
                .areas(area);

                frame.render_widget(
                    Paragraph::new("Are you sure you want to quit?").centered(),
                    msg_area,
                );

                if let Some(btns) = buttons {
                    let viewport = Viewport::from_area(frame.area());
                    let buf = frame.buffer_mut();
                    btns.render(buf, keys_area, p, viewport);
                }
            });
    }
}

#[cfg(test)]
mod tests {
    use crossterm::event::KeyCode;

    use super::*;
    use crate::action::Action;

    #[test]
    fn new_creates_modal() {
        let _modal = QuitModal::new();
    }

    #[test]
    fn handle_key_yes_on_y() {
        let mut modal = QuitModal::new();
        assert_eq!(modal.handle_key(KeyCode::Char('y')), Some(Action::Quit));
    }

    #[test]
    fn handle_key_dismiss_on_n() {
        let mut modal = QuitModal::new();
        assert_eq!(
            modal.handle_key(KeyCode::Char('n')),
            Some(Action::DismissQuit)
        );
    }

    #[test]
    fn handle_key_dismiss_on_esc() {
        let mut modal = QuitModal::new();
        assert_eq!(modal.handle_key(KeyCode::Esc), Some(Action::DismissQuit));
    }

    #[test]
    fn handle_key_enter_on_focused_yes() {
        let mut modal = QuitModal::new();
        // Yes (index 0) is focused by default
        assert_eq!(modal.handle_key(KeyCode::Enter), Some(Action::Quit));
    }

    #[test]
    fn handle_key_enter_on_focused_no() {
        let mut modal = QuitModal::new();
        // Tab to No
        modal.handle_key(KeyCode::Tab);
        assert_eq!(modal.handle_key(KeyCode::Enter), Some(Action::DismissQuit));
    }

    #[test]
    fn handle_key_none_for_other_keys() {
        let mut modal = QuitModal::new();
        assert_eq!(modal.handle_key(KeyCode::Char('a')), None);
        assert_eq!(modal.handle_key(KeyCode::Up), None);
        assert_eq!(modal.handle_key(KeyCode::Char('j')), None);
    }

    #[test]
    fn tab_cycles_focus() {
        let mut modal = QuitModal::new();
        // Tab to No
        assert_eq!(modal.handle_key(KeyCode::Tab), None);
        assert_eq!(modal.handle_key(KeyCode::Enter), Some(Action::DismissQuit));
        // Tab back to Yes
        assert_eq!(modal.handle_key(KeyCode::Tab), None);
        assert_eq!(modal.handle_key(KeyCode::Enter), Some(Action::Quit));
    }
}
