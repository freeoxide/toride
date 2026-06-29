//! Reusable confirmation modal with Confirm/Cancel buttons.
//!
//! A generic version of the quit confirmation pattern. Owns its own interactive
//! buttons, focus state, rendering, and input handling. Used for all destructive
//! SSH operations (delete key, remove host, hash all, etc.).

use crossterm::event::{KeyCode, MouseEvent};
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    text::Line,
    widgets::Paragraph,
};

use crate::ui::components::{ButtonRow, interactive_button::InteractiveButton};
use crate::ui::responsive::Viewport;
use crate::ui::theme::Palette;

use super::Modal;

/// Horizontal gap between the two buttons.
const BTN_GAP: u16 = 4;

/// Result of a confirmation interaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmResult {
    /// User confirmed the action.
    Confirmed,
    /// User cancelled / dismissed the modal.
    Cancelled,
}

/// Self-contained confirmation modal.
///
/// Owns interactive Confirm/Cancel buttons with focus cycling and mouse support.
/// Wraps the shared [`Modal`] widget. Construct via [`ConfirmModal::new`] and
/// call [`render`](Self::render) from within a modal's content closure or
/// directly from a screen's view method.
pub struct ConfirmModal {
    buttons: ButtonRow<ConfirmResult>,
    message: String,
    width: u16,
    height: u16,
}

impl ConfirmModal {
    /// Create a new confirmation modal with the given title and message.
    ///
    /// The title is used for the modal border; the message is displayed centered
    /// above the buttons.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        let buttons = vec![
            InteractiveButton::new("confirm", "ok", ConfirmResult::Confirmed),
            InteractiveButton::new("cancel", "x", ConfirmResult::Cancelled),
        ];

        Self {
            buttons: ButtonRow::new(buttons, vec![BTN_GAP, 0]),
            message: message.into(),
            width: 44,
            height: 7,
        }
    }

    /// Override the modal dimensions.
    #[must_use]
    pub fn dimensions(mut self, width: u16, height: u16) -> Self {
        self.width = width;
        self.height = height;
        self
    }

    /// Set the modal title (shown in the border).
    ///
    /// Since the `Modal` title is `&'static str`, this is set separately and
    /// stored for the render call.
    pub fn set_message(&mut self, message: impl Into<String>) {
        self.message = message.into();
    }

    /// Handle a key press while the confirm modal is open.
    pub fn handle_key(&mut self, code: KeyCode) -> Option<ConfirmResult> {
        match code {
            // Direct shortcuts
            KeyCode::Char('y' | 'Y') => Some(ConfirmResult::Confirmed),
            KeyCode::Char('n' | 'N') | KeyCode::Esc => Some(ConfirmResult::Cancelled),
            // Enter activates the focused button
            KeyCode::Enter => Some(
                self.buttons
                    .activate_focused()
                    .unwrap_or(ConfirmResult::Cancelled),
            ),
            // Focus cycling
            KeyCode::Tab | KeyCode::Right => {
                self.buttons.cycle_focus_next();
                None
            }
            KeyCode::BackTab | KeyCode::Left => {
                self.buttons.cycle_focus_prev();
                None
            }
            _ => None,
        }
    }

    /// Handle a mouse event while the confirm modal is open.
    pub fn handle_mouse(&mut self, mouse: &MouseEvent) -> Option<ConfirmResult> {
        self.buttons.handle_mouse(mouse)
    }

    /// Render the confirmation modal overlay.
    pub fn render(&mut self, frame: &mut Frame, p: Palette, title: &'static str) {
        let viewport = Viewport::from_area(frame.area());

        Modal::new(title)
            .dimensions(self.width, self.height)
            .render(frame, p, |frame, content_area| {
                let [_, msg_area, _, keys_area, _] = Layout::vertical([
                    Constraint::Fill(1),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Fill(1),
                ])
                .areas(content_area);

                let msg = Line::from(self.message.as_str()).centered();
                frame.render_widget(Paragraph::new(msg), msg_area);

                let buf = frame.buffer_mut();
                self.buttons.render(buf, keys_area, p, viewport);
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_modal_with_message() {
        let modal = ConfirmModal::new("Delete this key?");
        assert_eq!(modal.message, "Delete this key?");
    }

    #[test]
    fn dimensions_override() {
        let modal = ConfirmModal::new("test").dimensions(30, 5);
        assert_eq!(modal.width, 30);
        assert_eq!(modal.height, 5);
    }

    #[test]
    fn handle_key_y_confirms() {
        let mut modal = ConfirmModal::new("Delete?");
        assert_eq!(
            modal.handle_key(KeyCode::Char('y')),
            Some(ConfirmResult::Confirmed)
        );
    }

    #[test]
    fn handle_key_y_confirms_capital() {
        let mut modal = ConfirmModal::new("Delete?");
        assert_eq!(
            modal.handle_key(KeyCode::Char('Y')),
            Some(ConfirmResult::Confirmed)
        );
    }

    #[test]
    fn handle_key_n_cancels() {
        let mut modal = ConfirmModal::new("Delete?");
        assert_eq!(
            modal.handle_key(KeyCode::Char('n')),
            Some(ConfirmResult::Cancelled)
        );
    }

    #[test]
    fn handle_key_esc_cancels() {
        let mut modal = ConfirmModal::new("Delete?");
        assert_eq!(
            modal.handle_key(KeyCode::Esc),
            Some(ConfirmResult::Cancelled)
        );
    }

    #[test]
    fn handle_key_enter_confirms_on_focused_confirm() {
        let mut modal = ConfirmModal::new("Delete?");
        // Confirm (index 0) is focused by default
        assert_eq!(
            modal.handle_key(KeyCode::Enter),
            Some(ConfirmResult::Confirmed)
        );
    }

    #[test]
    fn handle_key_enter_cancels_on_focused_cancel() {
        let mut modal = ConfirmModal::new("Delete?");
        modal.handle_key(KeyCode::Tab); // Tab to Cancel
        assert_eq!(
            modal.handle_key(KeyCode::Enter),
            Some(ConfirmResult::Cancelled)
        );
    }

    #[test]
    fn handle_key_none_for_other_keys() {
        let mut modal = ConfirmModal::new("Delete?");
        assert_eq!(modal.handle_key(KeyCode::Char('a')), None);
        assert_eq!(modal.handle_key(KeyCode::Up), None);
    }

    #[test]
    fn tab_cycles_focus() {
        let mut modal = ConfirmModal::new("Delete?");
        assert_eq!(modal.handle_key(KeyCode::Tab), None);
        assert_eq!(
            modal.handle_key(KeyCode::Enter),
            Some(ConfirmResult::Cancelled)
        );
        // Tab back
        assert_eq!(modal.handle_key(KeyCode::Tab), None);
        assert_eq!(
            modal.handle_key(KeyCode::Enter),
            Some(ConfirmResult::Confirmed)
        );
    }

    #[test]
    fn set_message_updates_message() {
        let mut modal = ConfirmModal::new("old");
        modal.set_message("new message");
        assert_eq!(modal.message, "new message");
    }

    #[test]
    fn render_snapshot() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut modal = ConfirmModal::new("Delete id_ed25519?");
        let mut terminal = Terminal::new(TestBackend::new(60, 12)).unwrap();
        terminal
            .draw(|f| modal.render(f, CHARM, "Delete Key"))
            .unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("Delete id_ed25519?"),
            "message visible: {output}"
        );
    }
}
