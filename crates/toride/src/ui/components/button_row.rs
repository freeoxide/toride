//! A reusable row of interactive buttons with focus cycling, mouse hit-testing,
//! and automatic centering.
//!
//! Extracts the duplicated button-layout logic that was previously shared between
//! [`WelcomeScreen`](crate::ui::screens::WelcomeScreen) and
//! [`QuitModal`](crate::ui::screens::QuitModal).

use crossterm::event::MouseEvent;
use ratatui::{buffer::Buffer, layout::Rect};
use ratatui_interact::state::FocusManager;

use crate::ui::components::interactive_button::InteractiveButton;
use crate::ui::responsive::Viewport;
use crate::ui::theme::Palette;

/// A horizontally arranged row of interactive buttons with automatic centering,
/// keyboard focus cycling, and mouse hit-testing.
///
/// Owns the [`FocusManager`] and all [`InteractiveButton`] instances, so the
/// containing screen only needs to call [`render`](Self::render) and forward
/// input events.
pub struct ButtonRow<A: Copy + PartialEq> {
    buttons: Vec<InteractiveButton<A>>,
    focus: FocusManager<usize>,
    gaps: Vec<u16>,
}

impl<A: Copy + PartialEq> ButtonRow<A> {
    /// Create a new button row.
    ///
    /// `gaps` specifies the horizontal gap *after* each button (the last entry
    /// is unused but must be present so `gaps.len() == buttons.len()`).
    ///
    /// # Panics
    ///
    /// Panics if `gaps.len() != buttons.len()`.
    #[must_use]
    pub fn new(buttons: Vec<InteractiveButton<A>>, gaps: Vec<u16>) -> Self {
        assert_eq!(gaps.len(), buttons.len(), "gaps must match buttons count");
        let mut focus = FocusManager::new();
        let indices: Vec<usize> = (0..buttons.len()).collect();
        focus.register_all(indices);
        let mut row = Self {
            buttons,
            focus,
            gaps,
        };
        row.sync_focus();
        row
    }

    /// Render the button row, centered horizontally within `area`.
    pub fn render(&mut self, buf: &mut Buffer, area: Rect, p: Palette, viewport: Viewport) {
        let n = self.buttons.len();
        if n == 0 {
            return;
        }

        let widths: Vec<u16> = (0..n)
            .map(|i| self.buttons[i].min_width(viewport))
            .collect();
        let total_btn: u16 = widths.iter().sum();
        let total_gap: u16 = self.gaps.iter().sum();
        let total_width = total_btn + total_gap;

        let start_x = area.x + area.width.saturating_sub(total_width) / 2;
        let mut cursor_x = start_x;

        for (i, &w) in widths.iter().enumerate() {
            let btn_area = Rect::new(cursor_x, area.y, w, 1);
            self.buttons[i].render(buf, btn_area, p, viewport);
            cursor_x += w + self.gaps[i];
        }
    }

    /// Handle a mouse event, returning the action of the clicked button.
    #[must_use]
    pub fn handle_mouse(&mut self, mouse: &MouseEvent) -> Option<A> {
        self.buttons
            .iter_mut()
            .find_map(|btn| btn.handle_mouse(mouse))
    }

    /// Cycle keyboard focus to the next button.
    pub fn cycle_focus_next(&mut self) {
        self.focus.next();
        self.sync_focus();
    }

    /// Cycle keyboard focus to the previous button.
    pub fn cycle_focus_prev(&mut self) {
        self.focus.prev();
        self.sync_focus();
    }

    /// Return the action of the currently focused button, if any.
    #[must_use]
    pub fn activate_focused(&self) -> Option<A> {
        let idx = self.focused_index()?;
        Some(self.buttons[idx].action())
    }

    /// Index of the currently focused button.
    #[must_use]
    pub fn focused_index(&self) -> Option<usize> {
        self.focus.current().copied()
    }

    /// Number of buttons in the row.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buttons.len()
    }

    /// Whether the row has no buttons.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buttons.is_empty()
    }

    /// Propagate the [`FocusManager`] state to each button's visual focus flag.
    fn sync_focus(&mut self) {
        let focused = self.focus.current().copied();
        for (i, btn) in self.buttons.iter_mut().enumerate() {
            btn.set_focused(focused == Some(i));
        }
    }
}
