use crossterm::event::MouseEventKind;
use ratatui::{
    buffer::Buffer,
    layout::Position,
    layout::Rect,
    prelude::Widget,
};
use ratatui_interact::components::{Button, ButtonState, ButtonStyle, ButtonVariant};
use ratatui_interact::events::get_mouse_pos;

use super::responsive::Viewport;
use super::theme::{Palette, KEY_BG};

// ── Interactive button ─────────────────────────────────────────────────────────

/// A self-contained interactive button that tracks its own focus, hover,
/// press state, and rendered area for hit-testing.
///
/// Place it anywhere on any screen. Call [`render`] once per frame, then
/// forward mouse events via [`handle_mouse`]. Focus is set externally by the
/// owning screen's `FocusManager`.
///
/// # Visual states (all use static palette colours)
///
/// | State   | Foreground | Background |
/// |---------|-----------|------------|
/// | Default | `p.text`  | `KEY_BG`   |
/// | Focused | `p.bg`    | `p.accent` |
/// | Hovered | `p.bg`    | `p.accent` |
/// | Pressed | `p.bg`    | `p.accent2`|
///
/// [`render`]: InteractiveButton::render
/// [`handle_mouse`]: InteractiveButton::handle_mouse
pub struct InteractiveButton<A: Copy + PartialEq> {
    label_compact: &'static str,
    label_minimal: &'static str,
    action: A,
    state: ButtonState,
    area: Rect,
    pending_click: bool,
}

impl<A: Copy + PartialEq> InteractiveButton<A> {
    /// Create a new button.
    ///
    /// `label_compact` is shown when `viewport >= Compact`, otherwise
    /// `label_minimal` is used.
    #[must_use]
    pub fn new(
        label_compact: &'static str,
        label_minimal: &'static str,
        action: A,
    ) -> Self {
        Self {
            label_compact,
            label_minimal,
            action,
            state: ButtonState::enabled(),
            area: Rect::default(),
            pending_click: false,
        }
    }

    /// Whether this button currently has keyboard focus.
    #[must_use]
    pub fn is_focused(&self) -> bool {
        self.state.focused
    }

    /// Set or clear keyboard focus (called by the screen's `FocusManager`).
    pub fn set_focused(&mut self, focused: bool) {
        self.state.focused = focused;
    }

    /// Handle a mouse event.
    ///
    /// - **Move/Drag** — updates hover state internally.
    /// - **Down** — sets pressed visual if cursor is over this button.
    /// - **Up** — clears pressed and returns `Some(action)` if this button
    ///   was the one pressed.
    ///
    /// Returns `Some(action)` only on the `Up` event of a confirmed press.
    #[must_use]
    pub fn handle_mouse(&mut self, mouse: &ratatui::crossterm::event::MouseEvent) -> Option<A> {
        let (col, row) = get_mouse_pos(mouse);

        match mouse.kind {
            MouseEventKind::Moved | MouseEventKind::Drag(..) => {
                self.state.focused |= self.area.contains(Position::new(col, row));
                None
            }
            MouseEventKind::Down(_) => {
                if self.area.contains(Position::new(col, row)) {
                    self.state.pressed = true;
                    self.pending_click = true;
                }
                None
            }
            MouseEventKind::Up(..) => {
                self.state.pressed = false;
                if self.pending_click {
                    self.pending_click = false;
                    return Some(self.action);
                }
                None
            }
            _ => None,
        }
    }

    /// Compute the minimum width this button needs to render.
    #[must_use]
    pub fn min_width(&self, viewport: Viewport) -> u16 {
        let label = self.label(viewport);
        Button::new(label, &self.state).min_width()
    }

    /// Render the button at `rect` and store `rect` for future hit-testing.
    pub fn render(
        &mut self,
        buf: &mut Buffer,
        rect: Rect,
        p: Palette,
        viewport: Viewport,
    ) {
        self.area = rect;

        let label = self.label(viewport);

        let mut btn_style = ButtonStyle::new(ButtonVariant::SingleLine);
        btn_style.unfocused_fg = p.text;
        btn_style.unfocused_bg = KEY_BG;
        btn_style.focused_fg = p.bg;
        btn_style.focused_bg = p.accent;
        btn_style.pressed_fg = p.bg;
        btn_style.pressed_bg = p.accent2;

        Button::new(label, &self.state)
            .style(btn_style)
            .render(rect, buf);
    }

    fn label(&self, viewport: Viewport) -> &'static str {
        if viewport >= Viewport::Compact {
            self.label_compact
        } else {
            self.label_minimal
        }
    }
}
