use crossterm::event::MouseEventKind;
use ratatui::{buffer::Buffer, layout::Position, layout::Rect, prelude::Widget};
use ratatui_interact::components::{Button, ButtonState, ButtonStyle, ButtonVariant};
use ratatui_interact::events::get_mouse_pos;

use crate::ui::responsive::Viewport;
use crate::ui::theme::{KEY_BG, Palette};

/// A self-contained interactive button: call [`render`](Self::render) each
/// frame, then forward mouse events to [`handle_mouse`](Self::handle_mouse).
pub struct InteractiveButton<A: Copy + PartialEq> {
    label_compact: &'static str,
    label_minimal: &'static str,
    action: A,
    state: ButtonState,
    kb_focused: bool,
    hovered: bool,
    area: Rect,
    pending_click: bool,
}

impl<A: Copy + PartialEq> InteractiveButton<A> {
    /// Creates a button showing `label_compact` once `viewport >= Compact`,
    /// else `label_minimal`.
    #[must_use]
    pub fn new(label_compact: &'static str, label_minimal: &'static str, action: A) -> Self {
        Self {
            label_compact,
            label_minimal,
            action,
            state: ButtonState::enabled(),
            kb_focused: false,
            hovered: false,
            area: Rect::default(),
            pending_click: false,
        }
    }

    /// The action emitted on click.
    #[must_use]
    pub fn action(&self) -> A {
        self.action
    }

    /// Whether the button has keyboard focus.
    #[must_use]
    pub fn is_focused(&self) -> bool {
        self.kb_focused
    }

    /// Whether the pointer currently hovers the button.
    #[must_use]
    pub fn is_hovered(&self) -> bool {
        self.hovered
    }

    /// Set keyboard focus.
    pub fn set_focused(&mut self, focused: bool) {
        self.kb_focused = focused;
    }

    /// Updates hover/press state; returns the action only on the `Up` event
    /// of a press that started on this button.
    #[must_use]
    pub fn handle_mouse(&mut self, mouse: &ratatui::crossterm::event::MouseEvent) -> Option<A> {
        let (col, row) = get_mouse_pos(mouse);

        match mouse.kind {
            MouseEventKind::Moved | MouseEventKind::Drag(..) => {
                self.hovered = self.area.contains(Position::new(col, row));
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

    /// Minimum button width for the label the `viewport` selects.
    #[must_use]
    pub fn min_width(&self, viewport: Viewport) -> u16 {
        let label = self.label(viewport);
        Button::new(label, &self.state).min_width()
    }

    /// Render the button at `rect` and store `rect` for future hit-testing.
    pub fn render(&mut self, buf: &mut Buffer, rect: Rect, p: Palette, viewport: Viewport) {
        self.area = rect;

        let label = self.label(viewport);

        let mut btn_style = ButtonStyle::new(ButtonVariant::SingleLine);
        btn_style.unfocused_fg = p.text;
        btn_style.unfocused_bg = KEY_BG;
        btn_style.focused_fg = p.bg;
        btn_style.focused_bg = p.accent;
        btn_style.pressed_fg = p.bg;
        btn_style.pressed_bg = p.accent2;

        self.state.focused = self.kb_focused;
        Button::new(label, &self.state)
            .style(btn_style)
            .render(rect, buf);

        if self.hovered && !self.kb_focused && !self.state.pressed {
            for pos in rect.positions() {
                if let Some(cell) = buf.cell_mut(pos) {
                    cell.set_bg(p.sel_bg);
                }
            }
        }
    }

    fn label(&self, viewport: Viewport) -> &'static str {
        if viewport >= Viewport::Compact {
            self.label_compact
        } else {
            self.label_minimal
        }
    }
}
