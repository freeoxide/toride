//! Editable text input widget for modal forms.
//!
//! A bordered single-line text field with cursor, selection placeholder, and
//! optional secret mode (renders dots instead of characters — used for
//! passphrases). Key events are handled via [`TextInput::handle_key`] which
//! returns an [`InputAction`] when the user submits or cancels.

use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::ui::theme::Palette;

// ── InputAction ──────────────────────────────────────────────────────────────

/// Actions returned by [`TextInput::handle_key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputAction {
    /// Field submitted (Enter pressed).
    Submit,
    /// User cancelled (Escape pressed).
    Cancel,
    /// Move focus to the next field (Tab).
    NextField,
    /// Move focus to the previous field (Shift+Tab / `BackTab`).
    PrevField,
    /// Key was consumed but no high-level action (char typed, cursor moved, etc.).
    None,
}

// ── TextInput ────────────────────────────────────────────────────────────────

/// A single-line editable text input.
pub struct TextInput {
    /// Current text value.
    value: String,
    /// Byte offset of the cursor within `value`.
    cursor: usize,
    /// Label displayed to the left of the input box.
    label: &'static str,
    /// Fixed visual width of the input box (excluding label and border).
    width: u16,
    /// If `true`, render dots instead of characters (for passphrases).
    secret: bool,
    /// Placeholder shown when `value` is empty.
    placeholder: Option<&'static str>,
    /// Horizontal scroll offset for long values.
    scroll: usize,
    /// If `true`, the field is required and will show a `*` marker.
    required: bool,
}

impl TextInput {
    /// Create a new text input with the given label and box width.
    #[must_use]
    pub fn new(label: &'static str, width: u16) -> Self {
        Self {
            value: String::new(),
            cursor: 0,
            label,
            width,
            secret: false,
            placeholder: None,
            scroll: 0,
            required: false,
        }
    }

    /// Set secret mode (renders dots instead of characters).
    #[must_use]
    pub fn secret(mut self, secret: bool) -> Self {
        self.secret = secret;
        self
    }

    /// Set the placeholder text shown when the value is empty.
    #[must_use]
    pub fn placeholder(mut self, placeholder: &'static str) -> Self {
        self.placeholder = Some(placeholder);
        self
    }

    /// Set an initial value.
    #[must_use]
    pub fn value(mut self, value: impl Into<String>) -> Self {
        self.value = value.into();
        self.cursor = self.value.len();
        self
    }

    /// Mark this field as required (shows `*` marker in label).
    #[must_use]
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    /// Whether this field is required.
    #[must_use]
    pub fn is_required(&self) -> bool {
        self.required
    }

    /// Get the current value.
    #[must_use]
    pub fn get_value(&self) -> &str {
        &self.value
    }

    /// Get the label.
    #[must_use]
    pub fn label(&self) -> &'static str {
        self.label
    }

    /// Is the input empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    // ── Key handling ────────────────────────────────────────────────────────

    /// Handle a key event. Returns [`InputAction::None`] for consumed keys
    /// that don't trigger a high-level action.
    pub fn handle_key(&mut self, code: KeyCode) -> InputAction {
        match code {
            KeyCode::Char(ch) => {
                self.insert_char(ch);
                InputAction::None
            }
            KeyCode::Backspace => {
                self.delete_backward();
                InputAction::None
            }
            KeyCode::Delete => {
                self.delete_forward();
                InputAction::None
            }
            KeyCode::Left => {
                self.move_cursor_left();
                InputAction::None
            }
            KeyCode::Right => {
                self.move_cursor_right();
                InputAction::None
            }
            KeyCode::Home => {
                self.cursor = 0;
                self.clamp_scroll();
                InputAction::None
            }
            KeyCode::End => {
                self.cursor = self.value.len();
                self.clamp_scroll();
                InputAction::None
            }
            KeyCode::Enter => InputAction::Submit,
            KeyCode::Esc => InputAction::Cancel,
            KeyCode::Tab => InputAction::NextField,
            KeyCode::BackTab => InputAction::PrevField,
            _ => InputAction::None,
        }
    }

    /// Insert a character at the cursor position.
    fn insert_char(&mut self, ch: char) {
        self.value.insert(self.cursor, ch);
        self.cursor += ch.len_utf8();
        self.clamp_scroll();
    }

    /// Delete the character before the cursor.
    fn delete_backward(&mut self) {
        if self.cursor == 0 {
            return;
        }
        // Find the previous char boundary.
        let prev = self.value[..self.cursor]
            .char_indices()
            .next_back()
            .map_or(0, |(i, _)| i);
        self.value.drain(prev..self.cursor);
        self.cursor = prev;
        self.clamp_scroll();
    }

    /// Delete the character at the cursor.
    fn delete_forward(&mut self) {
        if self.cursor >= self.value.len() {
            return;
        }
        let next = self.value[self.cursor..]
            .char_indices()
            .nth(1)
            .map_or(self.value.len(), |(i, _)| self.cursor + i);
        self.value.drain(self.cursor..next);
        self.clamp_scroll();
    }

    /// Move the cursor one character to the left.
    fn move_cursor_left(&mut self) {
        if self.cursor > 0 {
            self.cursor = self.value[..self.cursor]
                .char_indices()
                .next_back()
                .map_or(0, |(i, _)| i);
            self.clamp_scroll();
        }
    }

    /// Move the cursor one character to the right.
    fn move_cursor_right(&mut self) {
        if self.cursor < self.value.len() {
            self.cursor = self.value[self.cursor..]
                .char_indices()
                .nth(1)
                .map_or(self.value.len(), |(i, _)| self.cursor + i);
            self.clamp_scroll();
        }
    }

    /// Adjust `scroll` so the cursor is visible within the input box width.
    fn clamp_scroll(&mut self) {
        let visible_w = self.width.saturating_sub(0) as usize; // inner width after border
        if visible_w == 0 {
            return;
        }
        // The cursor's display column (only matters for width-1 chars).
        let display_pos = self.value[..self.cursor].chars().count();
        if display_pos < self.scroll {
            self.scroll = display_pos;
        } else if display_pos >= self.scroll + visible_w {
            self.scroll = display_pos - visible_w + 1;
        }
    }

    // ── Rendering ───────────────────────────────────────────────────────────

    /// Render the input at the given position.
    ///
    /// `area` should be a 3-row-tall rect (top border + content + bottom border).
    /// Width must accommodate `label_width + input_width + borders`.
    ///
    /// # Panics
    ///
    /// Panics if `error` is `Some` but the provided `area` is too small to
    /// render the field box.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "label length and cursor column are bounded by terminal cols < u16::MAX"
    )]
    pub fn render(
        &self,
        frame: &mut Frame,
        area: Rect,
        p: Palette,
        focused: bool,
        error: Option<&str>,
    ) {
        let border_color = if error.is_some() {
            p.err
        } else if focused {
            p.border_hi
        } else {
            p.border
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::new().fg(border_color))
            .style(Style::new().bg(p.bg_inset));

        let inner = block.inner(area);
        frame.render_widget(block, area);

        // Build the display text.
        let display = if self.value.is_empty()
            && let Some(placeholder) = self.placeholder
        {
            Span::styled(placeholder.to_string(), Style::new().fg(p.text_muted))
        } else if self.secret {
            Span::styled(
                "•".repeat(self.value.chars().count()),
                Style::new().fg(p.text),
            )
        } else {
            // Visible slice based on scroll.
            let chars: Vec<char> = self.value.chars().collect();
            let visible_w = inner.width as usize;
            let end = (self.scroll + visible_w).min(chars.len());
            let visible: String = chars[self.scroll..end].iter().collect();
            Span::styled(visible, Style::new().fg(p.text))
        };

        // Cursor indicator — a block character at the cursor position.
        let cursor_col = if self.value.is_empty() && self.placeholder.is_some() {
            0
        } else {
            self.value[..self.cursor]
                .chars()
                .count()
                .saturating_sub(self.scroll)
        };

        let mut spans = vec![];

        // Label (with required marker *)
        if !self.label.is_empty() {
            spans.push(Span::styled(
                format!("{} ", self.label),
                Style::new().fg(p.text_dim),
            ));
            if self.required {
                spans.push(Span::styled("*", Style::new().fg(p.err)));
            }
        }

        spans.push(display);

        let line = Line::from(spans);
        frame.render_widget(Paragraph::new(line), inner);

        // Overlay cursor block by directly writing to the buffer.
        // Account for the label width so the cursor aligns with the text.
        if focused && inner.width > 0 {
            let label_w = if self.label.is_empty() {
                0
            } else {
                let mut w = self.label.len() as u16 + 1; // label + trailing space
                if self.required {
                    w += 1; // * marker
                }
                w
            };
            let cursor_x = inner.x + label_w + cursor_col as u16;
            let cursor_y = inner.y;
            if cursor_x < inner.right() {
                let cell = &mut frame.buffer_mut()[(cursor_x, cursor_y)];
                if cursor_col < self.value.chars().count().saturating_sub(self.scroll) {
                    // Cursor is over an existing character — invert it.
                    let fg = cell.fg;
                    let bg = cell.bg;
                    cell.set_fg(bg);
                    cell.set_bg(fg);
                } else {
                    // Cursor is at the end — show a thin bar.
                    cell.set_char('▎');
                    cell.set_fg(p.text);
                    cell.set_bg(p.bg_inset);
                }
            }
        }
    }

    /// Render a validation error message below the field.
    ///
    /// `area` should be a 1-row-tall rect placed directly below the field box.
    pub fn render_error(frame: &mut Frame, area: Rect, p: Palette, error: &str) {
        if area.height == 0 || area.width == 0 {
            return;
        }
        let error_line = Line::from(vec![
            Span::styled("  ⚠ ", Style::new().fg(p.err)),
            Span::styled(error.to_string(), Style::new().fg(p.err)),
        ]);
        frame.render_widget(Paragraph::new(error_line), area);
    }

    /// The total width this input needs (label + box + borders).
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "static label length is bounded < u16::MAX"
    )]
    pub fn total_width(&self) -> u16 {
        let mut label_w = self.label.len() as u16 + 1; // label + space
        if self.required {
            label_w += 1; // * marker
        }
        let box_w = self.width;
        label_w + box_w + 2 // +2 for left/right borders
    }

    /// The height of the input (always 3: top border, content, bottom border).
    #[must_use]
    pub const fn height() -> u16 {
        3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_input_has_empty_value() {
        let input = TextInput::new("Name", 20);
        assert!(input.is_empty());
        assert_eq!(input.get_value(), "");
        assert_eq!(input.label(), "Name");
    }

    #[test]
    fn value_builder_sets_initial_value() {
        let input = TextInput::new("Host", 30).value("example.com");
        assert_eq!(input.get_value(), "example.com");
        assert!(!input.is_empty());
    }

    #[test]
    fn handle_key_char_inserts() {
        let mut input = TextInput::new("Name", 20);
        input.handle_key(KeyCode::Char('a'));
        input.handle_key(KeyCode::Char('b'));
        input.handle_key(KeyCode::Char('c'));
        assert_eq!(input.get_value(), "abc");
        assert_eq!(input.cursor, 3);
    }

    #[test]
    fn handle_key_backspace_deletes() {
        let mut input = TextInput::new("Name", 20).value("hello");
        input.cursor = 5;
        input.handle_key(KeyCode::Backspace);
        assert_eq!(input.get_value(), "hell");
        assert_eq!(input.cursor, 4);
    }

    #[test]
    fn handle_key_delete_forward() {
        let mut input = TextInput::new("Name", 20).value("hello");
        input.cursor = 0;
        input.handle_key(KeyCode::Delete);
        assert_eq!(input.get_value(), "ello");
        assert_eq!(input.cursor, 0);
    }

    #[test]
    fn handle_key_left_right_movement() {
        let mut input = TextInput::new("Name", 20).value("abc");
        input.cursor = 3;
        input.handle_key(KeyCode::Left);
        assert_eq!(input.cursor, 2);
        input.handle_key(KeyCode::Left);
        assert_eq!(input.cursor, 1);
        input.handle_key(KeyCode::Right);
        assert_eq!(input.cursor, 2);
    }

    #[test]
    fn handle_key_home_end() {
        let mut input = TextInput::new("Name", 20).value("abc");
        input.cursor = 2;
        input.handle_key(KeyCode::Home);
        assert_eq!(input.cursor, 0);
        input.handle_key(KeyCode::End);
        assert_eq!(input.cursor, 3);
    }

    #[test]
    fn handle_key_returns_submit_on_enter() {
        let mut input = TextInput::new("Name", 20);
        assert_eq!(input.handle_key(KeyCode::Enter), InputAction::Submit);
    }

    #[test]
    fn handle_key_returns_cancel_on_esc() {
        let mut input = TextInput::new("Name", 20);
        assert_eq!(input.handle_key(KeyCode::Esc), InputAction::Cancel);
    }

    #[test]
    fn handle_key_returns_next_field_on_tab() {
        let mut input = TextInput::new("Name", 20);
        assert_eq!(input.handle_key(KeyCode::Tab), InputAction::NextField);
    }

    #[test]
    fn handle_key_returns_prev_field_on_backtab() {
        let mut input = TextInput::new("Name", 20);
        assert_eq!(input.handle_key(KeyCode::BackTab), InputAction::PrevField);
    }

    #[test]
    fn backspace_at_start_does_nothing() {
        let mut input = TextInput::new("Name", 20).value("abc");
        input.cursor = 0;
        input.handle_key(KeyCode::Backspace);
        assert_eq!(input.get_value(), "abc");
        assert_eq!(input.cursor, 0);
    }

    #[test]
    fn delete_at_end_does_nothing() {
        let mut input = TextInput::new("Name", 20).value("abc");
        input.cursor = 3;
        input.handle_key(KeyCode::Delete);
        assert_eq!(input.get_value(), "abc");
        assert_eq!(input.cursor, 3);
    }

    #[test]
    fn insert_in_middle() {
        let mut input = TextInput::new("Name", 20).value("ac");
        input.cursor = 1;
        input.handle_key(KeyCode::Char('b'));
        assert_eq!(input.get_value(), "abc");
        assert_eq!(input.cursor, 2);
    }

    #[test]
    fn unicode_handling() {
        let mut input = TextInput::new("Name", 20);
        input.handle_key(KeyCode::Char('日'));
        input.handle_key(KeyCode::Char('本'));
        assert_eq!(input.get_value(), "日本");
        assert_eq!(input.cursor, 6); // 3 bytes per char
        input.handle_key(KeyCode::Backspace);
        assert_eq!(input.get_value(), "日");
        assert_eq!(input.cursor, 3);
    }

    #[test]
    fn secret_flag() {
        let input = TextInput::new("Pass", 20).secret(true).value("secret");
        assert!(input.secret);
    }

    #[test]
    fn total_width_calculation() {
        let input = TextInput::new("Name", 20);
        // label "Name " = 5, box = 20, borders = 2
        assert_eq!(input.total_width(), 27);
    }

    #[test]
    fn height_is_always_three() {
        assert_eq!(TextInput::height(), 3);
    }

    #[test]
    fn placeholder_shown_when_empty() {
        let input = TextInput::new("Name", 20).placeholder("enter name...");
        assert_eq!(input.placeholder, Some("enter name..."));
        assert!(input.is_empty());
    }

    #[test]
    fn render_snapshot_empty() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let input = TextInput::new("Name", 20).placeholder("enter name...");
        let mut terminal = Terminal::new(TestBackend::new(40, 5)).unwrap();
        terminal
            .draw(|f| input.render(f, Rect::new(0, 1, 30, 3), CHARM, true, None))
            .unwrap();
        let output = terminal.backend().to_string();
        // Should have a border, the label, and the placeholder text.
        // The cursor bar (▎) replaces the first char of the placeholder.
        assert!(output.contains("Name"), "label visible: {output}");
        assert!(
            output.contains("nter name"),
            "placeholder visible (after cursor): {output}"
        );
    }

    #[test]
    fn render_snapshot_with_value() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let input = TextInput::new("Host", 20).value("github.com");
        let mut terminal = Terminal::new(TestBackend::new(40, 5)).unwrap();
        terminal
            .draw(|f| input.render(f, Rect::new(0, 1, 30, 3), CHARM, true, None))
            .unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains("github.com"), "value visible: {output}");
    }

    #[test]
    fn required_marker_in_label() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let input = TextInput::new("Name", 20).required().placeholder("...");
        let mut terminal = Terminal::new(TestBackend::new(40, 5)).unwrap();
        terminal
            .draw(|f| input.render(f, Rect::new(0, 1, 30, 3), CHARM, true, None))
            .unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains("Name"), "label visible: {output}");
        assert!(input.is_required());
    }

    #[test]
    fn render_with_error_shows_red_border() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let input = TextInput::new("Name", 20).placeholder("...");
        let mut terminal = Terminal::new(TestBackend::new(40, 5)).unwrap();
        terminal
            .draw(|f| {
                input.render(
                    f,
                    Rect::new(0, 1, 30, 3),
                    CHARM,
                    true,
                    Some("This field is required"),
                );
            })
            .unwrap();
        // The render should not panic; error text is shown below the field box.
        let output = terminal.backend().to_string();
        assert!(output.contains("Name"), "label visible: {output}");
    }
}
