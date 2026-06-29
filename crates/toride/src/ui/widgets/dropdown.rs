//! Simple cycle-selector dropdown widget for enum values.
//!
//! Shows the currently selected option with up/down arrows. Pressing Up/Down
//! cycles through available options. Used in form modals for selections like
//! SSH key type, key format, etc.

use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::ui::theme::Palette;

use super::text_input::InputAction;

// ── Dropdown ─────────────────────────────────────────────────────────────────

/// A simple dropdown that cycles through a fixed list of string options.
pub struct Dropdown {
    /// Display label rendered to the left of the box.
    label: &'static str,
    /// Available options.
    options: Vec<&'static str>,
    /// Index of the currently selected option.
    selected: usize,
    /// Visual width of the dropdown box.
    width: u16,
    /// If `true`, the field is required and will show a `*` marker.
    required: bool,
}

impl Dropdown {
    /// Create a new dropdown with the given label, options, and box width.
    ///
    /// # Panics
    ///
    /// Panics if `options` is empty.
    #[must_use]
    pub fn new(label: &'static str, options: Vec<&'static str>, width: u16) -> Self {
        assert!(
            !options.is_empty(),
            "Dropdown must have at least one option"
        );
        Self {
            label,
            options,
            selected: 0,
            width,
            required: false,
        }
    }

    /// Pre-select an option by index.
    #[must_use]
    pub fn selected(mut self, idx: usize) -> Self {
        self.selected = idx.min(self.options.len() - 1);
        self
    }

    /// Pre-select an option by matching its label.
    #[must_use]
    pub fn selected_by_label(mut self, label: &str) -> Self {
        if let Some(idx) = self.options.iter().position(|&o| o == label) {
            self.selected = idx;
        }
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

    /// Get the currently selected option string.
    #[must_use]
    pub fn value(&self) -> &'static str {
        self.options[self.selected]
    }

    /// Get the index of the currently selected option.
    #[must_use]
    pub fn selected_index(&self) -> usize {
        self.selected
    }

    /// Get the label.
    #[must_use]
    pub fn label(&self) -> &'static str {
        self.label
    }

    /// Number of available options.
    #[must_use]
    pub fn option_count(&self) -> usize {
        self.options.len()
    }

    // ── Key handling ────────────────────────────────────────────────────────

    /// Handle a key event. Returns [`InputAction::None`] for consumed keys.
    pub fn handle_key(&mut self, code: KeyCode) -> InputAction {
        match code {
            KeyCode::Up => {
                if self.selected > 0 {
                    self.selected -= 1;
                } else {
                    self.selected = self.options.len() - 1;
                }
                InputAction::None
            }
            KeyCode::Down => {
                if self.selected < self.options.len() - 1 {
                    self.selected += 1;
                } else {
                    self.selected = 0;
                }
                InputAction::None
            }
            KeyCode::Enter | KeyCode::Tab => InputAction::NextField,
            KeyCode::Esc => InputAction::Cancel,
            KeyCode::BackTab => InputAction::PrevField,
            _ => InputAction::None,
        }
    }

    // ── Rendering ───────────────────────────────────────────────────────────

    /// Render the dropdown at the given position.
    ///
    /// `area` should be a 3-row-tall rect (top border + content + bottom border).
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

        let current = self.options[self.selected];
        let arrows = if self.options.len() > 1 {
            " ▲▼"
        } else {
            ""
        };

        let mut label_spans = vec![Span::styled(
            format!("{} ", self.label),
            Style::new().fg(p.text_dim),
        )];
        if self.required {
            label_spans.push(Span::styled("*", Style::new().fg(p.err)));
        }
        label_spans.push(Span::styled(current.to_string(), Style::new().fg(p.text)));
        label_spans.push(Span::styled(
            arrows.to_string(),
            Style::new().fg(p.text_muted),
        ));

        let line = Line::from(label_spans);

        frame.render_widget(Paragraph::new(line), inner);
    }

    /// The total width this dropdown needs (label + box + borders).
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "static label length is bounded < u16::MAX"
    )]
    pub fn total_width(&self) -> u16 {
        let label_w = self.label.len() as u16 + 1;
        let box_w = self.width;
        label_w + box_w + 2
    }

    /// The height of the dropdown (always 3: top border, content, bottom border).
    #[must_use]
    pub const fn height() -> u16 {
        3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_types() -> Vec<&'static str> {
        vec!["Ed25519", "RSA 4096", "ECDSA P-256", "DSA"]
    }

    #[test]
    fn new_sets_first_option_selected() {
        let dd = Dropdown::new("Type", key_types(), 16);
        assert_eq!(dd.value(), "Ed25519");
        assert_eq!(dd.selected_index(), 0);
    }

    #[test]
    fn selected_builder() {
        let dd = Dropdown::new("Type", key_types(), 16).selected(2);
        assert_eq!(dd.value(), "ECDSA P-256");
    }

    #[test]
    fn selected_clamps_to_last() {
        let dd = Dropdown::new("Type", key_types(), 16).selected(99);
        assert_eq!(dd.value(), "DSA");
    }

    #[test]
    fn selected_by_label() {
        let dd = Dropdown::new("Type", key_types(), 16).selected_by_label("RSA 4096");
        assert_eq!(dd.value(), "RSA 4096");
        assert_eq!(dd.selected_index(), 1);
    }

    #[test]
    fn selected_by_label_unknown_keeps_default() {
        let dd = Dropdown::new("Type", key_types(), 16).selected_by_label("UNKNOWN");
        assert_eq!(dd.value(), "Ed25519");
    }

    #[test]
    fn handle_key_down_cycles_forward() {
        let mut dd = Dropdown::new("Type", key_types(), 16);
        dd.handle_key(KeyCode::Down);
        assert_eq!(dd.value(), "RSA 4096");
        dd.handle_key(KeyCode::Down);
        assert_eq!(dd.value(), "ECDSA P-256");
        dd.handle_key(KeyCode::Down);
        assert_eq!(dd.value(), "DSA");
        dd.handle_key(KeyCode::Down);
        assert_eq!(dd.value(), "Ed25519"); // wraps
    }

    #[test]
    fn handle_key_up_cycles_backward() {
        let mut dd = Dropdown::new("Type", key_types(), 16);
        dd.handle_key(KeyCode::Up);
        assert_eq!(dd.value(), "DSA"); // wraps
        dd.handle_key(KeyCode::Up);
        assert_eq!(dd.value(), "ECDSA P-256");
    }

    #[test]
    fn handle_key_enter_returns_next_field() {
        let mut dd = Dropdown::new("Type", key_types(), 16);
        assert_eq!(dd.handle_key(KeyCode::Enter), InputAction::NextField);
    }

    #[test]
    fn handle_key_esc_returns_cancel() {
        let mut dd = Dropdown::new("Type", key_types(), 16);
        assert_eq!(dd.handle_key(KeyCode::Esc), InputAction::Cancel);
    }

    #[test]
    fn handle_key_tab_returns_next_field() {
        let mut dd = Dropdown::new("Type", key_types(), 16);
        assert_eq!(dd.handle_key(KeyCode::Tab), InputAction::NextField);
    }

    #[test]
    fn handle_key_backtab_returns_prev_field() {
        let mut dd = Dropdown::new("Type", key_types(), 16);
        assert_eq!(dd.handle_key(KeyCode::BackTab), InputAction::PrevField);
    }

    #[test]
    fn label_returns_label() {
        let dd = Dropdown::new("Type", key_types(), 16);
        assert_eq!(dd.label(), "Type");
    }

    #[test]
    fn option_count() {
        let dd = Dropdown::new("Type", key_types(), 16);
        assert_eq!(dd.option_count(), 4);
    }

    #[test]
    fn total_width() {
        let dd = Dropdown::new("Type", key_types(), 16);
        // label "Type " = 5, box = 16, borders = 2
        assert_eq!(dd.total_width(), 23);
    }

    #[test]
    fn height_is_three() {
        assert_eq!(Dropdown::height(), 3);
    }

    #[test]
    #[should_panic(expected = "Dropdown must have at least one option")]
    fn new_panics_with_empty_options() {
        let _ = Dropdown::new("X", vec![], 10);
    }

    #[test]
    fn render_shows_selected_option() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let dd = Dropdown::new("Type", key_types(), 16).selected(1);
        let mut terminal = Terminal::new(TestBackend::new(40, 5)).unwrap();
        terminal
            .draw(|f| dd.render(f, Rect::new(0, 1, 28, 3), CHARM, true, None))
            .unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("RSA 4096"),
            "selected option visible: {output}"
        );
        assert!(output.contains("▲▼"), "arrows visible: {output}");
    }

    #[test]
    fn single_option_no_arrows() {
        let dd = Dropdown::new("Fmt", vec!["OpenSSH"], 12);
        let mut dd_mut = dd;
        dd_mut.handle_key(KeyCode::Down); // should not panic or change
        assert_eq!(dd_mut.value(), "OpenSSH");
    }
}
