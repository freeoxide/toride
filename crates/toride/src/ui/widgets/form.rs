//! Form modal helper for multi-field input forms.
//!
//! Composes [`TextInput`] and [`Dropdown`] fields into a vertically stacked
//! form inside a [`Modal`] overlay. Manages field focus cycling (Tab / Shift+Tab),
//! validation on submit, error display, and themed rendering. Includes interactive
//! Add/Cancel buttons with mouse support.

use crossterm::event::{KeyCode, MouseEvent};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    text::Line,
    widgets::Paragraph,
};

use crate::ui::components::{ButtonRow, interactive_button::InteractiveButton};
use crate::ui::responsive::Viewport;
use crate::ui::theme::Palette;

use super::{Dropdown, Modal, TextInput, text_input::InputAction, validate::Validator};

/// Result of a form interaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormResult {
    /// User submitted the form (Enter on last field or explicit submit) and
    /// all field validations passed.
    Submitted,
    /// User cancelled the form (Escape).
    Cancelled,
    /// Key consumed but form still active (typing, cursor movement, field
    /// cycling, or validation failed on submit).
    Pending,
}

// ── FocusTarget ──────────────────────────────────────────────────────────────

/// Where focus currently sits in the form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FocusTarget {
    /// Focus is on a form field (index).
    Field(usize),
    /// Focus is on the button row.
    Buttons,
}

// ── FormField ─────────────────────────────────────────────────────────────────

/// The underlying widget kind for a form field.
enum FieldKind {
    Text(TextInput),
    Select(Dropdown),
}

/// A single field in a form, with optional validation and error state.
pub struct FormField {
    kind: FieldKind,
    validators: Vec<Box<dyn Validator>>,
    /// Current validation error message, if any.
    error: Option<String>,
}

impl FormField {
    /// Create a text field wrapping the given [`TextInput`].
    fn text(input: TextInput) -> Self {
        let required = input.is_required();
        let mut field = Self {
            kind: FieldKind::Text(input),
            validators: Vec::new(),
            error: None,
        };
        if required {
            use super::validate::Required;
            field.validators.push(Box::new(Required));
        }
        field
    }

    /// Create a select field wrapping the given [`Dropdown`].
    fn select(dropdown: Dropdown) -> Self {
        let required = dropdown.is_required();
        let mut field = Self {
            kind: FieldKind::Select(dropdown),
            validators: Vec::new(),
            error: None,
        };
        if required {
            use super::validate::Required;
            field.validators.push(Box::new(Required));
        }
        field
    }

    /// Add a validator to this field.
    fn add_validator(&mut self, v: Box<dyn Validator>) {
        self.validators.push(v);
    }

    /// The label for this field.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match &self.kind {
            FieldKind::Text(t) => t.label(),
            FieldKind::Select(d) => d.label(),
        }
    }

    /// Run all validators and return the first error message, if any.
    /// Updates `self.error` with the result.
    fn validate(&mut self) -> Option<&str> {
        let value = match &self.kind {
            FieldKind::Text(t) => t.get_value().to_string(),
            FieldKind::Select(d) => d.value().to_string(),
        };
        for v in &self.validators {
            if let Some(err) = v.validate(&value) {
                self.error = Some(err.message.clone());
                return Some(self.error.as_deref().unwrap_or(""));
            }
        }
        self.error = None;
        None
    }

    /// Clear the current error (e.g. when the user starts editing the field).
    fn clear_error(&mut self) {
        self.error = None;
    }

    /// Whether this field currently has a validation error.
    #[must_use]
    pub fn has_error(&self) -> bool {
        self.error.is_some()
    }
}

// ── FormModal ─────────────────────────────────────────────────────────────────

/// A form modal containing an ordered list of fields with focus management,
/// validation, error display, and interactive Add/Cancel buttons.
///
/// Construct with [`FormModal::new`], add fields with builder methods, then
/// call [`render`](Self::render) inside a modal content closure.
pub struct FormModal {
    fields: Vec<FormField>,
    /// Current focus target (field index or buttons).
    focus: FocusTarget,
    /// Visual width available for the form content.
    #[allow(dead_code)]
    width: u16,
    /// Interactive Add/Cancel buttons.
    buttons: ButtonRow<FormResult>,
}

/// Horizontal gap between buttons.
const BTN_GAP: u16 = 4;

impl FormModal {
    /// Create a new form with the given content width.
    #[must_use]
    pub fn new(width: u16) -> Self {
        let buttons = vec![
            InteractiveButton::new("add", "↵", FormResult::Submitted),
            InteractiveButton::new("cancel", "esc", FormResult::Cancelled),
        ];
        Self {
            fields: Vec::new(),
            focus: FocusTarget::Field(0),
            width,
            buttons: ButtonRow::new(buttons, vec![BTN_GAP, 0]),
        }
    }

    /// Add a text input field.
    #[must_use]
    pub fn text_field(mut self, input: TextInput) -> Self {
        self.fields.push(FormField::text(input));
        self
    }

    /// Add a text input field with an additional custom validator.
    #[must_use]
    pub fn text_field_validated(mut self, input: TextInput, validator: Box<dyn Validator>) -> Self {
        let mut field = FormField::text(input);
        field.add_validator(validator);
        self.fields.push(field);
        self
    }

    /// Add a dropdown selector field.
    #[must_use]
    pub fn select_field(mut self, dropdown: Dropdown) -> Self {
        self.fields.push(FormField::select(dropdown));
        self
    }

    /// Number of fields in the form.
    #[must_use]
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }

    /// Get the value of a text field by index. Returns `None` if the field
    /// is not a text field or the index is out of bounds.
    #[must_use]
    pub fn text_value(&self, index: usize) -> Option<&str> {
        let f = self.fields.get(index)?;
        match &f.kind {
            FieldKind::Text(t) => Some(t.get_value()),
            FieldKind::Select(_) => None,
        }
    }

    /// Get the selected option of a dropdown field by index. Returns `None`
    /// if the field is not a dropdown or the index is out of bounds.
    #[must_use]
    pub fn select_value(&self, index: usize) -> Option<&'static str> {
        let f = self.fields.get(index)?;
        match &f.kind {
            FieldKind::Text(_) => None,
            FieldKind::Select(d) => Some(d.value()),
        }
    }

    /// Get the current focus index (field only — returns 0 if buttons focused).
    #[must_use]
    pub fn focus(&self) -> usize {
        match self.focus {
            FocusTarget::Field(i) => i,
            FocusTarget::Buttons => self.fields.len().saturating_sub(1),
        }
    }

    /// Whether focus is currently on the button row.
    #[must_use]
    pub fn buttons_focused(&self) -> bool {
        self.focus == FocusTarget::Buttons
    }

    /// Whether the form has any fields.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    // ── Key handling ────────────────────────────────────────────────────────

    /// Handle a key event, routing it to the currently focused field or button.
    ///
    /// On submit (Enter on Add button or last field), runs validation on all
    /// fields. If any fail, sets error state, focuses the first invalid field,
    /// and returns `FormResult::Pending`. Otherwise returns `FormResult::Submitted`.
    pub fn handle_key(&mut self, code: KeyCode) -> FormResult {
        if self.fields.is_empty() {
            if matches!(code, KeyCode::Esc) {
                return FormResult::Cancelled;
            }
            return FormResult::Submitted;
        }

        match self.focus {
            FocusTarget::Field(field_idx) => {
                // Clear error on the current field when the user interacts.
                self.fields[field_idx].clear_error();

                let action = match &mut self.fields[field_idx].kind {
                    FieldKind::Text(t) => t.handle_key(code),
                    FieldKind::Select(d) => d.handle_key(code),
                };

                match action {
                    InputAction::Cancel => FormResult::Cancelled,
                    InputAction::Submit => {
                        // Enter on last field → validate all; otherwise move to next.
                        if field_idx == self.fields.len() - 1 {
                            // Move to buttons
                            self.focus = FocusTarget::Buttons;
                            FormResult::Pending
                        } else {
                            self.focus = FocusTarget::Field(field_idx + 1);
                            FormResult::Pending
                        }
                    }
                    InputAction::NextField => {
                        // Tab: from last field → buttons, otherwise → next field
                        if field_idx == self.fields.len() - 1 {
                            self.focus = FocusTarget::Buttons;
                        } else {
                            self.focus = FocusTarget::Field(field_idx + 1);
                        }
                        FormResult::Pending
                    }
                    InputAction::PrevField => {
                        // Shift+Tab: from first field → buttons, otherwise → prev field
                        if field_idx == 0 {
                            self.focus = FocusTarget::Buttons;
                        } else {
                            self.focus = FocusTarget::Field(field_idx - 1);
                        }
                        FormResult::Pending
                    }
                    InputAction::None => FormResult::Pending,
                }
            }
            FocusTarget::Buttons => self.handle_button_key(code),
        }
    }

    /// Handle key events while the button row is focused.
    fn handle_button_key(&mut self, code: KeyCode) -> FormResult {
        match code {
            KeyCode::Enter => {
                let result = self
                    .buttons
                    .activate_focused()
                    .unwrap_or(FormResult::Cancelled);
                if result == FormResult::Submitted {
                    if self.validate_all() {
                        FormResult::Submitted
                    } else {
                        FormResult::Pending
                    }
                } else {
                    FormResult::Cancelled
                }
            }
            KeyCode::Tab => {
                // Tab from buttons → first field
                self.focus = FocusTarget::Field(0);
                FormResult::Pending
            }
            KeyCode::BackTab => {
                // Shift+Tab from buttons → cycle buttons, or back to last field
                self.buttons.cycle_focus_prev();
                FormResult::Pending
            }
            KeyCode::Right => {
                self.buttons.cycle_focus_next();
                FormResult::Pending
            }
            KeyCode::Left => {
                self.buttons.cycle_focus_prev();
                FormResult::Pending
            }
            KeyCode::Esc => FormResult::Cancelled,
            _ => FormResult::Pending,
        }
    }

    /// Handle a mouse event. Returns `Some(FormResult)` if a button was clicked.
    pub fn handle_mouse(&mut self, mouse: &MouseEvent) -> Option<FormResult> {
        let result = self.buttons.handle_mouse(mouse)?;
        if result == FormResult::Submitted {
            if self.validate_all() {
                Some(FormResult::Submitted)
            } else {
                Some(FormResult::Pending)
            }
        } else {
            Some(FormResult::Cancelled)
        }
    }

    /// Handle a key event but never submit — only cycle fields.
    /// Returns `true` if the key was consumed.
    pub fn handle_key_cycle(&mut self, code: KeyCode) -> bool {
        if self.fields.is_empty() {
            return false;
        }

        let action = match self.focus {
            FocusTarget::Field(i) => match &mut self.fields[i].kind {
                FieldKind::Text(t) => t.handle_key(code),
                FieldKind::Select(d) => d.handle_key(code),
            },
            FocusTarget::Buttons => {
                // On buttons, consume Tab/BackTab for cycling
                match code {
                    KeyCode::Tab => {
                        self.focus = FocusTarget::Field(0);
                        return true;
                    }
                    KeyCode::BackTab => {
                        self.buttons.cycle_focus_prev();
                        return true;
                    }
                    _ => return true,
                }
            }
        };

        match action {
            InputAction::NextField => {
                match self.focus {
                    FocusTarget::Field(i) if i == self.fields.len() - 1 => {
                        self.focus = FocusTarget::Buttons;
                    }
                    FocusTarget::Field(i) => {
                        self.focus = FocusTarget::Field(i + 1);
                    }
                    FocusTarget::Buttons => {}
                }
                true
            }
            InputAction::PrevField => {
                match self.focus {
                    FocusTarget::Field(0) => {
                        self.focus = FocusTarget::Buttons;
                    }
                    FocusTarget::Field(i) => {
                        self.focus = FocusTarget::Field(i - 1);
                    }
                    FocusTarget::Buttons => {}
                }
                true
            }
            InputAction::Cancel | InputAction::Submit | InputAction::None => true,
        }
    }

    /// Validate all fields. Returns `true` if all pass.
    /// On failure, focuses the first invalid field.
    fn validate_all(&mut self) -> bool {
        let mut all_valid = true;
        let mut first_invalid = None;

        for (i, field) in self.fields.iter_mut().enumerate() {
            if field.validate().is_some() {
                if first_invalid.is_none() {
                    first_invalid = Some(i);
                }
                all_valid = false;
            }
        }

        if let Some(idx) = first_invalid {
            self.focus = FocusTarget::Field(idx);
        }

        all_valid
    }

    // ── Rendering ───────────────────────────────────────────────────────────

    /// Render all form fields and buttons vertically within the given area.
    ///
    /// Each field gets a 3-row-tall slot (border + content + border), plus an
    /// extra 1-row error line if the field has a validation error, with a
    /// 1-row gap between fields. Buttons render below the last field.
    pub fn render(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        if self.fields.is_empty() {
            return;
        }

        let viewport = Viewport::from_area(area);
        let field_h: u16 = 3; // border + content + border
        let error_h: u16 = 1; // error text below field
        let gap: u16 = 1;
        let button_h: u16 = 1;
        let button_gap: u16 = 1;

        // Build dynamic constraints: fields + errors + gaps + buttons.
        let mut constraints: Vec<Constraint> = Vec::new();

        for i in 0..self.fields.len() {
            let field_rows = if self.fields[i].has_error() {
                field_h + error_h
            } else {
                field_h
            };
            constraints.push(Constraint::Length(field_rows));
            if i < self.fields.len() - 1 {
                constraints.push(Constraint::Length(gap));
            }
        }

        // Gap before buttons
        constraints.push(Constraint::Length(button_gap));
        // Button row
        constraints.push(Constraint::Length(button_h));

        let rects = Layout::vertical(constraints).split(area);

        let field_count = self.fields.len();
        let mut rect_idx = 0;
        for (i, field) in self.fields.iter_mut().enumerate() {
            let field_area = rects[rect_idx];
            let focused = self.focus == FocusTarget::Field(i);
            let error_msg = field.error.clone();

            match &field.kind {
                FieldKind::Text(t) => {
                    t.render(frame, field_area, p, focused, error_msg.as_deref());
                }
                FieldKind::Select(d) => {
                    d.render(frame, field_area, p, focused, error_msg.as_deref());
                }
            }

            // Render error row if present.
            if let Some(ref err) = error_msg {
                let error_y = field_area.y + field_h; // below the 3-row box
                if error_y < field_area.bottom() {
                    let error_area = Rect::new(field_area.x, error_y, field_area.width, error_h);
                    TextInput::render_error(frame, error_area, p, err);
                }
            }

            rect_idx += 1; // field chunk
            if i < field_count - 1 {
                rect_idx += 1; // inter-field gap
            }
        }

        // Render buttons
        // rect_idx now points to the button_gap chunk; buttons are at rect_idx + 1
        if rect_idx + 1 < rects.len() {
            let button_area = rects[rect_idx + 1];
            let buf = frame.buffer_mut();
            self.buttons.render(buf, button_area, p, viewport);
        }
    }

    /// Render the form inside a [`Modal`] with the given title and dimensions.
    pub fn render_in_modal(
        &mut self,
        frame: &mut Frame,
        p: Palette,
        title: &'static str,
        modal_w: u16,
        modal_h: u16,
    ) {
        Modal::new(title)
            .dimensions(modal_w, modal_h)
            .render(frame, p, |frame, content_area| {
                self.render(frame, content_area, p);
            });
    }

    /// Render the form inside a [`Modal`] with an additional instruction line
    /// above the fields.
    pub fn render_in_modal_with_hint(
        &mut self,
        frame: &mut Frame,
        p: Palette,
        title: &'static str,
        modal_w: u16,
        modal_h: u16,
        hint: &str,
    ) {
        Modal::new(title)
            .dimensions(modal_w, modal_h)
            .render(frame, p, |frame, content_area| {
                let [hint_area, _, form_area] = Layout::vertical([
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Min(0),
                ])
                .areas(content_area);

                frame.render_widget(Paragraph::new(Line::from(hint).centered()), hint_area);

                self.render(frame, form_area, p);
            });
    }

    /// Calculate the total form height needed (fields + error rows + gaps + buttons).
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "form field counts are small < u16::MAX"
    )]
    pub fn total_height(&self) -> u16 {
        if self.fields.is_empty() {
            return 0;
        }
        let field_h: u16 = 3;
        let error_h: u16 = 1;
        let gap: u16 = 1;
        let n = self.fields.len() as u16;
        let error_count = self.fields.iter().filter(|f| f.has_error()).count() as u16;
        // fields + errors + gaps between fields + gap before buttons + button row
        n * field_h + error_count * error_h + n.saturating_sub(1) * gap + 1 + 1
    }

    /// Calculate the maximum possible form height (all fields with errors).
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "form field counts are small < u16::MAX"
    )]
    pub fn max_height(&self) -> u16 {
        if self.fields.is_empty() {
            return 0;
        }
        let field_h: u16 = 3;
        let error_h: u16 = 1;
        let gap: u16 = 1;
        let n = self.fields.len() as u16;
        // Same as total_height but with all fields having errors
        n * (field_h + error_h) + n.saturating_sub(1) * gap + 1 + 1
    }

    /// Reset focus to the first field (does NOT reset field values or errors).
    pub fn reset(&mut self) {
        self.focus = FocusTarget::Field(0);
    }

    /// Set a validation error on a specific field and focus it.
    /// Does nothing if the index is out of bounds.
    pub fn set_field_error(&mut self, index: usize, message: &str) {
        if let Some(field) = self.fields.get_mut(index) {
            field.error = Some(message.to_string());
            self.focus = FocusTarget::Field(index);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::validate::Port;
    use super::*;

    fn sample_form() -> FormModal {
        FormModal::new(40)
            .text_field(TextInput::new("Name", 30).required())
            .select_field(Dropdown::new("Type", vec!["Ed25519", "RSA 4096"], 20))
            .text_field(TextInput::new("Comment", 30).placeholder("user@host"))
    }

    #[test]
    fn new_form_is_empty() {
        let form = FormModal::new(40);
        assert!(form.is_empty());
        assert_eq!(form.field_count(), 0);
    }

    #[test]
    fn sample_form_has_three_fields() {
        let form = sample_form();
        assert_eq!(form.field_count(), 3);
        assert!(!form.is_empty());
    }

    #[test]
    fn focus_starts_at_first_field() {
        let form = sample_form();
        assert_eq!(form.focus(), 0);
        assert!(!form.buttons_focused());
    }

    #[test]
    fn text_value_returns_value() {
        let form = FormModal::new(40).text_field(TextInput::new("Name", 30).value("id_new"));
        assert_eq!(form.text_value(0), Some("id_new"));
    }

    #[test]
    fn text_value_returns_none_for_dropdown() {
        let form = sample_form();
        assert_eq!(form.text_value(1), None);
    }

    #[test]
    fn select_value_returns_current() {
        let form = sample_form();
        assert_eq!(form.select_value(1), Some("Ed25519"));
    }

    #[test]
    fn select_value_returns_none_for_text() {
        let form = sample_form();
        assert_eq!(form.select_value(0), None);
    }

    #[test]
    fn out_of_bounds_returns_none() {
        let form = sample_form();
        assert_eq!(form.text_value(99), None);
        assert_eq!(form.select_value(99), None);
    }

    #[test]
    fn tab_cycles_fields_then_buttons() {
        let mut form = sample_form();
        form.handle_key(KeyCode::Tab);
        assert_eq!(form.focus(), 1);
        form.handle_key(KeyCode::Tab);
        assert_eq!(form.focus(), 2);
        form.handle_key(KeyCode::Tab);
        assert!(form.buttons_focused());
        // Tab from buttons wraps to first field
        form.handle_key(KeyCode::Tab);
        assert_eq!(form.focus(), 0);
    }

    #[test]
    fn backtab_cycles_backwards() {
        let mut form = sample_form();
        form.handle_key(KeyCode::BackTab);
        assert!(form.buttons_focused()); // wraps to buttons
        form.handle_key(KeyCode::BackTab);
        // BackTab on buttons cycles button focus, stays on buttons
        assert!(form.buttons_focused());
    }

    #[test]
    fn enter_on_last_field_moves_to_buttons() {
        let mut form = sample_form();
        form.focus = FocusTarget::Field(2);
        let result = form.handle_key(KeyCode::Enter);
        assert!(form.buttons_focused());
        assert_eq!(result, FormResult::Pending);
    }

    #[test]
    fn enter_on_add_button_validates() {
        let mut form = FormModal::new(40)
            .text_field(TextInput::new("Name", 30).required().value("my-key"))
            .text_field(TextInput::new("Comment", 30).placeholder("optional"));
        // Go to buttons and press Enter on Add
        form.focus = FocusTarget::Buttons;
        let result = form.handle_key(KeyCode::Enter);
        assert_eq!(result, FormResult::Submitted);
    }

    #[test]
    fn enter_on_add_button_fails_validation() {
        let mut form = sample_form();
        // Name (field 0) is required but empty. Go to buttons and press Enter.
        form.focus = FocusTarget::Buttons;
        let result = form.handle_key(KeyCode::Enter);
        assert_eq!(result, FormResult::Pending);
        assert_eq!(form.focus(), 0); // jumps to first invalid field
        assert!(form.fields[0].has_error());
    }

    #[test]
    fn esc_cancels() {
        let mut form = sample_form();
        let result = form.handle_key(KeyCode::Esc);
        assert_eq!(result, FormResult::Cancelled);
    }

    #[test]
    fn esc_cancels_from_buttons() {
        let mut form = sample_form();
        form.focus = FocusTarget::Buttons;
        let result = form.handle_key(KeyCode::Esc);
        assert_eq!(result, FormResult::Cancelled);
    }

    #[test]
    fn typing_in_text_field() {
        let mut form = FormModal::new(40).text_field(TextInput::new("Name", 30));
        assert_eq!(form.handle_key(KeyCode::Char('a')), FormResult::Pending);
        assert_eq!(form.handle_key(KeyCode::Char('b')), FormResult::Pending);
        assert_eq!(form.text_value(0), Some("ab"));
    }

    #[test]
    fn dropdown_cycling_in_form() {
        let mut form = sample_form();
        form.focus = FocusTarget::Field(1); // Focus the dropdown
        form.handle_key(KeyCode::Down);
        assert_eq!(form.select_value(1), Some("RSA 4096"));
    }

    #[test]
    fn total_height_calculation() {
        let form = sample_form(); // 3 fields, no errors
        // 3 * 3 (field heights) + 2 * 1 (gaps) + 1 (gap before buttons) + 1 (buttons) = 13
        assert_eq!(form.total_height(), 13);
    }

    #[test]
    fn total_height_empty() {
        let form = FormModal::new(40);
        assert_eq!(form.total_height(), 0);
    }

    #[test]
    fn validation_with_custom_validator() {
        let mut form = FormModal::new(40)
            .text_field_validated(TextInput::new("Port", 10).required(), Box::new(Port));
        // Type an invalid port
        for ch in "abc".chars() {
            form.handle_key(KeyCode::Char(ch));
        }
        // Go to buttons and submit
        form.focus = FocusTarget::Buttons;
        let result = form.handle_key(KeyCode::Enter);
        assert_eq!(result, FormResult::Pending);
        assert!(form.fields[0].has_error());
    }

    #[test]
    fn validation_passes_with_valid_data() {
        let mut form =
            FormModal::new(40).text_field(TextInput::new("Name", 30).required().value("my-key"));
        form.focus = FocusTarget::Buttons;
        let result = form.handle_key(KeyCode::Enter);
        assert_eq!(result, FormResult::Submitted);
    }

    #[test]
    fn error_clears_on_typing() {
        let mut form = sample_form();
        // Force an error by submitting with empty Name
        form.focus = FocusTarget::Buttons;
        form.handle_key(KeyCode::Enter);
        assert!(form.fields[0].has_error());

        // Now focus the Name field and type
        form.focus = FocusTarget::Field(0);
        form.handle_key(KeyCode::Char('a'));
        assert!(!form.fields[0].has_error());
    }

    #[test]
    fn render_shows_buttons() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut form =
            FormModal::new(40).text_field(TextInput::new("Name", 30).required().value("test"));
        let mut terminal = Terminal::new(TestBackend::new(60, 12)).unwrap();
        terminal
            .draw(|f| {
                form.render_in_modal(f, CHARM, "Test Form", 50, 10);
            })
            .unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains("↵"), "add button visible: {output}");
        assert!(output.contains("esc"), "cancel button visible: {output}");
    }
}
