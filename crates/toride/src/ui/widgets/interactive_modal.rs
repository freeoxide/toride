//! A stateful interactive modal that owns visibility, rect tracking,
//! click-outside detection, optional buttons, and input interception.
//!
//! Wraps the rendering-only [`Modal`] widget and adds the interaction layer
//! that every modal caller otherwise has to reinvent: visibility state, modal
//! rect storage for hit-testing, click-outside-to-close, and button focus
//! cycling / activation.
//!
//! # Usage
//!
//! **Buttonless (display-only):**
//! ```ignore
//! let mut modal = InteractiveModal::<Action>::display("Key Detail")
//!     .dimensions(54, 12);
//!
//! // Open
//! modal.open();
//!
//! // Input — returns ModalEvent
//! match modal.handle_key(code) {
//!     ModalEvent::Closed => { /* user pressed Esc */ }
//!     ModalEvent::Consumed => { /* key swallowed */ }
//!     ModalEvent::Button(_) => unreachable!(), // no buttons
//! }
//!
//! // Render
//! if modal.is_visible() {
//!     modal.render(frame, palette, |frame, area| {
//!         // render content into `area`
//!     });
//! }
//! ```
//!
//! **With buttons:**
//! ```ignore
//! let modal = InteractiveModal::with_buttons("module",
//!     ButtonRow::new(vec![
//!         InteractiveButton::new("open", "↵", Action::Continue),
//!         InteractiveButton::new("close", "esc", Action::Back),
//!     ], vec![4, 0]),
//! ).dimensions(54, 10);
//! ```

use crossterm::event::{KeyCode, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{Frame, layout::Rect};

use crate::ui::components::ButtonRow;
use crate::ui::responsive::Viewport;
use crate::ui::theme::Palette;

use super::{Modal, ModalBorder};

// ── ModalEvent ─────────────────────────────────────────────────────────────

/// Outcome of an interactive modal input event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModalEvent<A> {
    /// The event was consumed but the modal is still open (focus cycling,
    /// mouse hover, etc.). No action needed.
    Consumed,
    /// The modal was closed by the user (Esc, click-outside).
    /// No button action to report.
    Closed,
    /// A button was activated (keyboard or mouse). Carries the button's action.
    Button(A),
}

// ── InteractiveModal ────────────────────────────────────────────────────────

/// Default modal width.
const DEFAULT_WIDTH: u16 = 52;
/// Default modal height.
const DEFAULT_HEIGHT: u16 = 16;

/// A self-contained interactive modal that manages visibility, rect tracking,
/// click-outside detection, button routing, and input interception.
///
/// Generic over the action type `A` so different modals return different types
/// (`Action`, `ConfirmResult`, `FormResult`, etc.).
///
/// Wraps the rendering-only [`Modal`] widget. Call [`render`](Self::render)
/// to display and [`handle_key`](Self::handle_key) /
/// [`handle_mouse`](Self::handle_mouse) for input.
pub struct InteractiveModal<A: Copy + PartialEq> {
    title: &'static str,
    width: u16,
    height: u16,
    border: ModalBorder,
    visible: bool,
    modal_rect: Option<Rect>,
    buttons: Option<ButtonRow<A>>,
    close_on_click_outside: bool,
}

impl<A: Copy + PartialEq> InteractiveModal<A> {
    // ── Constructors ────────────────────────────────────────────────────

    /// Create a new interactive modal with the given title and no buttons.
    ///
    /// Defaults: `52×16`, `ModalBorder::Default`, click-outside enabled.
    #[must_use]
    pub fn new(title: &'static str) -> Self {
        Self {
            title,
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
            border: ModalBorder::Default,
            visible: false,
            modal_rect: None,
            buttons: None,
            close_on_click_outside: true,
        }
    }

    /// Alias for [`new`](Self::new) — emphasises that this is a display-only
    /// modal with no interactive buttons.
    #[must_use]
    pub fn display(title: &'static str) -> Self {
        Self::new(title)
    }

    /// Create a modal with interactive buttons.
    #[must_use]
    pub fn with_buttons(title: &'static str, buttons: ButtonRow<A>) -> Self {
        Self {
            buttons: Some(buttons),
            ..Self::new(title)
        }
    }

    // ── Builder methods ─────────────────────────────────────────────────

    /// Override modal dimensions (clamped to terminal at render time).
    #[must_use]
    pub fn dimensions(mut self, width: u16, height: u16) -> Self {
        self.width = width;
        self.height = height;
        self
    }

    /// Override border style.
    #[must_use]
    pub fn border(mut self, border: ModalBorder) -> Self {
        self.border = border;
        self
    }

    /// Toggle click-outside-to-close. Defaults to `true`.
    #[must_use]
    pub fn close_on_click_outside(mut self, enabled: bool) -> Self {
        self.close_on_click_outside = enabled;
        self
    }

    // ── State management ────────────────────────────────────────────────

    /// Whether the modal is currently visible.
    #[must_use]
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Open the modal.
    pub fn open(&mut self) {
        self.visible = true;
    }

    /// Close the modal and clear the stored rect.
    pub fn close(&mut self) {
        self.visible = false;
        self.modal_rect = None;
    }

    // ── Input handling ──────────────────────────────────────────────────

    /// Handle a key event while the modal is open.
    ///
    /// - `Esc` → `Closed`
    /// - `Enter` (with buttons) → activates focused button → `Button(A)`
    /// - `Tab` / `Right` (with buttons) → cycle focus forward → `Consumed`
    /// - `BackTab` / `Left` (with buttons) → cycle focus backward → `Consumed`
    /// - Any other key → `Consumed` (swallowed — nothing leaks through)
    pub fn handle_key(&mut self, code: KeyCode) -> ModalEvent<A> {
        if code == KeyCode::Esc {
            self.close();
            return ModalEvent::Closed;
        }

        if let Some(ref mut buttons) = self.buttons {
            match code {
                KeyCode::Enter => {
                    if let Some(action) = buttons.activate_focused() {
                        self.close();
                        ModalEvent::Button(action)
                    } else {
                        ModalEvent::Consumed
                    }
                }
                KeyCode::Tab | KeyCode::Right => {
                    buttons.cycle_focus_next();
                    ModalEvent::Consumed
                }
                KeyCode::BackTab | KeyCode::Left => {
                    buttons.cycle_focus_prev();
                    ModalEvent::Consumed
                }
                _ => ModalEvent::Consumed,
            }
        } else {
            // No buttons: swallow all keys while open.
            ModalEvent::Consumed
        }
    }

    /// Handle a mouse event while the modal is open.
    ///
    /// 1. If buttons exist, delegate to the button row first. If a button is
    ///    activated, close and return `Button(A)`.
    /// 2. If click-outside is enabled and the click landed outside the modal
    ///    rect, close and return `Closed`.
    /// 3. Otherwise return `Consumed`.
    pub fn handle_mouse(&mut self, mouse: &MouseEvent) -> ModalEvent<A> {
        // Step 1: button delegation.
        if let Some(ref mut buttons) = self.buttons
            && let Some(action) = buttons.handle_mouse(mouse)
        {
            self.close();
            return ModalEvent::Button(action);
        }

        // Step 2: click-outside detection.
        if self.close_on_click_outside
            && matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left))
            && let Some(rect) = self.modal_rect
        {
            let col = mouse.column;
            let row = mouse.row;
            if col < rect.x || col >= rect.right() || row < rect.y || row >= rect.bottom() {
                self.close();
                return ModalEvent::Closed;
            }
        }

        // Step 3: everything else consumed.
        ModalEvent::Consumed
    }

    // ── Rendering ───────────────────────────────────────────────────────

    /// Render the modal overlay, storing the rect for future hit-testing.
    ///
    /// The `content_fn` closure renders the modal's interior content.
    /// Call this only when [`is_visible`](Self::is_visible) returns `true`.
    pub fn render(
        &mut self,
        frame: &mut Frame,
        palette: Palette,
        content_fn: impl FnOnce(&mut Frame, Rect),
    ) {
        let modal = Modal::new(self.title)
            .dimensions(self.width, self.height)
            .border(std::mem::replace(&mut self.border, ModalBorder::Default));
        self.modal_rect = Some(modal.rect(frame.area()));
        modal.render(frame, palette, content_fn);
    }

    /// Render the button row into the given area.
    ///
    /// Returns `false` if there are no buttons.
    pub fn render_buttons(&mut self, frame: &mut Frame, area: Rect, palette: Palette) -> bool {
        if let Some(ref mut buttons) = self.buttons {
            let viewport = Viewport::from_area(frame.area());
            let buf = frame.buffer_mut();
            buttons.render(buf, area, palette, viewport);
            true
        } else {
            false
        }
    }

    /// Render the modal overlay, storing the rect for future hit-testing.
    ///
    /// The `content_fn` closure receives `Option<&mut ButtonRow<A>>` so it can
    /// render buttons without double-borrowing `self`. Use this when the caller
    /// needs to render buttons inside the content closure (avoids borrow conflicts).
    pub fn render_with_extracted_buttons(
        &mut self,
        frame: &mut Frame,
        palette: Palette,
        content_fn: impl FnOnce(&mut Frame, Rect, Option<&mut ButtonRow<A>>),
    ) {
        let modal = Modal::new(self.title)
            .dimensions(self.width, self.height)
            .border(std::mem::replace(&mut self.border, ModalBorder::Default));
        self.modal_rect = Some(modal.rect(frame.area()));
        let mut buttons = self.buttons.take();
        modal.render(frame, palette, |frame, area| {
            content_fn(frame, area, buttons.as_mut());
        });
        self.buttons = buttons;
    }

    /// Access the button row mutably for custom setup.
    /// Returns `None` for buttonless modals.
    pub fn buttons_mut(&mut self) -> Option<&mut ButtonRow<A>> {
        self.buttons.as_mut()
    }
}

impl<A: Copy + PartialEq + Default> Default for InteractiveModal<A> {
    fn default() -> Self {
        Self::new("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::Action;

    // ── State management ─────────────────────────────────────────────

    #[test]
    fn new_starts_hidden() {
        let modal: InteractiveModal<Action> = InteractiveModal::new("Test");
        assert!(!modal.is_visible());
    }

    #[test]
    fn open_close_cycle() {
        let mut modal: InteractiveModal<Action> = InteractiveModal::new("Test");
        modal.open();
        assert!(modal.is_visible());
        modal.close();
        assert!(!modal.is_visible());
    }

    // ── handle_key (buttonless) ──────────────────────────────────────

    #[test]
    fn esc_closes_buttonless() {
        let mut modal: InteractiveModal<Action> = InteractiveModal::new("Test");
        modal.open();
        let result = modal.handle_key(KeyCode::Esc);
        assert_eq!(result, ModalEvent::Closed);
        assert!(!modal.is_visible());
    }

    #[test]
    fn other_keys_consumed_buttonless() {
        let mut modal: InteractiveModal<Action> = InteractiveModal::new("Test");
        modal.open();
        assert_eq!(modal.handle_key(KeyCode::Char('a')), ModalEvent::Consumed);
        assert_eq!(modal.handle_key(KeyCode::Up), ModalEvent::Consumed);
        assert!(modal.is_visible());
    }

    // ── handle_key (with buttons) ────────────────────────────────────

    fn confirm_modal() -> InteractiveModal<Action> {
        use crate::ui::components::interactive_button::InteractiveButton;
        InteractiveModal::with_buttons(
            "Confirm?",
            ButtonRow::new(
                vec![
                    InteractiveButton::new("yes", "y", Action::Quit),
                    InteractiveButton::new("no", "n", Action::DismissQuit),
                ],
                vec![4, 0],
            ),
        )
        .dimensions(36, 7)
    }

    #[test]
    fn esc_closes_with_buttons() {
        let mut modal = confirm_modal();
        modal.open();
        assert_eq!(modal.handle_key(KeyCode::Esc), ModalEvent::Closed);
        assert!(!modal.is_visible());
    }

    #[test]
    fn enter_activates_focused_button() {
        let mut modal = confirm_modal();
        modal.open();
        // "yes" (index 0) is focused by default → Quit
        assert_eq!(
            modal.handle_key(KeyCode::Enter),
            ModalEvent::Button(Action::Quit)
        );
        assert!(!modal.is_visible());
    }

    #[test]
    fn tab_cycles_and_enter_activates() {
        let mut modal = confirm_modal();
        modal.open();
        // Tab to "no"
        assert_eq!(modal.handle_key(KeyCode::Tab), ModalEvent::Consumed);
        assert_eq!(
            modal.handle_key(KeyCode::Enter),
            ModalEvent::Button(Action::DismissQuit)
        );
    }

    #[test]
    fn backtab_cycles_backward() {
        let mut modal = confirm_modal();
        modal.open();
        // BackTab from index 0 → wraps to last
        assert_eq!(modal.handle_key(KeyCode::BackTab), ModalEvent::Consumed);
        assert_eq!(
            modal.handle_key(KeyCode::Enter),
            ModalEvent::Button(Action::DismissQuit)
        );
    }

    #[test]
    fn right_cycles_forward() {
        let mut modal = confirm_modal();
        modal.open();
        assert_eq!(modal.handle_key(KeyCode::Right), ModalEvent::Consumed);
        assert_eq!(
            modal.handle_key(KeyCode::Enter),
            ModalEvent::Button(Action::DismissQuit)
        );
    }

    #[test]
    fn left_cycles_backward() {
        let mut modal = confirm_modal();
        modal.open();
        assert_eq!(modal.handle_key(KeyCode::Left), ModalEvent::Consumed);
        // Left from index 0 wraps to index 1 (no)
        assert_eq!(
            modal.handle_key(KeyCode::Enter),
            ModalEvent::Button(Action::DismissQuit)
        );
    }

    #[test]
    fn unknown_key_consumed_with_buttons() {
        let mut modal = confirm_modal();
        modal.open();
        assert_eq!(modal.handle_key(KeyCode::Char('z')), ModalEvent::Consumed);
        assert_eq!(modal.handle_key(KeyCode::Up), ModalEvent::Consumed);
        assert!(modal.is_visible());
    }

    // ── Builders ─────────────────────────────────────────────────────

    #[test]
    fn dimensions_override() {
        let modal: InteractiveModal<Action> = InteractiveModal::new("Test").dimensions(30, 5);
        assert_eq!(modal.width, 30);
        assert_eq!(modal.height, 5);
    }

    #[test]
    fn close_on_click_outside_default_true() {
        let modal: InteractiveModal<Action> = InteractiveModal::new("Test");
        assert!(modal.close_on_click_outside);
    }

    #[test]
    fn close_on_click_outside_can_disable() {
        let modal: InteractiveModal<Action> =
            InteractiveModal::new("Test").close_on_click_outside(false);
        assert!(!modal.close_on_click_outside);
    }

    // ── Render snapshot ──────────────────────────────────────────────

    #[test]
    fn render_buttonless_snapshot() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut modal: InteractiveModal<Action> = InteractiveModal::new("Detail").dimensions(40, 8);
        modal.open();
        let mut terminal = Terminal::new(TestBackend::new(60, 16)).unwrap();
        terminal
            .draw(|f| {
                modal.render(f, CHARM, |_frame, _area| {
                    // empty content
                });
            })
            .unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains("Detail"), "title visible: {output}");
    }

    #[test]
    fn render_with_buttons_snapshot() {
        use crate::ui::theme::CHARM;
        use ratatui::{
            Terminal,
            backend::TestBackend,
            layout::{Constraint, Layout},
            text::Line,
            widgets::Paragraph,
        };

        let mut modal = confirm_modal();
        modal.open();
        // Extract buttons before the closure to avoid double borrow.
        let mut buttons = modal.buttons.take();
        let mut terminal = Terminal::new(TestBackend::new(60, 16)).unwrap();
        terminal
            .draw(|f| {
                modal.render(f, CHARM, |frame, area| {
                    let [_, msg, _, btn, _] = Layout::vertical([
                        Constraint::Fill(1),
                        Constraint::Length(1),
                        Constraint::Length(1),
                        Constraint::Length(1),
                        Constraint::Fill(1),
                    ])
                    .areas(area);
                    frame
                        .render_widget(Paragraph::new(Line::from("Are you sure?").centered()), msg);
                    if let Some(ref mut btns) = buttons {
                        let viewport = Viewport::from_area(frame.area());
                        let buf = frame.buffer_mut();
                        btns.render(buf, btn, CHARM, viewport);
                    }
                });
            })
            .unwrap();
        // Restore buttons
        modal.buttons = buttons;
        let output = terminal.backend().to_string();
        assert!(output.contains("Confirm?"), "title: {output}");
        assert!(output.contains("Are you sure?"), "message: {output}");
    }
}
