use std::time::Instant;

use crossterm::event::{KeyCode, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    buffer::Buffer,
    layout::{Constraint, Layout, Position, Rect},
    prelude::Widget,
    style::{Color, Style},
    text::{Line, Span},
    widgets::Paragraph,
};
use ratatui_interact::components::{Button, ButtonState, ButtonStyle, ButtonVariant};
use ratatui_interact::events::get_mouse_pos;
use ratatui_interact::state::FocusManager;
use ratatui_interact::traits::ClickRegionRegistry;
use tachyonfx::{Interpolatable, color_from_hsl, color_to_hsl};

use crate::action::Action;
use crate::ui::gradient::GradientCache;
use crate::ui::responsive::{self, Viewport};
use crate::ui::theme::{self, Palette, KEY_BG};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const EDITION: &str = "SINGLE-HOST";

// ANSI Shadow figlet — matches screens.jsx LOGO constant exactly
const LOGO: &[&str] = &[
    "████████╗ ██████╗ ██████╗ ██╗██████╗ ███████╗",
    "╚══██╔══╝██╔═══██╗██╔══██╗██║██╔══██╗██╔════╝",
    "   ██║   ██║   ██║██████╔╝██║██║  ██║█████╗  ",
    "   ██║   ██║   ██║██╔══██╗██║██║  ██║██╔══╝  ",
    "   ██║   ╚██████╔╝██║  ██║██║██████╔╝███████╗",
    "   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝",
];

/// Button labels for compact and minimal viewports.
const BTN_LABELS_COMPACT: &[&str] = &["↵ continue", "? help", "q quit"];
const BTN_LABELS_MINIMAL: &[&str] = &["↵", "?", "q"];
const BTN_GAPS: &[u16] = &[0, 2, 2];

/// Actions associated with each button index.
const BTN_ACTIONS: &[Action] = &[Action::Continue, Action::Help, Action::Quit];

pub struct WelcomeScreen {
    gradient_cache: GradientCache,
    anim_start: Instant,
    color_cycle: Vec<Color>,
    buttons: [ButtonState; 3],
    focus: FocusManager<usize>,
    click_registry: ClickRegionRegistry<Action>,
    hover_pos: Option<(u16, u16)>,
    pending_click: Option<Action>,
}

impl Default for WelcomeScreen {
    fn default() -> Self {
        Self::new()
    }
}

impl WelcomeScreen {
    #[must_use]
    pub fn new() -> Self {
        let mut focus = FocusManager::new();
        focus.register_all([0, 1, 2]);

        let mut buttons = [ButtonState::enabled(), ButtonState::enabled(), ButtonState::enabled()];
        if let Some(&idx) = focus.current() {
            buttons[idx].focused = true;
        }

        Self {
            gradient_cache: GradientCache::new(),
            anim_start: Instant::now(),
            color_cycle: build_color_cycle(theme::CHARM.accent),
            buttons,
            focus,
            click_registry: ClickRegionRegistry::new(),
            hover_pos: None,
            pending_click: None,
        }
    }

    pub fn invalidate_cache(&mut self) {
        self.gradient_cache.invalidate();
    }

    /// Handle a key event. Supports direct shortcuts (q, ?, Enter), Tab/Shift+Tab
    /// for focus cycling, and Arrow keys.
    #[must_use]
    pub fn handle_key(&mut self, code: KeyCode) -> Option<Action> {
        // Direct shortcuts always work
        match code {
            KeyCode::Char('q') | KeyCode::Esc => return Some(Action::Quit),
            KeyCode::Char('?') => return Some(Action::Help),
            KeyCode::Enter | KeyCode::Char(' ') => return Some(Action::Continue),
            _ => {}
        }

        // Focus cycling
        match code {
            KeyCode::Tab | KeyCode::Right => self.cycle_focus_next(),
            KeyCode::BackTab | KeyCode::Left => self.cycle_focus_prev(),
            _ => {}
        }
        None
    }

    /// Handle a mouse event. Returns an Action if a button was clicked.
    ///
    /// Press feedback: `Down` sets the button's pressed state and stores the
    /// action; `Up` clears pressed states and returns the stored action so the
    /// user sees the visual press before the action fires.
    #[must_use]
    pub fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action> {
        let (col, row) = get_mouse_pos(&mouse);

        match mouse.kind {
            MouseEventKind::Moved | MouseEventKind::Drag(..) => {
                self.hover_pos = Some((col, row));
                None
            }
            MouseEventKind::Down(_) => {
                if let Some(&action) = self.click_registry.handle_click(col, row) {
                    if let Some(idx) = BTN_ACTIONS.iter().position(|&a| a == action) {
                        self.buttons[idx].pressed = true;
                    }
                    self.pending_click = Some(action);
                }
                None
            }
            MouseEventKind::Up(..) => {
                for btn in &mut self.buttons {
                    btn.pressed = false;
                }
                self.pending_click.take()
            }
            _ => None,
        }
    }

    fn cycle_focus_next(&mut self) {
        self.focus.next();
        self.sync_focus_to_buttons();
    }

    fn cycle_focus_prev(&mut self) {
        self.focus.prev();
        self.sync_focus_to_buttons();
    }

    fn sync_focus_to_buttons(&mut self) {
        let focused = self.focus.current().copied();
        for (i, btn) in self.buttons.iter_mut().enumerate() {
            btn.focused = focused == Some(i);
        }
    }

    pub fn view(&mut self, frame: &mut Frame) {
        self.view_with_palette(frame, theme::CHARM);
    }

    fn view_with_palette(&mut self, frame: &mut Frame, p: Palette) {
        let area = frame.area();
        let viewport = Viewport::from_area(area);

        // Fallback for tiny terminals
        if responsive::render_too_small(frame, p) {
            return;
        }

        // Gradient background
        let buf = frame.buffer_mut();
        self.gradient_cache.render_or_copy(buf, area, p);

        // Adaptive center column
        let center = responsive::center_area(area);

        // Vertical layout
        let [
            _top,
            logo_area,
            _g1,
            version_area,
            prompt_area,
            _g2,
            keys_area,
            _bottom,
        ] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(6),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Fill(1),
        ])
        .areas(center);

        // ── Animated border ───────────────────────────────────────────────
        let border_rect = content_border_rect(logo_area, keys_area, area);
        let elapsed = self.anim_start.elapsed().as_secs_f32();
        draw_animated_border(buf, border_rect, &self.color_cycle, elapsed);

        // ── Logo ──────────────────────────────────────────────────────────
        let logo_style = Style::new().fg(p.accent).bold();
        let logo_lines = responsive::truncate_logo(LOGO, center.width, logo_style);
        frame.render_widget(Paragraph::new(logo_lines).centered(), logo_area);

        // ── Version ───────────────────────────────────────────────────────
        let version_line = Line::from(vec![
            Span::styled("砦", Style::new().fg(p.accent2).bold()),
            Span::styled("  ·  ", Style::new().fg(p.text_muted)),
            Span::styled(VERSION, Style::new().fg(p.accent2).bold()),
            Span::styled("  ·  ", Style::new().fg(p.text_muted)),
            Span::styled(EDITION, Style::new().fg(p.accent2).bold()),
        ]);
        frame.render_widget(Paragraph::new(version_line).centered(), version_area);

        // ── Prompt ────────────────────────────────────────────────────────
        let prompt_text = if viewport >= Viewport::Compact {
            "Press any key, or click a button, to enter."
        } else {
            "Press any key to enter."
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                prompt_text,
                Style::new().fg(p.text_dim),
            )))
            .centered(),
            prompt_area,
        );

        // ── Interactive buttons ───────────────────────────────────────────
        self.render_buttons(frame, keys_area, p, viewport);
    }

    fn render_buttons(
        &mut self,
        frame: &mut Frame,
        keys_area: Rect,
        p: Palette,
        viewport: Viewport,
    ) {
        let labels = if viewport >= Viewport::Compact {
            BTN_LABELS_COMPACT
        } else {
            BTN_LABELS_MINIMAL
        };

        // Compute button widths (fixed-size array avoids per-frame allocation)
        let btn_widths: [u16; 3] = std::array::from_fn(|i| {
            Button::new(labels[i], &self.buttons[i]).min_width()
        });

        let total_btn: u16 = btn_widths.iter().sum();
        let total_gap: u16 = BTN_GAPS.iter().sum();
        let total_width = total_btn + total_gap;

        // Center the button row within keys_area
        let btn_row_x = keys_area.x.saturating_sub(total_width / 2)
            + keys_area.width / 2;

        // Clear click registry for this frame
        self.click_registry.clear();

        let mut cursor_x = btn_row_x;
        for (i, (&label, &width)) in labels.iter().zip(btn_widths.iter()).enumerate() {
            // Check hover
            let is_hovered = self.hover_pos.is_some_and(|(mx, my)| {
                let btn_rect = Rect::new(cursor_x, keys_area.y, width, 1);
                btn_rect.contains(Position::new(mx, my))
            });

            // Build a local render state so hover never mutates persistent state
            let render_state = ButtonState {
                focused: self.buttons[i].focused || is_hovered,
                pressed: self.buttons[i].pressed,
                enabled: self.buttons[i].enabled,
                toggled: self.buttons[i].toggled,
            };

            let mut btn_style = ButtonStyle::new(ButtonVariant::SingleLine);
            btn_style.unfocused_fg = p.text;
            btn_style.unfocused_bg = KEY_BG;
            btn_style.focused_fg = p.bg;
            btn_style.focused_bg = p.accent;
            btn_style.pressed_fg = p.bg;
            btn_style.pressed_bg = p.accent2;

            let btn_area = Rect::new(cursor_x, keys_area.y, width, 1);
            Button::new(label, &render_state)
                .style(btn_style)
                .render(btn_area, frame.buffer_mut());

            // Register click region (Action is Copy — no clone needed)
            self.click_registry.register(btn_area, BTN_ACTIONS[i]);

            cursor_x += width + BTN_GAPS[i];
        }
    }
}

// ── Animated border ───────────────────────────────────────────────────────────

/// Compute the border rect as the union of content areas expanded by 2 cells
/// of padding, clamped to the frame area.
fn content_border_rect(logo_area: Rect, keys_area: Rect, frame_area: Rect) -> Rect {
    let pad = 2u16;
    let x = logo_area.x.saturating_sub(pad).max(frame_area.x);
    let y = logo_area.y.saturating_sub(pad).max(frame_area.y);
    let right = (keys_area.right() + pad).min(frame_area.right());
    let bottom = (keys_area.bottom() + pad).min(frame_area.bottom());
    Rect {
        x,
        y,
        width: right.saturating_sub(x),
        height: bottom.saturating_sub(y),
    }
}

/// Build a seamless looping color gradient from a base color using HSL manipulation.
/// Ported from exabind's `select_category_color_cycle()`, with a final wrap-around
/// segment that interpolates back to the base color for smooth looping at corners.
fn build_color_cycle(base_color: Color) -> Vec<Color> {
    let (h, s, l) = color_to_hsl(&base_color);

    let color_l = color_from_hsl(h, s, 80.0);
    let color_d = color_from_hsl(h, s, 40.0);
    let color_hue_neg = color_from_hsl((h - 25.0).rem_euclid(360.0), s, (l + 10.0).min(100.0));
    let color_sat_neg = color_from_hsl(h, (s - 20.0).max(0.0), (l + 10.0).min(100.0));
    let color_hue_pos = color_from_hsl((h + 25.0).rem_euclid(360.0), s, (l + 10.0).min(100.0));
    let color_sat_pos = color_from_hsl(h, (s + 20.0).min(100.0), (l + 10.0).min(100.0));

    let keyframes: &[(usize, Color)] = &[
        (4, color_d),
        (2, color_l),
        (4, color_hue_neg),
        (7, color_sat_neg),
        (7, color_hue_pos),
        (7, color_sat_pos),
    ];

    let mut colors = vec![base_color];
    let mut prev = base_color;
    #[allow(clippy::cast_precision_loss)] // step counts are small (< 50)
    for &(steps, target) in keyframes {
        let steps_f = steps as f32;
        for i in 1..steps {
            colors.push(prev.lerp(&target, i as f32 / steps_f));
        }
        colors.push(target);
        prev = target;
    }

    // Wrap-around: interpolate from last keyframe back to base color
    // so the cycle loops seamlessly at the join point (top-left corner).
    let wrap_steps = 7;
    #[allow(clippy::cast_precision_loss)] // wrap_steps and i are always < 50
    let wrap_f = wrap_steps as f32;
    for i in 1..wrap_steps {
        #[allow(clippy::cast_precision_loss)]
        colors.push(prev.lerp(&base_color, i as f32 / wrap_f));
    }

    colors
}

/// Draw an animated color-cycling border around `border_rect`.
///
/// Walks the perimeter clockwise (top→right→bottom→left), drawing box-drawing
/// characters with foreground colors that cycle over time, producing a flowing
/// rainbow effect at ~12 cells/second.
fn draw_animated_border(
    buf: &mut Buffer,
    border_rect: Rect,
    color_cycle: &[Color],
    elapsed_secs: f32,
) {
    if border_rect.width < 3 || border_rect.height < 3 {
        return;
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let idx = (elapsed_secs * 12.0) as usize;
    let cycle_len = color_cycle.len();
    let mut perimeter_idx = 0usize;

    let color_at = |pidx: usize| -> Color { color_cycle[(idx + pidx) % cycle_len] };

    let set_cell = |buf: &mut Buffer, x: u16, y: u16, ch: char, pidx: usize| {
        if let Some(cell) = buf.cell_mut(Position::new(x, y)) {
            cell.set_char(ch);
            cell.set_fg(color_at(pidx));
        }
    };

    let x0 = border_rect.x;
    let y0 = border_rect.y;
    let x1 = border_rect.right() - 1;
    let y1 = border_rect.bottom() - 1;

    // Top edge: left → right
    set_cell(buf, x0, y0, '┌', perimeter_idx);
    perimeter_idx += 1;
    for x in (x0 + 1)..x1 {
        set_cell(buf, x, y0, '─', perimeter_idx);
        perimeter_idx += 1;
    }
    set_cell(buf, x1, y0, '┐', perimeter_idx);
    perimeter_idx += 1;

    // Right edge: top → bottom
    for y in (y0 + 1)..y1 {
        set_cell(buf, x1, y, '│', perimeter_idx);
        perimeter_idx += 1;
    }

    // Bottom edge: right → left
    set_cell(buf, x1, y1, '┘', perimeter_idx);
    perimeter_idx += 1;
    for x in ((x0 + 1)..x1).rev() {
        set_cell(buf, x, y1, '─', perimeter_idx);
        perimeter_idx += 1;
    }
    set_cell(buf, x0, y1, '└', perimeter_idx);
    perimeter_idx += 1;

    // Left edge: bottom → top
    for y in ((y0 + 1)..y1).rev() {
        set_cell(buf, x0, y, '│', perimeter_idx);
        perimeter_idx += 1;
    }
}
