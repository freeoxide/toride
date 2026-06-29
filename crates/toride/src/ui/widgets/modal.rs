//! Reusable modal overlay widget.
//!
//! Renders a centered, bordered popup on top of existing screen content with a
//! dimmed scrim backdrop. Any content can be rendered inside via a closure.
//!
//! # Example
//!
//! ```ignore
//! use crate::ui::widgets::{Modal, ModalBorder};
//!
//! // Default themed border
//! Modal::new("Help")
//!     .render(frame, palette, |frame, area| { /* ... */ });
//!
//! // Animated color-cycling border
//! Modal::new("Confirm")
//!     .dimensions(40, 8)
//!     .border(ModalBorder::Animated)
//!     .render(frame, palette, |frame, area| { /* ... */ });
//!
//! // Dashed border with custom color
//! Modal::new("Error")
//!     .border(ModalBorder::TypedCustom(BorderType::HeavyDoubleDashed, Color::Red))
//!     .render(frame, palette, |frame, area| { /* ... */ });
//!
//! // No border at all
//! Modal::new("Tooltip")
//!     .border(ModalBorder::None)
//!     .render(frame, palette, |frame, area| { /* ... */ });
//! ```

use ratatui::{
    Frame,
    buffer::Buffer,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Style},
    widgets::{Block, BorderType, Clear},
};

use crate::ui::theme::Palette;
use crate::ui::widgets::gradient::AnimatedBorder;

/// Default modal dimensions.
const DEFAULT_WIDTH: u16 = 52;
const DEFAULT_HEIGHT: u16 = 16;

/// Scrim blend factors (how much to dim bg / fg toward the scrim target).
const SCRIM_BG_FACTOR: f32 = 0.55;
const SCRIM_FG_FACTOR: f32 = 0.45;

// ── ModalBorder ────────────────────────────────────────────────────────────────

/// Configurable border styles for [`Modal`].
pub enum ModalBorder {
    /// No border — just the panel background.
    None,
    /// Standard ratatui border using the palette's `border_hi` color.
    Default,
    /// Standard ratatui border with a custom color.
    Custom(Color),
    /// ratatui border with a specific [`BorderType`] using the palette's `border_hi` color.
    Typed(BorderType),
    /// ratatui border with a specific [`BorderType`] and custom color.
    TypedCustom(BorderType, Color),
    /// Animated color-cycling border using the palette's `accent` color.
    Animated,
    /// Animated color-cycling border with a custom base color.
    AnimatedCustom(Color),
}

// ── Modal widget ───────────────────────────────────────────────────────────────

/// A reusable modal overlay widget.
///
/// Handles the full overlay pipeline: dimmed scrim, centered bordered box with
/// solid background, and arbitrary content rendering inside. Construct with
/// [`Modal::new`] and optional builder methods, then call [`Modal::render`].
pub struct Modal {
    title: &'static str,
    width: u16,
    height: u16,
    border: ModalBorder,
}

impl Modal {
    /// Create a new modal with the given title displayed in the border.
    #[must_use]
    pub fn new(title: &'static str) -> Self {
        Self {
            title,
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
            border: ModalBorder::Default,
        }
    }

    /// Set the modal dimensions (clamped to terminal size at render time).
    #[must_use]
    pub fn dimensions(mut self, width: u16, height: u16) -> Self {
        self.width = width;
        self.height = height;
        self
    }

    /// Compute the centered rect for this modal within `area` without rendering.
    #[must_use]
    pub fn rect(&self, area: Rect) -> Rect {
        Self::centered_rect(self.width, self.height, area)
    }

    /// Set the border style. Defaults to [`ModalBorder::Default`].
    #[must_use]
    pub fn border(mut self, border: ModalBorder) -> Self {
        self.border = border;
        self
    }

    /// Render the modal overlay.
    ///
    /// This performs the full pipeline:
    /// 1. Dims all existing buffer cells **outside** the modal rect (scrim)
    /// 2. Clears the modal area so the block background is opaque
    /// 3. Renders the border (depending on [`ModalBorder`] variant)
    /// 4. Calls `content_fn` with the inner content area
    pub fn render(
        self,
        frame: &mut Frame,
        palette: Palette,
        content_fn: impl FnOnce(&mut Frame, Rect),
    ) {
        let area = frame.area();
        let modal_rect = Self::centered_rect(self.width, self.height, area);

        // 1. Dimmed scrim
        apply_scrim(
            frame.buffer_mut(),
            area,
            modal_rect,
            dim_color(palette.bg),
            SCRIM_BG_FACTOR,
            SCRIM_FG_FACTOR,
        );

        // 2. Clear modal area so block bg fills every cell
        frame.render_widget(Clear, modal_rect);

        // 3. Render border and compute content area
        let title = format!(" {} ", self.title);
        let content_area = match &self.border {
            ModalBorder::None => {
                let block = Block::default()
                    .title(title.as_str())
                    .title_alignment(Alignment::Center)
                    .style(Style::new().bg(palette.panel));
                let inner = block.inner(modal_rect);
                frame.render_widget(block, modal_rect);
                inner
            }
            ModalBorder::Default
            | ModalBorder::Custom(_)
            | ModalBorder::Typed(_)
            | ModalBorder::TypedCustom(_, _) => {
                let border_type = match &self.border {
                    ModalBorder::Typed(bt) | ModalBorder::TypedCustom(bt, _) => *bt,
                    _ => BorderType::Plain,
                };
                let border_fg = match &self.border {
                    ModalBorder::Custom(c) | ModalBorder::TypedCustom(_, c) => *c,
                    _ => palette.border_hi,
                };
                let block = Block::bordered()
                    .title(title.as_str())
                    .title_alignment(Alignment::Center)
                    .border_type(border_type)
                    .border_style(Style::new().fg(border_fg))
                    .style(Style::new().bg(palette.panel));
                let inner = block.inner(modal_rect);
                frame.render_widget(block, modal_rect);
                inner
            }
            ModalBorder::Animated | ModalBorder::AnimatedCustom(_) => {
                let color = match &self.border {
                    ModalBorder::AnimatedCustom(c) => *c,
                    _ => palette.accent,
                };
                let block = Block::default()
                    .title(title.as_str())
                    .title_alignment(Alignment::Center)
                    .style(Style::new().bg(palette.panel));
                let inner = block.inner(modal_rect);
                frame.render_widget(block, modal_rect);
                AnimatedBorder::new(color).draw(frame.buffer_mut(), modal_rect);
                inner
            }
        };

        // 4. Caller's content
        content_fn(frame, content_area);
    }

    /// Compute a centered rect using `Layout` constraints (ratatui best practice).
    fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
        let w = width.min(area.width);
        let h = height.min(area.height);

        let [_, row, _] = Layout::vertical([
            Constraint::Length((area.height.saturating_sub(h)) / 2),
            Constraint::Length(h),
            Constraint::Length((area.height.saturating_sub(h)) / 2),
        ])
        .areas(area);

        let [_, center, _] = Layout::horizontal([
            Constraint::Length((area.width.saturating_sub(w)) / 2),
            Constraint::Length(w),
            Constraint::Length((area.width.saturating_sub(w)) / 2),
        ])
        .areas(row);

        center
    }
}

// ── Color blending helpers ─────────────────────────────────────────────────────

/// Darken an RGB color to ~1/3 brightness (scrim blend target).
fn dim_color(color: Color) -> Color {
    match color {
        Color::Rgb(r, g, b) => Color::Rgb(r / 3, g / 3, b / 3),
        other => other,
    }
}

/// Linearly interpolate `color` toward `target` by `t` (0.0 = unchanged, 1.0 = target).
fn blend_toward(color: Color, target: Color, t: f32) -> Color {
    let Color::Rgb(cr, cg, cb) = color else {
        return color;
    };
    let Color::Rgb(tr, tg, tb) = target else {
        return color;
    };
    #[expect(
        clippy::cast_lossless,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "u8→f32 for blending math; f32→u8 rounded value is in 0..=255"
    )]
    let r = (cr as f32 + (tr as f32 - cr as f32) * t).round() as u8;
    #[expect(
        clippy::cast_lossless,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "u8→f32 for blending math; f32→u8 rounded value is in 0..=255"
    )]
    let g = (cg as f32 + (tg as f32 - cg as f32) * t).round() as u8;
    #[expect(
        clippy::cast_lossless,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "u8→f32 for blending math; f32→u8 rounded value is in 0..=255"
    )]
    let b = (cb as f32 + (tb as f32 - cb as f32) * t).round() as u8;
    Color::Rgb(r, g, b)
}

/// Dim all cells in `buf` within `area` that fall **outside** `exclude`,
/// blending their bg/fg toward `target` by the given factors.
#[expect(
    clippy::cast_possible_truncation,
    reason = "buffer indices are bounded by terminal cols/rows < u16::MAX"
)]
fn apply_scrim(
    buf: &mut Buffer,
    area: Rect,
    exclude: Rect,
    target: Color,
    bg_factor: f32,
    fg_factor: f32,
) {
    let area_w = area.width as usize;
    for (i, cell) in buf.content.iter_mut().enumerate() {
        let x = area.x + (i % area_w) as u16;
        let y = area.y + (i / area_w) as u16;
        if x >= exclude.left() && x < exclude.right() && y >= exclude.top() && y < exclude.bottom()
        {
            continue;
        }
        cell.set_bg(blend_toward(cell.bg, target, bg_factor));
        cell.set_fg(blend_toward(cell.fg, target, fg_factor));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn centered_rect_fits_within_area() {
        let area = Rect::new(0, 0, 80, 24);
        let rect = Modal::centered_rect(52, 16, area);
        assert!(rect.width <= area.width);
        assert!(rect.height <= area.height);
        assert!(rect.x >= area.x);
        assert!(rect.y >= area.y);
    }

    #[test]
    fn centered_rect_clamps_to_area() {
        let area = Rect::new(0, 0, 30, 10);
        let rect = Modal::centered_rect(52, 16, area);
        assert_eq!(rect.width, 30);
        assert_eq!(rect.height, 10);
    }

    #[test]
    fn centered_rect_is_actually_centered() {
        let area = Rect::new(0, 0, 80, 24);
        let rect = Modal::centered_rect(40, 10, area);
        assert_eq!(
            (rect.x - area.x) + rect.width + (area.width - rect.x - rect.width),
            area.width - area.x
        );
    }

    #[test]
    fn dim_color_darkens_rgb() {
        let dimmed = dim_color(Color::Rgb(30, 20, 40));
        assert_eq!(dimmed, Color::Rgb(10, 6, 13));
    }

    #[test]
    fn dim_color_passes_through_non_rgb() {
        let color = Color::Red;
        assert_eq!(dim_color(color), color);
    }

    #[test]
    fn blend_toward_interpolates() {
        let from = Color::Rgb(100, 50, 0);
        let target = Color::Rgb(10, 6, 13);
        let result = blend_toward(from, target, 0.5);
        assert_eq!(result, Color::Rgb(55, 28, 7));
    }

    #[test]
    fn blend_toward_zero_is_unchanged() {
        let color = Color::Rgb(100, 200, 50);
        let target = Color::Rgb(10, 6, 13);
        assert_eq!(blend_toward(color, target, 0.0), color);
    }

    #[test]
    fn blend_toward_one_is_target() {
        let color = Color::Rgb(100, 200, 50);
        let target = Color::Rgb(10, 6, 13);
        assert_eq!(blend_toward(color, target, 1.0), target);
    }

    #[test]
    fn blend_toward_passes_through_non_rgb_color() {
        let color = Color::Red;
        let target = Color::Rgb(10, 6, 13);
        assert_eq!(blend_toward(color, target, 0.5), color);
    }

    #[test]
    fn blend_toward_passes_through_non_rgb_target() {
        let color = Color::Rgb(100, 200, 50);
        let target = Color::Red;
        assert_eq!(blend_toward(color, target, 0.5), color);
    }

    #[test]
    fn new_sets_defaults() {
        let modal = Modal::new("Test");
        assert_eq!(modal.title, "Test");
        assert_eq!(modal.width, DEFAULT_WIDTH);
        assert_eq!(modal.height, DEFAULT_HEIGHT);
    }

    #[test]
    fn dimensions_overrides_size() {
        let modal = Modal::new("Test").dimensions(40, 8);
        assert_eq!(modal.width, 40);
        assert_eq!(modal.height, 8);
    }

    #[test]
    fn border_builder_sets_variant() {
        let modal = Modal::new("Test").border(ModalBorder::None);
        assert!(matches!(modal.border, ModalBorder::None));

        let modal = Modal::new("Test").border(ModalBorder::Animated);
        assert!(matches!(modal.border, ModalBorder::Animated));

        let modal = Modal::new("Test").border(ModalBorder::Custom(Color::Red));
        assert!(matches!(modal.border, ModalBorder::Custom(Color::Red)));

        let modal = Modal::new("Test").border(ModalBorder::Typed(BorderType::Double));
        assert!(matches!(
            modal.border,
            ModalBorder::Typed(BorderType::Double)
        ));

        let modal = Modal::new("Test").border(ModalBorder::TypedCustom(
            BorderType::HeavyDoubleDashed,
            Color::Green,
        ));
        assert!(matches!(
            modal.border,
            ModalBorder::TypedCustom(BorderType::HeavyDoubleDashed, Color::Green)
        ));

        let modal = Modal::new("Test").border(ModalBorder::AnimatedCustom(Color::Cyan));
        assert!(matches!(
            modal.border,
            ModalBorder::AnimatedCustom(Color::Cyan)
        ));
    }

    #[test]
    fn default_border_is_default() {
        let modal = Modal::new("Test");
        assert!(matches!(modal.border, ModalBorder::Default));
    }
}
