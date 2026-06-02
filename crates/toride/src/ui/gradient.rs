use std::time::Instant;

use ratatui::{
    buffer::Buffer,
    layout::{Position, Rect},
    style::Color,
};
use tachyonfx::{Interpolatable, color_from_hsl, color_to_hsl};

use super::theme::Palette;

// ── Gradient cache ─────────────────────────────────────────────────────────────

/// Caches gradient background colours keyed by area, avoiding recomputation
/// when the terminal size hasn't changed.
pub struct GradientCache {
    cached_area: Option<Rect>,
    colors: Vec<Color>,
}

impl GradientCache {
    /// Create an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cached_area: None,
            colors: Vec::new(),
        }
    }

    /// Invalidate the cache so the next render regenerates the gradient.
    pub fn invalidate(&mut self) {
        self.cached_area = None;
    }

    /// Render the gradient into the cache (if the area changed) and copy
    /// background colours to `buf`.
    pub fn render_or_copy(&mut self, buf: &mut Buffer, area: Rect, p: Palette) {
        let needs_regen = self.cached_area != Some(area);
        if needs_regen {
            render_gradient_bg(&mut self.colors, area, p);
            self.cached_area = Some(area);
        }
        copy_bg_to_buf(&self.colors, buf, area);
    }
}

impl Default for GradientCache {
    fn default() -> Self {
        Self::new()
    }
}

// ── Animated border ────────────────────────────────────────────────────────────

/// Animated color-cycling border that draws box-drawing characters around a
/// rect, with foreground colours flowing clockwise at ~12 cells/second.
///
/// Pure UI widget — no business logic coupling. Call [`AnimatedBorder::draw`]
/// once per frame with the target rect.
pub struct AnimatedBorder {
    color_cycle: Vec<Color>,
    anim_start: Instant,
}

impl AnimatedBorder {
    /// Create a new border that cycles from `base_color`.
    #[must_use]
    pub fn new(base_color: Color) -> Self {
        Self {
            color_cycle: build_color_cycle(base_color),
            anim_start: Instant::now(),
        }
    }

    /// Draw the animated border into `buf` around `rect`.
    pub fn draw(&self, buf: &mut Buffer, rect: Rect) {
        let elapsed = self.anim_start.elapsed().as_secs_f32();
        draw_animated_border(buf, rect, &self.color_cycle, elapsed);
    }
}

// ── Gradient computation ───────────────────────────────────────────────────────

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    reason = "color math: f64->u8 truncation is intentional for RGB blending"
)]
fn render_gradient_bg(colors: &mut Vec<Color>, area: Rect, p: Palette) {
    colors.clear();
    let (cr, cg, cb) = rgb_components(p.bg);
    let er = (f64::from(cr) * 0.6) as u8;
    let eg = (f64::from(cg) * 0.6) as u8;
    let eb = (f64::from(cb) * 0.6) as u8;

    let cx = u16::midpoint(area.left(), area.right());
    let cy = u16::midpoint(area.top(), area.bottom());
    let max_dist = ((f64::from(cx.saturating_sub(area.left())))
        .hypot(f64::from(cy.saturating_sub(area.top()))))
    .max(1.0);

    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            let dx = f64::from(i32::from(x).abs_diff(i32::from(cx)));
            let dy = f64::from(i32::from(y).abs_diff(i32::from(cy)));
            let t = (dx.hypot(dy) / max_dist).min(1.0).powi(3);
            let r = lerp(f64::from(cr), f64::from(er), t) as u8;
            let g = lerp(f64::from(cg), f64::from(eg), t) as u8;
            let b = lerp(f64::from(cb), f64::from(eb), t) as u8;
            colors.push(Color::Rgb(r, g, b));
        }
    }
}

/// Copy cached background colours directly to the frame buffer, using direct
/// indexing to avoid the double bounds check of `cell()` / `cell_mut()`.
fn copy_bg_to_buf(colors: &[Color], buf: &mut Buffer, area: Rect) {
    let mut i = 0usize;
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            if i < colors.len() {
                buf[Position::new(x, y)].set_bg(colors[i]);
            }
            i += 1;
        }
    }
}

// ── Animated border internals ──────────────────────────────────────────────────

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

// ── Transition gradient ─────────────────────────────────────────────────────────

/// Render a radial gradient directly into the frame buffer with animated
/// parameters for transitions. Unlike `render_gradient_bg`, this bypasses the
/// `GradientCache` and writes straight to `buf` every frame.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    reason = "color math: f64->u8 truncation is intentional for RGB blending"
)]
pub fn render_transition_gradient(
    buf: &mut Buffer,
    area: Rect,
    p: Palette,
    center_offset: (f64, f64),
    edge_delta: f64,
    brightness_dip: f64,
    eased_progress: f32,
) {
    let (cr, cg, cb) = rgb_components(p.bg);

    // Apply brightness dip that peaks at mid-progress via a sin bell curve.
    let dip_factor = 1.0 + brightness_dip * (std::f64::consts::PI * eased_progress as f64).sin();
    let base_red = f64::from(cr) * dip_factor;
    let base_green = f64::from(cg) * dip_factor;
    let base_blue = f64::from(cb) * dip_factor;

    // Edge color modulated at midpoint.
    let edge_factor = 0.6 + edge_delta * (std::f64::consts::PI * eased_progress as f64).sin();
    let er = base_red * edge_factor;
    let eg = base_green * edge_factor;
    let eb = base_blue * edge_factor;

    // Animated gradient center.
    let cx = f64::from(u16::midpoint(area.left(), area.right()))
        + center_offset.0 * eased_progress as f64 * f64::from(area.width);
    let cy = f64::from(u16::midpoint(area.top(), area.bottom()))
        + center_offset.1 * eased_progress as f64 * f64::from(area.height);

    let max_dist = (cx - f64::from(area.left()))
        .hypot(cy - f64::from(area.top()))
        .max(1.0);

    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            let dx = (f64::from(x) - cx).abs();
            let dy = (f64::from(y) - cy).abs();
            let t = (dx.hypot(dy) / max_dist).min(1.0).powi(3);
            let r = lerp(base_red, er, t) as u8;
            let g = lerp(base_green, eg, t) as u8;
            let b = lerp(base_blue, eb, t) as u8;
            buf[Position::new(x, y)].set_bg(Color::Rgb(r, g, b));
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

fn rgb_components(color: Color) -> (u8, u8, u8) {
    match color {
        Color::Rgb(r, g, b) => (r, g, b),
        _ => (0, 0, 0),
    }
}

fn lerp(a: f64, b: f64, t: f64) -> f64 {
    a * (1.0 - t) + b * t
}
