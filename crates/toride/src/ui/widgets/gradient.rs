use std::time::Instant;

use ratatui::{
    buffer::Buffer,
    layout::{Position, Rect},
    style::Color,
};
use tachyonfx::{Interpolatable, color_from_hsl, color_to_hsl};

use crate::ui::helpers::color::{lerp_f64, to_rgb};
use crate::ui::theme::Palette;

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

    /// Draw the animated border into `buf` around `rect`, advancing the colour
    /// cycle by wall-clock `elapsed` since construction.
    pub fn draw(&self, buf: &mut Buffer, rect: Rect) {
        let elapsed = self.anim_start.elapsed().as_secs_f32();
        draw_animated_border(buf, rect, &self.color_cycle, elapsed);
    }

    /// Draw the border as a static single-colour outline (the base colour at
    /// cycle index 0). Used under reduced motion so the border stays visible
    /// without a per-frame colour flow.
    pub fn draw_static(&self, buf: &mut Buffer, rect: Rect) {
        draw_animated_border(buf, rect, &self.color_cycle, 0.0);
    }
}

// ── Gradient computation ───────────────────────────────────────────────────────

/// Core radial gradient computation shared by static and animated gradients.
///
/// Returns `Vec<Color>` for the area, blending from `base` (center) to `edge`
/// (perimeter) using a cubic falloff centred at `(cx, cy)`.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "color math: f64->u8 truncation is intentional for RGB blending"
)]
fn radial_gradient(
    area: Rect,
    base: (f64, f64, f64),
    edge: (f64, f64, f64),
    cx: f64,
    cy: f64,
) -> Vec<Color> {
    let max_dist = (cx - f64::from(area.left()))
        .hypot(cy - f64::from(area.top()))
        .max(1.0);

    let mut colors = Vec::with_capacity(area.width as usize * area.height as usize);
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            let dx = (f64::from(x) - cx).abs();
            let dy = (f64::from(y) - cy).abs();
            let t = (dx.hypot(dy) / max_dist).min(1.0).powi(3);
            let r = lerp_f64(base.0, edge.0, t) as u8;
            let g = lerp_f64(base.1, edge.1, t) as u8;
            let b = lerp_f64(base.2, edge.2, t) as u8;
            colors.push(Color::Rgb(r, g, b));
        }
    }
    colors
}

/// Compute the static gradient for caching. Uses a fixed centre and a static
/// edge colour at 60% of the base.
fn render_gradient_bg(colors: &mut Vec<Color>, area: Rect, p: Palette) {
    colors.clear();
    let (cr, cg, cb) = to_rgb(p.bg);
    let base = (f64::from(cr), f64::from(cg), f64::from(cb));
    let edge = (base.0 * 0.6, base.1 * 0.6, base.2 * 0.6);

    let cx = f64::from(u16::midpoint(area.left(), area.right()));
    let cy = f64::from(u16::midpoint(area.top(), area.bottom()));

    *colors = radial_gradient(area, base, edge, cx, cy);
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
pub fn build_color_cycle(base_color: Color) -> Vec<Color> {
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
    #[expect(clippy::cast_precision_loss, reason = "step counts are small (< 50)")]
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
    #[expect(
        clippy::cast_precision_loss,
        reason = "wrap_steps and i are always < 50"
    )]
    let wrap_f = wrap_steps as f32;
    #[expect(clippy::cast_precision_loss, reason = "wrap index i is always < 50")]
    for i in 1..wrap_steps {
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

    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "animation index from elapsed time"
    )]
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
pub fn render_transition_gradient(
    buf: &mut Buffer,
    area: Rect,
    p: Palette,
    center_offset: (f64, f64),
    edge_delta: f64,
    brightness_dip: f64,
    eased_progress: f32,
) {
    let (cr, cg, cb) = to_rgb(p.bg);

    // Apply brightness dip that peaks at mid-progress via a sin bell curve.
    let dip_factor =
        1.0 + brightness_dip * (std::f64::consts::PI * f64::from(eased_progress)).sin();
    let base_red = f64::from(cr) * dip_factor;
    let base_green = f64::from(cg) * dip_factor;
    let base_blue = f64::from(cb) * dip_factor;

    // Edge color modulated at midpoint.
    let edge_factor = 0.6 + edge_delta * (std::f64::consts::PI * f64::from(eased_progress)).sin();
    let er = base_red * edge_factor;
    let eg = base_green * edge_factor;
    let eb = base_blue * edge_factor;

    // Animated gradient center.
    let cx = f64::from(u16::midpoint(area.left(), area.right()))
        + center_offset.0 * f64::from(eased_progress) * f64::from(area.width);
    let cy = f64::from(u16::midpoint(area.top(), area.bottom()))
        + center_offset.1 * f64::from(eased_progress) * f64::from(area.height);

    let colors = radial_gradient(
        area,
        (base_red, base_green, base_blue),
        (er, eg, eb),
        cx,
        cy,
    );

    // Write directly to buffer.
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

// ── Tests ───────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use ratatui::buffer::Buffer;
    use ratatui::layout::Rect;
    use ratatui::style::Color;

    use super::*;
    use crate::ui::theme::CATPPUCCIN;

    // ── GradientCache ─────────────────────────────────────────────────────

    #[test]
    fn gradient_cache_new_has_no_cached_area() {
        // Fresh cache has no cached area, so render_or_copy must regenerate.
        let area = Rect::new(0, 0, 4, 2);
        let mut buf = Buffer::empty(area);
        let mut cache = GradientCache::new();

        cache.render_or_copy(&mut buf, area, CATPPUCCIN);

        // Every cell should have a non-default background colour.
        for cell in &buf.content {
            assert_ne!(
                cell.bg,
                Color::default(),
                "expected gradient background, got default"
            );
        }
    }

    #[test]
    fn gradient_cache_default_works() {
        // Default should behave identically to new() — no cached area.
        let area = Rect::new(0, 0, 2, 1);
        let mut buf = Buffer::empty(area);
        let mut cache = GradientCache::default();

        cache.render_or_copy(&mut buf, area, CATPPUCCIN);

        assert_ne!(
            buf.content[0].bg,
            Color::default(),
            "default cache should render gradient on first use"
        );
    }

    #[test]
    fn gradient_cache_invalidate_clears_cached_area() {
        use crate::ui::theme::NORD;

        let area = Rect::new(0, 0, 4, 1);
        let mut buf = Buffer::empty(area);
        let mut cache = GradientCache::new();

        // First render populates the cache.
        cache.render_or_copy(&mut buf, area, CATPPUCCIN);
        let first_bg = buf.content[0].bg;

        // Mutate the palette so a re-render would produce a different result.
        // We use a different palette with a distinct bg colour.

        // Without invalidation the cache should still serve the old colors.
        let mut buf2 = Buffer::empty(area);
        cache.render_or_copy(&mut buf2, area, NORD);
        assert_eq!(
            buf2.content[0].bg, first_bg,
            "cache hit should reuse old colours"
        );

        // Invalidate and re-render — now colours must come from the new palette.
        cache.invalidate();
        let mut buf3 = Buffer::empty(area);
        cache.render_or_copy(&mut buf3, area, NORD);

        // NORD and CATPPUCCIN have different bg colours, so the gradient
        // should differ after invalidation.
        assert_ne!(
            buf3.content[0].bg, first_bg,
            "invalidated cache should regenerate with new palette"
        );
    }

    // ── AnimatedBorder ────────────────────────────────────────────────────

    #[test]
    fn animated_border_new_creates_with_color() {
        let border = AnimatedBorder::new(Color::Rgb(100, 150, 200));

        // Drawing on a valid rect should populate corner characters without panic.
        let area = Rect::new(0, 0, 10, 5);
        let mut buf = Buffer::empty(area);

        border.draw(&mut buf, area);

        // Top-left corner should be set to box-drawing '┌'.
        let tl = buf.cell(ratatui::layout::Position::new(0, 0)).unwrap();
        assert_eq!(tl.symbol(), "┌", "top-left corner should be ┌");

        // Top-right corner.
        let tr = buf.cell(ratatui::layout::Position::new(9, 0)).unwrap();
        assert_eq!(tr.symbol(), "┐", "top-right corner should be ┐");

        // Bottom-right corner.
        let br = buf.cell(ratatui::layout::Position::new(9, 4)).unwrap();
        assert_eq!(br.symbol(), "┘", "bottom-right corner should be ┘");

        // Bottom-left corner.
        let bl = buf.cell(ratatui::layout::Position::new(0, 4)).unwrap();
        assert_eq!(bl.symbol(), "└", "bottom-left corner should be └");
    }

    #[test]
    fn animated_border_draw_too_small_is_noop() {
        let border = AnimatedBorder::new(Color::Rgb(50, 50, 50));
        let area = Rect::new(0, 0, 2, 2); // width < 3 and height < 3
        let mut buf = Buffer::empty(area);

        // Should not panic and should leave the buffer untouched.
        border.draw(&mut buf, area);

        for cell in &buf.content {
            assert_eq!(cell.symbol(), " ", "cells should remain default space");
        }
    }

    // ── to_rgb (via public gradient rendering) ────────────────────

    #[test]
    fn gradient_uses_rgb_from_palette_bg() {
        // If the palette bg is Rgb, the gradient should produce Rgb colours
        // (not default/reset). This indirectly validates to_rgb.
        let area = Rect::new(0, 0, 6, 3);
        let mut buf = Buffer::empty(area);
        let mut cache = GradientCache::new();

        cache.render_or_copy(&mut buf, area, CATPPUCCIN);

        for cell in &buf.content {
            assert!(
                matches!(cell.bg, Color::Rgb(_, _, _)),
                "gradient cells should have Rgb backgrounds, got {:?}",
                cell.bg
            );
        }
    }

    #[test]
    fn gradient_with_non_rgb_bg_produces_black_tones() {
        // When bg is not Rgb, to_rgb returns (0,0,0). The gradient
        // should still render without panic, producing Rgb(0..,0..,0..).
        let non_rgb_palette = crate::ui::theme::Palette {
            bg: Color::Black, // not Rgb
            ..CATPPUCCIN
        };
        let area = Rect::new(0, 0, 3, 1);
        let mut buf = Buffer::empty(area);
        let mut cache = GradientCache::new();

        cache.render_or_copy(&mut buf, area, non_rgb_palette);

        // All cells should still get an Rgb background.
        for cell in &buf.content {
            assert!(
                matches!(cell.bg, Color::Rgb(_, _, _)),
                "non-Rgb palette bg should still produce Rgb gradient, got {:?}",
                cell.bg
            );
        }
    }
}
