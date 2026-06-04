//! Shared color interpolation utilities.
//!
//! Provides a single source of truth for linear color blending, RGB extraction,
//! and dimming — replacing scattered private copies across widgets and shell modules.

use ratatui::style::Color;

/// Linearly interpolate between two colours (`t` clamped to `0..=1`).
///
/// Non-RGB inputs are treated as black `(0, 0, 0)`.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "blended channel is 0..=255 and fits in u8"
)]
pub fn lerp_color(a: Color, b: Color, t: f32) -> Color {
    let t = t.clamp(0.0, 1.0);
    let (ar, ag, ab) = to_rgb(a);
    let (br, bg, bb) = to_rgb(b);
    let mix = |x: u8, y: u8| (f32::from(x) + (f32::from(y) - f32::from(x)) * t).round() as u8;
    Color::Rgb(mix(ar, br), mix(ag, bg), mix(ab, bb))
}

/// Extract RGB channels from a [`Color`], defaulting non-RGB colours to black.
pub fn to_rgb(c: Color) -> (u8, u8, u8) {
    match c {
        Color::Rgb(r, g, b) => (r, g, b),
        _ => (0, 0, 0),
    }
}

/// Darken an RGB colour to ~1/3 brightness.
///
/// Non-RGB colours are passed through unchanged.
pub fn dim_color(color: Color) -> Color {
    match color {
        Color::Rgb(r, g, b) => Color::Rgb(r / 3, g / 3, b / 3),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lerp_color_halfway() {
        let a = Color::Rgb(0, 0, 0);
        let b = Color::Rgb(100, 200, 50);
        let result = lerp_color(a, b, 0.5);
        assert_eq!(result, Color::Rgb(50, 100, 25));
    }

    #[test]
    fn lerp_color_clamps_t() {
        let a = Color::Rgb(0, 0, 0);
        let b = Color::Rgb(100, 200, 50);
        assert_eq!(lerp_color(a, b, -1.0), a);
        assert_eq!(lerp_color(a, b, 2.0), b);
    }

    #[test]
    fn lerp_color_zero_is_a() {
        let a = Color::Rgb(10, 20, 30);
        let b = Color::Rgb(100, 200, 50);
        assert_eq!(lerp_color(a, b, 0.0), a);
    }

    #[test]
    fn lerp_color_one_is_b() {
        let a = Color::Rgb(10, 20, 30);
        let b = Color::Rgb(100, 200, 50);
        assert_eq!(lerp_color(a, b, 1.0), b);
    }

    #[test]
    fn to_rgb_extracts_rgb() {
        assert_eq!(to_rgb(Color::Rgb(10, 20, 30)), (10, 20, 30));
    }

    #[test]
    fn to_rgb_defaults_non_rgb() {
        assert_eq!(to_rgb(Color::Red), (0, 0, 0));
    }

    #[test]
    fn dim_color_darkens_rgb() {
        assert_eq!(dim_color(Color::Rgb(30, 20, 40)), Color::Rgb(10, 6, 13));
    }

    #[test]
    fn dim_color_passes_through_non_rgb() {
        assert_eq!(dim_color(Color::Red), Color::Red);
    }
}
