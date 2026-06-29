use ratatui::style::{Color, Style};
use ratatui::text::Line;

use crate::ui::theme::Palette;

// ── Line builders ────────────────────────────────────────────────────────────

/// Build an indented `label: value` [`Line`] with the label and value styled
/// independently.
pub fn kv_line(label: &str, value: &str, label_style: Style, value_style: Style) -> Line<'static> {
    Line::from(vec![
        ratatui::text::Span::raw("    "),
        ratatui::text::Span::styled(label.to_string(), label_style),
        ratatui::text::Span::raw(": "),
        ratatui::text::Span::styled(value.to_string(), value_style),
    ])
}

/// Like [`kv_line`], but the value takes a plain [`Color`] instead of a full
/// [`Style`].
pub fn color_kv_line(
    label: &str,
    value: &str,
    label_style: Style,
    value_color: Color,
) -> Line<'static> {
    Line::from(vec![
        ratatui::text::Span::raw("    "),
        ratatui::text::Span::styled(label.to_string(), label_style),
        ratatui::text::Span::raw(": "),
        ratatui::text::Span::styled(value.to_string(), Style::new().fg(value_color)),
    ])
}

/// Build a yes/no key-value line, colouring the value with the palette's
/// `ok` (yes) or `text_dim` (no) slot.
pub fn yn_kv_line(label: &str, value: bool, label_style: Style, p: Palette) -> Line<'static> {
    let (text, color) = if value {
        ("yes", p.ok)
    } else {
        ("no", p.text_dim)
    };
    color_kv_line(label, text, label_style, color)
}

/// Map a percentage to a semantic status colour: `err` at ≥90%, `warn` at
/// ≥70%, otherwise `ok`.
pub fn percent_color(pct: f64, p: Palette) -> Color {
    if pct >= 90.0 {
        p.err
    } else if pct >= 70.0 {
        p.warn
    } else {
        p.ok
    }
}

// ── Byte formatting ──────────────────────────────────────────────────────────

const KB: u64 = 1024;
const MB: u64 = KB * 1024;
const GB: u64 = MB * 1024;
const TB: u64 = GB * 1024;
const PB: u64 = TB * 1024;

#[expect(
    clippy::cast_precision_loss,
    reason = "u64→f64 for byte formatting display"
)]
/// Format a byte count into a human-readable binary-prefixed string
/// (e.g. `1.5 KiB`, `2.0 GiB`).
pub fn format_bytes(bytes: u64) -> String {
    if bytes >= PB {
        format!("{:.1} PiB", bytes as f64 / PB as f64)
    } else if bytes >= TB {
        format!("{:.1} TiB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1} GiB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MiB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KiB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Format a duration in seconds into a compact `d h m s` string, omitting
/// leading zero components except always showing seconds.
pub fn format_duration(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;

    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if hours > 0 || !parts.is_empty() {
        parts.push(format!("{hours}h"));
    }
    if minutes > 0 || !parts.is_empty() {
        parts.push(format!("{minutes}m"));
    }
    parts.push(format!("{seconds}s"));
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::theme::CHARM;

    // ── format_bytes ────────────────────────────────────────────────────────────

    #[test]
    fn format_bytes_zero() {
        assert_eq!(format_bytes(0), "0 B");
    }

    #[test]
    fn format_bytes_small() {
        assert_eq!(format_bytes(1), "1 B");
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn format_bytes_kibibyte() {
        assert_eq!(format_bytes(1024), "1.0 KiB");
    }

    #[test]
    fn format_bytes_mebibyte() {
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
    }

    #[test]
    fn format_bytes_gibibyte() {
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GiB");
    }

    #[test]
    fn format_bytes_tebibyte() {
        assert_eq!(format_bytes(1024_u64.pow(4)), "1.0 TiB");
    }

    #[test]
    fn format_bytes_pebibyte() {
        assert_eq!(format_bytes(1024_u64.pow(5)), "1.0 PiB");
    }

    #[test]
    fn format_bytes_fractional() {
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(2560), "2.5 KiB");
    }

    #[test]
    fn format_bytes_boundary_kib() {
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
    }

    #[test]
    fn format_bytes_boundary_mib() {
        let one_kib_short = 1024 * 1024 - 1;
        // 1023.9 KiB (approximately)
        let result = format_bytes(one_kib_short);
        assert!(
            result.contains("KiB"),
            "below 1 MiB should use KiB: {result}"
        );

        let result = format_bytes(1024 * 1024);
        assert_eq!(result, "1.0 MiB");
    }

    #[test]
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "test value is a known positive integer GiB count"
    )]
    fn format_bytes_large_value() {
        // 2.5 GiB
        let val = (2.5 * 1024.0 * 1024.0 * 1024.0) as u64;
        let result = format_bytes(val);
        assert!(result.contains("GiB"), "should use GiB: {result}");
    }

    // ── format_duration ─────────────────────────────────────────────────────────

    #[test]
    fn format_duration_zero() {
        assert_eq!(format_duration(0), "0s");
    }

    #[test]
    fn format_duration_one_second() {
        assert_eq!(format_duration(1), "1s");
    }

    #[test]
    fn format_duration_seconds_only() {
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(59), "59s");
    }

    #[test]
    fn format_duration_sixty_one_seconds() {
        assert_eq!(format_duration(61), "1m 1s");
    }

    #[test]
    fn format_duration_exactly_one_minute() {
        assert_eq!(format_duration(60), "1m 0s");
    }

    #[test]
    fn format_duration_minutes_and_seconds() {
        assert_eq!(format_duration(125), "2m 5s");
    }

    #[test]
    fn format_duration_exactly_one_hour() {
        assert_eq!(format_duration(3600), "1h 0m 0s");
    }

    #[test]
    fn format_duration_hours_minutes_seconds() {
        assert_eq!(format_duration(3661), "1h 1m 1s");
    }

    #[test]
    fn format_duration_exactly_one_day() {
        assert_eq!(format_duration(86400), "1d 0h 0m 0s");
    }

    #[test]
    fn format_duration_days_hours_minutes_seconds() {
        // 1 day, 1 hour, 1 minute, 1 second
        assert_eq!(format_duration(86400 + 3600 + 60 + 1), "1d 1h 1m 1s");
    }

    #[test]
    fn format_duration_complex() {
        // 1 day, 1 hour, 1 minute, 1 second = 90061
        assert_eq!(format_duration(90061), "1d 1h 1m 1s");
    }

    #[test]
    fn format_duration_large() {
        // 2 days, 3 hours, 4 minutes, 5 seconds
        let secs = 2 * 86400 + 3 * 3600 + 4 * 60 + 5;
        assert_eq!(format_duration(secs), "2d 3h 4m 5s");
    }

    // ── percent_color ───────────────────────────────────────────────────────────

    #[test]
    fn percent_color_low_is_ok() {
        assert_eq!(percent_color(50.0, CHARM), CHARM.ok);
    }

    #[test]
    fn percent_color_below_warning_threshold() {
        assert_eq!(percent_color(69.0, CHARM), CHARM.ok);
    }

    #[test]
    fn percent_color_warning_threshold() {
        // 70% is the boundary for warn
        assert_eq!(percent_color(70.0, CHARM), CHARM.warn);
    }

    #[test]
    fn percent_color_mid_warning() {
        assert_eq!(percent_color(80.0, CHARM), CHARM.warn);
    }

    #[test]
    fn percent_color_just_below_error() {
        assert_eq!(percent_color(89.9, CHARM), CHARM.warn);
    }

    #[test]
    fn percent_color_error_threshold() {
        assert_eq!(percent_color(90.0, CHARM), CHARM.err);
    }

    #[test]
    fn percent_color_high_is_error() {
        assert_eq!(percent_color(95.0, CHARM), CHARM.err);
    }

    #[test]
    fn percent_color_exact_boundaries() {
        // 69.9 -> ok
        assert_eq!(percent_color(69.9, CHARM), CHARM.ok);
        // 70.0 -> warn
        assert_eq!(percent_color(70.0, CHARM), CHARM.warn);
        // 89.9 -> warn
        assert_eq!(percent_color(89.9, CHARM), CHARM.warn);
        // 90.0 -> err
        assert_eq!(percent_color(90.0, CHARM), CHARM.err);
    }

    // ── kv_line / color_kv_line / yn_kv_line ────────────────────────────────────

    #[test]
    fn kv_line_has_label_colon_value() {
        let line = kv_line("Host", "box", Style::default(), Style::default());
        // kv_line produces: "    Host : box"
        let spans = &line.spans;
        assert_eq!(
            spans.len(),
            4,
            "kv_line should produce 4 spans (indent, label, sep, value)"
        );
    }

    #[test]
    fn color_kv_line_has_correct_span_count() {
        let line = color_kv_line("CPU", "50%", Style::default(), CHARM.warn);
        assert_eq!(line.spans.len(), 4);
    }

    #[test]
    fn yn_kv_line_true_uses_ok_color() {
        let line = yn_kv_line("Swap", true, Style::default(), CHARM);
        // Spans: [0]=indent, [1]=label, [2]=sep, [3]=value
        let value_span = &line.spans[3];
        assert_eq!(value_span.style.fg, Some(CHARM.ok));
    }

    #[test]
    fn yn_kv_line_false_uses_dim_color() {
        let line = yn_kv_line("Swap", false, Style::default(), CHARM);
        let value_span = &line.spans[3];
        assert_eq!(value_span.style.fg, Some(CHARM.text_dim));
    }
}
