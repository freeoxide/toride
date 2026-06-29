//! Top header bar: logo, inline cpu/ram gauges, disk/net throughput (or spinner),
//! and a right-aligned clock.

use std::time::Instant;

use ratatui::{
    Frame,
    layout::{Position, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::ui::helpers::percent_color;
use crate::ui::theme::Palette;

/// Data needed to render the header bar.
pub struct HeaderData<'a> {
    /// CPU usage percentage (0–100), if known.
    pub cpu: Option<f64>,
    /// RAM usage percentage (0–100), if known.
    pub ram: Option<f64>,
    /// Disk I/O throughput label (e.g. `"50↓ 20↑ MB/s"`), if known.
    pub disk: Option<&'a str>,
    /// Network usage label (e.g. `"12 MB/s"`), if known.
    pub net: Option<&'a str>,
    /// Right-aligned clock label (e.g. `09:17 PM`).
    pub clock: &'a str,
    /// Timestamp used to drive the logo shimmer animation.
    pub shimmer_start: Instant,
}

/// Render the header bar into `area`.
pub fn render_header(frame: &mut Frame, area: Rect, p: Palette, data: &HeaderData) {
    let block = Block::default()
        .borders(Borders::TOP | Borders::BOTTOM)
        .border_style(Style::new().fg(p.border))
        .style(Style::new().bg(p.bg_alt));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let sep = Span::styled("   ·   ", Style::new().fg(p.text_muted));

    let mut left = vec![
        Span::styled(" 砦 ", Style::new().fg(p.accent).bold()),
        Span::styled("toride", Style::new().fg(p.accent).bold()),
        sep.clone(),
    ];
    left.extend(pct_gauge_spans("cpu", data.cpu, p));
    left.push(sep.clone());
    left.extend(pct_gauge_spans("ram", data.ram, p));

    let elapsed = data.shimmer_start.elapsed().as_secs_f32();

    left.push(sep.clone());
    if let Some(disk_label) = data.disk {
        left.extend(throughput_gauge_spans("disk", disk_label, p.accent3, p));
    } else {
        left.extend(spinner_gauge_spans("disk", elapsed, p));
    }

    left.push(sep);
    if let Some(net_label) = data.net {
        left.extend(throughput_gauge_spans("net", net_label, p.accent3, p));
    } else {
        left.extend(spinner_gauge_spans("net", elapsed, p));
    }

    frame.render_widget(Paragraph::new(Line::from(left)), inner);

    // Shimmer sweep across the logo (" 砦 toride" = 9 cells in header row 1).
    // Skipped under reduced motion (solid accent logo).
    if !p.reduced_motion {
        apply_logo_shimmer(frame.buffer_mut(), inner, elapsed);
    }

    let clock = Line::from(Span::styled(
        format!("{} ", data.clock),
        Style::new().fg(p.text_dim),
    ));
    frame.render_widget(Paragraph::new(clock).right_aligned(), inner);
}

/// Gaussian brightness sweep across the kanji + "toride" logo cells.
fn apply_logo_shimmer(buf: &mut ratatui::buffer::Buffer, inner: Rect, elapsed: f32) {
    use tachyonfx::ColorSpace;

    // " 砦 " (CJK width-2 → 4 cols) + "toride" (6 cols) = 10 columns
    const LOGO_W: u16 = 10;
    let logo_end = (inner.x + LOGO_W).min(inner.right());

    let sweep_period = 3.0f32;
    let sweep_pos = (elapsed % sweep_period) / sweep_period;
    let sigma = 0.06f32;

    for x in inner.x..logo_end {
        let cell = &mut buf[Position::new(x, inner.y)];
        if cell.symbol() == " " {
            continue;
        }

        let cell_norm = f32::from(x - inner.x) / f32::from(LOGO_W);
        let dist = cell_norm - sweep_pos;
        let brightness = (-dist * dist / (2.0 * sigma * sigma)).exp();

        if brightness > 0.01 {
            let fg = cell.fg;
            let lightened = ColorSpace::Hsl.lighten(&fg, brightness * 0.4);
            cell.set_fg(lightened);
        }
    }
}

/// Compute the hitbox [`Rect`] for each gauge span within the header's inner row.
///
/// Returns `[cpu_rect, ram_rect, disk_rect, net_rect]`. `data` must match the
/// data passed to [`render_header`] for the same frame so the widths are
/// consistent.
#[must_use]
pub fn gauge_hitboxes(area: Rect, data: &HeaderData) -> [Rect; 4] {
    let block = Block::default().borders(Borders::TOP | Borders::BOTTOM);
    let inner = block.inner(area);

    // Walk the same span layout as render_header to find x offsets.
    let mut x = inner.x;
    // " 砦 " (CJK width-2 = 4 cols) + "toride" (6 cols) + "   ·   " (7 cols)
    x += 4 + 6 + 7;

    let labels = ["cpu", "ram"];
    let pcts = [data.cpu, data.ram];
    let mut rects = [Rect::default(); 4];

    for (i, (&label, &pct)) in labels.iter().zip(pcts.iter()).enumerate() {
        let w = pct_gauge_width(label, pct);
        rects[i] = Rect::new(x, inner.y, w, 1);
        x += w;
        x += 7; // separator "   ·   "
    }

    // Disk gauge (index 2): spinner or throughput label.
    {
        let w = match data.disk {
            Some(label) => throughput_gauge_width("disk", label),
            None => spinner_gauge_width("disk"),
        };
        rects[2] = Rect::new(x, inner.y, w, 1);
        x += w;
        x += 7; // separator
    }

    // Net gauge (index 3): spinner or throughput label.
    if let Some(net_label) = data.net {
        let w = throughput_gauge_width("net", net_label);
        rects[3] = Rect::new(x, inner.y, w, 1);
    }

    rects
}

// ── Width helpers ──────────────────────────────────────────────────────────

/// Width of a throughput gauge: `"disk " + "▮ " + label`.
fn throughput_gauge_width(label: &str, value: &str) -> u16 {
    u16::try_from(label.len() + 1 + 2 + value.len()).unwrap_or(10)
}

/// Width of a spinner gauge: `"disk " + "▮ " + 1 spinner char`.
fn spinner_gauge_width(label: &str) -> u16 {
    u16::try_from(label.len() + 1 + 2 + 1).unwrap_or(10)
}

/// Width of a percentage gauge: `"cpu " + "▮ " + "35%"`.
fn pct_gauge_width(label: &str, pct: Option<f64>) -> u16 {
    let text = match pct {
        Some(v) => format!("{v:.0}%"),
        None => "—".to_string(),
    };
    throughput_gauge_width(label, &text)
}

// ── Span builders ─────────────────────────────────────────────────────────

/// Build the spans for a percentage-based inline gauge (`cpu ▮ 35%`).
fn pct_gauge_spans(label: &str, pct: Option<f64>, p: Palette) -> Vec<Span<'static>> {
    let (glyph_color, text): (Color, String) = match pct {
        Some(v) => (percent_color(v, p), format!("{v:.0}%")),
        None => (p.text_muted, "—".to_string()),
    };
    vec![
        Span::styled(format!("{label} "), Style::new().fg(p.text_dim)),
        Span::styled("▮ ", Style::new().fg(glyph_color)),
        Span::styled(text, Style::new().fg(p.text).bold()),
    ]
}

/// Build the spans for a throughput gauge (`disk ▮ 50↓ 20↑ MB/s`).
fn throughput_gauge_spans(
    label: &str,
    value: &str,
    color: Color,
    p: Palette,
) -> Vec<Span<'static>> {
    vec![
        Span::styled(format!("{label} "), Style::new().fg(p.text_dim)),
        Span::styled("▮ ", Style::new().fg(color)),
        Span::styled(value.to_string(), Style::new().fg(p.text).bold()),
    ]
}

/// Build the spans for a gauge that is still loading (animated braille spinner).
///
/// Under reduced motion the spinner frame is frozen to index 0 — the gauge
/// still signals "loading" (it only appears when data is pending) without
/// per-frame cycling.
fn spinner_gauge_spans(label: &str, elapsed: f32, p: Palette) -> Vec<Span<'static>> {
    use rattles::Rattle;
    use rattles::presets::braille::WaveRows;

    let frames = WaveRows::FRAMES;
    let interval_ms = u32::try_from(WaveRows::INTERVAL.as_millis()).unwrap_or(u32::MAX);
    let idx = if p.reduced_motion {
        0
    } else {
        // Display-only spinner animation index: the elapsed→u32 cast is fine
        // because negative/oversized values merely wrap through the frame ring.
        #[expect(
            clippy::cast_possible_truncation,
            reason = "display-only spinner index"
        )]
        #[expect(clippy::cast_sign_loss, reason = "elapsed is non-negative")]
        let elapsed_ms = (elapsed * 1000.0) as u32;
        elapsed_ms / interval_ms.max(1)
    };
    let frame = frames[idx as usize % frames.len()];
    // Take the first line of the frame for inline display.
    let text = frame.first().map_or("·", |s| *s);
    vec![
        Span::styled(format!("{label} "), Style::new().fg(p.text_dim)),
        Span::styled("▮ ", Style::new().fg(p.text_muted)),
        Span::styled(text.to_string(), Style::new().fg(p.text_dim)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::theme::CHARM;
    use ratatui::{Terminal, backend::TestBackend};

    fn render(data: &HeaderData) -> String {
        let mut terminal = Terminal::new(TestBackend::new(60, 3)).unwrap();
        terminal
            .draw(|f| render_header(f, f.area(), CHARM, data))
            .unwrap();
        terminal.backend().to_string()
    }

    fn header_data(
        cpu: Option<f64>,
        ram: Option<f64>,
        disk: Option<&'static str>,
        clock: &'static str,
    ) -> HeaderData<'static> {
        HeaderData {
            cpu,
            ram,
            disk,
            net: None,
            clock,
            shimmer_start: Instant::now(),
        }
    }

    #[test]
    fn renders_logo_and_clock() {
        let out = render(&header_data(
            Some(35.0),
            Some(23.0),
            Some("1.2↓ 0.5↑ MB"),
            "09:17 PM",
        ));
        assert!(out.contains("toride"), "logo: {out}");
        assert!(out.contains("09:17 PM"), "clock: {out}");
        assert!(out.contains("35%"), "cpu gauge: {out}");
    }

    #[test]
    fn renders_dash_when_unknown() {
        let out = render(&header_data(None, None, None, "--:--"));
        assert!(out.contains('—'), "expected em-dash placeholder: {out}");
    }

    #[test]
    fn spinner_freezes_to_first_frame_under_reduced_motion() {
        // The braille spinner's frame index normally advances with elapsed
        // time; under reduced motion it must pin to frame 0 and be
        // time-invariant (a static "loading" glyph, not cycling).
        use rattles::Rattle;
        use rattles::presets::braille::WaveRows;

        let reduced = CHARM.with_reduced_motion(true);
        let first_frame_char = WaveRows::FRAMES[0].first().map_or("·", |s| *s);

        // Reduced: time-invariant and pinned to frame 0.
        let zero = spinner_gauge_spans("disk", 0.0, reduced);
        let late = spinner_gauge_spans("disk", 999.0, reduced);
        assert_eq!(
            zero[2].content.as_ref(),
            late[2].content.as_ref(),
            "reduced-motion spinner must be time-invariant"
        );
        assert_eq!(
            late[2].content.as_ref(),
            first_frame_char,
            "reduced-motion spinner must pin to frame 0"
        );

        // Sanity: full motion DOES advance past frame 0 for some elapsed
        // (proves the freeze branch above is actually doing something).
        let full_advances = (1..2000).any(|ms| {
            #[expect(clippy::cast_precision_loss, reason = "display-only spinner elapsed")]
            let elapsed = ms as f32;
            let s = spinner_gauge_spans("disk", elapsed, CHARM);
            s[2].content.as_ref() != first_frame_char
        });
        assert!(
            full_advances,
            "full-motion spinner should advance past frame 0 for some elapsed"
        );
    }
}
