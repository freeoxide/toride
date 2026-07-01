//! Shared severity styling + findings-grouping helpers.
//!
//! Several content screens (fail2ban, toride_audit, toride_cloud, toride_proxy,
//! toride_backup, toride_users, toride_harden, toride_updates, toride_mise,
//! toride_monitor, toride_wireguard, toride_tailscale, ufw_kit) each render a
//! "Doctor Findings" block: a bold accent header, a grouped list sorted by
//! severity (each group gets a bold `ICON  SEVERITY (n)` header followed by the
//! indented title / detail / fix of every finding), and a `no findings` line
//! when the list is empty.
//!
//! The exact bytes are pinned by ~1560 insta snapshots, so this module exposes
//! a single generic renderer that reproduces the verbatim output each screen
//! previously produced in its private copy of the routine. Per-screen variation
//! (which severity buckets exist, the `(icon, color)` mapping, the title/detail
//! truncation widths, and which finding field supplies the title vs the detail)
//! is captured by [`SeverityStyler`], the `order` slice, [`FindingWidths`] and
//! the [`Finding`] trait implementation respectively.

use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use crate::ui::responsive::truncate_str;
use crate::ui::theme::Palette;

/// View onto a single finding for the grouped renderer.
///
/// Each finding-entry type implements this so the shared renderer can pull the
/// severity / title / detail / fix text without knowing the concrete struct.
/// Accessors return borrowed field views; the renderer truncates and styles.
pub trait Finding {
    /// Lowercase severity bucket this finding belongs to (e.g. `"critical"`).
    fn severity(&self) -> &str;

    /// Primary (title) line shown after the `· ` marker.
    fn title(&self) -> &str;

    /// Optional secondary line shown dimmed beneath the title.
    fn detail(&self) -> Option<&str>;

    /// Optional remediation line shown with a `→ ` accent marker.
    fn fix(&self) -> Option<&str>;
}

/// Truncation widths (in display columns) for the title and detail lines.
///
/// `fix` lines are always truncated to 70 columns to match every prior copy.
#[derive(Clone, Copy, Debug)]
pub struct FindingWidths {
    /// Max display width for the title line.
    pub title: usize,
    /// Max display width for the detail line.
    pub detail: usize,
}

impl FindingWidths {
    /// Title capped at 60, detail at 70 — the most common prior layout.
    pub const TITLE_60: Self = Self {
        title: 60,
        detail: 70,
    };

    /// Title capped at 70, detail at 70 — used by `message`-based findings.
    pub const TITLE_70: Self = Self {
        title: 70,
        detail: 70,
    };
}

/// Function mapping a lowercase severity bucket to an `(icon, color)` pair.
///
/// Screens with divergent mappings (e.g. an `"important"` bucket, or a
/// different colour for `"important"`) pass their own styler so the rendered
/// icons/colours stay byte-identical to the prior private copies.
pub type SeverityStyler = fn(&str, Palette) -> (&'static str, ratatui::style::Color);

/// Standard 5-bucket styler: `critical` / `error` / `warning` / `info` / `ok`.
///
/// Also used by screens whose private styler was a strict subset (e.g.
/// `toride_mise`, `toride_wireguard`, `toride_tailscale`): the extra arms never
/// fire because those screens' `order` slices only enumerate a subset of
/// buckets, so output stays byte-identical.
pub fn severity_style_full(sev: &str, p: Palette) -> (&'static str, ratatui::style::Color) {
    match sev {
        "critical" => ("⛔", p.err),
        "error" => ("✗", p.err),
        "warning" => ("!", p.warn),
        "info" => ("i", p.info),
        "ok" => ("✓", p.ok),
        _ => ("·", p.text_dim),
    }
}

/// Styler that additionally maps an `"important"` bucket to a red `!`
/// (`p.err`), used by `toride_harden` and `ufw_kit`.
pub fn severity_style_with_important_err(
    sev: &str,
    p: Palette,
) -> (&'static str, ratatui::style::Color) {
    match sev {
        "critical" => ("⛔", p.err),
        "important" => ("!", p.err),
        "error" => ("✗", p.err),
        "warning" => ("!", p.warn),
        "info" => ("i", p.info),
        "ok" => ("✓", p.ok),
        _ => ("·", p.text_dim),
    }
}

/// Styler that folds `"important"` into the `"warning"` bucket (`!` on
/// `p.warn`) and omits a standalone `"error"` arm, used by `toride_updates`.
pub fn severity_style_with_important_warn(
    sev: &str,
    p: Palette,
) -> (&'static str, ratatui::style::Color) {
    match sev {
        "critical" => ("⛔", p.err),
        "important" | "warning" => ("!", p.warn),
        "info" => ("i", p.info),
        "ok" => ("✓", p.ok),
        _ => ("·", p.text_dim),
    }
}

/// Severity-grouped "Doctor Findings" renderer.
///
/// Emits, in order:
/// 1. A bold accent header `Doctor Findings ({n})`.
/// 2. If empty, a single dimmed `  no findings` line and returns.
/// 3. For each severity in `order` (skipping empty buckets): a bold
///    `ICON  SEVERITY (count)` header, then for each finding the title line
///    `    · {title}`, an optional dimmed detail line, and an optional accent
///    `→ fix` line.
///
/// `styler` and `order` carry the per-screen severity variation; `widths`
/// carries the per-screen truncation widths. Output is byte-identical to the
/// prior inlined copies.
pub fn push_findings_grouped<F: Finding>(
    lines: &mut Vec<Line<'static>>,
    p: Palette,
    findings: &[F],
    order: &[&str],
    styler: SeverityStyler,
    widths: FindingWidths,
) {
    let header = format!("Doctor Findings ({})", findings.len());
    lines.push(Line::from(Span::styled(
        header,
        Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
    )));

    if findings.is_empty() {
        lines.push(Line::from(Span::styled(
            "  no findings",
            Style::new().fg(p.text_dim),
        )));
        return;
    }

    for sev in order {
        let group: Vec<&F> = findings.iter().filter(|f| f.severity() == *sev).collect();
        if group.is_empty() {
            continue;
        }
        let (icon, color) = styler(sev, p);
        lines.push(Line::from(vec![
            Span::styled(
                format!("{icon} "),
                Style::new().fg(color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{} ({})", sev.to_uppercase(), group.len()),
                Style::new().fg(color).add_modifier(Modifier::BOLD),
            ),
        ]));
        for f in group {
            let title = truncate_str(f.title(), widths.title);
            lines.push(Line::from(vec![
                Span::styled("    · ", Style::new().fg(p.text_dim)),
                Span::styled(title, Style::new().fg(p.text)),
            ]));
            if let Some(detail) = f.detail()
                && !detail.is_empty()
            {
                let detail = truncate_str(detail, widths.detail);
                lines.push(Line::from(Span::styled(
                    format!("      {detail}"),
                    Style::new().fg(p.text_dim),
                )));
            }
            if let Some(fix) = f.fix() {
                let fix = truncate_str(fix, 70);
                lines.push(Line::from(vec![
                    Span::styled("      → ", Style::new().fg(p.accent2)),
                    Span::styled(fix, Style::new().fg(p.accent2)),
                ]));
            }
        }
    }
}
