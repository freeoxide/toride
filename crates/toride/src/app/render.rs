//! Transition-aware view rendering.
//!
//! Handles the main render dispatch, screen transitions (animated gradient
//! swaps at the midpoint), per-screen cache invalidation, and the help modal
//! overlay.

use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    widgets::{Block, Clear},
};
use tachyonfx::Interpolation;

use crate::navigation::Screen;
use crate::ui::responsive::Viewport;
use crate::ui::screens::help::HelpScreen;
use crate::ui::theme::Palette;

use super::App;

impl App {
    /// Main render method. Handles transition rendering and delegates to the
    /// active screen's `view()`.
    pub(super) fn view(&mut self, frame: &mut Frame) {
        let p = self.active_theme.palette();

        if let Some(ts) = self.transition.take() {
            let raw_progress = ts.progress();
            let eased = Interpolation::CubicInOut.alpha(raw_progress);

            // Determine which screen to show foreground for
            let show_to = if ts.reverse {
                raw_progress > 0.5
            } else {
                raw_progress >= 0.5
            };

            // Render transition gradient
            let area = frame.area();
            #[expect(
                clippy::cast_lossless,
                reason = "eased is f32 from tachyonfx, offset needs f64"
            )]
            let offset = if ts.reverse {
                (
                    ts.params.center_offset.0 * (1.0 - eased as f64),
                    ts.params.center_offset.1 * (1.0 - eased as f64),
                )
            } else {
                (
                    ts.params.center_offset.0 * eased as f64,
                    ts.params.center_offset.1 * eased as f64,
                )
            };
            crate::ui::widgets::gradient::render_transition_gradient(
                frame.buffer_mut(),
                area,
                *p,
                offset,
                ts.params.edge_delta,
                ts.params.brightness_dip,
                eased,
            );

            // Render foreground of appropriate screen
            if show_to {
                let to_screen = Screen::from_key(ts.to);
                self.screen_by_enum(to_screen).view_foreground(frame, *p);
            } else {
                self.current_screen().view_foreground(frame, *p);
            }

            // Check completion — reconstitute transition only if not done
            if ts.is_done() {
                let to_screen = Screen::from_key(ts.to);
                if ts.reverse {
                    self.nav.commit_back(to_screen);
                } else {
                    self.nav.commit_forward(to_screen);
                }
                self.screen_by_enum(to_screen).invalidate_cache();
                self.transition = None;
            } else {
                self.transition = Some(ts);
            }
        } else {
            self.current_screen().view(frame, *p);
        }

        // Help modal overlay — rendered on top of whatever is behind it
        if self.help_visible {
            Self::render_help_modal(frame, *p);
        }
    }

    /// Render the help modal overlay (dimmed scrim + bordered content box).
    fn render_help_modal(frame: &mut Frame, p: Palette) {
        let area = frame.area();
        let viewport = Viewport::from_area(area);

        // 1. Dimmed scrim over the entire area
        let dimmed_bg = dim_color(p.bg);
        frame.render_widget(Clear, area);
        frame.render_widget(
            Block::default().style(Style::new().bg(dimmed_bg)),
            area,
        );

        // 2. Centered modal box
        let modal_area = modal_area(area);
        let block = Block::bordered()
            .border_style(Style::new().fg(p.border_hi))
            .style(Style::new().bg(p.panel));
        let content_area = block.inner(modal_area);
        frame.render_widget(block, modal_area);

        // 3. Help content inside the border
        HelpScreen::render(frame, content_area, p, viewport);
    }

    /// Get a specific screen by its [`Screen`] enum value as `&mut dyn AppScreen`.
    ///
    /// This is needed during transitions where we must address a screen that
    /// may not be the *current* one.
    fn screen_by_enum(&mut self, screen: Screen) -> &mut dyn crate::ui::screens::AppScreen {
        match screen {
            Screen::Welcome => &mut self.welcome,
            Screen::Status => &mut self.status,
        }
    }
}

// ── Modal helpers ─────────────────────────────────────────────────────────────

/// Compute a centered modal rect (~52×16), clamped to terminal size.
fn modal_area(area: Rect) -> Rect {
    const MODAL_W: u16 = 52;
    const MODAL_H: u16 = 16;
    let w = MODAL_W.min(area.width);
    let h = MODAL_H.min(area.height);
    let x = (area.width.saturating_sub(w)) / 2;
    let y = (area.height.saturating_sub(h)) / 2;
    Rect::new(area.x + x, area.y + y, w, h)
}

/// Darken an RGB color to ~1/3 brightness for the scrim effect.
fn dim_color(color: ratatui::style::Color) -> ratatui::style::Color {
    match color {
        ratatui::style::Color::Rgb(r, g, b) => ratatui::style::Color::Rgb(r / 3, g / 3, b / 3),
        other => other,
    }
}
