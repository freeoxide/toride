//! Transition-aware view rendering.
//!
//! Handles the main render dispatch, screen transitions (animated gradient
//! swaps at the midpoint), per-screen cache invalidation, and the help modal
//! overlay.

use ratatui::Frame;
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
        // Bake the resolved `reduced_motion` decision into the palette each
        // frame. The palette already flows into every render path (screens,
        // shell components, modals), so carrying the flag here lets each
        // consumer neutralize its own animation with no extra parameter
        // threading. `p` is a borrowed local so all existing `*p` sites compile
        // unchanged.
        let mut p_owned = *self.active_theme.palette();
        p_owned.reduced_motion = self.reduced_motion;
        let p: &Palette = &p_owned;

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
        if self.help_modal.is_visible() {
            let viewport = Viewport::from_area(frame.area());
            self.help_modal.render(frame, *p, |frame, content_area| {
                HelpScreen::render(frame, content_area, *p, viewport);
            });
        }

        // Quit confirmation modal
        if self.quit_visible {
            self.quit_modal.render(frame, *p);
        }
    }

    /// Get a specific screen by its [`Screen`] enum value as `&mut dyn AppScreen`.
    ///
    /// This is needed during transitions where we must address a screen that
    /// may not be the *current* one.
    pub(super) fn screen_by_enum(
        &mut self,
        screen: Screen,
    ) -> &mut dyn crate::ui::screens::AppScreen {
        match screen {
            Screen::Welcome => &mut self.welcome,
            Screen::Dashboard => &mut self.dashboard,
        }
    }
}
