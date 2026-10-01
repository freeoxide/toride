//! Shared base for full-screen views that need a gradient background.
//!
//! Extracts the boilerplate shared by `DashboardScreen` and `WelcomeScreen`:
//! gradient cache ownership, background rendering, cache invalidation, and the
//! "too small" terminal guard.

use ratatui::{Frame, buffer::Buffer, layout::Rect};

use crate::ui::responsive;
use crate::ui::theme::Palette;
use crate::ui::widgets::gradient::GradientCache;

/// Common infrastructure for screens that paint a radial gradient background.
pub struct ScreenBase {
    gradient_cache: GradientCache,
}

impl ScreenBase {
    /// Create a new base with a fresh gradient cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            gradient_cache: GradientCache::new(),
        }
    }

    /// Invalidate the cached gradient (call on theme change or resize).
    pub fn invalidate(&mut self) {
        self.gradient_cache.invalidate();
    }

    /// Render the gradient background unless `skip` is true.
    ///
    /// Pass `skip = true` during animated transitions where a transition
    /// gradient is painted instead.
    pub fn render_bg(&mut self, buf: &mut Buffer, area: Rect, p: Palette, skip: bool) {
        if !skip {
            self.gradient_cache.render_or_copy(buf, area, p);
        }
    }

    /// Check if the terminal is too small and render the fallback message.
    ///
    /// Returns `true` if the screen is too small (caller should return early).
    pub fn guard_too_small(frame: &mut Frame, p: Palette) -> bool {
        responsive::render_too_small(frame, p)
    }
}

impl Default for ScreenBase {
    fn default() -> Self {
        Self::new()
    }
}
