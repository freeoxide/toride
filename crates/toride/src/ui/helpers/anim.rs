//! Reusable animation primitive for per-item float interpolation.
//!
//! [`AnimatedFloats`] tracks a list of `f32` values that animate toward target
//! values at a configurable speed, using linear step interpolation driven by
//! delta-time. Used by the sidebar highlight animation and any future widget
//! that needs smooth per-element fades.

use std::time::Instant;

/// A list of `f32` values that animate toward per-frame targets using
/// constant-speed linear interpolation.
///
/// Each call to [`tick`](Self::tick) advances every value toward its
/// corresponding target by a step proportional to elapsed time divided by the
/// configured duration.
pub struct AnimatedFloats {
    values: Vec<f32>,
    last_tick: Instant,
}

impl AnimatedFloats {
    /// Create `len` values all starting at `initial`.
    #[must_use]
    pub fn new(len: usize, initial: f32) -> Self {
        Self {
            values: vec![initial; len],
            last_tick: Instant::now(),
        }
    }

    /// Advance every value toward its corresponding `targets` entry.
    ///
    /// `duration_secs` controls the speed — a full 0-to-1 transition takes
    /// exactly `duration_secs` seconds of wall-clock time. Values that are
    /// already within one step of their target are snapped exactly.
    ///
    /// # Panics
    ///
    /// Panics if `targets.len() != self.values.len()`.
    pub fn tick(&mut self, targets: &[f32], duration_secs: f32) {
        assert_eq!(targets.len(), self.values.len(), "targets length mismatch");
        let now = Instant::now();
        let dt = now.duration_since(self.last_tick).as_secs_f32();
        self.last_tick = now;
        let step = (dt / duration_secs).min(1.0);
        for (i, &target) in targets.iter().enumerate() {
            let cur = self.values[i];
            let diff = target - cur;
            if diff.abs() <= step {
                self.values[i] = target;
            } else {
                self.values[i] = cur + step * diff.signum();
            }
        }
    }

    /// Snap every value exactly to its corresponding `targets` entry in one
    /// step (no interpolation). Used under reduced motion so a highlight lands
    /// on the selected item immediately on the single redraw a keypress
    /// triggers — otherwise the value would be frozen mid-transition.
    ///
    /// A render path must never panic on data, so a `targets` slice shorter
    /// than `self.values` is tolerated: each value is snapped to its matching
    /// target when one exists and left untouched otherwise (the mismatch is
    /// debug-logged). This matches [`tick`](Self::tick)'s per-index stepping
    /// rather than asserting equal length.
    pub fn snap_to_targets(&mut self, targets: &[f32]) {
        if targets.len() != self.values.len() {
            // Degrade gracefully instead of panicking inside a render path —
            // a transient length mismatch (e.g. a sidebar resized between
            // frames) must never crash the TUI.
            tracing::debug!(
                values = self.values.len(),
                targets = targets.len(),
                "AnimatedFloats::snap_to_targets: length mismatch; snapping only overlapping indices"
            );
        }
        for (i, slot) in self.values.iter_mut().enumerate() {
            if let Some(&target) = targets.get(i) {
                *slot = target;
            }
        }
        self.last_tick = Instant::now();
    }

    /// Get the current value at index `i`.
    #[must_use]
    pub fn get(&self, i: usize) -> f32 {
        self.values.get(i).copied().unwrap_or(0.0)
    }

    /// Directly set the value at index `i`.
    pub fn set(&mut self, i: usize, value: f32) {
        if i < self.values.len() {
            self.values[i] = value;
        }
    }

    /// Number of animated values.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Whether all values have settled within `eps` of their `targets`.
    ///
    /// Useful for `needs_animation()` — returns `true` when nothing left to animate.
    ///
    /// # Panics
    ///
    /// Panics if `targets.len() != self.values.len()`.
    #[must_use]
    pub fn is_settled(&self, targets: &[f32], eps: f32) -> bool {
        assert_eq!(targets.len(), self.values.len(), "targets length mismatch");
        self.values
            .iter()
            .zip(targets)
            .all(|(&cur, &target)| (cur - target).abs() <= eps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_initializes_all_values() {
        let af = AnimatedFloats::new(3, 0.5);
        assert_eq!(af.len(), 3);
        assert!((af.get(0) - 0.5).abs() < f32::EPSILON);
        assert!((af.get(1) - 0.5).abs() < f32::EPSILON);
        assert!((af.get(2) - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn set_updates_value() {
        let mut af = AnimatedFloats::new(3, 0.0);
        af.set(1, 1.0);
        assert!((af.get(1) - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn set_ignores_out_of_bounds() {
        let mut af = AnimatedFloats::new(2, 0.0);
        af.set(10, 1.0); // should not panic
    }

    #[test]
    fn get_returns_zero_for_out_of_bounds() {
        let af = AnimatedFloats::new(2, 0.5);
        assert!((af.get(99) - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn is_settled_when_at_targets() {
        let af = AnimatedFloats::new(3, 0.0);
        assert!(af.is_settled(&[0.0, 0.0, 0.0], 0.01));
    }

    #[test]
    fn is_not_settled_when_away_from_targets() {
        let mut af = AnimatedFloats::new(2, 0.0);
        af.set(0, 0.5);
        assert!(!af.is_settled(&[1.0, 0.0], 0.01));
    }

    #[test]
    fn tick_advances_toward_target() {
        let mut af = AnimatedFloats::new(1, 0.0);
        // Wait a tiny bit so dt > 0
        std::thread::sleep(std::time::Duration::from_millis(20));
        af.tick(&[1.0], 0.15);
        // Value should have moved toward 1.0 but not reached it
        let v = af.get(0);
        assert!(v > 0.0, "value should have moved: {v}");
        assert!(v < 1.0, "value should not have reached target in 20ms: {v}");
    }

    #[test]
    fn is_empty_when_len_zero() {
        let af = AnimatedFloats::new(0, 0.0);
        assert!(af.is_empty());
    }

    #[test]
    fn snap_to_targets_lands_immediately() {
        // Reduced-motion path: values must reach their targets in one step
        // (no lerp), so a highlight on a single redraw is correct, not mid-fade.
        let mut af = AnimatedFloats::new(3, 0.0);
        af.snap_to_targets(&[0.0, 1.0, 0.5]);
        assert!((af.get(0) - 0.0).abs() < f32::EPSILON);
        assert!((af.get(1) - 1.0).abs() < f32::EPSILON);
        assert!((af.get(2) - 0.5).abs() < f32::EPSILON);
        // And it reports settled against those targets.
        assert!(af.is_settled(&[0.0, 1.0, 0.5], 0.001));
    }

    #[test]
    fn snap_to_targets_tolerates_length_mismatch_without_panic() {
        // A render path must never panic on data: a targets slice shorter or
        // longer than the values must degrade gracefully (snap the overlap,
        // leave the rest untouched) rather than aborting the TUI.
        let mut af = AnimatedFloats::new(3, 0.2);
        // Shorter targets — index 2 has no target, must stay at its old value.
        af.snap_to_targets(&[0.0, 1.0]);
        assert!((af.get(0) - 0.0).abs() < f32::EPSILON);
        assert!((af.get(1) - 1.0).abs() < f32::EPSILON);
        assert!(
            (af.get(2) - 0.2).abs() < f32::EPSILON,
            "value with no target must be untouched"
        );

        // Longer targets — extras are simply ignored (no panic, no growth).
        af.snap_to_targets(&[0.5, 0.5, 0.5, 9.0, 9.0]);
        assert_eq!(af.len(), 3, "values vec must not grow");
        assert!((af.get(0) - 0.5).abs() < f32::EPSILON);
        assert!((af.get(1) - 0.5).abs() < f32::EPSILON);
        assert!((af.get(2) - 0.5).abs() < f32::EPSILON);
    }
}
