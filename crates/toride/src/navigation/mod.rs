//! Screen routing and navigation back-stack.
//!
//! [`Navigator`] owns the current screen and navigation history, providing
//! forward and backward navigation with animated transitions.

use crate::ui::transition::{TransitionCache, TransitionState};

// ── Screen enum ─────────────────────────────────────────────────────────────

/// Identifies a screen in the application.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum Screen {
    /// Welcome / splash screen.
    #[default]
    Welcome = 0,
    /// Main dashboard (modules, updates, activity).
    Dashboard = 1,
}

impl Screen {
    /// Compact numeric key used by [`TransitionCache`].
    pub(crate) fn key(self) -> u8 {
        self as u8
    }

    /// Convert a numeric key back to a [`Screen`].
    ///
    /// Returns [`Screen::Welcome`] for unknown keys.
    #[expect(clippy::match_same_arms, reason = "fallback for unknown screen keys")]
    pub(crate) fn from_key(key: u8) -> Self {
        match key {
            0 => Screen::Welcome,
            1 => Screen::Dashboard,
            _ => Screen::Welcome,
        }
    }
}

// ── Navigator ───────────────────────────────────────────────────────────────

/// Manages the current screen and navigation back-stack.
pub struct Navigator {
    screen: Screen,
    nav_stack: Vec<Screen>,
}

impl Navigator {
    /// Create a navigator starting at the welcome screen.
    #[must_use]
    pub fn new() -> Self {
        Self {
            screen: Screen::Welcome,
            nav_stack: vec![Screen::Welcome],
        }
    }

    /// Current active screen.
    pub fn current(&self) -> Screen {
        self.screen
    }

    /// Whether the navigator can go back (more than one entry in the stack).
    pub fn can_go_back(&self) -> bool {
        self.nav_stack.len() > 1
    }

    /// Begin a forward navigation to `target`.
    ///
    /// Returns a [`TransitionState`] for the animated transition.
    /// Call [`commit_forward`](Self::commit_forward) when the transition completes.
    pub fn start_forward(&self, target: Screen, cache: &mut TransitionCache) -> TransitionState {
        TransitionState::new(self.screen.key(), target.key(), cache, false)
    }

    /// Begin a backward navigation.
    ///
    /// Returns `None` if there is nowhere to go back to.
    /// Call [`commit_back`](Self::commit_back) when the transition completes.
    pub fn start_backward(&mut self, cache: &mut TransitionCache) -> Option<TransitionState> {
        if self.nav_stack.len() <= 1 {
            return None;
        }
        let from = self.screen;
        // Pop the current screen now so the stack is ready when transition completes
        self.nav_stack.pop();
        let &target = self.nav_stack.last()?;
        Some(TransitionState::new(from.key(), target.key(), cache, true))
    }

    /// Finalize a completed forward transition.
    pub fn commit_forward(&mut self, target: Screen) {
        self.screen = target;
        self.nav_stack.push(target);
    }

    /// Finalize a completed backward transition.
    pub fn commit_back(&mut self, target: Screen) {
        self.screen = target;
        // Stack was already popped in start_backward
    }
}

impl Default for Navigator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Screen enum ─────────────────────────────────────────────────────────────

    #[test]
    fn screen_key_values() {
        assert_eq!(Screen::Welcome.key(), 0);
        assert_eq!(Screen::Dashboard.key(), 1);
    }

    #[test]
    fn screen_from_key_roundtrip() {
        for screen in [Screen::Welcome, Screen::Dashboard] {
            assert_eq!(Screen::from_key(screen.key()), screen);
        }
    }

    #[test]
    fn screen_from_key_unknown_falls_back_to_welcome() {
        assert_eq!(Screen::from_key(255), Screen::Welcome);
        assert_eq!(Screen::from_key(3), Screen::Welcome);
        assert_eq!(Screen::from_key(99), Screen::Welcome);
    }

    #[test]
    fn screen_default_is_welcome() {
        assert_eq!(Screen::default(), Screen::Welcome);
    }

    // ── Navigator ───────────────────────────────────────────────────────────────

    #[test]
    fn navigator_new_starts_at_welcome() {
        let nav = Navigator::new();
        assert_eq!(nav.current(), Screen::Welcome);
    }

    #[test]
    fn navigator_new_cannot_go_back() {
        let nav = Navigator::new();
        assert!(!nav.can_go_back());
    }

    #[test]
    fn navigator_forward_navigation() {
        let mut nav = Navigator::new();
        let mut cache = TransitionCache::new();

        // Navigate Welcome -> Status
        let _ts = nav.start_forward(Screen::Dashboard, &mut cache);
        nav.commit_forward(Screen::Dashboard);
        assert_eq!(nav.current(), Screen::Dashboard);
        assert!(nav.can_go_back());
    }

    #[test]
    fn navigator_forward_then_back() {
        let mut nav = Navigator::new();
        let mut cache = TransitionCache::new();

        // Forward: Welcome -> Status
        nav.commit_forward(Screen::Dashboard);

        // Back: Status -> Welcome
        let ts = nav.start_backward(&mut cache);
        assert!(ts.is_some());
        let ts = ts.unwrap();
        nav.commit_back(Screen::from_key(ts.to));
        assert_eq!(nav.current(), Screen::Welcome);
        assert!(!nav.can_go_back());
    }

    #[test]
    fn navigator_multi_step_forward_and_back() {
        let mut nav = Navigator::new();
        let mut cache = TransitionCache::new();

        // Welcome -> Status
        let _ts = nav.start_forward(Screen::Dashboard, &mut cache);
        nav.commit_forward(Screen::Dashboard);
        assert_eq!(nav.current(), Screen::Dashboard);
        assert!(nav.can_go_back());

        // Back: Status -> Welcome
        let ts = nav.start_backward(&mut cache).unwrap();
        nav.commit_back(Screen::from_key(ts.to));
        assert_eq!(nav.current(), Screen::Welcome);
        assert!(!nav.can_go_back());
    }

    #[test]
    fn navigator_backward_when_cannot_go_back_returns_none() {
        let mut nav = Navigator::new();
        let mut cache = TransitionCache::new();
        assert!(nav.start_backward(&mut cache).is_none());
    }

    #[test]
    fn navigator_default_matches_new() {
        let nav_new = Navigator::new();
        let nav_default = Navigator::default();
        assert_eq!(nav_new.current(), nav_default.current());
    }

    // ── Additional tests ────────────────────────────────────────────────────────

    #[test]
    fn screen_derives_default_and_equals_welcome() {
        // Verify Screen derives Default and default() returns Welcome.
        let default_screen: Screen = Screen::default();
        assert_eq!(default_screen, Screen::Welcome);
        // Also confirm explicit #[default] annotation via Clone/Copy/PartialEq.
        let welcome = Screen::Welcome;
        assert_eq!(default_screen, welcome);
    }

    #[test]
    fn navigator_complex_navigation_welcome_status_back() {
        let mut nav = Navigator::new();
        let mut cache = TransitionCache::new();

        // Welcome -> Status
        let _ts = nav.start_forward(Screen::Dashboard, &mut cache);
        nav.commit_forward(Screen::Dashboard);
        assert_eq!(nav.current(), Screen::Dashboard);
        assert!(nav.can_go_back());
        assert_eq!(nav.nav_stack.len(), 2);

        // Back: Status -> Welcome
        let ts = nav.start_backward(&mut cache).unwrap();
        nav.commit_back(Screen::from_key(ts.to));
        assert_eq!(nav.current(), Screen::Welcome);
        assert!(!nav.can_go_back());
        assert_eq!(nav.nav_stack.len(), 1);
    }

    #[test]
    fn navigator_commit_forward_multiple_times() {
        let mut nav = Navigator::new();
        let mut cache = TransitionCache::new();

        // Commit forward: Welcome -> Status
        let _ts = nav.start_forward(Screen::Dashboard, &mut cache);
        nav.commit_forward(Screen::Dashboard);
        assert_eq!(nav.current(), Screen::Dashboard);

        // Commit forward: Status -> Welcome
        let _ts = nav.start_forward(Screen::Welcome, &mut cache);
        nav.commit_forward(Screen::Welcome);
        assert_eq!(nav.current(), Screen::Welcome);

        // After 2 forward commits starting from new, stack has 3 entries.
        assert_eq!(nav.nav_stack.len(), 3);
        assert!(nav.can_go_back());
    }

    #[test]
    fn navigator_nav_stack_length_after_various_operations() {
        let mut nav = Navigator::new();
        let mut cache = TransitionCache::new();

        // Initial state: stack has 1 entry [Welcome]
        assert_eq!(nav.nav_stack.len(), 1);

        // After 1 forward: stack has 2 entries [Welcome, Status]
        nav.commit_forward(Screen::Dashboard);
        assert_eq!(nav.nav_stack.len(), 2);

        // After 1 back: stack has 1 entry [Welcome]
        let ts = nav.start_backward(&mut cache).unwrap();
        nav.commit_back(Screen::from_key(ts.to));
        assert_eq!(nav.nav_stack.len(), 1);

        // After another forward: stack has 2 entries [Welcome, Status]
        let _ts = nav.start_forward(Screen::Dashboard, &mut cache);
        nav.commit_forward(Screen::Dashboard);
        assert_eq!(nav.nav_stack.len(), 2);

        // Cannot go back further after one back
        let ts = nav.start_backward(&mut cache).unwrap();
        nav.commit_back(Screen::from_key(ts.to));
        assert!(nav.start_backward(&mut cache).is_none());
        assert_eq!(nav.nav_stack.len(), 1);
    }
}
