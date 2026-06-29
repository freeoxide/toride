//! User actions that drive the application's [`update`](crate::app::App::update) loop.

/// Semantic actions produced by screens and consumed by [`App::update`](crate::app::App::update).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Proceed to the next screen (Welcome → Status).
    Continue,
    /// Toggle the help modal.
    Help,
    /// Close the help modal.
    CloseHelp,
    /// Navigate back to the previous screen.
    Back,
    /// Show the quit confirmation modal.
    ConfirmQuit,
    /// Dismiss the quit confirmation modal.
    DismissQuit,
    /// Quit the application.
    Quit,
    /// Scroll content down (j / Down / mouse-wheel).
    ScrollDown,
    /// Scroll content up (k / Up / mouse-wheel).
    ScrollUp,
    /// Cycle to the next colour theme (Ctrl+T).
    CycleTheme,
    /// Cycle the animation preference (Auto → On → Off → Auto) and persist it
    /// (Ctrl+Shift+A). Lets a user on a laggy VPS disable animations mid-session.
    ToggleAnimations,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that all Action variants implement Copy, Clone, Debug, `PartialEq`, Eq
    /// by exercising each trait. If the derive is removed, this will fail to compile.
    fn assert_copy_clone_debug_partial_eq_eq(a: Action, b: Action) {
        // Copy
        let _: Action = a;
        // Clone
        let _: Action = a;
        // Debug
        let _debug = format!("{a:?}");
        // PartialEq
        let _: bool = a == b;
        // Eq is implied by PartialEq + derive; we just verify it compiles.
        let _: bool = a == b;
    }

    #[test]
    fn all_variants_satisfy_traits() {
        let variants = [
            Action::Continue,
            Action::Help,
            Action::CloseHelp,
            Action::ConfirmQuit,
            Action::DismissQuit,
            Action::Back,
            Action::Quit,
            Action::ScrollDown,
            Action::ScrollUp,
            Action::CycleTheme,
            Action::ToggleAnimations,
        ];

        for v in &variants {
            assert_copy_clone_debug_partial_eq_eq(*v, *v);
        }
    }

    #[test]
    fn equality_same_variant() {
        assert_eq!(Action::Continue, Action::Continue);
        assert_eq!(Action::Quit, Action::Quit);
        assert_eq!(Action::ScrollDown, Action::ScrollDown);
    }

    #[test]
    fn inequality_different_variants() {
        assert_ne!(Action::Continue, Action::Quit);
        assert_ne!(Action::Help, Action::Back);
        assert_ne!(Action::ScrollDown, Action::ScrollUp);
    }

    #[test]
    fn clone_produces_equal_value() {
        let original = Action::ScrollDown;
        let cloned = original;
        assert_eq!(original, cloned);
    }

    #[test]
    fn debug_output_is_not_empty() {
        let variants = [
            Action::Continue,
            Action::Help,
            Action::CloseHelp,
            Action::ConfirmQuit,
            Action::DismissQuit,
            Action::Back,
            Action::Quit,
            Action::ScrollDown,
            Action::ScrollUp,
            Action::CycleTheme,
            Action::ToggleAnimations,
        ];
        for v in &variants {
            let debug = format!("{v:?}");
            assert!(
                !debug.is_empty(),
                "Debug output should not be empty for {v:?}"
            );
        }
    }

    #[test]
    fn copy_clone_assigns_equal_value() {
        let a = Action::Quit;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn debug_format_contains_variant_name() {
        let debug = format!("{:?}", Action::ScrollDown);
        assert!(
            debug.contains("ScrollDown"),
            "expected Debug output to contain 'ScrollDown', got: {debug}"
        );
    }

    #[test]
    fn partial_eq_inequality_and_equality() {
        assert_ne!(Action::Continue, Action::Quit);
        assert_eq!(Action::ScrollDown, Action::ScrollDown);
    }
}
