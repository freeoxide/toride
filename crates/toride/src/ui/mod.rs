/// Reusable interactive components (buttons, button rows).
pub mod components;
/// Small rendering and math helpers (color, format, animation).
pub mod helpers;
/// Responsive layout primitives (viewport breakpoints, truncation).
pub mod responsive;
/// The screen system: `AppScreen` trait and concrete screens.
pub mod screens;
/// Dashboard shell layout pieces (header, sidebar, footer).
pub mod shell;
/// Colour palette definitions and built-in themes.
pub mod theme;
/// Animated screen-transition state and cached gradient parameters.
pub mod transition;
/// Low-level ratatui widgets (modal, card, badge, inputs, etc.).
pub mod widgets;

// Re-export commonly used types for convenience
pub use components::InteractiveButton;
pub use screens::{AppScreen, DashboardScreen, HelpScreen, WelcomeScreen};
pub use theme::Palette;
pub use transition::{TransitionCache, TransitionState};
pub use widgets::{AnimatedBorder, GradientCache};
