//! Application metadata sourced from `Cargo.toml` at compile time.
//!
//! Provides a single source of truth for the package name, version, and other
//! manifest values so they're available throughout the crate without repeating
//! `env!` macros in every file.

/// Package name from `Cargo.toml` (`toride`).
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// Package version from `Cargo.toml` (e.g. `"0.1.0"`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Package description from `Cargo.toml`, or `"unknown"` if not set.
pub const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

/// Edition string shown in the UI (application-level, not from Cargo).
pub const EDITION: &str = "SINGLE-HOST";

/// Returns a formatted `"name version"` string for display.
///
/// # Example
/// ```ignore
/// use crate::version;
/// assert_eq!(version::full(), "toride 0.1.0");
/// ```
pub fn full() -> String {
    format!("{NAME} {VERSION}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_toride() {
        assert_eq!(NAME, "toride");
    }

    #[test]
    fn version_is_not_empty() {
        assert_ne!(VERSION, "");
    }

    #[test]
    fn full_contains_name_and_version() {
        let f = full();
        assert!(f.starts_with(NAME));
        assert!(f.contains(VERSION));
    }

    #[test]
    fn edition_is_set() {
        assert_ne!(EDITION, "");
    }
}
