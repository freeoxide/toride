//! Registry that stores and looks up diagnostic checks by ID.
//!
//! Provides [`CheckRegistry`], a `HashMap`-backed collection of
//! `Box<dyn Check>` entries keyed by their [`Check::id`](super::check::Check::id).
//! Used by [`DoctorService`](super::DoctorService) to discover and execute
//! all registered checks.

use std::collections::HashMap;

use crate::doctor::check::Check;

/// Registry of available diagnostic checks.
///
/// Checks are keyed by their [`id()`](Check::id) and can be looked up
/// or iterated. The registry owns the checks via `Box<dyn Check>`.
#[derive(Default)]
pub struct CheckRegistry {
    checks: HashMap<&'static str, Box<dyn Check>>,
}

impl CheckRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a check.
    ///
    /// If a check with the same [`id()`](Check::id) already exists, it is
    /// replaced.
    pub fn register(&mut self, check: impl Check + 'static) {
        self.checks.insert(check.id(), Box::new(check));
    }

    /// Look up a check by ID.
    ///
    /// Returns `None` if no check with the given ID is registered.
    pub fn get(&self, id: &str) -> Option<&dyn Check> {
        self.checks.get(id).map(std::convert::AsRef::as_ref)
    }
}
