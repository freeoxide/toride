use std::collections::HashMap;

use crate::doctor::check::Check;

/// Registry of available diagnostic checks.
pub struct CheckRegistry {
    checks: HashMap<&'static str, Box<dyn Check>>,
}

impl CheckRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            checks: HashMap::new(),
        }
    }

    /// Register a check.
    pub fn register(&mut self, check: impl Check + 'static) {
        self.checks.insert(check.id(), Box::new(check));
    }

    /// Look up a check by ID.
    pub fn get(&self, id: &str) -> Option<&dyn Check> {
        self.checks.get(id).map(std::convert::AsRef::as_ref)
    }
}
