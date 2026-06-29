//! Field validation for form inputs.
//!
//! Provides a [`Validator`] trait and built-in validators for common checks
//! (required, min/max length, port numbers, hostnames). Inspired by
//! `ratatui-form`'s validation module but integrated with our `Palette` theme.

/// A validation error produced by a failed check.
#[derive(Debug, Clone)]
pub struct ValidationError {
    /// Human-readable error message shown below the field.
    pub message: String,
}

impl ValidationError {
    /// Create a new validation error with the given message.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Trait for field validators.
///
/// Implementors check a field's string value and return `Some(ValidationError)`
/// if the value is invalid, or `None` if it passes.
pub trait Validator: std::fmt::Debug + Send + Sync {
    /// Validate the given value. Returns `None` if valid.
    fn validate(&self, value: &str) -> Option<ValidationError>;
}

// ── Built-in validators ───────────────────────────────────────────────────────

/// Rejects empty (whitespace-only) values.
#[derive(Debug, Clone)]
pub struct Required;

impl Validator for Required {
    fn validate(&self, value: &str) -> Option<ValidationError> {
        if value.trim().is_empty() {
            Some(ValidationError::new("This field is required"))
        } else {
            None
        }
    }
}

/// Rejects values shorter than the minimum length.
#[derive(Debug, Clone)]
pub struct MinLength(pub usize);

impl Validator for MinLength {
    fn validate(&self, value: &str) -> Option<ValidationError> {
        if value.len() < self.0 {
            Some(ValidationError::new(format!(
                "Must be at least {} characters",
                self.0
            )))
        } else {
            None
        }
    }
}

/// Rejects values longer than the maximum length.
#[derive(Debug, Clone)]
pub struct MaxLength(pub usize);

impl Validator for MaxLength {
    fn validate(&self, value: &str) -> Option<ValidationError> {
        if value.len() > self.0 {
            Some(ValidationError::new(format!(
                "Must be at most {} characters",
                self.0
            )))
        } else {
            None
        }
    }
}

/// Validates that the value is a valid TCP/UDP port number (1–65535) or empty.
///
/// Empty values are allowed (port is typically optional). Use `Required` alongside
/// this validator if the port must be provided.
#[derive(Debug, Clone)]
pub struct Port;

impl Validator for Port {
    fn validate(&self, value: &str) -> Option<ValidationError> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None; // empty is ok (optional)
        }
        match trimmed.parse::<u16>() {
            Ok(p) if p > 0 => None,
            _ => Some(ValidationError::new(
                "Must be a valid port number (1–65535)",
            )),
        }
    }
}

/// Validates that the value looks like a hostname (non-empty, no spaces).
#[derive(Debug, Clone)]
pub struct Hostname;

impl Validator for Hostname {
    fn validate(&self, value: &str) -> Option<ValidationError> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            // Use Required for empty-check; this validator only checks format.
            return None;
        }
        if trimmed.contains(' ') || trimmed.contains('\t') {
            return Some(ValidationError::new("Must be a valid hostname"));
        }
        None
    }
}

/// Validates against a custom closure.
#[derive(Debug)]
pub struct Pattern {
    /// Label for the error message (e.g. "email address").
    pub label: &'static str,
    /// The check function. Returns `true` if valid.
    pub check: fn(&str) -> bool,
}

impl Validator for Pattern {
    fn validate(&self, value: &str) -> Option<ValidationError> {
        if value.is_empty() {
            return None; // empty is handled by Required
        }
        if (self.check)(value) {
            None
        } else {
            Some(ValidationError::new(format!(
                "Must be a valid {}",
                self.label
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_rejects_empty() {
        assert!(Required.validate("").is_some());
        assert!(Required.validate("   ").is_some());
    }

    #[test]
    fn required_allows_nonempty() {
        assert!(Required.validate("hello").is_none());
    }

    #[test]
    fn min_length_rejects_short() {
        assert!(MinLength(3).validate("ab").is_some());
    }

    #[test]
    fn min_length_allows_long_enough() {
        assert!(MinLength(3).validate("abc").is_none());
    }

    #[test]
    fn max_length_rejects_long() {
        assert!(MaxLength(5).validate("abcdef").is_some());
    }

    #[test]
    fn max_length_allows_short_enough() {
        assert!(MaxLength(5).validate("abc").is_none());
    }

    #[test]
    fn port_valid() {
        assert!(Port.validate("22").is_none());
        assert!(Port.validate("443").is_none());
        assert!(Port.validate("65535").is_none());
    }

    #[test]
    fn port_invalid() {
        assert!(Port.validate("0").is_some());
        assert!(Port.validate("99999").is_some());
        assert!(Port.validate("abc").is_some());
        assert!(Port.validate("-1").is_some());
    }

    #[test]
    fn port_allows_empty() {
        assert!(Port.validate("").is_none());
    }

    #[test]
    fn hostname_valid() {
        assert!(Hostname.validate("example.com").is_none());
        assert!(Hostname.validate("192.168.1.1").is_none());
        assert!(Hostname.validate("my-server").is_none());
    }

    #[test]
    fn hostname_rejects_spaces() {
        assert!(Hostname.validate("bad host").is_some());
    }

    #[test]
    fn hostname_allows_empty() {
        assert!(Hostname.validate("").is_none());
    }

    #[test]
    fn pattern_custom() {
        let digits = Pattern {
            label: "number",
            check: |v| v.chars().all(|c| c.is_ascii_digit()),
        };
        assert!(digits.validate("123").is_none());
        assert!(digits.validate("abc").is_some());
    }

    #[test]
    fn pattern_allows_empty() {
        let anything = Pattern {
            label: "x",
            check: |_| false,
        };
        assert!(anything.validate("").is_none());
    }
}
