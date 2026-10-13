//! Binary discovery helpers.
//!
//! Utilities for locating executables on the system `$PATH` using the
//! `which` crate.

use crate::error::{Error, Result};
use std::path::PathBuf;

/// Check whether a binary exists on the system `$PATH`.
///
/// Returns `true` if `which::which(name)` succeeds.
///
/// # Examples
///
/// ```rust,no_run
/// use toride_runner::discovery::binary_exists;
///
/// if binary_exists("ufw") {
///     println!("ufw is installed");
/// }
/// ```
pub fn binary_exists(name: &str) -> bool {
    which::which(name).is_ok()
}

/// Find the full path to a binary on the system `$PATH`.
///
/// # Errors
///
/// Returns [`Error::BinaryNotFound`] if the binary cannot be located.
pub fn find_binary(name: &str) -> Result<PathBuf> {
    which::which(name).map_err(|_| Error::BinaryNotFound(name.to_owned()))
}

/// Verify that a required binary is present, returning an error if not.
///
/// This is a convenience wrapper around [`find_binary`] that discards
/// the path, useful for pre-flight checks.
///
/// # Errors
///
/// Returns [`Error::BinaryNotFound`] if the binary cannot be located.
pub fn require_binary(name: &str) -> Result<()> {
    find_binary(name)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ls_exists_on_unix() {
        assert!(binary_exists("ls"));
    }

    #[test]
    fn nonexistent_binary() {
        assert!(!binary_exists("definitely_not_a_real_binary_xyz_123"));
    }

    #[test]
    fn find_ls_returns_path() {
        let path = find_binary("ls").unwrap();
        assert!(path.to_string_lossy().contains("ls"));
    }

    #[test]
    fn require_nonexistent_fails() {
        let result = require_binary("definitely_not_a_real_binary_xyz_123");
        assert!(result.is_err());
    }
}
