//! Shared filesystem utilities for the toride project.
//!
//! Provides atomic writes, file locking, path expansion, permission helpers,
//! and optional-read utilities used across multiple toride crates.
//!
//! # High-level API
//!
//! ```ignore
//! use toride_fs::{atomic_write, expand_path, read_optional};
//!
//! atomic_write("/etc/toride/config.toml", &content)?;
//! let data = read_optional("/etc/toride/optional.json")?;
//! let resolved = expand_path("~/config");
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![expect(
    clippy::must_use_candidate,
    reason = "constructors and getters are obvious"
)]
// All public `Result`-returning functions already document their errors via
// `# Errors` sections, so `missing_errors_doc` has nothing to flag. Use an
// `allow` (with a reason) rather than an `expect`, which would otherwise
// trigger `unfulfilled_lint_expectations` under `-D warnings`.
#![allow(
    clippy::missing_errors_doc,
    reason = "all Result fns carry # Errors docs"
)]

// ---------------------------------------------------------------------------
// Module declarations
// ---------------------------------------------------------------------------

pub mod atomic;
pub mod error;
pub mod expand;
pub mod lock;
pub mod permissions;
pub mod read;

// ---------------------------------------------------------------------------
// Re-exports -- convenience for downstream crates
// ---------------------------------------------------------------------------

pub use atomic::{atomic_write, atomic_write_bytes, atomic_write_with_perms};
pub use error::{Error, Result};
pub use expand::{expand_path, expand_tilde};
pub use lock::{with_lock, with_lock_path};
pub use permissions::set_permissions;
pub use read::{read_optional, read_optional_bytes};
