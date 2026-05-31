//! Trait interface for individual SSH diagnostic checks.
//!
//! Defines the [`Check`] trait that every diagnostic check must implement,
//! along with the [`CheckFuture`] type alias for async execution. Checks are
//! registered in a [`CheckRegistry`](super::registry::CheckRegistry) and
//! executed by [`DoctorService`](super::DoctorService).

use crate::{Diagnostic, Result};

/// Return type for async check execution.
///
/// Boxes the future so that heterogeneous check implementations can be
/// stored in a single collection.
pub type CheckFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<Diagnostic>>> + Send + 'a>>;

/// A single diagnostic check that can be run independently.
///
/// Each check inspects one aspect of the SSH environment (file permissions,
/// agent availability, config correctness, etc.) and returns zero or more
/// [`Diagnostic`] findings.
pub trait Check: Send + Sync {
    /// Machine-readable check identifier (e.g. `"ssh_dir_exists"`).
    ///
    /// This identifier is used to deduplicate findings and to look up
    /// checks in the [`CheckRegistry`](super::registry::CheckRegistry).
    fn id(&self) -> &'static str;

    /// Module name for diagnostic grouping (e.g. `"local"`, `"remote"`).
    ///
    /// Findings are grouped by module in UI output.
    fn module(&self) -> &'static str;

    /// Execute the check and return any findings.
    ///
    /// Implementations should return `Ok(vec![])` when the check passes
    /// with no noteworthy findings. Multiple findings may be returned
    /// when a single check inspects several items (e.g. all private key
    /// files for correct permissions).
    fn run(&self) -> CheckFuture<'_>;
}
