//! Download progress reported by the installer's streaming download loop.
//!
//! [`Installer::install_with_resolver`](crate::Installer::install_with_resolver)
//! streams the artifact body chunk-by-chunk. When the caller wires a callback
//! via [`Installer::with_progress`](crate::Installer::with_progress), the
//! installer hands it a [`Progress`] snapshot as bytes flow in — letting the
//! UI render a progress bar, a percentage, or a spinner that reflects real
//! throughput.
//!
//! ## Percent computation
//!
//! The installer never divides: it just reports `downloaded` and `total`. The
//! caller computes the percent (treating a missing `total` as indeterminate):
//!
//! ```rust,ignore
//! use toride_installer::Progress;
//!
//! fn percent(p: Progress) -> Option<u64> {
//!     // `None` total means the server sent no Content-Length: the download
//!     // is indeterminate, so there is no meaningful percentage to show.
//!     p.total.filter(|&t| t != 0).map(|t| p.downloaded * 100 / t)
//! }
//! ```
//!
//! When no callback is set, the installer's behavior is byte-for-byte
//! unchanged — progress reporting is purely observational.

/// Bytes downloaded so far, plus the total size when the server sent
/// `Content-Length`.
///
/// Passed to the callback installed via
/// [`Installer::with_progress`](crate::Installer::with_progress). The values
/// are a point-in-time snapshot; the installer throttles callbacks (see the
/// module docs) so a long download does not produce one callback per byte.
///
/// Callers compute the percent as `total.map(|t| downloaded * 100 / t)` and
/// treat `total == None` as indeterminate (no progress percentage to show).
/// Guard against `total == Some(0)` before dividing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    /// Bytes downloaded so far.
    pub downloaded: u64,
    /// Total bytes when the response carried `Content-Length`; `None`
    /// otherwise (chunked transfer encoding, broken servers, …).
    pub total: Option<u64>,
}

impl Progress {
    /// Convenience percent in `0..=100`, or `None` when the total is unknown
    /// (or reported as zero, which would otherwise divide by zero).
    ///
    /// Equivalent to `self.total.filter(|&t| t != 0).map(|t| self.downloaded * 100 / t)`.
    /// Most callers inline this rather than calling here, but it is provided
    /// so the division-safety guard lives in one place.
    #[must_use]
    pub fn percent(self) -> Option<u64> {
        // Guard against `total == 0`: a zero-length Content-Length is a legal
        // (if odd) response and must not panic the caller's percent math.
        self.total.filter(|&t| t != 0).map(|t| self.downloaded * 100 / t)
    }
}
