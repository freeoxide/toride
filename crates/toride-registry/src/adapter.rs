//! # Adapter boundary
//!
//! The [`Adapter`] trait is the seam between the external world and the
//! normalized model (DESIGN.md §3): every source-specific concern — wire
//! structs, endpoints, quirk handling, fetch clients — lives behind it, in
//! the per-source modules under [`sources`](crate::sources). Callers see
//! only [`App`](crate::App) and [`SourceRef`](crate::model::SourceRef).
//!
//! The trait follows the house async style:
//! `#[async_trait::async_trait]` + `Send + Sync` supertraits, matching
//! toride-installer's `ReleaseResolver`. The `Registry` facade that fans
//! `search` out across `Vec<Box<dyn Adapter>>` (DESIGN.md §3.3) lands with
//! the implementation phase.

use crate::error::Result;
use crate::model::{App, SourceKind, SourceRef};

/// Normalizes one external repository into [`App`](crate::App)s.
///
/// Contract: ALL source-specific knowledge lives in the implementing
/// module — wire structs, endpoints, quirk handling. Callers see only
/// `App` and [`SourceRef`]. Each adapter additionally keeps its parse and
/// fetch halves strictly separated (DESIGN.md §3.1): only the fetch half
/// touches the network; only the parse half is fixture-tested offline.
#[async_trait::async_trait]
pub trait Adapter: Send + Sync {
    /// Which source this adapter normalizes.
    fn source(&self) -> SourceKind;

    /// Look up one app by its source-native id (cask token, formula
    /// name, flatpak app id, distro package + repo). `Ok(None)` = the
    /// source has no such entry.
    ///
    /// # Errors
    ///
    /// Transport or payload-parse failures
    /// ([`Error::Http`](crate::Error::Http),
    /// [`Error::Parse`](crate::Error::Parse)).
    async fn lookup(&self, id: &SourceRef) -> Result<Option<App>>;

    /// Free-text search. Returns normalized stubs — enough for a result
    /// list (`id`, `name`, `summary`, `install`, `platforms`); heavy
    /// fields (`artifacts`, full `description`) may require
    /// [`Adapter::lookup`].
    ///
    /// # Errors
    ///
    /// Transport or payload-parse failures
    /// ([`Error::Http`](crate::Error::Http),
    /// [`Error::Parse`](crate::Error::Parse)).
    async fn search(&self, query: &str) -> Result<Vec<App>>;
}
