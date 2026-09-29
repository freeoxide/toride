//! # toride-registry
//!
//! Normalizes external package registries — Homebrew (formulae.brew.sh),
//! Flathub, AppStream/DEP-11 distro catalogs, and Repology — into the one
//! normalized [`App`] model. Every external repository has its own
//! structure; each is normalized by exactly one [`Adapter`], the only
//! place source-specific knowledge lives. Search, resolve, alias handling
//! and install planning downstream see only `App`
//! ([`TorideId`], [`SourceRef`], [`InstallMethod`]).
//!
//! ## Design
//!
//! The crate is split into:
//!
//! - the normalized [`model`] — the single shape that crosses the adapter
//!   boundary outward;
//! - the [`Adapter`] trait — the contract each per-source module
//!   implements, with a strict parse (pure, `&str` in → `App` out,
//!   fixture-tested offline) / fetch (thin clients returning raw body
//!   text) split;
//! - the per-source modules under [`sources`] — wave 1 wires
//!   [`homebrew`][sources::homebrew], [`flathub`][sources::flathub],
//!   [`appstream`][sources::appstream], and the parse-only Repology oracle
//!   [`repology`][sources::repology];
//! - the alias layer — [`TorideId`] derivation plus the Repology-filled
//!   alias index mapping the canonical toride id to per-source ids
//!   (DESIGN.md §5).
//!
//! Installation itself is out of scope here: [`InstallMethod`] describes
//! *what* to run/fetch; execution stays with toride-installer / the host.
//!
//! ## Pipeline
//!
//! 1. **Fetch** — each source's thin client GETs/POSTs and returns raw
//!    body text (never deserialized values), so live and fixture payloads
//!    flow through the same parse signatures.
//! 2. **Parse** — the pure per-source parsers turn that text into
//!    normalized types; they take no clock, no network, no client.
//! 3. **Normalize** — adapters emit [`App`]s carrying a [`SourceRef`] per
//!    source that knows the app, [`Platform`] claims, checksummed
//!    [`Artifact`]s, and an [`InstallMethod`].
//! 4. **Alias** — the canonical [`TorideId`] is derived (Repology project
//!    name when the oracle knows the app, else the first source id) and
//!    mapped to per-source ids through the alias index.
//! 5. **Plan** — an [`InstallMethod`] plus the host [`Platform`] becomes
//!    concrete steps for the host: the native manager command, a direct
//!    checksummed download when the manager is missing, or `unsupported`.
//!
//! ## Quick start
//!
//! The end-to-end flow (rust,ignore until the `Registry` facade of
//! DESIGN.md §3.3 lands — the model, error, adapter trait, and all four
//! `sources` modules are real today):
//!
//! ```rust,ignore
//! use toride_registry::model::{Arch, Os, Platform, TorideId};
//! use toride_registry::{App, Registry};
//!
//! // One adapter per external source; wave 1 wires homebrew, flathub
//! // and appstream (DESIGN.md §7).
//! let registry = Registry::new(vec![
//!     Box::new(toride_registry::sources::homebrew::HomebrewAdapter::default()),
//!     Box::new(toride_registry::sources::flathub::FlathubAdapter::default()),
//! ]);
//!
//! // Free-text search fans out to every adapter, returning normalized apps.
//! let hits: Vec<App> = registry.search("brave browser").await?;
//!
//! // Canonical toride id → per-source identity rows (alias index).
//! let id = TorideId::slugify("brave-browser");
//! let rows = registry.resolve(&id)?;
//!
//! // Install descriptor → concrete steps for the host platform.
//! let host = Platform { os: Os::Linux, arch: Some(Arch::X86_64), min_release: None };
//! let plan = registry.plan(&hits[0], &host)?;
//! ```

#![deny(unsafe_code)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::module_name_repetitions)]

pub mod adapter;
pub mod error;
#[cfg(feature = "http")]
pub(crate) mod http;
pub mod model;
pub mod sources;

// Re-exports — the public API surface.
pub use adapter::Adapter;
pub use error::{Error, Result};
pub use model::{
    App, Arch, Artifact, ArtifactKind, Availability, Checksum, ChecksumAlgo, DistroFamily,
    InstallMethod, Os, Platform, SourceKind, SourceRef, TorideId, Version,
};
