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
//! - the [`Registry`] facade (DESIGN.md §3.3) — search fan-out with
//!   per-source error tolerance, resolve merging `sources` rows, and
//!   `plan` rendering install descriptors per host platform;
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
//! The [`Registry`] facade is the entry point: adapters in via
//! [`RegistryBuilder::with_adapter`] (the concrete `sources` adapters
//! behind the `http` feature), normalized answers out. Offline example:
//!
//! ```
//! use toride_registry::model::{App, Os, Platform};
//! use toride_registry::{PlannedOp, Registry, TorideId};
//!
//! let registry = Registry::builder().build();
//!
//! let outcome = tokio::runtime::Runtime::new()
//!     .unwrap()
//!     .block_on(registry.search("brave browser"))
//!     .unwrap();
//! assert!(outcome.apps.is_empty());
//! assert!(outcome.failures.is_empty());
//!
//! let rows = tokio::runtime::Runtime::new()
//!     .unwrap()
//!     .block_on(registry.resolve(&TorideId::slugify("brave-browser")))
//!     .unwrap();
//! assert!(rows.is_empty());
//!
//! let app: App = serde_json::from_str(
//!     r#"{"id":"brave","name":"Brave","aliases":[],"summary":null,"description":null,
//!         "homepage":null,"license":null,"developer":null,"binaries":[],"latest":null,
//!         "platforms":[],"artifacts":[],"sources":[],"availability":"Available",
//!         "install":{"Flatpak":{"app_id":"com.brave.Browser","remote":"flathub"}}}"#,
//! )
//! .unwrap();
//! let host = Platform { os: Os::Linux, arch: None, min_release: None };
//! assert_eq!(
//!     Registry::plan(&app, &host),
//!     PlannedOp::Command {
//!         program: "flatpak".to_owned(),
//!         args: vec![
//!             "install".to_owned(),
//!             "--user".to_owned(),
//!             "flathub".to_owned(),
//!             "com.brave.Browser".to_owned(),
//!         ],
//!     }
//! );
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
pub use adapter::{Adapter, PlannedOp, Registry, RegistryBuilder, SearchOutcome};
pub use error::{Error, Result, SourceFailure};
pub use model::{
    App, Arch, Artifact, ArtifactKind, Availability, Checksum, ChecksumAlgo, DistroFamily,
    InstallMethod, Os, Platform, SourceKind, SourceRef, TorideId, VerificationPolicy, Version,
};
