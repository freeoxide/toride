//! # Per-source adapters
//!
//! One module per external repository (DESIGN.md §1). Each owns its wire
//! structs, its pure parse functions, and its thin fetch client, and
//! implements [`Adapter`](crate::adapter::Adapter) so downstream sees only
//! [`App`](crate::App) — never a source-specific shape.
//!
//! Wave-1 status (DESIGN.md §7): all four modules are implemented.
//! [`homebrew`], [`flathub`], and [`appstream`] each carry the complete
//! parse half, an `http`-gated fetch client, and their `Adapter` wiring,
//! fixture-tested offline. [`repology`] is the parse-only Repology oracle
//! — deliberately no `Adapter` impl (it has no search/browse surface and
//! installs nothing); its candidates feed the alias index instead. Each
//! module's `//!` doc names its scope, fixtures, and the survey section
//! it is grounded in.

pub mod appstream;
pub mod flathub;
pub mod homebrew;
pub mod repology;
