//! # Install backends
//!
//! Thin registry of the crate's [`Backend`](crate::Backend) implementations
//! — one `pub mod` per install technology, with a flat re-export of each
//! backend type for callers that want `backends::HomebrewBackend` without
//! the module path. A new backend wires in by adding its module here and
//! extending the re-export list.

pub mod distro;
pub mod flatpak;
pub mod homebrew;

pub use distro::DistroBackend;
pub use flatpak::FlatpakBackend;
pub use homebrew::HomebrewBackend;
