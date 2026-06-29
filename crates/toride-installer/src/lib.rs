//! # toride-installer
//!
//! A generalized, **tool-agnostic** release-artifact installer framework
//! written in pure Rust (no `curl | sh`). Given a description of a tool and
//! a target platform, it resolves, downloads, verifies, extracts, and
//! installs the tool's release artifact into a chosen directory.
//!
//! ## Design
//!
//! The framework is split into:
//!
//! - a declarative [`Tool`] config (name, artifact kind, binary path,
//!   checksum source, default install dir) plus a [`ReleaseResolver`]
//!   trait for mapping `(Target, version) -> URL`;
//! - a generic [`Installer`] engine that runs the pipeline below; and
//! - a small set of **concrete tools** under [`tools`] (only [`mise`][tools::mise]
//!   is wired today).
//!
//! Adding a new tool (node, bun, …) means implementing [`ReleaseResolver`]
//! and constructing a [`Tool`] — the engine is otherwise unchanged.
//!
//! ## Pipeline
//!
//! 1. **Resolve** the artifact URL (and the concrete version when the
//!    request is `"latest"`).
//! 2. **Download** via `reqwest`, following redirects, capped at
//!    [`DEFAULT_MAX_BYTES`].
//! 3. **Verify** — sha256 when the tool publishes one; otherwise the
//!    documented size-floor sanity check ([`DEFAULT_MIN_BYTES`]).
//! 4. **Extract** — [`Binary`][ArtifactKind::Binary] placed directly,
//!    [`Tarball`][ArtifactKind::Tarball] decompressed (gzip **or** xz) and
//!    the configured entry located. Both kinds are implemented so the
//!    framework is genuinely general.
//! 5. **Install** — written atomically (temp + rename via [`toride_fs`])
//!    into the install dir and `chmod 0o755` on Unix.
//!
//! ## Quick start (mise)
//!
//! ```rust,ignore
//! use toride_installer::tools::mise;
//!
//! # async fn run() -> toride_installer::Result<()> {
//! let dest = mise::install_mise("latest", None).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Wiring a new tool
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use async_trait::async_trait;
//! use toride_installer::{
//!     Installer, Target, Result,
//!     tool::{ArtifactKind, Checksum, ReleaseResolver, Tool},
//! };
//!
//! struct NodeResolver;
//!
//! #[async_trait]
//! impl ReleaseResolver for NodeResolver {
//!     async fn resolve(&self, target: Target, version: &str)
//!         -> Result<(String, String)>
//!     {
//!         let url = format!(
//!             "https://nodejs.org/dist/v{version}/node-v{version}-{}.tar.xz",
//!             target.keyword(),
//!         );
//!         Ok((version.to_owned(), url))
//!     }
//! }
//!
//! let node = Tool::builder()
//!     .name("node")
//!     .artifact(ArtifactKind::tarball_xz())          // hypothetical helper
//!     .bin_path("bin/node")
//!     .bin_name("node")
//!     .build()?;
//!
//! # async fn run(node: Tool, resolver: NodeResolver) -> toride_installer::Result<()> {
//! let dest = Installer::new()
//!     .install_with_resolver(&node, Target::host()?, "20.10.0", None, &resolver)
//!     .await?;
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_code)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::module_name_repetitions)]

pub mod error;
pub mod extract;
pub mod installer;
pub mod target;
pub mod tool;
pub mod tools;

// Re-exports — the public API surface.
pub use error::{Error, Result};
pub use installer::{
    DEFAULT_MAX_BYTES, DEFAULT_MIN_BYTES, Installer, InstallerBuilder, TemplateResolver, Verifier,
    install_tool,
};
pub use target::{Arch, Os, Target};
pub use tool::{ArtifactKind, Checksum, ReleaseResolver, Tarball, Tool, ToolBuilder};
