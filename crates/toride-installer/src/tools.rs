//! Concrete tools.
//!
//! Only [`mise`] is wired today. Adding a new tool means implementing
//! [`ReleaseResolver`](crate::tool::ReleaseResolver) and constructing a
//! [`Tool`](crate::Tool) — the engine is otherwise unchanged. See the crate
//! docs for how node/bun/etc. would plug in.
//!
//! The descriptor half of each tool (constants + `*_tool()`) is deliberately
//! ungated so the offline detector can classify it without the `http`
//! feature; the resolver and install/ensure paths ride behind `http`.

pub mod mise;
