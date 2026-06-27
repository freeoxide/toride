//! Concrete tools.
//!
//! Only [`mise`] is wired today. Adding a new tool means implementing
//! [`ReleaseResolver`](crate::tool::ReleaseResolver) and constructing a
//! [`Tool`](crate::Tool) — the engine is otherwise unchanged. See the crate
//! docs for how node/bun/etc. would plug in.

pub mod mise;
