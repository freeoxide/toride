//! Environment variable resolution for mise.
//!
//! This module provides types and methods for querying the environment
//! variables that mise would set for a given set of tools or the active
//! configuration.
//!
//! - [`generated`] — generated environment types ([`EnvRequest`], [`MiseEnv`],
//!   [`EnvEntry`]) and the [`Mise::env`] / [`Mise::env_for`] methods.

pub mod generated;

pub use generated::{EnvEntry, EnvRequest, MiseEnv};
