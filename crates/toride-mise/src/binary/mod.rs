//! Binary discovery, version handling, and bootstrap support for mise.

mod discovery;
mod install;
mod version;

pub use discovery::MiseBinary;
pub use install::{BootstrapMethod, BootstrapOptions, install_mise};
pub use version::MiseVersion;
