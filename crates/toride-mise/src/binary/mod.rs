//! Binary discovery, version handling, and bootstrap support for mise.

mod discovery;
mod install;
mod version;

pub use discovery::MiseBinary;
pub use install::{install_mise, BootstrapMethod, BootstrapOptions};
pub use version::MiseVersion;
