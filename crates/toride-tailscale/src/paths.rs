//! Tailscale path resolution for system directories.
//!
//! Provides [`TailscalePaths`], which resolves and caches canonical paths for
//! the Tailscale state directory, socket, and configuration files. All other
//! service modules accept `&TailscalePaths` to locate the resources they
//! operate on.

use std::path::{Path, PathBuf};

use crate::Result;

/// Resolved paths for the Tailscale system directory layout.
///
/// All paths are resolved relative to `/var/lib/tailscale` at construction
/// time. The `Default` impl returns the standard system paths.
///
/// # Example
///
/// ```ignore
/// use toride_tailscale::paths::TailscalePaths;
///
/// let paths = TailscalePaths::default();
/// assert_eq!(paths.state_dir(), Path::new("/var/lib/tailscale"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscalePaths {
    /// Root Tailscale state directory (e.g. `/var/lib/tailscale`).
    state_dir: PathBuf,
    /// Path to the Tailscale daemon socket.
    socket_path: PathBuf,
    /// Path to the Tailscale identity file.
    identity_path: PathBuf,
    /// Path to the Tailscale configuration file.
    config_path: PathBuf,
}

impl Default for TailscalePaths {
    /// Return standard system paths for Tailscale.
    fn default() -> Self {
        let state_dir = PathBuf::from("/var/lib/tailscale");
        Self::with_state_dir(state_dir)
    }
}

impl TailscalePaths {
    /// Create a `TailscalePaths` from the default `/var/lib/tailscale` location.
    ///
    /// # Errors
    ///
    /// Returns an error if the state directory does not exist.
    pub fn system() -> Result<Self> {
        let paths = Self::default();
        if !paths.state_dir.exists() {
            return Err(crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "Tailscale state directory not found: {}",
                    paths.state_dir.display()
                ),
            )));
        }
        Ok(paths)
    }

    /// Create a `TailscalePaths` from an explicit state directory.
    pub fn with_state_dir(state_dir: PathBuf) -> Self {
        let socket_path = state_dir.join("tailscaled.sock");
        let identity_path = state_dir.join("identity.json");
        let config_path = PathBuf::from("/etc/default/tailscaled");
        Self {
            state_dir,
            socket_path,
            identity_path,
            config_path,
        }
    }

    /// Returns the root Tailscale state directory.
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Returns the path to the Tailscale daemon socket.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Returns the path to the Tailscale identity file.
    pub fn identity_path(&self) -> &Path {
        &self.identity_path
    }

    /// Returns the path to the Tailscale daemon configuration file.
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }
}
