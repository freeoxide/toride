//! Config path resolution for [`Mise`](crate::Mise).
//!
//! This module provides `impl Mise::config_path` which resolves the global mise
//! config file path by querying `mise config path` (or falling back to the
//! XDG default).

use camino::Utf8PathBuf;

use crate::client::Mise;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// impl Mise — path operations
// ---------------------------------------------------------------------------

impl Mise {
    /// Resolve the global mise config file path.
    ///
    /// First tries `mise config path` to let mise report its own path. Falls
    /// back to the XDG convention `~/.config/mise/config.toml` when the
    /// command is unavailable (e.g. the binary has not been installed).
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if `mise config path` exits
    /// non-zero and the fallback path cannot be determined.
    pub async fn config_path(&self) -> MiseResult<Utf8PathBuf> {
        // Ask mise directly.
        let result = self.run_checked(["config", "path"]).await;
        match result {
            Ok(output) => {
                let raw = output.stdout_trimmed().to_owned();
                if raw.is_empty() {
                    Self::fallback_config_path()
                } else {
                    Ok(Utf8PathBuf::from(raw))
                }
            }
            Err(_) => Self::fallback_config_path(),
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Compute the fallback config path using the XDG convention.
    ///
    /// Returns `~/.config/mise/config.toml`.
    fn fallback_config_path() -> MiseResult<Utf8PathBuf> {
        dirs::config_dir()
            .map(|mut p| {
                p.push("mise");
                p.push("config.toml");
                Utf8PathBuf::from_path_buf(p)
                    .unwrap_or_else(|_| Utf8PathBuf::from("~/.config/mise/config.toml"))
            })
            .ok_or_else(|| {
                crate::error::MiseError::Io(std::io::Error::other(
                    "cannot determine config directory: XDG_CONFIG_HOME and HOME are unset",
                ))
            })
    }
}
