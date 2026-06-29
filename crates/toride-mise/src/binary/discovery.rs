//! Mise binary discovery: locate the `mise` executable on the host.

use camino::Utf8PathBuf;

use super::version::MiseVersion;
use crate::error::MiseError;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// MiseBinary
// ---------------------------------------------------------------------------

/// Represents a discovered `mise` binary on the system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiseBinary {
    /// Absolute path to the `mise` executable.
    pub path: Utf8PathBuf,
    /// Parsed version, if `mise --version` has been queried.
    pub version: Option<MiseVersion>,
}

impl MiseBinary {
    /// Discover the `mise` binary using a cascade of strategies.
    ///
    /// 1. `MISE_BIN` environment variable (must point to an existing file).
    /// 2. `which` lookup on `$PATH`.
    /// 3. Well-known installation paths (`~/.local/bin/mise`, `/usr/local/bin/mise`).
    /// 4. App-bundled binary path (alongside the current executable).
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::BinaryNotFound`] if none of the strategies succeed.
    pub fn discover() -> MiseResult<Self> {
        // 1. MISE_BIN env var
        if let Ok(val) = std::env::var("MISE_BIN") {
            let path = Utf8PathBuf::from(&val);
            if path.is_file() {
                return Ok(Self {
                    path,
                    version: None,
                });
            }
        }

        // 2. which lookup
        if let Ok(path) = which::which("mise") {
            let utf8 = Utf8PathBuf::from_path_buf(path).map_err(|pb| {
                MiseError::Io(std::io::Error::other(format!(
                    "non-utf8 path from which: {}",
                    pb.display()
                )))
            })?;
            return Ok(Self {
                path: utf8,
                version: None,
            });
        }

        // 3. Well-known paths
        let candidates: Vec<Utf8PathBuf> = dirs_home_local_bin()
            .into_iter()
            .chain(std::iter::once(Utf8PathBuf::from("/usr/local/bin/mise")))
            .collect();

        for candidate in candidates {
            if candidate.is_file() {
                return Ok(Self {
                    path: candidate,
                    version: None,
                });
            }
        }

        // 4. App-bundled binary path: look for `mise` alongside the current executable.
        if let Ok(exe) = std::env::current_exe()
            && let Some(dir) = exe.parent()
        {
            let bundled = dir.join("mise");
            if bundled.is_file()
                && let Ok(utf8) = Utf8PathBuf::from_path_buf(bundled)
            {
                return Ok(Self {
                    path: utf8,
                    version: None,
                });
            }
        }

        Err(MiseError::BinaryNotFound)
    }

    /// Create a [`MiseBinary`] from a known path without performing discovery.
    ///
    /// The caller is responsible for ensuring the path points to a valid
    /// `mise` executable.
    pub fn from_path(path: impl Into<Utf8PathBuf>) -> Self {
        Self {
            path: path.into(),
            version: None,
        }
    }

    /// Return the binary path as a string slice.
    pub fn as_str(&self) -> &str {
        self.path.as_str()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns `~/.local/bin/mise` if the home directory can be determined.
fn dirs_home_local_bin() -> Option<Utf8PathBuf> {
    dirs::home_dir()
        .map(|h| Utf8PathBuf::from_path_buf(h.join(".local/bin/mise")).unwrap_or_default())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_path_sets_version_none() {
        let bin = MiseBinary::from_path("/usr/local/bin/mise");
        assert_eq!(bin.path.as_str(), "/usr/local/bin/mise");
        assert!(bin.version.is_none());
    }

    #[test]
    fn as_str_returns_path() {
        let bin = MiseBinary::from_path("/usr/bin/mise");
        assert_eq!(bin.as_str(), "/usr/bin/mise");
    }
}
