//! Backend listing via `mise backends ls`.
//!
//! Provides [`BackendInfo`] for deserialised backend entries and a
//! [`Mise::backends`] method for listing available backends.

use camino::Utf8PathBuf;
use serde::Deserialize;

use crate::client::Mise;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// A single backend entry as reported by `mise backends ls`.
#[derive(Debug, Clone, Deserialize)]
pub struct BackendInfo {
    /// The backend name (e.g. `"core"`, `"aqua"`, `"asdf"`).
    pub name: String,
    /// Whether the backend is installed and available.
    #[serde(default)]
    pub installed: bool,
}

/// A single bin-path entry as reported by `mise bin-paths --bin-names --json`.
#[derive(Debug, Clone, Deserialize)]
pub struct BinPathEntry {
    /// The tool name that provides this binary.
    #[serde(default)]
    pub name: Option<String>,
    /// The filesystem path to the binary.
    pub path: String,
}

impl BinPathEntry {
    /// Return the path as a [`Utf8PathBuf`].
    pub fn path(&self) -> Utf8PathBuf {
        Utf8PathBuf::from(&self.path)
    }
}

// ---------------------------------------------------------------------------
// Mise methods
// ---------------------------------------------------------------------------

impl Mise {
    /// List all known mise backends.
    ///
    /// Invokes `mise backends ls`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    pub async fn backends(&self) -> MiseResult<Vec<String>> {
        let output = self.run_checked(["backends", "ls"]).await?;
        let lines = output
            .stdout_trimmed()
            .lines()
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty())
            .collect();
        Ok(lines)
    }

    /// Return the bin directories for all active mise-managed tools.
    ///
    /// Invokes `mise bin-paths --json`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn bin_paths(&self) -> MiseResult<Vec<Utf8PathBuf>> {
        let paths: Vec<String> = self.run_json(["bin-paths", "--json"]).await?;
        Ok(paths.into_iter().map(Utf8PathBuf::from).collect())
    }

    /// Return the bin directories for all active mise-managed tools,
    /// including the tool name associated with each path.
    ///
    /// Invokes `mise bin-paths --bin-names --json`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn bin_paths_with_names(&self) -> MiseResult<Vec<BinPathEntry>> {
        self.run_json(["bin-paths", "--bin-names", "--json"]).await
    }
}
