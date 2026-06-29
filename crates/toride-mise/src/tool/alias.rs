//! Tool alias management via `mise tool-alias`.
//!
//! Exposes [`ToolAlias`] for deserialised alias entries and adds
//! [`Mise::tool_aliases_list`], [`Mise::tool_alias_get`],
//! [`Mise::tool_alias_set`], and [`Mise::tool_alias_unset`] methods
//! on the client.

use serde::Deserialize;

use crate::client::Mise;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// JSON response types
// ---------------------------------------------------------------------------

/// A single tool alias entry as returned by `mise tool-alias ls --output=json`.
#[derive(Debug, Clone, Deserialize)]
pub struct ToolAlias {
    /// The tool name the alias belongs to (e.g. `"node"`).
    pub tool: String,
    /// The alias name (e.g. `"lts"`).
    pub alias: String,
    /// The version the alias resolves to (e.g. `"22"`).
    pub version: String,
}

// ---------------------------------------------------------------------------
// Mise methods
// ---------------------------------------------------------------------------

impl Mise {
    /// List tool aliases, optionally filtered by tool name.
    ///
    /// When `tool` is `Some`, only aliases for that tool are returned by passing
    /// it as a positional argument to the CLI.
    ///
    /// Invokes `mise tool-alias ls [TOOL]` and parses the plain-text table
    /// output. Real mise does not support `--json` for this command; it prints
    /// rows like: `node  lts  22`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    pub async fn tool_aliases_list(&self, tool: Option<&str>) -> MiseResult<Vec<ToolAlias>> {
        let mut args: Vec<String> = vec!["tool-alias".into(), "ls".into()];
        if let Some(t) = tool {
            args.push(t.into());
        }
        let output = self.run_checked(args).await?;
        let mut aliases = Vec::new();
        for line in output.stdout_trimmed().lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                aliases.push(ToolAlias {
                    tool: parts[0].to_owned(),
                    alias: parts[1].to_owned(),
                    version: parts[2].to_owned(),
                });
            }
        }
        Ok(aliases)
    }

    /// Get the version a tool alias resolves to.
    ///
    /// Invokes `mise tool-alias get <tool> <alias>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    pub async fn tool_alias_get(&self, tool: &str, alias: &str) -> MiseResult<String> {
        let output = self.run_checked(["tool-alias", "get", tool, alias]).await?;
        Ok(output.stdout_trimmed().to_owned())
    }

    /// Set (create or update) a tool alias.
    ///
    /// Invokes `mise tool-alias set <tool> <alias> <version>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    pub async fn tool_alias_set(&self, tool: &str, alias: &str, version: &str) -> MiseResult<()> {
        self.run_checked(["tool-alias", "set", tool, alias, version])
            .await?;
        Ok(())
    }

    /// Remove a tool alias.
    ///
    /// Invokes `mise tool-alias unset <tool> <alias>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    pub async fn tool_alias_unset(&self, tool: &str, alias: &str) -> MiseResult<()> {
        self.run_checked(["tool-alias", "unset", tool, alias])
            .await?;
        Ok(())
    }
}
