//! SSH config file parsing, editing, and host resolution.
//!
//! Provides [`ConfigService`] for reading and writing `~/.ssh/config` via a
//! lossless AST, plus [`ResolvedHost`] for merging config directives into a
//! final per-host configuration. Sub-modules cover the AST types, individual
//! directives, in-place editing, managed host blocks, parsing, and resolution.

pub mod ast;
mod directives;
mod editor;
mod managed;
mod parse;
pub mod resolve;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::Result;
use crate::paths::SshPaths;
use crate::types::{Diagnostic, Severity};

pub use resolve::ResolvedHost;

/// SSH config file operations.
///
/// Obtained from [`SshManager::config()`](crate::SshManager::config).
pub struct ConfigService<'a> {
    paths: &'a SshPaths,
}

impl<'a> ConfigService<'a> {
    pub(crate) fn new(paths: &'a SshPaths) -> Self {
        Self { paths }
    }

    /// Load and parse the SSH config into a lossless AST.
    ///
    /// If the config file does not exist, returns an empty AST.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the config file exists but cannot be read.
    pub async fn load(&self) -> Result<ast::ConfigAst> {
        let path = self.paths.config_path();
        if !path.exists() {
            return Ok(ast::ConfigAst { nodes: Vec::new() });
        }
        let content = tokio::fs::read_to_string(&path).await?;
        Ok(ast::parse(&content))
    }

    /// Save the AST back to the config file.
    ///
    /// Writes the lossless string representation and ensures the file
    /// has appropriate permissions (0o600 — owner read/write only).
    /// OpenSSH requires user config not be writable by others; 0o600 is
    /// the strictest correct permission.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigWriteFailed`] if the atomic write (temp
    /// file + rename) fails, or [`Error::Io`] if permissions cannot be set.
    pub async fn save(&self, ast: &ast::ConfigAst) -> Result<()> {
        let path = self.paths.config_path();
        let content = ast.to_string_lossless();

        // Create a backup of the existing config before overwriting.
        if path.exists() {
            let backup_path = path.with_extension("config.bak");
            if let Err(e) = std::fs::copy(path, &backup_path) {
                tracing::warn!(
                    "failed to back up config to {}: {e}",
                    backup_path.display()
                );
            }
        }

        // Atomic write: write to temp file, then rename.
        let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        let tmp_path = parent.join(format!(
            ".config.tmp.{}.{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        tokio::fs::write(&tmp_path, &content).await?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            tokio::fs::set_permissions(&tmp_path, perms).await?;
        }

        tokio::fs::rename(&tmp_path, path).await.map_err(|e| {
            // Clean up temp file on rename failure.
            let _ = std::fs::remove_file(&tmp_path);
            crate::Error::ConfigWriteFailed(format!("failed to rename config: {e}"))
        })?;

        Ok(())
    }

    /// Get a resolved [`ResolvedHost`] for the given alias.
    ///
    /// Performs full resolution including Include expansion and token expansion.
    /// If `CanonicalizeHostname` is enabled, a second resolution pass is
    /// performed using the resolved `HostName` as the lookup key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigIncludeCycle`] if an Include chain forms a
    /// cycle, or [`Error::Io`] if the config file cannot be read.
    pub async fn resolve_host(&self, host: &str) -> Result<ResolvedHost> {
        resolve::resolve(self.paths.ssh_dir(), host, None).await
    }

    /// Parse the SSH config using ssh2-config-rs for typed access.
    ///
    /// Returns the ssh2-config-rs [`ssh2_config_rs::SshConfig`] which supports
    /// `.query(host)` for resolving parameters.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigParseFailed`] if the config file cannot be
    /// parsed, or [`Error::Io`] if it cannot be read.
    pub async fn parse_typed(&self) -> Result<ssh2_config_rs::SshConfig> {
        parse::parse_config(self.paths.config_path()).await
    }

    /// Get a directive value for a host from the AST.
    ///
    /// Uses first-match-wins semantics.
    pub fn get_host_directive(ast: &ast::ConfigAst, host: &str, key: &str) -> Option<String> {
        directives::get_directive(ast, host, key)
    }

    /// Get all directives for a host.
    pub fn get_all_host_directives(ast: &ast::ConfigAst, host: &str) -> Vec<(String, String)> {
        directives::get_all_directives(ast, host)
    }

    /// Add a new Host block to the AST.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DuplicateHost`] if a Host block with the given
    /// name already exists.
    pub fn add_host(
        ast: &mut ast::ConfigAst,
        name: &str,
        directives: Vec<(String, String)>,
    ) -> Result<()> {
        editor::add_host(ast, name, directives)
    }

    /// Remove a Host block from the AST by name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HostNotFound`] if no Host block matches the given name.
    pub fn remove_host(ast: &mut ast::ConfigAst, name: &str) -> Result<()> {
        editor::remove_host(ast, name)
    }

    /// Rename a Host block.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HostNotFound`] if no Host block matches `old_name`,
    /// or [`Error::DuplicateHost`] if a block with `new_name` already exists.
    pub fn rename_host(ast: &mut ast::ConfigAst, old_name: &str, new_name: &str) -> Result<()> {
        editor::rename_host(ast, old_name, new_name)
    }

    /// Add a managed block (or replace an existing one).
    pub fn upsert_managed_block(
        ast: &mut ast::ConfigAst,
        name: &str,
        directives: Vec<(String, String)>,
    ) {
        managed::upsert_managed_block(ast, name, directives);
    }

    /// Remove a managed block by name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ManagedBlockNotFound`] if no managed block with
    /// the given name exists.
    pub fn remove_managed_block(ast: &mut ast::ConfigAst, name: &str) -> Result<()> {
        managed::remove_managed_block(ast, name)
    }

    /// List all managed block names.
    pub fn list_managed_blocks(ast: &ast::ConfigAst) -> Vec<String> {
        managed::list_managed_blocks(ast)
    }

    /// Ensure the config file exists (touch it if not).
    ///
    /// Creates the `~/.ssh` directory and an empty config file if either
    /// is missing.  On Unix, sets directory permissions to `0o700` and
    /// file permissions to `0o600`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if directory creation or file writing fails.
    pub async fn ensure_config_file(&self) -> Result<()> {
        let path = self.paths.config_path();
        if !path.exists() {
            // Ensure ~/.ssh directory exists.
            tokio::fs::create_dir_all(self.paths.ssh_dir()).await?;
            tokio::fs::write(&path, "").await?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
                tokio::fs::set_permissions(
                    self.paths.ssh_dir(),
                    std::fs::Permissions::from_mode(0o700),
                )
                .await?;
            }
        }
        Ok(())
    }

    /// Get the path to the config file.
    pub fn config_path(&self) -> &Path {
        self.paths.config_path()
    }

    /// Load, modify, and save the config atomically.
    ///
    /// Takes a closure that mutates the AST. Loads before, saves after.
    ///
    /// # Errors
    ///
    /// Returns any error from loading, from the mutation closure, or from
    /// saving.  See [`Self::load`] and [`Self::save`] for specifics.
    pub async fn edit<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&mut ast::ConfigAst) -> Result<()>,
    {
        self.ensure_config_file().await?;
        let mut ast = self.load().await?;
        f(&mut ast)?;
        self.save(&ast).await
    }

    /// Run config-specific diagnostics on the loaded SSH config.
    ///
    /// Checks for:
    /// 1. `ProxyCommand` / `ProxyJump` conflicts in the same Host block.
    /// 2. Duplicate Host aliases across blocks.
    /// 3. `Host *` placed before specific Host blocks.
    /// 4. `IdentityFile` paths that do not exist on disk.
    /// 5. `IdentityFile` paths pointing to `.pub` files (should be the private key).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the config file cannot be read.
    pub async fn diagnose(&self) -> Result<Vec<Diagnostic>> {
        let ast = self.load().await?;
        let ssh_dir = self.paths.ssh_dir();
        let mut diagnostics = Vec::new();

        // Tracks first-seen header for each host pattern (duplicate detection).
        let mut seen_patterns: HashMap<String, String> = HashMap::new();

        // Tracks `Host *` ordering relative to specific blocks.
        let mut star_index: Option<usize> = None;
        let mut last_specific_index: Option<usize> = None;

        for (i, node) in ast.nodes.iter().enumerate() {
            let ast::ConfigNode::HostBlock(b) = node
            else {
                continue;
            };

            check_proxy_conflict(&b.header, &b.nodes, &mut diagnostics);
            check_duplicate_aliases(&b.header, &b.patterns, &mut seen_patterns, &mut diagnostics);

            // Track Host * ordering.
            if b.patterns.iter().any(|p| p == "*") {
                if star_index.is_none() {
                    star_index = Some(i);
                }
            } else if !b.patterns.is_empty() {
                last_specific_index = Some(i);
            }

            check_identity_files(&b.header, &b.nodes, ssh_dir, &mut diagnostics);
        }

        check_host_star_placement(star_index, last_specific_index, &mut diagnostics);

        Ok(diagnostics)
    }
}

/// Check for ProxyCommand/ProxyJump conflict in a Host block.
fn check_proxy_conflict(
    header: &str,
    nodes: &[ast::ConfigNode],
    diagnostics: &mut Vec<Diagnostic>,
) {
    let has_proxy_command = nodes.iter().any(|n| {
        matches!(
            n,
            ast::ConfigNode::Directive(d)
                if d.keyword.eq_ignore_ascii_case("ProxyCommand")
        )
    });
    let has_proxy_jump = nodes.iter().any(|n| {
        matches!(
            n,
            ast::ConfigNode::Directive(d)
                if d.keyword.eq_ignore_ascii_case("ProxyJump")
        )
    });
    if has_proxy_command && has_proxy_jump {
        diagnostics.push(Diagnostic {
            id: "config_proxy_conflict",
            severity: Severity::Warning,
            message: format!(
                "Host block '{header}' has both ProxyCommand and ProxyJump set",
            ),
            hint: Some(
                "ProxyJump takes precedence over ProxyCommand; \
                 remove one to avoid confusion"
                    .into(),
            ),
            module: "config",
        });
    }
}

/// Check for duplicate Host aliases.
fn check_duplicate_aliases(
    header: &str,
    patterns: &[String],
    seen_patterns: &mut HashMap<String, String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for pat in patterns {
        if pat == "*" {
            continue;
        }
        if let Some(first_header) = seen_patterns.get(pat) {
            diagnostics.push(Diagnostic {
                id: "config_duplicate_alias",
                severity: Severity::Warning,
                message: format!(
                    "Host alias '{pat}' appears in both '{first_header}' and '{header}'",
                ),
                hint: Some(format!(
                    "Merge or remove the duplicate entry for '{pat}'",
                )),
                module: "config",
            });
        } else {
            seen_patterns.insert(pat.clone(), header.to_owned());
        }
    }
}

/// Check IdentityFile directives for .pub references and missing files.
fn check_identity_files(
    header: &str,
    nodes: &[ast::ConfigNode],
    ssh_dir: &Path,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for child in nodes {
        if let ast::ConfigNode::Directive(d) = child
            && d.keyword.eq_ignore_ascii_case("IdentityFile")
        {
            // Points to a .pub file?
            if d.value.to_lowercase().ends_with(".pub") {
                diagnostics.push(Diagnostic {
                    id: "config_identity_pub",
                    severity: Severity::Warning,
                    message: format!(
                        "IdentityFile '{}' in '{header}' points to a public key \
                         (.pub file)",
                        d.value,
                    ),
                    hint: Some(
                        "IdentityFile should reference the private key, \
                         not the .pub file"
                            .into(),
                    ),
                    module: "config",
                });
            }

            // Does the file exist?
            let expanded = expand_identity_path(&d.value, ssh_dir);
            if !expanded.exists() {
                diagnostics.push(Diagnostic {
                    id: "config_identity_missing",
                    severity: Severity::Warning,
                    message: format!(
                        "IdentityFile '{}' in '{header}' does not exist \
                         (resolved: {})",
                        d.value,
                        expanded.display()
                    ),
                    hint: Some(format!(
                        "Generate the missing key or update the \
                         IdentityFile entry in '{header}'",
                    )),
                    module: "config",
                });
            }
        }
    }
}

/// Emit Host * placement diagnostic if it appears before specific blocks.
fn check_host_star_placement(
    star_index: Option<usize>,
    last_specific_index: Option<usize>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if let (Some(star), Some(last)) = (star_index, last_specific_index)
        && star < last
    {
        diagnostics.push(Diagnostic {
            id: "config_host_star_placement",
            severity: Severity::Warning,
            message:
                "'Host *' appears before specific Host blocks; \
                 later blocks cannot override its defaults"
                    .into(),
            hint: Some(
                "Move 'Host *' to the end of the config file so \
                 specific blocks take precedence"
                    .into(),
            ),
            module: "config",
        });
    }
}

/// Expand an `IdentityFile` value to an absolute path on disk.
///
/// Handles `~` expansion and relative paths (resolved against the SSH
/// directory, matching OpenSSH behaviour).  Delegates to
/// [`crate::paths::expand_path`].
pub(crate) fn expand_identity_path(raw: &str, ssh_dir: &Path) -> PathBuf {
    crate::paths::expand_path(raw, ssh_dir)
}

/// Check if a hostname matches any of the given SSH config patterns.
/// Public re-export for use in other modules.
pub fn host_matches(host: &str, patterns: &[impl AsRef<str>]) -> bool {
    directives::host_matches_patterns(host, patterns)
}

/// Check if a path is inside the `~/.ssh` directory.
pub fn is_in_ssh_dir(path: &Path, ssh_dir: &Path) -> bool {
    path.starts_with(ssh_dir)
}

#[cfg(test)]
#[path = "mod.test.rs"]
mod tests;
