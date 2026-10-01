//! SSH config file parsing, editing, and host resolution.

pub mod ast;
pub mod cache;
mod directives;
mod editor;
mod managed;
mod parse;
pub mod resolve;
pub mod sshd;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use toride_ssh_core::Result;
use toride_ssh_core::SshPaths;
use toride_ssh_core::{Diagnostic, Error, Severity};

pub use resolve::ResolvedHost;

/// SSH config file operations.
pub struct ConfigService<'a> {
    paths: &'a SshPaths,
}

impl<'a> ConfigService<'a> {
    #[must_use]
    pub fn new(paths: &'a SshPaths) -> Self {
        Self { paths }
    }

    /// Load and parse the SSH config into a lossless AST (cached); returns an
    /// empty AST when the file is missing.
    ///
    /// # Errors
    /// [`Error::Io`] when the file is unreadable.
    pub async fn load(&self) -> Result<ast::ConfigAst> {
        let path = self.paths.config_path();
        if !path.exists() {
            return Ok(ast::ConfigAst { nodes: Vec::new() });
        }
        let path = path.to_path_buf();
        let ast = tokio::task::spawn_blocking(move || cache::load_cached_ast(&path))
            .await
            .map_err(|e| Error::TaskFailed(e.to_string()))??;
        Ok((*ast).clone())
    }

    /// Save the AST atomically with `0o600` permissions.
    ///
    /// # Errors
    /// [`Error::ConfigWriteFailed`] (write/rename) or [`Error::Io`] (chmod).
    pub async fn save(&self, ast: &ast::ConfigAst) -> Result<()> {
        let path = self.paths.config_path();
        let content = ast.to_string_lossless();

        if path.exists() {
            let backup_path = path.with_extension("config.bak");
            if let Err(e) = std::fs::copy(path, &backup_path) {
                tracing::warn!("failed to back up config to {}: {e}", backup_path.display());
            }
        }

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
            let _ = std::fs::remove_file(&tmp_path);
            toride_ssh_core::Error::ConfigWriteFailed(format!("failed to rename config: {e}"))
        })?;

        Ok(())
    }

    /// Resolve a host alias to a [`ResolvedHost`], expanding Includes and
    /// tokens.
    ///
    /// # Errors
    /// [`Error::ConfigIncludeCycle`] or [`Error::Io`].
    pub async fn resolve_host(&self, host: &str) -> Result<ResolvedHost> {
        resolve::resolve(self.paths.ssh_dir(), host, None).await
    }

    /// Parse the config into an [`ssh2_config_rs::SshConfig`] (supports
    /// `.query(host)`).
    ///
    /// # Errors
    /// [`Error::ConfigParseFailed`] or [`Error::Io`].
    pub async fn parse_typed(&self) -> Result<ssh2_config_rs::SshConfig> {
        parse::parse_config(self.paths.config_path()).await
    }

    /// Get a directive value for a host from the AST; first match wins.
    #[must_use]
    pub fn get_host_directive(ast: &ast::ConfigAst, host: &str, key: &str) -> Option<String> {
        directives::get_directive(ast, host, key)
    }

    /// Get all directives for a host.
    #[must_use]
    pub fn get_all_host_directives(ast: &ast::ConfigAst, host: &str) -> Vec<(String, String)> {
        directives::get_all_directives(ast, host)
    }

    /// Add a new Host block.
    ///
    /// # Errors
    /// [`Error::DuplicateHost`] if one with the given name already exists.
    pub fn add_host(
        ast: &mut ast::ConfigAst,
        name: &str,
        directives: Vec<(String, String)>,
    ) -> Result<()> {
        editor::add_host(ast, name, directives)
    }

    /// Remove a Host block by name.
    ///
    /// # Errors
    /// [`Error::HostNotFound`] if absent.
    pub fn remove_host(ast: &mut ast::ConfigAst, name: &str) -> Result<()> {
        editor::remove_host(ast, name)
    }

    /// Rename a Host block.
    ///
    /// # Errors
    /// [`Error::HostNotFound`] if `old_name` is absent, or
    /// [`Error::DuplicateHost`] if `new_name` exists.
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
    /// [`Error::ManagedBlockNotFound`] if absent.
    pub fn remove_managed_block(ast: &mut ast::ConfigAst, name: &str) -> Result<()> {
        managed::remove_managed_block(ast, name)
    }

    /// List all managed block names.
    #[must_use]
    pub fn list_managed_blocks(ast: &ast::ConfigAst) -> Vec<String> {
        managed::list_managed_blocks(ast)
    }

    /// Create `~/.ssh` (`0o700`) and the config file (`0o600`) if missing.
    ///
    /// # Errors
    /// [`Error::Io`] on failure.
    pub async fn ensure_config_file(&self) -> Result<()> {
        let path = self.paths.config_path();
        if !path.exists() {
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
    #[must_use]
    pub fn config_path(&self) -> &Path {
        self.paths.config_path()
    }

    /// Load, mutate via `f`, then save.
    ///
    /// # Errors
    /// From any step: ensure, load, `f`, or save.
    pub async fn edit<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&mut ast::ConfigAst) -> Result<()>,
    {
        self.ensure_config_file().await?;
        let mut ast = self.load().await?;
        f(&mut ast)?;
        self.save(&ast).await
    }

    /// Diagnose the config: proxy conflicts, duplicate aliases, `Host *`
    /// placement, and missing or `.pub` `IdentityFile`s.
    ///
    /// # Errors
    /// [`Error::Io`].
    pub async fn diagnose(&self) -> Result<Vec<Diagnostic>> {
        let ast = self.load().await?;
        let ssh_dir = self.paths.ssh_dir();
        let mut diagnostics = Vec::new();

        let mut seen_patterns: HashMap<String, String> = HashMap::new();

        let mut star_index: Option<usize> = None;
        let mut last_specific_index: Option<usize> = None;

        for (i, node) in ast.nodes.iter().enumerate() {
            let ast::ConfigNode::HostBlock(b) = node else {
                continue;
            };

            check_proxy_conflict(&b.header, &b.nodes, &mut diagnostics);
            check_duplicate_aliases(&b.header, &b.patterns, &mut seen_patterns, &mut diagnostics);

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
            message: format!("Host block '{header}' has both ProxyCommand and ProxyJump set"),
            hint: Some(
                "ProxyJump takes precedence over ProxyCommand; \
                 remove one to avoid confusion"
                    .into(),
            ),
            module: "config",
        });
    }
}

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
                hint: Some(format!("Merge or remove the duplicate entry for '{pat}'")),
                module: "config",
            });
        } else {
            seen_patterns.insert(pat.clone(), header.to_owned());
        }
    }
}

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
            message: "'Host *' appears before specific Host blocks; \
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

/// Expand `~` and resolve a relative `IdentityFile` value against `ssh_dir`.
#[must_use]
pub fn expand_identity_path(raw: &str, ssh_dir: &Path) -> PathBuf {
    toride_ssh_core::paths::expand_path(raw, ssh_dir)
}

/// Check if a hostname matches any of the given SSH config patterns.
pub fn host_matches(host: &str, patterns: &[impl AsRef<str>]) -> bool {
    directives::host_matches_patterns(host, patterns)
}

/// Check if a path is inside the `~/.ssh` directory.
#[must_use]
pub fn is_in_ssh_dir(path: &Path, ssh_dir: &Path) -> bool {
    path.starts_with(ssh_dir)
}

#[cfg(test)]
#[path = "mod.test.rs"]
mod tests;
