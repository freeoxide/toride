//! SSH config file parsing, editing, and host resolution.

pub mod ast;
pub mod cache;
pub mod directives;
pub mod editor;
pub mod managed;
mod parse;
pub mod resolve;
pub mod sshd;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use toride_ssh_core::Result;
use toride_ssh_core::SshPaths;
use toride_ssh_core::{Diagnostic, DiagnosticSeverity, Error};

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
    /// The AST is shared through an [`Arc`], so repeated loads do not
    /// deep-clone every node; use [`Self::load_owned`] when you need to
    /// mutate.
    ///
    /// # Errors
    /// [`Error::Io`] when the file is unreadable.
    pub async fn load(&self) -> Result<Arc<ast::ConfigAst>> {
        let path = self.paths.config_path();
        if !path.exists() {
            return Ok(Arc::new(ast::ConfigAst { nodes: Vec::new() }));
        }
        let path = path.to_path_buf();
        let ast = tokio::task::spawn_blocking(move || cache::load_cached_ast(&path))
            .await
            .map_err(|e| Error::TaskFailed(e.to_string()))??;
        Ok(ast)
    }

    /// Load a deep copy of the AST for mutation (see [`Self::load`]).
    ///
    /// # Errors
    /// [`Error::Io`] when the file is unreadable.
    pub async fn load_owned(&self) -> Result<ast::ConfigAst> {
        Ok((*self.load().await?).clone())
    }

    /// Save the AST atomically with `0o600` permissions.
    ///
    /// The write goes through [`toride_fs::atomic_write_with_perms`]
    /// (`O_EXCL` temp file, fsync, rename, chmod), keeping the `.bak` copy of
    /// the previous config when one exists.
    ///
    /// # Errors
    /// [`Error::ConfigWriteFailed`] on write or rename failure.
    pub async fn save(&self, ast: &ast::ConfigAst) -> Result<()> {
        let path = self.paths.config_path();
        let content = ast.to_string_lossless();

        if path.exists() {
            let backup_path = path.with_extension("config.bak");
            if let Err(e) = std::fs::copy(path, &backup_path) {
                tracing::warn!("failed to back up config to {}: {e}", backup_path.display());
            }
        }

        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || {
            toride_fs::atomic_write_with_perms(&path, &content, 0o600)
        })
        .await
        .map_err(|e| Error::TaskFailed(e.to_string()))?
        .map_err(|e| Error::ConfigWriteFailed(e.to_string()))?;

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
    /// The whole load-mutate-save critical section is serialized across
    /// processes by an advisory `flock` on the lock file named by
    /// [`config_edit_lock_path`], mirroring [`sshd::edit`]'s lock
    /// discipline: two concurrent editors cannot each load the original,
    /// apply their edit, and have the second save clobber the first.
    ///
    /// # Errors
    /// From any step: ensure, lock, load, `f`, or save.
    pub async fn edit<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&mut ast::ConfigAst) -> Result<()>,
    {
        self.ensure_config_file().await?;
        edit_under_lock(self.paths.config_path(), || async {
            let mut ast = self.load_owned().await?;
            f(&mut ast)?;
            self.save(&ast).await
        })
        .await
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

/// Lock file path for a config file, shared by every in-process and
/// cross-process writer (`<config>.toride.lock` beside the config).
#[must_use]
pub fn config_edit_lock_path(config_path: &Path) -> PathBuf {
    let mut name = config_path.file_name().unwrap_or_default().to_os_string();
    name.push(".toride.lock");
    config_path.with_file_name(name)
}

/// Run `f` while holding the cross-process edit lock for `config_path`.
///
/// The exclusive `flock` guard is acquired on a lock file named by
/// [`config_edit_lock_path`] **before** `f` starts and held until it
/// finishes, so a load-mutate-save critical section (see
/// [`ConfigService::edit`]) cannot interleave with another writer. The
/// acquire is a `try_write` retry loop with a small sleep instead of a
/// blocking `flock` wait: a blocking wait on an async worker thread
/// deadlocks a bounded runtime whenever the lock holder needs that same
/// worker to finish. The guard and its backing file are plain locals
/// dropped on every return path.
///
/// # Errors
/// [`Error::Io`] when the lock file cannot be opened, plus whatever `f`
/// returns.
pub async fn edit_under_lock<F, Fut, T>(config_path: &Path, f: F) -> Result<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let lock_path = config_edit_lock_path(config_path);
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Io(std::io::Error::other(format!("config edit lock: {e}"))))?;
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| {
            Error::Io(std::io::Error::other(format!(
                "config edit lock: cannot open {}: {e}",
                lock_path.display()
            )))
        })?;
    let mut lock = fd_lock::RwLock::new(file);
    let _guard = loop {
        match lock.try_write() {
            Ok(guard) => break guard,
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(5)).await,
        }
    };
    tracing::debug!(path = %lock_path.display(), "config edit lock acquired");

    f().await
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
            severity: DiagnosticSeverity::Warning,
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
                severity: DiagnosticSeverity::Warning,
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
                    severity: DiagnosticSeverity::Warning,
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
                    severity: DiagnosticSeverity::Warning,
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
            severity: DiagnosticSeverity::Warning,
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
