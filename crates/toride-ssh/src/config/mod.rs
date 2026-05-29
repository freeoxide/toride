mod ast;
mod directives;
mod editor;
mod managed;
mod parse;
mod resolve;

use std::path::Path;

use crate::paths::SshPaths;
use crate::Result;

pub use resolve::ResolvedHost;

/// SSH config file operations.
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
    /// has appropriate permissions (0o644).
    pub async fn save(&self, ast: &ast::ConfigAst) -> Result<()> {
        let path = self.paths.config_path();
        let content = ast.to_string_lossless();
        tokio::fs::write(&path, &content).await?;

        // Set permissions to 0o644 (owner read/write, group/other read).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o644);
            std::fs::set_permissions(&path, perms)?;
        }

        Ok(())
    }

    /// Get a resolved [`ResolvedHost`] for the given alias.
    ///
    /// Performs full resolution including Include expansion and token expansion.
    pub async fn resolve_host(&self, host: &str) -> Result<ResolvedHost> {
        resolve::resolve(self.paths.ssh_dir(), host).await
    }

    /// Parse the SSH config using ssh2-config-rs for typed access.
    ///
    /// Returns the ssh2-config-rs [`ssh2_config_rs::SshConfig`] which supports
    /// `.query(host)` for resolving parameters.
    pub async fn parse_typed(&self) -> Result<ssh2_config_rs::SshConfig> {
        parse::parse_config(&self.paths.config_path()).await
    }

    /// Get a directive value for a host from the AST.
    ///
    /// Uses first-match-wins semantics.
    pub fn get_host_directive(
        ast: &ast::ConfigAst,
        host: &str,
        key: &str,
    ) -> Option<String> {
        directives::get_directive(ast, host, key)
    }

    /// Get all directives for a host.
    pub fn get_all_host_directives(
        ast: &ast::ConfigAst,
        host: &str,
    ) -> Vec<(String, String)> {
        directives::get_all_directives(ast, host)
    }

    /// Add a new Host block to the AST.
    pub fn add_host(
        ast: &mut ast::ConfigAst,
        name: &str,
        directives: Vec<(String, String)>,
    ) -> Result<()> {
        editor::add_host(ast, name, directives)
    }

    /// Remove a Host block from the AST by name.
    pub fn remove_host(ast: &mut ast::ConfigAst, name: &str) -> Result<()> {
        editor::remove_host(ast, name)
    }

    /// Rename a Host block.
    pub fn rename_host(
        ast: &mut ast::ConfigAst,
        old_name: &str,
        new_name: &str,
    ) -> Result<()> {
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
    pub fn remove_managed_block(ast: &mut ast::ConfigAst, name: &str) -> Result<()> {
        managed::remove_managed_block(ast, name)
    }

    /// List all managed block names.
    pub fn list_managed_blocks(ast: &ast::ConfigAst) -> Vec<String> {
        managed::list_managed_blocks(ast)
    }

    /// Ensure the config file exists (touch it if not).
    pub async fn ensure_config_file(&self) -> Result<()> {
        let path = self.paths.config_path();
        if !path.exists() {
            // Ensure ~/.ssh directory exists.
            tokio::fs::create_dir_all(self.paths.ssh_dir()).await?;
            tokio::fs::write(&path, "").await?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
                std::fs::set_permissions(
                    self.paths.ssh_dir(),
                    std::fs::Permissions::from_mode(0o700),
                )?;
            }
        }
        Ok(())
    }

    /// Get the path to the config file.
    pub fn config_path(&self) -> std::path::PathBuf {
        self.paths.config_path()
    }

    /// Load, modify, and save the config atomically.
    ///
    /// Takes a closure that mutates the AST. Loads before, saves after.
    pub async fn edit<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&mut ast::ConfigAst) -> Result<()>,
    {
        self.ensure_config_file().await?;
        let mut ast = self.load().await?;
        f(&mut ast)?;
        self.save(&ast).await
    }
}

/// Check if a hostname matches any of the given SSH config patterns.
/// Public re-export for use in other modules.
pub fn host_matches(host: &str, patterns: &[String]) -> bool {
    directives::host_matches_patterns(host, patterns)
}

/// Check if a path is inside the `~/.ssh` directory.
pub fn is_in_ssh_dir(path: &Path, ssh_dir: &Path) -> bool {
    path.starts_with(ssh_dir)
}
