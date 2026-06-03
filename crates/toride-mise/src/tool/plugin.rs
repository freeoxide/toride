//! Plugin management via `mise plugins`.
//!
//! Exposes [`PluginInfo`] and [`PluginInstallRequest`] for plugin operations
//! and adds methods on [`Mise`] for listing, installing, linking,
//! uninstalling, and updating mise plugins.

use camino::Utf8PathBuf;

use crate::client::Mise;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// JSON response types
// ---------------------------------------------------------------------------

/// A single plugin as reported by `mise plugins ls --json`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PluginInfo {
    /// The plugin name (e.g. `"node"`, `"python"`).
    pub name: String,
    /// The URL or path the plugin was installed from, if known.
    #[serde(default)]
    pub url: Option<String>,
    /// Whether the plugin is currently installed.
    #[serde(default)]
    pub installed: bool,
}

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

/// Parameters for a plugin install operation.
#[derive(Debug, Clone)]
pub struct PluginInstallRequest {
    /// The plugin name to install.
    pub name: String,
    /// Optional URL to install the plugin from.
    pub url: Option<String>,
    /// Pass `--force` to reinstall if already present.
    pub force: bool,
    /// Pass `--all` to install all plugins listed in config.
    pub all: bool,
    /// Pass `--verbose` for detailed output.
    pub verbose: bool,
}

/// Parameters for a plugin link operation.
///
/// Construct with [`PluginLinkRequest::new`].
#[derive(Debug, Clone)]
pub struct PluginLinkRequest {
    /// The plugin name to create.
    pub name: String,
    /// The filesystem path to link as a plugin.
    pub path: Utf8PathBuf,
}

impl PluginLinkRequest {
    /// Create a new `PluginLinkRequest` for the given name and path.
    pub fn new(name: impl Into<String>, path: impl Into<Utf8PathBuf>) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Mise methods
// ---------------------------------------------------------------------------

impl Mise {
    /// Return a [`Plugins`] helper that provides the spec-recommended API shape.
    ///
    /// The returned helper borrows `self`, so it can be used like:
    ///
    /// ```rust,ignore
    /// let plugins = mise.plugins();
    /// let list = plugins.list().await?;
    /// ```
    pub fn plugins(&self) -> Plugins<'_> {
        Plugins { mise: self }
    }

    /// List locally installed plugins.
    ///
    /// Invokes `mise plugins ls --json`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn plugins_list(&self) -> MiseResult<Vec<PluginInfo>> {
        self.run_json(["plugins", "ls", "--json"]).await
    }

    /// List all remote plugins available in the mise registry.
    ///
    /// Invokes `mise plugins ls-remote`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn plugins_list_remote(&self) -> MiseResult<Vec<PluginInfo>> {
        self.run_json(["plugins", "ls-remote", "--json"]).await
    }

    /// Install a mise plugin.
    ///
    /// Builds the appropriate flags from [`PluginInstallRequest`] and invokes
    /// `mise plugins install`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the installation fails.
    pub async fn plugin_install(&self, req: PluginInstallRequest) -> MiseResult<()> {
        let mut args: Vec<String> = vec!["plugins".into(), "install".into()];

        if req.force {
            args.push("--force".into());
        }
        if req.all {
            args.push("--all".into());
        }
        if req.verbose {
            args.push("--verbose".into());
        }

        args.push(req.name.clone());
        if let Some(ref url) = req.url {
            args.push(url.clone());
        }

        self.run_checked(&args).await?;
        Ok(())
    }

    /// Link a local directory as a mise plugin.
    ///
    /// Invokes `mise plugins link <name> <path>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the link operation fails.
    pub async fn plugin_link(&self, name: &str, path: Utf8PathBuf) -> MiseResult<()> {
        self.run_checked(["plugins", "link", name, path.as_str()])
            .await?;
        Ok(())
    }

    /// Link a local directory as a mise plugin using a [`PluginLinkRequest`].
    ///
    /// Invokes `mise plugins link <name> <path>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the link operation fails.
    pub async fn plugin_link_request(&self, req: PluginLinkRequest) -> MiseResult<()> {
        self.run_checked(["plugins", "link", &req.name, req.path.as_str()])
            .await?;
        Ok(())
    }

    /// Uninstall a mise plugin.
    ///
    /// Invokes `mise plugins uninstall <name>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the uninstallation fails.
    pub async fn plugin_uninstall(&self, name: &str) -> MiseResult<()> {
        self.run_checked(["plugins", "uninstall", name]).await?;
        Ok(())
    }

    /// Update one or more installed plugins.
    ///
    /// If `names` is empty, all installed plugins are updated.
    ///
    /// Invokes `mise plugins update [names…]`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the update fails.
    pub async fn plugin_update(&self, names: &[String]) -> MiseResult<()> {
        let mut args: Vec<String> = vec!["plugins".into(), "update".into()];
        for name in names {
            args.push(name.clone());
        }
        self.run_checked(&args).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Plugins helper — spec-recommended API shape
// ---------------------------------------------------------------------------

/// Helper that provides the spec-recommended `mise.plugins().list()` API shape.
///
/// Obtained via [`Mise::plugins`]. Each method delegates to the corresponding
/// method on [`Mise`].
pub struct Plugins<'a> {
    mise: &'a Mise,
}

impl Plugins<'_> {
    /// List locally installed plugins.
    ///
    /// Invokes `mise plugins ls --json`.
    pub async fn list(&self) -> MiseResult<Vec<PluginInfo>> {
        self.mise.plugins_list().await
    }

    /// Install a mise plugin.
    pub async fn install(&self, req: PluginInstallRequest) -> MiseResult<()> {
        self.mise.plugin_install(req).await
    }

    /// Link a local directory as a mise plugin.
    pub async fn link(&self, req: PluginLinkRequest) -> MiseResult<()> {
        self.mise.plugin_link_request(req).await
    }

    /// Uninstall a mise plugin.
    pub async fn uninstall(&self, name: &str) -> MiseResult<()> {
        self.mise.plugin_uninstall(name).await
    }

    /// Update one or more installed plugins.
    pub async fn update(&self, names: &[String]) -> MiseResult<()> {
        self.mise.plugin_update(names).await
    }
}
