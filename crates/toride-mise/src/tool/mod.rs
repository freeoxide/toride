//! Tool management modules for mise.
//!
//! This directory-level module groups all tool-related functionality:
//!
//! - **spec** — Parsing of mise tool specification strings.
//! - **registry** — Searching the mise tool registry.
//! - **remote** — Querying remote tool versions available for install.
//! - **installed** — Inspecting locally installed tools and their status.
//! - **active** — Listing currently active (resolved) tools.
//! - **install** — Installing and activating tool versions.
//! - **uninstall** — Uninstalling and deactivating tool versions.
//! - **upgrade** — Upgrading installed tools to newer versions.
//! - **prune** — Removing unused tool installations.
//! - **plugin** — Managing mise plugins (install, link, uninstall, update).
//! - **alias** — Managing tool aliases.
//! - **task** — Managing and running mise tasks.

pub mod active;
pub mod alias;
pub mod backend;
pub mod cache;
pub mod installed;
pub mod install;
pub mod plugin;
pub mod prune;
pub mod registry;
pub mod remote;
pub mod spec;
pub mod task;
pub mod uninstall;
pub mod upgrade;

pub use spec::{ToolOptionValue, ToolSpec, VersionRequest};
pub use registry::RegistryTool;
pub use installed::{ToolStatus, ListToolsRequest};
pub use active::{ActiveTool, ListActiveRequest};
pub use install::{InstallRequest, UseRequest, UseScope};
pub use uninstall::{UninstallRequest, UnuseRequest};
pub use upgrade::{OutdatedTool, UpgradeRequest};
pub use prune::{PrunePlan, PruneRequest};
pub use remote::{ListRemoteRequest, RemoteVersion};
pub use backend::BackendInfo;
pub use cache::CachePruneRequest;
pub use alias::ToolAlias;
pub use plugin::{PluginInfo, PluginInstallRequest};
pub use task::{TaskInfo, TaskRunRequest};
