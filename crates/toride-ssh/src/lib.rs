#![warn(missing_docs)]
#![allow(dead_code, reason = "scaffolding for modules under active development")]
#![expect(
    clippy::must_use_candidate,
    reason = "service methods are call-and-forget; callers rarely use return"
)]
#![expect(
    clippy::doc_markdown,
    reason = "SSH-specific terms like ed25519 trigger false positives"
)]

//! `toride-ssh` — async SSH manager library.
//!
//! This is the **facade crate** that re-exports all sub-crates behind a
//! unified API. The entry point is [`SshManager`], which resolves `~/.ssh`
//! paths and provides accessor methods for each subsystem.
//!
//! # Subsystem accessors
//!
//! - [`SshManager::keys`] — key generation, inventory, repair
//! - [`SshManager::config`] — config parsing, editing, resolution
//! - [`SshManager::agent`] — SSH agent interaction *(feature: `agent`)*
//! - [`SshManager::authorized_keys`] — authorized_keys management *(feature: `authorized-keys`)*
//! - [`SshManager::doctor`] — diagnostic checks *(feature: `doctor`)*
//! - [`SshManager::known_hosts`] — known_hosts management *(feature: `known-hosts`)*
//! - [`SshManager::forward`] — port forwarding via ControlMaster *(feature: `forward`)*
//! - [`SshManager::certificate`] — SSH certificate/CA operations *(feature: `certificate`)*
//!
//! # Testing with a custom CLI runner
//!
//! Use [`SshManager::with_cli_runner`] to inject a [`MockCliRunner`] so that
//! no real SSH processes are spawned during tests.

// Re-export core types (Error, Result, SshKey, CliRunner, etc.)
pub use toride_ssh_core::*;

// Re-export config subsystem
pub use toride_ssh_config as config;

// Re-export key subsystem
pub use toride_ssh_key as key;

// Feature-gated subsystem re-exports
#[cfg(feature = "agent")]
pub use toride_ssh_agent as agent;
#[cfg(feature = "authorized-keys")]
pub use toride_ssh_authorized_keys as authorized_keys;
#[cfg(feature = "certificate")]
pub use toride_ssh_certificate as certificate;
#[cfg(feature = "doctor")]
pub use toride_ssh_doctor as doctor;
#[cfg(feature = "forward")]
pub use toride_ssh_forward as forward;
#[cfg(feature = "known-hosts")]
pub use toride_ssh_known_hosts as known_hosts;

use std::sync::Arc;

/// Entry point for all SSH management operations.
///
/// `SshManager` is cheaply [`Clone`](Clone)-able and safe to share
/// across async tasks. Each subsystem is accessed via a dedicated
/// accessor method (e.g. [`keys()`](Self::keys), [`config()`](Self::config)).
///
/// # Examples
///
/// ```rust,no_run
/// use toride_ssh::SshManager;
///
/// # async fn example() -> toride_ssh::Result<()> {
/// let mgr = SshManager::new()?;
/// let keys = mgr.keys().list().await?;
/// println!("Found {} keys", keys.len());
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct SshManager {
    paths: SshPaths,
    runner: Arc<dyn CliRunner>,
}

impl Default for SshManager {
    /// Return a best-effort manager using [`DefaultCliRunner`].
    ///
    /// Falls back to `~/.ssh` if the home directory is unavailable.
    fn default() -> Self {
        Self {
            paths: SshPaths::default(),
            runner: Arc::new(DefaultCliRunner),
        }
    }
}

impl SshManager {
    /// Create a new manager resolving `~/.ssh` from the user's home directory.
    ///
    /// Uses [`DefaultCliRunner`] for all CLI operations. For tests, prefer
    /// [`with_cli_runner`](Self::with_cli_runner) with a [`MockCliRunner`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::HomeNotFound`] if the user's home directory cannot
    /// be resolved.
    pub fn new() -> Result<Self> {
        let paths = SshPaths::new()?;
        Ok(Self {
            paths,
            runner: Arc::new(DefaultCliRunner),
        })
    }

    /// Create a manager with a custom [`CliRunner`].
    ///
    /// This is the primary injection point for tests: pass a
    /// [`MockCliRunner`] to control command execution without spawning
    /// real SSH processes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HomeNotFound`] if the user's home directory cannot
    /// be resolved.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::sync::Arc;
    /// use toride_ssh::{SshManager, MockCliRunner};
    ///
    /// # fn example() -> toride_ssh::Result<()> {
    /// let mock = Arc::new(MockCliRunner::new());
    /// mock.set_tool_exists("ssh-keygen", true);
    /// let mgr = SshManager::with_cli_runner(mock)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_cli_runner(runner: Arc<dyn CliRunner>) -> Result<Self> {
        let paths = SshPaths::new()?;
        Ok(Self { paths, runner })
    }

    /// Key management operations.
    pub fn keys(&self) -> key::KeyService<'_> {
        key::KeyService::new(&self.paths, &*self.runner)
    }

    /// SSH config operations.
    pub fn config(&self) -> config::ConfigService<'_> {
        config::ConfigService::new(&self.paths)
    }

    /// SSH agent operations.
    #[cfg(feature = "agent")]
    pub fn agent(&self) -> agent::AgentService<'_> {
        agent::AgentService::new(&self.paths, &*self.runner)
    }

    /// `authorized_keys` management (listing, adding, removing keys).
    #[cfg(feature = "authorized-keys")]
    pub fn authorized_keys(&self) -> authorized_keys::AuthorizedKeysService<'_> {
        authorized_keys::AuthorizedKeysService::new(&self.paths)
    }

    /// Diagnostic checks.
    #[cfg(feature = "doctor")]
    pub fn doctor(&self) -> doctor::DoctorService<'_> {
        doctor::DoctorService::new(&self.paths, &*self.runner)
    }

    /// Known hosts management (listing, scanning, adding, removing).
    #[cfg(feature = "known-hosts")]
    pub fn known_hosts(&self) -> known_hosts::KnownHostsService<'_> {
        known_hosts::KnownHostsService::new(&self.paths, &*self.runner)
    }

    /// SSH certificate and CA operations (inspection, validity, KRL).
    #[cfg(feature = "certificate")]
    pub fn certificate(&self) -> certificate::CertificateService {
        certificate::CertificateService::new()
    }

    /// Port forwarding management via ControlMaster.
    #[cfg(feature = "forward")]
    pub fn forward(&self) -> forward::ForwardService<'_> {
        forward::ForwardService::new(&self.paths)
    }
}
