#![warn(missing_docs)]
#![expect(
    clippy::must_use_candidate,
    reason = "service methods are call-and-forget; callers rarely use return"
)]
#![expect(
    clippy::doc_markdown,
    reason = "SSH-specific terms like ed25519 trigger false positives"
)]

//! `toride-ssh`: async SSH manager library.
//!
//! This is the **facade crate** that re-exports all sub-crates behind a
//! unified API. The entry point is [`SshManager`], which resolves `~/.ssh`
//! paths and provides accessor methods for each subsystem.
//!
//! # Subsystem accessors
//!
//! - [`SshManager::keys`]: key generation, inventory, repair
//! - [`SshManager::config`]: config parsing, editing, resolution
//! - [`SshManager::agent`]: SSH agent interaction *(feature: `agent`)*
//! - [`SshManager::authorized_keys`]: authorized_keys management *(feature: `authorized-keys`)*
//! - [`SshManager::doctor`]: diagnostic checks *(feature: `doctor`)*
//! - [`SshManager::known_hosts`]: known_hosts management *(feature: `known-hosts`)*
//! - [`SshManager::forward`]: port forwarding via ControlMaster *(feature: `forward`)*
//! - [`SshManager::certificate`]: SSH certificate/CA operations *(feature: `certificate`)*
//! - [`SshManager::exec`]: remote command execution *(feature: `exec`)*
//! - [`SshManager::upload`]: file upload via sftp *(feature: `upload`)*
//!
//! # Testing without real SSH processes
//!
//! The [`CliRunner`]-backed subsystems (keys, agent, doctor, known-hosts)
//! take a [`MockCliRunner`] through [`SshManager::with_cli_runner`], so
//! they spawn nothing in tests. The `certificate` subsystem has no runner
//! injection: its operations spawn real `ssh-keygen` through
//! [`toride_ssh_core::runner::ssh_keygen`] whatever runner the manager
//! carries. The `exec` and `upload` subsystems are built on the separate
//! [`toride_runner::Runner`] trait instead: pass any runner (for example
//! `toride_runner::fake::FakeRunner`) to [`SshManager::exec_with`] or
//! [`SshManager::upload_with`], or construct
//! [`exec::ExecService`]/[`upload::UploadService`] directly.

pub use toride_ssh_core::*;

pub use toride_ssh_config as config;

pub use toride_ssh_key as key;

#[cfg(feature = "agent")]
pub use toride_ssh_agent as agent;
#[cfg(feature = "authorized-keys")]
pub use toride_ssh_authorized_keys as authorized_keys;
#[cfg(feature = "certificate")]
pub use toride_ssh_certificate as certificate;
#[cfg(feature = "doctor")]
pub use toride_ssh_doctor as doctor;
#[cfg(feature = "exec")]
pub use toride_ssh_exec as exec;
#[cfg(feature = "forward")]
pub use toride_ssh_forward as forward;
#[cfg(feature = "known-hosts")]
pub use toride_ssh_known_hosts as known_hosts;
#[cfg(feature = "upload")]
pub use toride_ssh_upload as upload;

use std::sync::Arc;

#[cfg(any(feature = "exec", feature = "upload"))]
use toride_runner::DuctRunner;

/// Entry point for all SSH management operations.
///
/// `SshManager` is cheaply [`Clone`]-able and safe to share
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
    /// This is the injection point for the `CliRunner`-backed subsystems
    /// (keys, agent, doctor, known-hosts): pass a [`MockCliRunner`] to
    /// control their command execution without spawning real SSH processes.
    /// The `certificate` subsystem takes no runner and spawns real
    /// `ssh-keygen` regardless of this setting; the `exec` and `upload`
    /// subsystems do not go through the [`CliRunner`], so inject their
    /// runner per service via [`Self::exec_with`] and [`Self::upload_with`]
    /// instead.
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

    /// Remote command execution over ssh, on the default duct runner.
    ///
    /// The default runner applies its 60 s fallback timeout to invocations
    /// without a spec timeout; set a longer cap with
    /// [`ExecService::with_timeout`](exec::ExecService::with_timeout), or
    /// inject a configured runner through [`Self::exec_with`].
    #[cfg(feature = "exec")]
    pub fn exec(&self) -> exec::ExecService {
        exec::ExecService::new(Box::new(DuctRunner))
    }

    /// Remote command execution over ssh on the given runner.
    ///
    /// This is the injection point for tests (pass a
    /// `toride_runner::fake::FakeRunner`) and for configured runners such
    /// as `DuctRunner::builder().no_default_timeout().build()`.
    #[cfg(feature = "exec")]
    pub fn exec_with(&self, runner: Box<dyn toride_runner::Runner>) -> exec::ExecService {
        exec::ExecService::new(runner)
    }

    /// One-shot file upload to a remote host via sftp, on the default duct runner.
    ///
    /// The default runner applies its 60 s fallback timeout to invocations
    /// without a spec timeout; set a longer cap with
    /// [`UploadService::with_timeout`](upload::UploadService::with_timeout),
    /// or inject a configured runner through [`Self::upload_with`].
    #[cfg(feature = "upload")]
    pub fn upload(&self) -> upload::UploadService {
        upload::UploadService::new(Box::new(DuctRunner))
    }

    /// One-shot file upload to a remote host via sftp on the given runner.
    ///
    /// This is the injection point for tests (pass a
    /// `toride_runner::fake::FakeRunner`) and for configured runners such
    /// as `DuctRunner::builder().no_default_timeout().build()`.
    #[cfg(feature = "upload")]
    pub fn upload_with(&self, runner: Box<dyn toride_runner::Runner>) -> upload::UploadService {
        upload::UploadService::new(runner)
    }
}
