//! Port forwarding management via SSH `ControlMaster` sessions:
//! [`ForwardService`] over the low-level `control` module.

pub mod control;

use std::collections::HashMap;
use std::path::Path;

use toride_ssh_core::SshPaths;
use toride_ssh_core::{Error, Result};

pub use control::{ControlSession, ForwardType, PortForward};

/// Port forwarding management via `ControlMaster` sessions.
///
/// Obtained from `SshManager::forward()`.
pub struct ForwardService<'a> {
    paths: &'a SshPaths,
}

impl<'a> ForwardService<'a> {
    #[must_use]
    pub fn new(paths: &'a SshPaths) -> Self {
        Self { paths }
    }

    /// List `(session, forwards)` pairs in session order; a session whose
    /// listing fails is included with an empty list (logged, not propagated).
    ///
    /// # Errors
    /// As [`Self::list_sessions`].
    pub async fn list(&self) -> Result<Vec<(ControlSession, Vec<PortForward>)>> {
        let sessions = self.list_sessions().await?;
        let listings =
            control::list_forwards_bounded(sessions.iter().map(|s| s.control_path.clone())).await;
        Ok(sessions
            .into_iter()
            .zip(listings)
            .map(|(session, result)| match result {
                Ok(forwards) => (session, forwards),
                Err(e) => {
                    tracing::warn!(
                        "failed to list forwards for {}: {e}",
                        session.control_path.display()
                    );
                    (session, Vec::new())
                }
            })
            .collect())
    }

    /// Discover active `ControlMaster` sessions, verified via `ssh -O check`.
    ///
    /// # Errors
    /// [`Error::TaskFailed`] if the directory scan task fails.
    pub async fn list_sessions(&self) -> Result<Vec<ControlSession>> {
        control::list_sessions(self.paths.ssh_dir()).await
    }

    /// Cancel the forward on `local_port`.
    ///
    /// # Errors
    /// [`Error::ForwardNotFound`], [`Error::ForwardFailed`] (non-UTF-8
    /// path), [`Error::CommandFailed`], or [`Error::TaskFailed`].
    pub async fn cancel(&self, control_path: &Path, local_port: u16) -> Result<()> {
        control::cancel_forward(control_path, local_port).await
    }

    /// List forwards for the session at `control_path`.
    ///
    /// # Errors
    /// [`Error::ForwardFailed`] (non-UTF-8 path), [`Error::CommandFailed`],
    /// or [`Error::TaskFailed`].
    pub async fn list_forwards(&self, control_path: &Path) -> Result<Vec<PortForward>> {
        control::list_forwards(control_path).await
    }

    /// Cancel a known forward, skipping the list round-trip.
    ///
    /// # Errors
    /// [`Error::ForwardFailed`] (non-UTF-8 path), [`Error::CommandFailed`],
    /// or [`Error::TaskFailed`].
    pub async fn cancel_known(&self, control_path: &Path, forward: &PortForward) -> Result<()> {
        control::cancel_known_forward(control_path, forward).await
    }

    /// Gracefully shut down a `ControlMaster` session (`ssh -O exit`).
    ///
    /// # Errors
    /// [`Error::ForwardFailed`] (non-UTF-8 path), [`Error::CommandFailed`],
    /// or [`Error::TaskFailed`].
    pub async fn exit_session(&self, control_path: &Path) -> Result<()> {
        control::exit_session(control_path).await
    }

    /// Map each local port claimed by more than one session to the control
    /// socket paths claiming it.
    ///
    /// # Errors
    /// As [`Self::list_sessions`].
    pub async fn conflicting_local_ports(&self) -> Result<HashMap<u16, Vec<std::path::PathBuf>>> {
        let sessions = self.list_sessions().await?;
        let listings =
            control::list_forwards_bounded(sessions.iter().map(|s| s.control_path.clone())).await;
        let mut port_owners: HashMap<u16, Vec<std::path::PathBuf>> = HashMap::new();

        for (session, result) in sessions.iter().zip(listings) {
            match result {
                Ok(forwards) => {
                    for fwd in forwards {
                        port_owners
                            .entry(fwd.local_port)
                            .or_default()
                            .push(session.control_path.clone());
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "failed to list forwards for {}: {e}",
                        session.control_path.display()
                    );
                }
            }
        }

        port_owners.retain(|_, owners| owners.len() > 1);
        Ok(port_owners)
    }

    const TEST_CONNECTIVITY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

    /// Connect to `127.0.0.1:<local_port>` within `timeout`; proves only that
    /// the local socket accepts — not end-to-end forwarding to the remote side.
    ///
    /// # Errors
    /// [`Error::ForwardFailed`] on timeout or connect failure.
    pub async fn test_connectivity_with_timeout(
        &self,
        local_port: u16,
        timeout: std::time::Duration,
    ) -> Result<()> {
        let addr = format!("127.0.0.1:{local_port}");

        tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr))
            .await
            .map_err(|_| {
                Error::ForwardFailed(format!(
                    "connection to {addr} timed out after {} seconds",
                    timeout.as_secs()
                ))
            })?
            .map_err(|e| Error::ForwardFailed(format!("cannot connect to {addr}: {e}")))?;

        tracing::debug!("successfully connected to forwarded port {local_port}");
        Ok(())
    }

    /// [`test_connectivity_with_timeout`](Self::test_connectivity_with_timeout)
    /// with the default 2s timeout; local-acceptance only, not end-to-end.
    ///
    /// # Errors
    /// As [`Self::test_connectivity_with_timeout`].
    pub async fn test_connectivity(&self, local_port: u16) -> Result<()> {
        self.test_connectivity_with_timeout(local_port, Self::TEST_CONNECTIVITY_TIMEOUT)
            .await
    }
}
