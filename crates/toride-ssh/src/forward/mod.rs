pub mod control;

use std::path::Path;

use crate::paths::SshPaths;
use crate::Result;

pub use control::{ControlSession, ForwardType, PortForward};

/// Port forwarding management via ControlMaster sessions.
pub struct ForwardService<'a> {
    paths: &'a SshPaths,
}

impl<'a> ForwardService<'a> {
    pub(crate) fn new(paths: &'a SshPaths) -> Self {
        Self { paths }
    }

    /// List all active port forwards across all discovered ControlMaster sessions.
    pub async fn list(&self) -> Result<Vec<(ControlSession, Vec<PortForward>)>> {
        let sessions = self.list_sessions().await?;
        let mut results = Vec::with_capacity(sessions.len());

        for session in sessions {
            match control::list_forwards(&session.control_path).await {
                Ok(forwards) => results.push((session, forwards)),
                Err(e) => {
                    tracing::warn!(
                        "failed to list forwards for {}: {e}",
                        session.control_path.display()
                    );
                    results.push((session, Vec::new()));
                }
            }
        }

        Ok(results)
    }

    /// Discover active ControlMaster sessions.
    pub async fn list_sessions(&self) -> Result<Vec<ControlSession>> {
        control::list_sessions(self.paths.ssh_dir()).await
    }

    /// Cancel a port forward on a specific session by local port number.
    pub async fn cancel(&self, control_path: &Path, local_port: u16) -> Result<()> {
        control::cancel_forward(control_path, local_port).await
    }

    /// List forwards for a single session identified by its control socket path.
    pub async fn forward_list_for_session(&self, control_path: &Path) -> Result<Vec<PortForward>> {
        control::list_forwards(control_path).await
    }

    /// Cancel a known forward (avoids the extra list round-trip).
    pub async fn cancel_known(&self, control_path: &Path, forward: &PortForward) -> Result<()> {
        control::cancel_known_forward(control_path, forward).await
    }

    /// Gracefully shut down a ControlMaster session.
    pub async fn exit_session(&self, control_path: &Path) -> Result<()> {
        control::exit_session(control_path).await
    }
}
