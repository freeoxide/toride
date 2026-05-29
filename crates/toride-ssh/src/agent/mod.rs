//! SSH agent management (listing, adding, removing keys).

mod client;
mod session;

pub use session::ControlSession;

use std::path::Path;

use crate::paths::SshPaths;
use crate::Error;
use crate::Result;
use crate::SshKey;

/// SSH agent operations.
pub struct AgentService<'a> {
    paths: &'a SshPaths,
}

impl<'a> AgentService<'a> {
    pub(crate) fn new(paths: &'a SshPaths) -> Self {
        Self { paths }
    }

    /// Check if the SSH agent is reachable.
    ///
    /// Returns `true` when `SSH_AUTH_SOCK` points to an existing socket and
    /// we can successfully connect to the agent.
    pub async fn status(&self) -> Result<bool> {
        let Ok(socket_path) = std::env::var("SSH_AUTH_SOCK") else {
            return Ok(false);
        };

        if !Path::new(&socket_path).exists() {
            return Ok(false);
        }

        #[cfg(feature = "agent")]
        {
            match client::connect().await {
                Ok(mut c) => {
                    c.request_identities()
                        .await
                        .map_err(|e| Error::AgentOperationFailed(e.to_string()))?;
                    Ok(true)
                }
                Err(Error::AgentNotAvailable) => Ok(false),
                Err(e) => Err(e),
            }
        }

        #[cfg(not(feature = "agent"))]
        {
            match crate::runner::ssh_add_list().await {
                Ok(_) => Ok(true),
                Err(Error::CommandFailed(_)) => Ok(false),
                Err(e) => Err(e),
            }
        }
    }

    /// List all keys currently loaded in the SSH agent.
    pub async fn list_keys(&self) -> Result<Vec<SshKey>> {
        client::list_identities().await
    }

    /// Add a private key to the SSH agent.
    pub async fn add_key(&self, key_path: &Path) -> Result<()> {
        client::add_key(key_path).await
    }

    /// Remove a key from the SSH agent.
    pub async fn remove_key(&self, key_path: &Path) -> Result<()> {
        client::remove_key(key_path).await
    }

    /// List active ControlMaster sessions.
    ///
    /// Scans for control socket files in the SSH directory and `/tmp`,
    /// verifying each is still alive.
    pub async fn list_sessions(&self) -> Result<Vec<ControlSession>> {
        session::list_sessions(self.paths.ssh_dir()).await
    }
}
