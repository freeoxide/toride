//! SSH agent management (listing, adding, removing keys).

pub mod askpass;
mod client;
mod session;

pub use askpass::AskpassHandler;
pub use client::list_identities;
pub use session::ControlSession;

use std::path::Path;

use toride_ssh_core::Error;
use toride_ssh_core::Result;
use toride_ssh_core::SshKey;
use toride_ssh_core::SshPaths;

/// SSH agent operations.
///
/// Obtained from [`SshManager::agent()`](crate::SshManager::agent).
pub struct AgentService<'a> {
    paths: &'a SshPaths,
    runner: &'a dyn toride_ssh_core::CliRunner,
}

impl<'a> AgentService<'a> {
    pub fn new(paths: &'a SshPaths, runner: &'a dyn toride_ssh_core::CliRunner) -> Self {
        Self { paths, runner }
    }

    /// Check if the SSH agent is reachable.
    ///
    /// Returns `true` when `SSH_AUTH_SOCK` points to an existing socket and
    /// we can successfully connect to the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if the agent check command itself fails unexpectedly
    /// (not merely because the agent is unavailable).
    pub async fn status(&self) -> Result<bool> {
        #[cfg(feature = "native")]
        {
            // `connect()` already validates `SSH_AUTH_SOCK` and socket
            // existence, so no need to duplicate those checks here.
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

        #[cfg(not(feature = "native"))]
        {
            match self.runner.run("ssh-add", vec!["-l".to_owned()]).await {
                Ok(_) => Ok(true),
                Err(Error::CommandFailed(_)) => Ok(false),
                Err(e) => Err(e),
            }
        }
    }

    /// List all keys currently loaded in the SSH agent.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AgentNotAvailable`] if the agent is not running,
    /// or [`Error::AgentOperationFailed`] if the agent protocol fails.
    pub async fn list_keys(&self) -> Result<Vec<SshKey>> {
        client::list_identities(self.runner).await
    }

    /// Add a private key to the SSH agent.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AgentOperationFailed`] if the key cannot be added
    /// (e.g. passphrase required, agent rejects the key).
    pub async fn add_key(&self, key_path: &Path) -> Result<()> {
        client::add_key(key_path, self.runner).await
    }

    /// Remove a key from the SSH agent.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AgentOperationFailed`] if the key cannot be removed.
    pub async fn remove_key(&self, key_path: &Path) -> Result<()> {
        client::remove_key(key_path, self.runner).await
    }

    /// Test whether a key is usable by the SSH agent (`ssh-add -T`).
    ///
    /// Returns `true` if the key is usable (already decrypted/loaded or
    /// accessible via hardware token), `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AgentOperationFailed`] if the test command itself
    /// cannot be executed.
    pub async fn test_key_usability(&self, key_path: &Path) -> Result<bool> {
        client::test_key_usability(key_path, self.runner).await
    }

    /// Add a key restricted to specific destination hosts (`ssh-add -h`).
    ///
    /// The key will only be authorized for connections to the listed hosts.
    /// At least one host must be provided.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AgentOperationFailed`] if `hosts` is empty or if
    /// the command fails.
    pub async fn destination_constrained_add(&self, key_path: &Path, hosts: &[&str]) -> Result<()> {
        client::destination_constrained_add(key_path, hosts, self.runner).await
    }

    /// Remove all keys from the SSH agent (`ssh-add -D`).
    ///
    /// Returns the number of keys removed (best-effort; some agents don't report count).
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the command fails.
    pub async fn remove_all(&self) -> Result<()> {
        let result = self.runner.run("ssh-add", vec!["-D".to_owned()]).await?;

        tracing::debug!("ssh-add -D output: {result}");
        Ok(())
    }

    /// Add a key to the SSH agent with a lifetime limit (`ssh-add -t`).
    ///
    /// `lifetime_seconds` specifies how long the key should remain loaded.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the key cannot be added or the
    /// lifetime argument is invalid.
    pub async fn add_key_with_lifetime(
        &self,
        key_path: &Path,
        lifetime_seconds: u32,
    ) -> Result<()> {
        let path_str = key_path
            .to_str()
            .ok_or_else(|| Error::CommandFailed("key path is not valid UTF-8".to_owned()))?
            .to_owned();

        self.runner
            .run(
                "ssh-add",
                vec!["-t".to_owned(), lifetime_seconds.to_string(), path_str],
            )
            .await?;
        Ok(())
    }

    /// Add a key to the SSH agent with confirmation required (`ssh-add -c`).
    ///
    /// The agent will request user confirmation each time the key is used.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the key cannot be added.
    pub async fn add_key_with_confirmation(&self, key_path: &Path) -> Result<()> {
        let path_str = key_path
            .to_str()
            .ok_or_else(|| Error::CommandFailed("key path is not valid UTF-8".to_owned()))?
            .to_owned();

        self.runner
            .run("ssh-add", vec!["-c".to_owned(), path_str])
            .await?;
        Ok(())
    }

    /// Add a passphrase-protected key to the SSH agent using `SSH_ASKPASS`.
    ///
    /// This creates a temporary askpass script that supplies the passphrase
    /// non-interactively, which is useful when loading keys from a TUI or
    /// other automated context where terminal input is not available.
    ///
    /// The temporary script is cleaned up automatically when this method
    /// returns (on success or failure).
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the key cannot be added, or
    /// [`Error::Io`] if the temporary askpass script cannot be created.
    pub async fn add_key_with_passphrase(&self, key_path: &Path, passphrase: &str) -> Result<()> {
        let askpass = AskpassHandler::new(passphrase)?;
        let path_str = key_path
            .to_str()
            .ok_or_else(|| Error::CommandFailed("key path is not valid UTF-8".to_owned()))?
            .to_owned();
        let script = askpass.script_path().to_string_lossy().into_owned();

        let result = self
            .runner
            .run_with_env(
                "ssh-add",
                vec![path_str],
                vec![
                    ("SSH_ASKPASS".to_owned(), script),
                    ("SSH_ASKPASS_REQUIRE".to_owned(), "force".to_owned()),
                    ("DISPLAY".to_owned(), ":0".to_owned()),
                ],
            )
            .await;

        // askpass is dropped here, cleaning up the temporary script.
        result?;
        Ok(())
    }

    /// Add a key to the SSH agent and store its passphrase in the macOS Keychain
    /// (`ssh-add --apple-use-keychain <key>`).
    ///
    /// This integrates with the macOS Keychain so the key's passphrase is
    /// remembered across reboots. Only available on macOS.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the key cannot be added to the
    /// keychain.
    #[cfg(target_os = "macos")]
    pub async fn add_to_keychain(&self, key_path: &Path) -> Result<()> {
        let path_str = key_path
            .to_str()
            .ok_or_else(|| Error::CommandFailed("key path is not valid UTF-8".to_owned()))?
            .to_owned();

        self.runner
            .run("ssh-add", vec!["--apple-use-keychain".to_owned(), path_str])
            .await?;
        Ok(())
    }

    /// Load all keys from the macOS Keychain into the SSH agent
    /// (`ssh-add --apple-load-keychain`).
    ///
    /// Reads stored passphrases from the Keychain and loads the corresponding
    /// keys automatically. Only available on macOS.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the keychain load fails.
    #[cfg(target_os = "macos")]
    pub async fn load_keychain(&self) -> Result<()> {
        self.runner
            .run("ssh-add", vec!["--apple-load-keychain".to_owned()])
            .await?;
        Ok(())
    }

    /// List active `ControlMaster` sessions.
    ///
    /// Scans for control socket files in the SSH directory and `/tmp`,
    /// verifying each is still alive.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TaskFailed`] if the background scan task panics
    /// or is cancelled.
    pub async fn list_sessions(&self) -> Result<Vec<ControlSession>> {
        session::list_sessions(self.paths.ssh_dir()).await
    }
}
