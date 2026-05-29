mod generate;
mod inventory;
mod repair;

use crate::paths::SshPaths;
use crate::{Error, KeyCreateParams, KeyDeleteParams, Result, SshKey};

/// Get Unix file permissions from metadata.
#[cfg(unix)]
pub(crate) fn get_permissions(path: &std::path::Path) -> Option<crate::Permissions> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path).ok()?;
    let mode = metadata.permissions().mode();
    // Only keep the lower 12 bits (rwx + setuid/setgid/sticky)
    Some(crate::Permissions {
        mode: mode & 0o7777,
    })
}

#[cfg(not(unix))]
pub(crate) fn get_permissions(_path: &std::path::Path) -> Option<crate::Permissions> {
    None
}

/// Validate a key name to prevent path traversal attacks.
///
/// Key names must not contain path separators or `..` components.
fn validate_key_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::KeyGenerationFailed("key name must not be empty".to_string()));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(Error::KeyGenerationFailed(
            "key name must not contain path separators".to_string(),
        ));
    }
    if name.contains("..") {
        return Err(Error::KeyGenerationFailed(
            "key name must not contain '..'".to_string(),
        ));
    }
    Ok(())
}

/// Key management operations.
pub struct KeyService<'a> {
    paths: &'a SshPaths,
}

impl<'a> KeyService<'a> {
    pub(crate) fn new(paths: &'a SshPaths) -> Self {
        Self { paths }
    }

    /// List all SSH keys found on disk and in the agent.
    pub async fn list(&self) -> Result<Vec<SshKey>> {
        inventory::scan_keys(self.paths).await
    }

    /// Generate a new SSH key pair.
    pub async fn create(&self, params: KeyCreateParams) -> Result<SshKey> {
        validate_key_name(&params.name)?;
        generate::generate_key(self.paths, params).await
    }

    /// Delete a key and optionally its public pair, certificate, agent entry, and config refs.
    pub async fn delete(&self, params: KeyDeleteParams) -> Result<()> {
        validate_key_name(&params.name)?;
        let private_path = self.paths.ssh_dir().join(&params.name);

        if !private_path.exists() {
            return Err(Error::KeyNotFound(params.name.clone()));
        }

        let public_path = private_path.with_extension("pub");

        let cert_path = {
            let name = params.name.clone();
            self.paths.ssh_dir().join(format!("{name}-cert.pub"))
        };

        let paths = self.paths.clone();
        let params_clone = params.clone();
        let private_path = private_path.clone();
        let public_path = public_path.clone();
        let cert_path = cert_path.clone();

        tokio::task::spawn_blocking(move || {
            // Backup if requested
            if params_clone.backup {
                let backup_path = private_path.with_extension("bak");
                std::fs::rename(&private_path, &backup_path).map_err(|e| {
                    Error::Io(e)
                })?;

                if params_clone.remove_public && public_path.exists() {
                    let stem = public_path.file_stem().unwrap_or_default().to_string_lossy();
                    let pub_backup = public_path.with_file_name(format!("{stem}.pub.bak"));
                    if let Err(e) = std::fs::rename(&public_path, &pub_backup) {
                        tracing::warn!("failed to backup {}: {e}", public_path.display());
                    }
                }

                if params_clone.remove_certificate && cert_path.exists() {
                    let name = cert_path.file_name().unwrap_or_default().to_string_lossy();
                    let cert_backup = cert_path.with_file_name(format!("{name}.bak"));
                    if let Err(e) = std::fs::rename(&cert_path, &cert_backup) {
                        tracing::warn!("failed to backup {}: {e}", cert_path.display());
                    }
                }
            } else {
                // Remove the private key file
                std::fs::remove_file(&private_path).map_err(|e| {
                    Error::Io(e)
                })?;

                // Remove public key companion
                if params_clone.remove_public && public_path.exists() {
                    std::fs::remove_file(&public_path).map_err(|e| {
                        Error::Io(e)
                    })?;
                }

                // Remove certificate companion
                if params_clone.remove_certificate && cert_path.exists() {
                    std::fs::remove_file(&cert_path).map_err(|e| {
                        Error::Io(e)
                    })?;
                }
            }

            Ok::<(), Error>(())
        })
        .await
        .map_err(|e| Error::TaskFailed(format!("delete task failed: {e}")))??;

        // Remove from agent if requested (non-fatal)
        if params.remove_from_agent {
            remove_key_from_agent(&self.paths.ssh_dir().join(&params.name)).await;
        }

        // Remove from config if requested
        if params.remove_from_config {
            remove_from_config(&paths, &params.name).await?;
        }

        Ok(())
    }

    /// Derive the `.pub` file from a private key.
    pub async fn repair_public(&self, private_key_path: &std::path::Path) -> Result<()> {
        repair::repair_public_key(private_key_path).await
    }
}

/// Remove a key from the SSH agent.
///
/// This is intentionally non-fatal: the key may not be loaded in the agent,
/// which is a perfectly normal state. Errors are logged but not propagated.
async fn remove_key_from_agent(private_path: &std::path::Path) {
    let path_str = match private_path.to_str() {
        Some(s) => s.to_string(),
        None => {
            tracing::warn!("invalid key path for ssh-add, skipping agent removal");
            return;
        }
    };

    let result = tokio::task::spawn_blocking(move || {
        // ssh-add -d removes a key from the agent by path
        duct::cmd("ssh-add", ["-d", path_str.as_str()])
            .read()
            .map_err(|e| {
                tracing::warn!("ssh-add -d failed (key may not be in agent): {e}");
                e
            })
    })
    .await;

    if let Err(e) = result {
        tracing::warn!("ssh-add task failed: {e}");
    }
}

/// Remove `IdentityFile` references from `~/.ssh/config`.
///
/// This is a basic implementation that removes lines containing the key path.
/// Read errors are non-fatal (the config may be unreadable due to permissions).
async fn remove_from_config(paths: &SshPaths, key_name: &str) -> crate::Result<()> {
    let config_path = paths.config_path();

    if !config_path.exists() {
        return Ok(());
    }

    let config_path_clone = config_path.clone();
    let key_name_owned = key_name.to_string();
    let ssh_dir_str = paths.ssh_dir().to_string_lossy().into_owned();

    tokio::task::spawn_blocking(move || {
        let content = match std::fs::read_to_string(&config_path_clone) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("cannot read config for cleanup: {e}");
                return Ok(());
            }
        };

        // Remove lines that reference this key as an IdentityFile.
        // Match lines like: IdentityFile ~/.ssh/<key_name> or IdentityFile <full_path>
        let key_pattern_tilde = format!("~/.ssh/{key_name_owned}");
        let key_pattern_abs = format!("{ssh_dir_str}/{key_name_owned}");

        let trailing_newline = content.ends_with('\n');

        let new_content: String = content
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                if !trimmed.starts_with("IdentityFile") {
                    return true;
                }
                // Check if this IdentityFile line references our key
                let value = trimmed.trim_start_matches("IdentityFile").trim();
                // Remove quotes if present
                let value = value.trim_matches('"').trim_matches('\'');
                value != key_pattern_tilde && value != key_pattern_abs && value != key_name_owned
            })
            .collect::<Vec<&str>>()
            .join("\n");

        // Preserve trailing newline from the original file
        let final_content = if trailing_newline && !new_content.is_empty() {
            format!("{new_content}\n")
        } else {
            new_content
        };

        if final_content != content {
            std::fs::write(&config_path_clone, final_content).map_err(|e| {
                Error::ConfigWriteFailed(format!(
                    "failed to update config: {}",
                    e
                ))
            })?;
        }

        Ok(())
    })
    .await
    .map_err(|e| Error::TaskFailed(format!("config cleanup task failed: {e}")))?
}
