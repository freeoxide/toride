mod generate;
mod inventory;
pub mod install;
mod repair;

pub use install::InstallOutcome;
pub use install::UninstallOutcome;

use std::ffi::OsStr;

use crate::paths::SshPaths;
use crate::{Error, KeyCreateParams, KeyDeleteParams, KeyFormat, Result, SshKey};

/// Maximum allowed key name length (typical filesystem limit).
const MAX_KEY_NAME_LENGTH: usize = 255;

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
/// Key names must not contain path separators, `..` components, or null bytes.
/// Maximum length is 255 bytes (typical filesystem limit).
fn validate_key_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidKeyName("key name must not be empty".to_owned()));
    }
    if name.len() > MAX_KEY_NAME_LENGTH {
        return Err(Error::InvalidKeyName(
            format!("key name must not exceed {MAX_KEY_NAME_LENGTH} bytes"),
        ));
    }
    if name.contains('\0') {
        return Err(Error::InvalidKeyName(
            "key name must not contain null bytes".to_owned(),
        ));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(Error::InvalidKeyName(
            "key name must not contain path separators".to_owned(),
        ));
    }
    if name.contains("..") {
        return Err(Error::InvalidKeyName(
            "key name must not contain '..'".to_owned(),
        ));
    }
    Ok(())
}

/// Return a unique backup path by appending a Unix timestamp suffix if the
/// path already exists.  For example, if `foo.bak` exists, returns
/// `foo.bak.1717020000`.
fn unique_backup_path(base: &std::path::Path) -> std::path::PathBuf {
    if !base.exists() {
        return base.to_path_buf();
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ext = match base.extension() {
        Some(e) => format!("{}.{}", e.to_string_lossy(), ts),
        None => ts.to_string(),
    };
    base.with_extension(ext)
}

/// Key management operations.
///
/// Obtained from [`SshManager::keys()`](crate::SshManager::keys).
pub struct KeyService<'a> {
    paths: &'a SshPaths,
    runner: &'a dyn crate::CliRunner,
}

impl<'a> KeyService<'a> {
    pub(crate) fn new(paths: &'a SshPaths, runner: &'a dyn crate::CliRunner) -> Self {
        Self { paths, runner }
    }

    /// List all SSH keys found on disk and in the agent.
    ///
    /// Scans `~/.ssh/id_*` files and queries the SSH agent via `ssh-add -l`.
    /// Keys that cannot be parsed are skipped with a warning.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TaskFailed`] if the background scan task panics
    /// or is cancelled.
    pub async fn list(&self) -> Result<Vec<SshKey>> {
        inventory::scan_keys(self.paths, Some(self.runner)).await
    }

    /// Generate a new SSH key pair.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyName`] if the key name is invalid
    /// (empty, contains path separators or null bytes, or exceeds 255 bytes),
    /// [`Error::ToolNotFound`] if `ssh-keygen` is not in `PATH`, or
    /// [`Error::CommandFailed`] if key generation fails.
    pub async fn create(&self, params: KeyCreateParams) -> Result<SshKey> {
        validate_key_name(&params.name)?;
        generate::generate_key(self.paths, params, self.runner).await
    }

    /// Delete a key and optionally its public pair, certificate, agent entry, and config refs.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyNotFound`] if the key does not exist,
    /// [`Error::InvalidKeyName`] if the key name is invalid,
    /// [`Error::Io`] if file operations fail, [`Error::TaskFailed`] if
    /// the background deletion task panics, or
    /// [`Error::ConfigWriteFailed`] if config cleanup fails.
    pub async fn delete(&self, params: KeyDeleteParams) -> Result<()> {
        validate_key_name(&params.name)?;
        let private_path = self.paths.ssh_dir().join(&params.name);

        if !private_path.exists() {
            return Err(Error::KeyNotFound(params.name.clone()));
        }

        let public_path = private_path.with_extension("pub");

        let cert_path = self.paths.ssh_dir().join(format!("{}-cert.pub", params.name));

        // Destructure to avoid cloning the entire params struct into spawn_blocking.
        let backup = params.backup;
        let remove_public = params.remove_public;
        let remove_certificate = params.remove_certificate;

        // Remove from agent if requested (non-fatal).
        // Must happen BEFORE the file is deleted/renamed so that ssh-add -d
        // can still reference the original path.
        if params.remove_from_agent {
            remove_key_from_agent(&self.paths.ssh_dir().join(&params.name), self.runner).await;
        }

        tokio::task::spawn_blocking(move || {
            // Backup if requested
            if backup {
                let backup_path = unique_backup_path(&private_path.with_extension("bak"));
                std::fs::rename(&private_path, &backup_path)?;

                if remove_public && public_path.exists() {
                    let stem = public_path.file_stem().unwrap_or_else(|| OsStr::new("")).to_string_lossy();
                    let pub_backup_base = public_path.with_file_name(format!("{stem}.pub.bak"));
                    let pub_backup = unique_backup_path(&pub_backup_base);
                    if let Err(e) = std::fs::rename(&public_path, &pub_backup) {
                        tracing::warn!("failed to backup {}: {e}", public_path.display());
                    }
                }

                if remove_certificate && cert_path.exists() {
                    let name = cert_path.file_name().unwrap_or_else(|| OsStr::new("")).to_string_lossy();
                    let cert_backup_base = cert_path.with_file_name(format!("{name}.bak"));
                    let cert_backup = unique_backup_path(&cert_backup_base);
                    if let Err(e) = std::fs::rename(&cert_path, &cert_backup) {
                        tracing::warn!("failed to backup {}: {e}", cert_path.display());
                    }
                }
            } else {
                // Remove the private key file
                std::fs::remove_file(&private_path)?;

                // Remove public key companion
                if remove_public && public_path.exists() {
                    std::fs::remove_file(&public_path)?;
                }

                // Remove certificate companion
                if remove_certificate && cert_path.exists() {
                    std::fs::remove_file(&cert_path)?;
                }
            }

            Ok::<(), Error>(())
        })
        .await
        .map_err(|e| Error::TaskFailed(format!("delete task failed: {e}")))??;

        // Remove from config if requested
        if params.remove_from_config {
            remove_from_config(self.paths, &params.name).await?;
        }

        Ok(())
    }

    /// Derive the `.pub` file from a private key.
    ///
    /// First attempts an in-process parse. For encrypted keys, falls back to
    /// `ssh-keygen -y -f <path>` to extract the public key and writes it to
    /// the corresponding `.pub` file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyNotFound`] if the private key does not exist,
    /// [`Error::ToolNotFound`] if `ssh-keygen` is not in `PATH`, or
    /// [`Error::CommandFailed`] if public key extraction fails (e.g.
    /// the key is encrypted and no passphrase was provided).
    pub async fn repair_public(
        &self,
        private_key_path: &std::path::Path,
        passphrase: Option<&str>,
    ) -> Result<()> {
        repair::repair_public_key(private_key_path, passphrase, self.runner).await
    }

    /// Rename a key pair (private, public, certificate).
    ///
    /// Renames `~/.ssh/<old_name>` to `~/.ssh/<new_name>` and all companion
    /// files (`.pub`, `-cert.pub`). Does NOT update config references — call
    /// `remove_from_config` for the old name and add new `IdentityFile` entries
    /// separately.
    ///
    /// If the private key rename succeeds but the public key or certificate
    /// rename fails, the operation continues with a warning. This may leave
    /// the key pair in an inconsistent state where the private key has the
    /// new name but the public key retains the old name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyNotFound`] if the old key does not exist,
    /// [`Error::KeyExists`] if a key with the new name already exists,
    /// [`Error::InvalidKeyName`] if either name is invalid, or
    /// [`Error::Io`] if the private key rename fails.
    pub async fn rename(&self, old_name: &str, new_name: &str) -> Result<()> {
        validate_key_name(old_name)?;
        validate_key_name(new_name)?;

        let old_private = self.paths.ssh_dir().join(old_name);
        let new_private = self.paths.ssh_dir().join(new_name);

        if !old_private.exists() {
            return Err(Error::KeyNotFound(old_name.to_owned()));
        }
        if new_private.exists() {
            return Err(Error::KeyExists(new_name.to_owned()));
        }

        let old_public = old_private.with_extension("pub");
        let new_public = new_private.with_extension("pub");
        let old_cert = self.paths.ssh_dir().join(format!("{old_name}-cert.pub"));
        let new_cert = self.paths.ssh_dir().join(format!("{new_name}-cert.pub"));

        tokio::task::spawn_blocking(move || {
            // Rename private key
            std::fs::rename(&old_private, &new_private).map_err(Error::Io)?;

            // Rename public key if it exists
            if old_public.exists()
                && let Err(e) = std::fs::rename(&old_public, &new_public)
            {
                tracing::warn!("failed to rename public key: {e}");
            }

            // Rename certificate if it exists
            if old_cert.exists()
                && let Err(e) = std::fs::rename(&old_cert, &new_cert)
            {
                tracing::warn!("failed to rename certificate: {e}");
            }

            Ok(())
        })
        .await
        .map_err(|e| Error::TaskFailed(format!("rename task failed: {e}")))?
    }

    /// Fix permissions on key files (set private keys to 0o600, public to 0o644).
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyNotFound`] if the key does not exist,
    /// [`Error::InvalidKeyName`] if the key name is invalid, or
    /// [`Error::Io`] if `chmod` fails.
    pub async fn chmod_fix(&self, key_name: &str) -> Result<()> {
        validate_key_name(key_name)?;

        let private_path = self.paths.ssh_dir().join(key_name);
        if !private_path.exists() {
            return Err(Error::KeyNotFound(key_name.to_owned()));
        }

        let public_path = private_path.with_extension("pub");

        tokio::task::spawn_blocking(move || {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    &private_path,
                    std::fs::Permissions::from_mode(0o600),
                )
                .map_err(Error::Io)?;

                if public_path.exists()
                    && let Err(e) = std::fs::set_permissions(
                        &public_path,
                        std::fs::Permissions::from_mode(0o644),
                    )
                {
                    tracing::warn!("failed to set public key permissions: {e}");
                }
            }
            #[cfg(not(unix))]
            {
                let _ = (private_path, public_path);
            }
            Ok(())
        })
        .await
        .map_err(|e| Error::TaskFailed(format!("chmod task failed: {e}")))?
    }

    /// Change the passphrase on an existing key (`ssh-keygen -p`).
    ///
    /// If `old_passphrase` is `None`, the key is assumed to be unencrypted.
    /// If `new_passphrase` is `None` or empty, the passphrase is removed.
    ///
    /// # Security
    ///
    /// Passphrases are passed as command-line arguments to `ssh-keygen`, which
    /// makes them briefly visible to other processes via `/proc/<pid>/cmdline`
    /// or `ps`. This is an inherent limitation of the `ssh-keygen` interface.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyNotFound`] if the key file does not exist, or
    /// [`Error::CommandFailed`] if the passphrase change fails (e.g. wrong
    /// old passphrase).
    pub async fn change_passphrase(
        &self,
        key_path: &std::path::Path,
        old_passphrase: Option<&str>,
        new_passphrase: Option<&str>,
    ) -> Result<()> {
        if !key_path.exists() {
            return Err(Error::KeyNotFound(key_path.display().to_string()));
        }

        let path_str = key_path
            .to_str()
            .ok_or_else(|| Error::CommandFailed("key path is not valid UTF-8".to_owned()))?
            .to_owned();

        let old_pass = old_passphrase.unwrap_or("").to_owned();
        let new_pass = new_passphrase.unwrap_or("").to_owned();

        self.runner
            .run(
                "ssh-keygen",
                vec![
                    "-p".to_owned(),
                    "-f".to_owned(),
                    path_str,
                    "-P".to_owned(),
                    old_pass,
                    "-N".to_owned(),
                    new_pass,
                ],
            )
            .await?;

        Ok(())
    }

    /// Change the comment on an existing key (`ssh-keygen -c`).
    ///
    /// Updates both the private and public key files.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyNotFound`] if the key file does not exist, or
    /// [`Error::CommandFailed`] if the comment change fails.
    pub async fn change_comment(
        &self,
        key_path: &std::path::Path,
        new_comment: &str,
        passphrase: Option<&str>,
    ) -> Result<()> {
        if !key_path.exists() {
            return Err(Error::KeyNotFound(key_path.display().to_string()));
        }

        let path_str = key_path
            .to_str()
            .ok_or_else(|| Error::CommandFailed("key path is not valid UTF-8".to_owned()))?
            .to_owned();

        let pass = passphrase.unwrap_or("").to_owned();

        let mut args = vec![
            "-c".to_owned(),
            "-f".to_owned(),
            path_str,
            "-C".to_owned(),
            new_comment.to_owned(),
        ];
        if !pass.is_empty() {
            args.extend(["-P".to_owned(), pass]);
        }

        self.runner.run("ssh-keygen", args).await?;
        Ok(())
    }

    /// Convert a key between OpenSSH and PEM formats.
    ///
    /// - [`KeyFormat::Pem`]: exports the key in PEM format via `ssh-keygen -e -m PEM`.
    /// - [`KeyFormat::OpenSSH`]: imports a PEM-format key to OpenSSH format via `ssh-keygen -i -m PEM`.
    ///
    /// Returns the converted key content as a string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyNotFound`] if the key file does not exist,
    /// [`Error::ToolNotFound`] if `ssh-keygen` is not available, or
    /// [`Error::CommandFailed`] if the conversion command fails.
    pub async fn convert(
        &self,
        key_path: &std::path::Path,
        target_format: KeyFormat,
    ) -> Result<String> {
        if !key_path.exists() {
            return Err(Error::KeyNotFound(key_path.display().to_string()));
        }

        if !self.runner.tool_exists("ssh-keygen") {
            return Err(Error::ToolNotFound("ssh-keygen".to_owned()));
        }

        let path_str = key_path
            .to_str()
            .ok_or_else(|| Error::CommandFailed("key path is not valid UTF-8".to_owned()))?
            .to_owned();

        let args = match target_format {
            KeyFormat::Pem => vec![
                "-e".to_owned(),
                "-m".to_owned(),
                "PEM".to_owned(),
                "-f".to_owned(),
                path_str,
            ],
            KeyFormat::OpenSSH => vec![
                "-i".to_owned(),
                "-m".to_owned(),
                "PEM".to_owned(),
                "-f".to_owned(),
                path_str,
            ],
        };

        self.runner.run("ssh-keygen", args).await
    }

    /// Install a public key to a remote host's `authorized_keys`.
    ///
    /// Uses `ssh-copy-id` if available, otherwise falls back to manual SSH.
    /// See [`install::install_key_to_remote`] for details.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ToolNotFound`] if neither `ssh-copy-id` nor `ssh`
    /// is available, [`Error::CommandFailed`] if the installation command
    /// fails, or [`Error::KeyNotFound`] if the key path does not exist.
    pub async fn install_key_to_remote(
        &self,
        key_path: &std::path::Path,
        dest: &str,
    ) -> Result<install::InstallOutcome> {
        install::install_key_to_remote(key_path, dest, self.runner).await
    }

    /// Remove a public key from a remote host's `authorized_keys`.
    ///
    /// SSHes into the remote and uses `grep -vF` to strip the matching key
    /// line from `~/.ssh/authorized_keys`. See
    /// [`install::uninstall_key_from_remote`] for details.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyNotFound`] if the key path does not exist,
    /// [`Error::ToolNotFound`] if `ssh` is not available, or
    /// [`Error::CommandFailed`] if the remote command fails.
    pub async fn uninstall_key_from_remote(
        &self,
        key_path: &std::path::Path,
        dest: &str,
    ) -> Result<install::UninstallOutcome> {
        install::uninstall_key_from_remote(key_path, dest, self.runner).await
    }
}

/// Remove a key from the SSH agent.
///
/// This is intentionally non-fatal: the key may not be loaded in the agent,
/// which is a perfectly normal state. Errors are logged but not propagated.
async fn remove_key_from_agent(private_path: &std::path::Path, runner: &dyn crate::CliRunner) {
    let Some(path_str) = private_path.to_str().map(str::to_owned) else {
        tracing::warn!("invalid key path for ssh-add, skipping agent removal");
        return;
    };

    if let Err(e) = runner
        .run("ssh-add", vec!["-d".to_owned(), path_str])
        .await
    {
        tracing::warn!("ssh-add -d failed (key may not be in agent): {e}");
    }
}

/// Remove `IdentityFile` references from `~/.ssh/config`.
///
/// This is a basic implementation that removes lines containing the key path.
/// Read errors are non-fatal (the config may be unreadable due to permissions).
async fn remove_from_config(paths: &SshPaths, key_name: &str) -> Result<()> {
    // Allocate an owned PathBuf for use inside `spawn_blocking` (requires `'static`).
    let config_path = paths.config_path().to_path_buf();

    if !config_path.exists() {
        return Ok(());
    }

    let key_name_owned = key_name.to_owned();
    let ssh_dir_str = paths
        .ssh_dir()
        .to_str()
        .ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("SSH directory path is not valid UTF-8: {}", paths.ssh_dir().display()),
            ))
        })?
        .to_owned();

    tokio::task::spawn_blocking(move || {
        let content = match std::fs::read_to_string(&config_path) {
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

        // Also match CertificateFile directives for the companion cert.
        let cert_name = format!("{key_name_owned}-cert.pub");
        let cert_pattern_tilde = format!("~/.ssh/{cert_name}");
        let cert_pattern_abs = format!("{ssh_dir_str}/{cert_name}");

        let trailing_newline = content.ends_with('\n');
        // Preserve the original line ending style (\r\n vs \n).
        let line_ending = if content.contains("\r\n") { "\r\n" } else { "\n" };

        let new_content: String = content
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                // Extract the keyword (first whitespace-delimited token) and
                // compare case-insensitively.  This avoids matching directives
                // like "IdentityFileSomething" or comments containing the word.
                let keyword = trimmed.split_whitespace().next().unwrap_or("");

                if keyword.eq_ignore_ascii_case("IdentityFile") {
                    // Extract the value (everything after the keyword).
                    let value = trimmed[keyword.len()..].trim();
                    // Remove quotes if present
                    let value = value.trim_matches('"').trim_matches('\'');
                    return value != key_pattern_tilde
                        && value != key_pattern_abs
                        && value != key_name_owned;
                }

                if keyword.eq_ignore_ascii_case("CertificateFile") {
                    // Extract the value (everything after the keyword).
                    let value = trimmed[keyword.len()..].trim();
                    // Remove quotes if present
                    let value = value.trim_matches('"').trim_matches('\'');
                    return value != cert_pattern_tilde
                        && value != cert_pattern_abs
                        && value != cert_name;
                }

                true
            })
            .collect::<Vec<&str>>()
            .join(line_ending);

        // Preserve trailing newline from the original file
        let final_content = if trailing_newline && !new_content.is_empty() {
            format!("{new_content}{line_ending}")
        } else {
            new_content
        };

        if final_content != content {
            // Atomic write: temp file + rename to prevent corruption on crash.
            let parent = config_path.parent().unwrap_or_else(|| std::path::Path::new("."));
            let tmp_path = parent.join(format!(
                ".config.tmp.{}.{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ));
            std::fs::write(&tmp_path, &final_content).map_err(|e| {
                Error::ConfigWriteFailed(format!("failed to write temp config: {e}"))
            })?;
            if let Err(e) = std::fs::rename(&tmp_path, &config_path) {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(Error::ConfigWriteFailed(format!(
                    "failed to rename config: {e}"
                )));
            }
        }

        Ok(())
    })
    .await
    .map_err(|e| Error::TaskFailed(format!("config cleanup task failed: {e}")))?
}

#[cfg(test)]
#[path = "mod.test.rs"]
mod tests;
