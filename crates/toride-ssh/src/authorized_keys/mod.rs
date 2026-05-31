//! `authorized_keys` file management.
//!
//! Provides listing, adding, removing, and querying entries in
//! `~/.ssh/authorized_keys`.

pub mod options;
pub mod parse;

use parse::AuthorizedKeyEntry;

use crate::paths::SshPaths;
use crate::Error;
use crate::Result;

/// Re-export the entry type for convenience.
pub use parse::AuthorizedKeyEntry as Entry;
/// Re-export the options type for convenience.
pub use options::AuthorizedKeyOptions as Options;

/// `authorized_keys` file management.
///
/// Obtained from [`SshManager::authorized_keys()`](crate::SshManager::authorized_keys).
pub struct AuthorizedKeysService<'a> {
    paths: &'a SshPaths,
}

/// File permissions for authorized_keys: owner read/write only (0o600).
const AUTHORIZED_KEYS_MODE: u32 = 0o600;

impl<'a> AuthorizedKeysService<'a> {
    pub(crate) fn new(paths: &'a SshPaths) -> Self {
        Self { paths }
    }

    /// List all authorized key entries.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub async fn list(&self) -> Result<Vec<AuthorizedKeyEntry>> {
        parse::parse_authorized_keys(self.paths.authorized_keys_path()).await
    }

    /// Append a new entry to the authorized_keys file.
    ///
    /// `public_key` should be a full OpenSSH public key line
    /// (e.g. `ssh-ed25519 AAAAC3Nz... user@host`). If `options` is provided,
    /// it is prepended to the key line.
    ///
    /// # Errors
    ///
    /// - [`Error::KeyParseFailed`] if the public key is not valid OpenSSH format.
    /// - [`Error::AuthorizedKeysWriteFailed`] if the file cannot be written.
    /// - [`Error::Io`] on filesystem errors.
    pub async fn add(
        &self,
        public_key: &str,
        comment: Option<&str>,
        options: Option<&str>,
    ) -> Result<()> {
        // Reject options containing newlines to prevent injection attacks.
        if let Some(opts) = options
            && (opts.contains('\n') || opts.contains('\r'))
        {
            return Err(Error::AuthorizedKeysWriteFailed(
                "options must not contain newlines".to_owned(),
            ));
        }

        // Allocate an owned PathBuf for use inside `spawn_blocking` (requires `'static`).
        let path = self.paths.authorized_keys_path().to_path_buf();

        // Parse and validate the key once.
        let mut pk = ssh_key::PublicKey::from_openssh(public_key.trim()).map_err(|e| {
            Error::KeyParseFailed(format!("invalid public key: {e}"))
        })?;

        // Apply comment override if provided.
        if let Some(comment) = comment {
            pk.set_comment(comment);
        }
        let key_line = pk.to_openssh().map_err(|e| {
            Error::KeyParseFailed(format!("failed to serialize key: {e}"))
        })?;

        // Check for duplicate before writing — reuse the parsed key's fingerprint.
        let target_fp = pk.fingerprint(ssh_key::HashAlg::Sha256).to_string();
        if self.contains_fingerprint(&target_fp).await? {
            return Err(Error::KeyExists(
                "key already present in authorized_keys".to_string(),
            ));
        }

        // Prepend options if given
        let line = if let Some(opts) = options {
            format!("{opts} {key_line}")
        } else {
            key_line
        };

        // Ensure ~/.ssh directory exists
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Append the line atomically: write to temp file, then rename.
        let line_with_newline = format!("{line}\n");
        let data = line_with_newline.into_bytes();

        tokio::task::spawn_blocking(move || {
            use std::fs::OpenOptions;
            use std::io::Write;

            // If the file exists, we append. If not, we create and set permissions.
            let is_new = !path.exists();

            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|e| Error::AuthorizedKeysWriteFailed(e.to_string()))?;

            file.write_all(&data)
                .map_err(|e| Error::AuthorizedKeysWriteFailed(e.to_string()))?;

            file.sync_all()
                .map_err(|e| Error::AuthorizedKeysWriteFailed(e.to_string()))?;

            // Set restrictive permissions on new files
            if is_new {
                set_permissions(&path)?;
            }

            Ok(())
        })
        .await
        .map_err(|e| Error::AuthorizedKeysWriteFailed(e.to_string()))?
    }

    /// Remove entries matching the given fingerprint.
    ///
    /// The fingerprint should be in the format `SHA256:base64data`.
    /// Returns the number of entries removed.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, parsed, or written.
    pub async fn remove(&self, fingerprint: &str) -> Result<usize> {
        // Allocate an owned PathBuf for use inside `spawn_blocking` (requires `'static`).
        let path = self.paths.authorized_keys_path().to_path_buf();

        let entries = self.list().await?;

        // Collect line numbers of entries whose fingerprint matches.
        let lines_to_remove: std::collections::HashSet<usize> = entries
            .iter()
            .filter(|e| e.fingerprint().as_deref() == Some(fingerprint))
            .map(|e| e.line_number)
            .collect();

        if lines_to_remove.is_empty() {
            return Ok(0);
        }

        let removed = lines_to_remove.len();

        // Read the raw file to preserve formatting of kept lines
        let raw_contents = tokio::fs::read_to_string(&path).await?;

        // Reconstruct the file without removed lines.
        // Uses `fold` to avoid an intermediate `Vec` allocation.
        let mut new_contents = raw_contents
            .lines()
            .enumerate()
            .filter(|(i, _)| !lines_to_remove.contains(&(i + 1)))
            .map(|(_, line)| line)
            .fold(String::new(), |mut acc, line| {
                if !acc.is_empty() {
                    acc.push('\n');
                }
                acc.push_str(line);
                acc
            });
        new_contents.push('\n');

        // Write atomically: write to temp file in same directory, then rename
        tokio::task::spawn_blocking(move || {
            atomic_write(&path, &new_contents)
        })
        .await
        .map_err(|e| Error::AuthorizedKeysWriteFailed(e.to_string()))??;

        Ok(removed)
    }

    /// Check if a key is already present in authorized_keys.
    ///
    /// `public_key` should be a full OpenSSH public key line. Comparison is
    /// done by fingerprint (SHA-256).
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed, or if the
    /// provided key string is not valid.
    pub async fn contains(&self, public_key: &str) -> Result<bool> {
        // Compute the fingerprint of the key we are looking for
        let target_pk = ssh_key::PublicKey::from_openssh(public_key.trim()).map_err(|e| {
            Error::KeyParseFailed(format!("invalid public key: {e}"))
        })?;
        let target_fp = target_pk.fingerprint(ssh_key::HashAlg::Sha256).to_string();

        self.contains_fingerprint(&target_fp).await
    }

    /// Check if a fingerprint is already present in authorized_keys.
    ///
    /// This is an internal helper that avoids re-parsing the input key when
    /// the caller already has a fingerprint.
    async fn contains_fingerprint(&self, target_fp: &str) -> Result<bool> {
        let entries = self.list().await?;
        Ok(entries.iter().any(|e| e.fingerprint().as_deref() == Some(target_fp)))
    }
}

/// Write `contents` to `path` atomically using a temp file + rename.
///
/// The temp file is created in the same directory as `path` to guarantee
/// the rename is on the same filesystem. Uses `create_new` to prevent
/// symlink attacks on multi-user systems. Permissions are set to 0o600.
fn atomic_write(path: &std::path::Path, contents: &str) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let temp_path = parent.join(format!(
        ".authorized_keys.tmp.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));

    // Write to temp file using create_new to prevent symlink attacks.
    {
        let mut tmp_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|e| Error::AuthorizedKeysWriteFailed(e.to_string()))?;
        std::io::Write::write_all(&mut tmp_file, contents.as_bytes())
            .map_err(|e| Error::AuthorizedKeysWriteFailed(e.to_string()))?;
    }

    // Set permissions before rename
    set_permissions(&temp_path)?;

    // Atomic rename
    if let Err(e) = std::fs::rename(&temp_path, path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(Error::AuthorizedKeysWriteFailed(e.to_string()));
    }

    Ok(())
}

/// Set file permissions to `AUTHORIZED_KEYS_MODE` (0o600) on unix.
fn set_permissions(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(AUTHORIZED_KEYS_MODE))
            .map_err(|e| Error::AuthorizedKeysWriteFailed(format!(
                "failed to set permissions on {}: {e}",
                path.display()
            )))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
