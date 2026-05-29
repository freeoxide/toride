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
        parse::parse_authorized_keys(&self.paths.authorized_keys_path()).await
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
        let path = self.paths.authorized_keys_path();

        // Validate the key
        let mut key_line = public_key.trim().to_string();

        // Apply comment override if provided
        if let Some(comment) = comment {
            // Re-parse and serialize with the new comment
            let mut pk = ssh_key::PublicKey::from_openssh(&key_line).map_err(|e| {
                Error::KeyParseFailed(format!("invalid public key: {e}"))
            })?;
            pk.set_comment(comment);
            key_line = pk.to_openssh().map_err(|e| {
                Error::KeyParseFailed(format!("failed to serialize key: {e}"))
            })?;
        } else {
            // Still validate even without overriding comment
            ssh_key::PublicKey::from_openssh(&key_line).map_err(|e| {
                Error::KeyParseFailed(format!("invalid public key: {e}"))
            })?;
        }

        // Check for duplicate before writing
        if self.contains(public_key).await? {
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
        let path_clone = path.clone();
        let data = line_with_newline.into_bytes();

        tokio::task::spawn_blocking(move || {
            use std::fs::OpenOptions;
            use std::io::Write;

            // If the file exists, we append. If not, we create and set permissions.
            let is_new = !path_clone.exists();

            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path_clone)
                .map_err(|e| Error::AuthorizedKeysWriteFailed(e.to_string()))?;

            file.write_all(&data)
                .map_err(|e| Error::AuthorizedKeysWriteFailed(e.to_string()))?;

            file.sync_all()
                .map_err(|e| Error::AuthorizedKeysWriteFailed(e.to_string()))?;

            // Set restrictive permissions on new files
            if is_new {
                set_permissions(&path_clone)?;
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
        let path = self.paths.authorized_keys_path();
        let fingerprint = fingerprint.to_string();

        let entries = self.list().await?;
        let mut removed = 0;

        // Build a set of line numbers to remove
        let mut lines_to_remove = std::collections::HashSet::new();
        for entry in &entries {
            // Reconstruct the key portion to compute fingerprint
            let key_line = format!("{} {}", entry.key_type, entry.public_key);
            if let Ok(pk) = ssh_key::PublicKey::from_openssh(&key_line) {
                let fp = pk.fingerprint(ssh_key::HashAlg::Sha256).to_string();
                if fp == fingerprint {
                    lines_to_remove.insert(entry.line_number);
                    removed += 1;
                }
            }
        }

        if removed == 0 {
            return Ok(0);
        }

        // Read the raw file to preserve formatting of kept lines
        let raw_contents = tokio::fs::read_to_string(&path).await?;

        // Reconstruct the file without removed lines
        let mut kept_lines = Vec::new();
        for (i, line) in raw_contents.lines().enumerate() {
            let line_num = i + 1;
            if !lines_to_remove.contains(&line_num) {
                kept_lines.push(line.to_string());
            }
        }

        let new_contents = format!("{}\n", kept_lines.join("\n"));

        // Write atomically: write to temp file in same directory, then rename
        let path_clone = path.clone();
        tokio::task::spawn_blocking(move || {
            atomic_write(&path_clone, &new_contents)
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
        let target_key = public_key.trim().to_string();

        // Compute the fingerprint of the key we are looking for
        let target_pk = ssh_key::PublicKey::from_openssh(&target_key).map_err(|e| {
            Error::KeyParseFailed(format!("invalid public key: {e}"))
        })?;
        let target_fp = target_pk.fingerprint(ssh_key::HashAlg::Sha256).to_string();

        let entries = self.list().await?;

        for entry in entries {
            let key_line = format!("{} {}", entry.key_type, entry.public_key);
            if let Ok(pk) = ssh_key::PublicKey::from_openssh(&key_line) {
                let fp = pk.fingerprint(ssh_key::HashAlg::Sha256).to_string();
                if fp == target_fp {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

/// Write `contents` to `path` atomically using a temp file + rename.
///
/// The temp file is created in the same directory as `path` to guarantee
/// the rename is on the same filesystem. Permissions are set to 0o600.
fn atomic_write(path: &std::path::Path, contents: &str) -> Result<()> {
    let parent = path.parent().unwrap_or(std::path::Path::new("."));
    let temp_name = format!(
        ".authorized_keys.tmp.{}",
        std::process::id()
    );
    let temp_path = parent.join(temp_name);

    // Write to temp file
    std::fs::write(&temp_path, contents)
        .map_err(|e| Error::AuthorizedKeysWriteFailed(e.to_string()))?;

    // Set permissions before rename
    set_permissions(&temp_path)?;

    // Atomic rename
    std::fs::rename(&temp_path, path)
        .map_err(|e| Error::AuthorizedKeysWriteFailed(e.to_string()))?;

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
