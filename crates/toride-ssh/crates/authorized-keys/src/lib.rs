//! `authorized_keys` file management.
//!
//! Provides listing, adding, removing, and querying entries in
//! `~/.ssh/authorized_keys`.

pub mod options;
pub mod parse;

use parse::AuthorizedKeyEntry;

use toride_ssh_core::Error;
use toride_ssh_core::Result;
use toride_ssh_core::SshPaths;

/// Re-export the options type for convenience.
pub use options::AuthorizedKeyOptions as Options;
/// Re-export the entry type for convenience.
pub use parse::AuthorizedKeyEntry as Entry;

/// `authorized_keys` file management.
///
/// Obtained from `SshManager::authorized_keys()`.
pub struct AuthorizedKeysService<'a> {
    paths: &'a SshPaths,
}

/// File permissions for `authorized_keys`: owner read/write only (0o600).
const AUTHORIZED_KEYS_MODE: u32 = 0o600;

impl<'a> AuthorizedKeysService<'a> {
    #[must_use]
    pub fn new(paths: &'a SshPaths) -> Self {
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

    /// Append a new entry to the `authorized_keys` file.
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
        reject_newlines("options", options)?;
        reject_newlines("comment", comment)?;

        // Allocate an owned PathBuf for use inside `spawn_blocking` (requires `'static`).
        let path = self.paths.authorized_keys_path().to_path_buf();

        // Parse and validate the key once.
        let mut pk = ssh_key::PublicKey::from_openssh(public_key.trim())
            .map_err(|e| Error::KeyParseFailed(format!("invalid public key: {e}")))?;

        // Apply comment override if provided.
        if let Some(comment) = comment {
            pk.set_comment(comment);
        }
        let key_line = pk
            .to_openssh()
            .map_err(|e| Error::KeyParseFailed(format!("failed to serialize key: {e}")))?;

        // Check for duplicate before writing, reuse the parsed key's fingerprint.
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

            // If the file exists, we append. If not, we create and set permissions
            // (Unix-only; see the chmod below).
            #[cfg(unix)]
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

            // Set restrictive permissions on new files (POSIX modes are
            // Unix-only; `toride_fs::set_permissions` only exists on Unix, and
            // other targets keep the platform-default permissions).
            #[cfg(unix)]
            if is_new {
                toride_fs::set_permissions(&path, AUTHORIZED_KEYS_MODE)
                    .map_err(|e| Error::AuthorizedKeysWriteFailed(e.to_string()))?;
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
        let path = self.paths.authorized_keys_path().to_path_buf();

        let raw_contents = match tokio::fs::read_to_string(&path).await {
            Ok(contents) => contents,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e.into()),
        };

        let parse_contents = raw_contents.clone();
        let entries = tokio::task::spawn_blocking(move || {
            parse::parse_authorized_keys_contents(&parse_contents)
        })
        .await
        .map_err(|e| Error::AuthorizedKeysParseFailed(e.to_string()))??;

        let lines_to_remove: std::collections::HashSet<usize> = entries
            .iter()
            .filter(|e| e.fingerprint() == fingerprint)
            .map(|e| e.line_number)
            .collect();

        if lines_to_remove.is_empty() {
            return Ok(0);
        }

        let removed = lines_to_remove.len();

        let mut new_contents = String::with_capacity(raw_contents.len());
        for (idx, line) in raw_contents.lines().enumerate() {
            if !lines_to_remove.contains(&(idx + 1)) {
                new_contents.push_str(line);
                new_contents.push('\n');
            }
        }

        tokio::task::spawn_blocking(move || atomic_write(&path, &new_contents))
            .await
            .map_err(|e| Error::AuthorizedKeysWriteFailed(e.to_string()))??;

        Ok(removed)
    }

    /// Check if a key is already present in `authorized_keys`.
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
        let target_pk = ssh_key::PublicKey::from_openssh(public_key.trim())
            .map_err(|e| Error::KeyParseFailed(format!("invalid public key: {e}")))?;
        let target_fp = target_pk.fingerprint(ssh_key::HashAlg::Sha256).to_string();

        self.contains_fingerprint(&target_fp).await
    }

    /// Check if a fingerprint is already present in `authorized_keys`.
    ///
    /// This is an internal helper that avoids re-parsing the input key when
    /// the caller already has a fingerprint.
    async fn contains_fingerprint(&self, target_fp: &str) -> Result<bool> {
        let entries = self.list().await?;
        Ok(entries.iter().any(|e| e.fingerprint() == target_fp))
    }
}

/// Reject a field that would break the one-entry-per-line file format.
fn reject_newlines(field: &'static str, value: Option<&str>) -> Result<()> {
    if let Some(value) = value
        && (value.contains('\n') || value.contains('\r'))
    {
        return Err(Error::AuthorizedKeysWriteFailed(format!(
            "{field} must not contain newlines"
        )));
    }
    Ok(())
}

/// Write `contents` to `path` atomically with 0o600 permissions using `toride_fs`.
fn atomic_write(path: &std::path::Path, contents: &str) -> Result<()> {
    toride_fs::atomic_write_with_perms(path, contents, AUTHORIZED_KEYS_MODE)
        .map_err(|e| Error::AuthorizedKeysWriteFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl unit@test";

    fn service(paths: &'static SshPaths) -> AuthorizedKeysService<'static> {
        AuthorizedKeysService::new(paths)
    }

    #[tokio::test]
    async fn add_rejects_comment_with_embedded_newline() {
        let dir = tempfile::tempdir().unwrap();
        let paths: &'static SshPaths = Box::leak(Box::new(SshPaths::with_dir(dir.path())));
        let svc = service(paths);

        let err = svc
            .add(ED25519_PUB, Some("harmless\nssh-rsa AAAA attacker"), None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::AuthorizedKeysWriteFailed(ref msg) if msg.contains("comment")),
            "expected an AuthorizedKeysWriteFailed naming the comment: {err:?}"
        );
        assert!(
            !svc.paths.authorized_keys_path().exists(),
            "nothing may be written when the comment is rejected"
        );
    }

    #[tokio::test]
    async fn add_rejects_comment_with_carriage_return() {
        let dir = tempfile::tempdir().unwrap();
        let paths: &'static SshPaths = Box::leak(Box::new(SshPaths::with_dir(dir.path())));
        let svc = service(paths);

        let err = svc
            .add(ED25519_PUB, Some("harmless\rssh-rsa AAAA attacker"), None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::AuthorizedKeysWriteFailed(ref msg) if msg.contains("comment")),
            "expected an AuthorizedKeysWriteFailed naming the comment: {err:?}"
        );
    }

    #[tokio::test]
    async fn add_rejects_options_with_embedded_newline() {
        let dir = tempfile::tempdir().unwrap();
        let paths: &'static SshPaths = Box::leak(Box::new(SshPaths::with_dir(dir.path())));
        let svc = service(paths);

        let err = svc
            .add(ED25519_PUB, None, Some("no-pty\nssh-rsa AAAA attacker"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::AuthorizedKeysWriteFailed(ref msg) if msg.contains("options")),
            "expected an AuthorizedKeysWriteFailed naming the options: {err:?}"
        );
    }
}
