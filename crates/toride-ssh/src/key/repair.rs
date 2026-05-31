//! Repair missing public key files from private keys.

use std::path::Path;

use crate::{CliRunner, Error, Result};

/// Derive and write the `.pub` file for a private key.
///
/// When the private key is encrypted and cannot be parsed directly by the
/// `ssh_key` crate, falls back to `ssh-keygen -y -f <path>` via the
/// [`CliRunner`]. If a `passphrase` is provided it is passed via `-P`.
#[expect(clippy::too_many_lines, reason = "two code paths (in-process + ssh-keygen fallback)")]
pub async fn repair_public_key(
    private_key_path: &Path,
    passphrase: Option<&str>,
    runner: &dyn CliRunner,
) -> Result<()> {
    // Validate the path before spawning the blocking task.
    if !private_key_path.exists() {
        return Err(Error::KeyNotFound(private_key_path.display().to_string()));
    }
    if !private_key_path.is_file() {
        return Err(Error::KeyParseFailed(format!(
            "{} is not a regular file",
            private_key_path.display()
        )));
    }

    let private_path = private_key_path.to_path_buf();

    // Try the in-process path first (unencrypted keys).
    let in_process_result = tokio::task::spawn_blocking(move || {
        // Read and parse the private key
        let private_key_data = std::fs::read_to_string(&private_path).map_err(|e| {
            Error::KeyParseFailed(format!(
                "failed to read private key {}: {e}",
                private_path.display()
            ))
        })?;

        let private_key = ssh_key::PrivateKey::from_openssh(&private_key_data).map_err(|e| {
            Error::KeyParseFailed(format!(
                "failed to parse private key {}: {e}",
                private_path.display()
            ))
        })?;

        // Derive the public key path
        let public_path = private_path.with_extension("pub");

        // Back up existing .pub file before overwriting.
        if public_path.exists() {
            let backup_path = public_path.with_extension("pub.bak");
            if let Err(e) = std::fs::rename(&public_path, &backup_path) {
                tracing::warn!(
                    "failed to back up public key to {}: {e}",
                    backup_path.display()
                );
            }
        }

        // Get the public key and write it
        let public_key = private_key.public_key();
        if let Err(e) = public_key.write_openssh_file(&public_path) {
            return Err(Error::KeyParseFailed(format!(
                "failed to write public key {}: {e}",
                public_path.display()
            )));
        }

        // Set permissions to 0o644 on unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&public_path, std::fs::Permissions::from_mode(0o644))
                .map_err(Error::Io)?;
        }

        Ok(())
    })
    .await
    .map_err(|e| Error::TaskFailed(format!("repair_public_key task failed: {e}")))?;

    // If the in-process parse succeeded, return immediately.
    if in_process_result.is_ok() {
        return Ok(());
    }

    // In-process parse failed — likely an encrypted key. Fall back to
    // `ssh-keygen -y -f <path>` which can handle passphrase-protected keys.
    tracing::debug!(
        "in-process key parse failed ({}), falling back to ssh-keygen",
        in_process_result.as_ref().unwrap_err()
    );

    let path_str = private_key_path
        .to_str()
        .ok_or_else(|| Error::CommandFailed("key path is not valid UTF-8".to_owned()))?
        .to_owned();

    let mut args = vec![
        "-y".to_owned(),
        "-f".to_owned(),
        path_str.clone(),
    ];

    if let Some(pass) = passphrase
        && !pass.is_empty()
    {
        args.extend(["-P".to_owned(), pass.to_owned()]);
    }

    let public_key_output = runner.run("ssh-keygen", args).await?;

    // Derive the public key path and write the output.
    let public_path = private_key_path.with_extension("pub");
    let private_path = private_key_path.to_path_buf();

    tokio::task::spawn_blocking(move || {
        // Back up existing .pub file before overwriting.
        if public_path.exists() {
            let backup_path = public_path.with_extension("pub.bak");
            if let Err(e) = std::fs::rename(&public_path, &backup_path) {
                tracing::warn!(
                    "failed to back up public key to {}: {e}",
                    backup_path.display()
                );
            }
        }

        // Append a newline if missing, consistent with ssh-keygen output.
        let content = if public_key_output.ends_with('\n') {
            public_key_output
        } else {
            format!("{public_key_output}\n")
        };

        std::fs::write(&public_path, &content).map_err(|e| {
            Error::KeyParseFailed(format!(
                "failed to write public key {}: {e}",
                public_path.display()
            ))
        })?;

        // Set permissions to 0o644 on unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&public_path, std::fs::Permissions::from_mode(0o644))
                .map_err(Error::Io)?;
        }

        // Ensure the private key still has restrictive permissions after
        // ssh-keygen may have touched it.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if private_path.exists()
                && let Err(e) = std::fs::set_permissions(
                    &private_path,
                    std::fs::Permissions::from_mode(0o600),
                )
            {
                tracing::warn!("failed to restore private key permissions: {e}");
            }
        }

        Ok(())
    })
    .await
    .map_err(|e| Error::TaskFailed(format!("repair_public_key write task failed: {e}")))?
}
