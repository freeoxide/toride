//! SSH agent client wrapping `ssh-agent-lib` and `ssh-add` CLI.
//!
//! When the `agent` feature is enabled, the native SSH agent protocol is used
//! for listing identities. Key add/remove operations use the `ssh-add` CLI to
//! avoid type mismatches between `ssh-agent-lib`'s `ssh-key 0.6` and our
//! `ssh-key 0.7`.

use std::path::Path;

use toride_ssh_core::{CliRunner, Error, Fingerprint, KeySource, KeyType, Result, SshKey};

/// Connect to the SSH agent via `SSH_AUTH_SOCK`.
///
/// Returns a boxed [`Session`](ssh_agent_lib::agent::Session) trait object
/// that can be used to interact with the agent. Returns
/// [`Error::AgentNotAvailable`] when `SSH_AUTH_SOCK` is unset or the socket
/// does not exist.
#[cfg(feature = "native")]
pub async fn connect() -> Result<Box<dyn ssh_agent_lib::agent::Session>> {
    let socket_path = std::env::var("SSH_AUTH_SOCK").map_err(|_| Error::AgentNotAvailable)?;

    let path = std::path::PathBuf::from(&socket_path);
    if !path.exists() {
        return Err(Error::AgentNotAvailable);
    }

    // Verify SSH_AUTH_SOCK points to an actual socket, not a regular file or FIFO.
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if let Ok(meta) = std::fs::metadata(&path)
            && !meta.file_type().is_socket()
        {
            return Err(Error::AgentOperationFailed(format!(
                "SSH_AUTH_SOCK ({socket_path}) is not a Unix socket"
            )));
        }
    }

    // Connect directly via UnixStream to avoid pulling in service_binding.
    let stream = tokio::task::spawn_blocking(move || {
        std::os::unix::net::UnixStream::connect(&path)
            .map_err(|e| Error::AgentOperationFailed(e.to_string()))
    })
    .await
    .map_err(|e| Error::AgentOperationFailed(e.to_string()))??;

    let tokio_stream = tokio::net::UnixStream::from_std(stream)
        .map_err(|e| Error::AgentOperationFailed(e.to_string()))?;

    Ok(Box::new(ssh_agent_lib::client::Client::new(tokio_stream)))
}

/// List all identities currently loaded in the SSH agent.
///
/// Uses the native agent protocol when the `agent` feature is enabled,
/// falling back to parsing `ssh-add -l` output otherwise.
///
/// # Errors
///
/// Returns [`Error::AgentNotAvailable`] if the agent is not running, or
/// [`Error::AgentOperationFailed`] if the agent protocol or CLI command fails.
pub async fn list_identities(runner: &dyn CliRunner) -> Result<Vec<SshKey>> {
    #[cfg(feature = "native")]
    {
        match list_identities_native().await {
            Ok(keys) => return Ok(keys),
            // No agent at all — propagate immediately rather than trying CLI.
            Err(Error::AgentNotAvailable) => return Err(Error::AgentNotAvailable),
            // Other errors (e.g. protocol mismatch) — fall through to CLI.
            Err(_) => {}
        }
    }

    list_identities_via_cli(runner).await
}

/// Add a private key to the SSH agent via `ssh-add`.
pub async fn add_key(key_path: &Path, runner: &dyn CliRunner) -> Result<()> {
    let path_str = key_path
        .to_str()
        .ok_or_else(|| Error::AgentOperationFailed("key path is not valid UTF-8".into()))?
        .to_owned();

    runner
        .run("ssh-add", vec![path_str])
        .await
        .map_err(|e| Error::AgentOperationFailed(e.to_string()))?;
    Ok(())
}

/// Test whether a key is usable by the SSH agent (`ssh-add -T`).
///
/// Returns `Ok(true)` if the key is usable (exit code 0), `Ok(false)` if not
/// (non-zero exit code), and `Err` if the command itself could not be run.
///
/// This is useful for checking whether a key that requires a passphrase has
/// already been decrypted and loaded, or whether a hardware token key is
/// accessible.
pub async fn test_key_usability(key_path: &Path, runner: &dyn CliRunner) -> Result<bool> {
    let path_str = key_path
        .to_str()
        .ok_or_else(|| Error::AgentOperationFailed("key path is not valid UTF-8".into()))?
        .to_owned();

    match runner.run("ssh-add", vec!["-T".to_owned(), path_str]).await {
        Ok(_) => Ok(true),
        Err(Error::CommandFailed(_)) => Ok(false),
        Err(e) => Err(Error::AgentOperationFailed(e.to_string())),
    }
}

/// Add a key to the SSH agent restricted to specific destinations (`ssh-add -h`).
///
/// The `hosts` slice specifies the allowed destinations. Only connections to
/// these hosts will be authorized to use the key. The hosts are joined with
/// `>` to form the `ssh-add -h` argument.
///
/// # Errors
///
/// Returns an error if `hosts` is empty, if the key cannot be added, or if
/// the command fails.
pub async fn destination_constrained_add(
    key_path: &Path,
    hosts: &[&str],
    runner: &dyn CliRunner,
) -> Result<()> {
    if hosts.is_empty() {
        return Err(Error::AgentOperationFailed(
            "destination-constrained add requires at least one host".into(),
        ));
    }

    let path_str = key_path
        .to_str()
        .ok_or_else(|| Error::AgentOperationFailed("key path is not valid UTF-8".into()))?
        .to_owned();

    let constraint = hosts.join(">");
    runner
        .run("ssh-add", vec!["-h".to_owned(), constraint, path_str])
        .await
        .map_err(|e| Error::AgentOperationFailed(e.to_string()))?;
    Ok(())
}

/// Remove a key from the SSH agent via `ssh-add -d`.
pub async fn remove_key(key_path: &Path, runner: &dyn CliRunner) -> Result<()> {
    let pub_path = key_path.with_extension("pub");
    let path = if pub_path.exists() {
        pub_path
    } else {
        key_path.to_path_buf()
    };

    let path_str = path
        .to_str()
        .ok_or_else(|| Error::AgentOperationFailed("key path is not valid UTF-8".into()))?
        .to_owned();

    runner
        .run("ssh-add", vec!["-d".to_owned(), path_str])
        .await
        .map_err(|e| Error::AgentOperationFailed(e.to_string()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Native implementation (agent feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "native")]
async fn list_identities_native() -> Result<Vec<SshKey>> {
    let mut client = connect().await?;
    let identities = client
        .request_identities()
        .await
        .map_err(|e| Error::AgentOperationFailed(e.to_string()))?;

    let mut keys = Vec::with_capacity(identities.len());
    for identity in identities {
        let key_data = identity.credential.key_data();
        let alg_str = key_data.algorithm().to_string();
        let Some(key_type) = parse_key_type_from_algorithm(&alg_str) else {
            tracing::warn!("skipping agent key with unknown algorithm: {alg_str}");
            continue;
        };

        let fingerprint = match encode_key_data(key_data) {
            Ok(bytes) => Some(compute_sha256_fingerprint(&bytes, key_type)),
            Err(e) => {
                tracing::warn!("failed to encode agent key data: {e}");
                None
            }
        };

        keys.push(SshKey {
            path: std::path::PathBuf::from(if identity.comment.is_empty() {
                format!("agent:{key_type:?}")
            } else {
                format!("agent:{}", identity.comment)
            }),
            key_type,
            fingerprint,
            comment: if identity.comment.is_empty() {
                None
            } else {
                Some(identity.comment)
            },
            encrypted: false,
            source: KeySource::Agent,
            permissions: None,
            has_public_pair: false,
            has_certificate: false,
            last_modified: None,
            used_by_hosts: Vec::new(),
            key_format: None,
        });
    }

    Ok(keys)
}

/// Encode `ssh_key 0.6` `KeyData` to bytes using the `Encode` trait.
#[cfg(feature = "native")]
fn encode_key_data(key_data: &ssh_agent_lib::ssh_key::public::KeyData) -> Result<Vec<u8>> {
    use ssh_agent_lib::ssh_encoding::Encode;

    let len = key_data
        .encoded_len()
        .map_err(|e| Error::AgentOperationFailed(format!("encoded_len failed: {e}")))?;
    let mut buf = Vec::with_capacity(len);
    key_data
        .encode(&mut buf)
        .map_err(|e| Error::AgentOperationFailed(format!("encode failed: {e}")))?;
    Ok(buf)
}

/// Compute a SHA-256 fingerprint from raw public key bytes.
#[allow(dead_code, reason = "public API helper, not exercised in-workspace")]
fn compute_sha256_fingerprint(bytes: &[u8], key_type: KeyType) -> Fingerprint {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    use ssh_key::sha2::{Digest, Sha256};

    let hash = Sha256::digest(bytes);
    Fingerprint {
        hash: STANDARD_NO_PAD.encode(hash),
        key_type,
    }
}

/// Map an algorithm name string (e.g. `"ssh-ed25519"`, `"ssh-rsa"`) to [`KeyType`].
///
/// Returns `None` for unknown algorithms so callers can decide how to handle them
/// rather than silently misidentifying the key type.
#[allow(dead_code, reason = "public API helper, not exercised in-workspace")]
pub(crate) fn parse_key_type_from_algorithm(alg: &str) -> Option<KeyType> {
    match alg {
        "ssh-ed25519" => Some(KeyType::Ed25519),
        "ssh-rsa" => Some(KeyType::Rsa { bits: 0 }),
        "ecdsa-sha2-nistp256" => Some(KeyType::EcdsaP256),
        "ecdsa-sha2-nistp384" => Some(KeyType::EcdsaP384),
        "ecdsa-sha2-nistp521" => Some(KeyType::EcdsaP521),
        "ssh-dss" => Some(KeyType::Dsa),
        "sk-ssh-ed25519@openssh.com" => Some(KeyType::SkEd25519),
        "sk-ecdsa-sha2-nistp256@openssh.com" => Some(KeyType::SkEcdsaP256),
        _ => {
            tracing::warn!("unknown SSH key algorithm \"{alg}\"");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// CLI fallback
// ---------------------------------------------------------------------------

/// Parse `ssh-add -l` output into a list of [`SshKey`] values.
async fn list_identities_via_cli(runner: &dyn CliRunner) -> Result<Vec<SshKey>> {
    let output = runner.run("ssh-add", vec!["-l".to_owned()]).await?;
    Ok(output.lines().filter_map(parse_ssh_add_line).collect())
}

/// Parse a single `ssh-add -l` output line.
///
/// Format: `<bits> SHA256:<hash> <comment> (<type>)`
pub(crate) fn parse_ssh_add_line(line: &str) -> Option<SshKey> {
    let line = line.trim();
    if line.is_empty() || line.contains("The agent has no identities") {
        return None;
    }

    let (_bits, rest) = line.split_once(' ')?;
    let rest = rest.trim();

    // Extract parenthesised key type from the end.
    let (rest, key_type_opt) = if let Some(start) = rest.rfind('(') {
        if let Some(end) = rest[start..].find(')') {
            let kt = &rest[start + 1..start + end];
            (rest[..start].trim_end(), Some(kt))
        } else {
            (rest, None)
        }
    } else {
        (rest, None)
    };

    let key_type = key_type_opt.and_then(parse_key_type_from_display)?;

    // Split fingerprint from comment, keeping both as borrowed slices.
    let (fingerprint_part, comment_part) = if let Some(space) = rest.find(' ') {
        let (fp, c) = rest.split_at(space);
        let c = c.trim();
        (fp, if c.is_empty() { None } else { Some(c) })
    } else {
        (rest, None)
    };

    let hash = fingerprint_part
        .strip_prefix("SHA256:")
        .unwrap_or(fingerprint_part)
        .to_string();

    Some(SshKey {
        path: std::path::PathBuf::from(format!("agent:{}", comment_part.unwrap_or("unknown"))),
        key_type,
        fingerprint: Some(Fingerprint { hash, key_type }),
        comment: comment_part.map(str::to_owned),
        encrypted: false,
        source: KeySource::Agent,
        permissions: None,
        has_public_pair: false,
        has_certificate: false,
        last_modified: None,
        used_by_hosts: Vec::new(),
        key_format: None,
    })
}

/// Map a display key type like "ED25519" or "RSA" to [`KeyType`].
///
/// These strings come from `ssh-add -l` output, e.g. `(ED25519)`, `(RSA)`,
/// `(ECDSA)`, `(ED25519-SK)`, `(ECDSA-SK)`.
fn parse_key_type_from_display(s: &str) -> Option<KeyType> {
    if s.eq_ignore_ascii_case("ED25519") {
        Some(KeyType::Ed25519)
    } else if s.eq_ignore_ascii_case("ED25519-SK") {
        Some(KeyType::SkEd25519)
    } else if s.eq_ignore_ascii_case("RSA") {
        Some(KeyType::Rsa { bits: 0 })
    } else if s.eq_ignore_ascii_case("ECDSA") {
        Some(KeyType::EcdsaP256)
    } else if s.eq_ignore_ascii_case("ECDSA-SK") {
        Some(KeyType::SkEcdsaP256)
    } else if s.eq_ignore_ascii_case("DSA") {
        Some(KeyType::Dsa)
    } else {
        None
    }
}

#[cfg(test)]
#[path = "client.test.rs"]
mod tests;
