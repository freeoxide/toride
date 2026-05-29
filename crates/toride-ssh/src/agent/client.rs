//! SSH agent client wrapping `ssh-agent-lib` and `ssh-add` CLI.
//!
//! When the `agent` feature is enabled, the native SSH agent protocol is used
//! for listing identities. Key add/remove operations use the `ssh-add` CLI to
//! avoid type mismatches between `ssh-agent-lib`'s `ssh-key 0.6` and our
//! `ssh-key 0.7`.

use std::path::Path;

use crate::{Error, Fingerprint, KeySource, KeyType, Result, SshKey};
use crate::runner;

/// Connect to the SSH agent via `SSH_AUTH_SOCK`.
///
/// Returns a boxed [`Session`](ssh_agent_lib::agent::Session) trait object
/// that can be used to interact with the agent. Returns
/// [`Error::AgentNotAvailable`] when `SSH_AUTH_SOCK` is unset or the socket
/// does not exist.
#[cfg(feature = "agent")]
pub async fn connect() -> Result<Box<dyn ssh_agent_lib::agent::Session>> {
    let socket_path = std::env::var("SSH_AUTH_SOCK")
        .map_err(|_| Error::AgentNotAvailable)?;

    if !std::path::Path::new(&socket_path).exists() {
        return Err(Error::AgentNotAvailable);
    }

    let path = std::path::PathBuf::from(&socket_path);

    // Connect directly via UnixStream to avoid pulling in service_binding.
    let stream = tokio::task::spawn_blocking(move || {
        std::os::unix::net::UnixStream::connect(&path)
            .map_err(|e| Error::AgentOperationFailed(e.to_string()))
    })
    .await
    .map_err(|e| Error::AgentOperationFailed(e.to_string()))??;

    let tokio_stream = tokio::net::UnixStream::from_std(stream)
        .map_err(|e| Error::AgentOperationFailed(e.to_string()))?;

    Ok(Box::new(
        ssh_agent_lib::client::Client::new(tokio_stream),
    ))
}

/// List all identities currently loaded in the SSH agent.
///
/// Uses the native agent protocol when the `agent` feature is enabled,
/// falling back to parsing `ssh-add -l` output otherwise.
pub async fn list_identities() -> Result<Vec<SshKey>> {
    #[cfg(feature = "agent")]
    {
        match list_identities_native().await {
            Ok(keys) => return Ok(keys),
            Err(Error::AgentNotAvailable) => return Err(Error::AgentNotAvailable),
            Err(_) => { /* fall through to CLI */ }
        }
    }

    list_identities_via_cli().await
}

/// Add a private key to the SSH agent via `ssh-add`.
pub async fn add_key(key_path: &Path) -> Result<()> {
    let path = key_path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let path_str = path.to_str().ok_or_else(|| {
            Error::AgentOperationFailed("key path is not valid UTF-8".into())
        })?;
        duct::cmd("ssh-add", [path_str])
            .read()
            .map_err(|e| Error::AgentOperationFailed(e.to_string()))
    })
    .await
    .map_err(|e| Error::AgentOperationFailed(e.to_string()))??;
    Ok(())
}

/// Remove a key from the SSH agent via `ssh-add -d`.
pub async fn remove_key(key_path: &Path) -> Result<()> {
    let pub_path = key_path.with_extension("pub");
    let path = if pub_path.exists() {
        pub_path
    } else {
        key_path.to_path_buf()
    };

    tokio::task::spawn_blocking(move || {
        let path_str = path.to_str().ok_or_else(|| {
            Error::AgentOperationFailed("key path is not valid UTF-8".into())
        })?;
        duct::cmd("ssh-add", ["-d", path_str])
            .read()
            .map_err(|e| Error::AgentOperationFailed(e.to_string()))
    })
    .await
    .map_err(|e| Error::AgentOperationFailed(e.to_string()))??;
    Ok(())
}

// ---------------------------------------------------------------------------
// Native implementation (agent feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "agent")]
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
        let key_type = parse_key_type_from_algorithm(&alg_str);

        // Encode the public key to bytes and compute SHA-256 fingerprint.
        let fingerprint = encode_key_data(key_data)
            .ok()
            .map(|bytes| compute_sha256_fingerprint(&bytes, key_type));

        keys.push(SshKey {
            path: std::path::PathBuf::from(if identity.comment.is_empty() {
                format!("agent:{:?}", key_type)
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
        });
    }

    Ok(keys)
}

/// Encode `ssh_key 0.6` `KeyData` to bytes using the `Encode` trait.
#[cfg(feature = "agent")]
fn encode_key_data(
    key_data: &ssh_agent_lib::ssh_key::public::KeyData,
) -> std::result::Result<Vec<u8>, ()> {
    use ssh_agent_lib::ssh_encoding::Encode;

    let len = key_data.encoded_len().map_err(|_| ())?;
    let mut buf = Vec::with_capacity(len);
    key_data.encode(&mut buf).map_err(|_| ())?;
    Ok(buf)
}

/// Compute a SHA-256 fingerprint from raw public key bytes.
fn compute_sha256_fingerprint(bytes: &[u8], key_type: KeyType) -> Fingerprint {
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    use base64::Engine;
    use ssh_key::sha2::{Digest, Sha256};

    let hash = Sha256::digest(bytes);
    Fingerprint {
        hash: STANDARD_NO_PAD.encode(hash),
        key_type,
    }
}

/// Map an algorithm name string (e.g. "ssh-ed25519", "ssh-rsa") to [`KeyType`].
pub(crate) fn parse_key_type_from_algorithm(alg: &str) -> KeyType {
    match alg {
        "ssh-ed25519" => KeyType::Ed25519,
        "ssh-rsa" => KeyType::Rsa { bits: 0 },
        "ecdsa-sha2-nistp256" => KeyType::EcdsaP256,
        "ecdsa-sha2-nistp384" => KeyType::EcdsaP384,
        "ecdsa-sha2-nistp521" => KeyType::EcdsaP521,
        "ssh-dss" => KeyType::Dsa,
        "sk-ssh-ed25519@openssh.com" => KeyType::SkEd25519,
        "sk-ecdsa-sha2-nistp256@openssh.com" => KeyType::SkEcdsaP256,
        _ => {
            tracing::warn!("unknown SSH key algorithm \"{alg}\", falling back to Ed25519");
            KeyType::Ed25519
        }
    }
}

// ---------------------------------------------------------------------------
// CLI fallback
// ---------------------------------------------------------------------------

/// Parse `ssh-add -l` output into a list of [`SshKey`] values.
async fn list_identities_via_cli() -> Result<Vec<SshKey>> {
    let output = runner::ssh_add_list().await?;
    let mut keys = Vec::new();

    for line in output.lines() {
        if let Some(key) = parse_ssh_add_line(line) {
            keys.push(key);
        }
    }

    Ok(keys)
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
    let (rest, key_type_str) = if let Some(start) = rest.rfind('(') {
        if let Some(end) = rest[start..].find(')') {
            let kt = &rest[start + 1..start + end];
            (rest[..start].trim_end(), kt.to_string())
        } else {
            (rest, String::new())
        }
    } else {
        (rest, String::new())
    };

    let key_type = parse_key_type_from_display(&key_type_str)?;

    // Split fingerprint from comment.
    let (fingerprint_str, comment) = if let Some(space) = rest.find(' ') {
        let (fp, c) = rest.split_at(space);
        let c = c.trim();
        (
            fp.to_string(),
            if c.is_empty() {
                None
            } else {
                Some(c.to_string())
            },
        )
    } else {
        (rest.to_string(), None)
    };

    let hash = fingerprint_str
        .strip_prefix("SHA256:")
        .unwrap_or(&fingerprint_str)
        .to_string();

    Some(SshKey {
        path: std::path::PathBuf::from(format!(
            "agent:{}",
            comment.as_deref().unwrap_or("unknown")
        )),
        key_type,
        fingerprint: Some(Fingerprint { hash, key_type }),
        comment,
        encrypted: false,
        source: KeySource::Agent,
        permissions: None,
        has_public_pair: false,
        has_certificate: false,
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
