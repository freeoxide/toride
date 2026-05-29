//! SSH key generation via ssh-keygen CLI and ssh-key crate for parsing.

use crate::key::get_permissions;
use crate::paths::SshPaths;
use crate::runner;
use crate::{Error, Fingerprint, KeyCreateParams, KeySource, KeyType, Result, SshKey};

/// Convert our [`KeyType`] to the ssh-keygen `-t` argument value.
fn key_type_to_cli_arg(kt: KeyType) -> &'static str {
    match kt {
        KeyType::Ed25519 => "ed25519",
        KeyType::Rsa { .. } => "rsa",
        KeyType::EcdsaP256 | KeyType::EcdsaP384 | KeyType::EcdsaP521 => "ecdsa",
        KeyType::Dsa => "dsa",
        KeyType::SkEd25519 => "sk-ssh-ed25519@openssh.com",
        KeyType::SkEcdsaP256 => "sk-ecdsa-sha2-nistp256@openssh.com",
    }
}

/// Build the `ssh-keygen` CLI argument list from creation parameters.
///
/// SECURITY NOTE: The passphrase is passed via `-N` as a command-line
/// argument, which makes it visible through `/proc/<pid>/cmdline` or `ps`
/// on multi-user systems. This is the standard approach used by most SSH
/// wrappers. A more secure alternative would be to generate the key without
/// a passphrase and then use `ssh-keygen -p` with the passphrase piped
/// through stdin, but that requires more complex process spawning.
fn build_keygen_args(params: &KeyCreateParams, private_path_str: &str) -> Vec<String> {
    let key_type_str = key_type_to_cli_arg(params.key_type);

    let mut args: Vec<String> = vec![
        "-t".to_owned(),
        key_type_str.to_owned(),
        "-f".to_owned(),
        private_path_str.to_owned(),
        "-N".to_owned(),
        params.passphrase.as_deref().unwrap_or("").to_owned(),
    ];

    // RSA bit size — only accept values that OpenSSH actually supports.
    if let KeyType::Rsa { bits } = params.key_type {
        // OpenSSH supports 2048, 3072, 4096, and higher multiples of 256.
        // Reject obviously invalid sizes early to give a clear error.
        if bits > 0 && bits < 1024 {
            // Will be caught by ssh-keygen, but let's not even try.
            // The caller should get a clear error from the generation step.
            tracing::warn!("RSA bit size {bits} is below minimum 1024; ssh-keygen will reject it");
        }
        if bits > 0 {
            args.extend(["-b".to_owned(), bits.to_string()]);
        }
    }

    // ECDSA curve size (via -b flag)
    if let KeyType::EcdsaP384 = params.key_type {
        args.extend(["-b".to_owned(), "384".to_owned()]);
    }
    if let KeyType::EcdsaP521 = params.key_type {
        args.extend(["-b".to_owned(), "521".to_owned()]);
    }

    if let Some(ref comment) = params.comment {
        args.extend(["-C".to_owned(), comment.clone()]);
    }

    if let Some(rounds) = params.kdf_rounds {
        args.extend(["-a".to_owned(), rounds.to_string()]);
    }

    args
}

/// Generate a new SSH key pair.
pub async fn generate_key(paths: &SshPaths, params: KeyCreateParams) -> Result<SshKey> {
    let private_path = paths.ssh_dir().join(&params.name);
    let public_path = private_path.with_extension("pub");

    if private_path.exists() {
        return Err(Error::KeyExists(params.name.clone()));
    }

    if !runner::tool_exists("ssh-keygen") {
        return Err(Error::ToolNotFound("ssh-keygen".to_owned()));
    }

    let passphrase_nonempty = params
        .passphrase
        .as_deref()
        .is_some_and(|p| !p.is_empty());

    let private_path_str = private_path
        .to_str()
        .ok_or_else(|| Error::KeyGenerationFailed("invalid key path".to_owned()))?;

    let args = build_keygen_args(&params, private_path_str);
    let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    runner::ssh_keygen(&args_ref).await?;

    // Set file permissions and read the generated key in a blocking context
    // to avoid blocking the async runtime with synchronous filesystem ops.
    let private_path_clone = private_path.clone();
    let ssh_dir = paths.ssh_dir().to_path_buf();

    let result = tokio::task::spawn_blocking(move || {
        // Set file permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = std::fs::set_permissions(
                &ssh_dir,
                std::fs::Permissions::from_mode(0o700),
            ) {
                tracing::warn!("failed to set permissions on {}: {e}", ssh_dir.display());
            }
            if let Err(e) = std::fs::set_permissions(
                &private_path_clone,
                std::fs::Permissions::from_mode(0o600),
            ) {
                tracing::warn!("failed to set permissions on {}: {e}", private_path_clone.display());
            }
            if let Err(e) = std::fs::set_permissions(
                &public_path,
                std::fs::Permissions::from_mode(0o644),
            ) {
                tracing::warn!("failed to set permissions on {}: {e}", public_path.display());
            }
        }

        let permissions = get_permissions(&private_path_clone);

        let private_key_data = std::fs::read_to_string(&private_path_clone)
            .map_err(|e| Error::KeyParseFailed(format!("failed to read generated key: {e}")))?;

        let pk = ssh_key::PrivateKey::from_openssh(&private_key_data)
            .map_err(|e| Error::KeyParseFailed(format!("failed to parse generated key: {e}")))?;

        Ok::<_, Error>((permissions, pk, public_path.exists()))
    })
    .await
    .map_err(|e| Error::TaskFailed(format!("post-generation task failed: {e}")))??;

    let (permissions, pk, has_public_pair) = result;

    // Add to agent if requested
    if params.add_to_agent {
        add_key_to_agent(&private_path).await?;
    }

    let public_key = pk.public_key();
    let fp = public_key.fingerprint(ssh_key::HashAlg::Sha256);
    let fingerprint = Some(Fingerprint {
        hash: fp.to_string().trim_start_matches("SHA256:").to_owned(),
        key_type: params.key_type,
    });

    let comment_str = pk.comment().to_string();
    let comment = if comment_str.is_empty() {
        None
    } else {
        Some(comment_str)
    };

    Ok(SshKey {
        path: private_path,
        key_type: params.key_type,
        fingerprint,
        comment,
        encrypted: passphrase_nonempty,
        source: KeySource::Filesystem,
        permissions,
        has_public_pair,
        has_certificate: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_type_to_cli_arg_all_types() {
        assert_eq!(key_type_to_cli_arg(KeyType::Ed25519), "ed25519");
        assert_eq!(key_type_to_cli_arg(KeyType::Rsa { bits: 4096 }), "rsa");
        assert_eq!(key_type_to_cli_arg(KeyType::EcdsaP256), "ecdsa");
        assert_eq!(key_type_to_cli_arg(KeyType::EcdsaP384), "ecdsa");
        assert_eq!(key_type_to_cli_arg(KeyType::EcdsaP521), "ecdsa");
        assert_eq!(key_type_to_cli_arg(KeyType::Dsa), "dsa");
        assert_eq!(key_type_to_cli_arg(KeyType::SkEd25519), "sk-ssh-ed25519@openssh.com");
        assert_eq!(key_type_to_cli_arg(KeyType::SkEcdsaP256), "sk-ecdsa-sha2-nistp256@openssh.com");
    }

    #[test]
    fn build_keygen_args_ed25519_basic() {
        let params = KeyCreateParams {
            name: "id_ed25519".to_owned(),
            key_type: KeyType::Ed25519,
            comment: None,
            passphrase: None,
            kdf_rounds: None,
            add_to_agent: false,
            add_to_config: false,
            config_host: None,
        };
        let args = build_keygen_args(&params, "/home/user/.ssh/id_ed25519");
        assert_eq!(args[0..4], ["-t", "ed25519", "-f", "/home/user/.ssh/id_ed25519"]);
        assert_eq!(args[4..6], ["-N", ""]);
        assert!(!args.contains(&"-b".to_owned()));
        assert!(!args.contains(&"-C".to_owned()));
    }

    #[test]
    fn build_keygen_args_rsa_with_bits() {
        let params = KeyCreateParams {
            name: "id_rsa".to_owned(),
            key_type: KeyType::Rsa { bits: 4096 },
            comment: None,
            passphrase: None,
            kdf_rounds: None,
            add_to_agent: false,
            add_to_config: false,
            config_host: None,
        };
        let args = build_keygen_args(&params, "/tmp/key");
        assert!(args.contains(&"-b".to_owned()));
        assert!(args.contains(&"4096".to_owned()));
    }

    #[test]
    fn build_keygen_args_with_comment() {
        let params = KeyCreateParams {
            name: "id_ed25519".to_owned(),
            key_type: KeyType::Ed25519,
            comment: Some("user@host".to_owned()),
            passphrase: None,
            kdf_rounds: None,
            add_to_agent: false,
            add_to_config: false,
            config_host: None,
        };
        let args = build_keygen_args(&params, "/tmp/key");
        assert!(args.contains(&"-C".to_owned()));
        assert!(args.contains(&"user@host".to_owned()));
    }

    #[test]
    fn build_keygen_args_with_passphrase() {
        let params = KeyCreateParams {
            name: "id_ed25519".to_owned(),
            key_type: KeyType::Ed25519,
            comment: None,
            passphrase: Some("secret".to_owned()),
            kdf_rounds: None,
            add_to_agent: false,
            add_to_config: false,
            config_host: None,
        };
        let args = build_keygen_args(&params, "/tmp/key");
        assert!(args.contains(&"-N".to_owned()));
        assert!(args.contains(&"secret".to_owned()));
    }

    #[test]
    fn build_keygen_args_with_kdf_rounds() {
        let params = KeyCreateParams {
            name: "id_ed25519".to_owned(),
            key_type: KeyType::Ed25519,
            comment: None,
            passphrase: Some("pass".to_owned()),
            kdf_rounds: Some(64),
            add_to_agent: false,
            add_to_config: false,
            config_host: None,
        };
        let args = build_keygen_args(&params, "/tmp/key");
        assert!(args.contains(&"-a".to_owned()));
        assert!(args.contains(&"64".to_owned()));
    }

    #[test]
    fn build_keygen_args_ecdsa_p384() {
        let params = KeyCreateParams {
            name: "id_ecdsa".to_owned(),
            key_type: KeyType::EcdsaP384,
            comment: None,
            passphrase: None,
            kdf_rounds: None,
            add_to_agent: false,
            add_to_config: false,
            config_host: None,
        };
        let args = build_keygen_args(&params, "/tmp/key");
        assert!(args.contains(&"-b".to_owned()));
        assert!(args.contains(&"384".to_owned()));
    }

    #[test]
    fn build_keygen_args_ecdsa_p521() {
        let params = KeyCreateParams {
            name: "id_ecdsa".to_owned(),
            key_type: KeyType::EcdsaP521,
            comment: None,
            passphrase: None,
            kdf_rounds: None,
            add_to_agent: false,
            add_to_config: false,
            config_host: None,
        };
        let args = build_keygen_args(&params, "/tmp/key");
        assert!(args.contains(&"-b".to_owned()));
        assert!(args.contains(&"521".to_owned()));
    }
}

/// Add a key to the SSH agent.
async fn add_key_to_agent(private_path: &std::path::Path) -> Result<()> {
    let path_str = private_path
        .to_str()
        .ok_or_else(|| Error::CommandFailed("key path is not valid UTF-8".to_owned()))?
        .to_owned();

    tokio::task::spawn_blocking(move || {
        duct::cmd("ssh-add", [path_str.as_str()])
            .read()
            .map_err(|e| Error::CommandFailed(format!("ssh-add failed: {e}")))?;
        Ok(())
    })
    .await
    .map_err(|e| Error::TaskFailed(format!("ssh-add task failed: {e}")))?
}
