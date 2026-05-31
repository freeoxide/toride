//! SSH key generation via ssh-keygen CLI and ssh-key crate for parsing.

use base64::Engine;

use crate::key::get_permissions;
use crate::paths::SshPaths;
use crate::{CliRunner, Error, Fingerprint, KeyCreateParams, KeyFormat, KeySource, KeyType, Result, SshKey};

/// Minimum RSA key size accepted by OpenSSH.
const MIN_RSA_BITS: u32 = 1024;

/// Recommended RSA key size (doctor flags RSA-2048 as weak).
const RECOMMENDED_RSA_BITS: u32 = 3072;

/// Timeout for `ssh-add` to complete (e.g. waiting for passphrase prompt).
const SSH_ADD_TIMEOUT_SECS: u64 = 30;

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
    if let KeyType::Rsa { bits } = params.key_type
        && bits > 0
    {
        args.extend(["-b".to_owned(), bits.to_string()]);
    }

    // ECDSA curve size (via -b flag)
    if params.key_type == KeyType::EcdsaP256 {
        args.extend(["-b".to_owned(), "256".to_owned()]);
    }
    if params.key_type == KeyType::EcdsaP384 {
        args.extend(["-b".to_owned(), "384".to_owned()]);
    }
    if params.key_type == KeyType::EcdsaP521 {
        args.extend(["-b".to_owned(), "521".to_owned()]);
    }

    if let Some(ref comment) = params.comment {
        args.extend(["-C".to_owned(), comment.clone()]);
    }

    if let Some(rounds) = params.kdf_rounds {
        args.extend(["-a".to_owned(), rounds.to_string()]);
    }

    if params.touch_required {
        args.extend(["-O".to_owned(), "touch-required".to_owned()]);
    }

    if params.verify_required {
        args.extend(["-O".to_owned(), "verify-required".to_owned()]);
    }

    args
}

/// Generate a new SSH key pair.
#[expect(clippy::too_many_lines, reason = "orchestrates generation, permissions, agent, config")]
pub async fn generate_key(
    paths: &SshPaths,
    params: KeyCreateParams,
    runner: &dyn CliRunner,
) -> Result<SshKey> {
    let private_path = paths.ssh_dir().join(&params.name);
    let public_path = private_path.with_extension("pub");

    if private_path.exists() {
        return Err(Error::KeyExists(params.name.clone()));
    }

    if !runner.tool_exists("ssh-keygen") {
        return Err(Error::ToolNotFound("ssh-keygen".to_owned()));
    }

    // Validate RSA bit size early to give a clear error before calling ssh-keygen.
    if let KeyType::Rsa { bits } = params.key_type
        && bits > 0
        && bits < MIN_RSA_BITS
    {
        return Err(Error::KeyGenerationFailed(format!(
            "RSA bit size {bits} is below minimum {MIN_RSA_BITS}"
        )));
    }

    // Warn (but do not error) when RSA bits are below the recommended size.
    if let KeyType::Rsa { bits } = params.key_type
        && bits > 0
        && bits < RECOMMENDED_RSA_BITS
    {
        tracing::warn!(
            "RSA key size {bits} is below the recommended {RECOMMENDED_RSA_BITS} bits; \
             consider using at least {RECOMMENDED_RSA_BITS} bits or switching to Ed25519"
        );
    }

    let passphrase_nonempty = params
        .passphrase
        .as_deref()
        .is_some_and(|p| !p.is_empty());

    let private_path_str = private_path
        .to_str()
        .ok_or_else(|| Error::KeyGenerationFailed("invalid key path".to_owned()))?;

    let args = build_keygen_args(&params, private_path_str);
    runner.run("ssh-keygen", args).await?;

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
        add_key_to_agent(&private_path, runner).await?;
    }

    // Add to SSH config if requested.
    if params.add_to_config {
        let host_alias = params
            .config_host
            .as_deref()
            .unwrap_or(&params.name)
            .to_owned();
        let identity_value = format!("~/.ssh/{}", params.name);
        let config_service = crate::config::ConfigService::new(paths);
        config_service
            .edit(|ast| {
                crate::config::ConfigService::add_host(
                    ast,
                    &host_alias,
                    vec![
                        ("HostName".to_owned(), host_alias.clone()),
                        ("IdentityFile".to_owned(), identity_value),
                    ],
                )
            })
            .await?;
    }

    let public_key = pk.public_key();
    let fp = public_key.fingerprint(ssh_key::HashAlg::Sha256);
    let fingerprint = Some(Fingerprint {
        hash: base64::engine::general_purpose::STANDARD_NO_PAD.encode(fp.as_bytes()),
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
        last_modified: None,
        used_by_hosts: Vec::new(),
        key_format: Some(KeyFormat::OpenSSH),
    })
}

/// Add a key to the SSH agent.
///
/// Delegates to [`CliRunner::run`] so the call is testable with
/// [`MockCliRunner`].  A `tokio::time::timeout` wraps the call so that a
/// stuck agent (e.g. waiting for a passphrase prompt that never arrives) does
/// not hang indefinitely.
async fn add_key_to_agent(private_path: &std::path::Path, runner: &dyn CliRunner) -> Result<()> {
    let path_str = private_path
        .to_str()
        .ok_or_else(|| Error::CommandFailed("key path is not valid UTF-8".to_owned()))?
        .to_owned();

    let args = vec![path_str];

    tokio::time::timeout(
        std::time::Duration::from_secs(SSH_ADD_TIMEOUT_SECS),
        runner.run("ssh-add", args),
    )
    .await
    .map_err(|_| {
        Error::CommandFailed(format!(
            "ssh-add timed out after {SSH_ADD_TIMEOUT_SECS} seconds"
        ))
    })??;

    Ok(())
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
            touch_required: false,
            verify_required: false,
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
            touch_required: false,
            verify_required: false,
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
            touch_required: false,
            verify_required: false,
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
            touch_required: false,
            verify_required: false,
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
            touch_required: false,
            verify_required: false,
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
            touch_required: false,
            verify_required: false,
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
            touch_required: false,
            verify_required: false,
        };
        let args = build_keygen_args(&params, "/tmp/key");
        assert!(args.contains(&"-b".to_owned()));
        assert!(args.contains(&"521".to_owned()));
    }

    #[test]
    fn build_keygen_args_touch_required() {
        let params = KeyCreateParams {
            name: "id_sk".to_owned(),
            key_type: KeyType::SkEd25519,
            comment: None,
            passphrase: None,
            kdf_rounds: None,
            add_to_agent: false,
            add_to_config: false,
            config_host: None,
            touch_required: true,
            verify_required: false,
        };
        let args = build_keygen_args(&params, "/tmp/key");
        assert!(args.contains(&"-O".to_owned()));
        assert!(args.contains(&"touch-required".to_owned()));
        assert!(!args.contains(&"verify-required".to_owned()));
    }

    #[test]
    fn build_keygen_args_verify_required() {
        let params = KeyCreateParams {
            name: "id_sk".to_owned(),
            key_type: KeyType::SkEd25519,
            comment: None,
            passphrase: None,
            kdf_rounds: None,
            add_to_agent: false,
            add_to_config: false,
            config_host: None,
            touch_required: false,
            verify_required: true,
        };
        let args = build_keygen_args(&params, "/tmp/key");
        assert!(args.contains(&"-O".to_owned()));
        assert!(args.contains(&"verify-required".to_owned()));
        assert!(!args.contains(&"touch-required".to_owned()));
    }

    #[test]
    fn build_keygen_args_touch_and_verify_required() {
        let params = KeyCreateParams {
            name: "id_sk".to_owned(),
            key_type: KeyType::SkEcdsaP256,
            comment: None,
            passphrase: None,
            kdf_rounds: None,
            add_to_agent: false,
            add_to_config: false,
            config_host: None,
            touch_required: true,
            verify_required: true,
        };
        let args = build_keygen_args(&params, "/tmp/key");
        assert!(args.contains(&"touch-required".to_owned()));
        assert!(args.contains(&"verify-required".to_owned()));
    }

    #[test]
    fn build_keygen_args_no_fido_options_when_false() {
        let params = KeyCreateParams {
            name: "id_ed25519".to_owned(),
            key_type: KeyType::Ed25519,
            comment: None,
            passphrase: None,
            kdf_rounds: None,
            add_to_agent: false,
            add_to_config: false,
            config_host: None,
            touch_required: false,
            verify_required: false,
        };
        let args = build_keygen_args(&params, "/tmp/key");
        assert!(!args.contains(&"touch-required".to_owned()));
        assert!(!args.contains(&"verify-required".to_owned()));
    }
}
