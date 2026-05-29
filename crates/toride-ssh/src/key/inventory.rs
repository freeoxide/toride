//! SSH key file discovery and parsing.

use std::ffi::OsStr;
use std::path::PathBuf;

use crate::key::get_permissions;
use crate::paths::SshPaths;
use crate::{Error, Fingerprint, KeySource, KeyType, Result, SshKey};

/// Convert an [`ssh_key::Algorithm`] to our [`KeyType`].
///
/// Returns `None` for unknown algorithms so callers can decide how to handle them
/// rather than silently misidentifying the key type.
fn algorithm_to_key_type(algo: &ssh_key::Algorithm) -> Option<KeyType> {
    match algo {
        ssh_key::Algorithm::Ed25519 => Some(KeyType::Ed25519),
        ssh_key::Algorithm::Rsa { .. } => Some(KeyType::Rsa { bits: 0 }),
        ssh_key::Algorithm::Ecdsa { curve } => Some(match curve {
            ssh_key::EcdsaCurve::NistP256 => KeyType::EcdsaP256,
            ssh_key::EcdsaCurve::NistP384 => KeyType::EcdsaP384,
            ssh_key::EcdsaCurve::NistP521 => KeyType::EcdsaP521,
        }),
        ssh_key::Algorithm::Dsa => Some(KeyType::Dsa),
        ssh_key::Algorithm::SkEd25519 => Some(KeyType::SkEd25519),
        ssh_key::Algorithm::SkEcdsaSha2NistP256 => Some(KeyType::SkEcdsaP256),
        _ => {
            tracing::warn!("unknown key algorithm: {:?}", algo);
            None
        }
    }
}

/// Try to parse a private key file and determine its metadata.
fn inspect_private_key(path: &std::path::Path) -> Result<SshKey> {
    let path = path.to_path_buf();
    let filename = path
        .file_name()
        .unwrap_or(OsStr::new(""))
        .to_string_lossy()
        .into_owned();

    let pub_path = path.with_extension("pub");
    let cert_path = {
        let name = path.file_name().unwrap_or(OsStr::new("")).to_string_lossy();
        path.with_file_name(format!("{name}-cert.pub"))
    };

    let has_public_pair = pub_path.exists();
    let has_certificate = cert_path.exists();
    let permissions = get_permissions(&path);

    let private_key_data = std::fs::read_to_string(&path)
        .map_err(|e| Error::KeyParseFailed(format!("failed to read {filename}: {e}")))?;

    // Check the file content for encryption markers which is more
    // reliable than parsing the error message string.
    let is_encrypted_from_content = is_likely_encrypted(&private_key_data);

    match ssh_key::PrivateKey::from_openssh(&private_key_data) {
        Ok(pk) => {
            // Explicit fallback: if we can't determine the algorithm, treat as
            // Ed25519. This is a best-effort heuristic for encrypted/unknown keys.
            let key_type = algorithm_to_key_type(&pk.algorithm())
                .unwrap_or(KeyType::Ed25519);
            let public_key = pk.public_key();
            let fp = public_key.fingerprint(ssh_key::HashAlg::Sha256);
            let fingerprint = Some(Fingerprint {
                hash: fp.to_string().trim_start_matches("SHA256:").to_owned(),
                key_type,
            });
            let comment_str = pk.comment().to_string();
            let comment = if comment_str.is_empty() {
                None
            } else {
                Some(comment_str)
            };

            Ok(SshKey {
                path,
                key_type,
                fingerprint,
                comment,
                encrypted: false,
                source: KeySource::Filesystem,
                permissions,
                has_public_pair,
                has_certificate,
            })
        }
        Err(e) => {
            // If parsing failed because the key is encrypted, we still want
            // to return a useful entry. Use content-based detection first,
            // then fall back to error message matching for edge cases.
            let err_str = e.to_string();
            let is_encrypted = is_encrypted_from_content
                || err_str.contains("encrypted")
                || err_str.contains("passphrase")
                || err_str.contains("cipher")
                || err_str.contains("bcrypt");

            // For encrypted keys, try to infer key type from the filename
            let key_type = guess_key_type_from_name(&filename);

            Ok(SshKey {
                path,
                key_type,
                fingerprint: None,
                comment: None,
                encrypted: is_encrypted,
                source: KeySource::Filesystem,
                permissions,
                has_public_pair,
                has_certificate,
            })
        }
    }
}

/// Check whether raw key file content indicates an encrypted private key.
///
/// OpenSSH encrypted keys contain `ENCRYPTED` in the header guard line.
/// PEM-encrypted keys contain `ENCRYPTED` in the proc-type header.
fn is_likely_encrypted(data: &str) -> bool {
    // OpenSSH format: "-----BEGIN OPENSSH PRIVATE KEY-----\n...encrypted..."
    // Check for "ENCRYPTED" keyword in the first few lines of the header.
    for line in data.lines().take(5) {
        // OpenSSH encrypted keys contain "ENCRYPTED" in the header.
        // PEM format: "Proc-Type: 4,ENCRYPTED"
        if line.contains("ENCRYPTED") || line.contains("encrypted") {
            return true;
        }
    }
    false
}

/// Guess key type from a filename like `id_ed25519`, `id_rsa`, etc.
///
/// Security key (FIDO) variants are checked first since their names contain
/// the base algorithm as a substring (e.g., `id_ed25519_sk` contains `ed25519`).
fn guess_key_type_from_name(name: &str) -> KeyType {
    let lower = name.to_ascii_lowercase();
    // Check FIDO/SK variants first since they also contain the base algo name
    if lower.contains("ed25519_sk") {
        KeyType::SkEd25519
    } else if lower.contains("ecdsa_sk") {
        KeyType::SkEcdsaP256
    } else if lower.contains("ed25519") {
        KeyType::Ed25519
    } else if lower.contains("ecdsa") {
        KeyType::EcdsaP256
    } else if lower.contains("rsa") {
        KeyType::Rsa { bits: 0 }
    } else if lower.contains("dsa") {
        KeyType::Dsa
    } else {
        KeyType::Ed25519
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guess_key_type_from_name_ed25519() {
        assert!(matches!(guess_key_type_from_name("id_ed25519"), KeyType::Ed25519));
    }

    #[test]
    fn guess_key_type_from_name_rsa() {
        assert!(matches!(guess_key_type_from_name("id_rsa"), KeyType::Rsa { .. }));
    }

    #[test]
    fn guess_key_type_from_name_ecdsa() {
        assert!(matches!(guess_key_type_from_name("id_ecdsa"), KeyType::EcdsaP256));
    }

    #[test]
    fn guess_key_type_from_name_dsa() {
        assert!(matches!(guess_key_type_from_name("id_dsa"), KeyType::Dsa));
    }

    #[test]
    fn guess_key_type_from_name_sk_ed25519() {
        // SK variants must be checked before base algo (ed25519_sk contains "ed25519")
        assert!(matches!(guess_key_type_from_name("id_ed25519_sk"), KeyType::SkEd25519));
    }

    #[test]
    fn guess_key_type_from_name_sk_ecdsa() {
        assert!(matches!(guess_key_type_from_name("id_ecdsa_sk"), KeyType::SkEcdsaP256));
    }

    #[test]
    fn guess_key_type_from_name_unknown_defaults_to_ed25519() {
        assert!(matches!(guess_key_type_from_name("my_custom_key"), KeyType::Ed25519));
    }

    #[test]
    fn guess_key_type_from_name_case_insensitive() {
        assert!(matches!(guess_key_type_from_name("ID_ED25519"), KeyType::Ed25519));
        assert!(matches!(guess_key_type_from_name("Id_RSA"), KeyType::Rsa { .. }));
    }

    #[test]
    fn is_likely_encrypted_openssh_format() {
        // OpenSSH encrypted keys have "ENCRYPTED" in the header comment area.
        let data = "-----BEGIN OPENSSH PRIVATE KEY-----\nENCRYPTED\nb3BlbnNzaC1rZXktdjEAAAA...\n";
        assert!(is_likely_encrypted(data));
    }

    #[test]
    fn is_likely_encrypted_pem_format() {
        let data = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,...\n";
        assert!(is_likely_encrypted(data));
    }

    #[test]
    fn is_likely_encrypted_unencrypted() {
        let data = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAEbm9uZQAAAAEAAAAEAAA...\n";
        assert!(!is_likely_encrypted(data));
    }

    #[test]
    fn is_likely_encrypted_empty() {
        assert!(!is_likely_encrypted(""));
    }

    #[test]
    fn algorithm_to_key_type_all_known() {
        assert!(algorithm_to_key_type(&ssh_key::Algorithm::Ed25519).is_some());
        assert!(algorithm_to_key_type(&ssh_key::Algorithm::Rsa { hash: None }).is_some());
        assert!(algorithm_to_key_type(&ssh_key::Algorithm::Ecdsa { curve: ssh_key::EcdsaCurve::NistP256 }).is_some());
        assert!(algorithm_to_key_type(&ssh_key::Algorithm::Ecdsa { curve: ssh_key::EcdsaCurve::NistP384 }).is_some());
        assert!(algorithm_to_key_type(&ssh_key::Algorithm::Ecdsa { curve: ssh_key::EcdsaCurve::NistP521 }).is_some());
        assert!(algorithm_to_key_type(&ssh_key::Algorithm::Dsa).is_some());
        assert!(algorithm_to_key_type(&ssh_key::Algorithm::SkEd25519).is_some());
        assert!(algorithm_to_key_type(&ssh_key::Algorithm::SkEcdsaSha2NistP256).is_some());
    }

    #[test]
    fn algorithm_to_key_type_ecdsa_curves() {
        let p256 = algorithm_to_key_type(&ssh_key::Algorithm::Ecdsa { curve: ssh_key::EcdsaCurve::NistP256 }).unwrap();
        assert!(matches!(p256, KeyType::EcdsaP256));

        let p384 = algorithm_to_key_type(&ssh_key::Algorithm::Ecdsa { curve: ssh_key::EcdsaCurve::NistP384 }).unwrap();
        assert!(matches!(p384, KeyType::EcdsaP384));

        let p521 = algorithm_to_key_type(&ssh_key::Algorithm::Ecdsa { curve: ssh_key::EcdsaCurve::NistP521 }).unwrap();
        assert!(matches!(p521, KeyType::EcdsaP521));
    }
}

/// Scan `~/.ssh/id_*` and the agent for available keys.
pub async fn scan_keys(paths: &SshPaths) -> Result<Vec<SshKey>> {
    let ssh_dir = paths.ssh_dir().to_path_buf();
    let default_names = SshPaths::default_key_names();

    tokio::task::spawn_blocking(move || {
        let mut keys = Vec::new();
        let mut seen_names = std::collections::HashSet::<std::ffi::OsString>::new();

        // Read directory entries
        let entries = match std::fs::read_dir(&ssh_dir) {
            Ok(entries) => entries,
            Err(e) => {
                // If the .ssh directory doesn't exist, return an empty list
                if e.kind() == std::io::ErrorKind::NotFound {
                    return Ok(keys);
                }
                return Err(Error::Io(e));
            }
        };

        // Collect all id_* files that are NOT .pub or -cert.pub
        let mut private_key_paths: Vec<PathBuf> = Vec::new();

        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();

            // Skip non-id_* files, public keys, certificates, and backups
            if !name.starts_with("id_") {
                continue;
            }
            if name.ends_with(".pub") || name.ends_with(".bak") || name.ends_with(".old") {
                continue;
            }

            // Only consider regular files
            let file_type = entry.file_type()?;
            if !file_type.is_file() {
                continue;
            }

            // Deduplicate by base name
            if seen_names.insert(file_name.clone()) {
                private_key_paths.push(entry.path());
            }
        }

        // Ensure all default key names are checked even if not in directory listing
        for &default_name in default_names {
            let default_os: std::ffi::OsString = default_name.into();
            if seen_names.insert(default_os) {
                let default_path = ssh_dir.join(default_name);
                if default_path.is_file() {
                    private_key_paths.push(default_path);
                }
            }
        }

        // Sort for deterministic output
        private_key_paths.sort();

        // Inspect each private key
        for path in private_key_paths {
            match inspect_private_key(&path) {
                Ok(key) => keys.push(key),
                Err(e) => {
                    // Log but don't fail the entire scan for one bad key
                    tracing::warn!(
                        "skipping key {}: {}",
                        path.display(),
                        e
                    );
                }
            }
        }

        Ok(keys)
    })
    .await
    .map_err(|e| Error::TaskFailed(format!("scan_keys task failed: {e}")))?
}
