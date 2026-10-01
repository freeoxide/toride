use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

use base64::Engine;

use crate::get_permissions;
use toride_ssh_core::SshPaths;
use toride_ssh_core::{Error, Fingerprint, KeyFormat, KeySource, KeyType, Result, SshKey};

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

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    mtime_ns: u128,
    len: u64,
}

struct CachedKey {
    stamp: FileStamp,
    key: SshKey,
}

static KEY_PARSE_CACHE: LazyLock<Mutex<HashMap<PathBuf, CachedKey>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn key_stamp(metadata: &std::fs::Metadata) -> Option<FileStamp> {
    let mtime_ns = metadata
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_nanos();
    Some(FileStamp {
        mtime_ns,
        len: metadata.len(),
    })
}

pub(crate) fn inspect_private_key_cached(path: &Path) -> Result<SshKey> {
    let metadata = std::fs::metadata(path).map_err(|e| Error::KeyParseFailed(format!("{e}")))?;
    let Some(stamp) = key_stamp(&metadata) else {
        return inspect_private_key(path);
    };

    {
        let cache = KEY_PARSE_CACHE
            .lock()
            .expect("key parse cache mutex poisoned");
        if let Some(entry) = cache.get(path)
            && entry.stamp == stamp
        {
            return Ok(entry.key.clone());
        }
    }

    let key = inspect_private_key(path)?;
    KEY_PARSE_CACHE
        .lock()
        .expect("key parse cache mutex poisoned")
        .insert(
            path.to_path_buf(),
            CachedKey {
                stamp,
                key: key.clone(),
            },
        );
    Ok(key)
}

#[cfg(test)]
pub(crate) fn clear_key_cache_for_tests() {
    KEY_PARSE_CACHE
        .lock()
        .expect("key parse cache mutex poisoned")
        .clear();
}

fn inspect_private_key(path: &std::path::Path) -> Result<SshKey> {
    let path = path.to_path_buf();
    let filename = path
        .file_name()
        .unwrap_or_else(|| OsStr::new(""))
        .to_string_lossy()
        .into_owned();

    let pub_path = path.with_extension("pub");
    let cert_path = {
        let name = path
            .file_name()
            .unwrap_or_else(|| OsStr::new(""))
            .to_string_lossy();
        path.with_file_name(format!("{name}-cert.pub"))
    };

    let has_public_pair = pub_path.exists();
    let has_certificate = cert_path.exists();
    let permissions = get_permissions(&path);
    let last_modified = std::fs::metadata(&path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs());

    let private_key_data = std::fs::read_to_string(&path)
        .map_err(|e| Error::KeyParseFailed(format!("failed to read {filename}: {e}")))?;

    let is_encrypted_from_content = is_likely_encrypted(&private_key_data);

    let key_format = detect_key_format(&private_key_data);

    match ssh_key::PrivateKey::from_openssh(&private_key_data) {
        Ok(pk) => {
            let mut key_type = algorithm_to_key_type(&pk.algorithm()).unwrap_or(KeyType::Ed25519);
            let public_key = pk.public_key();

            if matches!(key_type, KeyType::Rsa { .. })
                && let Some(rsa_public) = public_key.key_data().rsa()
            {
                let bits = rsa_public.key_size();
                key_type = KeyType::Rsa { bits };
            }
            let fp = public_key.fingerprint(ssh_key::HashAlg::Sha256);
            let fingerprint = Some(Fingerprint {
                hash: base64::engine::general_purpose::STANDARD_NO_PAD.encode(fp.as_bytes()),
                key_type,
            });
            let comment_str = pk.comment().to_string();
            let comment = if comment_str.is_empty() {
                None
            } else {
                Some(comment_str)
            };

            let resolved_format = key_format.or(Some(KeyFormat::OpenSSH));

            Ok(SshKey {
                path,
                key_type,
                fingerprint,
                comment,
                encrypted: pk.is_encrypted() || is_encrypted_from_content,
                source: KeySource::Filesystem,
                permissions,
                has_public_pair,
                has_certificate,
                last_modified,
                used_by_hosts: Vec::new(),
                key_format: resolved_format,
            })
        }
        Err(e) => {
            let err_str = e.to_string();
            let is_encrypted = is_encrypted_from_content
                || err_str.contains("encrypted")
                || err_str.contains("passphrase")
                || err_str.contains("cipher")
                || err_str.contains("bcrypt");

            let mut key_type = guess_key_type_from_name(&filename);

            if matches!(
                key_type,
                KeyType::EcdsaP256 | KeyType::EcdsaP384 | KeyType::EcdsaP521
            ) && pub_path.exists()
                && let Ok(pub_data) = std::fs::read_to_string(&pub_path)
                && let Ok(pub_key) = ssh_key::PublicKey::from_openssh(&pub_data)
                && let Some(actual) = algorithm_to_key_type(&pub_key.algorithm())
            {
                key_type = actual;
            }

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
                last_modified,
                used_by_hosts: Vec::new(),
                key_format,
            })
        }
    }
}

fn is_likely_encrypted(data: &str) -> bool {
    let mut found = false;
    for line in data.lines().take(5) {
        if line.contains("ENCRYPTED") {
            found = true;
            break;
        }
    }
    if !found {
        found = data.lines().take(5).any(|line| line.contains("bcrypt"));
    }
    found
}

fn detect_key_format(data: &str) -> Option<KeyFormat> {
    let first_line = data.lines().next().unwrap_or("");
    if first_line.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
        Some(KeyFormat::OpenSSH)
    } else if first_line.starts_with("-----BEGIN ")
        && first_line.ends_with(" PRIVATE KEY-----")
        && !first_line.contains("OPENSSH")
    {
        Some(KeyFormat::Pem)
    } else {
        None
    }
}

fn guess_key_type_from_name(name: &str) -> KeyType {
    let lower = name.to_ascii_lowercase();
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

struct ConfigKeyScan {
    identity_paths: Vec<PathBuf>,
    pkcs11_providers: Vec<String>,
    identity_host_map: HashMap<PathBuf, Vec<String>>,
}

fn scan_ssh_config(ssh_dir: &Path) -> ConfigKeyScan {
    let config_path = ssh_dir.join("config");
    let Ok(ast) = toride_ssh_config::cache::load_cached_ast(&config_path) else {
        return ConfigKeyScan {
            identity_paths: Vec::new(),
            pkcs11_providers: Vec::new(),
            identity_host_map: HashMap::new(),
        };
    };
    let mut identity_paths = Vec::new();
    let mut seen_identity = HashSet::new();
    let mut pkcs11_providers = Vec::new();
    let mut seen_pkcs11 = HashSet::new();
    let mut identity_host_map: HashMap<PathBuf, Vec<String>> = HashMap::new();

    for node in &ast.nodes {
        let (host_alias, nodes): (Option<String>, &[toride_ssh_config::ast::ConfigNode]) =
            match node {
                toride_ssh_config::ast::ConfigNode::HostBlock(b) => {
                    let alias = b.patterns.first().cloned().unwrap_or_default();
                    (Some(alias), &b.nodes)
                }
                toride_ssh_config::ast::ConfigNode::MatchBlock(b) => (None, &b.nodes),
                toride_ssh_config::ast::ConfigNode::Directive(_) => {
                    (None, std::slice::from_ref(node))
                }
                _ => (None, &[]),
            };

        for child in nodes {
            if let toride_ssh_config::ast::ConfigNode::Directive(d) = child {
                if d.keyword.eq_ignore_ascii_case("IdentityFile") {
                    let trimmed = d.value.trim_matches('"').trim_matches('\'');
                    let expanded = toride_ssh_config::expand_identity_path(trimmed, ssh_dir);
                    if seen_identity.insert(expanded.clone()) {
                        identity_paths.push(expanded.clone());
                    }
                    if let Some(ref alias) = host_alias {
                        identity_host_map
                            .entry(expanded)
                            .or_default()
                            .push(alias.clone());
                    }
                } else if d.keyword.eq_ignore_ascii_case("PKCS11Provider")
                    && seen_pkcs11.insert(d.value.clone())
                {
                    pkcs11_providers.push(d.value.clone());
                }
            }
        }
    }

    ConfigKeyScan {
        identity_paths,
        pkcs11_providers,
        identity_host_map,
    }
}

fn check_ssh_v1_keys(ssh_dir: &Path) {
    let identity_path = ssh_dir.join("identity");
    let identity_pub_path = ssh_dir.join("identity.pub");

    if identity_path.exists() {
        tracing::warn!(
            "SSH v1 private key found at {} — SSH v1 is deprecated and insecure; \
             generate a new SSH v2 key (e.g. ed25519)",
            identity_path.display()
        );
    }
    if identity_pub_path.exists() {
        tracing::warn!(
            "SSH v1 public key found at {} — SSH v1 is deprecated and insecure; \
             generate a new SSH v2 key (e.g. ed25519)",
            identity_pub_path.display()
        );
    }
}

fn scan_standalone_pub_files(ssh_dir: &Path, known_private_keys: &HashSet<PathBuf>) -> Vec<SshKey> {
    let Ok(entries) = std::fs::read_dir(ssh_dir) else {
        return Vec::new();
    };

    let mut standalone = Vec::new();

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();

        if !name.ends_with(".pub") || name.ends_with("-cert.pub") {
            continue;
        }

        if name == "identity.pub" {
            continue;
        }

        let pub_path = entry.path();
        let private_path = pub_path.with_extension("");

        if known_private_keys.contains(&private_path) || private_path.exists() {
            continue;
        }

        let permissions = get_permissions(&pub_path);
        let last_modified = std::fs::metadata(&pub_path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs());

        let Ok(pub_data) = std::fs::read_to_string(&pub_path) else {
            continue;
        };

        let (key_type, fingerprint, comment) = match ssh_key::PublicKey::from_openssh(&pub_data) {
            Ok(pk) => {
                let kt = algorithm_to_key_type(&pk.algorithm()).unwrap_or(KeyType::Ed25519);
                let fp = pk.fingerprint(ssh_key::HashAlg::Sha256);
                let fingerprint = Some(Fingerprint {
                    hash: base64::engine::general_purpose::STANDARD_NO_PAD.encode(fp.as_bytes()),
                    key_type: kt,
                });
                let comment_str = pk.comment().to_string();
                let comment = if comment_str.is_empty() {
                    None
                } else {
                    Some(comment_str)
                };
                (kt, fingerprint, comment)
            }
            Err(_) => continue,
        };

        standalone.push(SshKey {
            path: pub_path,
            key_type,
            fingerprint,
            comment,
            encrypted: false,
            source: KeySource::Filesystem,
            permissions,
            has_public_pair: true,
            has_certificate: false,
            last_modified,
            used_by_hosts: Vec::new(),
            key_format: None,
        });
    }

    standalone
}

#[cfg(feature = "agent-integration")]
async fn merge_agent_keys(keys: &mut Vec<SshKey>, runner: &dyn toride_ssh_core::CliRunner) {
    let agent_keys = match toride_ssh_agent::list_identities(runner).await {
        Ok(keys) => keys,
        Err(Error::AgentNotAvailable) => return,
        Err(e) => {
            tracing::warn!("failed to query SSH agent for key inventory: {e}");
            return;
        }
    };

    let new_keys = filter_new_agent_keys(keys, agent_keys);
    keys.extend(new_keys);
}

#[cfg(feature = "agent-integration")]
fn filter_new_agent_keys(existing: &[SshKey], agent_keys: Vec<SshKey>) -> Vec<SshKey> {
    let fs_fingerprints: HashSet<&str> = existing
        .iter()
        .filter_map(|k| k.fingerprint.as_ref().map(|f| f.hash.as_str()))
        .collect();

    agent_keys
        .into_iter()
        .filter(|agent_key| {
            !agent_key
                .fingerprint
                .as_ref()
                .is_some_and(|f| fs_fingerprints.contains(f.hash.as_str()))
        })
        .collect()
}

async fn query_pkcs11_provider(
    provider: &str,
    runner: &dyn toride_ssh_core::CliRunner,
) -> (KeyType, Option<Fingerprint>) {
    if !runner.tool_exists("ssh-keygen") {
        tracing::warn!(
            "ssh-keygen not found, cannot query PKCS#11 provider {provider}; \
             defaulting to Ed25519"
        );
        return (KeyType::Ed25519, None);
    }

    let args = vec!["-D".to_owned(), provider.to_owned()];
    let output = match runner.run("ssh-keygen", args).await {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!("ssh-keygen -D {provider} failed: {e}; defaulting to Ed25519");
            return (KeyType::Ed25519, None);
        }
    };

    let Some(first_line) = output.lines().next() else {
        tracing::warn!("ssh-keygen -D {provider} produced no output; defaulting to Ed25519");
        return (KeyType::Ed25519, None);
    };

    if let Ok(pk) = ssh_key::PublicKey::from_openssh(first_line) {
        let key_type = algorithm_to_key_type(&pk.algorithm()).unwrap_or(KeyType::Ed25519);
        let fp = pk.fingerprint(ssh_key::HashAlg::Sha256);
        let fingerprint = Some(Fingerprint {
            hash: base64::engine::general_purpose::STANDARD_NO_PAD.encode(fp.as_bytes()),
            key_type,
        });
        (key_type, fingerprint)
    } else {
        tracing::warn!(
            "failed to parse ssh-keygen -D output for {provider}; defaulting to Ed25519"
        );
        (KeyType::Ed25519, None)
    }
}

fn scan_filesystem_keys(
    ssh_dir: &Path,
    default_names: &[&str],
    config_scan: &ConfigKeyScan,
) -> Result<Vec<SshKey>> {
    let mut keys = Vec::new();
    let mut seen_paths = HashSet::<PathBuf>::new();
    let mut private_key_paths: Vec<PathBuf> = Vec::new();

    let entries = match std::fs::read_dir(ssh_dir) {
        Ok(entries) => entries,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(keys);
            }
            return Err(Error::Io(e));
        }
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();

        if !name.starts_with("id_") {
            continue;
        }
        if name.ends_with(".pub") || name.ends_with(".bak") || name.ends_with(".old") {
            continue;
        }

        let file_type = entry.file_type()?;
        if !file_type.is_file() && !file_type.is_symlink() {
            continue;
        }

        if seen_paths.insert(entry.path()) {
            private_key_paths.push(entry.path());
        }
    }

    for &default_name in default_names {
        let default_path = ssh_dir.join(default_name);
        if default_path.is_file() && seen_paths.insert(default_path.clone()) {
            private_key_paths.push(default_path);
        }
    }

    for identity_path in &config_scan.identity_paths {
        if identity_path.is_file() && seen_paths.insert(identity_path.clone()) {
            private_key_paths.push(identity_path.clone());
        }
    }

    private_key_paths.sort();

    for path in &private_key_paths {
        match inspect_private_key_cached(path) {
            Ok(mut key) => {
                if let Some(hosts) = config_scan.identity_host_map.get(path) {
                    key.used_by_hosts.clone_from(hosts);
                }
                keys.push(key);
            }
            Err(e) => {
                tracing::warn!("skipping key {}: {}", path.display(), e);
            }
        }
    }

    check_ssh_v1_keys(ssh_dir);

    let standalone = scan_standalone_pub_files(ssh_dir, &seen_paths);
    keys.extend(standalone);

    Ok(keys)
}

pub async fn scan_keys(
    paths: &SshPaths,
    runner: Option<&dyn toride_ssh_core::CliRunner>,
) -> Result<Vec<SshKey>> {
    let ssh_dir = paths.ssh_dir().to_path_buf();
    let default_names = SshPaths::default_key_names();

    let config_scan = tokio::task::spawn_blocking(move || {
        let config_scan = scan_ssh_config(&ssh_dir);
        let keys = scan_filesystem_keys(&ssh_dir, default_names, &config_scan)?;
        Ok::<_, Error>((keys, config_scan))
    })
    .await
    .map_err(|e| Error::TaskFailed(format!("scan_keys task failed: {e}")))??;

    let (mut keys, config_scan) = (config_scan.0, config_scan.1);

    for provider in &config_scan.pkcs11_providers {
        tracing::info!("PKCS#11 provider detected in SSH config: {}", provider);
        let (key_type, fingerprint) = if let Some(r) = runner {
            query_pkcs11_provider(provider, r).await
        } else {
            (KeyType::Ed25519, None)
        };
        keys.push(SshKey {
            path: PathBuf::from(format!("pkcs11:{provider}")),
            key_type,
            fingerprint,
            comment: Some(format!("PKCS#11 provider: {provider}")),
            encrypted: false,
            source: KeySource::Pkcs11,
            permissions: None,
            has_public_pair: false,
            has_certificate: false,
            last_modified: None,
            used_by_hosts: Vec::new(),
            key_format: None,
        });
    }

    #[cfg(feature = "agent-integration")]
    if let Some(runner) = runner {
        merge_agent_keys(&mut keys, runner).await;
    }

    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guess_key_type_from_name_ed25519() {
        assert!(matches!(
            guess_key_type_from_name("id_ed25519"),
            KeyType::Ed25519
        ));
    }

    #[test]
    fn guess_key_type_from_name_rsa() {
        assert!(matches!(
            guess_key_type_from_name("id_rsa"),
            KeyType::Rsa { .. }
        ));
    }

    #[test]
    fn guess_key_type_from_name_ecdsa() {
        assert!(matches!(
            guess_key_type_from_name("id_ecdsa"),
            KeyType::EcdsaP256
        ));
    }

    #[test]
    fn guess_key_type_from_name_dsa() {
        assert!(matches!(guess_key_type_from_name("id_dsa"), KeyType::Dsa));
    }

    #[test]
    fn guess_key_type_from_name_sk_ed25519() {
        assert!(matches!(
            guess_key_type_from_name("id_ed25519_sk"),
            KeyType::SkEd25519
        ));
    }

    #[test]
    fn guess_key_type_from_name_sk_ecdsa() {
        assert!(matches!(
            guess_key_type_from_name("id_ecdsa_sk"),
            KeyType::SkEcdsaP256
        ));
    }

    #[test]
    fn guess_key_type_from_name_unknown_defaults_to_ed25519() {
        assert!(matches!(
            guess_key_type_from_name("my_custom_key"),
            KeyType::Ed25519
        ));
    }

    #[test]
    fn guess_key_type_from_name_case_insensitive() {
        assert!(matches!(
            guess_key_type_from_name("ID_ED25519"),
            KeyType::Ed25519
        ));
        assert!(matches!(
            guess_key_type_from_name("Id_RSA"),
            KeyType::Rsa { .. }
        ));
    }

    #[test]
    fn is_likely_encrypted_openssh_format() {
        let data = "-----BEGIN OPENSSH PRIVATE KEY-----\nENCRYPTED\nb3BlbnNzaC1rZXktdjEAAAA...\n";
        assert!(is_likely_encrypted(data));
    }

    #[test]
    fn is_likely_encrypted_pem_format() {
        let data =
            "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,...\n";
        assert!(is_likely_encrypted(data));
    }

    #[test]
    fn is_likely_encrypted_unencrypted() {
        let data =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAEbm9uZQAAAAEAAAAEAAA...\n";
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
        assert!(
            algorithm_to_key_type(&ssh_key::Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256
            })
            .is_some()
        );
        assert!(
            algorithm_to_key_type(&ssh_key::Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP384
            })
            .is_some()
        );
        assert!(
            algorithm_to_key_type(&ssh_key::Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP521
            })
            .is_some()
        );
        assert!(algorithm_to_key_type(&ssh_key::Algorithm::Dsa).is_some());
        assert!(algorithm_to_key_type(&ssh_key::Algorithm::SkEd25519).is_some());
        assert!(algorithm_to_key_type(&ssh_key::Algorithm::SkEcdsaSha2NistP256).is_some());
    }

    #[test]
    fn algorithm_to_key_type_ecdsa_curves() {
        let p256 = algorithm_to_key_type(&ssh_key::Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP256,
        })
        .unwrap();
        assert!(matches!(p256, KeyType::EcdsaP256));

        let p384 = algorithm_to_key_type(&ssh_key::Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP384,
        })
        .unwrap();
        assert!(matches!(p384, KeyType::EcdsaP384));

        let p521 = algorithm_to_key_type(&ssh_key::Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP521,
        })
        .unwrap();
        assert!(matches!(p521, KeyType::EcdsaP521));
    }

    #[test]
    fn guess_key_type_from_name_empty() {
        assert!(matches!(guess_key_type_from_name(""), KeyType::Ed25519));
    }

    #[test]
    fn guess_key_type_from_name_partial_match() {
        assert!(matches!(
            guess_key_type_from_name("rsa_backup"),
            KeyType::Rsa { .. }
        ));
    }

    #[test]
    fn guess_key_type_from_name_no_match() {
        assert!(matches!(
            guess_key_type_from_name("my_ssh_key"),
            KeyType::Ed25519
        ));
    }

    #[test]
    fn guess_key_type_from_name_sk_before_base() {
        assert!(matches!(
            guess_key_type_from_name("id_ed25519_sk"),
            KeyType::SkEd25519
        ));
        assert!(matches!(
            guess_key_type_from_name("id_ecdsa_sk"),
            KeyType::SkEcdsaP256
        ));
    }

    #[test]
    fn is_likely_encrypted_lowercase_not_matched() {
        let data = "-----BEGIN OPENSSH PRIVATE KEY-----\nencrypted\n";
        assert!(!is_likely_encrypted(data));
    }

    #[test]
    fn is_likely_encrypted_beyond_first_5_lines() {
        let data = "line1\nline2\nline3\nline4\nline5\nENCRYPTED\n";
        assert!(!is_likely_encrypted(data));
    }

    #[test]
    fn is_likely_encrypted_pem_proc_type() {
        let data = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n";
        assert!(is_likely_encrypted(data));
    }

    #[tokio::test]
    async fn scan_keys_discovers_identity_file_from_config() {
        let dir = tempfile::tempdir().unwrap();
        let ssh_dir = dir.path();

        let key_path = ssh_dir.join("id_config_key");
        let output = std::process::Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-f",
                key_path.to_str().unwrap(),
                "-N",
                "",
                "-C",
                "config-test",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "ssh-keygen failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let config_content = format!("Host myhost\n    IdentityFile {}\n", key_path.display());
        std::fs::write(ssh_dir.join("config"), &config_content).unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(ssh_dir);
        let keys = scan_keys(&paths, None).await.unwrap();

        assert!(
            keys.iter().any(|k| k.path == key_path),
            "scan_keys should discover key file referenced in config: found {:?}",
            keys.iter().map(|k| &k.path).collect::<Vec<_>>()
        );
        let found = keys.iter().find(|k| k.path == key_path).unwrap();
        assert!(matches!(found.key_type, KeyType::Ed25519));
        assert!(!found.encrypted);
        assert!(found.fingerprint.is_some());
    }

    #[tokio::test]
    async fn scan_keys_discovers_multiple_config_keys() {
        let dir = tempfile::tempdir().unwrap();
        let ssh_dir = dir.path();

        for name in &["id_work", "id_personal"] {
            let key_path = ssh_dir.join(name);
            let output = std::process::Command::new("ssh-keygen")
                .args([
                    "-t",
                    "ed25519",
                    "-f",
                    key_path.to_str().unwrap(),
                    "-N",
                    "",
                    "-C",
                    name,
                ])
                .output()
                .unwrap();
            assert!(output.status.success());
        }

        let config = "\
Host work
    IdentityFile ~/.ssh/id_work

Host personal
    IdentityFile ~/.ssh/id_personal
";
        std::fs::write(ssh_dir.join("config"), config).unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(ssh_dir);
        let keys = scan_keys(&paths, None).await.unwrap();

        assert!(keys.iter().any(|k| k.path == ssh_dir.join("id_work")));
        assert!(keys.iter().any(|k| k.path == ssh_dir.join("id_personal")));
    }

    #[tokio::test]
    async fn scan_keys_encrypted_key_discoverable() {
        let dir = tempfile::tempdir().unwrap();
        let ssh_dir = dir.path();

        let key_path = ssh_dir.join("id_encrypted");
        let output = std::process::Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-f",
                key_path.to_str().unwrap(),
                "-N",
                "testpass",
                "-C",
                "encrypted-test",
            ])
            .output()
            .unwrap();
        assert!(output.status.success());

        let paths = toride_ssh_core::SshPaths::with_dir(ssh_dir);
        let keys = scan_keys(&paths, None).await.unwrap();

        let found = keys.iter().find(|k| k.path == key_path);
        assert!(found.is_some(), "encrypted key should still be discovered");
        let key = found.unwrap();
        assert!(key.encrypted, "encrypted key should be marked as encrypted");
        assert!(
            key.fingerprint.is_some(),
            "encrypted key should have a fingerprint"
        );
    }

    #[test]
    fn inspect_private_key_encrypted_key_returns_encrypted_true() {
        let dir = tempfile::tempdir().unwrap();

        let key_path = dir.path().join("id_ed25519");
        let output = std::process::Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-f",
                key_path.to_str().unwrap(),
                "-N",
                "secretpass",
                "-C",
                "encrypted-inspect-test",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "ssh-keygen failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let key = inspect_private_key(&key_path).unwrap();

        assert!(
            key.encrypted,
            "inspect_private_key should detect encrypted key (got encrypted=false)"
        );
        assert!(
            key.fingerprint.is_some(),
            "encrypted key should still produce a fingerprint when ssh_key parses it"
        );
        assert!(matches!(key.key_type, KeyType::Ed25519));
    }

    #[tokio::test]
    async fn scan_keys_empty_ssh_dir() {
        let dir = tempfile::tempdir().unwrap();
        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let keys = scan_keys(&paths, None).await.unwrap();
        assert!(keys.is_empty());
    }

    #[tokio::test]
    async fn scan_keys_nonexistent_ssh_dir() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nonexistent");
        let paths = toride_ssh_core::SshPaths::with_dir(&missing);
        let keys = scan_keys(&paths, None).await.unwrap();
        assert!(keys.is_empty());
    }

    #[tokio::test]
    async fn scan_keys_discovers_standalone_pub_file() {
        let dir = tempfile::tempdir().unwrap();
        let ssh_dir = dir.path();

        let key_pair_path = ssh_dir.join("id_standalone");
        let output = std::process::Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-f",
                key_pair_path.to_str().unwrap(),
                "-N",
                "",
                "-C",
                "standalone-test",
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        std::fs::remove_file(&key_pair_path).unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(ssh_dir);
        let keys = scan_keys(&paths, None).await.unwrap();

        let pub_path = ssh_dir.join("id_standalone.pub");
        let found = keys.iter().find(|k| k.path == pub_path);
        assert!(
            found.is_some(),
            "standalone .pub file should be discovered: found {:?}",
            keys.iter().map(|k| &k.path).collect::<Vec<_>>()
        );
        let key = found.unwrap();
        assert!(key.has_public_pair);
        assert!(!key.encrypted);
        assert!(key.fingerprint.is_some());
        assert!(matches!(found.unwrap().source, KeySource::Filesystem));
    }

    #[tokio::test]
    async fn scan_keys_skips_cert_pub_in_standalone_scan() {
        let dir = tempfile::tempdir().unwrap();
        let ssh_dir = dir.path();

        std::fs::write(
            ssh_dir.join("id_test-cert.pub"),
            "ssh-ed25519 AAAA... cert\n",
        )
        .unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(ssh_dir);
        let keys = scan_keys(&paths, None).await.unwrap();

        assert!(
            keys.iter()
                .all(|k| !k.path.to_string_lossy().contains("cert.pub")),
            "certificate files should not appear as standalone .pub entries",
        );
    }

    #[tokio::test]
    async fn scan_keys_handles_ssh_v1_keys_without_panic() {
        let dir = tempfile::tempdir().unwrap();
        let ssh_dir = dir.path();

        std::fs::write(ssh_dir.join("identity"), "fake-ssh1-private-key").unwrap();
        std::fs::write(ssh_dir.join("identity.pub"), "fake-ssh1-public-key").unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(ssh_dir);
        let _keys = scan_keys(&paths, None).await.unwrap();
    }

    #[tokio::test]
    async fn scan_keys_ssh_v1_identity_pub_excluded_from_standalone() {
        let dir = tempfile::tempdir().unwrap();
        let ssh_dir = dir.path();

        std::fs::write(ssh_dir.join("identity.pub"), "ssh-rsa AAAA... identity\n").unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(ssh_dir);
        let keys = scan_keys(&paths, None).await.unwrap();

        assert!(
            keys.iter()
                .all(|k| k.path.file_name().is_none_or(|n| n != "identity.pub")),
            "identity.pub should be excluded from standalone scan (handled by SSH v1 warning)",
        );
    }

    #[tokio::test]
    async fn scan_keys_detects_pkcs11_provider() {
        let dir = tempfile::tempdir().unwrap();
        let ssh_dir = dir.path();

        let config_content = "\
Host hsm
    PKCS11Provider /usr/lib/libpkcs11.so
";
        std::fs::write(ssh_dir.join("config"), config_content).unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(ssh_dir);
        let keys = scan_keys(&paths, None).await.unwrap();

        let pkcs11: Vec<_> = keys
            .iter()
            .filter(|k| k.source == KeySource::Pkcs11)
            .collect();
        assert_eq!(pkcs11.len(), 1, "exactly one PKCS#11 entry expected");
        let key = pkcs11[0];
        assert!(key.path.to_string_lossy().contains("pkcs11:"));
        assert!(key.comment.as_ref().unwrap().contains("PKCS#11"));
        assert!(key.path.to_string_lossy().contains("/usr/lib/libpkcs11.so"));
    }

    #[tokio::test]
    async fn scan_keys_pkcs11_dedup_across_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let ssh_dir = dir.path();

        let config_content = "\
Host hsm1
    PKCS11Provider /usr/lib/libpkcs11.so

Host hsm2
    PKCS11Provider /usr/lib/libpkcs11.so
";
        std::fs::write(ssh_dir.join("config"), config_content).unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(ssh_dir);
        let keys = scan_keys(&paths, None).await.unwrap();

        let pkcs11: Vec<_> = keys
            .iter()
            .filter(|k| k.source == KeySource::Pkcs11)
            .collect();
        assert_eq!(
            pkcs11.len(),
            1,
            "duplicate PKCS#11 providers should be deduplicated"
        );
    }

    #[tokio::test]
    async fn scan_keys_discovers_config_identity_outside_ssh_dir() {
        let dir = tempfile::tempdir().unwrap();
        let ssh_dir = dir.path();

        let external_dir = tempfile::tempdir().unwrap();
        let key_path = external_dir.path().join("id_external");
        let output = std::process::Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-f",
                key_path.to_str().unwrap(),
                "-N",
                "",
                "-C",
                "external-test",
            ])
            .output()
            .unwrap();
        assert!(output.status.success());

        let config_content = format!("Host external\n    IdentityFile {}\n", key_path.display());
        std::fs::write(ssh_dir.join("config"), &config_content).unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(ssh_dir);
        let keys = scan_keys(&paths, None).await.unwrap();

        assert!(
            keys.iter().any(|k| k.path == key_path),
            "config-referenced key outside ssh_dir should be discovered: found {:?}",
            keys.iter().map(|k| &k.path).collect::<Vec<_>>()
        );
        let found = keys.iter().find(|k| k.path == key_path).unwrap();
        assert!(matches!(found.key_type, KeyType::Ed25519));
        assert!(found.fingerprint.is_some());
    }

    fn gen_ed25519(dir: &Path, name: &str, comment: &str) -> PathBuf {
        let key_path = dir.join(name);
        let output = std::process::Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-f",
                key_path.to_str().unwrap(),
                "-N",
                "",
                "-C",
                comment,
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "ssh-keygen failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        key_path
    }

    fn rewrite_with_new_stamp(path: &Path, previous: std::time::SystemTime, content: &str) {
        loop {
            std::fs::write(path, content).expect("rewrite key fixture");
            let now = std::fs::metadata(path)
                .expect("stat key fixture")
                .modified()
                .expect("mtime");
            if now != previous {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }

    fn mtime_of(path: &Path) -> std::time::SystemTime {
        std::fs::metadata(path)
            .expect("stat key fixture")
            .modified()
            .expect("mtime")
    }

    #[test]
    fn cached_inspect_matches_fresh_parse() {
        clear_key_cache_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let key_path = gen_ed25519(dir.path(), "id_cache_parity", "parity-test");

        let fresh = inspect_private_key(&key_path).expect("fresh parse");
        let cached = crate::inspect_key_cached(&key_path).expect("cached parse");
        assert_eq!(cached.path, fresh.path);
        assert_eq!(cached.key_type, fresh.key_type);
        assert_eq!(cached.encrypted, fresh.encrypted);
        assert_eq!(cached.comment, fresh.comment);
        assert_eq!(
            cached.fingerprint.as_ref().map(|f| f.hash.as_str()),
            fresh.fingerprint.as_ref().map(|f| f.hash.as_str())
        );
    }

    #[test]
    fn cache_hit_returns_identical_fingerprint_without_reparse() {
        clear_key_cache_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let key_path = gen_ed25519(dir.path(), "id_cache_hit", "hit-test");

        let first = crate::inspect_key_cached(&key_path).expect("first parse");
        let second = crate::inspect_key_cached(&key_path).expect("second (cached) parse");
        assert_eq!(
            first.fingerprint.expect("fingerprint").hash,
            second.fingerprint.expect("fingerprint").hash
        );
    }

    #[test]
    fn rewritten_key_reparses() {
        clear_key_cache_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let key_path = gen_ed25519(dir.path(), "id_cache_inval", "before-rotation");
        let before = crate::inspect_key_cached(&key_path).expect("parse before");
        assert_eq!(before.comment.as_deref(), Some("before-rotation"));

        let rotated = gen_ed25519(dir.path(), "id_cache_rotated", "after-rotation");
        let content = std::fs::read_to_string(&rotated).unwrap();
        rewrite_with_new_stamp(&key_path, mtime_of(&key_path), &content);

        let after = crate::inspect_key_cached(&key_path).expect("parse after");
        assert_eq!(
            after.comment.as_deref(),
            Some("after-rotation"),
            "a rewritten key must be re-parsed, never served stale"
        );
        assert_ne!(
            before.fingerprint.expect("fp").hash,
            after.fingerprint.expect("fp").hash
        );
    }

    #[tokio::test]
    async fn scan_keys_order_is_deterministic_for_cache_stability() {
        clear_key_cache_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let ssh_dir = dir.path();
        let a = gen_ed25519(ssh_dir, "id_alpha", "a");
        let b = gen_ed25519(ssh_dir, "id_beta", "b");
        let c = gen_ed25519(ssh_dir, "id_gamma", "c");

        let paths = toride_ssh_core::SshPaths::with_dir(ssh_dir);
        let first = scan_keys(&paths, None).await.unwrap();
        let private_paths: Vec<_> = first
            .iter()
            .map(|k| k.path.clone())
            .filter(|p| p.extension().is_none())
            .collect();
        let mut sorted = private_paths.clone();
        sorted.sort();
        assert_eq!(private_paths, sorted);
        assert!(private_paths.contains(&a));
        assert!(private_paths.contains(&b));
        assert!(private_paths.contains(&c));

        let second = scan_keys(&paths, None).await.unwrap();
        assert_eq!(
            first.iter().map(|k| k.path.clone()).collect::<Vec<_>>(),
            second.iter().map(|k| k.path.clone()).collect::<Vec<_>>(),
            "cache hits must be order-stable"
        );
    }

    #[cfg(feature = "agent-integration")]
    fn make_key(hash: &str, source: KeySource) -> SshKey {
        SshKey {
            path: PathBuf::from(format!("/{hash}")),
            key_type: KeyType::Ed25519,
            fingerprint: Some(Fingerprint {
                hash: hash.to_owned(),
                key_type: KeyType::Ed25519,
            }),
            comment: None,
            encrypted: false,
            source,
            permissions: None,
            has_public_pair: false,
            has_certificate: false,
            last_modified: None,
            used_by_hosts: Vec::new(),
            key_format: None,
        }
    }

    #[cfg(feature = "agent-integration")]
    fn make_key_no_fp(source: KeySource) -> SshKey {
        SshKey {
            path: PathBuf::from("/no-fp"),
            key_type: KeyType::Ed25519,
            fingerprint: None,
            comment: None,
            encrypted: false,
            source,
            permissions: None,
            has_public_pair: false,
            has_certificate: false,
            last_modified: None,
            used_by_hosts: Vec::new(),
            key_format: None,
        }
    }

    #[cfg(feature = "agent-integration")]
    #[test]
    fn filter_agent_keys_matching_fingerprint_is_filtered_out() {
        let existing = vec![make_key("AAAA", KeySource::Filesystem)];
        let agent = vec![make_key("AAAA", KeySource::Agent)];

        let result = filter_new_agent_keys(&existing, agent);
        assert!(
            result.is_empty(),
            "agent key with matching fingerprint should be filtered out"
        );
    }

    #[cfg(feature = "agent-integration")]
    #[test]
    fn filter_agent_keys_no_match_is_kept() {
        let existing = vec![make_key("AAAA", KeySource::Filesystem)];
        let agent = vec![make_key("BBBB", KeySource::Agent)];

        let result = filter_new_agent_keys(&existing, agent);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].fingerprint.as_ref().unwrap().hash, "BBBB");
    }

    #[cfg(feature = "agent-integration")]
    #[test]
    fn filter_agent_keys_partial_match() {
        let existing = vec![make_key("AAAA", KeySource::Filesystem)];
        let agent = vec![
            make_key("AAAA", KeySource::Agent),
            make_key("BBBB", KeySource::Agent),
            make_key("CCCC", KeySource::Agent),
        ];

        let result = filter_new_agent_keys(&existing, agent);
        assert_eq!(
            result.len(),
            2,
            "only non-matching agent keys should be kept"
        );
        let hashes: Vec<_> = result
            .iter()
            .map(|k| k.fingerprint.as_ref().unwrap().hash.as_str())
            .collect();
        assert!(hashes.contains(&"BBBB"));
        assert!(hashes.contains(&"CCCC"));
    }

    #[cfg(feature = "agent-integration")]
    #[test]
    fn filter_agent_keys_empty_agent_list() {
        let existing = vec![make_key("AAAA", KeySource::Filesystem)];
        let agent = vec![];

        let result = filter_new_agent_keys(&existing, agent);
        assert!(
            result.is_empty(),
            "empty agent list should produce empty result"
        );
    }

    #[cfg(feature = "agent-integration")]
    #[test]
    fn filter_agent_keys_empty_existing_list() {
        let existing: Vec<SshKey> = vec![];
        let agent = vec![
            make_key("AAAA", KeySource::Agent),
            make_key("BBBB", KeySource::Agent),
        ];

        let result = filter_new_agent_keys(&existing, agent);
        assert_eq!(
            result.len(),
            2,
            "all agent keys should be kept when no existing keys"
        );
    }

    #[cfg(feature = "agent-integration")]
    #[test]
    fn filter_agent_keys_agent_key_without_fingerprint_is_kept() {
        let existing = vec![make_key("AAAA", KeySource::Filesystem)];
        let agent = vec![make_key_no_fp(KeySource::Agent)];

        let result = filter_new_agent_keys(&existing, agent);
        assert_eq!(
            result.len(),
            1,
            "agent key without fingerprint cannot match and should be kept"
        );
    }

    #[cfg(feature = "agent-integration")]
    #[test]
    fn filter_agent_keys_existing_key_without_fingerprint_does_not_match() {
        let existing = vec![make_key_no_fp(KeySource::Filesystem)];
        let agent = vec![make_key("AAAA", KeySource::Agent)];

        let result = filter_new_agent_keys(&existing, agent);
        assert_eq!(
            result.len(),
            1,
            "existing key without fingerprint cannot match any agent key"
        );
    }
}
