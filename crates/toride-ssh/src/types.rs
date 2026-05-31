//! Core SSH types shared across all service modules.
//!
//! Defines enums and structs for key algorithms ([`KeyType`]), key formats,
//! diagnostic severities, file permissions, and parameter types for key
//! creation/deletion. These types form the vocabulary used by every other
//! module in this crate.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// SSH key algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyType {
    /// Ed25519 — modern default.
    Ed25519,
    /// RSA with specified bit size (2048, 3072, 4096).
    Rsa {
        /// Key size in bits.
        bits: u32,
    },
    /// ECDSA P-256.
    EcdsaP256,
    /// ECDSA P-384.
    EcdsaP384,
    /// ECDSA P-521.
    EcdsaP521,
    /// DSA (legacy).
    Dsa,
    /// FIDO2 security key Ed25519.
    SkEd25519,
    /// FIDO2 security key ECDSA P-256.
    SkEcdsaP256,
}

/// Target format for key conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyFormat {
    /// PEM (RFC 7468 / legacy OpenSSL PEM).
    Pem,
    /// OpenSSH format (the default since OpenSSH 6.5).
    OpenSSH,
}

/// SHA-256 fingerprint of an SSH key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Fingerprint {
    /// Base64-encoded SHA-256 hash (without the `SHA256:` prefix).
    pub hash: String,
    /// Algorithm of the key this fingerprint belongs to.
    pub key_type: KeyType,
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SHA256:{}", self.hash)
    }
}

/// Where a key was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeySource {
    /// Key file on disk under `~/.ssh`.
    Filesystem,
    /// Key loaded in the SSH agent (may not have a file).
    Agent,
    /// Key from a PKCS#11 hardware token.
    Pkcs11,
}

/// Unix file permission mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permissions {
    /// Octal permission bits (e.g. `0o600`).
    pub mode: u32,
}

/// A discovered SSH key with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKey {
    /// Path to the private key file.
    pub path: PathBuf,
    /// Detected key algorithm.
    pub key_type: KeyType,
    /// SHA-256 fingerprint, if computable.
    pub fingerprint: Option<Fingerprint>,
    /// Key comment.
    pub comment: Option<String>,
    /// Whether the private key is passphrase-protected.
    pub encrypted: bool,
    /// Where the key was found.
    pub source: KeySource,
    /// File permissions, if readable.
    pub permissions: Option<Permissions>,
    /// Whether a matching `.pub` file exists.
    pub has_public_pair: bool,
    /// Whether a matching `-cert.pub` file exists.
    pub has_certificate: bool,
    /// File modification time (seconds since Unix epoch), if available.
    pub last_modified: Option<u64>,
    /// Host aliases in `~/.ssh/config` that reference this key via `IdentityFile`.
    pub used_by_hosts: Vec<String>,
    /// Detected key format (PEM vs OpenSSH), if known.
    pub key_format: Option<KeyFormat>,
}

/// Diagnostic severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Severity {
    /// Check passed.
    Ok,
    /// Informational note.
    Info,
    /// Non-critical issue.
    Warning,
    /// Critical issue that will break things.
    Error,
}

/// A single diagnostic finding from the SSH doctor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Machine-readable check identifier.
    pub id: &'static str,
    /// How severe this finding is.
    pub severity: Severity,
    /// Human-readable description.
    pub message: String,
    /// Suggested fix.
    pub hint: Option<String>,
    /// Module that produced this finding.
    pub module: &'static str,
}

/// Parameters for creating a new SSH key.
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyCreateParams {
    /// Algorithm to use.
    pub key_type: KeyType,
    /// File name (without path or extension).
    pub name: String,
    /// Optional comment for the public key.
    pub comment: Option<String>,
    /// Passphrase to encrypt the private key.
    pub passphrase: Option<String>,
    /// bcrypt KDF rounds (higher = slower but more resistant to brute-force).
    pub kdf_rounds: Option<u32>,
    /// Whether to add the key to the SSH agent after creation.
    pub add_to_agent: bool,
    /// Whether to add a `Host` block to `~/.ssh/config`.
    pub add_to_config: bool,
    /// Host alias to use in config when `add_to_config` is true.
    pub config_host: Option<String>,
    /// Require physical touch on FIDO/security key before signing.
    pub touch_required: bool,
    /// Require user verification (biometric/PIN) on FIDO/security key.
    pub verify_required: bool,
}

impl KeyCreateParams {
    /// Create parameters for an Ed25519 key with sensible defaults.
    pub fn ed25519(name: String) -> Self {
        Self {
            key_type: KeyType::Ed25519,
            name,
            comment: None,
            passphrase: None,
            kdf_rounds: None,
            add_to_agent: false,
            add_to_config: false,
            config_host: None,
            touch_required: false,
            verify_required: false,
        }
    }

    /// Create parameters for an RSA 4096-bit key with sensible defaults.
    pub fn rsa_4096(name: String) -> Self {
        Self {
            key_type: KeyType::Rsa { bits: 4096 },
            name,
            comment: None,
            passphrase: None,
            kdf_rounds: None,
            add_to_agent: false,
            add_to_config: false,
            config_host: None,
            touch_required: false,
            verify_required: false,
        }
    }

    /// Create parameters for a FIDO2 Ed25519 security key with sensible defaults.
    pub fn ed25519_sk(name: String) -> Self {
        Self {
            key_type: KeyType::SkEd25519,
            name,
            comment: None,
            passphrase: None,
            kdf_rounds: None,
            add_to_agent: false,
            add_to_config: false,
            config_host: None,
            touch_required: true,
            verify_required: false,
        }
    }

    /// Create parameters for a FIDO2 ECDSA P-256 security key with sensible defaults.
    pub fn ecdsa_sk(name: String) -> Self {
        Self {
            key_type: KeyType::SkEcdsaP256,
            name,
            comment: None,
            passphrase: None,
            kdf_rounds: None,
            add_to_agent: false,
            add_to_config: false,
            config_host: None,
            touch_required: true,
            verify_required: false,
        }
    }
}

impl std::fmt::Debug for KeyCreateParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyCreateParams")
            .field("key_type", &self.key_type)
            .field("name", &self.name)
            .field("comment", &self.comment)
            .field("passphrase", &self.passphrase.as_ref().map(|_| "[REDACTED]"))
            .field("kdf_rounds", &self.kdf_rounds)
            .field("add_to_agent", &self.add_to_agent)
            .field("add_to_config", &self.add_to_config)
            .field("config_host", &self.config_host)
            .field("touch_required", &self.touch_required)
            .field("verify_required", &self.verify_required)
            .finish()
    }
}

/// Parameters for deleting an SSH key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDeleteParams {
    /// File name identifying the key.
    pub name: String,
    /// Remove the `.pub` companion file.
    pub remove_public: bool,
    /// Remove the `-cert.pub` certificate file.
    pub remove_certificate: bool,
    /// Remove the key from the SSH agent.
    pub remove_from_agent: bool,
    /// Remove `IdentityFile` references from `~/.ssh/config`.
    pub remove_from_config: bool,
    /// Create a backup before deletion.
    pub backup: bool,
}
