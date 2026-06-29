//! Key generation with `zeroize` hygiene.
//!
//! Provides utilities for generating WireGuard key pairs. Private keys are
//! wrapped in types that implement `Zeroize` so sensitive material is cleared
//! from memory when dropped.
//!
//! ## Backing implementation
//!
//! Key generation and public-key derivation are performed via the real
//! `wg genkey` and `wg pubkey` commands, executed through
//! [`toride_runner::Runner`]. Because the private key is a secret, every
//! command that carries it is built with [`CommandSpec::redact`](toride_runner::CommandSpec::redact)
//! set to `true`, so the key material is scrubbed from error messages and
//! logs. Tests use [`FakeRunner`](toride_runner::FakeRunner) with canned
//! `wg` output -- no real `wg` binary, credentials, or root are needed.

use std::time::Duration;

use toride_runner::{CommandSpec, Runner};
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// Timeout for `wg genkey` / `wg pubkey` (they are fast, but bound it).
const WG_KEYGEN_TIMEOUT_SECS: u64 = 5;

// ---------------------------------------------------------------------------
// PrivateKey
// ---------------------------------------------------------------------------

/// A WireGuard private key with automatic zeroization on drop.
///
/// The key is stored as a Base64-encoded string (44 bytes including padding).
/// When this value is dropped, the inner bytes are overwritten with zeroes.
#[derive(Clone)]
pub struct PrivateKey {
    inner: String,
}

impl PrivateKey {
    /// Create a `PrivateKey` from a Base64-encoded string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyGeneration`] if the string is not a valid
    /// Base64-encoded 32-byte key.
    pub fn from_base64(key: &str) -> Result<Self> {
        let bytes = base64_decode(key)?;
        if bytes.len() != 32 {
            return Err(Error::KeyGeneration(format!(
                "private key must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        Ok(Self {
            inner: key.to_owned(),
        })
    }

    /// Returns the Base64-encoded private key.
    pub fn as_base64(&self) -> &str {
        &self.inner
    }

    /// Derive the corresponding public key from this private key.
    ///
    /// Runs `wg pubkey` with the private key piped via stdin (the standard
    /// derivation path used by WireGuard). The command is marked `redact(true)`
    /// so the secret key is never surfaced in error messages or logs.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyGeneration`] if derivation fails (e.g. `wg` is not
    /// on `$PATH` or the key is malformed).
    pub fn public_key(&self) -> Result<PublicKey> {
        derive_public_key_with(&default_runner(), &self.inner)
    }

    /// Derive the public key using an explicit runner (for testing).
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyGeneration`] if the derivation command fails.
    pub fn public_key_with<R: Runner>(&self, runner: &R) -> Result<PublicKey> {
        derive_public_key_with(runner, &self.inner)
    }
}

impl Zeroize for PrivateKey {
    fn zeroize(&mut self) {
        // Overwrite the string's bytes safely. Replace every character with
        // '\0' (valid UTF-8) and then truncate, ensuring sensitive material
        // is cleared from the underlying buffer.
        let len = self.inner.len();
        self.inner.clear();
        for _ in 0..len {
            self.inner.push('\0');
        }
        self.inner.clear();
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivateKey(**REDACTED**)")
    }
}

impl std::fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("**REDACTED**")
    }
}

// ---------------------------------------------------------------------------
// PublicKey
// ---------------------------------------------------------------------------

/// A WireGuard public key.
///
/// Public keys are safe to display and log.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PublicKey {
    inner: String,
}

impl PublicKey {
    /// Create a `PublicKey` from a Base64-encoded string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyGeneration`] if the string is not a valid
    /// Base64-encoded 32-byte key.
    pub fn from_base64(key: &str) -> Result<Self> {
        let bytes = base64_decode(key)?;
        if bytes.len() != 32 {
            return Err(Error::KeyGeneration(format!(
                "public key must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        Ok(Self {
            inner: key.to_owned(),
        })
    }

    /// Returns the Base64-encoded public key.
    pub fn as_base64(&self) -> &str {
        &self.inner
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.inner)
    }
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Generate a new WireGuard key pair.
///
/// Runs `wg genkey` to produce a private key, then pipes it to `wg pubkey` to
/// derive the matching public key. The private key is wrapped in
/// [`PrivateKey`] for automatic zeroization. Both commands carry secret
/// material, so they are built with `redact(true)`.
///
/// # Errors
///
/// Returns [`Error::KeyGeneration`] if either `wg` command fails, or
/// [`Error::BinaryNotFound`] if `wg` is not on `$PATH`.
pub fn generate_keypair() -> Result<(PrivateKey, PublicKey)> {
    let runner = default_runner();
    generate_keypair_with(&runner)
}

/// Generate a new WireGuard key pair using an explicit runner (for testing).
///
/// # Errors
///
/// Returns [`Error::KeyGeneration`] if either command fails.
pub fn generate_keypair_with<R: Runner>(runner: &R) -> Result<(PrivateKey, PublicKey)> {
    tracing::info!("generating new WireGuard key pair");
    let private = generate_private_key_with(runner)?;
    let public = derive_public_key_with(runner, private.as_base64())?;
    Ok((private, public))
}

/// Generate only a private key.
///
/// # Errors
///
/// Returns [`Error::KeyGeneration`] if `wg genkey` fails, or
/// [`Error::BinaryNotFound`] if `wg` is not on `$PATH`.
pub fn generate_private_key() -> Result<PrivateKey> {
    let runner = default_runner();
    generate_private_key_with(&runner)
}

/// Generate only a private key using an explicit runner (for testing).
///
/// # Errors
///
/// Returns [`Error::KeyGeneration`] if the command fails.
pub fn generate_private_key_with<R: Runner>(runner: &R) -> Result<PrivateKey> {
    tracing::info!("generating new WireGuard private key");
    // `wg genkey` writes the private key to stdout. Redact so any captured
    // output that leaks into error messages is scrubbed.
    let spec = CommandSpec::new("wg")
        .arg("genkey")
        .redact(true)
        .timeout(Duration::from_secs(WG_KEYGEN_TIMEOUT_SECS));
    let output = runner.run_checked(&spec).map_err(|e| keygen_error(&e))?;
    let private_b64 = output.stdout_trimmed().to_owned();
    PrivateKey::from_base64(&private_b64)
}

/// Derive a public key from a private key using `wg pubkey`.
///
/// The private key (Base64) is piped to `wg pubkey` via stdin. The command is
/// marked `redact(true)` because the stdin carries a secret.
///
/// # Errors
///
/// Returns [`Error::KeyGeneration`] if derivation fails.
pub fn derive_public_key(private_key: &PrivateKey) -> Result<PublicKey> {
    let runner = default_runner();
    derive_public_key_with(&runner, private_key.as_base64())
}

/// Derive a public key from a Base64 private key using an explicit runner.
///
/// # Errors
///
/// Returns [`Error::KeyGeneration`] if the command fails.
fn derive_public_key_with<R: Runner>(runner: &R, private_b64: &str) -> Result<PublicKey> {
    tracing::debug!("deriving public key from private key via `wg pubkey`");
    let spec = CommandSpec::new("wg")
        .arg("pubkey")
        .stdin(private_b64)
        .redact(true)
        .timeout(Duration::from_secs(WG_KEYGEN_TIMEOUT_SECS));
    let output = runner.run_checked(&spec).map_err(|e| keygen_error(&e))?;
    let public_b64 = output.stdout_trimmed().to_owned();
    PublicKey::from_base64(&public_b64)
}

/// Build a default production runner (`DuctRunner`).
fn default_runner() -> toride_runner::DuctRunner {
    toride_runner::DuctRunner
}

/// Translate a runner error into [`Error::KeyGeneration`] (or
/// [`Error::BinaryNotFound`] when the `wg` binary is absent).
fn keygen_error(err: &toride_runner::Error) -> Error {
    // A missing `wg` binary surfaces as a spawn/NotFound error from the runner.
    let msg = err.to_string();
    if msg.contains("not found") || msg.contains("No such file") || msg.contains("ENOENT") {
        Error::BinaryNotFound("wg".to_owned())
    } else {
        Error::KeyGeneration(format!("`wg` key operation failed: {msg}"))
    }
}

// ---------------------------------------------------------------------------
// Base64 helper
// ---------------------------------------------------------------------------

/// Decode a Base64 string into raw bytes.
fn base64_decode(input: &str) -> Result<Vec<u8>> {
    let decoder = base64::engine::general_purpose::STANDARD;
    base64::Engine::decode(&decoder, input)
        .map_err(|e| Error::KeyGeneration(format!("base64 decode failed: {e}")))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::*;

    /// Canned private/public keypair produced by a real `wg genkey | wg pubkey`.
    /// These are test-only values; they are not used anywhere secure.
    const TEST_PRIVATE: &str = "yAnz5TF+lXXJte14tji3zsMNmPaKj7jMEumQzxRjZn4=";
    const TEST_PUBLIC: &str = "GtL7fZc/bLnqZldpVofMCD6hDjrK28SsdLxevJ+qtKU=";

    /// Exact command shape that `generate_private_key` must build.
    #[test]
    fn generate_private_key_builds_wg_genkey_redacted() {
        let runner = toride_runner::fake::FakeRunner::new()
            .push_response(toride_runner::CommandOutput::from_stdout(TEST_PRIVATE));
        let key = generate_private_key_with(&runner).unwrap();
        assert_eq!(key.as_base64(), TEST_PRIVATE);

        runner.assert_called_with(&CommandSpec::new("wg").arg("genkey").redact(true));
    }

    /// `generate_keypair` chains `wg genkey` -> `wg pubkey` and redacts both.
    #[test]
    fn generate_keypair_chains_genkey_and_pubkey() {
        let runner = toride_runner::fake::FakeRunner::new()
            // First call: `wg genkey` -> private key.
            .push_response(toride_runner::CommandOutput::from_stdout(TEST_PRIVATE))
            // Second call: `wg pubkey` (stdin = private) -> public key.
            .push_response(toride_runner::CommandOutput::from_stdout(TEST_PUBLIC));

        let (priv_key, pub_key) = generate_keypair_with(&runner).unwrap();
        assert_eq!(priv_key.as_base64(), TEST_PRIVATE);
        assert_eq!(pub_key.as_base64(), TEST_PUBLIC);

        let calls = runner.calls();
        // Both calls must target `wg` and be redacted.
        assert!(
            calls.iter().all(|c| c.program == "wg" && c.redact),
            "all keygen commands must be redacted: {calls:?}"
        );
        // The pubkey call must carry the private key on stdin.
        let pubkey_call = calls
            .iter()
            .find(|c| c.args.first().is_some_and(|a| a == "pubkey"))
            .expect("`wg pubkey` was called");
        assert_eq!(pubkey_call.stdin.as_deref(), Some(TEST_PRIVATE));
    }

    /// `PrivateKey::public_key_with` derives via `wg pubkey` with the key on stdin.
    #[test]
    fn public_key_derives_via_wg_pubkey_stdin() {
        let runner = toride_runner::fake::FakeRunner::new()
            .push_response(toride_runner::CommandOutput::from_stdout(TEST_PUBLIC));
        let priv_key = PrivateKey::from_base64(TEST_PRIVATE).unwrap();
        let pub_key = priv_key.public_key_with(&runner).unwrap();
        assert_eq!(pub_key.as_base64(), TEST_PUBLIC);

        runner.assert_called_with(
            &CommandSpec::new("wg")
                .arg("pubkey")
                .stdin(TEST_PRIVATE)
                .redact(true),
        );
    }

    /// Free function `derive_public_key` mirrors the method.
    #[test]
    fn derive_public_key_free_function_matches_method() {
        let runner = toride_runner::fake::FakeRunner::new()
            .push_response(toride_runner::CommandOutput::from_stdout(TEST_PUBLIC));
        let priv_key = PrivateKey::from_base64(TEST_PRIVATE).unwrap();
        let via_fn = derive_public_key_with(&runner, priv_key.as_base64()).unwrap();
        assert_eq!(via_fn.as_base64(), TEST_PUBLIC);
    }

    /// A malformed private key (rejected by `wg pubkey`) surfaces as an error.
    #[test]
    fn public_key_propagates_wg_failure() {
        let runner = toride_runner::fake::FakeRunner::new()
            .push_response(toride_runner::CommandOutput::from_stderr("invalid key", 1));
        let priv_key = PrivateKey::from_base64(TEST_PRIVATE).unwrap();
        let err = priv_key.public_key_with(&runner).unwrap_err();
        assert!(
            matches!(err, Error::KeyGeneration(_) | Error::Runner(_)),
            "got {err:?}"
        );
    }

    /// `wg pubkey` output is trimmed before validation (trailing newline).
    #[test]
    fn public_key_output_is_trimmed() {
        let runner = toride_runner::fake::FakeRunner::new().push_response(
            toride_runner::CommandOutput::from_stdout(format!("{TEST_PUBLIC}\n")),
        );
        let priv_key = PrivateKey::from_base64(TEST_PRIVATE).unwrap();
        let pub_key = priv_key.public_key_with(&runner).unwrap();
        assert_eq!(pub_key.as_base64(), TEST_PUBLIC);
    }

    /// Non-vacuity guard: confirm the genkey command is recorded with
    /// `redact == true`. `toride_runner::FakeRunner::specs_match` now compares
    /// the `redact` field, so the `assert_called_with(...).redact(true)` checks
    /// above are genuine (they would fail if a spec dropped `.redact(true)`).
    /// This test pins that property directly on the recorded call so a future
    /// regression to the spec builder is caught independent of `specs_match`.
    #[test]
    fn genkey_recorded_spec_carries_redact_true() {
        let runner = toride_runner::fake::FakeRunner::new()
            .push_response(toride_runner::CommandOutput::from_stdout(TEST_PRIVATE));
        let _ = generate_private_key_with(&runner).unwrap();
        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        assert!(
            calls[0].redact,
            "`wg genkey` carries a secret on stdout and MUST be built redact(true); got {:?}",
            calls[0]
        );
    }

    #[test]
    fn private_key_redacted_debug() {
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let pk = PrivateKey::from_base64(key).unwrap();
        let debug = format!("{pk:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains(key));
    }

    #[test]
    fn private_key_redacted_display() {
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let pk = PrivateKey::from_base64(key).unwrap();
        let display = format!("{pk}");
        assert!(display.contains("REDACTED"));
        assert!(!display.contains(key));
    }

    #[test]
    fn public_key_display_shows_value() {
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let pk = PublicKey::from_base64(key).unwrap();
        let display = format!("{pk}");
        assert_eq!(display, key);
    }

    #[test]
    fn invalid_key_length() {
        let short = base64::engine::general_purpose::STANDARD.encode(b"tooshort");
        assert!(PrivateKey::from_base64(&short).is_err());
        assert!(PublicKey::from_base64(&short).is_err());
    }

    #[test]
    fn invalid_base64() {
        assert!(PrivateKey::from_base64("not-base64!!!").is_err());
    }
}
