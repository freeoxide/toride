//! SSH certificate authority and key revocation list inspection.
//!
//! Parses CA certificate files and KRL (key revocation list) files produced
//! by `ssh-keygen`. Exposes [`CertificateInfo`], [`KrlInfo`], and
//! [`TrustedUserCAKeysStatus`] for diagnostics and inventory reporting.

mod ca;
mod krl;

/// Parsed details from an OpenSSH certificate file.
pub use ca::CertificateInfo;
/// Parsed details from an OpenSSH Key Revocation List (KRL) file.
pub use krl::KrlInfo;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Status of a local `TrustedUserCAKeys` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedUserCAKeysStatus {
    /// Path to the file.
    pub path: PathBuf,
    /// Whether the file exists.
    pub exists: bool,
    /// Whether the file is readable.
    pub readable: bool,
    /// Number of non-empty, non-comment lines (CA keys).
    pub key_count: usize,
}

use toride_ssh_core::Result;

/// Best-effort datetime string to Unix timestamp (seconds since epoch).
///
/// Handles the compact format emitted by `ssh-keygen` (`20240101T000000`)
/// as well as common ISO-ish formats. Returns `None` if no format matches.
pub(crate) fn parse_ssh_datetime(s: &str) -> Option<i64> {
    let formats = [
        "%Y%m%dT%H%M%S", // compact form used by ssh-keygen KRL output
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%:z",
        "%Y-%m-%dT%H:%M:%S%#z",
    ];

    for fmt in &formats {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, fmt) {
            return Some(dt.and_utc().timestamp());
        }
    }

    // Try date-only.
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return d.and_hms_opt(0, 0, 0).map(|dt| dt.and_utc().timestamp());
    }

    None
}

/// SSH certificate and CA operations.
#[derive(Default)]
pub struct CertificateService;

impl CertificateService {
    /// Create a new certificate service.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Inspect an OpenSSH certificate file and return structured details.
    ///
    /// # Errors
    ///
    /// Returns [`toride_ssh_core::Error::CommandFailed`] if the certificate path is not
    /// valid UTF-8, or if the `ssh-keygen -L` fallback command fails (e.g.
    /// `ssh-keygen` is not found in `PATH` or returns a non-zero exit code).
    ///
    /// Returns [`toride_ssh_core::Error::CertificateParseFailed`] if the certificate file
    /// cannot be parsed by either the native `ssh_key` crate parser or the
    /// `ssh-keygen -L` fallback (corrupt file, unsupported format, or
    /// `ssh-keygen` output that lacks a recognizable key type line).
    pub async fn inspect(&self, path: &Path) -> Result<CertificateInfo> {
        ca::inspect_certificate(path).await
    }

    /// Inspect a Key Revocation List (KRL) file.
    ///
    /// # Errors
    ///
    /// Returns an error if the KRL path is not valid UTF-8, `ssh-keygen` is
    /// not available or returns a non-zero exit code, or the file is not a
    /// valid KRL.
    pub async fn inspect_krl(&self, path: &Path) -> Result<KrlInfo> {
        krl::inspect_krl(path).await
    }

    /// Check whether a certificate is currently within its validity window.
    ///
    /// # Errors
    ///
    /// Returns [`toride_ssh_core::Error::CommandFailed`] if the certificate path is not
    /// valid UTF-8 or `ssh-keygen -L` fails. Returns
    /// [`toride_ssh_core::Error::CertificateParseFailed`] if the certificate file cannot
    /// be parsed.
    pub async fn is_valid(&self, path: &Path) -> Result<bool> {
        let info = self.inspect(path).await?;
        // Clamp to non-negative: timestamp() returns i64, valid_* fields are u64.
        let now = u64::try_from(chrono::Utc::now().timestamp().max(0)).unwrap_or(0);
        // OpenSSH validity check: valid_after <= now < valid_before
        Ok(info.valid_after <= now && now < info.valid_before)
    }

    /// Check whether a local `TrustedUserCAKeys` file exists and is readable.
    ///
    /// `TrustedUserCAKeys` is an `sshd_config` directive that lists the public
    /// keys of CAs trusted to sign user certificates. This method reads the
    /// file and returns whether it exists, is readable, and how many CA keys
    /// it contains.
    ///
    /// # Errors
    ///
    /// This method currently never returns an error. File-system failures
    /// (including a missing file) are captured in the returned status struct
    /// rather than propagated. The `Result` return type is reserved for future
    /// use if stricter validation is added.
    pub async fn check_trusted_user_ca_keys(&self, path: &Path) -> Result<TrustedUserCAKeysStatus> {
        match tokio::fs::read_to_string(path).await {
            Ok(content) => {
                let key_count = content
                    .lines()
                    .filter(|line| {
                        let trimmed = line.trim();
                        !trimmed.is_empty() && !trimmed.starts_with('#')
                    })
                    .count();

                Ok(TrustedUserCAKeysStatus {
                    path: path.to_path_buf(),
                    exists: true,
                    readable: true,
                    key_count,
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(TrustedUserCAKeysStatus {
                path: path.to_path_buf(),
                exists: false,
                readable: false,
                key_count: 0,
            }),
            Err(_) => Ok(TrustedUserCAKeysStatus {
                path: path.to_path_buf(),
                exists: true,
                readable: false,
                key_count: 0,
            }),
        }
    }

    /// Revoke a key by adding it to a KRL file.
    ///
    /// Creates the KRL file if it does not exist, or updates it if it does.
    /// The `key` parameter should be the path to the public key file to revoke.
    ///
    /// # Errors
    ///
    /// Returns an error if the KRL path is not valid UTF-8, or if
    /// `ssh-keygen -k` fails (e.g. `ssh-keygen` is not available, the key
    /// file does not exist, or the KRL file cannot be written).
    pub async fn revoke_key(&self, krl_path: &Path, key: &str) -> Result<()> {
        let krl_str = krl_path.to_str().ok_or_else(|| {
            toride_ssh_core::Error::CommandFailed(format!(
                "KRL path is not valid UTF-8: {}",
                krl_path.display()
            ))
        })?;

        // If the KRL already exists, use -u to update it in-place rather than
        // overwriting. Without -u, ssh-keygen -k replaces the entire KRL.
        let update = krl_path.exists();
        let mut args = Vec::with_capacity(5);
        args.push("-k");
        if update {
            args.push("-u");
        }
        args.push("-f");
        args.push(krl_str);
        args.push(key);

        toride_ssh_core::runner::ssh_keygen(&args).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ssh_datetime_compact() {
        // ssh-keygen KRL format: 20240101T000000
        let ts = parse_ssh_datetime("20240101T000000").unwrap();
        assert!(ts > 0);
        // Should be 2024-01-01 00:00:00 UTC
        assert_eq!(ts, 1_704_067_200);
    }

    #[test]
    fn parse_ssh_datetime_iso() {
        let ts = parse_ssh_datetime("2024-01-01T00:00:00").unwrap();
        assert_eq!(ts, 1_704_067_200);
    }

    #[test]
    fn parse_ssh_datetime_space_separated() {
        let ts = parse_ssh_datetime("2024-01-01 00:00:00").unwrap();
        assert_eq!(ts, 1_704_067_200);
    }

    #[test]
    fn parse_ssh_datetime_date_only() {
        let ts = parse_ssh_datetime("2024-01-01").unwrap();
        assert_eq!(ts, 1_704_067_200);
    }

    #[test]
    fn parse_ssh_datetime_invalid() {
        assert!(parse_ssh_datetime("").is_none());
        assert!(parse_ssh_datetime("not-a-date").is_none());
        assert!(parse_ssh_datetime("2024-13-01").is_none());
    }

    #[test]
    fn parse_ssh_datetime_different_dates() {
        // Verify different dates produce different timestamps
        let ts1 = parse_ssh_datetime("2024-01-01").unwrap();
        let ts2 = parse_ssh_datetime("2024-06-15").unwrap();
        assert!(ts2 > ts1);
    }

    // -----------------------------------------------------------------------
    // TrustedUserCAKeys local checking
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn trusted_user_ca_keys_file_exists() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("trusted-user-ca-keys.pem");
        std::fs::write(&ca_path, "ssh-ed25519 AAAAC3Nza... ca-key\n").unwrap();

        let svc = CertificateService::new();
        let status = svc.check_trusted_user_ca_keys(&ca_path).await.unwrap();
        assert!(status.exists);
        assert!(status.readable);
        assert_eq!(status.key_count, 1);
    }

    #[tokio::test]
    async fn trusted_user_ca_keys_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("nonexistent.pem");

        let svc = CertificateService::new();
        let status = svc.check_trusted_user_ca_keys(&ca_path).await.unwrap();
        assert!(!status.exists);
        assert!(!status.readable);
        assert_eq!(status.key_count, 0);
    }

    #[tokio::test]
    async fn trusted_user_ca_keys_multiple_keys() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca-keys.pem");
        std::fs::write(
            &ca_path,
            "# CA keys for user authentication\n\
             ssh-ed25519 AAAAC3Nza... ca-key-1\n\
             ssh-rsa AAAAB3Nza... ca-key-2\n\
             # staging CA\n\
             ssh-ed25519 AAAAC3Nza... ca-key-3\n",
        )
        .unwrap();

        let svc = CertificateService::new();
        let status = svc.check_trusted_user_ca_keys(&ca_path).await.unwrap();
        assert!(status.exists);
        assert!(status.readable);
        assert_eq!(status.key_count, 3);
    }

    #[tokio::test]
    async fn trusted_user_ca_keys_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("empty.pem");
        std::fs::write(&ca_path, "").unwrap();

        let svc = CertificateService::new();
        let status = svc.check_trusted_user_ca_keys(&ca_path).await.unwrap();
        assert!(status.exists);
        assert!(status.readable);
        assert_eq!(status.key_count, 0);
    }

    #[tokio::test]
    async fn trusted_user_ca_keys_comments_only() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("comments.pem");
        std::fs::write(
            &ca_path,
            "# This file contains CA keys\n# Managed by ansible\n",
        )
        .unwrap();

        let svc = CertificateService::new();
        let status = svc.check_trusted_user_ca_keys(&ca_path).await.unwrap();
        assert!(status.exists);
        assert!(status.readable);
        assert_eq!(status.key_count, 0);
    }
}
