mod ca;
mod krl;

pub use ca::CertificateInfo;
pub use krl::KrlInfo;

use std::path::Path;

use crate::Result;

/// Best-effort datetime string to Unix timestamp (seconds since epoch).
///
/// Handles the compact format emitted by `ssh-keygen` (`20240101T000000`)
/// as well as common ISO-ish formats. Returns `None` if no format matches.
pub(crate) fn parse_ssh_datetime(s: &str) -> Option<i64> {
    let formats = [
        "%Y%m%dT%H%M%S",    // compact form used by ssh-keygen KRL output
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
        return d
            .and_hms_opt(0, 0, 0)
            .map(|dt| dt.and_utc().timestamp());
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
    pub async fn inspect(&self, path: &Path) -> Result<CertificateInfo> {
        ca::inspect_certificate(path).await
    }

    /// Inspect a Key Revocation List (KRL) file.
    pub async fn inspect_krl(&self, path: &Path) -> Result<KrlInfo> {
        krl::inspect_krl(path).await
    }

    /// Check whether a certificate is currently within its validity window.
    pub async fn is_valid(&self, path: &Path) -> Result<bool> {
        let info = self.inspect(path).await?;
        // Clamp to non-negative: timestamp() returns i64, valid_* fields are u64.
        let now = u64::try_from(chrono::Utc::now().timestamp().max(0)).unwrap_or(0);
        // OpenSSH validity check: valid_after <= now < valid_before
        Ok(info.valid_after <= now && now < info.valid_before)
    }

    /// Revoke a key by adding it to a KRL file.
    ///
    /// Creates the KRL file if it does not exist, or updates it if it does.
    /// The `key` parameter should be the path to the public key file to revoke.
    pub async fn revoke_key(&self, krl_path: &Path, key: &str) -> Result<()> {
        let krl_str = krl_path.to_str().ok_or_else(|| {
            crate::Error::CommandFailed(format!(
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
        args.push(&krl_str);
        args.push(key);

        crate::runner::ssh_keygen(&args).await?;

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
        assert_eq!(ts, 1704067200);
    }

    #[test]
    fn parse_ssh_datetime_iso() {
        let ts = parse_ssh_datetime("2024-01-01T00:00:00").unwrap();
        assert_eq!(ts, 1704067200);
    }

    #[test]
    fn parse_ssh_datetime_space_separated() {
        let ts = parse_ssh_datetime("2024-01-01 00:00:00").unwrap();
        assert_eq!(ts, 1704067200);
    }

    #[test]
    fn parse_ssh_datetime_date_only() {
        let ts = parse_ssh_datetime("2024-01-01").unwrap();
        assert_eq!(ts, 1704067200);
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
}
