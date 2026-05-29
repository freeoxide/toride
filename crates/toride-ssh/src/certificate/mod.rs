mod ca;
mod krl;

pub use ca::CertificateInfo;
pub use krl::KrlInfo;

use std::path::Path;

use crate::Result;

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
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        // OpenSSH validity check: valid_after <= now < valid_before
        Ok(info.valid_after <= now && now < info.valid_before)
    }

    /// Revoke a key by adding it to a KRL file.
    ///
    /// Creates the KRL file if it does not exist, or updates it if it does.
    /// The `key` parameter should be the path to the public key file to revoke.
    pub async fn revoke_key(&self, krl_path: &Path, key: &str) -> Result<()> {
        let krl_str = krl_path.to_string_lossy().into_owned();
        let key_owned = key.to_owned();

        // If the KRL already exists, use -u to update it in-place rather than
        // overwriting. Without -u, ssh-keygen -k replaces the entire KRL.
        let update = krl_path.exists();
        let mut args: Vec<&str> = Vec::new();
        args.push("-k");
        if update {
            args.push("-u");
        }
        args.push("-f");
        args.push(&krl_str);
        args.push(&key_owned);

        crate::runner::ssh_keygen(&args).await?;

        Ok(())
    }
}
