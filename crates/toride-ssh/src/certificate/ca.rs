//! SSH certificate inspection via the `ssh_key` crate.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::Result;

/// Parsed details of an OpenSSH certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    /// Serial number assigned by the CA.
    pub serial: u64,
    /// Key algorithm name (e.g. `ssh-ed25519`).
    pub key_type: String,
    /// Free-form key ID assigned by the CA.
    pub key_id: String,
    /// Principals this certificate is valid for.
    pub valid_principals: Vec<String>,
    /// Valid-after timestamp (Unix seconds).
    pub valid_after: u64,
    /// Valid-before timestamp (Unix seconds).
    pub valid_before: u64,
    /// Critical options as key-value pairs.
    pub critical_options: Vec<(String, String)>,
    /// Extension names present on the certificate.
    pub extensions: Vec<String>,
    /// SHA-256 fingerprint of the signing CA key.
    pub ca_fingerprint: Option<String>,
    /// Whether the certificate is a CA certificate (host vs user).
    pub is_host: bool,
}

/// Parse a certificate file and return structured information.
///
/// The file must be an OpenSSH certificate (typically `-cert.pub`).
/// Falls back to `ssh-keygen -L` when the native parser cannot handle the
/// key format.
pub async fn inspect_certificate(path: &Path) -> Result<CertificateInfo> {
    // Try the native ssh-key parser first (fast, no subprocess).
    match inspect_native(path).await {
        Ok(info) => Ok(info),
        Err(native_err) => {
            // Log the native parse failure so it isn't silently swallowed when
            // we fall back to ssh-keygen -L.
            tracing::debug!(
                "native certificate parse failed, falling back to ssh-keygen -L: {native_err}"
            );
            inspect_via_keygen(path).await
        }
    }
}

/// Attempt to parse using `ssh_key::certificate::Certificate`.
async fn inspect_native(path: &Path) -> Result<CertificateInfo> {
    let path = path.to_path_buf();
    let cert = tokio::task::spawn_blocking(move || {
        ssh_key::certificate::Certificate::read_file(&path)
            .map_err(|e| crate::Error::CertificateParseFailed(e.to_string()))
    })
    .await
    .map_err(|e| crate::Error::CertificateParseFailed(e.to_string()))??;

    Ok(cert_to_info(&cert))
}

/// Parse `ssh-keygen -L` output when the native parser is insufficient.
async fn inspect_via_keygen(path: &Path) -> Result<CertificateInfo> {
    let path_str = path.to_string_lossy().into_owned();
    let output = crate::runner::ssh_keygen(&["-L", "-f", &path_str]).await?;

    parse_keygen_output(&output, path)
}

/// Convert a parsed `Certificate` into our `CertificateInfo`.
fn cert_to_info(cert: &ssh_key::certificate::Certificate) -> CertificateInfo {
    let critical_options: Vec<(String, String)> = cert
        .critical_options()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let extensions: Vec<String> = cert.extensions().keys().cloned().collect();

    let ca_fingerprint = cert.signature_key().fingerprint(ssh_key::HashAlg::Sha256);
    let ca_fp_string = format!("{ca_fingerprint}");

    CertificateInfo {
        serial: cert.serial(),
        key_type: cert.algorithm().to_string(),
        key_id: cert.key_id().to_owned(),
        valid_principals: cert.valid_principals().to_vec(),
        valid_after: cert.valid_after(),
        valid_before: cert.valid_before(),
        critical_options,
        extensions,
        ca_fingerprint: Some(ca_fp_string),
        is_host: cert.cert_type().is_host(),
    }
}

/// Best-effort parser for `ssh-keygen -L` text output.
///
/// `ssh-keygen -L` output looks roughly like:
///
/// ```text
/// /path/to/cert.pub:
///         Type: ssh-ed25519-cert-v01@openssh.com user certificate
///         Public key: ED25519-CERT SHA256:xxxx
///         Signing CA: ED25519 SHA256:yyyy (using ssh-ed25519)
///         Key ID: "some-id"
///         Serial: 12345
///         Valid: from 2024-01-01T00:00:00 to 2025-01-01T00:00:00
///         Principals:
///                 user1
///                 user2
///         Critical Options: (none)
///         Extensions:
///                 permit-X11-forwarding
///                 permit-agent-forwarding
///                 permit-port-forwarding
///                 permit-pty
///                 permit-user-rc
/// ```
fn parse_keygen_output(output: &str, path: &Path) -> Result<CertificateInfo> {
    let mut serial = 0u64;
    let mut key_type = String::new();
    let mut key_id = String::new();
    let mut valid_principals = Vec::new();
    let mut valid_after = 0u64;
    let mut valid_before = 0u64;
    let mut critical_options = Vec::new();
    let mut extensions = Vec::new();
    let mut ca_fingerprint: Option<String> = None;
    let mut is_host = false;

    let mut in_principals = false;
    let mut in_extensions = false;
    let mut in_critical = false;

    for line in output.lines() {
        let trimmed = line.trim();

        if in_principals {
            if trimmed.is_empty()
                || trimmed.starts_with("Critical")
                || trimmed.starts_with("Extensions")
            {
                in_principals = false;
            } else {
                valid_principals.push(trimmed.to_owned());
                continue;
            }
        }

        if in_extensions {
            if trimmed.is_empty() || trimmed.starts_with("Critical") {
                in_extensions = false;
            } else {
                extensions.push(trimmed.to_owned());
                continue;
            }
        }

        if in_critical {
            if trimmed.is_empty()
                || trimmed.starts_with("Extensions")
                || trimmed.starts_with("Critical")
            {
                in_critical = false;
            } else if !trimmed.starts_with('(') {
                // Parse "name value" or just "name"
                if let Some((k, v)) = trimmed.split_once(' ') {
                    critical_options.push((k.to_owned(), v.to_owned()));
                } else {
                    critical_options.push((trimmed.to_owned(), String::new()));
                }
                continue;
            }
        }

        if let Some(rest) = trimmed.strip_prefix("Type:") {
            let rest = rest.trim();
            if rest.contains("host certificate") {
                is_host = true;
            }
            // Extract key type, e.g. "ssh-ed25519-cert-v01@openssh.com ..."
            if let Some(sp) = rest.find(' ') {
                key_type = rest[..sp].to_owned();
            } else {
                key_type = rest.to_owned();
            }
        } else if let Some(rest) = trimmed.strip_prefix("Serial:") {
            serial = rest.trim().parse().map_err(|_| {
                crate::Error::CertificateParseFailed(format!("invalid serial: {}", rest.trim()))
            })?;
        } else if let Some(rest) = trimmed.strip_prefix("Key ID:") {
            key_id = rest.trim().trim_matches('"').to_owned();
        } else if let Some(rest) = trimmed.strip_prefix("Valid:") {
            // Parse "from YYYY-MM-DDTHH:MM:SS to YYYY-MM-DDTHH:MM:SS"
            // Also handle: "forever" for unbounded validity.
            let rest = rest.trim();
            if let Some(from_str) = rest.strip_prefix("from ") {
                if let Some((after_str, before_str)) = from_str.split_once(" to ") {
                    valid_after = datetime_str_to_unix(after_str.trim())?;
                    valid_before = if before_str.trim().eq_ignore_ascii_case("forever") {
                        u64::MAX
                    } else {
                        datetime_str_to_unix(before_str.trim())?
                    };
                }
            }
        } else if let Some(rest) = trimmed.strip_prefix("Signing CA:") {
            // Look for SHA256:... fingerprint
            if let Some(fp) = rest.split_whitespace().find(|s| s.starts_with("SHA256:")) {
                ca_fingerprint = Some(fp.to_owned());
            }
        } else if trimmed == "Principals:" {
            in_principals = true;
        } else if trimmed.starts_with("Extensions:") {
            if !trimmed.contains("(none)") {
                in_extensions = true;
            }
        } else if trimmed.starts_with("Critical Options:") {
            if !trimmed.contains("(none)") {
                in_critical = true;
            }
        }
    }

    // Sanity check that we parsed something meaningful.
    if key_type.is_empty() {
        return Err(crate::Error::CertificateParseFailed(format!(
            "ssh-keygen -L output for {} did not contain a key type",
            path.display()
        )));
    }

    Ok(CertificateInfo {
        serial,
        key_type,
        key_id,
        valid_principals,
        valid_after,
        valid_before,
        critical_options,
        extensions,
        ca_fingerprint,
        is_host,
    })
}

/// Convert a datetime string like "2024-01-01T00:00:00" to a Unix timestamp.
/// Handles the keyword "forever" by returning `u64::MAX`.
///
/// # Errors
///
/// Returns [`crate::Error::CertificateParseFailed`] if the datetime string
/// cannot be parsed with any known SSH date format.
fn datetime_str_to_unix(s: &str) -> Result<u64> {
    if s.eq_ignore_ascii_case("forever") {
        return Ok(u64::MAX);
    }

    // ssh-keygen outputs dates in various formats:
    //   "2024-01-01T00:00:00"  (ISO 8601 with T separator)
    //   "2024-01-01 00:00:00"  (space separator)
    //   "20240101T00:00:00"    (compact form, sometimes from -Q -l)
    // Also try timezone-aware variants.
    let formats = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y%m%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%:z",
        "%Y-%m-%dT%H:%M:%S%#z",
    ];

    for fmt in &formats {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, fmt) {
            return Ok(dt.and_utc().timestamp().max(0) as u64);
        }
    }

    Err(crate::Error::CertificateParseFailed(format!(
        "unrecognized datetime format: {s}"
    )))
}
