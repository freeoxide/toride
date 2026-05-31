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
    let path_str = path.to_str().ok_or_else(|| {
        crate::Error::CommandFailed(format!(
            "certificate path is not valid UTF-8: {}",
            path.display()
        ))
    })?;
    let output = crate::runner::ssh_keygen(&["-L", "-f", path_str]).await?;

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

/// Mutable state for the `ssh-keygen -L` line-by-line parser.
struct KeygenParserState {
    info: CertificateInfo,
    in_principals: bool,
    in_extensions: bool,
    in_critical: bool,
}

impl KeygenParserState {
    fn new() -> Self {
        Self {
            info: CertificateInfo {
                serial: 0,
                key_type: String::new(),
                key_id: String::new(),
                valid_principals: Vec::new(),
                valid_after: 0,
                valid_before: 0,
                critical_options: Vec::new(),
                extensions: Vec::new(),
                ca_fingerprint: None,
                is_host: false,
            },
            in_principals: false,
            in_extensions: false,
            in_critical: false,
        }
    }

    fn process_line(&mut self, line: &str) -> Result<()> {
        let trimmed = line.trim();

        if self.in_principals {
            if trimmed.is_empty()
                || trimmed.starts_with("Critical")
                || trimmed.starts_with("Extensions")
            {
                self.in_principals = false;
            } else {
                self.info.valid_principals.push(trimmed.to_owned());
                return Ok(());
            }
        }

        if self.in_extensions {
            if trimmed.is_empty() || trimmed.starts_with("Critical") {
                self.in_extensions = false;
            } else {
                self.info.extensions.push(trimmed.to_owned());
                return Ok(());
            }
        }

        if self.in_critical {
            if trimmed.is_empty()
                || trimmed.starts_with("Extensions")
                || trimmed.starts_with("Critical")
            {
                self.in_critical = false;
            } else if !trimmed.starts_with('(') {
                // Parse "name value" or just "name"
                if let Some((k, v)) = trimmed.split_once(' ') {
                    self.info.critical_options.push((k.to_owned(), v.to_owned()));
                } else {
                    self.info.critical_options.push((trimmed.to_owned(), String::new()));
                }
                return Ok(());
            }
        }

        if let Some(rest) = trimmed.strip_prefix("Type:") {
            let rest = rest.trim();
            if rest.contains("host certificate") {
                self.info.is_host = true;
            }
            // Extract key type, e.g. "ssh-ed25519-cert-v01@openssh.com ..."
            if let Some(sp) = rest.find(' ') {
                rest[..sp].clone_into(&mut self.info.key_type);
            } else {
                rest.clone_into(&mut self.info.key_type);
            }
        } else if let Some(rest) = trimmed.strip_prefix("Serial:") {
            self.info.serial = rest.trim().parse().map_err(|_| {
                crate::Error::CertificateParseFailed(format!("invalid serial: {}", rest.trim()))
            })?;
        } else if let Some(rest) = trimmed.strip_prefix("Key ID:") {
            rest.trim()
                .trim_matches('"')
                .clone_into(&mut self.info.key_id);
        } else if let Some(rest) = trimmed.strip_prefix("Valid:") {
            // Parse "from YYYY-MM-DDTHH:MM:SS to YYYY-MM-DDTHH:MM:SS"
            // Also handle: "forever" for unbounded validity.
            let rest = rest.trim();
            if let Some((after_str, before_str)) =
                rest.strip_prefix("from ").and_then(|s| s.split_once(" to "))
            {
                self.info.valid_after = datetime_str_to_unix(after_str.trim())?;
                self.info.valid_before = if before_str.trim().eq_ignore_ascii_case("forever") {
                    u64::MAX
                } else {
                    datetime_str_to_unix(before_str.trim())?
                };
            }
        } else if let Some(rest) = trimmed.strip_prefix("Signing CA:") {
            // Look for SHA256:... fingerprint
            if let Some(fp) = rest.split_whitespace().find(|s| s.starts_with("SHA256:")) {
                self.info.ca_fingerprint = Some(fp.to_owned());
            }
        } else if trimmed == "Principals:" {
            self.in_principals = true;
        } else if trimmed.starts_with("Extensions:") && !trimmed.contains("(none)") {
            self.in_extensions = true;
        } else if trimmed.starts_with("Critical Options:") && !trimmed.contains("(none)") {
            self.in_critical = true;
        }

        Ok(())
    }

    fn into_info(self) -> CertificateInfo {
        self.info
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
    let mut state = KeygenParserState::new();

    for line in output.lines() {
        state.process_line(line)?;
    }

    // Sanity check that we parsed something meaningful.
    if state.info.key_type.is_empty() {
        return Err(crate::Error::CertificateParseFailed(format!(
            "ssh-keygen -L output for {} did not contain a key type",
            path.display()
        )));
    }

    Ok(state.into_info())
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

    super::parse_ssh_datetime(s)
        .map(|ts| u64::try_from(ts.max(0)).unwrap_or(0))
        .ok_or_else(|| {
            crate::Error::CertificateParseFailed(format!(
                "unrecognized datetime format: {s}"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_keygen_output_user_cert() {
        let output = r#"/path/to/cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Public key: ED25519-CERT SHA256:xxxx
        Signing CA: ED25519 SHA256:yyyy (using ssh-ed25519)
        Key ID: "my-key-id"
        Serial: 12345
        Valid: from 2024-01-01T00:00:00 to 2025-01-01T00:00:00
        Principals:
                user1
                user2
        Critical Options: (none)
        Extensions:
                permit-X11-forwarding
                permit-agent-forwarding
                permit-port-forwarding
                permit-pty
                permit-user-rc
"#;
        let info = parse_keygen_output(output, std::path::Path::new("/path/to/cert.pub")).unwrap();
        assert_eq!(info.key_type, "ssh-ed25519-cert-v01@openssh.com");
        assert_eq!(info.key_id, "my-key-id");
        assert_eq!(info.serial, 12345);
        assert!(!info.is_host);
        assert_eq!(info.valid_principals, vec!["user1", "user2"]);
        assert_eq!(info.extensions.len(), 5);
        assert!(info.ca_fingerprint.is_some());
        assert!(info.ca_fingerprint.as_deref().unwrap().starts_with("SHA256:"));
    }

    #[test]
    fn parse_keygen_output_host_cert() {
        let output = r#"/path/to/host-cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com host certificate
        Public key: ED25519-CERT SHA256:xxxx
        Signing CA: ED25519 SHA256:yyyy
        Key ID: "host-key"
        Serial: 0
        Valid: from 2024-01-01T00:00:00 to forever
        Principals:
                example.com
                192.168.1.1
        Critical Options:
                force-command /usr/bin/limited
        Extensions: (none)
"#;
        let info = parse_keygen_output(output, std::path::Path::new("/path/to/cert.pub")).unwrap();
        assert!(info.is_host);
        assert_eq!(info.valid_before, u64::MAX);
        assert_eq!(info.valid_principals, vec!["example.com", "192.168.1.1"]);
        assert_eq!(info.critical_options.len(), 1);
        assert_eq!(info.critical_options[0].0, "force-command");
        assert!(info.extensions.is_empty());
    }

    #[test]
    fn parse_keygen_output_no_type_fails() {
        let output = "Some random output without type\n";
        let result = parse_keygen_output(output, std::path::Path::new("/path/to/cert.pub"));
        assert!(result.is_err());
    }

    #[test]
    fn parse_keygen_output_empty() {
        let result = parse_keygen_output("", std::path::Path::new("/path/to/cert.pub"));
        assert!(result.is_err());
    }

    #[test]
    fn parse_keygen_output_no_principals() {
        let output = r#"/path/to/cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Key ID: "test"
        Serial: 0
        Valid: from 2024-01-01T00:00:00 to 2025-01-01T00:00:00
        Principals: (none)
        Critical Options: (none)
        Extensions: (none)
"#;
        let info = parse_keygen_output(output, std::path::Path::new("/path/to/cert.pub")).unwrap();
        assert!(info.valid_principals.is_empty());
    }

    #[test]
    fn datetime_str_to_unix_forever() {
        assert_eq!(datetime_str_to_unix("forever").unwrap(), u64::MAX);
        assert_eq!(datetime_str_to_unix("FOREVER").unwrap(), u64::MAX);
    }

    #[test]
    fn datetime_str_to_unix_invalid() {
        assert!(datetime_str_to_unix("not-a-date").is_err());
        assert!(datetime_str_to_unix("").is_err());
    }

    #[test]
    fn datetime_str_to_unix_valid() {
        // Should parse a valid ISO timestamp
        let result = datetime_str_to_unix("2024-01-01T00:00:00");
        assert!(result.is_ok());
        assert!(result.unwrap() > 0);
    }

    #[test]
    fn keygen_parser_state_extensions_none() {
        let mut state = KeygenParserState::new();
        state.process_line("        Extensions: (none)").unwrap();
        assert!(!state.in_extensions);
        assert!(state.info.extensions.is_empty());
    }

    #[test]
    fn keygen_parser_state_critical_none() {
        let mut state = KeygenParserState::new();
        state.process_line("        Critical Options: (none)").unwrap();
        assert!(!state.in_critical);
        assert!(state.info.critical_options.is_empty());
    }

    // -----------------------------------------------------------------------
    // Certificate TrustedUserCAKeys — reading and validation
    // -----------------------------------------------------------------------

    #[test]
    fn parse_keygen_output_with_ca_fingerprint() {
        let output = r#"/path/to/cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Public key: ED25519-CERT SHA256:xxxx
        Signing CA: ED25519 SHA256:caFingerPrintBase64Here (using ssh-ed25519)
        Key ID: "ca-signed-key"
        Serial: 99
        Valid: from 2024-01-01T00:00:00 to 2025-12-31T23:59:59
        Principals:
                admin
        Critical Options: (none)
        Extensions:
                permit-pty
"#;
        let info = parse_keygen_output(output, std::path::Path::new("/path/to/cert.pub")).unwrap();
        assert!(info.ca_fingerprint.is_some());
        let ca_fp = info.ca_fingerprint.as_ref().unwrap();
        assert!(ca_fp.starts_with("SHA256:"), "CA fingerprint should start with SHA256: prefix");
        assert!(ca_fp.contains("caFingerPrintBase64Here"));
    }

    #[test]
    fn parse_keygen_output_host_cert_with_ca() {
        // TrustedUserCAKeys is used to validate host certificates.
        // A host cert signed by the CA should be parseable.
        let output = r#"/etc/ssh/ssh_host_ed25519_key-cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com host certificate
        Public key: ED25519-CERT SHA256:hostKeyHash
        Signing CA: ED25519 SHA256:trustedCAHash (using ssh-ed25519)
        Key ID: "host-key-signed-by-ca"
        Serial: 0
        Valid: from 2024-01-01T00:00:00 to forever
        Principals:
                server.example.com
                10.0.0.1
        Critical Options:
                force-command /usr/sbin/sshd
        Extensions: (none)
"#;
        let info = parse_keygen_output(output, std::path::Path::new("/etc/ssh/ssh_host_ed25519_key-cert.pub")).unwrap();
        assert!(info.is_host, "should be detected as a host certificate");
        assert_eq!(info.valid_before, u64::MAX, "forever should be u64::MAX");
        assert_eq!(info.valid_principals, vec!["server.example.com", "10.0.0.1"]);
        assert_eq!(info.critical_options.len(), 1);
        assert_eq!(info.critical_options[0].0, "force-command");
        assert!(info.ca_fingerprint.is_some());
    }

    #[test]
    fn parse_keygen_output_cert_without_signing_ca() {
        // Certificate without Signing CA line.
        let output = r#"/path/to/cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Public key: ED25519-CERT SHA256:xxxx
        Key ID: "no-ca"
        Serial: 0
        Valid: from 2024-01-01T00:00:00 to 2025-01-01T00:00:00
        Principals: (none)
        Critical Options: (none)
        Extensions: (none)
"#;
        let info = parse_keygen_output(output, std::path::Path::new("/path/to/cert.pub")).unwrap();
        assert!(info.ca_fingerprint.is_none(), "no Signing CA line means no CA fingerprint");
    }

    #[test]
    fn certificate_info_host_vs_user_type() {
        // Verify host vs user certificate detection.
        let user_output = r#"/path/to/cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Key ID: "user-key"
        Serial: 1
        Valid: from 2024-01-01T00:00:00 to 2025-01-01T00:00:00
        Principals: (none)
        Critical Options: (none)
        Extensions: (none)
"#;
        let user_info = parse_keygen_output(user_output, std::path::Path::new("/p")).unwrap();
        assert!(!user_info.is_host);

        let host_output = r#"/path/to/cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com host certificate
        Key ID: "host-key"
        Serial: 1
        Valid: from 2024-01-01T00:00:00 to 2025-01-01T00:00:00
        Principals: (none)
        Critical Options: (none)
        Extensions: (none)
"#;
        let host_info = parse_keygen_output(host_output, std::path::Path::new("/p")).unwrap();
        assert!(host_info.is_host);
    }

    #[test]
    fn certificate_validity_forever_both_ends() {
        let output = r#"/path/to/cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Key ID: "forever"
        Serial: 0
        Valid: from forever to forever
        Principals: (none)
        Critical Options: (none)
        Extensions: (none)
"#;
        let info = parse_keygen_output(output, std::path::Path::new("/p")).unwrap();
        assert_eq!(info.valid_after, u64::MAX);
        assert_eq!(info.valid_before, u64::MAX);
    }

    #[test]
    fn certificate_with_multiple_principals() {
        let output = r#"/path/to/cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Key ID: "multi-principal"
        Serial: 0
        Valid: from 2024-01-01T00:00:00 to 2025-01-01T00:00:00
        Principals:
                alice
                bob
                charlie
                deploy
        Critical Options: (none)
        Extensions: (none)
"#;
        let info = parse_keygen_output(output, std::path::Path::new("/p")).unwrap();
        assert_eq!(info.valid_principals.len(), 4);
        assert_eq!(info.valid_principals, vec!["alice", "bob", "charlie", "deploy"]);
    }
}
