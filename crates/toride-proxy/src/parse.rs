//! Parsing functions for nginx status, certbot certificates, and OpenSSL output.
//!
//! Provides pure functions that convert raw text output from external tools
//! into structured types.

use crate::certs_parse::{days_until, parse_openssl_enddate_epoch};
use crate::report::CertInfo;
use std::time::{SystemTime, UNIX_EPOCH};

/// Parsed nginx status information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NginxStatus {
    /// Whether nginx is running.
    pub running: bool,
    /// Parsed nginx version string (e.g. "1.24.0").
    pub version: Option<String>,
    /// PID of the nginx master process, if running.
    pub pid: Option<u32>,
}

impl NginxStatus {
    /// Create a status indicating nginx is not running.
    pub fn stopped() -> Self {
        Self {
            running: false,
            version: None,
            pid: None,
        }
    }
}

/// Parse `nginx -v` stderr output to extract the version.
///
/// nginx writes its version to stderr in the format:
/// `nginx version: nginx/1.24.0`
pub fn parse_nginx_version(output: &str) -> Option<String> {
    for line in output.lines() {
        if let Some(rest) = line.strip_prefix("nginx version: nginx/") {
            return Some(rest.trim().to_string());
        }
        if let Some(rest) = line.strip_prefix("nginx version: openresty/") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

/// Parse `systemctl status nginx` output for running state and PID.
///
/// Looks for "active (running)" and "Main PID" lines.
pub fn parse_nginx_status(output: &str) -> NginxStatus {
    let running = output.contains("active (running)");

    let pid = output.lines().find_map(|line| {
        let trimmed = line.trim();
        let rest = trimmed.strip_prefix("Main PID: ")?;
        rest.split_whitespace()
            .next()
            .and_then(|s| s.parse::<u32>().ok())
    });

    NginxStatus {
        running,
        version: None,
        pid,
    }
}

/// Parse `certbot certificates` output into structured [`CertInfo`] values.
///
/// Expected format (abbreviated):
/// ```text
/// Found the following certs:
///   Certificate Name: example.com
///     Serial Number: ...
///     Key Type: ...
///     Domains: example.com www.example.com
///     Expiry Date: 2024-09-01 00:00:00+00:00 (VALID: 89 days)
///     Certificate Path: /etc/letsencrypt/live/example.com/fullchain.pem
///     Private Key Path: /etc/letsencrypt/live/example.com/privkey.pem
/// ```
pub fn parse_certbot_certs(output: &str) -> Vec<CertInfo> {
    let mut certs = Vec::new();
    let mut current_name = String::new();
    let mut current_expiry = String::new();
    let mut current_days: i64 = 0;

    for line in output.lines() {
        let trimmed = line.trim();

        if let Some(name) = trimmed.strip_prefix("Certificate Name: ") {
            // Push the previous cert if we have one
            if !current_name.is_empty() {
                certs.push(CertInfo::new(
                    &current_name,
                    "Let's Encrypt",
                    "",
                    &current_expiry,
                    current_days,
                ));
            }
            current_name = name.trim().to_string();
            current_expiry.clear();
            current_days = 0;
        }

        if let Some(expiry) = trimmed.strip_prefix("Expiry Date: ") {
            // Parse the expiry date and days remaining
            let expiry = expiry.trim();
            if let Some(paren) = expiry.find('(') {
                current_expiry = expiry[..paren].trim().to_string();
                // Try to extract days from "(VALID: 89 days)" or "(EXPIRED)"
                let paren_content = &expiry[paren..];
                if paren_content.contains("EXPIRED") {
                    current_days = -1;
                } else if let Some(days_str) = extract_days(paren_content) {
                    current_days = days_str;
                }
            } else {
                current_expiry = expiry.to_string();
            }
        }
    }

    // Push the last cert
    if !current_name.is_empty() {
        certs.push(CertInfo::new(
            &current_name,
            "Let's Encrypt",
            "",
            &current_expiry,
            current_days,
        ));
    }

    certs
}

/// Parse `openssl x509 -text -noout` output for certificate details.
///
/// Extracts subject, issuer, validity dates, and SANs.
pub fn parse_openssl_cert(output: &str) -> Option<CertInfo> {
    let mut subject = String::new();
    let mut issuer = String::new();
    let mut not_before = String::new();
    let mut not_after = String::new();

    for line in output.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("Subject: ") {
            subject = parse_dn_value(trimmed);
        }
        if trimmed.starts_with("Issuer: ") {
            issuer = parse_dn_value(trimmed);
        }
        if let Some(val) = trimmed.strip_prefix("Not Before: ") {
            not_before = val.trim().to_string();
        }
        if let Some(val) = trimmed.strip_prefix("Not After : ") {
            not_after = val.trim().to_string();
        }
    }

    if subject.is_empty() {
        return None;
    }

    // Compute real days remaining from the Not After date vs now. The
    // `openssl x509 -text` "Not After" line uses the same `Mon DD HH:MM:SS YYYY
    // GMT` format as `-enddate`, so we reuse the shared epoch parser. When the
    // date is absent or unparseable we surface 0 (treated as invalid by
    // CertInfo::new, since is_valid is `days_remaining > 0`) rather than
    // fabricating a healthy expiry.
    let days_remaining = not_after
        .split_whitespace()
        .next()
        .and_then(|_| parse_openssl_enddate_epoch(&not_after))
        .map_or(0, |expiry_epoch| {
            let now_epoch = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            days_until(now_epoch, expiry_epoch)
        });

    Some(CertInfo::new(
        subject,
        issuer,
        not_before,
        not_after,
        days_remaining,
    ))
}

/// Extract the CN (Common Name) or first DNS name from a distinguished name.
fn parse_dn_value(dn: &str) -> String {
    // Strip the "Subject: " or "Issuer: " prefix
    let rest = dn.split_once(':').map_or(dn, |(_, v)| v.trim());

    // Try to find CN=
    for part in rest.split(',') {
        let part = part.trim();
        if let Some(cn) = part.strip_prefix("CN = ") {
            return cn.trim().to_string();
        }
        if let Some(cn) = part.strip_prefix("CN=") {
            return cn.trim().to_string();
        }
    }

    // Fall back to the full DN
    rest.to_string()
}

/// Extract the number of days from a parenthetical like "(VALID: 89 days)".
fn extract_days(s: &str) -> Option<i64> {
    // Look for a pattern like "N days"
    let parts: Vec<&str> = s.split_whitespace().collect();
    for i in 0..parts.len().saturating_sub(1) {
        if parts[i + 1].starts_with("day")
            && let Ok(n) = parts[i].parse::<i64>()
        {
            return Some(n);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nginx_version_standard() {
        let output = "nginx version: nginx/1.24.0\n";
        assert_eq!(parse_nginx_version(output), Some("1.24.0".into()));
    }

    #[test]
    fn parse_nginx_version_openresty() {
        let output = "nginx version: openresty/1.25.3\n";
        assert_eq!(parse_nginx_version(output), Some("1.25.3".into()));
    }

    #[test]
    fn parse_nginx_version_unknown_format() {
        assert_eq!(parse_nginx_version("something else"), None);
    }

    #[test]
    fn parse_nginx_status_running() {
        let output = "\
● nginx.service - A high performance web server
   Loaded: loaded
   Active: active (running) since Mon 2024-01-01 00:00:00 UTC
 Main PID: 1234 (nginx)
";
        let status = parse_nginx_status(output);
        assert!(status.running);
        assert_eq!(status.pid, Some(1234));
    }

    #[test]
    fn parse_nginx_status_stopped() {
        let output =
            "● nginx.service - A high performance web server\n   Active: inactive (dead)\n";
        let status = parse_nginx_status(output);
        assert!(!status.running);
        assert_eq!(status.pid, None);
    }

    #[test]
    fn parse_certbot_certs_output() {
        let output = "\
Found the following certs:
  Certificate Name: example.com
    Domains: example.com
    Expiry Date: 2024-09-01 00:00:00+00:00 (VALID: 89 days)
    Certificate Path: /etc/letsencrypt/live/example.com/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/example.com/privkey.pem
";
        let certs = parse_certbot_certs(output);
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].domain, "example.com");
        assert_eq!(certs[0].days_remaining, 89);
        assert!(certs[0].is_valid);
    }

    #[test]
    fn parse_certbot_certs_expired() {
        let output = "\
Found the following certs:
  Certificate Name: expired.com
    Expiry Date: 2023-01-01 00:00:00+00:00 (EXPIRED)
";
        let certs = parse_certbot_certs(output);
        assert_eq!(certs.len(), 1);
        assert!(!certs[0].is_valid);
    }

    #[test]
    fn extract_days_valid() {
        assert_eq!(extract_days("(VALID: 89 days)"), Some(89));
        assert_eq!(extract_days("(VALID: 0 days)"), Some(0));
    }

    #[test]
    fn extract_days_no_match() {
        assert_eq!(extract_days("(EXPIRED)"), None);
    }

    #[test]
    fn parse_openssl_cert_computes_real_days_remaining() {
        // Far-future expiry: days_remaining must be a large positive number,
        // not the previous hardcoded 0. Mirrors `openssl x509 -text -noout`
        // output where the Subject and Not After lines each carry their value
        // on the same physical line.
        let output = "\
Subject: C = US, O = Example, CN = example.com
Issuer: C = US, O = Test CA
Not Before: Jan  1 00:00:00 2024 GMT
Not After : Jan  1 00:00:00 2099 GMT
";
        let cert = parse_openssl_cert(output).expect("should parse");
        assert_eq!(cert.domain, "example.com");
        assert!(cert.days_remaining > 10_000, "got {}", cert.days_remaining);
        assert!(cert.is_valid);
    }

    #[test]
    fn parse_openssl_cert_expired_reports_negative() {
        // Past expiry: days_remaining must be negative (already expired).
        let output = "\
Subject: CN = expired.com
Not After : Jan  1 00:00:00 2001 GMT
";
        let cert = parse_openssl_cert(output).expect("should parse");
        assert!(cert.days_remaining < 0, "got {}", cert.days_remaining);
        assert!(!cert.is_valid);
    }

    #[test]
    fn parse_openssl_cert_unparseable_date_is_zero() {
        // Bogus date string -> days_remaining 0 (treated as invalid).
        let output = "\
Subject: CN = weird.com
Not After : not-a-date
";
        let cert = parse_openssl_cert(output).expect("should parse");
        assert_eq!(cert.days_remaining, 0);
        assert!(!cert.is_valid);
    }
}
