//! Validation functions for proxy configuration values.
//!
//! Ensures server names, ports, and certificate paths are well-formed
//! before they are used in configuration generation.

use crate::error::{Error, Result};

/// Validate that a server name is a valid domain name or IP address.
///
/// Server names must:
/// - Be non-empty
/// - Contain only alphanumeric characters, dots, hyphens, and asterisks (wildcards)
/// - Not start or end with a dot or hyphen
/// - Not contain consecutive dots
pub fn validate_server_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::Validation("server name must not be empty".into()));
    }

    if name.len() > 253 {
        return Err(Error::Validation(format!(
            "server name too long: {name} (max 253 characters)"
        )));
    }

    // Allow wildcard prefixes like *.example.com
    let check_name = name.strip_prefix("*.").unwrap_or(name);

    if check_name.starts_with('.') || check_name.starts_with('-') {
        return Err(Error::Validation(format!(
            "server name must not start with '.' or '-': {name}"
        )));
    }

    if check_name.ends_with('.') || check_name.ends_with('-') {
        return Err(Error::Validation(format!(
            "server name must not end with '.' or '-': {name}"
        )));
    }

    // Check for consecutive dots
    if check_name.contains("..") {
        return Err(Error::Validation(format!(
            "server name must not contain consecutive dots: {name}"
        )));
    }

    // Validate each label
    for label in check_name.split('.') {
        if label.is_empty() {
            return Err(Error::Validation(format!(
                "server name has empty label: {name}"
            )));
        }
        for ch in label.chars() {
            if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' {
                return Err(Error::Validation(format!(
                    "server name contains invalid character '{ch}' in: {name}"
                )));
            }
        }
    }

    Ok(())
}

/// Validate a domain used as a filename segment under `sites-available` /
/// `sites-enabled`.
///
/// This is a path-safety gate (defense against traversal and arbitrary-file
/// delete), distinct from [`validate_server_name`]: it rejects anything that
/// could escape the sites directory when joined onto a base path. A domain
/// segment must:
///
/// - be non-empty,
/// - not be absolute (start with `/`) or a Windows drive/root,
/// - contain no path separators (`/` or `\`),
/// - contain no parent-traversal component (`..` as a whole label, i.e. a
///   literal `..` segment, which `join` would otherwise resolve upward),
/// - contain no NUL byte,
/// - be composed solely of the DNS-label allowlist: ASCII alphanumeric, `-`,
///   `.`, and a leading `*.` wildcard.
///
/// The allowlist intentionally mirrors [`validate_server_name`] so legitimate
/// site domains (`example.com`, `sub.example.com`, `*.example.com`) pass while
/// path-shaped inputs (`../foo`, `/etc/passwd`, `a/b`, `..`) are refused before
/// they ever reach `Path::join`.
///
/// # Errors
///
/// Returns [`Error::Validation`] if the domain is not a safe single path
/// segment.
pub fn validate_site_domain(domain: &str) -> Result<()> {
    if domain.is_empty() {
        return Err(Error::Validation("site domain must not be empty".into()));
    }

    // Reject anything that looks path-shaped before joining.
    if domain.starts_with('/')
        || domain.starts_with('\\')
        || domain.contains('\0')
        || domain.contains('/')
        || domain.contains('\\')
    {
        return Err(Error::Validation(format!(
            "site domain must be a single path segment, not an absolute or nested path: {domain}"
        )));
    }

    // Reject a literal parent/current-traversal label. A bare `..` is resolved
    // by `Path::join` and would let the caller escape the sites directory; note
    // that `"..".split('.')` yields empty strings (not `".."`), so we must check
    // the whole-domain case explicitly in addition to the per-label scan. We
    // split on '.' and refuse a `..` component so inputs like `foo/../bar`
    // (already caught above for containing `/`) and `....`-style dodges are
    // also refused.
    if domain == "." || domain == ".." || domain.split('.').any(|label| label == "..") {
        return Err(Error::Validation(format!(
            "site domain must not be '.' or contain a '..' traversal component: {domain}"
        )));
    }

    // Allowlist the character set: DNS-label chars plus the leading `*.`
    // wildcard. Strip the wildcard prefix before the per-character check so
    // `*.example.com` is accepted (matching `validate_server_name`).
    let check = domain.strip_prefix("*.").unwrap_or(domain);
    for ch in check.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '.' {
            return Err(Error::Validation(format!(
                "site domain contains disallowed character '{ch}': {domain}"
            )));
        }
    }

    Ok(())
}

/// Validate that a port number is in the valid range for TCP/UDP.
///
/// Valid ports are 1-65535. Port 0 is not valid for listening.
pub fn validate_port(port: u16) -> Result<()> {
    if port == 0 {
        return Err(Error::Validation("port must not be 0".into()));
    }
    // u16 already bounds to 65535, so we only need to check for 0
    Ok(())
}

/// Validate that a certificate path points to a plausible certificate file.
///
/// Certificate paths must:
/// - Be non-empty
/// - End with a recognized extension (.pem, .crt, .cert, .cer)
/// - Not contain path traversal sequences
pub fn validate_cert_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(Error::Validation(
            "certificate path must not be empty".into(),
        ));
    }

    if path.contains("..") {
        return Err(Error::Validation(format!(
            "certificate path must not contain '..': {path}"
        )));
    }

    let valid_extensions = [".pem", ".crt", ".cert", ".cer"];
    let has_valid_ext = valid_extensions
        .iter()
        .any(|ext| path.to_ascii_lowercase().ends_with(ext));

    if !has_valid_ext {
        return Err(Error::Validation(format!(
            "certificate path must end with a recognized extension ({valid_extensions:?}): {path}",
        )));
    }

    Ok(())
}

/// Validate that an upstream address is well-formed.
///
/// Upstream addresses should be in the format `host:port` or a Unix socket path.
pub fn validate_upstream(upstream: &str) -> Result<()> {
    if upstream.is_empty() {
        return Err(Error::Validation(
            "upstream address must not be empty".into(),
        ));
    }

    // Unix socket paths start with "unix:"
    if let Some(socket_path) = upstream.strip_prefix("unix:") {
        if socket_path.is_empty() {
            return Err(Error::Validation(
                "unix socket path must not be empty".into(),
            ));
        }
        return Ok(());
    }

    // host:port format
    if let Some(port_str) = upstream.rsplit_once(':').map(|(_, p)| p) {
        if port_str.parse::<u16>().is_err() {
            return Err(Error::Validation(format!(
                "upstream port must be a valid number: {upstream}"
            )));
        }
    } else {
        return Err(Error::Validation(format!(
            "upstream address must be in host:port format: {upstream}"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_server_names() {
        assert!(validate_server_name("example.com").is_ok());
        assert!(validate_server_name("sub.example.com").is_ok());
        assert!(validate_server_name("*.example.com").is_ok());
        assert!(validate_server_name("my-site.example.org").is_ok());
    }

    #[test]
    fn invalid_server_names() {
        assert!(validate_server_name("").is_err());
        assert!(validate_server_name(".example.com").is_err());
        assert!(validate_server_name("example.com.").is_err());
        assert!(validate_server_name("-example.com").is_err());
        assert!(validate_server_name("example..com").is_err());
    }

    #[test]
    fn valid_site_domains() {
        assert!(validate_site_domain("example.com").is_ok());
        assert!(validate_site_domain("sub.example.com").is_ok());
        assert!(validate_site_domain("*.example.com").is_ok());
        assert!(validate_site_domain("my-site.example.org").is_ok());
    }

    #[test]
    fn site_domain_rejects_traversal_and_paths() {
        // Path-shaped inputs must be refused before they reach Path::join.
        assert!(validate_site_domain("").is_err());
        assert!(validate_site_domain("..").is_err());
        assert!(validate_site_domain("../etc/passwd").is_err());
        assert!(validate_site_domain("foo/../../../bar").is_err());
        assert!(validate_site_domain("/etc/passwd").is_err());
        assert!(validate_site_domain("a/b").is_err());
        assert!(validate_site_domain("a\\b").is_err());
        assert!(validate_site_domain("\\\\server\\share").is_err());
        assert!(validate_site_domain("foo\0bar").is_err());
        // Disallowed characters outside the DNS-label allowlist.
        assert!(validate_site_domain("ex ample.com").is_err());
        assert!(validate_site_domain("example.com;").is_err());
    }

    #[test]
    fn valid_ports() {
        assert!(validate_port(1).is_ok());
        assert!(validate_port(80).is_ok());
        assert!(validate_port(443).is_ok());
        assert!(validate_port(8080).is_ok());
        assert!(validate_port(65535).is_ok());
    }

    #[test]
    fn invalid_port_zero() {
        assert!(validate_port(0).is_err());
    }

    #[test]
    fn valid_cert_paths() {
        assert!(validate_cert_path("/etc/ssl/cert.pem").is_ok());
        assert!(validate_cert_path("/etc/ssl/cert.crt").is_ok());
        assert!(validate_cert_path("/etc/ssl/cert.cert").is_ok());
        assert!(validate_cert_path("/etc/ssl/cert.CER").is_ok());
    }

    #[test]
    fn invalid_cert_paths() {
        assert!(validate_cert_path("").is_err());
        assert!(validate_cert_path("/etc/ssl/../etc/cert.pem").is_err());
        assert!(validate_cert_path("/etc/ssl/cert.txt").is_err());
    }

    #[test]
    fn valid_upstreams() {
        assert!(validate_upstream("127.0.0.1:3000").is_ok());
        assert!(validate_upstream("localhost:8080").is_ok());
        assert!(validate_upstream("unix:/var/run/app.sock").is_ok());
    }

    #[test]
    fn invalid_upstreams() {
        assert!(validate_upstream("").is_err());
        assert!(validate_upstream("127.0.0.1").is_err());
        assert!(validate_upstream("host:notaport").is_err());
        assert!(validate_upstream("unix:").is_err());
    }
}
