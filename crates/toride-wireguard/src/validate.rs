//! Input validation for WireGuard configuration values.
//!
//! Provides validators for interface names, IP addresses, allowed-ips lists,
//! and port numbers. These are used by both the config subsystem and the
//! doctor module.

use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// validate_interface_name
// ---------------------------------------------------------------------------

/// Validate a WireGuard interface name.
///
/// Valid names:
/// - Start with `wg` followed by a digit (e.g. `wg0`, `wg1`, `wg99`).
/// - Are at most 15 characters (Linux `IFNAMSIZ` limit).
///
/// # Errors
///
/// Returns [`Error::InvalidAddress`] if the name does not match the pattern.
pub fn validate_interface_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidAddress(
            "interface name must not be empty".to_owned(),
        ));
    }
    if name.len() > 15 {
        return Err(Error::InvalidAddress(format!(
            "interface name too long ({} chars, max 15): {name}",
            name.len()
        )));
    }
    if !name.starts_with("wg") {
        return Err(Error::InvalidAddress(format!(
            "interface name must start with 'wg': {name}"
        )));
    }
    // The part after "wg" must be digits.
    let suffix = &name[2..];
    if suffix.is_empty() || !suffix.chars().all(|c| c.is_ascii_digit()) {
        return Err(Error::InvalidAddress(format!(
            "interface name must be 'wg' followed by digits: {name}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// validate_address
// ---------------------------------------------------------------------------

/// Validate a single IP address or CIDR notation.
///
/// Accepts both IPv4 (e.g. `10.0.0.1/24`) and IPv6 (e.g. `fd00::1/64`).
///
/// # Errors
///
/// Returns [`Error::InvalidAddress`] if the address is malformed.
pub fn validate_address(addr: &str) -> Result<()> {
    // Basic structure check: must contain an IP, optionally followed by /prefix.
    let ip_part = addr.split('/').next().unwrap_or(addr);
    if ip_part.parse::<std::net::IpAddr>().is_err() {
        return Err(Error::InvalidAddress(format!("invalid IP address: {addr}")));
    }

    // If there's a prefix, validate it.
    if let Some(prefix_str) = addr.split('/').nth(1) {
        let prefix: u8 = prefix_str
            .parse()
            .map_err(|_| Error::InvalidAddress(format!("invalid CIDR prefix: {addr}")))?;
        let max_prefix = if addr.contains(':') { 128 } else { 32 };
        if prefix > max_prefix {
            return Err(Error::InvalidAddress(format!(
                "CIDR prefix {prefix} exceeds maximum {max_prefix}: {addr}"
            )));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// validate_allowed_ips
// ---------------------------------------------------------------------------

/// Validate a list of allowed-ips entries.
///
/// Each entry must be a valid IP address or CIDR range. The list may be
/// provided as comma-separated string or as a slice.
///
/// # Errors
///
/// Returns [`Error::InvalidAddress`] if any entry is invalid.
pub fn validate_allowed_ips(ips: &[String]) -> Result<()> {
    for ip in ips {
        validate_address(ip)?;
    }
    Ok(())
}

/// Validate a comma-separated allowed-ips string (e.g. `"10.0.0.2/32, fd00::2/128"`).
///
/// # Errors
///
/// Returns [`Error::InvalidAddress`] if any entry is invalid.
pub fn validate_allowed_ips_str(ips: &str) -> Result<()> {
    let parsed: Vec<String> = ips.split(',').map(|s| s.trim().to_owned()).collect();
    validate_allowed_ips(&parsed)
}

// ---------------------------------------------------------------------------
// validate_endpoint
// ---------------------------------------------------------------------------

/// Validate a peer endpoint as a `host:port` socket address.
///
/// Accepts both IPv4 (e.g. `1.2.3.4:51820`) and IPv6 (e.g. `[fd00::1]:51820`)
/// socket addresses, matching what the `wg` tool expects for the `endpoint`
/// argument. Hostnames are not accepted here because `wg set` itself only
/// resolves them at apply time and a syntactic check cannot prove validity.
///
/// # Errors
///
/// Returns [`Error::InvalidAddress`] if the value is not a parseable socket
/// address.
pub fn validate_endpoint(endpoint: &str) -> Result<()> {
    if endpoint.parse::<std::net::SocketAddr>().is_err() {
        return Err(Error::InvalidAddress(format!(
            "invalid endpoint (expected host:port): {endpoint}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// validate_port
// ---------------------------------------------------------------------------

/// Validate a UDP port number for WireGuard.
///
/// Valid ports are in the range `1..=65535` (port 0 means "auto-assign" and
/// is accepted). Because `u16` already bounds the value to `0..=65535`, this
/// function always succeeds; it is retained for API symmetry with the other
/// validators and so callers can rely on a consistent validation surface.
///
/// # Errors
///
/// Never returns an error -- the `u16` type enforces the documented range at
/// the type level. (Kept as a `Result` for forward compatibility.)
pub fn validate_port(port: u16) -> Result<()> {
    // Port 0 is allowed (kernel auto-assign). The u16 type already bounds
    // the value to 0..=65535, matching the documented contract, so there is
    // nothing to reject here.
    let _ = port;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_interface_names() {
        assert!(validate_interface_name("wg0").is_ok());
        assert!(validate_interface_name("wg1").is_ok());
        assert!(validate_interface_name("wg99").is_ok());
    }

    #[test]
    fn invalid_interface_names() {
        assert!(validate_interface_name("").is_err());
        assert!(validate_interface_name("eth0").is_err());
        assert!(validate_interface_name("wg").is_err());
        assert!(validate_interface_name("wgabc").is_err());
        assert!(validate_interface_name("wg-1").is_err());
    }

    #[test]
    fn valid_addresses() {
        assert!(validate_address("10.0.0.1/24").is_ok());
        assert!(validate_address("192.168.1.1").is_ok());
        assert!(validate_address("fd00::1/64").is_ok());
        assert!(validate_address("::1").is_ok());
    }

    #[test]
    fn invalid_addresses() {
        assert!(validate_address("999.999.999.999").is_err());
        assert!(validate_address("not-an-ip").is_err());
        assert!(validate_address("10.0.0.1/33").is_err());
    }

    #[test]
    fn valid_allowed_ips() {
        assert!(validate_allowed_ips_str("10.0.0.2/32").is_ok());
        assert!(validate_allowed_ips_str("10.0.0.2/32, fd00::2/128").is_ok());
    }

    #[test]
    fn valid_ports() {
        assert!(validate_port(0).is_ok());
        assert!(validate_port(51820).is_ok());
        assert!(validate_port(65535).is_ok());
    }

    #[test]
    fn valid_endpoints() {
        assert!(validate_endpoint("1.2.3.4:51820").is_ok());
        assert!(validate_endpoint("[fd00::1]:51820").is_ok());
        assert!(validate_endpoint("0.0.0.0:0").is_ok());
    }

    #[test]
    fn invalid_endpoints() {
        assert!(validate_endpoint("1.2.3.4").is_err()); // no port
        assert!(validate_endpoint(":51820").is_err()); // no host
        assert!(validate_endpoint("not-an-endpoint").is_err());
        assert!(validate_endpoint("1.2.3.4:99999").is_err()); // port out of range
    }
}
