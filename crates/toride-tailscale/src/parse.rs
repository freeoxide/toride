//! Parsing utilities for Tailscale CLI output.
//!
//! Provides functions for parsing the output of `tailscale status` and
//! related commands into structured types.

use crate::Result;

// ---------------------------------------------------------------------------
// Public parse functions
// ---------------------------------------------------------------------------

/// Parse the output of `tailscale status --json` into a connection status
/// string.
///
/// The raw JSON output from `tailscale status` is complex; this function
/// extracts just the backend state field.
///
/// # Arguments
///
/// * `output` - The raw JSON output from `tailscale status --json`.
///
/// # Errors
///
/// Returns an error if the output is not valid JSON or does not contain the
/// expected fields.
pub fn parse_tailscale_status(output: &str) -> Result<String> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return Err(crate::Error::Other(
            "empty output from tailscale status".to_owned(),
        ));
    }

    // Attempt to parse as JSON and extract BackendState.
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed)
        && let Some(state) = val.get("BackendState").and_then(|v| v.as_str())
    {
        return Ok(state.to_owned());
    }

    // Fallback: return trimmed output as-is for non-JSON responses.
    Ok(trimmed.to_owned())
}

/// Parse a Tailscale IP address from `tailscale ip` output.
///
/// # Arguments
///
/// * `output` - The raw output from `tailscale ip`.
///
/// # Errors
///
/// Returns an error if the output does not contain a valid IP address.
pub fn parse_tailscale_ip(output: &str) -> Result<String> {
    let trimmed = output.trim();

    if trimmed.is_empty() {
        return Err(crate::Error::Other(
            "empty output from tailscale ip".to_owned(),
        ));
    }

    // Take the first line as the IP address.
    let ip = trimmed.lines().next().unwrap_or(trimmed);

    // Basic validation: must contain only digits, dots, colons, or hex chars.
    let valid = ip
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == ':');
    if !valid {
        return Err(crate::Error::Other(format!(
            "invalid Tailscale IP address: {ip}"
        )));
    }

    Ok(ip.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_status_extracts_backend_state() {
        let json = r#"{"BackendState": "Running", "Version": "1.50.0"}"#;
        let state = parse_tailscale_status(json).unwrap();
        assert_eq!(state, "Running");
    }

    #[test]
    fn parse_status_empty_output_errors() {
        let result = parse_tailscale_status("");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ip_extracts_first_address() {
        let output = "100.64.0.1\n";
        let ip = parse_tailscale_ip(output).unwrap();
        assert_eq!(ip, "100.64.0.1");
    }

    #[test]
    fn parse_ip_empty_output_errors() {
        let result = parse_tailscale_ip("");
        assert!(result.is_err());
    }
}
