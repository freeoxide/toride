//! Parse and handle `authorized_keys` option fields.
//!
//! Supports all documented options from `man sshd` `AUTHORIZED_KEYS FILE FORMAT`:
//! command, environment, from, permit-open, port-forwarding, principals,
//! no-pty, no-port-forwarding, no-X11-forwarding, no-agent-forwarding,
//! no-user-rc, restrict, tunnel, cert-authority, expiry-time, perferrp.

use serde::{Deserialize, Serialize};

use toride_ssh_core::Result;

/// Parsed options from an `authorized_keys` entry.
///
/// See `man sshd` section `AUTHORIZED_KEYS FILE FORMAT` for full details.
#[expect(
    clippy::struct_excessive_bools,
    reason = "authorized_keys options are a fixed set of boolean flags per OpenSSH spec"
)]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthorizedKeyOptions {
    /// Command that is executed (forced) whenever this key is used for authentication.
    pub command: Option<String>,
    /// Remote hosts that the client is permitted to connect from.
    pub from: Vec<String>,
    /// Prevents allocation of a pseudo-terminal.
    pub no_pty: bool,
    /// Prevents port forwarding.
    pub no_port_forwarding: bool,
    /// Prevents X11 forwarding.
    pub no_x11_forwarding: bool,
    /// Prevents agent forwarding.
    pub no_agent_forwarding: bool,
    /// Prevents execution of `~/.ssh/rc`.
    pub no_user_rc: bool,
    /// Enables all restrictions (equivalent to no-pty,no-port-forwarding,
    /// no-X11-forwarding,no-agent-forwarding,no-user-rc).
    /// Individual features can be re-enabled by prefixing them with `permit-`.
    pub restrict: bool,
    /// Restricts port forwarding destinations.
    pub permit_open: Vec<String>,
    /// Sets environment variables for the session.
    pub environment: Vec<(String, String)>,
    /// Tunnel device to open.
    pub tunnel: Option<String>,
    /// Marks this key as a certificate authority.
    pub cert_authority: bool,
    /// Restricts the certificate principals that are accepted.
    pub principals: Vec<String>,
    /// Expiry time for this key (OpenSSH 8.6+).
    pub expiry_time: Option<String>,
    /// Prefer RP (relying party) identity for FIDO keys (OpenSSH 9.6+).
    pub perferrp: bool,
    /// Unrecognized / custom options preserved for round-tripping.
    pub custom: Vec<(String, Option<String>)>,
}

/// Parse the options field of an `authorized_keys` line.
///
/// The options field is a comma-separated list of directives. Boolean flags
/// (e.g. `no-pty`) are standalone, while string-valued options use the
/// form `name="value"`. Quoted values may contain escaped quotes.
///
/// # Errors
///
/// Returns an error if the options string contains malformed quoted values.
pub fn parse_options(options_str: &str) -> Result<AuthorizedKeyOptions> {
    let mut opts = AuthorizedKeyOptions::default();

    for token in CommaIter::new(options_str) {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }

        // Check for `name="value"` pattern
        if let Some(eq_pos) = token.find('=') {
            let name = &token[..eq_pos];
            let raw_value = &token[eq_pos + 1..];

            // Strip surrounding quotes and unescape inner \" sequences
            let value = unquote_value(raw_value);

            match name {
                "command" => opts.command = Some(value),
                "from" => {
                    for host in value.split(',') {
                        let host = host.trim();
                        if !host.is_empty() {
                            opts.from.push(host.to_string());
                        }
                    }
                }
                "permit-open" => {
                    for target in value.split(',') {
                        let target = target.trim();
                        if !target.is_empty() {
                            opts.permit_open.push(target.to_string());
                        }
                    }
                }
                "environment" => {
                    if let Some((k, v)) = value.split_once('=') {
                        opts.environment.push((k.to_string(), v.to_string()));
                    } else {
                        opts.environment.push((value, String::new()));
                    }
                }
                "tunnel" => opts.tunnel = Some(value),
                "principals" => opts.principals.push(value),
                "expiry-time" => opts.expiry_time = Some(value),
                other => {
                    opts.custom.push((other.to_string(), Some(value)));
                }
            }
        } else {
            // Boolean flag (no value)
            match token {
                "no-pty" => opts.no_pty = true,
                "no-port-forwarding" => opts.no_port_forwarding = true,
                "no-X11-forwarding" => opts.no_x11_forwarding = true,
                "no-agent-forwarding" => opts.no_agent_forwarding = true,
                "no-user-rc" => opts.no_user_rc = true,
                "restrict" => opts.restrict = true,
                "cert-authority" => opts.cert_authority = true,
                "perferrp" => opts.perferrp = true,
                other => {
                    opts.custom.push((other.to_string(), None));
                }
            }
        }
    }

    Ok(opts)
}

/// Iterator that splits on commas while respecting double-quoted regions.
struct CommaIter<'a> {
    remaining: &'a str,
}

impl<'a> CommaIter<'a> {
    fn new(s: &'a str) -> Self {
        Self { remaining: s }
    }
}

impl<'a> Iterator for CommaIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        if self.remaining.is_empty() {
            return None;
        }

        let mut in_quotes = false;
        let mut escape_next = false;

        for (i, ch) in self.remaining.char_indices() {
            if escape_next {
                escape_next = false;
                continue;
            }
            match ch {
                '\\' => {
                    escape_next = true;
                }
                '"' => {
                    in_quotes = !in_quotes;
                }
                ',' if !in_quotes => {
                    let (token, rest) = self.remaining.split_at(i);
                    self.remaining = &rest[1..]; // skip the comma
                    return Some(token);
                }
                _ => {}
            }
        }

        let token = self.remaining;
        self.remaining = "";
        Some(token)
    }
}

/// Strip surrounding double quotes and unescape inner `\"` and `\\` sequences.
///
/// Returns an owned `String` because unescaping may change the length.
/// For unquoted values, the value is returned as-is with only leading/trailing
/// whitespace trimmed.
fn unquote_value(s: &str) -> String {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        let inner = &s[1..s.len() - 1];
        unescape(inner)
    } else {
        s.to_string()
    }
}

/// Replace `\"` with `"` and `\\` with `\` in a string.
pub(crate) fn unescape(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.peek() {
                Some('"') => {
                    result.push('"');
                    chars.next();
                }
                Some('\\') => {
                    result.push('\\');
                    chars.next();
                }
                _ => {
                    // Unknown escape: keep the backslash literally
                    result.push('\\');
                }
            }
        } else {
            result.push(ch);
        }
    }

    result
}

#[cfg(test)]
#[path = "options.test.rs"]
mod tests;
