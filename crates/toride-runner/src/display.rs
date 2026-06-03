//! Redacted command display helpers.
//!
//! These functions produce human-readable strings from a [`CommandSpec`]
//! suitable for logging and diagnostics. Sensitive flag values are replaced
//! with `"***"` — the actual child process arguments are never modified.

use crate::redact::redact_args;
use crate::spec::CommandSpec;

/// Default environment variable key substrings whose values should be redacted.
pub const REDACT_ENV_KEYS: &[&str] = &[
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "API_KEY",
    "APIKEY",
    "PRIVATE_KEY",
    "PASSPHRASE",
];

/// Produce a redacted display string for a command invocation.
///
/// If `spec.redact` is `true`, values after sensitive flags are replaced with
/// `"***"`. The `extra_flags` parameter lets callers add domain-specific flags
/// beyond the default [`REDACT_FLAGS`](crate::redact::REDACT_FLAGS).
///
/// # Examples
///
/// ```rust
/// use toride_runner::CommandSpec;
/// use toride_runner::display::display_command;
///
/// let spec = CommandSpec::new("curl")
///     .args(["--token", "secret123", "https://example.com"])
///     .redact(true);
///
/// let displayed = display_command(&spec, &[]);
/// assert!(displayed.contains("***"));
/// assert!(!displayed.contains("secret123"));
/// ```
pub fn display_command(spec: &CommandSpec, extra_flags: &[&str]) -> String {
    let mut parts = Vec::with_capacity(1 + spec.args.len());

    parts.push(spec.program.clone());

    let args = if spec.redact {
        let mut flags: Vec<&str> = crate::redact::REDACT_FLAGS.to_vec();
        flags.extend_from_slice(extra_flags);
        redact_args(&spec.args, &flags)
    } else {
        spec.args.clone()
    };

    parts.extend(args);

    let mut out = parts.join(" ");

    if let Some(ref cwd) = spec.cwd {
        out = format!("(cwd: {}) {}", cwd.display(), out);
    }

    out
}

/// Produce a redacted view of the environment variables for display.
///
/// Values whose keys contain any substring from `keys` (defaulting to
/// [`REDACT_ENV_KEYS`]) are replaced with `"***"`.
///
/// # Examples
///
/// ```rust
/// use toride_runner::CommandSpec;
/// use toride_runner::display::display_env;
///
/// let spec = CommandSpec::new("cmd")
///     .env("MY_TOKEN", "secret")
///     .env("PATH", "/usr/bin");
///
/// let env = display_env(&spec, &[]);
/// assert_eq!(env[0], ("MY_TOKEN".into(), "***".into()));
/// assert_eq!(env[1], ("PATH".into(), "/usr/bin".into()));
/// ```
pub fn display_env(spec: &CommandSpec, keys: &[&str]) -> Vec<(String, String)> {
    let match_keys = if keys.is_empty() {
        REDACT_ENV_KEYS.to_vec()
    } else {
        keys.to_vec()
    };

    spec.env
        .iter()
        .map(|(k, v)| {
            let should_redact = match_keys
                .iter()
                .any(|pattern| k.to_uppercase().contains(pattern));
            if should_redact {
                (k.clone(), "***".to_owned())
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CommandSpec;

    #[test]
    fn display_no_redaction_when_disabled() {
        let spec = CommandSpec::new("curl")
            .args(["--token", "secret123"])
            .redact(false);
        let displayed = display_command(&spec, &[]);
        assert!(displayed.contains("secret123"));
        assert!(!displayed.contains("***"));
    }

    #[test]
    fn display_redacts_when_enabled() {
        let spec = CommandSpec::new("curl")
            .args(["--token", "secret123", "https://example.com"])
            .redact(true);
        let displayed = display_command(&spec, &[]);
        assert!(displayed.contains("***"));
        assert!(!displayed.contains("secret123"));
        assert!(displayed.contains("https://example.com"));
    }

    #[test]
    fn display_shows_cwd() {
        let spec = CommandSpec::new("make").cwd("/project");
        let displayed = display_command(&spec, &[]);
        assert!(displayed.contains("(cwd: /project)"));
    }

    #[test]
    fn display_env_redacts_token() {
        let spec = CommandSpec::new("cmd")
            .env("API_TOKEN", "secret")
            .env("VERBOSE", "1");
        let env = display_env(&spec, &[]);
        assert_eq!(env[0].1, "***");
        assert_eq!(env[1].1, "1");
    }

    #[test]
    fn display_env_custom_keys() {
        let spec = CommandSpec::new("cmd").env("X_SPECIAL", "hidden");
        let env = display_env(&spec, &["SPECIAL"]);
        assert_eq!(env[0].1, "***");
    }
}
