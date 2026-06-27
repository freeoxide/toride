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
    "PASSCOMMAND",
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

/// Produce a redacted display string for a spec's arguments, suitable for
/// embedding in error variants and log messages.
///
/// This is the canonical redaction entry point used by every error/log site in
/// the crate so that `CommandFailed`, `CommandTimeout`, and
/// `OutputLimitExceeded` all agree on what reaches the caller. When
/// `spec.redact` is `true`, the full [`display_command`] output is returned
/// (program + redacted args + cwd, matching the historical behavior of the
/// `CommandFailed` path); otherwise the raw args are joined with spaces.
///
/// # Examples
///
/// ```rust
/// use toride_runner::CommandSpec;
/// use toride_runner::display::redacted_args_display;
///
/// let spec = CommandSpec::new("curl")
///     .args(["--token", "secret123", "https://example.com"])
///     .redact(true);
///
/// let displayed = redacted_args_display(&spec);
/// assert!(displayed.contains("***"));
/// assert!(!displayed.contains("secret123"));
/// ```
pub fn redacted_args_display(spec: &CommandSpec) -> String {
    if spec.redact {
        display_command(spec, &[])
    } else {
        spec.args.join(" ")
    }
}

/// Produce a redacted view of a spec's arguments as a `Vec<String>`, honoring
/// `spec.redact`.
///
/// Use this when an error variant must store arguments as a sequence (e.g.
/// [`Error::CommandTimeout`](crate::error::Error::CommandTimeout)) rather than
/// as a pre-joined display string. When `spec.redact` is `false`, the args are
/// returned unchanged. When it is `true`, values after sensitive flags are
/// replaced with `"***"` (using the default
/// [`REDACT_FLAGS`](crate::redact::REDACT_FLAGS)).
pub fn redacted_args_vec(spec: &CommandSpec) -> Vec<String> {
    if spec.redact {
        redact_args(&spec.args, crate::redact::REDACT_FLAGS)
    } else {
        spec.args.clone()
    }
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

/// Maximum number of stderr bytes retained in error variants.
///
/// Failed commands can emit arbitrarily large (or even unbounded) stderr.
/// Capping it bounds the size of [`Error::CommandFailed`](crate::error::Error::CommandFailed)
/// values and limits the surface area for accidental secret exposure when a
/// command echoes a token or passphrase to stderr.
pub const STDERR_CAP_BYTES: usize = 4 * 1024;

/// Truncation marker appended when stderr exceeds [`STDERR_CAP_BYTES`].
pub const STDERR_TRUNCATION_MARKER: &str = "...[stderr truncated]";

/// Scrub captured stderr for inclusion in an error variant.
///
/// Two policies apply, in order:
///
/// 1. **Value scrubbing** (only when `spec.redact` is `true`): the *values*
///    of sensitive arguments and environment variables are replaced with
///    `"***"` wherever they appear in stderr. Failed auth/key commands
///    routinely echo a token or passphrase back to stderr even though the
///    caller asked for redaction, so this mirrors the arg-redaction intent on
///    the free-form stderr stream. Only the secret *values* are matched (not
///    flag names), keeping the scrub targeted and low-risk.
/// 2. **Length cap** (always): stderr is truncated to [`STDERR_CAP_BYTES`]
///    bytes on a character boundary, with [`STDERR_TRUNCATION_MARKER`]
///    appended, bounding error size regardless of the redact setting.
///
/// # Examples
///
/// ```rust
/// use toride_runner::CommandSpec;
/// use toride_runner::display::scrub_stderr;
///
/// let spec = CommandSpec::new("curl")
///     .args(["--token", "hunter2"])
///     .redact(true);
///
/// let scrubbed = scrub_stderr(&spec, "auth failed for hunter2");
/// assert!(!scrubbed.contains("hunter2"));
/// assert!(scrubbed.contains("***"));
/// ```
pub fn scrub_stderr(spec: &CommandSpec, stderr: &str) -> String {
    let mut scrubbed = stderr.to_owned();

    if spec.redact {
        // Collect the secret values to scrub: argument values following a
        // sensitive flag, `--flag=value` secret values, and environment values
        // whose key matches a redaction pattern.
        let mut secrets: Vec<String> = Vec::new();
        collect_arg_secret_values(&spec.args, &mut secrets);
        for (key, value) in &spec.env {
            if REDACT_ENV_KEYS
                .iter()
                .any(|pattern| key.to_uppercase().contains(pattern))
            {
                secrets.push(value.clone());
            }
        }

        // Longest-first so a longer secret shadows a shorter prefix overlap.
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        for secret in secrets {
            if !secret.is_empty() {
                scrubbed = scrubbed.replace(&secret, "***");
            }
        }
    }

    cap_stderr(&scrubbed)
}

/// Collect the *value* tokens that follow a sensitive flag, plus the value
/// half of `--flag=value` pairs, into `out`. Mirrors the matching logic of
/// [`redact_args`](crate::redact::redact_args) but returns the secrets rather
/// than the redacted form.
fn collect_arg_secret_values(args: &[String], out: &mut Vec<String>) {
    let mut redact_next = false;
    for arg in args {
        if redact_next {
            out.push(arg.clone());
            redact_next = false;
            continue;
        }
        let mut handled = false;
        for flag in crate::redact::REDACT_FLAGS {
            if let Some(value) = arg.strip_prefix(&format!("{flag}=")) {
                if !value.is_empty() {
                    out.push(value.to_owned());
                }
                handled = true;
                break;
            }
        }
        if handled {
            continue;
        }
        if crate::redact::REDACT_FLAGS.contains(&arg.as_str()) {
            redact_next = true;
        }
    }
}

/// Truncate `stderr` to [`STDERR_CAP_BYTES`] on a `char` boundary, appending
/// [`STDERR_TRUNCATION_MARKER`] when truncation occurs.
fn cap_stderr(stderr: &str) -> String {
    if stderr.len() <= STDERR_CAP_BYTES {
        return stderr.to_owned();
    }

    // Find the largest char boundary at or below the cap so we never split a
    // multi-byte UTF-8 sequence (which would panic on String construction).
    let mut boundary = STDERR_CAP_BYTES;
    while boundary > 0 && !stderr.is_char_boundary(boundary) {
        boundary -= 1;
    }
    let mut truncated = String::with_capacity(boundary + STDERR_TRUNCATION_MARKER.len());
    truncated.push_str(&stderr[..boundary]);
    truncated.push_str(STDERR_TRUNCATION_MARKER);
    truncated
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

    #[test]
    fn redacted_args_display_preserves_args_when_redact_disabled() {
        let spec = CommandSpec::new("curl").args(["--token", "secret"]);
        assert_eq!(redacted_args_display(&spec), "--token secret");
    }

    #[test]
    fn redacted_args_display_redacts_when_enabled() {
        let spec = CommandSpec::new("curl")
            .args(["--token", "secret"])
            .redact(true);
        let displayed = redacted_args_display(&spec);
        assert!(displayed.contains("***"));
        assert!(!displayed.contains("secret"));
    }

    #[test]
    fn redacted_args_vec_preserves_args_when_redact_disabled() {
        let spec = CommandSpec::new("curl").args(["--token", "secret"]);
        assert_eq!(redacted_args_vec(&spec), vec!["--token", "secret"]);
    }

    #[test]
    fn redacted_args_vec_redacts_when_enabled() {
        let spec = CommandSpec::new("curl")
            .args(["--token", "secret", "url"])
            .redact(true);
        assert_eq!(
            redacted_args_vec(&spec),
            vec!["--token", "***", "url"]
        );
    }

    #[test]
    fn scrub_stderr_redacts_secret_arg_values_when_enabled() {
        let spec = CommandSpec::new("curl")
            .args(["--token", "hunter2"])
            .redact(true);
        let scrubbed = scrub_stderr(&spec, "auth failed for hunter2");
        assert!(!scrubbed.contains("hunter2"));
        assert!(scrubbed.contains("***"));
    }

    #[test]
    fn scrub_stderr_redacts_equals_form_secret() {
        let spec = CommandSpec::new("curl")
            .args(["--token=abc123"])
            .redact(true);
        let scrubbed = scrub_stderr(&spec, "rejected abc123");
        assert!(!scrubbed.contains("abc123"));
        assert!(scrubbed.contains("***"));
    }

    #[test]
    fn scrub_stderr_redacts_sensitive_env_values_when_enabled() {
        let spec = CommandSpec::new("cmd")
            .env("API_TOKEN", "env-secret")
            .redact(true);
        let scrubbed = scrub_stderr(&spec, "echoed env-secret here");
        assert!(!scrubbed.contains("env-secret"));
        assert!(scrubbed.contains("***"));
    }

    #[test]
    fn scrub_stderr_does_not_redact_when_redact_disabled() {
        let spec = CommandSpec::new("curl").args(["--token", "hunter2"]);
        // redact defaults to false, so the secret survives (only the length
        // cap applies).
        let scrubbed = scrub_stderr(&spec, "auth failed for hunter2");
        assert!(scrubbed.contains("hunter2"));
    }

    #[test]
    fn scrub_stderr_caps_oversized_output() {
        let spec = CommandSpec::new("cmd");
        let big = "x".repeat(STDERR_CAP_BYTES + 1000);
        let scrubbed = scrub_stderr(&spec, &big);
        assert!(scrubbed.len() < big.len());
        assert!(scrubbed.ends_with(STDERR_TRUNCATION_MARKER));
        // Never exceeds the cap by more than the marker length.
        assert!(scrubbed.len() <= STDERR_CAP_BYTES + STDERR_TRUNCATION_MARKER.len());
    }

    #[test]
    fn scrub_stderr_preserves_short_output() {
        let spec = CommandSpec::new("cmd");
        let stderr = "a short error";
        assert_eq!(scrub_stderr(&spec, stderr), stderr);
    }

    #[test]
    fn scrub_stderr_caps_on_char_boundary() {
        // A multi-byte sequence straddling the cap must not panic and must
        // produce valid UTF-8.
        let spec = CommandSpec::new("cmd");
        let mut stderr = String::from("x").repeat(STDERR_CAP_BYTES - 1);
        stderr.push('🦀'); // 4-byte char starting at the cap boundary
        stderr.push_str("tail");
        let scrubbed = scrub_stderr(&spec, &stderr);
        assert!(scrubbed.ends_with(STDERR_TRUNCATION_MARKER));
    }
}
