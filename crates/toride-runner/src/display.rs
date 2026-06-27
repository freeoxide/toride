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
///    of sensitive arguments, environment variables, and secret-bearing
///    [`CommandSpec::stdin`] content are replaced with `"***"` wherever they
///    appear in stderr. Failed auth/key commands routinely echo a token or
///    passphrase back to stderr even though the caller asked for redaction,
///    so this mirrors the arg-redaction intent on the free-form stderr
///    stream. Only the secret *values* are matched (not flag names), keeping
///    the scrub targeted and low-risk.
///
///    Stdin scrubbing covers the two paths this crate pipes a secret through
///    stdin: `wg pubkey <privkey>` (the raw single-token case) and
///    `wg setconf/syncconf` with a config blob embedding
///    `PrivateKey = <val>` (the `<name> = <val>` assignment case). On
///    failure, `wg` echoes the offending config line verbatim to stderr
///    (`wireguard-tools`: `fprintf(stderr, "Line unrecognized: '%s'\n",
///    line)`), so the raw private key would otherwise reach
///    [`Error::CommandFailed`](crate::error::Error::CommandFailed).stderr.
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
        // sensitive flag, `--flag=value` secret values, environment values
        // whose key matches a redaction pattern, and secret-bearing values
        // carried in stdin (e.g. a WireGuard private key piped to `wg pubkey`
        // or embedded in a `wg setconf`/`wg syncconf` config blob).
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
        if let Some(ref stdin) = spec.stdin {
            collect_stdin_secret_values(stdin, &mut secrets);
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

/// Name substrings (uppercased, matched anywhere in the field name) that mark
/// a `<name> = <value>` assignment in stdin as secret-bearing. Mirrors the
/// intent of [`REDACT_ENV_KEYS`] for the free-form stdin stream (e.g. a
/// `WireGuard` `wg setconf`/`wg syncconf` config blob carrying
/// `PrivateKey = <val>`).
const STDIN_SECRET_NAME_KEYS: &[&str] = &[
    "KEY",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "PASSPHRASE",
    "TOKEN",
];

/// Collect secret values carried in [`CommandSpec::stdin`] into `out`.
///
/// Two shapes are recognized, covering both stdin-secret paths used by this
/// workspace:
///
/// - **`<name> = <value>` assignments** (e.g. a `WireGuard` config blob):
///   any line of the form `<name> = <value>` whose `name` contains one of
///   [`STDIN_SECRET_NAME_KEYS`] (case-insensitive) contributes `<value>`.
///   This catches `PrivateKey = <base64>`, `PresharedKey = <base64>`,
///   `Password = ...`, etc. The value is trimmed of surrounding whitespace.
/// - **Raw single token** (e.g. `wg pubkey <privkey>`): if stdin is a single
///   line that is not a recognized secret assignment, the whole (trimmed)
///   payload is treated as one secret value. A Base64 key ends in padding
///   `=` characters, so mere presence of `=` is not enough to classify a
///   line as an assignment — only a `<name> = <value>` split that yields a
///   secret-bearing name counts. This keeps the private-key-piped-to-`pubkey`
///   case scrubbed.
///
/// Empty values are skipped. Values already present in `out` from other
/// sources are harmless — the scrub loop deduplicates by replacement.
fn collect_stdin_secret_values(stdin: &str, out: &mut Vec<String>) {
    let mut found_assignment = false;

    // Assignment case: scan each line for `<name> = <value>` whose name marks
    // it as secret-bearing (e.g. a WireGuard `PrivateKey = <base64>` line).
    for line in stdin.lines() {
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.is_empty() || value.is_empty() {
            continue;
        }
        found_assignment = true;
        let upper = name.to_uppercase();
        if STDIN_SECRET_NAME_KEYS.iter().any(|k| upper.contains(k)) {
            out.push(value.to_owned());
        }
    }

    // Single-token case: stdin is effectively ONE non-empty line that is not a
    // recognized `<name> = <value>` assignment -> treat it as a secret (the
    // `wg pubkey <privkey>` path). Accept optional trailing newline(s) (a
    // caller piping `echo <key>` adds one) by counting non-empty lines rather
    // than checking for any '\n'. A raw Base64 key's trailing `=` padding
    // doesn't count as an assignment (split_once yields an empty value), so
    // found_assignment stays false; a multi-line config blob has >1 non-empty
    // line (and is handled by the assignment loop above), so it's excluded.
    if !found_assignment {
        let non_empty: Vec<&str> = stdin
            .lines()
            .filter(|l| !l.trim().is_empty())
            .collect();
        if non_empty.len() == 1 {
            out.push(non_empty[0].trim().to_owned());
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

    // -----------------------------------------------------------------
    // Regression: stdin-carried secrets must be scrubbed from stderr.
    //
    // `wireguard-tools` echoes an unrecognized config line verbatim to
    // stderr (`fprintf(stderr, "Line unrecognized: '%s'\n", line)` in the
    // `wg` config parser). When `wg setconf`/`wg syncconf` fail on a blob
    // containing `PrivateKey = <val>`, that raw private key reaches the
    // captured stderr and — without stdin scrubbing — flows into
    // `Error::CommandFailed.stderr`. These tests prove the secret VALUE is
    // absent from the scrubbed output (not merely that `redact == true`).
    // -----------------------------------------------------------------

    /// A `WireGuard` private key is a 32-byte Base64 value (44 chars incl. padding).
    /// This is a synthetic test value, never used for anything secure.
    const WG_TEST_PRIVATE_KEY: &str = "yAnz5TF+lXXJte14tji3zsMNmPaKj7jMEumQzxRjZn4=";

    #[test]
    fn scrub_stderr_redacts_private_key_embedded_in_stdin_config_blob() {
        // Mirrors `wg setconf wg0 /dev/stdin` with a config carrying a private
        // key (toride-wireguard/src/client.rs `setconf_spec`). The spec is
        // built `redact(true)`, promising the secret is scrubbed from errors.
        let config = format!(
            "[Interface]\nPrivateKey = {WG_TEST_PRIVATE_KEY}\nListenPort = 51820\n"
        );
        let spec = CommandSpec::new("wg")
            .args(["setconf", "wg0", "/dev/stdin"])
            .stdin(config)
            .redact(true);

        // `wg` echoing the offending line to stderr on failure — the exact
        // leak vector described in wireguard-tools' config parser.
        let stderr = format!("Line unrecognized: 'PrivateKey = {WG_TEST_PRIVATE_KEY}'\n");

        let scrubbed = scrub_stderr(&spec, &stderr);
        // Non-vacuous: the secret VALUE itself must be gone from the output.
        assert!(
            !scrubbed.contains(WG_TEST_PRIVATE_KEY),
            "private key leaked into scrubbed stderr: {scrubbed}"
        );
        // And replaced with the redaction marker.
        assert!(scrubbed.contains("***"));
        // Non-secret content survives.
        assert!(scrubbed.contains("Line unrecognized"));
    }

    #[test]
    fn scrub_stderr_redacts_raw_single_token_stdin_pubkey_case() {
        // Mirrors `wg pubkey` with the private key piped via stdin
        // (toride-wireguard/src/key.rs `derive_public_key_with`). stdin is a
        // single token with no newline / `=`; the whole payload is the secret.
        let spec = CommandSpec::new("wg")
            .arg("pubkey")
            .stdin(WG_TEST_PRIVATE_KEY)
            .redact(true);

        // A hypothetical stderr that echoes the piped key back.
        let stderr = format!("invalid key: {WG_TEST_PRIVATE_KEY}");

        let scrubbed = scrub_stderr(&spec, &stderr);
        assert!(
            !scrubbed.contains(WG_TEST_PRIVATE_KEY),
            "private key leaked into scrubbed stderr: {scrubbed}"
        );
        assert!(scrubbed.contains("***"));
    }

    #[test]
    fn scrub_stderr_redacts_single_token_stdin_with_trailing_newline() {
        // Regression: a caller piping `echo <key>` (or any single secret with a
        // trailing newline) must still be scrubbed. The single-token branch
        // counts non-empty lines rather than rejecting any '\n', so a lone
        // secret line followed by a newline is still recognized as the secret.
        let stdin = format!("{WG_TEST_PRIVATE_KEY}\n");
        let spec = CommandSpec::new("wg")
            .arg("pubkey")
            .stdin(stdin)
            .redact(true);

        let stderr = format!("invalid key: {WG_TEST_PRIVATE_KEY}");
        let scrubbed = scrub_stderr(&spec, &stderr);
        assert!(
            !scrubbed.contains(WG_TEST_PRIVATE_KEY),
            "private key (trailing-newline stdin) leaked into scrubbed stderr: {scrubbed}"
        );
        assert!(scrubbed.contains("***"));
    }

    #[test]
    fn scrub_stderr_redacts_multiple_secret_assignments_in_stdin() {
        // A config blob carrying more than one secret-bearing line: the
        // PresharedKey is also sensitive and must be scrubbed independently.
        let psk = "SyntaxMPHJq1+DSEyFjQEZcsTQnMkk5dMtHOdPzTQw2c=";
        let config = format!(
            "[Interface]\nPrivateKey = {WG_TEST_PRIVATE_KEY}\n\
             [Peer]\nPresharedKey = {psk}\nAllowedIPs = 10.0.0.2/32\n"
        );
        let spec = CommandSpec::new("wg")
            .args(["syncconf", "wg0", "/dev/stdin"])
            .stdin(config)
            .redact(true);

        let stderr = format!("Line unrecognized: 'PresharedKey = {psk}'\n");

        let scrubbed = scrub_stderr(&spec, &stderr);
        assert!(!scrubbed.contains(psk), "preshared key leaked: {scrubbed}");
        assert!(
            !scrubbed.contains(WG_TEST_PRIVATE_KEY),
            "private key leaked: {scrubbed}"
        );
        assert!(scrubbed.contains("***"));
    }

    #[test]
    fn scrub_stderr_leaves_stdin_secret_when_redact_disabled() {
        // redact=false MUST preserve prior behavior — no stdin scrubbing.
        let config = format!("[Interface]\nPrivateKey = {WG_TEST_PRIVATE_KEY}\n");
        let spec = CommandSpec::new("wg")
            .args(["setconf", "wg0", "/dev/stdin"])
            .stdin(config);
        let stderr = format!("echoed {WG_TEST_PRIVATE_KEY}");
        let scrubbed = scrub_stderr(&spec, &stderr);
        assert!(
            scrubbed.contains(WG_TEST_PRIVATE_KEY),
            "redact=false must not scrub stdin: {scrubbed}"
        );
    }

    #[test]
    fn scrub_stderr_does_not_redact_non_secret_stdin_assignment() {
        // A non-secret `=` assignment (e.g. `ListenPort`) must not be scrubbed
        // even when redact is on — keeps the scrub targeted.
        let config = String::from("[Interface]\nListenPort = 51820\n");
        let spec = CommandSpec::new("wg")
            .args(["setconf", "wg0", "/dev/stdin"])
            .stdin(config)
            .redact(true);
        let stderr = "Line unrecognized: 'ListenPort = 51820'\n";
        let scrubbed = scrub_stderr(&spec, stderr);
        assert!(scrubbed.contains("51820"));
        assert!(!scrubbed.contains("***"));
    }
}
