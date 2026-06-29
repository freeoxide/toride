//! Argument redaction for sensitive command-line flags.
//!
//! When logging or displaying command invocations, values after sensitive
//! flags (passwords, tokens, keys) should be replaced with `"***"`.

/// Common command-line flags whose values should be redacted.
///
/// This list contains only long-form flags to avoid ambiguity. Short flags
/// like `-p` (port, protocol, PID) and `-k` (KRL generation) mean different
/// things across tools and would cause false-positive redaction. Domain crates
/// should add their own short flags via the `flags` parameter to
/// [`redact_args`] when they know the context.
pub const REDACT_FLAGS: &[&str] = &[
    "--password",
    "--passwd",
    "--token",
    "--access-token",
    "--api-key",
    "--apikey",
    "--secret",
    "--key",
    "--private-key",
    "--ssh-key",
    "--passphrase",
    "--password-command",
    "--email",
];

/// Redact sensitive values from a list of command arguments.
///
/// Any argument that appears in `flags` causes the *next* argument to be
/// replaced with `"***"`. Flag-value pairs joined by `=` (e.g.
/// `--password=secret`) are also redacted.
///
/// # Examples
///
/// ```rust
/// use toride_runner::redact::{redact_args, REDACT_FLAGS};
///
/// let args: Vec<String> = vec![
///     "program".into(),
///     "--password".into(),
///     "hunter2".into(),
///     "--verbose".into(),
/// ];
/// let redacted = redact_args(&args, REDACT_FLAGS);
/// assert_eq!(redacted[2], "***");
/// ```
pub fn redact_args(args: &[String], flags: &[&str]) -> Vec<String> {
    let mut result = Vec::with_capacity(args.len());
    let mut redact_next = false;

    for arg in args {
        if redact_next {
            result.push("***".to_owned());
            redact_next = false;
            continue;
        }

        // Check for `--flag=value` form.
        let mut handled = false;
        for flag in flags {
            if let Some(value) = arg.strip_prefix(&format!("{flag}="))
                && !value.is_empty()
            {
                result.push(format!("{flag}=***"));
                handled = true;
                break;
            }
        }
        if handled {
            continue;
        }

        // Check if this arg is a sensitive flag (next arg gets redacted).
        if flags.contains(&arg.as_str()) {
            redact_next = true;
        }

        result.push(arg.clone());
    }

    // If the last argument was a flag requiring redaction but there was no
    // value after it, just keep the flag.
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_simple_flag_value() {
        let args: Vec<String> = vec![
            "cmd".into(),
            "--password".into(),
            "secret".into(),
            "ok".into(),
        ];
        let result = redact_args(&args, REDACT_FLAGS);
        assert_eq!(result[2], "***");
        assert_eq!(result[3], "ok");
    }

    #[test]
    fn redact_equals_form() {
        let args: Vec<String> = vec!["cmd".into(), "--token=abc123".into()];
        let result = redact_args(&args, REDACT_FLAGS);
        assert_eq!(result[1], "--token=***");
    }

    #[test]
    fn no_redaction_needed() {
        let args: Vec<String> = vec!["echo".into(), "hello".into()];
        let result = redact_args(&args, REDACT_FLAGS);
        assert_eq!(result, args);
    }

    /// Regression: provider/PII secret flags MUST be in `REDACT_FLAGS`.
    /// `--access-token`, `--email`, and `--password-command` were previously
    /// missing, so e.g. `doctl --access-token <token>.redact(true)` silently
    /// leaked the token into logs/errors despite the redact flag.
    #[test]
    fn redact_provider_specific_secret_flags() {
        // doctl --access-token <token>
        let args: Vec<String> = vec![
            "doctl".into(),
            "--access-token".into(),
            "tok-abc".into(),
            "compute".into(),
            "firewall".into(),
            "list".into(),
        ];
        let result = redact_args(&args, REDACT_FLAGS);
        assert_eq!(
            result[2], "***",
            "doctl --access-token value must be redacted"
        );
        assert_eq!(result[4], "firewall", "non-secret args preserved");

        // certbot --email <email> (PII)
        let email_args: Vec<String> = vec![
            "certbot".into(),
            "--email".into(),
            "webmaster@example.com".into(),
        ];
        let email_result = redact_args(&email_args, REDACT_FLAGS);
        assert_eq!(
            email_result[2], "***",
            "certbot --email (PII) must be redacted"
        );

        // restic/borg --password-command <cmd>
        let pw_cmd_args: Vec<String> = vec![
            "restic".into(),
            "--password-command".into(),
            "cat /etc/restic/key".into(),
        ];
        let pw_cmd_result = redact_args(&pw_cmd_args, REDACT_FLAGS);
        assert_eq!(
            pw_cmd_result[2], "***",
            "--password-command value must be redacted"
        );
    }
}
