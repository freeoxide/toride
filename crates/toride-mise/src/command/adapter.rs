//! Command adapter — builds [`CommandSpec`] and parses mise output.
//!
//! This module is the single place that knows how to translate mise-specific
//! options into a [`toride_runner::CommandSpec`] and how to deserialise the
//! JSON that mise prints on stdout.

use std::path::Path;
use std::time::Duration;

use toride_runner::CommandSpec;

use crate::error::MiseError;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// build_spec
// ---------------------------------------------------------------------------

/// Construct a [`CommandSpec`] for a mise invocation.
///
/// All parameters are optional apart from `binary` (the path or name of the
/// mise executable). The function is a thin convenience wrapper around the
/// [`CommandSpec`] builder methods so callers do not have to depend on
/// `toride_runner` directly.
///
/// # Arguments
///
/// * `binary`   — Path to or name of the mise binary.
/// * `args`     — Positional arguments (e.g. `["ls", "--json"]`).
/// * `cwd`      — Working directory override (`None` = inherit).
/// * `env`      — Extra environment variable pairs.
/// * `timeout`  - Wall-clock timeout for the command.
/// * `redact`   — Whether to redact sensitive arguments in display output.
pub fn build_spec(
    binary: &str,
    args: &[String],
    cwd: Option<&Path>,
    env: &[(String, String)],
    timeout: Option<Duration>,
    redact: bool,
) -> CommandSpec {
    let mut spec = CommandSpec::new(binary).args(args.to_vec()).redact(redact);

    if let Some(dir) = cwd {
        spec = spec.cwd(dir);
    }

    spec = spec.envs(env.to_vec());

    if let Some(dur) = timeout {
        spec = spec.timeout(dur);
    }

    spec
}

// ---------------------------------------------------------------------------
// build_mise_args
// ---------------------------------------------------------------------------

/// Append common mise global flags to a base argument list.
///
/// The returned `Vec<String>` is suitable for passing to [`build_spec`] as the
/// `args` parameter.
///
/// # Arguments
///
/// * `base_args` — The sub-command and its own flags (e.g. `["ls"]`).
/// * `json`      — Append `--output=json` (or `--json` for short).
/// * `no_config` — Append `--no-config`.
/// * `no_env`    — Append `--no-env`.
/// * `no_hooks`  — Append `--no-hooks`.
/// * `locked`    — Append `--locked`.
#[allow(clippy::fn_params_excessive_bools)]
pub fn build_mise_args(
    base_args: &[&str],
    json: bool,
    no_config: bool,
    no_env: bool,
    no_hooks: bool,
    locked: bool,
) -> Vec<String> {
    let mut out: Vec<String> = base_args.iter().map(|s| (*s).to_owned()).collect();

    if json {
        out.push("--output=json".to_owned());
    }
    if no_config {
        out.push("--no-config".to_owned());
    }
    if no_env {
        out.push("--no-env".to_owned());
    }
    if no_hooks {
        out.push("--no-hooks".to_owned());
    }
    if locked {
        out.push("--locked".to_owned());
    }

    out
}

// ---------------------------------------------------------------------------
// parse_json_output
// ---------------------------------------------------------------------------

/// Deserialise the JSON that mise wrote to stdout.
///
/// `command` is used exclusively for error messages — it is the human-readable
/// representation of the command that produced `output` (e.g. `"mise ls --output=json"`).
pub fn parse_json_output<T>(output: &str, command: &str) -> MiseResult<T>
where
    T: serde::de::DeserializeOwned,
{
    let trimmed = output.trim();
    let stdout = trimmed.to_owned();
    serde_json::from_str(trimmed).map_err(|e| MiseError::JsonParse {
        command: command.to_owned(),
        source: e,
        stdout,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn build_spec_minimal() {
        let spec = build_spec("mise", &[], None, &[], None, false);
        assert_eq!(spec.program, "mise");
        assert!(spec.args.is_empty());
        assert!(spec.cwd.is_none());
        assert!(spec.timeout.is_none());
        assert!(!spec.redact);
    }

    #[test]
    fn build_spec_full() {
        let args: Vec<String> = vec!["ls".into(), "--output=json".into()];
        let env = vec![("MISE_DATA_DIR".into(), "/tmp/mise".into())];
        let spec = build_spec(
            "/usr/local/bin/mise",
            &args,
            Some(Path::new("/project")),
            &env,
            Some(Duration::from_secs(30)),
            true,
        );
        assert_eq!(spec.program, "/usr/local/bin/mise");
        assert_eq!(spec.args, args);
        assert_eq!(spec.cwd, Some(Path::new("/project").to_path_buf()));
        assert_eq!(spec.timeout, Some(Duration::from_secs(30)));
        assert!(spec.redact);
        assert_eq!(spec.env, env);
    }

    #[test]
    fn build_mise_args_all_flags() {
        let base = &["ls"];
        let args = build_mise_args(base, true, true, true, true, true);
        assert_eq!(
            args,
            vec![
                "ls",
                "--output=json",
                "--no-config",
                "--no-env",
                "--no-hooks",
                "--locked",
            ]
        );
    }

    #[test]
    fn build_mise_args_no_flags() {
        let base = &["where", "node"];
        let args = build_mise_args(base, false, false, false, false, false);
        assert_eq!(args, vec!["where", "node"]);
    }

    #[test]
    fn parse_json_output_success() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct Tool {
            name: String,
            version: String,
        }

        let json = r#"[{"name":"node","version":"22.0.0"}]"#;
        let result: Vec<Tool> = parse_json_output(json, "mise ls").unwrap();
        assert_eq!(result[0].name, "node");
        assert_eq!(result[0].version, "22.0.0");
    }

    #[test]
    fn parse_json_output_error_includes_command() {
        let result: MiseResult<serde_json::Value> =
            parse_json_output("not json at all", "mise current");
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mise current"),
            "error message should mention the command: {msg}"
        );
    }
}
