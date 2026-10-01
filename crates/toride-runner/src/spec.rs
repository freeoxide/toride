//! [`CommandSpec`] — a declarative description of a command to run.
//!
//! Use the builder-style methods to construct a spec, then pass it to
//! any [`Runner`](crate::Runner) implementation.

use std::path::PathBuf;
use std::time::Duration;

use crate::OutputMode;
use crate::policy::{ArgvPolicy, EnvPrecedence, OutputCap, PathResolution};

/// A declarative specification of a command to execute.
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
/// use toride_runner::CommandSpec;
///
/// let spec = CommandSpec::new("ufw")
///     .arg("status")
///     .timeout(Duration::from_secs(10));
/// ```
#[derive(Debug, Clone)]
pub struct CommandSpec {
    /// The program to execute; bare names follow [`PathResolution`] (the
    /// default searches the parent's `$PATH`).
    pub program: String,
    /// Positional arguments to pass to the program.
    pub args: Vec<String>,
    /// Optional data to pipe to the process's stdin.
    pub stdin: Option<String>,
    /// Whether the child's stdin should be wired to the platform null device.
    ///
    /// `false` (the default) leaves stdin inherited from the parent when
    /// [`CommandSpec::stdin`] carries no data — the child reads whatever the
    /// parent reads (for a foreground command, the terminal). `true` connects
    /// the child's stdin to the null device instead, so reads return EOF
    /// immediately: the child can neither block on nor consume the parent's
    /// stdin. Use it for non-interactive captured commands — version probes,
    /// catalogue sweeps — where an inherited stdin is at best meaningless and
    /// at worst steals keystrokes from the parent UI. When [`CommandSpec::stdin`]
    /// carries data, that data is piped and this flag has no effect.
    pub stdin_null: bool,
    /// Optional wall-clock timeout for the command.
    pub timeout: Option<Duration>,
    /// Extra environment variables (`(key, value)` pairs).
    pub env: Vec<(String, String)>,
    /// Environment variables to remove from the child process environment.
    /// An explicitly-added variable with the same key survives removal only
    /// under the default [`EnvPrecedence::ExplicitWins`].
    pub env_remove: Vec<String>,
    /// Whether the child should start from a clean environment.
    ///
    /// When true, runners apply a minimal platform environment where required
    /// and then apply [`CommandSpec::env`].
    pub clear_env: bool,
    /// Working directory for the command. Defaults to the current directory.
    pub cwd: Option<PathBuf>,
    /// How stdout and stderr should be handled.
    pub output_mode: OutputMode,
    /// Whether to redact sensitive arguments in display/logging output.
    /// Does **not** affect the actual args passed to the child process.
    pub redact: bool,
    /// Optional combined byte cap on captured stdout plus stderr.
    ///
    /// When set, runners enforce the cap *while* capturing (not after) by
    /// killing and reaping the child as soon as the limit is breached, and
    /// return [`Error::OutputLimitExceeded`](crate::error::Error::OutputLimitExceeded).
    /// `None` leaves capture unlimited unless [`CommandSpec::output_cap`]
    /// enforces one. Accounted in bytes — UTF-8 decoding happens after the
    /// byte-limit decision.
    ///
    /// This is a runtime safety policy, not command construction: it is
    /// excluded from [`FakeRunner`](crate::fake::FakeRunner) exact matching,
    /// the same way [`CommandSpec::timeout`] is.
    pub output_limit: Option<usize>,
    /// Which side wins when `env` and `env_remove` name the same key.
    /// Defaults to [`EnvPrecedence::ExplicitWins`] (toride's historical behavior).
    pub env_precedence: EnvPrecedence,
    /// How the program is located before spawn; defaults to
    /// [`PathResolution::OsSearch`], which passes the program to the runner verbatim.
    pub path_resolution: PathResolution,
    /// Whether argv is validated before spawn; defaults to [`ArgvPolicy::Allow`].
    pub argv_policy: ArgvPolicy,
    /// Output-cap policy; defaults to [`OutputCap::OptIn`], which honors
    /// [`CommandSpec::output_limit`] only when set.
    pub output_cap: OutputCap,
}

impl CommandSpec {
    /// Create a new spec for the given program with no arguments.
    #[must_use]
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            stdin: None,
            stdin_null: false,
            timeout: None,
            env: Vec::new(),
            env_remove: Vec::new(),
            clear_env: false,
            cwd: None,
            output_mode: OutputMode::Capture,
            redact: false,
            output_limit: None,
            env_precedence: EnvPrecedence::ExplicitWins,
            path_resolution: PathResolution::OsSearch,
            argv_policy: ArgvPolicy::Allow,
            output_cap: OutputCap::OptIn,
        }
    }

    /// Append a single argument.
    #[must_use]
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Append multiple arguments.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Set stdin data for the process.
    #[must_use]
    pub fn stdin(mut self, data: impl Into<String>) -> Self {
        self.stdin = Some(data.into());
        self
    }

    /// Wire the child's stdin to the platform null device (reads return EOF)
    /// instead of leaving it inherited from the parent. No-op when
    /// [`CommandSpec::stdin`] carries data — the piped data wins.
    #[must_use]
    pub fn stdin_null(mut self, null: bool) -> Self {
        self.stdin_null = null;
        self
    }

    /// Set a wall-clock timeout.
    #[must_use]
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.timeout = Some(duration);
        self
    }

    /// Add an environment variable.
    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Add multiple environment variables.
    #[must_use]
    pub fn envs<I, K, V>(mut self, pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.env
            .extend(pairs.into_iter().map(|(k, v)| (k.into(), v.into())));
        self
    }

    /// Remove an environment variable from the child process.
    #[must_use]
    pub fn env_remove(mut self, key: impl Into<String>) -> Self {
        self.env_remove.push(key.into());
        self
    }

    /// Remove multiple environment variables from the child process.
    #[must_use]
    pub fn env_removes<I, S>(mut self, keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.env_remove.extend(keys.into_iter().map(Into::into));
        self
    }

    /// Start the child with a clean environment before applying explicit env.
    #[must_use]
    pub fn clear_env(mut self, clear: bool) -> Self {
        self.clear_env = clear;
        self
    }

    /// Set the working directory for the command.
    #[must_use]
    pub fn cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Set how stdout and stderr should be handled.
    #[must_use]
    pub fn output_mode(mut self, output_mode: OutputMode) -> Self {
        self.output_mode = output_mode;
        self
    }

    /// Enable redaction of sensitive arguments in display/logging output.
    ///
    /// This does **not** affect the actual arguments passed to the child process.
    #[must_use]
    pub fn redact(mut self, redact: bool) -> Self {
        self.redact = redact;
        self
    }

    /// Set a combined byte cap on captured stdout plus stderr.
    ///
    /// Runners enforce this cap *while* capturing and return
    /// [`Error::OutputLimitExceeded`](crate::error::Error::OutputLimitExceeded)
    /// if it is breached, killing the child in the process. `None` (the
    /// default) preserves unlimited capture. See
    /// [`CommandSpec::output_limit`] for full semantics.
    #[must_use]
    pub fn output_limit(mut self, limit: usize) -> Self {
        self.output_limit = Some(limit);
        self
    }

    /// Set which side wins when `env` and `env_remove` name the same key.
    #[must_use]
    pub fn env_precedence(mut self, precedence: EnvPrecedence) -> Self {
        self.env_precedence = precedence;
        self
    }

    /// Set how the program is located before spawn.
    #[must_use]
    pub fn path_resolution(mut self, resolution: PathResolution) -> Self {
        self.path_resolution = resolution;
        self
    }

    /// Set whether argv is validated against [`SHELL_METACHARS`](crate::policy::SHELL_METACHARS) before spawn.
    #[must_use]
    pub fn argv_policy(mut self, policy: ArgvPolicy) -> Self {
        self.argv_policy = policy;
        self
    }

    /// Set the output-cap policy; [`OutputCap::Always`] overrides [`CommandSpec::output_limit`].
    #[must_use]
    pub fn output_cap(mut self, cap: OutputCap) -> Self {
        self.output_cap = cap;
        self
    }

    /// The byte cap runners enforce on captured stdout plus stderr:
    /// [`OutputCap::Always`] wins over the opt-in [`CommandSpec::output_limit`].
    #[must_use]
    pub fn effective_output_limit(&self) -> Option<usize> {
        match self.output_cap {
            OutputCap::Always(limit) => Some(limit),
            OutputCap::OptIn => self.output_limit,
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for CommandSpec {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("CommandSpec", 16)?;
        s.serialize_field("program", &self.program)?;
        s.serialize_field("args", &self.args)?;
        s.serialize_field("stdin", &self.stdin)?;
        s.serialize_field("stdin_null", &self.stdin_null)?;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "a timeout beyond u64::MAX nanos (~584 years) cannot occur"
        )]
        let timeout_nanos = self.timeout.map(|d| d.as_nanos() as u64);
        s.serialize_field("timeout_nanos", &timeout_nanos)?;
        s.serialize_field("env", &self.env)?;
        s.serialize_field("env_remove", &self.env_remove)?;
        s.serialize_field("clear_env", &self.clear_env)?;
        s.serialize_field(
            "cwd",
            &self.cwd.as_ref().map(|p| p.to_string_lossy().into_owned()),
        )?;
        s.serialize_field("output_mode", &self.output_mode)?;
        s.serialize_field("redact", &self.redact)?;
        s.serialize_field("output_limit", &self.output_limit)?;
        s.serialize_field("env_precedence", &self.env_precedence)?;
        s.serialize_field("path_resolution", &self.path_resolution)?;
        s.serialize_field("argv_policy", &self.argv_policy)?;
        s.serialize_field("output_cap", &self.output_cap)?;
        s.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for CommandSpec {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct CommandSpecHelper {
            program: String,
            args: Vec<String>,
            stdin: Option<String>,
            #[serde(default)]
            stdin_null: bool,
            #[serde(default)]
            timeout_nanos: Option<u64>,
            #[serde(default)]
            timeout: Option<u64>,
            #[serde(default)]
            env: Vec<(String, String)>,
            #[serde(default)]
            env_remove: Vec<String>,
            #[serde(default)]
            clear_env: bool,
            #[serde(default)]
            cwd: Option<String>,
            #[serde(default)]
            output_mode: OutputMode,
            #[serde(default)]
            redact: bool,
            #[serde(default)]
            output_limit: Option<usize>,
            #[serde(default)]
            env_precedence: EnvPrecedence,
            #[serde(default)]
            path_resolution: PathResolution,
            #[serde(default)]
            argv_policy: ArgvPolicy,
            #[serde(default)]
            output_cap: OutputCap,
        }

        let h = CommandSpecHelper::deserialize(deserializer)?;

        // Prefer nanosecond precision if available, fall back to seconds for
        // backward compatibility with previously-serialized data.
        let timeout = h
            .timeout_nanos
            .map(Duration::from_nanos)
            .or(h.timeout.map(Duration::from_secs));

        Ok(CommandSpec {
            program: h.program,
            args: h.args,
            stdin: h.stdin,
            stdin_null: h.stdin_null,
            timeout,
            env: h.env,
            env_remove: h.env_remove,
            clear_env: h.clear_env,
            cwd: h.cwd.map(PathBuf::from),
            output_mode: h.output_mode,
            redact: h.redact,
            output_limit: h.output_limit,
            env_precedence: h.env_precedence,
            path_resolution: h.path_resolution,
            argv_policy: h.argv_policy,
            output_cap: h.output_cap,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_output_limit_follows_opt_in_field() {
        let uncapped = CommandSpec::new("cmd");
        assert_eq!(uncapped.effective_output_limit(), None);

        let capped = CommandSpec::new("cmd").output_limit(4096);
        assert_eq!(capped.effective_output_limit(), Some(4096));
    }

    #[test]
    fn effective_output_limit_always_overrides_opt_in() {
        let spec = CommandSpec::new("cmd")
            .output_limit(1_000_000)
            .output_cap(OutputCap::Always(64));
        assert_eq!(spec.effective_output_limit(), Some(64));
    }

    #[test]
    fn effective_output_limit_always_works_without_opt_in() {
        let spec = CommandSpec::new("cmd").output_cap(OutputCap::Always(1_048_576));
        assert_eq!(spec.effective_output_limit(), Some(1_048_576));
    }

    #[test]
    fn policy_knobs_default_to_toride_semantics() {
        let spec = CommandSpec::new("cmd");
        assert_eq!(spec.env_precedence, EnvPrecedence::ExplicitWins);
        assert_eq!(spec.path_resolution, PathResolution::OsSearch);
        assert_eq!(spec.argv_policy, ArgvPolicy::Allow);
        assert_eq!(spec.output_cap, OutputCap::OptIn);
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use super::*;

    #[test]
    fn sub_second_timeout_round_trip() {
        let spec = CommandSpec::new("sleep")
            .arg("1")
            .timeout(Duration::from_millis(50));

        let json = serde_json::to_string(&spec).unwrap();
        let roundtripped: CommandSpec = serde_json::from_str(&json).unwrap();

        assert_eq!(
            roundtripped.timeout,
            Some(Duration::from_millis(50)),
            "sub-second timeout should survive serde round-trip"
        );
    }

    #[test]
    fn nanos_timeout_round_trip() {
        let spec = CommandSpec::new("cmd").timeout(Duration::from_nanos(123_456_789));

        let json = serde_json::to_string(&spec).unwrap();
        let roundtripped: CommandSpec = serde_json::from_str(&json).unwrap();

        assert_eq!(
            roundtripped.timeout,
            Some(Duration::from_nanos(123_456_789)),
            "nanosecond timeout should survive serde round-trip"
        );
    }

    #[test]
    fn backward_compat_seconds_timeout() {
        // Simulate data serialized with the old `as_secs()` format.
        let json = r#"{"program":"cmd","args":[],"stdin":null,"timeout":5,"env":[]}"#;
        let spec: CommandSpec = serde_json::from_str(json).unwrap();

        assert_eq!(spec.timeout, Some(Duration::from_secs(5)));
    }

    #[test]
    fn cwd_and_redact_round_trip() {
        let spec = CommandSpec::new("make")
            .cwd("/project")
            .redact(true)
            .env("KEY", "val");

        let json = serde_json::to_string(&spec).unwrap();
        let roundtripped: CommandSpec = serde_json::from_str(&json).unwrap();

        assert_eq!(roundtripped.cwd, Some(PathBuf::from("/project")));
        assert_eq!(roundtripped.output_mode, OutputMode::Capture);
        assert!(roundtripped.redact);
        assert_eq!(roundtripped.env, vec![("KEY".into(), "val".into())]);
        assert!(roundtripped.env_remove.is_empty());
        assert!(!roundtripped.clear_env);
    }

    #[test]
    fn missing_optional_fields_default() {
        let json = r#"{"program":"cmd","args":["a"],"stdin":null,"timeout_nanos":null,"env":[]}"#;
        let spec: CommandSpec = serde_json::from_str(json).unwrap();

        assert!(spec.cwd.is_none());
        assert_eq!(spec.output_mode, OutputMode::Capture);
        assert!(!spec.redact);
        assert!(spec.timeout.is_none());
        assert!(spec.env_remove.is_empty());
        assert!(!spec.clear_env);
        // Payloads serialized before `stdin_null` existed default to inherit.
        assert!(!spec.stdin_null);
    }

    #[test]
    fn stdin_null_round_trip() {
        let spec = CommandSpec::new("cat").stdin_null(true);

        let json = serde_json::to_string(&spec).unwrap();
        let roundtripped: CommandSpec = serde_json::from_str(&json).unwrap();

        assert!(roundtripped.stdin_null);
        assert_eq!(roundtripped.stdin, None);
    }

    #[test]
    fn output_mode_round_trip() {
        let spec = CommandSpec::new("cmd").output_mode(OutputMode::Inherit);

        let json = serde_json::to_string(&spec).unwrap();
        let roundtripped: CommandSpec = serde_json::from_str(&json).unwrap();

        assert_eq!(roundtripped.output_mode, OutputMode::Inherit);
    }

    #[test]
    fn env_policy_round_trip() {
        let spec = CommandSpec::new("cmd")
            .env("KEEP", "1")
            .env_remove("DROP")
            .clear_env(true);

        let json = serde_json::to_string(&spec).unwrap();
        let roundtripped: CommandSpec = serde_json::from_str(&json).unwrap();

        assert_eq!(roundtripped.env, vec![("KEEP".into(), "1".into())]);
        assert_eq!(roundtripped.env_remove, vec!["DROP"]);
        assert!(roundtripped.clear_env);
    }

    #[test]
    fn output_limit_round_trip() {
        let spec = CommandSpec::new("cmd").output_limit(4096);

        let json = serde_json::to_string(&spec).unwrap();
        let roundtripped: CommandSpec = serde_json::from_str(&json).unwrap();

        assert_eq!(roundtripped.output_limit, Some(4096));
    }

    #[test]
    fn output_limit_defaults_to_none_for_old_payloads() {
        // A payload serialized before output_limit existed must default to None.
        let json = r#"{"program":"cmd","args":[],"stdin":null,"timeout_nanos":null,"env":[]}"#;
        let spec: CommandSpec = serde_json::from_str(json).unwrap();

        assert!(spec.output_limit.is_none());
    }

    #[test]
    fn policy_knobs_round_trip() {
        let spec = CommandSpec::new("cmd")
            .env_precedence(EnvPrecedence::RemoveWins)
            .path_resolution(PathResolution::ChildEnvNoCwd)
            .argv_policy(ArgvPolicy::RejectShellMetachars)
            .output_cap(OutputCap::Always(1_048_576));

        let json = serde_json::to_string(&spec).unwrap();
        let roundtripped: CommandSpec = serde_json::from_str(&json).unwrap();

        assert_eq!(roundtripped.env_precedence, EnvPrecedence::RemoveWins);
        assert_eq!(roundtripped.path_resolution, PathResolution::ChildEnvNoCwd);
        assert_eq!(roundtripped.argv_policy, ArgvPolicy::RejectShellMetachars);
        assert_eq!(roundtripped.output_cap, OutputCap::Always(1_048_576));
    }

    #[test]
    fn policy_knobs_default_for_old_payloads() {
        let json = r#"{"program":"cmd","args":[],"stdin":null,"timeout_nanos":null,"env":[]}"#;
        let spec: CommandSpec = serde_json::from_str(json).unwrap();

        assert_eq!(spec.env_precedence, EnvPrecedence::ExplicitWins);
        assert_eq!(spec.path_resolution, PathResolution::OsSearch);
        assert_eq!(spec.argv_policy, ArgvPolicy::Allow);
        assert_eq!(spec.output_cap, OutputCap::OptIn);
    }
}
