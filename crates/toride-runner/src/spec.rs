//! [`CommandSpec`] — a declarative description of a command to run.
//!
//! Use the builder-style methods to construct a spec, then pass it to
//! any [`Runner`](crate::Runner) implementation.

use std::path::PathBuf;
use std::time::Duration;

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
    /// The program to execute (looked up via `$PATH` unless absolute).
    pub program: String,
    /// Positional arguments to pass to the program.
    pub args: Vec<String>,
    /// Optional data to pipe to the process's stdin.
    pub stdin: Option<String>,
    /// Optional wall-clock timeout for the command.
    pub timeout: Option<Duration>,
    /// Extra environment variables (`(key, value)` pairs).
    pub env: Vec<(String, String)>,
    /// Working directory for the command. Defaults to the current directory.
    pub cwd: Option<PathBuf>,
    /// Whether to redact sensitive arguments in display/logging output.
    /// Does **not** affect the actual args passed to the child process.
    pub redact: bool,
}

impl CommandSpec {
    /// Create a new spec for the given program with no arguments.
    #[must_use]
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            stdin: None,
            timeout: None,
            env: Vec::new(),
            cwd: None,
            redact: false,
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

    /// Set the working directory for the command.
    #[must_use]
    pub fn cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
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
}

#[cfg(feature = "serde")]
impl serde::Serialize for CommandSpec {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("CommandSpec", 7)?;
        s.serialize_field("program", &self.program)?;
        s.serialize_field("args", &self.args)?;
        s.serialize_field("stdin", &self.stdin)?;
        s.serialize_field("timeout_nanos", &self.timeout.map(|d| d.as_nanos() as u64))?;
        s.serialize_field("env", &self.env)?;
        s.serialize_field(
            "cwd",
            &self.cwd.as_ref().map(|p| p.to_string_lossy().into_owned()),
        )?;
        s.serialize_field("redact", &self.redact)?;
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
            timeout_nanos: Option<u64>,
            #[serde(default)]
            timeout: Option<u64>,
            env: Vec<(String, String)>,
            #[serde(default)]
            cwd: Option<String>,
            #[serde(default)]
            redact: bool,
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
            timeout,
            env: h.env,
            cwd: h.cwd.map(PathBuf::from),
            redact: h.redact,
        })
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
        assert!(roundtripped.redact);
        assert_eq!(roundtripped.env, vec![("KEY".into(), "val".into())]);
    }

    #[test]
    fn missing_optional_fields_default() {
        let json = r#"{"program":"cmd","args":["a"],"stdin":null,"timeout_nanos":null,"env":[]}"#;
        let spec: CommandSpec = serde_json::from_str(json).unwrap();

        assert!(spec.cwd.is_none());
        assert!(!spec.redact);
        assert!(spec.timeout.is_none());
    }
}
