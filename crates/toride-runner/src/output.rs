//! [`CommandOutput`]: the result of executing a command.
//!
//! Captures stdout, stderr, exit code, and a convenience `success` flag.

/// The captured output of a completed command.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    /// Standard output captured from the process.
    pub stdout: String,
    /// Standard error captured from the process.
    pub stderr: String,
    /// Exit code, if the process exited normally.
    pub exit_code: Option<i32>,
    /// Whether the process exited with code `0`.
    pub success: bool,
}

impl CommandOutput {
    /// Create a new output from raw components.
    #[must_use]
    pub fn new(stdout: String, stderr: String, exit_code: Option<i32>) -> Self {
        let success = exit_code.is_some_and(|c| c == 0);
        Self {
            stdout,
            stderr,
            exit_code,
            success,
        }
    }

    /// Create a successful output with the given stdout and no stderr.
    #[must_use]
    pub fn from_stdout(stdout: impl Into<String>) -> Self {
        Self::new(stdout.into(), String::new(), Some(0))
    }

    /// Create a failed output with the given stderr and exit code.
    #[must_use]
    pub fn from_stderr(stderr: impl Into<String>, exit_code: i32) -> Self {
        Self::new(String::new(), stderr.into(), Some(exit_code))
    }

    /// Return stdout split into non-empty lines.
    #[must_use]
    pub fn stdout_lines(&self) -> Vec<&str> {
        self.stdout.lines().filter(|l| !l.is_empty()).collect()
    }

    /// Return stdout with leading and trailing whitespace removed.
    #[must_use]
    pub fn stdout_trimmed(&self) -> &str {
        self.stdout.trim()
    }

    /// Return stdout and stderr concatenated, separated by a newline if both
    /// are non-empty.
    #[must_use]
    pub fn combined_output(&self) -> String {
        match (self.stdout.is_empty(), self.stderr.is_empty()) {
            (true, true) => String::new(),
            (true, false) => self.stderr.clone(),
            (false, true) => self.stdout.clone(),
            (false, false) => format!("{}\n{}", self.stdout, self.stderr),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for CommandOutput {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("CommandOutput", 4)?;
        s.serialize_field("stdout", &self.stdout)?;
        s.serialize_field("stderr", &self.stderr)?;
        s.serialize_field("exit_code", &self.exit_code)?;
        s.serialize_field("success", &self.success)?;
        s.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for CommandOutput {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct CommandOutputHelper {
            stdout: String,
            stderr: String,
            exit_code: Option<i32>,
            success: bool,
        }

        let h = CommandOutputHelper::deserialize(deserializer)?;
        Ok(CommandOutput {
            stdout: h.stdout,
            stderr: h.stderr,
            exit_code: h.exit_code,
            success: h.success,
        })
    }
}
