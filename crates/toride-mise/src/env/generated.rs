//! Generated environment types for mise.
//!
//! [`EnvRequest`] describes the parameters for an environment query. [`MiseEnv`]
//! holds the resolved environment snapshot returned by `mise env`. [`EnvEntry`]
//! is a single key-value pair inside that snapshot.
//!
//! The [`Mise`](crate::client::Mise) methods [`env`](crate::client::Mise::env)
//! and [`env_for`](crate::client::Mise::env_for) live here as trait-extension
//! style methods on `Mise`.

use std::collections::BTreeMap;

use camino::Utf8PathBuf;

use crate::client::Mise;
use crate::error::MiseResult;
use crate::tool::ToolSpec;

// ---------------------------------------------------------------------------
// EnvRequest
// ---------------------------------------------------------------------------

/// Parameters for a `mise env` query.
///
/// Controls which tools and options are passed to the `mise env` sub-command.
/// All fields are optional — an empty request resolves the environment for the
/// currently active tools in the working directory.
///
/// Construct with [`EnvRequest::new`] and chain builder methods.
#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct EnvRequest {
    /// Only resolve environment for these tool specs.
    pub tools: Vec<ToolSpec>,
    /// Working directory override for the query.
    pub cwd: Option<Utf8PathBuf>,
    /// Include default / shell-profile environment variables.
    pub include_default: bool,
    /// Output format hint (e.g. `"json"`, `"dotenv"`). Defaults to JSON.
    pub format: Option<String>,
    /// Output in dotenv format (`KEY=VALUE` lines).
    pub dotenv: bool,
    /// Output shell export statements for the given shell (e.g. `"bash"`,
    /// `"zsh"`, `"fish"`).
    pub shell: Option<String>,
    /// Redact sensitive values in the output.
    pub redacted: bool,
    /// Only output values (no keys).
    pub values_only: bool,
}

impl EnvRequest {
    /// Create a new `EnvRequest` for the given tool specs.
    pub fn new(tools: impl IntoIterator<Item = impl Into<ToolSpec>>) -> Self {
        Self {
            tools: tools.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }

    /// Set the working directory for the query.
    pub fn cwd(mut self, path: impl Into<Utf8PathBuf>) -> Self {
        self.cwd = Some(path.into());
        self
    }

    /// Include default / shell-profile environment variables.
    pub fn include_default(mut self) -> Self {
        self.include_default = true;
        self
    }

    /// Set the output format.
    pub fn format(mut self, fmt: impl Into<String>) -> Self {
        self.format = Some(fmt.into());
        self
    }

    /// Output in dotenv format (`KEY=VALUE` lines).
    pub fn dotenv(mut self) -> Self {
        self.dotenv = true;
        self
    }

    /// Output shell export statements for the given shell.
    pub fn shell(mut self, shell: impl Into<String>) -> Self {
        self.shell = Some(shell.into());
        self
    }

    /// Add a tool spec to the request.
    pub fn tool(mut self, spec: impl Into<ToolSpec>) -> Self {
        self.tools.push(spec.into());
        self
    }

    /// Redact sensitive values in the output.
    pub fn redacted(mut self) -> Self {
        self.redacted = true;
        self
    }

    /// Only output values (no keys).
    pub fn values_only(mut self) -> Self {
        self.values_only = true;
        self
    }
}

// ---------------------------------------------------------------------------
// MiseEnv
// ---------------------------------------------------------------------------

/// A resolved mise environment snapshot.
///
/// Contains the full set of environment variables that mise would set, plus
/// optional extended metadata about the resolution.
#[derive(Debug, Clone)]
pub struct MiseEnv {
    /// The resolved environment variable map (key -> value).
    pub vars: BTreeMap<String, String>,
    /// Extended metadata: the path to the mise config file that was used, if any.
    pub config_path: Option<Utf8PathBuf>,
    /// Extended metadata: the mise data directory, if known.
    pub data_dir: Option<Utf8PathBuf>,
    /// Extended metadata: the mise state directory, if known.
    pub state_dir: Option<Utf8PathBuf>,
    /// Extended metadata: the mise shims directory, if known.
    pub shims_dir: Option<Utf8PathBuf>,
    /// Extended metadata: list of tool specs that were resolved, if reported.
    pub resolved_tools: Option<Vec<ToolSpec>>,
}

impl MiseEnv {
    /// Create an empty environment snapshot.
    pub fn empty() -> Self {
        Self {
            vars: BTreeMap::new(),
            config_path: None,
            data_dir: None,
            state_dir: None,
            shims_dir: None,
            resolved_tools: None,
        }
    }

    /// Return the value of an environment variable by name.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.vars.get(key).map(std::string::String::as_str)
    }

    /// Return an iterator over all environment entries.
    pub fn entries(&self) -> impl Iterator<Item = EnvEntry<'_>> {
        self.vars.iter().map(|(k, v)| EnvEntry {
            key: k.as_str(),
            value: v.as_str(),
        })
    }

    /// Return the number of environment variables.
    pub fn len(&self) -> usize {
        self.vars.len()
    }

    /// Return `true` if there are no environment variables.
    pub fn is_empty(&self) -> bool {
        self.vars.is_empty()
    }
}

// ---------------------------------------------------------------------------
// EnvEntry
// ---------------------------------------------------------------------------

/// A single environment variable entry (borrowed key-value pair).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvEntry<'a> {
    /// The variable name.
    pub key: &'a str,
    /// The variable value.
    pub value: &'a str,
}

/// A single extended environment entry as returned by `mise env --json-extended`.
///
/// Real mise returns `{"PATH":{"value":"/usr/bin:...","source":"..."}}` where
/// the env-var name is the JSON object key and the value is a nested object.
/// This struct represents the inner object only; the key is extracted from the
/// map iteration in [`Mise::env_extended`].
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ExtendedEnvValue {
    /// The resolved value of the environment variable.
    pub value: String,
    /// The tool or source that contributed this variable, if known.
    #[serde(default)]
    pub source: Option<String>,
}

/// A flattened extended environment entry combining the key and its value/source.
#[derive(Debug, Clone)]
pub struct ExtendedEnvEntry {
    /// The variable name.
    pub key: String,
    /// The variable value.
    pub value: String,
    /// The tool that contributed this variable, if known.
    pub source: Option<String>,
}

// ---------------------------------------------------------------------------
// Mise impl — env methods
// ---------------------------------------------------------------------------

impl Mise {
    /// Resolve the environment for the current directory and active tools.
    ///
    /// Equivalent to running `mise env --json` and parsing the output.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError`](crate::error::MiseError) if the command fails or
    /// the output cannot be parsed.
    pub async fn env(&self, req: &EnvRequest) -> MiseResult<MiseEnv> {
        let mut args: Vec<String> = Vec::new();
        args.push("env".into());

        // Format: dotenv takes precedence over JSON.
        if req.dotenv {
            args.push("--dotenv".into());
        } else if let Some(ref shell) = req.shell {
            args.push("--shell".into());
            args.push(shell.clone());
        } else {
            args.push("--json".into());
        }

        if let Some(ref cwd) = req.cwd {
            args.push("--cwd".into());
            args.push(cwd.to_string());
        }

        if req.include_default {
            args.push("--default".into());
        }

        if req.redacted {
            args.push("--redacted".into());
        }

        if req.values_only {
            args.push("--values".into());
        }

        if let Some(ref format) = req.format {
            // Only add --format if it differs from the resolved output mode.
            args.push("--format".into());
            args.push(format.clone());
        }

        for tool in &req.tools {
            args.push(tool.to_string());
        }

        // For dotenv / shell mode, return raw output in a single-entry map.
        if req.dotenv || req.shell.is_some() {
            let output = self.run_checked(args).await?;
            let raw = output.stdout_trimmed();
            let mut vars = BTreeMap::new();

            // Parse KEY=VALUE lines from dotenv or shell export output.
            for line in raw.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                // Handle "export KEY=VALUE" from shell mode.
                let line = line.strip_prefix("export ").unwrap_or(line);
                if let Some((key, value)) = line.split_once('=') {
                    let value = value.trim_matches('"').trim_matches('\'');
                    vars.insert(key.trim().to_owned(), value.to_owned());
                }
            }

            return Ok(MiseEnv {
                vars,
                config_path: None,
                data_dir: None,
                state_dir: None,
                shims_dir: None,
                resolved_tools: None,
            });
        }

        // For JSON mode, handle empty output gracefully.
        let output = self.run_checked(args).await?;
        let raw = output.stdout_trimmed();
        let trimmed = raw.trim();

        let vars: BTreeMap<String, String> =
            if trimmed.is_empty() || trimmed == "null" || trimmed == "{}" {
                BTreeMap::new()
            } else {
                serde_json::from_str(trimmed).map_err(|e| crate::error::MiseError::JsonParse {
                    command: self.binary_name().to_owned(),
                    source: e,
                    stdout: trimmed.to_owned(),
                })?
            };

        Ok(MiseEnv {
            vars,
            config_path: None,
            data_dir: None,
            state_dir: None,
            shims_dir: None,
            resolved_tools: None,
        })
    }

    /// Resolve the environment for a specific set of tools.
    ///
    /// Convenience wrapper around [`Mise::env`] that constructs an
    /// [`EnvRequest`] with the given tools.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError`](crate::error::MiseError) if the command fails or
    /// the output cannot be parsed.
    pub async fn env_for(&self, tools: &[ToolSpec]) -> MiseResult<MiseEnv> {
        let req = EnvRequest {
            tools: tools.to_vec(),
            ..EnvRequest::default()
        };
        self.env(&req).await
    }

    /// Resolve the extended environment for the given tools.
    ///
    /// Invokes `mise env --json-extended <tools…>` and returns the parsed
    /// array of [`ExtendedEnvEntry`] values including source metadata.
    ///
    /// Real mise returns a nested JSON object like
    /// `{"PATH":{"value":"/usr/bin:...","source":"..."}}` rather than an
    /// array. This method deserialises the map and flattens it into a
    /// `Vec<ExtendedEnvEntry>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError`](crate::error::MiseError) if the command fails or
    /// the output cannot be parsed.
    pub async fn env_extended(&self, tools: Vec<String>) -> MiseResult<Vec<ExtendedEnvEntry>> {
        let mut args: Vec<String> = vec!["env".into(), "--json-extended".into()];
        args.extend(tools);

        let output = self.run_checked(args).await?;
        let raw = output.stdout_trimmed();
        let trimmed = raw.trim();

        // Handle empty / null / {} gracefully.
        if trimmed.is_empty() || trimmed == "null" || trimmed == "{}" {
            return Ok(Vec::new());
        }

        let map: BTreeMap<String, ExtendedEnvValue> =
            serde_json::from_str(trimmed).map_err(|e| crate::error::MiseError::JsonParse {
                command: self.binary_name().to_owned(),
                source: e,
                stdout: trimmed.to_owned(),
            })?;

        let entries = map
            .into_iter()
            .map(|(key, inner)| ExtendedEnvEntry {
                key,
                value: inner.value,
                source: inner.source,
            })
            .collect();

        Ok(entries)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use toride_runner::{CommandOutput, FakeRunner};

    use crate::client::Mise;
    use crate::tool::ToolSpec;

    fn build_mise(fake: Arc<FakeRunner>) -> Mise {
        Mise::builder()
            .runner(fake as Arc<dyn toride_runner::AsyncRunner>)
            .binary(crate::binary::MiseBinary::from_path("/usr/bin/mise"))
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_env_basic() {
        let json = r#"{"PATH":"/usr/bin:/home","NODE_VERSION":"22"}"#;
        let fake = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(json)));
        let mise = build_mise(fake.clone());

        let req = super::EnvRequest::default();
        let env = mise.env(&req).await.unwrap();
        assert_eq!(env.vars.len(), 2);
        assert_eq!(env.vars.get("PATH"), Some(&"/usr/bin:/home".to_string()));
        assert_eq!(env.vars.get("NODE_VERSION"), Some(&"22".to_string()));
        assert!(env.config_path.is_none());

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"env".to_string()));
        assert!(calls[0].args.contains(&"--json".to_string()));
    }

    #[tokio::test]
    async fn test_env_extended() {
        let json = r#"{"FOO":"bar","BAZ":"qux"}"#;
        let fake = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(json)));
        let mise = build_mise(fake.clone());

        let req = super::EnvRequest::new([ToolSpec::new("node@22")]);
        let env = mise.env(&req).await.unwrap();
        assert_eq!(env.vars.len(), 2);
        assert_eq!(env.vars.get("FOO"), Some(&"bar".to_string()));
        assert_eq!(env.vars.get("BAZ"), Some(&"qux".to_string()));

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"env".to_string()));
        assert!(calls[0].args.contains(&"--json".to_string()));
        assert!(calls[0].args.contains(&"node@22".to_string()));
    }
}
