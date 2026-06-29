//! Tool registry search via `mise registry`.
//!
//! Exposes [`RegistryTool`] for deserialised registry entries and adds
//! [`Mise::registry`], [`Mise::registry_with_security`],
//! [`Mise::registry_by_backend`], [`Mise::registry_tool`], and
//! [`Mise::registry_lookup`] methods on the client.

use serde::Deserialize;

use crate::client::Mise;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// JSON response types
// ---------------------------------------------------------------------------

/// A single entry returned by `mise registry --json`.
///
/// Real mise (2026.x) outputs fields named `short`, `backends` (array),
/// `description`, and `aliases`. We accept both the real field names and
/// our older `name`/`backend` names for backward compatibility.
#[derive(Debug, Clone)]
pub struct RegistryTool {
    /// The short tool name (e.g. `"node"`, `"1password"`).
    ///
    /// Real mise uses the JSON key `"short"`. We also accept `"name"` for
    /// backward compatibility with older builds or test fakes.
    pub short: String,
    /// A short human-readable description of the tool.
    pub description: String,
    /// The backend(s) that provide this tool (e.g. `["core:node"]`,
    /// `["vfox:mise-plugins/vfox-1password", "aqua:1password/cli"]`).
    ///
    /// Real mise returns an array. We also accept a single string for backward
    /// compatibility via the legacy `backend` field.
    pub backends: Vec<String>,
    /// Aliases / alternate names for this tool (e.g. `["1password-cli", "op"]`).
    pub aliases: Vec<String>,
    /// Security features for the tool, when requested via `--security`.
    pub security: Option<Vec<SecurityFeature>>,
}

impl<'de> serde::Deserialize<'de> for RegistryTool {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Helper struct that mirrors [`RegistryTool`] but accepts both old and
        /// new field names.
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(alias = "name")]
            short: String,
            #[serde(default, deserialize_with = "deserialize_description")]
            description: String,
            #[serde(default, deserialize_with = "deserialize_backends")]
            backends: Vec<String>,
            /// Legacy single-backend field (older test fakes).
            #[serde(default, deserialize_with = "deserialize_single_backend")]
            backend: Vec<String>,
            #[serde(default, deserialize_with = "deserialize_aliases")]
            aliases: Vec<String>,
            #[serde(default)]
            security: Option<Vec<SecurityFeature>>,
        }

        let raw = Raw::deserialize(deserializer)?;
        // Merge: if `backends` is empty but `backend` had a value, use that.
        let backends = if raw.backends.is_empty() && !raw.backend.is_empty() {
            raw.backend
        } else {
            raw.backends
        };

        Ok(RegistryTool {
            short: raw.short,
            description: raw.description,
            backends,
            aliases: raw.aliases,
            security: raw.security,
        })
    }
}

/// Deserializer that turns a missing field or `null` into an empty vec.
fn deserialize_single_backend<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;
    use std::fmt;

    struct SingleBackendVisitor;

    impl de::Visitor<'_> for SingleBackendVisitor {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a string or null")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(vec![v.to_owned()])
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }
    }

    deserializer.deserialize_any(SingleBackendVisitor)
}

/// Deserializer that turns `null` into an empty string for the description field.
fn deserialize_description<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;
    use std::fmt;

    struct DescriptionVisitor;

    impl de::Visitor<'_> for DescriptionVisitor {
        type Value = String;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a string or null")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(v.to_owned())
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(String::new())
        }
    }

    deserializer.deserialize_any(DescriptionVisitor)
}

/// Deserializer that turns `null` into an empty vec for the aliases field.
fn deserialize_aliases<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;
    use std::fmt;

    struct AliasesVisitor;

    impl<'de> de::Visitor<'de> for AliasesVisitor {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a sequence of strings, a single string, or null")
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::new();
            while let Some(s) = seq.next_element::<String>()? {
                out.push(s);
            }
            Ok(out)
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(vec![v.to_owned()])
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }
    }

    deserializer.deserialize_any(AliasesVisitor)
}

/// Security metadata for a registry tool entry.
///
/// Real mise outputs `security` as an array of tagged enum variants when using
/// `--security`. Each variant uses `#[serde(tag = "type")]` internally in mise.
/// Example JSON: `[{"type":"checksum","algorithm":"sha256"}]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum SecurityFeature {
    /// Checksum verification with an optional algorithm.
    Checksum {
        /// The hash algorithm (e.g. `"sha256"`).
        #[serde(default)]
        algorithm: Option<String>,
    },
    /// GitHub attestations verification.
    GithubAttestations {
        /// The signer workflow, if specified.
        #[serde(default)]
        signer_workflow: Option<String>,
    },
    /// SLSA provenance verification.
    Slsa {
        /// The SLSA level (e.g. `"3"`).
        #[serde(default)]
        level: Option<String>,
    },
    /// Cosign signature verification.
    Cosign,
    /// Minisign signature verification.
    Minisign {
        /// The public key used for verification.
        #[serde(default)]
        public_key: Option<String>,
    },
    /// GPG signature verification.
    Gpg,
}

/// Custom deserializer that accepts either a single string or an array of strings.
fn deserialize_backends<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;
    use std::fmt;

    struct BackendsVisitor;

    impl<'de> de::Visitor<'de> for BackendsVisitor {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a string or an array of strings")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(vec![v.to_owned()])
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::new();
            while let Some(s) = seq.next_element::<String>()? {
                out.push(s);
            }
            Ok(out)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }
    }

    deserializer.deserialize_any(BackendsVisitor)
}

// ---------------------------------------------------------------------------
// Mise methods
// ---------------------------------------------------------------------------

impl Mise {
    /// List every tool in the mise registry.
    ///
    /// Invokes `mise registry --json` and returns the parsed list.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn registry(&self) -> MiseResult<Vec<RegistryTool>> {
        self.run_json(["registry", "--json"]).await
    }

    /// Look up a specific tool in the mise registry by exact name.
    ///
    /// Invokes `mise registry <query> --json`. Note: this performs an exact
    /// registry lookup, not a fuzzy search. Real mise does not have a `search`
    /// subcommand; it uses a positional `NAME` argument to filter.
    /// When an exact match is found, mise returns a single JSON object instead
    /// of an array; this method normalises both forms into a `Vec`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn registry_lookup(&self, query: &str) -> MiseResult<Vec<RegistryTool>> {
        let output = self.run_checked(["registry", query, "--json"]).await?;
        let raw = output.stdout_trimmed();
        let raw_owned = raw.to_owned();
        // mise may return a single object `{...}` or an array `[...]`.
        let trimmed = raw.trim();
        if trimmed.starts_with('{') {
            let tool: RegistryTool =
                serde_json::from_str(trimmed).map_err(|e| crate::error::MiseError::JsonParse {
                    command: self.binary_name().to_owned(),
                    source: e,
                    stdout: raw_owned,
                })?;
            Ok(vec![tool])
        } else {
            serde_json::from_str(raw).map_err(|e| crate::error::MiseError::JsonParse {
                command: self.binary_name().to_owned(),
                source: e,
                stdout: raw_owned,
            })
        }
    }

    /// List every tool in the mise registry with security metadata.
    ///
    /// Invokes `mise registry --json --security` and returns the parsed list.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn registry_with_security(&self) -> MiseResult<Vec<RegistryTool>> {
        self.run_json(["registry", "--json", "--security"]).await
    }

    /// List registry entries filtered by backend.
    ///
    /// Fetches the full registry and filters results to those whose backends
    /// contain the given backend string.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn registry_by_backend(&self, backend: &str) -> MiseResult<Vec<RegistryTool>> {
        let all = self.registry().await?;
        Ok(all
            .into_iter()
            .filter(|t| t.backends.iter().any(|b| b.contains(backend)))
            .collect())
    }

    /// Look up a single tool in the registry by name.
    ///
    /// Returns `None` if no tool with the given name exists in the registry.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn registry_tool(&self, name: &str) -> MiseResult<Option<RegistryTool>> {
        let all = self.registry().await?;
        Ok(all
            .into_iter()
            .find(|t| t.short == name || t.aliases.contains(&name.to_owned())))
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

    fn build_mise(fake: Arc<FakeRunner>) -> Mise {
        Mise::builder()
            .runner(fake as Arc<dyn toride_runner::AsyncRunner>)
            .binary(crate::binary::MiseBinary::from_path("/usr/bin/mise"))
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_registry_parses_json() {
        let json = r#"[{"short":"node","backends":["core:node"],"description":"Node.js","aliases":[]},{"short":"npm:prettier","backends":["npm:prettier"],"description":"Prettier","aliases":[]}]"#;
        let fake = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(json)));
        let mise = build_mise(fake.clone());

        let tools = mise.registry().await.unwrap();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].short, "node");
        assert_eq!(tools[0].backends, vec!["core:node"]);
        assert_eq!(tools[1].short, "npm:prettier");
        assert_eq!(tools[1].backends, vec!["npm:prettier"]);

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"registry".to_string()));
        assert!(calls[0].args.contains(&"--json".to_string()));
    }

    #[tokio::test]
    async fn test_registry_parses_legacy_format() {
        let json = r#"[{"name":"node","description":"Node.js","backend":"core"}]"#;
        let fake = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(json)));
        let mise = build_mise(fake.clone());

        let tools = mise.registry().await.unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].short, "node");
        assert_eq!(tools[0].backends, vec!["core"]);
    }

    #[tokio::test]
    async fn test_registry_lookup() {
        let json =
            r#"[{"short":"node","backends":["core:node"],"description":"Node.js","aliases":[]}]"#;
        let fake = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(json)));
        let mise = build_mise(fake.clone());

        let tools = mise.registry_lookup("node").await.unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].short, "node");

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"registry".to_string()));
        assert!(calls[0].args.contains(&"node".to_string()));
        assert!(calls[0].args.contains(&"--json".to_string()));
    }
}
