//! Typed `Deserialize` structs for every mise JSON output format.
//!
//! Each struct maps to the JSON produced by a specific `mise` sub-command.
//! All fields are `Option`-wrapped so that variations across mise versions or
//! configurations (e.g. missing keys, new keys added in newer releases) are
//! handled gracefully without causing parse failures.
//!
//! # Mapping to mise commands
//!
//! | Struct            | Command                      |
//! |-------------------|------------------------------|
//! | [`LsOutput`]      | `mise ls --json`             |
//! | [`RegistryOutput`]| `mise registry --json`       |
//! | [`OutdatedOutput`]| `mise outdated --json`       |
//! | [`EnvOutput`]     | `mise env --json`            |
//! | [`DoctorOutput`]  | `mise doctor --json`         |
//! | [`SettingsOutput`]| `mise settings ls --json`    |
//! | [`VersionOutput`] | `mise --version` (parsed)    |

use std::collections::BTreeMap;

use serde::Deserialize;

// ---------------------------------------------------------------------------
// mise ls --json
// ---------------------------------------------------------------------------

/// Output of `mise ls --json`.
///
/// The top-level is a map from tool name to a list of version entries.
/// Example:
///
/// ```json
/// {
///   "node": [
///     {
///       "version": "20.0.0",
///       "install_path": "/Users/jdx/.mise/installs/node/20.0.0",
///       "source": { "type": "mise.toml", "path": "/Users/jdx/mise.toml" }
///     }
///   ]
/// }
/// ```
pub type LsOutput = BTreeMap<String, Vec<LsToolEntry>>;

/// A single tool version entry inside [`LsOutput`].
#[derive(Debug, Clone, Deserialize)]
pub struct LsToolEntry {
    /// The resolved version string (e.g. `"20.0.0"`).
    #[serde(default)]
    pub version: Option<String>,
    /// The filesystem path where this version is installed.
    #[serde(default)]
    pub install_path: Option<String>,
    /// Where the version requirement originated.
    #[serde(default)]
    pub source: Option<LsSource>,
    /// Whether this version is the currently active one.
    #[serde(default)]
    pub active: Option<bool>,
    /// The tool backend (e.g. `"core"`, `"npm"`).
    #[serde(default)]
    pub backend: Option<String>,
    /// The binary path for this tool version, if applicable.
    #[serde(default)]
    pub bin_path: Option<String>,
    /// The requested version string as written in config.
    #[serde(default)]
    pub requested: Option<String>,
}

/// Source information for a tool version entry.
#[derive(Debug, Clone, Deserialize)]
pub struct LsSource {
    /// The type of source (e.g. `"mise.toml"`, `"cli"`).
    #[serde(default)]
    #[serde(rename = "type")]
    pub source_type: Option<String>,
    /// The filesystem path of the source config file.
    #[serde(default)]
    pub path: Option<String>,
}

// ---------------------------------------------------------------------------
// mise registry --json
// ---------------------------------------------------------------------------

/// Output of `mise registry --json`.
///
/// Returns a list of all tools known to the mise registry.
pub type RegistryOutput = Vec<RegistryToolEntry>;

/// A single tool in the mise registry.
///
/// Real mise uses keys `short`, `backends` (array), `description`, and `aliases`.
/// We accept both the real field names and the older `name`/`backend` names for
/// backward compatibility.
#[derive(Debug, Clone, Deserialize)]
pub struct RegistryToolEntry {
    /// The short tool name (e.g. `"node"`, `"npm:prettier"`).
    ///
    /// Real mise uses the JSON key `"short"`. We also accept `"name"` for
    /// backward compatibility.
    #[serde(default, alias = "name")]
    pub short: Option<String>,
    /// A short human-readable description of the tool.
    #[serde(default)]
    pub description: Option<String>,
    /// The backend(s) that provide this tool (e.g. `["core:node"]`).
    ///
    /// Real mise returns an array. We also accept a single string via the
    /// legacy `backend` field.
    #[serde(default, alias = "backend")]
    pub backends: Option<Vec<String>>,
    /// The full name including namespace prefix (e.g. `"core:node"`).
    #[serde(default)]
    pub full_name: Option<String>,
    /// Aliases / short names for this tool.
    #[serde(default)]
    pub aliases: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// mise outdated --json
// ---------------------------------------------------------------------------

/// Output of `mise outdated --json`.
///
/// A map from tool name to its version status.
/// Example:
///
/// ```json
/// {
///   "python": {
///     "requested": "3.11",
///     "current": "3.11.0",
///     "latest": "3.11.1"
///   }
/// }
/// ```
pub type OutdatedOutput = BTreeMap<String, OutdatedToolEntry>;

/// Version status for an outdated tool.
#[derive(Debug, Clone, Deserialize)]
pub struct OutdatedToolEntry {
    /// The version string as requested in config.
    #[serde(default)]
    pub requested: Option<String>,
    /// The currently installed version.
    #[serde(default)]
    pub current: Option<String>,
    /// The latest available version.
    #[serde(default)]
    pub latest: Option<String>,
    /// The binary name or tool identifier, if reported.
    #[serde(default)]
    pub name: Option<String>,
    /// The backend providing the tool, if reported.
    #[serde(default)]
    pub backend: Option<String>,
}

// ---------------------------------------------------------------------------
// mise env --json
// ---------------------------------------------------------------------------

/// Output of `mise env --json`.
///
/// A flat map of environment variable names to their resolved values.
/// Example:
///
/// ```json
/// {
///   "NODE_VERSION": "20.0.0",
///   "PATH": "/Users/jdx/.mise/installs/node/20.0.0/bin:..."
/// }
/// ```
pub type EnvOutput = BTreeMap<String, String>;

/// A single entry in the `mise env --json-extended` output.
///
/// Real mise wraps each value in an object: `{"PATH": {"value": "/usr/bin:..."}}`.
#[derive(Debug, Clone, Deserialize)]
pub struct EnvExtendedEntry {
    /// The resolved value of the environment variable.
    #[serde(default)]
    pub value: Option<String>,
}

/// Output of `mise env --json-extended`.
///
/// A map from environment variable name to an [`EnvExtendedEntry`].
/// Real mise outputs: `{"PATH": {"value": "/usr/bin:/bin"}}`.
pub type EnvExtendedOutput = BTreeMap<String, EnvExtendedEntry>;

// ---------------------------------------------------------------------------
// mise doctor --json
// ---------------------------------------------------------------------------

/// Output of `mise doctor --json`.
///
/// Contains diagnostic information about the mise installation and environment.
/// All fields are `Option`-wrapped so that variations across mise versions are
/// handled gracefully.
#[derive(Debug, Clone, Deserialize)]
pub struct DoctorOutput {
    /// The mise version string (e.g. `"2026.5.18 macos-arm64 (2026-05-31)"`).
    #[serde(default)]
    pub version: Option<String>,
    /// Whether mise shell integration is activated.
    #[serde(default)]
    pub activated: Option<bool>,
    /// Whether shims directory is on PATH.
    #[serde(default)]
    pub shims_on_path: Option<bool>,
    /// Whether a self-update is available.
    #[serde(default)]
    pub self_update_available: Option<bool>,
    /// Aqua registry information.
    #[serde(default)]
    pub aqua: Option<DoctorAqua>,
    /// Build information (target, features, rust version, etc.).
    #[serde(default)]
    pub build_info: Option<DoctorBuildInfo>,
    /// Directory paths reported by mise.
    #[serde(default)]
    pub dirs: Option<DoctorDirs>,
    /// List of detected config files.
    #[serde(default)]
    pub config_files: Option<Vec<String>>,
    /// List of environment files.
    #[serde(default)]
    pub env_files: Option<Vec<String>>,
    /// Environment variables set by mise.
    #[serde(default)]
    pub env_vars: Option<serde_json::Value>,
    /// List of ignored config files.
    #[serde(default)]
    pub ignored_config_files: Option<Vec<String>>,
    /// List of installed / active tool entries.
    #[serde(default)]
    pub tools: Option<Vec<DoctorToolEntry>>,
    /// Any warnings or issues detected by the doctor check.
    #[serde(default)]
    pub warnings: Option<Vec<String>>,
    /// PATH entries as seen by mise.
    #[serde(default)]
    pub paths: Option<Vec<String>>,
    /// Shell information (name, version).
    #[serde(default)]
    pub shell: Option<DoctorShell>,
    /// Loaded plugins or backends (a JSON object map).
    #[serde(default)]
    pub plugins: Option<serde_json::Value>,
    /// Current settings.
    #[serde(default)]
    pub settings: Option<serde_json::Value>,
    /// The resolved toolset (a JSON object map).
    #[serde(default)]
    pub toolset: Option<serde_json::Value>,
    /// The detected operating system (from `mise version --json`, not always
    /// present in `doctor --json`).
    #[serde(default)]
    pub os: Option<String>,
    /// The detected CPU architecture.
    #[serde(default)]
    pub arch: Option<String>,
}

/// Aqua registry information inside [`DoctorOutput`].
#[derive(Debug, Clone, Deserialize)]
pub struct DoctorAqua {
    /// The aqua registry repository (e.g. `"aquaproj/aqua-registry"`).
    #[serde(default)]
    pub baked_in_registry_repository: Option<String>,
    /// The aqua registry tag (e.g. `"v4.519.0"`).
    #[serde(default)]
    pub baked_in_registry_tag: Option<String>,
    /// The number of tools in the baked-in registry.
    #[serde(default)]
    pub baked_in_registry_tools: Option<u64>,
}

/// Build information inside [`DoctorOutput`].
#[derive(Debug, Clone, Deserialize)]
pub struct DoctorBuildInfo {
    /// The compile target triple (e.g. `"aarch64-apple-darwin"`).
    #[serde(default)]
    pub target: Option<String>,
    /// Enabled feature flags (comma-separated string).
    #[serde(default)]
    pub features: Option<String>,
    /// The build timestamp.
    #[serde(default)]
    pub built: Option<String>,
    /// The Rust compiler version used to build mise.
    #[serde(default)]
    pub rust_version: Option<String>,
    /// The build profile (e.g. `"release"`).
    #[serde(default)]
    pub profile: Option<String>,
}

/// Directory paths reported by `mise doctor --json`.
///
/// Nested inside the `dirs` key of the doctor output.
/// Real mise uses keys `cache`, `config`, `data`, `shims`, `state`.
#[derive(Debug, Clone, Deserialize)]
pub struct DoctorDirs {
    /// Path to the mise cache directory.
    #[serde(default)]
    pub cache: Option<String>,
    /// Path to the mise data directory.
    #[serde(default)]
    pub data: Option<String>,
    /// Path to the mise state directory.
    #[serde(default)]
    pub state: Option<String>,
    /// Path to the mise config directory.
    #[serde(default)]
    pub config: Option<String>,
    /// Path to the mise shims directory.
    #[serde(default)]
    pub shims: Option<String>,
}

/// Shell information reported by `mise doctor --json`.
///
/// Real mise outputs: `{"name":"/bin/zsh","version":"zsh 5.9 (arm64-apple-darwin25.0)"}`.
#[derive(Debug, Clone, Deserialize)]
pub struct DoctorShell {
    /// The shell binary path (e.g. `"/bin/zsh"`).
    #[serde(default)]
    pub name: Option<String>,
    /// The shell version string (e.g. `"zsh 5.9 (arm64-apple-darwin25.0)"`).
    #[serde(default)]
    pub version: Option<String>,
}

/// A tool entry inside [`DoctorOutput`].
#[derive(Debug, Clone, Deserialize)]
pub struct DoctorToolEntry {
    /// Tool name.
    #[serde(default)]
    pub name: Option<String>,
    /// The requested version string.
    #[serde(default)]
    pub requested: Option<String>,
    /// The installed version, if present.
    #[serde(default)]
    pub installed: Option<String>,
    /// The config source path.
    #[serde(default)]
    pub source: Option<String>,
    /// The install path on disk.
    #[serde(default)]
    pub install_path: Option<String>,
}

// ---------------------------------------------------------------------------
// mise settings ls --json
// ---------------------------------------------------------------------------

/// Output of `mise settings ls --json`.
///
/// A map from setting key to its current value. Values may be strings, numbers,
/// booleans, or nested structures, so they are represented as
/// `serde_json::Value`.
pub type SettingsOutput = BTreeMap<String, serde_json::Value>;

/// Output of `mise settings ls --json-extended`.
///
/// Each setting includes its value and the source it was defined in.
#[derive(Debug, Clone, Deserialize)]
pub struct SettingsExtendedEntry {
    /// The resolved value of the setting.
    #[serde(default)]
    pub value: Option<serde_json::Value>,
    /// The source file that defined this setting.
    #[serde(default)]
    pub source: Option<String>,
}

/// Extended settings output (with sources) from `mise settings ls --json-extended`.
pub type SettingsExtendedOutput = BTreeMap<String, SettingsExtendedEntry>;

// ---------------------------------------------------------------------------
// mise --version
// ---------------------------------------------------------------------------

/// Output of `mise --version`.
///
/// Mise prints a plain version string (e.g. `"2024.12.1"`) rather than JSON.
/// When parsing, this struct can be used by wrapping the output:
/// `serde_json::from_value(json!({ "version": output }))`.
///
/// For direct string parsing, see [`VersionOutput::parse_version_str`].
#[derive(Debug, Clone, Deserialize)]
pub struct VersionOutput {
    /// The full version string (e.g. `"2024.12.1 macos-arm64 (2024-12-15)"`).
    #[serde(default)]
    pub version: Option<String>,
    /// Just the semver-like portion, if extractable.
    #[serde(default)]
    pub semver: Option<String>,
    /// The target triple, if included in the version output.
    #[serde(default)]
    pub target: Option<String>,
    /// The build date, if included.
    #[serde(default)]
    pub build_date: Option<String>,
    /// The commit hash, if included.
    #[serde(default)]
    pub commit: Option<String>,
}

impl VersionOutput {
    /// Parse the plain-text output of `mise --version` into a [`VersionOutput`].
    ///
    /// Mise prints something like `2024.12.1 macos-arm64 (2024-12-15)`. This
    /// method splits it into its constituent parts on a best-effort basis.
    pub fn parse_version_str(raw: &str) -> Self {
        let trimmed = raw.trim();
        let mut parts = trimmed.splitn(2, ' ');

        let version = parts.next().map(std::borrow::ToOwned::to_owned);
        let rest = parts.next().unwrap_or("");

        // Try to extract target triple (e.g. "macos-arm64").
        let target = rest
            .split_whitespace()
            .next()
            .map(std::borrow::ToOwned::to_owned);

        // Try to extract build date from parentheses.
        let build_date = if let Some(start) = rest.find('(') {
            if let Some(end) = rest.find(')') {
                let inner = &rest[start + 1..end];
                Some(inner.trim().to_owned())
            } else {
                None
            }
        } else {
            None
        };

        Self {
            version,
            semver: None,
            target,
            build_date,
            commit: None,
        }
    }
}

// ---------------------------------------------------------------------------
// mise version --json
// ---------------------------------------------------------------------------

/// Output of `mise version --json`.
///
/// Real mise (2026.x) outputs:
///
/// ```json
/// {
///   "version": "2026.5.18 macos-arm64 (2026-05-31)",
///   "latest": "2026.5.18",
///   "os": "macos",
///   "arch": "arm64",
///   "build_time": "2026-05-31 21:11:31 +00:00"
/// }
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct MiseVersionJson {
    /// The full version string (e.g. `"2026.5.18 macos-arm64 (2026-05-31)"`).
    #[serde(default)]
    pub version: Option<String>,
    /// The latest available version (e.g. `"2026.5.18"`).
    #[serde(default)]
    pub latest: Option<String>,
    /// The OS identifier (e.g. `"macos"`, `"linux"`).
    #[serde(default)]
    pub os: Option<String>,
    /// The CPU architecture (e.g. `"arm64"`, `"x86_64"`).
    #[serde(default)]
    pub arch: Option<String>,
    /// The build timestamp (e.g. `"2026-05-31 21:11:31 +00:00"`).
    #[serde(default)]
    pub build_time: Option<String>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ls_output() {
        let json = r#"{
            "node": [
                {
                    "version": "20.0.0",
                    "install_path": "/home/user/.local/share/mise/installs/node/20.0.0",
                    "source": { "type": "mise.toml", "path": "/project/mise.toml" }
                }
            ]
        }"#;
        let output: LsOutput = serde_json::from_str(json).unwrap();
        assert!(output.contains_key("node"));
        let entries = &output["node"];
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].version.as_deref(), Some("20.0.0"));
        assert_eq!(
            entries[0].source.as_ref().unwrap().source_type.as_deref(),
            Some("mise.toml")
        );
    }

    #[test]
    fn parse_outdated_output() {
        let json = r#"{
            "python": {
                "requested": "3.11",
                "current": "3.11.0",
                "latest": "3.11.1"
            }
        }"#;
        let output: OutdatedOutput = serde_json::from_str(json).unwrap();
        assert!(output.contains_key("python"));
        let entry = &output["python"];
        assert_eq!(entry.requested.as_deref(), Some("3.11"));
        assert_eq!(entry.current.as_deref(), Some("3.11.0"));
        assert_eq!(entry.latest.as_deref(), Some("3.11.1"));
    }

    #[test]
    fn parse_env_output() {
        let json = r#"{
            "NODE_VERSION": "20.0.0",
            "PATH": "/usr/local/bin:/usr/bin"
        }"#;
        let output: EnvOutput = serde_json::from_str(json).unwrap();
        assert_eq!(
            output.get("NODE_VERSION").map(String::as_str),
            Some("20.0.0")
        );
        assert_eq!(output.get("MISSING"), None);
    }

    #[test]
    fn parse_settings_output() {
        let json = r#"{
            "always_keep_download": false,
            "node.mirror_url": "https://npm.taobao.org/mirrors/node"
        }"#;
        let output: SettingsOutput = serde_json::from_str(json).unwrap();
        assert_eq!(
            output["always_keep_download"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            output["node.mirror_url"],
            serde_json::Value::String("https://npm.taobao.org/mirrors/node".to_owned())
        );
    }

    #[test]
    fn parse_version_string() {
        let raw = "2024.12.1 macos-arm64 (2024-12-15)\n";
        let v = VersionOutput::parse_version_str(raw);
        assert_eq!(v.version.as_deref(), Some("2024.12.1"));
        assert_eq!(v.target.as_deref(), Some("macos-arm64"));
        assert_eq!(v.build_date.as_deref(), Some("2024-12-15"));
    }

    #[test]
    fn parse_version_string_bare() {
        let raw = "2024.1.0";
        let v = VersionOutput::parse_version_str(raw);
        assert_eq!(v.version.as_deref(), Some("2024.1.0"));
        assert!(v.target.is_none());
        assert!(v.build_date.is_none());
    }

    #[test]
    fn ls_output_handles_extra_fields_gracefully() {
        let json = r#"{
            "node": [
                {
                    "version": "20.0.0",
                    "some_new_field": "ignored"
                }
            ],
            "python": []
        }"#;
        let output: LsOutput = serde_json::from_str(json).unwrap();
        assert!(output.contains_key("node"));
        assert!(output.contains_key("python"));
        assert!(output["node"][0].install_path.is_none());
    }

    #[test]
    fn registry_output_all_optional() {
        let json = r#"[
            {"short": "node"},
            {"short": "python", "description": "Python language", "backends": ["core:python"]}
        ]"#;
        let output: RegistryOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.len(), 2);
        assert_eq!(output[0].short.as_deref(), Some("node"));
        assert!(output[0].description.is_none());
        assert_eq!(output[1].backends, Some(vec!["core:python".to_owned()]));
    }

    #[test]
    fn doctor_output_minimal() {
        let json = r#"{"version": "2024.12.1"}"#;
        let output: DoctorOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.version.as_deref(), Some("2024.12.1"));
        assert!(output.os.is_none());
        assert!(output.tools.is_none());
        assert!(output.shell.is_none());
        assert!(output.plugins.is_none());
        assert!(output.dirs.is_none());
    }

    #[test]
    fn doctor_output_with_dirs_and_paths() {
        let json = r#"{
            "version": "2024.12.1",
            "dirs": {
                "cache": "/home/user/Library/Caches/mise",
                "data": "/home/user/.local/share/mise",
                "state": "/home/user/.local/state/mise",
                "config": "/home/user/.config/mise",
                "shims": "/home/user/.local/share/mise/shims"
            },
            "paths": ["/home/user/.local/share/mise/shims", "/usr/bin"]
        }"#;
        let output: DoctorOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.version.as_deref(), Some("2024.12.1"));
        let dirs = output.dirs.as_ref().unwrap();
        assert_eq!(
            dirs.cache.as_deref(),
            Some("/home/user/Library/Caches/mise")
        );
        assert_eq!(dirs.data.as_deref(), Some("/home/user/.local/share/mise"));
        assert_eq!(dirs.state.as_deref(), Some("/home/user/.local/state/mise"));
        assert_eq!(dirs.config.as_deref(), Some("/home/user/.config/mise"));
        assert_eq!(
            dirs.shims.as_deref(),
            Some("/home/user/.local/share/mise/shims")
        );
        let paths = output.paths.as_ref().unwrap();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0], "/home/user/.local/share/mise/shims");
    }

    #[test]
    fn doctor_output_with_shell_and_plugins() {
        let json = r#"{
            "version": "2024.12.1",
            "shell": {"name": "/bin/zsh", "version": "zsh 5.9 (arm64-apple-darwin25.0)"},
            "plugins": {}
        }"#;
        let output: DoctorOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.version.as_deref(), Some("2024.12.1"));
        let shell = output.shell.as_ref().unwrap();
        assert_eq!(shell.name.as_deref(), Some("/bin/zsh"));
        assert!(shell.version.as_ref().unwrap().contains("zsh"));
        assert!(output.plugins.is_some());
    }

    #[test]
    fn doctor_output_real_mise_format() {
        // Matches the actual output from mise 2026.5.18
        let json = r#"{
            "activated": false,
            "aqua": {
                "baked_in_registry_repository": "aquaproj/aqua-registry",
                "baked_in_registry_tag": "v4.519.0",
                "baked_in_registry_tools": 2207
            },
            "build_info": {
                "target": "aarch64-apple-darwin",
                "features": "openssl, rustls-native-roots, self_update",
                "built": "Sun, 31 May 2026 21:11:31 +0000",
                "rust_version": "rustc 1.94.1 (e408947bf 2026-03-25)",
                "profile": "release"
            },
            "config_files": [],
            "dirs": {
                "cache": "/Users/test/Library/Caches/mise",
                "config": "/Users/test/.config/mise",
                "data": "/Users/test/.local/share/mise",
                "shims": "/Users/test/.local/share/mise/shims",
                "state": "/Users/test/.local/state/mise"
            },
            "env_files": [],
            "env_vars": {},
            "ignored_config_files": [],
            "paths": ["/Users/test/.local/bin", "/usr/bin"],
            "plugins": {},
            "self_update_available": true,
            "settings": {},
            "shell": {
                "name": "/bin/zsh",
                "version": "zsh 5.9 (arm64-apple-darwin25.0)"
            },
            "shims_on_path": false,
            "toolset": {},
            "version": "2026.5.18 macos-arm64 (2026-05-31)"
        }"#;
        let output: DoctorOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.activated, Some(false));
        assert!(output.aqua.is_some());
        let aqua = output.aqua.as_ref().unwrap();
        assert_eq!(aqua.baked_in_registry_tools, Some(2207));
        assert!(output.build_info.is_some());
        let bi = output.build_info.as_ref().unwrap();
        assert_eq!(bi.target.as_deref(), Some("aarch64-apple-darwin"));
        assert_eq!(bi.profile.as_deref(), Some("release"));
        assert!(output.dirs.is_some());
        let dirs = output.dirs.as_ref().unwrap();
        assert_eq!(
            dirs.cache.as_deref(),
            Some("/Users/test/Library/Caches/mise")
        );
        assert_eq!(dirs.data.as_deref(), Some("/Users/test/.local/share/mise"));
        assert_eq!(output.self_update_available, Some(true));
        assert_eq!(output.shims_on_path, Some(false));
        assert!(output.shell.is_some());
        assert!(output.plugins.is_some());
    }

    #[test]
    fn settings_extended_output() {
        let json = r#"{
            "always_keep_download": {
                "value": false,
                "source": "~/.config/mise/config.toml"
            }
        }"#;
        let output: SettingsExtendedOutput = serde_json::from_str(json).unwrap();
        let entry = &output["always_keep_download"];
        assert_eq!(entry.value, Some(serde_json::Value::Bool(false)));
        assert_eq!(entry.source.as_deref(), Some("~/.config/mise/config.toml"));
    }

    #[test]
    fn version_json_real_output() {
        let json = r#"{
            "version": "2026.5.18 macos-arm64 (2026-05-31)",
            "latest": "2026.5.18",
            "os": "macos",
            "arch": "arm64",
            "build_time": "2026-05-31 21:11:31 +00:00"
        }"#;
        let v: MiseVersionJson = serde_json::from_str(json).unwrap();
        assert_eq!(
            v.version.as_deref(),
            Some("2026.5.18 macos-arm64 (2026-05-31)")
        );
        assert_eq!(v.latest.as_deref(), Some("2026.5.18"));
        assert_eq!(v.os.as_deref(), Some("macos"));
        assert_eq!(v.arch.as_deref(), Some("arm64"));
        assert_eq!(v.build_time.as_deref(), Some("2026-05-31 21:11:31 +00:00"));
    }

    #[test]
    fn env_extended_real_output() {
        let json = r#"{
            "PATH": {
                "value": "/Users/test/.local/bin:/usr/bin"
            }
        }"#;
        let output: EnvExtendedOutput = serde_json::from_str(json).unwrap();
        assert!(output.contains_key("PATH"));
        let entry = &output["PATH"];
        assert_eq!(
            entry.value.as_deref(),
            Some("/Users/test/.local/bin:/usr/bin")
        );
    }
}
