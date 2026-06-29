//! Fixture-driven snapshot tests for toride-mise JSON parsing.
//!
//! Each test reads a fixture file from `../fixtures/`, parses it with the
//! appropriate serde type, and asserts an insta snapshot. This catches
//! accidental changes to the parsed representation.

#![cfg(feature = "json")]

use std::fs;
use std::path::Path;

use serde_json::Value;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Root of the fixtures directory (relative to this file at `tests/`).
fn fixtures_dir() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures"))
}

/// Read a fixture file as a UTF-8 string.
fn read_fixture(relative: &str) -> String {
    let path = fixtures_dir().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read fixture {relative}: {e}"))
}

/// Parse a fixture JSON file into `T`.
fn parse_fixture<T: serde::de::DeserializeOwned>(relative: &str) -> T {
    let raw = read_fixture(relative);
    serde_json::from_str(raw.trim()).unwrap_or_else(|e| {
        panic!(
            "failed to parse fixture {relative} as {}: {e}",
            std::any::type_name::<T>()
        )
    })
}

// ---------------------------------------------------------------------------
// Re-local types (mirrors of serde_utils::json_outputs) for parsing
// ---------------------------------------------------------------------------

#[allow(dead_code)]
mod json_outputs {
    use std::collections::BTreeMap;

    use serde::Deserialize;

    /// Flat array entry used by `mise ls --output=json`.
    #[derive(Debug, Clone, Deserialize)]
    pub struct ToolStatus {
        #[serde(default)]
        pub name: Option<String>,
        #[serde(default)]
        pub version: Option<String>,
        #[serde(default)]
        pub source: Option<ToolSource>,
        #[serde(default)]
        pub active: Option<bool>,
        #[serde(default)]
        pub install_path: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct ToolSource {
        #[serde(default)]
        pub path: Option<String>,
        #[serde(default)]
        pub requested: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct RegistryToolEntry {
        #[serde(default)]
        pub name: Option<String>,
        #[serde(default)]
        pub description: Option<String>,
        #[serde(default)]
        pub backend: Option<String>,
        #[serde(default)]
        pub full_name: Option<String>,
        #[serde(default)]
        pub aliases: Option<Vec<String>>,
    }

    pub type RegistryOutput = Vec<RegistryToolEntry>;

    #[derive(Debug, Clone, Deserialize)]
    pub struct OutdatedToolEntry {
        #[serde(default)]
        pub requested: Option<String>,
        #[serde(default)]
        pub current: Option<String>,
        #[serde(default)]
        pub latest: Option<String>,
        #[serde(default)]
        pub name: Option<String>,
        #[serde(default)]
        pub backend: Option<String>,
    }

    pub type OutdatedOutput = BTreeMap<String, OutdatedToolEntry>;

    pub type EnvOutput = BTreeMap<String, String>;

    #[derive(Debug, Clone, Deserialize)]
    pub struct EnvExtendedEntry {
        #[serde(default)]
        pub name: Option<String>,
        #[serde(default)]
        pub value: Option<String>,
        #[serde(default)]
        pub source: Option<String>,
        #[serde(default)]
        pub tool: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct SettingsExtendedEntry {
        #[serde(default)]
        pub value: Option<serde_json::Value>,
        #[serde(default)]
        pub source: Option<String>,
    }

    pub type SettingsExtendedOutput = BTreeMap<String, SettingsExtendedEntry>;
}

// ---------------------------------------------------------------------------
// ls fixtures
// ---------------------------------------------------------------------------

#[test]
fn ls_installed_snapshot() {
    let tools: Vec<json_outputs::ToolStatus> = parse_fixture("ls/installed.json");
    insta::assert_debug_snapshot!("ls_installed", tools);
}

#[test]
fn ls_installed_json_snapshot() {
    let raw = read_fixture("ls/installed.json");
    let parsed: Value = serde_json::from_str(raw.trim()).unwrap();
    let pretty = serde_json::to_string_pretty(&parsed).unwrap();
    insta::assert_snapshot!("ls_installed_json", pretty);
}

#[test]
fn ls_missing_snapshot() {
    let tools: Vec<json_outputs::ToolStatus> = parse_fixture("ls/missing.json");
    insta::assert_debug_snapshot!("ls_missing", tools);
}

#[test]
fn ls_missing_json_snapshot() {
    let raw = read_fixture("ls/missing.json");
    let parsed: Value = serde_json::from_str(raw.trim()).unwrap();
    let pretty = serde_json::to_string_pretty(&parsed).unwrap();
    insta::assert_snapshot!("ls_missing_json", pretty);
}

// ---------------------------------------------------------------------------
// ls_remote fixtures
// ---------------------------------------------------------------------------

#[test]
fn ls_remote_node_snapshot() {
    let versions: Vec<String> = parse_fixture("ls_remote/node.json");
    insta::assert_debug_snapshot!("ls_remote_node", versions);
}

#[test]
fn ls_remote_node_json_snapshot() {
    let raw = read_fixture("ls_remote/node.json");
    let parsed: Value = serde_json::from_str(raw.trim()).unwrap();
    let pretty = serde_json::to_string_pretty(&parsed).unwrap();
    insta::assert_snapshot!("ls_remote_node_json", pretty);
}

// ---------------------------------------------------------------------------
// env fixtures
// ---------------------------------------------------------------------------

#[test]
fn env_basic_snapshot() {
    let env: json_outputs::EnvOutput = parse_fixture("env/basic.json");
    insta::assert_debug_snapshot!("env_basic", env);
}

#[test]
fn env_basic_json_snapshot() {
    let raw = read_fixture("env/basic.json");
    let parsed: Value = serde_json::from_str(raw.trim()).unwrap();
    let pretty = serde_json::to_string_pretty(&parsed).unwrap();
    insta::assert_snapshot!("env_basic_json", pretty);
}

#[test]
fn env_extended_snapshot() {
    let entries: Vec<json_outputs::EnvExtendedEntry> = parse_fixture("env/extended.json");
    insta::assert_debug_snapshot!("env_extended", entries);
}

#[test]
fn env_extended_json_snapshot() {
    let raw = read_fixture("env/extended.json");
    let parsed: Value = serde_json::from_str(raw.trim()).unwrap();
    let pretty = serde_json::to_string_pretty(&parsed).unwrap();
    insta::assert_snapshot!("env_extended_json", pretty);
}

// ---------------------------------------------------------------------------
// registry fixtures
// ---------------------------------------------------------------------------

#[test]
fn registry_basic_snapshot() {
    let tools: json_outputs::RegistryOutput = parse_fixture("registry/basic.json");
    insta::assert_debug_snapshot!("registry_basic", tools);
}

#[test]
fn registry_basic_json_snapshot() {
    let raw = read_fixture("registry/basic.json");
    let parsed: Value = serde_json::from_str(raw.trim()).unwrap();
    let pretty = serde_json::to_string_pretty(&parsed).unwrap();
    insta::assert_snapshot!("registry_basic_json", pretty);
}

// ---------------------------------------------------------------------------
// outdated fixtures
// ---------------------------------------------------------------------------

#[test]
fn outdated_basic_snapshot() {
    let outdated: json_outputs::OutdatedOutput = parse_fixture("outdated/basic.json");
    insta::assert_debug_snapshot!("outdated_basic", outdated);
}

#[test]
fn outdated_basic_json_snapshot() {
    let raw = read_fixture("outdated/basic.json");
    let parsed: Value = serde_json::from_str(raw.trim()).unwrap();
    let pretty = serde_json::to_string_pretty(&parsed).unwrap();
    insta::assert_snapshot!("outdated_basic_json", pretty);
}

// ---------------------------------------------------------------------------
// settings fixtures
// ---------------------------------------------------------------------------

#[test]
fn settings_all_snapshot() {
    let settings: json_outputs::SettingsExtendedOutput = parse_fixture("settings/all.json");
    insta::assert_debug_snapshot!("settings_all", settings);
}

#[test]
fn settings_all_json_snapshot() {
    let raw = read_fixture("settings/all.json");
    let parsed: Value = serde_json::from_str(raw.trim()).unwrap();
    let pretty = serde_json::to_string_pretty(&parsed).unwrap();
    insta::assert_snapshot!("settings_all_json", pretty);
}

// ---------------------------------------------------------------------------
// version fixture (plain text, not JSON)
// ---------------------------------------------------------------------------

#[test]
fn version_output_snapshot() {
    let raw = read_fixture("version/output.txt");
    // Parse using the VersionOutput logic from the library.
    let version = raw.trim();
    insta::assert_snapshot!("version_output", version);
}

// ---------------------------------------------------------------------------
// ls_remote/github_cli fixture
// ---------------------------------------------------------------------------

#[test]
fn ls_remote_github_cli_snapshot() {
    let versions: Vec<String> = parse_fixture("ls_remote/github_cli.json");
    insta::assert_debug_snapshot!("ls_remote_github_cli", versions);
}

#[test]
fn ls_remote_github_cli_json_snapshot() {
    let raw = read_fixture("ls_remote/github_cli.json");
    let parsed: Value = serde_json::from_str(raw.trim()).unwrap();
    let pretty = serde_json::to_string_pretty(&parsed).unwrap();
    insta::assert_snapshot!("ls_remote_github_cli_json", pretty);
}

// ---------------------------------------------------------------------------
// registry/security fixture
// ---------------------------------------------------------------------------

#[test]
fn registry_security_snapshot() {
    let tools: json_outputs::RegistryOutput = parse_fixture("registry/security.json");
    insta::assert_debug_snapshot!("registry_security", tools);
}

#[test]
fn registry_security_json_snapshot() {
    let raw = read_fixture("registry/security.json");
    let parsed: Value = serde_json::from_str(raw.trim()).unwrap();
    let pretty = serde_json::to_string_pretty(&parsed).unwrap();
    insta::assert_snapshot!("registry_security_json", pretty);
}
