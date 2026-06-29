//! `CommandSpec` snapshot tests for toride-mise.
//!
//! Builds a [`CommandSpec`] for each major mise operation and snapshots the
//! resulting args/program via `insta::assert_debug_snapshot!`. This catches
//! accidental changes to the command-line interface.

#![cfg(feature = "json")]

use std::path::Path;
use std::time::Duration;

use toride_runner::CommandSpec;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal `CommandSpec` for `mise`.
fn mise_spec(args: &[&str]) -> CommandSpec {
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    CommandSpec::new("mise").args(args).redact(false)
}

/// Build a redacted `CommandSpec` for `mise`.
///
/// Used for commands like `mise env` that can echo tool-managed secrets in
/// their arguments or captured output. Mirrors the central `redact(true)`
/// applied by [`toride_mise`]'s `build_command`.
fn mise_spec_redacted(args: &[&str]) -> CommandSpec {
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    CommandSpec::new("mise").args(args).redact(true)
}

/// Build a `CommandSpec` with a custom cwd.
fn mise_spec_with_cwd(args: &[&str], cwd: &Path) -> CommandSpec {
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    CommandSpec::new("mise").args(args).cwd(cwd).redact(false)
}

/// Build a `CommandSpec` with env vars and a timeout.
fn mise_spec_full(args: &[&str], env: Vec<(String, String)>, timeout: Duration) -> CommandSpec {
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    CommandSpec::new("mise")
        .args(args)
        .envs(env)
        .timeout(timeout)
        .redact(true)
}

// ---------------------------------------------------------------------------
// Snapshot tests — one per major mise operation
// ---------------------------------------------------------------------------

#[test]
fn command_spec_ls() {
    let spec = mise_spec(&["ls", "--output=json"]);
    insta::assert_debug_snapshot!("command_spec_ls", spec);
}

#[test]
fn command_spec_ls_installed() {
    let spec = mise_spec(&["ls", "--installed", "--output=json"]);
    insta::assert_debug_snapshot!("command_spec_ls_installed", spec);
}

#[test]
fn command_spec_ls_missing() {
    let spec = mise_spec(&["ls", "--missing", "--output=json"]);
    insta::assert_debug_snapshot!("command_spec_ls_missing", spec);
}

#[test]
fn command_spec_ls_current() {
    let spec = mise_spec(&["ls", "--current", "--output=json"]);
    insta::assert_debug_snapshot!("command_spec_ls_current", spec);
}

#[test]
fn command_spec_ls_remote() {
    let spec = mise_spec(&["ls-remote", "node", "--output=json"]);
    insta::assert_debug_snapshot!("command_spec_ls_remote", spec);
}

#[test]
fn command_spec_ls_remote_with_prefix() {
    let spec = mise_spec(&["ls-remote", "node@22", "--output=json"]);
    insta::assert_debug_snapshot!("command_spec_ls_remote_with_prefix", spec);
}

#[test]
fn command_spec_latest() {
    let spec = mise_spec(&["latest", "node", "--output=json"]);
    insta::assert_debug_snapshot!("command_spec_latest", spec);
}

#[test]
fn command_spec_env() {
    let spec = mise_spec_redacted(&["env", "--json"]);
    insta::assert_debug_snapshot!("command_spec_env", spec);
}

#[test]
fn command_spec_env_with_tool() {
    let spec = mise_spec_redacted(&["env", "--json", "node@22"]);
    insta::assert_debug_snapshot!("command_spec_env_with_tool", spec);
}

#[test]
fn command_spec_env_dotenv() {
    let spec = mise_spec_redacted(&["env", "--dotenv"]);
    insta::assert_debug_snapshot!("command_spec_env_dotenv", spec);
}

#[test]
fn command_spec_env_shell() {
    let spec = mise_spec_redacted(&["env", "--shell", "bash"]);
    insta::assert_debug_snapshot!("command_spec_env_shell", spec);
}

#[test]
fn command_spec_registry() {
    let spec = mise_spec(&["registry", "--output=json"]);
    insta::assert_debug_snapshot!("command_spec_registry", spec);
}

#[test]
fn command_spec_registry_search() {
    let spec = mise_spec(&["registry", "search", "node", "--output=json"]);
    insta::assert_debug_snapshot!("command_spec_registry_search", spec);
}

#[test]
fn command_spec_outdated() {
    let spec = mise_spec(&["outdated", "--output=json"]);
    insta::assert_debug_snapshot!("command_spec_outdated", spec);
}

#[test]
fn command_spec_upgrade() {
    let spec = mise_spec(&["upgrade", "node"]);
    insta::assert_debug_snapshot!("command_spec_upgrade", spec);
}

#[test]
fn command_spec_upgrade_all() {
    let spec = mise_spec(&["upgrade"]);
    insta::assert_debug_snapshot!("command_spec_upgrade_all", spec);
}

#[test]
fn command_spec_upgrade_with_flags() {
    let spec = mise_spec(&["upgrade", "--bump", "--dry-run", "--jobs", "4", "node"]);
    insta::assert_debug_snapshot!("command_spec_upgrade_with_flags", spec);
}

#[test]
fn command_spec_install() {
    let spec = mise_spec(&["install", "node@22"]);
    insta::assert_debug_snapshot!("command_spec_install", spec);
}

#[test]
fn command_spec_use() {
    let spec = mise_spec(&["use", "--global", "node@22"]);
    insta::assert_debug_snapshot!("command_spec_use", spec);
}

#[test]
fn command_spec_uninstall() {
    let spec = mise_spec(&["uninstall", "node@22.0.0"]);
    insta::assert_debug_snapshot!("command_spec_uninstall", spec);
}

#[test]
fn command_spec_settings_ls() {
    let spec = mise_spec(&["settings", "ls", "--output=json"]);
    insta::assert_debug_snapshot!("command_spec_settings_ls", spec);
}

#[test]
fn command_spec_version() {
    let spec = mise_spec(&["--version"]);
    insta::assert_debug_snapshot!("command_spec_version", spec);
}

#[test]
fn command_spec_with_cwd() {
    let spec = mise_spec_with_cwd(&["env", "--json"], Path::new("/project/dir"));
    insta::assert_debug_snapshot!("command_spec_with_cwd", spec);
}

#[test]
fn command_spec_with_env_and_timeout() {
    let spec = mise_spec_full(
        &["ls", "--output=json"],
        vec![("MISE_DATA_DIR".into(), "/tmp/mise".into())],
        Duration::from_secs(30),
    );
    insta::assert_debug_snapshot!("command_spec_with_env_and_timeout", spec);
}

#[test]
fn command_spec_redacted() {
    let args: Vec<String> = vec!["ls".into(), "--output=json".into()];
    let spec = CommandSpec::new("mise").args(args).redact(true);
    insta::assert_debug_snapshot!("command_spec_redacted", spec);
}

#[test]
fn command_spec_prune() {
    let spec = mise_spec(&["prune", "--dry-run"]);
    insta::assert_debug_snapshot!("command_spec_prune", spec);
}

#[test]
fn command_spec_where() {
    let spec = mise_spec(&["where", "node"]);
    insta::assert_debug_snapshot!("command_spec_where", spec);
}
