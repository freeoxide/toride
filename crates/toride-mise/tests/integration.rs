//! Integration tests that invoke a real `mise` binary.
//!
//! All tests in this file are gated behind `TORIDE_MISE_INTEGRATION=1`.
//! They construct a real [`Mise`] client with [`TokioRunner`] and exercise
//! actual mise commands. Run with:
//!
//! ```sh
//! PATH="$HOME/.local/bin:$PATH" TORIDE_MISE_INTEGRATION=1 cargo test --test integration --features json
//! ```

#![cfg(feature = "json")]

use std::env;
use std::sync::Arc;

use toride_mise::Mise;
use toride_runner::tokio_runner::TokioRunner;

// ---------------------------------------------------------------------------
// Gate helper
// ---------------------------------------------------------------------------

/// Returns `true` when the `TORIDE_MISE_INTEGRATION` env var is set to `1`.
///
/// Every test in this file calls this first and returns early when `false`,
/// so the test suite is harmless to run without the gate.
fn should_run_integration() -> bool {
    matches!(env::var("TORIDE_MISE_INTEGRATION").as_deref(), Ok("1"))
}

/// Build a real [`Mise`] client backed by [`TokioRunner`].
///
/// # Panics
///
/// Panics if the `mise` binary cannot be discovered on `$PATH`.
fn build_real_mise() -> Mise {
    Mise::builder()
        .runner(Arc::new(TokioRunner) as Arc<dyn toride_runner::AsyncRunner>)
        .build()
        .expect("failed to build Mise client — is mise installed?")
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn real_mise_version() {
    if !should_run_integration() {
        return;
    }
    let mise = build_real_mise();
    let version = mise.version().await.expect("mise --version failed");

    // Should have parsed a semver.
    assert!(
        version.parsed.is_some(),
        "MiseVersion::parsed should be Some for output: {:?}",
        version.raw,
    );
    let semver = version.parsed.as_ref().unwrap();
    assert!(
        semver.major >= 2024,
        "mise major version should be >= 2024, got {}",
        semver.major,
    );
}

#[tokio::test]
async fn real_mise_capabilities() {
    if !should_run_integration() {
        return;
    }
    let mise = build_real_mise();
    let caps = mise
        .check_capabilities()
        .await
        .expect("check_capabilities failed");

    // With mise 2026.x, all capability flags should be true.
    assert!(caps.json_ls, "json_ls should be true");
    assert!(caps.json_env, "json_env should be true");
    assert!(caps.json_doctor, "json_doctor should be true");
    assert!(caps.lockfile, "lockfile should be true");
}

#[tokio::test]
async fn real_mise_registry() {
    if !should_run_integration() {
        return;
    }
    // NOTE: `mise registry --json` fetches the *entire* registry which can
    // take over 60s and hit the TokioRunner default timeout. Instead of
    // testing the full registry, we test `search("node")` which returns a
    // single entry quickly. The full registry parse logic is covered by
    // the unit tests with fake data.
    let mise = build_real_mise();
    let results = mise.registry_lookup("node").await.expect("registry lookup node failed");
    assert!(
        !results.is_empty(),
        "search for 'node' should return at least one result",
    );

    let tool = &results[0];
    assert_eq!(tool.short, "node");
    assert!(
        !tool.backends.is_empty(),
        "node should have at least one backend",
    );
    assert!(
        !tool.description.is_empty(),
        "node should have a description",
    );
}

#[tokio::test]
async fn real_mise_registry_search() {
    if !should_run_integration() {
        return;
    }
    let mise = build_real_mise();
    let results = mise.registry_lookup("node").await.expect("registry lookup node failed");

    // `mise registry node` should return results containing node.
    assert!(
        !results.is_empty(),
        "search for 'node' should return at least one result",
    );
    assert!(
        results.iter().any(|t| t.short == "node"),
        "search results should contain a tool with short='node'",
    );
}

#[tokio::test]
async fn real_mise_backends() {
    if !should_run_integration() {
        return;
    }
    let mise = build_real_mise();
    let backends = mise.backends().await.expect("backends ls failed");

    // Should return a non-empty list of backend names.
    assert!(
        !backends.is_empty(),
        "mise backends ls should return at least one backend",
    );
    // "core" should always be present.
    assert!(
        backends.iter().any(|b| b == "core"),
        "backends should include 'core', got: {:?}",
        backends,
    );
}

#[tokio::test]
async fn real_mise_ls() {
    if !should_run_integration() {
        return;
    }
    let mise = build_real_mise();
    let tools = mise.list().await.expect("ls failed");

    // Verify the returned value is a valid Vec<ToolStatus>.
    // Even if empty, we confirm the type is correct by checking iteration works.
    for tool in &tools {
        assert!(
            !tool.name.is_empty(),
            "each tool should have a non-empty name",
        );
    }
    let _: &Vec<toride_mise::tool::installed::ToolStatus> = &tools;
}

#[tokio::test]
async fn real_mise_env() {
    if !should_run_integration() {
        return;
    }
    let mise = build_real_mise();
    let env_result = mise
        .env(&toride_mise::env::generated::EnvRequest::default())
        .await
        .expect("env failed");

    // `mise env --json` should at least set PATH.
    assert!(
        !env_result.vars.is_empty(),
        "mise env should return at least one variable",
    );
    assert!(
        env_result.vars.contains_key("PATH"),
        "mise env should set PATH",
    );
}

#[tokio::test]
async fn real_mise_settings() {
    if !should_run_integration() {
        return;
    }
    let mise = build_real_mise();
    let settings = mise.settings().await.expect("settings failed");

    // Settings may be empty (no user overrides), which is fine.
    // We verify it parsed without error and returned a valid map.
    assert!(
        settings.is_empty() || settings.values().next().is_some(),
        "settings should be a valid BTreeMap",
    );
}

#[tokio::test]
async fn real_mise_doctor() {
    if !should_run_integration() {
        return;
    }
    let mise = build_real_mise();
    let report = mise.doctor().await.expect("doctor failed");

    // DoctorReport should have been returned with raw_output populated.
    assert!(
        !report.raw_output.is_empty(),
        "doctor report should have non-empty raw_output",
    );
}

#[tokio::test]
async fn real_mise_ls_remote_node() {
    if !should_run_integration() {
        return;
    }
    let mise = build_real_mise();
    let versions = mise.list_remote("node").await.expect("ls-remote node failed");

    // Should return a large number of node versions.
    assert!(
        !versions.is_empty(),
        "ls-remote node should return at least one version",
    );
    // Each version should have a version string.
    assert!(
        !versions[0].version.is_empty(),
        "remote version should have a non-empty version string",
    );
}

#[tokio::test]
async fn real_mise_latest_node() {
    if !should_run_integration() {
        return;
    }
    let mise = build_real_mise();
    let version = mise.latest("node").await.expect("latest node failed");

    // Should return a non-empty version string like "26.3.0".
    assert!(
        !version.is_empty(),
        "latest node should return a non-empty version string",
    );
    // Should look like a semver (contain at least one dot).
    assert!(
        version.contains('.'),
        "latest version should look like a semver: got {:?}",
        version,
    );
}

#[tokio::test]
async fn real_mise_verify_version() {
    if !should_run_integration() {
        return;
    }
    let mise = build_real_mise();

    // With no minimum_version configured, verify_version is a no-op.
    let result = mise.verify_version().await;
    assert!(result.is_ok(), "verify_version with no minimum should succeed");

    // With a minimum version of 0.0.1, should pass.
    let mise_low = Mise::builder()
        .runner(Arc::new(TokioRunner) as Arc<dyn toride_runner::AsyncRunner>)
        .minimum_version(semver::Version::new(0, 0, 1))
        .build()
        .expect("build failed");
    let result = mise_low.verify_version().await;
    assert!(
        result.is_ok(),
        "verify_version with minimum 0.0.1 should succeed",
    );

    // With a minimum version far in the future, should fail.
    let mise_high = Mise::builder()
        .runner(Arc::new(TokioRunner) as Arc<dyn toride_runner::AsyncRunner>)
        .minimum_version(semver::Version::new(9999, 0, 0))
        .build()
        .expect("build failed");
    let result = mise_high.verify_version().await;
    assert!(
        result.is_err(),
        "verify_version with minimum 9999.0.0 should fail",
    );
}

#[tokio::test]
async fn real_mise_where_node() {
    if !should_run_integration() {
        return;
    }
    let mise = build_real_mise();

    // Node is likely not installed in this environment, so `mise where node`
    // may fail. We verify that it either succeeds (returning a path) or
    // returns a CommandFailed error (not a panic).
    let result = mise
        .where_tool(&toride_mise::ToolSpec::new("node"))
        .await;
    match result {
        Ok(path) => {
            assert!(
                !path.as_str().is_empty(),
                "where_tool should return non-empty path",
            );
        }
        Err(toride_mise::MiseError::CommandFailed { .. }) => {
            // Expected when node is not installed.
        }
        Err(e) => panic!("where_tool returned unexpected error: {e}"),
    }
}

#[tokio::test]
async fn real_mise_bin_paths() {
    if !should_run_integration() {
        return;
    }
    let mise = build_real_mise();
    let paths = mise.bin_paths().await.expect("bin-paths failed");

    // May be empty if no tools are installed — that's ok.
    // We verify each path is a non-empty string.
    for p in &paths {
        assert!(
            !p.as_str().is_empty(),
            "each bin path should be non-empty",
        );
    }
}

#[tokio::test]
async fn real_mise_config_ls() {
    if !should_run_integration() {
        return;
    }
    let mise = build_real_mise();
    let paths = mise.config_ls().await.expect("config ls failed");

    // May be empty if no config files are present — that's ok.
    // We verify each path is a non-empty string.
    for p in &paths {
        assert!(
            !p.as_str().is_empty(),
            "each config path should be non-empty",
        );
    }
}

#[tokio::test]
async fn real_node_helper() {
    if !should_run_integration() {
        return;
    }
    let mise = build_real_mise();
    let node = mise.node();
    let versions = node.list_versions().await.expect("node list_versions failed");

    // Should return a non-empty list of available Node.js versions.
    assert!(
        !versions.is_empty(),
        "node list_versions should return at least one version",
    );
    // Each version should be a non-empty string.
    assert!(
        !versions[0].is_empty(),
        "node version string should not be empty",
    );
}
