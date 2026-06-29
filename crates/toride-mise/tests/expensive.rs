//! Expensive integration tests that install real tools via mise.
//!
//! All tests are gated behind `TORIDE_MISE_EXPENSIVE=1`. These tests are
//! slow (tens of seconds to minutes) because they download and install real
//! tool versions. Run with:
//!
//! ```sh
//! TORIDE_MISE_EXPENSIVE=1 cargo test --test expensive --features json
//! ```

#![cfg(feature = "json")]

use std::env;
use std::sync::Arc;

use toride_mise::Mise;
use toride_runner::tokio_runner::TokioRunner;

// ---------------------------------------------------------------------------
// Gate helper
// ---------------------------------------------------------------------------

/// Returns `true` when the `TORIDE_MISE_EXPENSIVE` env var is set to `1`.
fn should_run_expensive() -> bool {
    matches!(env::var("TORIDE_MISE_EXPENSIVE").as_deref(), Ok("1"))
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
// Expensive tests
// ---------------------------------------------------------------------------

/// Install a small, fast tool. `usage` is a lightweight binary that downloads
/// quickly, making it suitable for a quick smoke test of the install pipeline.
#[tokio::test]
async fn install_tiny_tool() {
    if !should_run_expensive() {
        return;
    }
    let mise = build_real_mise();
    mise.install("usage@latest")
        .await
        .expect("install usage failed");

    // Verify the tool shows up in `mise ls`.
    let output = mise.run_checked(["ls", "--json"]).await.expect("ls failed");
    let stdout = output.stdout_trimmed();
    assert!(
        stdout.contains("usage"),
        "usage not found in mise ls output after install"
    );
}

/// Install node@22. This is expensive because the Node.js tarball is large.
#[tokio::test]
async fn node_install() {
    if !should_run_expensive() {
        return;
    }
    let mise = build_real_mise();
    mise.install("node@22")
        .await
        .expect("install node@22 failed");

    let output = mise.run_checked(["ls", "--json"]).await.expect("ls failed");
    let stdout = output.stdout_trimmed();
    assert!(
        stdout.contains("node"),
        "node not found in mise ls output after install"
    );
}

/// Install python@3.12. This is expensive because `CPython` must be compiled or
/// a large binary distribution must be downloaded.
#[tokio::test]
async fn python_install() {
    if !should_run_expensive() {
        return;
    }
    let mise = build_real_mise();
    mise.install("python@3.12")
        .await
        .expect("install python@3.12 failed");

    let output = mise.run_checked(["ls", "--json"]).await.expect("ls failed");
    let stdout = output.stdout_trimmed();
    assert!(
        stdout.contains("python"),
        "python not found in mise ls output after install"
    );
}
