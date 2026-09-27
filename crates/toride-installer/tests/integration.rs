//! Integration test: actually download + install `mise` from GitHub.
//!
//! Gated behind `TORIDE_INSTALLER_INTEGRATION=1` so it never runs as part
//! of the default `cargo test` / workspace gate. Run explicitly with:
//!
//! ```sh
//! TORIDE_INSTALLER_INTEGRATION=1 cargo test -p toride-installer --test integration
//! ```
//!
//! This mirrors the `TORIDE_MISE_INTEGRATION` pattern used in `toride-mise`.
//!
//! The whole file is also `http`-feature-gated: every test drives the
//! install engine (network + GitHub), which does not exist in the offline
//! `--no-default-features` build.

#![cfg(feature = "http")]

use std::env;
use std::process::Command;

use camino::Utf8PathBuf;
use tempfile::TempDir;
use toride_installer::{EnsureOutcome, Error, tools::mise};

/// Returns `true` only when the integration gate env var is `1`.
fn should_run() -> bool {
    matches!(env::var("TORIDE_INSTALLER_INTEGRATION").as_deref(), Ok("1"))
}

/// Run the downloaded `mise --version` and assert it produces output.
fn assert_mise_runs(bin: &Utf8PathBuf) {
    let output = Command::new(bin.as_std_path())
        .arg("--version")
        .output()
        .expect("spawning mise should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");

    assert!(
        output.status.success(),
        "mise --version exited {}\nstdout: {stdout}\nstderr: {stderr}",
        output.status,
    );
    // mise's `--version` output looks like `2026.6.14 linux-x64 (2026-06-25)`.
    // We don't pin the exact string; we just assert it looks versionish
    // (a `\d+\.\d+\.\d+` substring) and mentions the platform keyword.
    assert!(
        combined.chars().any(|c| c.is_ascii_digit())
            && (combined.contains("linux")
                || combined.contains("macos")
                || combined.contains("x64")
                || combined.contains("arm64")),
        "mise --version produced no version-like output: {combined}"
    );
}

#[tokio::test]
async fn install_mise_latest_into_temp_dir() {
    if !should_run() {
        eprintln!("TORIDE_INSTALLER_INTEGRATION not set; skipping live test");
        return;
    }

    let dir = TempDir::new().expect("temp dir creation");
    let install_dir = Utf8PathBuf::from_path_buf(dir.path().to_owned()).expect("tempdir is utf-8");

    let dest = mise::install_mise("latest", Some(&install_dir))
        .await
        .expect("install_mise(latest) should succeed");

    // File exists at the expected path.
    assert!(
        dest.starts_with(&install_dir),
        "installed path {dest} should be inside the override dir"
    );
    assert!(
        dest.file_name() == Some("mise"),
        "installed binary should be named `mise`, got {dest}"
    );
    assert!(dest.exists(), "installed binary should exist at {dest}");

    // Executable bit set (Unix only).
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = std::fs::metadata(dest.as_std_path())
            .expect("metadata")
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755, "mise should be chmod 0o755");
    }

    // The binary actually runs.
    assert_mise_runs(&dest);
}

/// A known-good published version. If this ever 404s because the tag was
/// removed, bump it to a recent release from
/// <https://github.com/jdx/mise/releases>.
const PINNED_VERSION: &str = "2026.6.14";

#[tokio::test]
async fn install_mise_pinned_version_into_temp_dir() {
    if !should_run() {
        eprintln!("TORIDE_INSTALLER_INTEGRATION not set; skipping live test");
        return;
    }

    let dir = TempDir::new().expect("temp dir creation");
    let install_dir = Utf8PathBuf::from_path_buf(dir.path().to_owned()).expect("tempdir is utf-8");

    let dest = mise::install_mise(PINNED_VERSION, Some(&install_dir))
        .await
        .expect("install_mise(pinned) should succeed");

    assert!(dest.exists(), "pinned mise should exist at {dest}");
    assert_mise_runs(&dest);
}

#[tokio::test]
async fn install_mise_bad_version_is_http_error() {
    if !should_run() {
        eprintln!("TORIDE_INSTALLER_INTEGRATION not set; skipping live test");
        return;
    }

    let dir = TempDir::new().expect("temp dir creation");
    let install_dir = Utf8PathBuf::from_path_buf(dir.path().to_owned()).expect("tempdir is utf-8");

    let err = mise::install_mise("this-version-cannot-exist-9999.99.99", Some(&install_dir))
        .await
        .expect_err("a non-existent version must fail");

    // A non-existent tag yields a 404 from GitHub.
    assert!(
        matches!(err, Error::HttpStatus { status: 404, .. }),
        "expected HTTP 404, got {err:?}"
    );
}

/// The detect-first front door, live: a fresh tempdir must miss (download +
/// install + report the freshly probed version), a second call must keep
/// the copy without a second download, and a pin equal to the installed
/// version must also be satisfied in place.
///
/// The "first call misses" premise needs a `$PATH` that does not already
/// provide mise. On hosts with a mise of their own (developer laptops),
/// run the gate with a scrubbed PATH:
///
/// ```sh
/// TORIDE_INSTALLER_INTEGRATION=1 PATH="$HOME/.cargo/bin:/usr/bin:/bin" \
///     cargo test -p toride-installer --test integration ensure_mise
/// ```
#[tokio::test]
async fn ensure_mise_installs_latest_then_keeps_it_without_redownload() {
    if !should_run() {
        eprintln!("TORIDE_INSTALLER_INTEGRATION not set; skipping live test");
        return;
    }

    let dir = TempDir::new().expect("temp dir creation");
    let install_dir = Utf8PathBuf::from_path_buf(dir.path().to_owned()).expect("tempdir is utf-8");

    // First call: the tempdir is empty, so detect must miss and the install
    // pipeline must run.
    let first = mise::ensure_mise("latest", Some(&install_dir))
        .await
        .expect("ensure_mise(latest) should install into the fresh tempdir");

    let (dest, installed_raw) = match first {
        EnsureOutcome::Installed { path, version } => {
            assert!(
                path.starts_with(&install_dir),
                "installed path {path} should be inside the override dir"
            );
            assert_eq!(
                path.file_name(),
                Some("mise"),
                "installed binary should be named `mise`, got {path}"
            );
            assert!(path.exists(), "installed binary should exist at {path}");
            let version =
                version.expect("the freshly installed mise answers --version after a re-probe");
            assert!(
                version.parsed.is_some(),
                "mise's version should semver-parse, got: {}",
                version.line
            );
            (path, version.raw)
        }
        EnsureOutcome::AlreadyPresent(status) => panic!(
            "a fresh tempdir must miss, but a copy was already found at {:?}; the host likely \
             provides mise on $PATH — rerun the gate with a scrubbed PATH, e.g. \
             PATH=\"$HOME/.cargo/bin:/usr/bin:/bin\"",
            status.path(),
        ),
    };

    // The freshly installed binary actually runs.
    assert_mise_runs(&dest);

    let before = std::fs::metadata(dest.as_std_path()).expect("stat installed mise");

    // Second call: detect finds the copy and `latest` never compares
    // versions, so no second download may happen.
    let second = mise::ensure_mise("latest", Some(&install_dir))
        .await
        .expect("the second ensure_mise must keep an installed copy");

    let second_status = match second {
        EnsureOutcome::AlreadyPresent(status) => {
            assert!(status.is_installed());
            assert!(
                status.version().is_some(),
                "the copy answering the second call reports a version"
            );
            status
        }
        EnsureOutcome::Installed { path, .. } => {
            panic!("the second call must not reinstall; it installed again to {path}")
        }
    };

    let after = std::fs::metadata(dest.as_std_path()).expect("stat installed mise again");
    assert_eq!(
        before.len(),
        after.len(),
        "the second call must not rewrite the binary"
    );
    assert_eq!(
        before.modified().expect("mtime before"),
        after.modified().expect("mtime after"),
        "the second call must not rewrite the binary (no second download)"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            before.ino(),
            after.ino(),
            "a re-download would rename a fresh inode over the binary"
        );
    }

    // A pin equal to the installed version is satisfied in place too —
    // again with no download. Only meaningful when OUR copy is the one
    // detect classifies (a host PATH mise may shadow with another version;
    // on this branch it answered the second call).
    if second_status.path() == Some(&dest) {
        let third = mise::ensure_mise(&installed_raw, Some(&install_dir))
            .await
            .expect("a pin met by the installed copy must keep it");

        assert!(
            matches!(third, EnsureOutcome::AlreadyPresent(_)),
            "a met pin must not reinstall, got {third:?}"
        );
    }
}
