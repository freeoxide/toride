//! Mise binary discovery: locate the `mise` executable on the host.
//!
//! The `$PATH` + managed-location probe is delegated to
//! `toride_installer`'s offline [`Detector`](toride_installer::Detector)
//! over that crate's mise descriptor, so "where we look" cannot drift from
//! where the installer's install path writes. This crate deliberately keeps
//! the env-var and app-bundled tiers the detector does not model: env
//! overrides stay out of `Detector` itself, so they must be consulted
//! before it.

use camino::Utf8PathBuf;
use toride_installer::Detector;
use toride_installer::tools::mise::mise_tool;

use super::version::MiseVersion;
use crate::error::MiseError;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// MiseBinary
// ---------------------------------------------------------------------------

/// Represents a discovered `mise` binary on the system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiseBinary {
    /// Absolute path to the `mise` executable.
    pub path: Utf8PathBuf,
    /// Parsed version, if `mise --version` has been queried.
    pub version: Option<MiseVersion>,
}

impl MiseBinary {
    /// Discover the `mise` binary using a cascade of strategies.
    ///
    /// 1. `MISE_BIN` environment variable (must point to an existing file).
    ///    Kept above the detector on purpose: `Detector` deliberately has no
    ///    env-override tier.
    /// 2. `toride_installer`'s offline `Detector` over the mise descriptor:
    ///    the real `$PATH` first (the binary a shell would execute), then
    ///    the managed install location (`~/.local/bin/mise`) — the same
    ///    precedence the installer's install path uses, so discovery cannot
    ///    drift from installs. The detector probes `mise --version` (then
    ///    `-V`) and reports it in `version`; a failed probe degrades to
    ///    `version: None`, never to a missed binary. A non-UTF-8 `$PATH`
    ///    hit is treated as absent by the detector (it falls through to the
    ///    later tiers) rather than surfacing as an error.
    /// 3. The system-wide `/usr/local/bin/mise`, kept as an extra fallback:
    ///    the detector models only `$PATH` and the managed location, and a
    ///    PATH-scrubbed host with a system-wide mise must still be found.
    /// 4. App-bundled binary path (alongside the current executable).
    ///
    /// Discovery performs blocking work: tier 2 runs the detector's
    /// `mise --version` / `-V` subprocess probes, each bounded by
    /// [`DEFAULT_PROBE_TIMEOUT`](toride_installer::DEFAULT_PROBE_TIMEOUT).
    /// Sync callers may use this freely; async callers must go through
    /// [`MiseBinary::discover_async`] so the probes stay off the async
    /// runtime worker.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::BinaryNotFound`] if none of the strategies succeed.
    pub fn discover() -> MiseResult<Self> {
        // 1. MISE_BIN env var
        if let Ok(val) = std::env::var("MISE_BIN") {
            let path = Utf8PathBuf::from(&val);
            if path.is_file() {
                return Ok(Self {
                    path,
                    version: None,
                });
            }
        }

        // 2. toride-installer's offline detector: `$PATH`, then the managed
        //    install location. Never errors and never touches the network.
        let status = Detector::new().detect(&mise_tool());
        if let Some(path) = status.path() {
            return Ok(Self {
                path: path.clone(),
                version: status.version().map(MiseVersion::from),
            });
        }

        // 3. System-wide fallback the detector does not model.
        let system_wide = Utf8PathBuf::from("/usr/local/bin/mise");
        if system_wide.is_file() {
            return Ok(Self {
                path: system_wide,
                version: None,
            });
        }

        // 4. App-bundled binary path: look for `mise` alongside the current executable.
        if let Ok(exe) = std::env::current_exe()
            && let Some(dir) = exe.parent()
        {
            let bundled = dir.join("mise");
            if bundled.is_file()
                && let Ok(utf8) = Utf8PathBuf::from_path_buf(bundled)
            {
                return Ok(Self {
                    path: utf8,
                    version: None,
                });
            }
        }

        Err(MiseError::BinaryNotFound)
    }

    /// `spawn_blocking` wrapper over [`MiseBinary::discover`] — the cascade
    /// ends in the detector's sync subprocess probes (`mise --version`,
    /// then `-V`), which must not run on an async runtime worker.
    ///
    /// Parity: returns exactly what `discover` returns. A blocking task
    /// that panics or is cancelled has no other error channel here, so it
    /// surfaces as [`MiseError::Io`] (tokio's `JoinError` → `io::Error`
    /// conversion records "task panicked" / "task was cancelled").
    pub async fn discover_async() -> MiseResult<Self> {
        tokio::task::spawn_blocking(Self::discover)
            .await
            .map_err(std::io::Error::from)?
    }

    /// Create a [`MiseBinary`] from a known path without performing discovery.
    ///
    /// The caller is responsible for ensuring the path points to a valid
    /// `mise` executable.
    pub fn from_path(path: impl Into<Utf8PathBuf>) -> Self {
        Self {
            path: path.into(),
            version: None,
        }
    }

    /// Return the binary path as a string slice.
    pub fn as_str(&self) -> &str {
        self.path.as_str()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use camino::Utf8Path;
    use std::sync::Arc;
    use tempfile::TempDir;
    use toride_installer::ToolStatus;
    use toride_runner::{CommandOutput, CommandSpec, FakeRunner};

    /// The exact version-probe spec `Detector` issues — registered as a
    /// strict `FakeRunner` response (which ignores `timeout` when
    /// matching) and asserted on below.
    fn probe_spec(bin: &Utf8Path, arg: &str) -> CommandSpec {
        CommandSpec::new(bin.as_str())
            .arg(arg)
            .timeout(toride_installer::DEFAULT_PROBE_TIMEOUT)
            .stdin_null(true)
    }

    /// A tempdir as `Utf8PathBuf` (tempdirs are UTF-8 on CI hosts).
    fn utf8_dir(dir: &TempDir) -> Utf8PathBuf {
        Utf8PathBuf::from_path_buf(dir.path().to_owned()).expect("tempdir path is utf-8")
    }

    #[test]
    fn from_path_sets_version_none() {
        let bin = MiseBinary::from_path("/usr/local/bin/mise");
        assert_eq!(bin.path.as_str(), "/usr/local/bin/mise");
        assert!(bin.version.is_none());
    }

    #[test]
    fn as_str_returns_path() {
        let bin = MiseBinary::from_path("/usr/bin/mise");
        assert_eq!(bin.as_str(), "/usr/bin/mise");
    }

    #[test]
    fn managed_location_matches_detector_for_the_mise_descriptor() {
        // The discovery contract this adoption rests on: the directory the
        // installer's install path writes to is exactly what `Detector`
        // (and therefore tier 2 of `discover`) consults — here pinned with
        // an explicit override; the default tier resolves to `~/.local/bin`
        // on both sides because it is the same `Detector` code.
        let tmp = TempDir::new().unwrap();
        let dir = utf8_dir(&tmp);
        let tool = mise_tool();
        assert_eq!(
            Detector::managed_path(&tool, Some(&dir)).unwrap(),
            dir.join(&tool.bin_name)
        );
    }

    /// ENVIRONMENTAL: drives the adopted detector over the real mise
    /// descriptor with a strict `FakeRunner`, pinning the precedence the
    /// discovery cascade relies on — the managed copy is found off `$PATH`
    /// and its version comes from the `--version` probe. Skipped when the
    /// host has a real mise on `$PATH` (the PATH hit would win with no
    /// registered response); `$PATH` is never mutated here.
    #[test]
    fn detector_finds_managed_mise_with_probed_version() {
        if toride_runner::discovery::find_binary(mise_tool().bin_name.as_str()).is_ok() {
            eprintln!("mise found on $PATH; skipping managed-precedence test");
            return;
        }

        let tmp = TempDir::new().unwrap();
        let dir = utf8_dir(&tmp);
        let tool = mise_tool();
        let bin = dir.join(&tool.bin_name);
        std::fs::write(&bin, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))
                .expect("chmod dummy executable");
        }

        let fake = FakeRunner::new().strict().respond(
            probe_spec(&bin, "--version"),
            CommandOutput::from_stdout("mise 2026.9.1 linux-x64"),
        );
        let status = Detector::builder()
            .runner(Arc::new(fake))
            .install_dir(dir)
            .build()
            .detect(&tool);

        let ToolStatus::Managed { path, version } = status else {
            panic!("the managed copy must be found off $PATH, got {status:?}");
        };
        assert_eq!(path, bin);
        let version = version.expect("the fake probe answered --version");
        assert_eq!(version.raw, "2026.9.1");
        assert_eq!(version.line, "mise 2026.9.1 linux-x64");
    }

    /// Parity (the same shape as the installer's `detect_async_matches_
    /// detect`): `discover_async` runs the identical cascade on the
    /// blocking pool, so both routes must agree — the same binary when one
    /// is found, a shared miss verdict otherwise.
    #[tokio::test]
    async fn discover_async_matches_discover() {
        let sync = MiseBinary::discover();
        let discovered = MiseBinary::discover_async().await;
        assert_eq!(discovered.is_ok(), sync.is_ok());
        if let (Ok(expected), Ok(found)) = (&sync, &discovered) {
            assert_eq!(found, expected);
        }
    }
}
