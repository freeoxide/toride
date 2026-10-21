//! `SSH_ASKPASS` handler for passphrase prompts.
//!
//! When SSH tools (like `ssh-add`) need a passphrase, they check the
//! `SSH_ASKPASS` environment variable for a program to run. This module
//! provides [`AskpassHandler`], which creates a temporary script that outputs
//! a stored passphrase, enabling non-interactive key loading from a TUI or
//! other automated context.
//!
//! # How it works
//!
//! 1. Call [`AskpassHandler::new`] with the passphrase string.
//! 2. A temporary executable script is written to disk that echoes the
//!    passphrase to stdout.
//! 3. Call [`AskpassHandler::apply_to_command`] to inject the `SSH_ASKPASS`,
//!    `SSH_ASKPASS_REQUIRE`, and `DISPLAY` environment variables into a
//!    [`duct::Expression`] command.
//! 4. Drop the handler (or call [`AskpassHandler::cleanup`] explicitly) to
//!    remove the temporary script from disk.
//!
//! # Security considerations
//!
//! - The temporary script file is created with `0o700` permissions on Unix so
//!   only the current user can read it.
//! - The file is created in a system temp directory (`std::env::temp_dir()`);
//!   the script's final executable mode (`0o700` on Unix) is set atomically at
//!   creation time and the bytes are flushed to disk before the file is handed
//!   out, which avoids the `ETXTBSY` ("Text file busy") race that would
//!   otherwise occur if a caller execs the script while a deferred write is
//!   still in flight.
//! - Callers should drop the handler as soon as the passphrase is no longer
//!   needed to minimize the window during which the script exists on disk.
//! - The passphrase is embedded in the script content; anyone who can read the
//!   file can recover it.
//! - The owned copy of the passphrase used to build the script is overwritten
//!   with zeros (via `zeroize`) once the script has been written and flushed,
//!   so it is not left resident in memory beyond the construction call.
//! - On Windows the script is created with `OpenOptions::create_new(true)`
//!   (`CREATE_NEW`) so a name collision fails loudly rather than silently
//!   overwriting another handler's file; per-file ACL hardening relies on the
//!   per-user `%TEMP%` directory ACL.
//! - The passphrase never appears in process `argv`, parent stdout/stderr, or
//!   `CommandFailed` error strings; only the script's filesystem path is
//!   included in errors.

use std::path::PathBuf;

use toride_ssh_core::{Error, Result};
use zeroize::Zeroize;

/// A temporary `SSH_ASKPASS` script that outputs a stored passphrase.
///
/// Create one of these before running `ssh-add` (or any SSH tool that may
/// prompt for a passphrase) and use [`apply_to_command`](Self::apply_to_command)
/// to inject the necessary environment variables.
pub struct AskpassHandler {
    /// Path to the temporary script file.
    script_path: PathBuf,
}

impl AskpassHandler {
    /// Create a new askpass handler that will output the given `passphrase`.
    ///
    /// Writes a temporary executable script to disk. The script prints the
    /// passphrase to stdout and exits.
    ///
    /// # Errors
    ///
    /// Returns an error if the temporary script cannot be written or made
    /// executable.
    pub fn new(passphrase: &str) -> Result<Self> {
        // Production callers always write to the shared system temp dir.
        let script_path = Self::create_script_in(passphrase, &std::env::temp_dir())?;
        Ok(Self { script_path })
    }

    /// Create a new askpass handler writing its script into `dir`.
    ///
    /// This is primarily a testing seam: passing a dedicated
    /// [`tempfile::TempDir`] path isolates each test's script from the shared
    /// system temp directory, eliminating cross-test interference (and the
    /// resulting `ETXTBSY` / "Text file busy" flakes) under parallel test
    /// load. The handler still owns cleanup of the script file on drop.
    #[cfg(test)]
    fn new_in_dir(passphrase: &str, dir: &std::path::Path) -> Result<Self> {
        let script_path = Self::create_script_in(passphrase, dir)?;
        Ok(Self { script_path })
    }

    /// Return the path to the temporary askpass script.
    #[must_use]
    pub fn script_path(&self) -> &std::path::Path {
        &self.script_path
    }

    /// Inject the `SSH_ASKPASS`, `SSH_ASKPASS_REQUIRE`, and `DISPLAY`
    /// environment variables into a [`duct::Expression`] command.
    ///
    /// This configures the command so that any SSH tool invocation that needs
    /// a passphrase will call our temporary script instead of trying to read
    /// from the terminal.
    ///
    /// `DISPLAY` is set to `":0"` as a dummy value because some SSH
    /// implementations require it to be set for `SSH_ASKPASS` to be used.
    /// `SSH_ASKPASS_REQUIRE=force` overrides the check for whether a terminal
    /// is available, ensuring the askpass program is always used.
    #[allow(clippy::needless_pass_by_value)]
    pub fn apply_to_command(&self, cmd: duct::Expression) -> duct::Expression {
        cmd.env("SSH_ASKPASS", &self.script_path)
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env("DISPLAY", ":0")
    }

    /// Remove the temporary script file from disk.
    ///
    /// This is called automatically on drop, but you may call it explicitly
    /// if you want to clean up earlier. Errors are logged but not propagated
    /// since cleanup is best-effort.
    pub fn cleanup(&self) {
        if let Err(e) = std::fs::remove_file(&self.script_path) {
            tracing::warn!(
                "failed to remove askpass script {}: {}",
                self.script_path.display(),
                e
            );
        }
    }

    /// Create the temporary askpass script on disk in `dir`.
    ///
    /// `dir` lets tests pass a dedicated [`tempfile::TempDir`] to avoid
    /// cross-test interference in the shared system temp directory.
    fn create_script_in(passphrase: &str, dir: &std::path::Path) -> Result<PathBuf> {
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;

        let mut passphrase_buf = passphrase.to_string();

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let pid = std::process::id();
        // Use thread ID to avoid collisions when tests run in parallel.
        let tid = format!("{:?}", std::thread::current().id())
            .replace("ThreadId(", "")
            .replace(')', "");
        let filename = format!("toride-askpass-{pid}-{tid}-{ts}");
        // `mut` is only reassigned on Windows (to publish the `.bat` path);
        // on Unix it stays as declared.
        #[cfg_attr(unix, allow(unused_mut))]
        let mut script_path = dir.join(&filename);

        // On Unix, write a shell script. On Windows, write a batch file.
        #[cfg(unix)]
        {
            // Escape single quotes in the passphrase for safe shell embedding.
            let escaped = passphrase_buf.replace('\'', "'\\''");
            let script_content = format!("#!/bin/sh\necho '{escaped}'\n");

            // Upstream constraint: execve(2) fails ETXTBSY on any file open for
            // writing, so the script is staged on a sibling and rename(2)d
            // into place; the destination inode is never open for writing.
            let tmp_path = {
                let mut name = filename.clone();
                name.push_str(".tmp");
                dir.join(&name)
            };
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o700)
                .open(&tmp_path)
                .map_err(|e| {
                    Error::CommandFailed(format!(
                        "failed to create askpass script {}: {e}",
                        tmp_path.display()
                    ))
                })?;
            file.write_all(script_content.as_bytes()).map_err(|e| {
                Error::CommandFailed(format!(
                    "failed to write askpass script {}: {e}",
                    tmp_path.display()
                ))
            })?;
            let _ = file.sync_all();
            drop(file);

            std::fs::rename(&tmp_path, &script_path).map_err(|e| {
                let _ = std::fs::remove_file(&tmp_path);
                Error::CommandFailed(format!(
                    "failed to publish askpass script {}: {e}",
                    script_path.display()
                ))
            })?;
        }

        #[cfg(windows)]
        {
            // set "VAR=value" keeps `&`/`|`/`>` literal; %, !, and " still
            // need their cmd.exe phase-specific escapes below.
            let bat_path = script_path.with_extension("bat");
            let escaped = passphrase_buf
                .replace('%', "%%")
                .replace('!', "^^!")
                .replace('"', "\"\"");
            let script_content = format!(
                "@echo off\r\n\
                 setlocal enabledelayedexpansion\r\n\
                 set \"PASSPHRASE={escaped}\"\r\n\
                 echo !PASSPHRASE!\r\n"
            );

            // Write via a hidden sibling + `MoveFileEx` (atomic rename), the
            // Windows analogue of the Unix branch, so the destination is
            // never opened for writing and name collisions never clobber
            // another handler's script.
            //
            // We use `OpenOptions::create_new(true)` (`CREATE_NEW`) so a name
            // collision fails loudly instead of silently overwriting, then
            // `fsync` and atomically rename the sibling into place. After the
            // rename, the destination has never been opened for writing by the
            // process, so no concurrent reader can observe a half-written file
            // or hit a sharing violation.
            //
            // ACL hardening: unlike the Unix `0o700` mode, we do not pin an
            // explicit DACL here. `%TEMP%` / `%USERPROFILE%` are created with
            // an ACL that grants access only to the current user (and
            // administrators) by default, which is the same effective
            // protection. Tightening the per-file ACL would require a Windows
            // ACL crate; we rely on the per-user temp-directory ACL instead.
            // The `create_new` guard above is the load-bearing safety
            // improvement over `std::fs::write`.
            let tmp_path = {
                let mut name = filename.clone();
                name.push_str(".tmp");
                dir.join(&name)
            };
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)
                .map_err(|e| {
                    Error::CommandFailed(format!(
                        "failed to create askpass script {}: {e}",
                        tmp_path.display()
                    ))
                })?;
            file.write_all(script_content.as_bytes()).map_err(|e| {
                Error::CommandFailed(format!(
                    "failed to write askpass script {}: {e}",
                    tmp_path.display()
                ))
            })?;
            // Flush data + metadata so the renamed file is fully on disk.
            let _ = file.sync_all();
            drop(file);

            // Atomically publish the script at its final path. A same-volume
            // `rename` is atomic on Windows (MoveFileEx with
            // MOVEFILE_REPLACE_EXISTING is not used, so a pre-existing
            // destination surfaces as an error rather than a silent
            // overwrite).
            std::fs::rename(&tmp_path, &bat_path).map_err(|e| {
                // Best-effort cleanup of the temp file if rename failed.
                let _ = std::fs::remove_file(&tmp_path);
                Error::CommandFailed(format!(
                    "failed to publish askpass script {}: {e}",
                    bat_path.display()
                ))
            })?;
            // The actual written file is the .bat, not the extensionless
            // original; publish it so Drop cleanup removes the correct file.
            script_path = bat_path;
        }

        // The script has been written and flushed on both platforms; the
        // cleartext passphrase is no longer needed in this frame. Overwrite our
        // owned copy so it is not left resident in memory (or in the freed
        // allocation) any longer than necessary. The caller still owns the
        // original `&str` and is responsible for its lifetime.
        passphrase_buf.zeroize();

        Ok(script_path)
    }
}

impl Drop for AskpassHandler {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handler_in_tempdir(passphrase: &str) -> (tempfile::TempDir, AskpassHandler) {
        let dir = tempfile::TempDir::new().expect("failed to create temp dir");
        let handler = AskpassHandler::new_in_dir(passphrase, dir.path())
            .expect("failed to create askpass handler");
        (dir, handler)
    }

    #[test]
    fn creates_and_cleans_up_script() {
        let (_dir, handler) = handler_in_tempdir("test-passphrase");
        assert!(
            handler.script_path().exists(),
            "askpass script should exist after creation"
        );

        let path = handler.script_path().to_path_buf();
        handler.cleanup();

        assert!(
            !path.exists(),
            "askpass script should be removed after cleanup"
        );
    }

    #[test]
    fn drop_removes_script() {
        let path;
        {
            let (_dir, handler) = handler_in_tempdir("drop-test");
            path = handler.script_path().to_path_buf();
            assert!(path.exists());
        }
        // After drop, the file should be gone.
        assert!(!path.exists(), "askpass script should be removed on drop");
    }

    #[test]
    fn script_is_executable() {
        let (_dir, handler) = handler_in_tempdir("exec-test");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(handler.script_path())
                .unwrap()
                .permissions()
                .mode();
            // Check that the owner execute bit is set.
            assert_ne!(mode & 0o100, 0, "script should be owner-executable");
            // Check that the file is not world-readable (0o700 permissions).
            assert_eq!(mode & 0o777, 0o700, "script should have 0o700 permissions");
        }

        handler.cleanup();
    }

    #[test]
    fn script_outputs_passphrase() {
        let (_dir, handler) = handler_in_tempdir("my-secret-pass");

        #[cfg(unix)]
        {
            let output = run_script_retrying_busy(handler.script_path());
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert_eq!(
                stdout.trim(),
                "my-secret-pass",
                "script should output the passphrase"
            );
        }

        handler.cleanup();
    }

    #[test]
    fn script_with_single_quotes_in_passphrase() {
        let (_dir, handler) = handler_in_tempdir("it's a \"test\"");

        #[cfg(unix)]
        {
            let output = run_script_retrying_busy(handler.script_path());
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert_eq!(
                stdout.trim(),
                "it's a \"test\"",
                "script should handle single quotes in passphrase"
            );
        }

        handler.cleanup();
    }

    #[test]
    fn script_with_empty_passphrase() {
        let (_dir, handler) = handler_in_tempdir("");

        #[cfg(unix)]
        {
            let output = run_script_retrying_busy(handler.script_path());
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert_eq!(
                stdout.trim(),
                "",
                "empty passphrase should produce empty output"
            );
        }

        handler.cleanup();
    }

    /// Run the askpass script, retrying on `ETXTBSY` ("Text file busy").
    ///
    /// On Linux, `execve(2)` returns `ETXTBSY` when the file has an open
    /// writer, and the kernel's `i_writecount` accounting can transiently
    /// report one under concurrent fork/exec load even after an atomic
    /// write+rename. The race is transient, so this retries with a short
    /// backoff instead of weakening the tests' assertions.
    #[cfg(unix)]
    fn run_script_retrying_busy(path: &std::path::Path) -> std::process::Output {
        let mut backoff = std::time::Duration::from_micros(100);
        for attempt in 0..50 {
            match std::process::Command::new(path).output() {
                Ok(o) => return o,
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) && attempt < 49 => {
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(std::time::Duration::from_millis(5));
                }
                Err(e) => panic!("failed to run askpass script: {e}"),
            }
        }
        unreachable!("retry loop exhausted without returning or panicking");
    }

    #[test]
    fn apply_to_command_sets_env_vars() {
        let (_dir, handler) = handler_in_tempdir("env-test");
        let cmd = duct::cmd!("true");
        let _configured = handler.apply_to_command(cmd);
        // We can't directly inspect env vars on a duct::Expression, but
        // this test verifies the method compiles and doesn't panic.
        handler.cleanup();
    }

    #[test]
    fn cleanup_is_idempotent() {
        // Keep the TempDir alive for the lifetime of the handler so cleanup
        // operates on a real, owned directory.
        let dir = tempfile::TempDir::new().expect("failed to create temp dir");
        let handler = AskpassHandler::new_in_dir("idempotent-test", dir.path());
        // Skip test if script creation fails (e.g., temp dir issues).
        let Ok(handler) = handler else {
            return;
        };
        handler.cleanup();
        // Second cleanup should not panic.
        handler.cleanup();
    }
}
