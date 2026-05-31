//! SSH_ASKPASS handler for passphrase prompts.
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
//! - The file is created in a system temp directory (`std::env::temp_dir()`).
//! - Callers should drop the handler as soon as the passphrase is no longer
//!   needed to minimize the window during which the script exists on disk.
//! - The passphrase is embedded in the script content; anyone who can read the
//!   file can recover it.

use std::path::PathBuf;

use crate::{Error, Result};

/// A temporary SSH_ASKPASS script that outputs a stored passphrase.
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
        let script_path = Self::create_script(passphrase)?;
        Ok(Self { script_path })
    }

    /// Return the path to the temporary askpass script.
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
    pub fn apply_to_command(
        &self,
        cmd: duct::Expression,
    ) -> duct::Expression {
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

    /// Create the temporary askpass script on disk.
    fn create_script(passphrase: &str) -> Result<PathBuf> {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir();
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
        let script_path = dir.join(&filename);

        // On Unix, write a shell script. On Windows, write a batch file.
        #[cfg(unix)]
        {
            // Escape single quotes in the passphrase for safe shell embedding.
            let escaped = passphrase.replace('\'', "'\\''");
            let script_content = format!("#!/bin/sh\necho '{escaped}'\n");

            std::fs::write(&script_path, &script_content).map_err(|e| {
                Error::CommandFailed(format!(
                    "failed to write askpass script {}: {e}",
                    script_path.display()
                ))
            })?;

            // Make the script executable (rwx------).
            std::fs::set_permissions(
                &script_path,
                std::fs::Permissions::from_mode(0o700),
            )
            .map_err(|e| {
                Error::CommandFailed(format!(
                    "failed to set permissions on askpass script: {e}"
                ))
            })?;
        }

        #[cfg(windows)]
        {
            // On Windows, write a batch file that echoes the passphrase.
            //
            // We use `setlocal enabledelayedexpansion` and `set "VAR=value"`
            // so that shell metacharacters like `&`, `|`, `>`, `<`, and `^`
            // are treated as literal text (they are harmless inside the
            // quoted `set` form). The following characters still need
            // escaping:
            //
            // - `%` → `%%` — prevents `%VAR%`-style expansion in the
            //   percent-expansion phase (phase 1).
            // - `!` → `^^!` — the first `^` is consumed by phase-1 caret
            //   processing, leaving `^!`; in the delayed-expansion phase
            //   (phase 3), `^` escapes `!`, yielding a literal `!`.
            // - `"` → `""` — embeds a literal double-quote inside the
            //   `set "VAR=value"` assignment (Windows 10+ / Server 2016+).
            let bat_path = script_path.with_extension("bat");
            let escaped = passphrase
                .replace('%', "%%")
                .replace('!', "^^!")
                .replace('"', "\"\"");
            let script_content = format!(
                "@echo off\r\n\
                 setlocal enabledelayedexpansion\r\n\
                 set \"PASSPHRASE={escaped}\"\r\n\
                 echo !PASSPHRASE!\r\n"
            );
            std::fs::write(&bat_path, &script_content).map_err(|e| {
                Error::CommandFailed(format!(
                    "failed to write askpass script {}: {e}",
                    bat_path.display()
                ))
            })?;
            // Return the actual written path so Drop cleanup removes the
            // correct file (the .bat, not the extensionless original).
            return Ok(bat_path);
        }

        #[allow(unreachable_code)]
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

    #[test]
    fn creates_and_cleans_up_script() {
        let handler = AskpassHandler::new("test-passphrase").unwrap();
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
            let handler = AskpassHandler::new("drop-test").unwrap();
            path = handler.script_path().to_path_buf();
            assert!(path.exists());
        }
        // After drop, the file should be gone.
        assert!(
            !path.exists(),
            "askpass script should be removed on drop"
        );
    }

    #[test]
    fn script_is_executable() {
        let handler = AskpassHandler::new("exec-test").unwrap();

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
        let handler = AskpassHandler::new("my-secret-pass").unwrap();

        #[cfg(unix)]
        {
            let output = std::process::Command::new(handler.script_path())
                .output()
                .expect("failed to run askpass script");
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
        let handler = AskpassHandler::new("it's a \"test\"").unwrap();

        #[cfg(unix)]
        {
            let output = std::process::Command::new(handler.script_path())
                .output()
                .expect("failed to run askpass script");
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
        let handler = AskpassHandler::new("").unwrap();

        #[cfg(unix)]
        {
            let output = std::process::Command::new(handler.script_path())
                .output()
                .expect("failed to run askpass script");
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert_eq!(
                stdout.trim(),
                "",
                "empty passphrase should produce empty output"
            );
        }

        handler.cleanup();
    }

    #[test]
    fn apply_to_command_sets_env_vars() {
        let handler = AskpassHandler::new("env-test").unwrap();
        let cmd = duct::cmd!("true");
        let _configured = handler.apply_to_command(cmd);
        // We can't directly inspect env vars on a duct::Expression, but
        // this test verifies the method compiles and doesn't panic.
        handler.cleanup();
    }

    #[test]
    fn cleanup_is_idempotent() {
        let handler = AskpassHandler::new("idempotent-test");
        // Skip test if script creation fails (e.g., temp dir issues).
        let Ok(handler) = handler else { return; };
        handler.cleanup();
        // Second cleanup should not panic.
        handler.cleanup();
    }
}
