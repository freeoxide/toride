//! File permission helpers.
//!
//! Utilities for setting and checking Unix file permissions and ownership.
//! Used for security-sensitive files like SSH configs, `Fail2Ban` configs,
//! and other files that must not be world-readable or world-writable.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use tracing;

use crate::error::{Error, Result};

/// Set file permissions to the given Unix mode.
///
/// `mode` is a raw Unix permission bits value (e.g. `0o600` for
/// owner-only read/write, `0o644` for owner read/write, group/other read).
///
/// # Errors
///
/// Returns [`Error::Io`] if the metadata call or permission change fails.
pub fn set_permissions(path: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    tracing::debug!(path = %path.display(), mode = format!("{mode:o}"), "permissions set");
    Ok(())
}

/// Verify that a file is **not** world-writable.
///
/// Checks the "other" write bit (`0o002`). If set, returns an error.
///
/// # Errors
///
/// Returns [`Error::PermissionDenied`] if the file is world-writable.
/// Returns [`Error::Io`] if the file metadata cannot be read.
pub fn check_not_world_writable(path: &Path) -> Result<()> {
    let mode = fs::metadata(path)?.mode();
    if mode & 0o002 != 0 {
        return Err(Error::PermissionDenied(format!(
            "{} is world-writable (mode {:o}); refusing to use",
            path.display(),
            mode & 0o777
        )));
    }
    Ok(())
}

/// Check whether the file at `path` is owned by root (uid 0).
///
/// Returns `Ok(true)` if the owner uid is 0, `Ok(false)` otherwise.
///
/// # Errors
///
/// Returns [`Error::Io`] if the file metadata cannot be read.
pub fn check_owner_is_root(path: &Path) -> Result<bool> {
    let uid = fs::metadata(path)?.uid();
    Ok(uid == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use tempfile::TempDir;

    #[test]
    fn check_not_world_writable_passes_for_0o644_file() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let path = dir.path().join("secure.txt");

        fs::write(&path, "data").expect("write should succeed");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("set_permissions should succeed");

        let result = check_not_world_writable(&path);
        assert!(result.is_ok(), "0o644 file should not be world-writable");
    }

    #[test]
    fn check_not_world_writable_fails_for_0o666_file() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let path = dir.path().join("insecure.txt");

        fs::write(&path, "data").expect("write should succeed");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666))
            .expect("set_permissions should succeed");

        let result = check_not_world_writable(&path);
        assert!(
            result.is_err(),
            "0o666 file should be flagged as world-writable"
        );

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("world-writable"),
            "error message should mention world-writable: {err_msg}"
        );
    }

    #[test]
    fn check_not_world_writable_passes_for_0o600_file() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let path = dir.path().join("private.txt");

        fs::write(&path, "data").expect("write should succeed");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("set_permissions should succeed");

        let result = check_not_world_writable(&path);
        assert!(result.is_ok(), "0o600 file should not be world-writable");
    }

    #[test]
    fn check_not_world_writable_fails_for_nonexistent_file() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let path = dir.path().join("missing.txt");

        let result = check_not_world_writable(&path);
        assert!(result.is_err(), "non-existent file should return an error");
    }

    #[test]
    fn set_permissions_changes_file_mode() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let path = dir.path().join("perms.txt");

        fs::write(&path, "data").expect("write should succeed");

        set_permissions(&path, 0o755).expect("set_permissions should succeed");

        let mode = fs::metadata(&path)
            .expect("metadata should be available")
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755);
    }

    #[test]
    fn set_permissions_to_0o600() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let path = dir.path().join("owner_only.txt");

        fs::write(&path, "data").expect("write should succeed");

        set_permissions(&path, 0o600).expect("set_permissions should succeed");

        let mode = fs::metadata(&path)
            .expect("metadata should be available")
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn set_permissions_fails_for_nonexistent_file() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let path = dir.path().join("missing.txt");

        let result = set_permissions(&path, 0o644);
        assert!(
            result.is_err(),
            "setting permissions on non-existent file should fail"
        );
    }
}
