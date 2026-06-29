//! Optional file read utilities.
//!
//! Provides functions that read a file's contents but return `Ok(None)`
//! instead of an error when the file does not exist. Useful for optional
//! configuration files and data files.

use std::fs;
use std::path::Path;

use tracing;

use crate::error::{Error, Result};

/// Read a file's contents as a UTF-8 string, returning `Ok(None)` if the
/// file does not exist.
///
/// # Errors
///
/// Returns [`Error::Io`] if the file exists but cannot be read, or if the
/// contents are not valid UTF-8.
pub fn read_optional(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(content) => {
            tracing::trace!(path = %path.display(), "file read successfully");
            Ok(Some(content))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::trace!(path = %path.display(), "file not found, returning None");
            Ok(None)
        }
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "failed to read file");
            Err(Error::Io(e))
        }
    }
}

/// Read a file's contents as raw bytes, returning `Ok(None)` if the file
/// does not exist.
///
/// # Errors
///
/// Returns [`Error::Io`] if the file exists but cannot be read.
pub fn read_optional_bytes(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(content) => {
            tracing::trace!(path = %path.display(), "file read as bytes successfully");
            Ok(Some(content))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::trace!(path = %path.display(), "file not found, returning None");
            Ok(None)
        }
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "failed to read file");
            Err(Error::Io(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn read_optional_returns_content_for_existing_file() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let path = dir.path().join("exists.txt");

        fs::write(&path, "file contents").expect("write should succeed");

        let result = read_optional(&path).expect("read_optional should succeed");
        assert_eq!(result, Some("file contents".to_string()));
    }

    #[test]
    fn read_optional_returns_none_for_nonexistent_file() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let path = dir.path().join("does_not_exist.txt");

        let result = read_optional(&path).expect("read_optional should succeed");
        assert_eq!(result, None);
    }

    #[test]
    fn read_optional_returns_err_for_unreadable_file() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let path = dir.path().join("unreadable.txt");

        fs::write(&path, "data").expect("write should succeed");

        // Remove read permission
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000))
            .expect("set_permissions should succeed");

        let result = read_optional(&path);
        // On macOS, a non-root user cannot read a 0o000 file.
        // If running as root (sudo), skip the assertion.
        if !running_as_root() {
            assert!(result.is_err(), "expected error for unreadable file");
        }
    }

    #[test]
    fn read_optional_bytes_returns_correct_bytes() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let path = dir.path().join("bytes.dat");

        let data: Vec<u8> = vec![0x00, 0xFF, 0x80, 0x7F];
        fs::write(&path, &data).expect("write should succeed");

        let result = read_optional_bytes(&path).expect("read_optional_bytes should succeed");
        assert_eq!(result, Some(data));
    }

    #[test]
    fn read_optional_bytes_returns_none_for_nonexistent_file() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let path = dir.path().join("missing.dat");

        let result = read_optional_bytes(&path).expect("read_optional_bytes should succeed");
        assert_eq!(result, None);
    }

    #[test]
    fn read_optional_empty_file_returns_some_empty() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let path = dir.path().join("empty.txt");

        fs::write(&path, "").expect("write should succeed");

        let result = read_optional(&path).expect("read_optional should succeed");
        assert_eq!(result, Some(String::new()));
    }

    /// Check if the current process is running as root (uid 0) by invoking `id -u`.
    fn running_as_root() -> bool {
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
    }
}
