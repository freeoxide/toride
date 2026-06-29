//! Atomic file write utilities.
//!
//! Provides functions that write data to a temporary file first and then
//! atomically rename it to the target path. This ensures readers never
//! observe a partially-written file.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use tracing;

use crate::error::{Error, Result};

/// Default mode for atomically-written files: owner-only read/write.
const ATOMIC_FILE_MODE: u32 = 0o600;

/// Write a UTF-8 string to `path` atomically.
///
/// Creates a named temporary file in the same directory as `path`, writes
/// the content, and then renames the temp file to `path`. If the rename
/// fails the temp file is cleaned up automatically.
///
/// The final file is created with mode `0o600` (owner-only read/write) — a
/// safer-by-default choice than the process umask. For config files that a
/// daemon running as a *different* user must read (e.g. an nginx/caddy site
/// config read by a worker process, or a ufw application profile), use
/// [`atomic_write_with_perms`] with `0o644` instead.
///
/// # Errors
///
/// Returns [`Error::AtomicWriteFailed`] if the temp file cannot be created,
/// written to, or persisted (renamed) to the target path.
pub fn atomic_write(path: &Path, content: &str) -> Result<()> {
    atomic_write_bytes(path, content.as_bytes())
}

/// Write raw bytes to `path` atomically.
///
/// Creates a named temporary file in the same directory as `path`, writes
/// the bytes, and then renames the temp file to `path`.
///
/// The final file is created with mode `0o600` (owner-only read/write). For
/// daemon-readable config files that need group/other read permission, use
/// [`atomic_write_with_perms`] with `0o644`.
///
/// # Errors
///
/// Returns [`Error::AtomicWriteFailed`] if the temp file cannot be created,
/// written to, or persisted (renamed) to the target path.
pub fn atomic_write_bytes(path: &Path, content: &[u8]) -> Result<()> {
    atomic_write_bytes_with_mode(path, content, ATOMIC_FILE_MODE)?;
    tracing::debug!(path = %path.display(), "atomic write complete");
    Ok(())
}

/// Best-effort directory fsync used to make atomic renames durable.
///
/// Opens the directory read-only and calls `sync_all()` (which maps to
/// `fsync(2)` on Unix). Any error is traced and swallowed: this is a
/// durability enhancement, not a correctness requirement.
#[cfg(unix)]
fn fsync_dir_best_effort(dir: &Path) {
    match fs::File::open(dir) {
        Ok(handle) => {
            if let Err(e) = handle.sync_all() {
                tracing::trace!(
                    dir = %dir.display(),
                    error = %e,
                    "best-effort directory fsync failed (non-fatal)",
                );
            }
        }
        Err(e) => {
            tracing::trace!(
                dir = %dir.display(),
                error = %e,
                "could not open parent dir for best-effort fsync (non-fatal)",
            );
        }
    }
}

/// No-op on non-Unix targets where directory fsync is unavailable.
#[cfg(not(unix))]
fn fsync_dir_best_effort(_dir: &Path) {}

/// Write a UTF-8 string to `path` atomically, then set file permissions.
///
/// Combines [`atomic_write`] with a `chmod` to the specified `perms` mode
/// (e.g. `0o600` for owner-only read/write).
///
/// # Errors
///
/// Returns [`Error::AtomicWriteFailed`] if the write or persist fails.
/// Returns [`Error::Io`] if the permission change fails.
pub fn atomic_write_with_perms(path: &Path, content: &str, perms: u32) -> Result<()> {
    atomic_write_bytes_with_mode(path, content.as_bytes(), perms)?;

    // Safety-net chmod after the rename. The temp file was already created
    // with `perms`, so rename(2) preserves the mode and this should normally
    // be a no-op. If it fails for any reason, roll back by removing the final
    // file so we never leave a file with the wrong mode behind.
    if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(perms)) {
        let _ = fs::remove_file(path);
        return Err(Error::Io(e));
    }

    tracing::debug!(
        path = %path.display(),
        mode = format!("{perms:o}"),
        "atomic write with permissions complete"
    );
    Ok(())
}

/// Private core: write `content` atomically, creating the temp file with the
/// explicit `mode` so the final inode lands with the correct permissions via
/// rename(2) (which preserves mode), fsyncing for durability on both sides of
/// the rename.
///
/// Shared by [`atomic_write_bytes`] (mode 0o600) and
/// [`atomic_write_with_perms`] (caller-supplied mode).
fn atomic_write_bytes_with_mode(path: &Path, content: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().ok_or_else(|| Error::AtomicWriteFailed {
        path: path.display().to_string(),
        reason: "path has no parent directory".to_owned(),
    })?;

    // Create the temp file with the EXPLICIT requested mode up front so the
    // final inode -- reachable the instant the rename completes -- already
    // has the correct permissions, regardless of umask.
    let mut tmp = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(mode))
        .tempfile_in(parent)
        .map_err(|e| Error::AtomicWriteFailed {
            path: path.display().to_string(),
            reason: format!("failed to create temp file: {e}"),
        })?;

    tmp.write_all(content)
        .map_err(|e| Error::AtomicWriteFailed {
            path: path.display().to_string(),
            reason: format!("failed to write temp file: {e}"),
        })?;

    tmp.flush().map_err(|e| Error::AtomicWriteFailed {
        path: path.display().to_string(),
        reason: format!("failed to flush temp file: {e}"),
    })?;

    // DURABILITY: fsync the temp file before the rename lands.
    tmp.as_file()
        .sync_all()
        .map_err(|e| Error::AtomicWriteFailed {
            path: path.display().to_string(),
            reason: format!("failed to fsync temp file: {e}"),
        })?;

    tmp.persist(path).map_err(|e| Error::AtomicWriteFailed {
        path: path.display().to_string(),
        reason: format!("failed to persist temp file: {e}"),
    })?;

    // Best-effort fsync of the parent directory to make the rename durable.
    fsync_dir_best_effort(parent);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use tempfile::TempDir;

    #[test]
    fn atomic_write_creates_file_with_correct_content() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let path = dir.path().join("output.txt");

        atomic_write(&path, "hello world").expect("atomic_write should succeed");

        let content = fs::read_to_string(&path).expect("file should be readable");
        assert_eq!(content, "hello world");
    }

    #[test]
    fn atomic_write_is_atomic_old_or_new_content() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let path = dir.path().join("atomic.txt");

        // Write initial content
        fs::write(&path, "old content").expect("initial write should succeed");

        // Overwrite atomically
        atomic_write(&path, "new content").expect("atomic_write should succeed");

        // After the write, the file must have exactly the new content
        let content = fs::read_to_string(&path).expect("file should be readable");
        assert_eq!(content, "new content");
    }

    #[test]
    fn atomic_write_overwrites_existing_file() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let path = dir.path().join("overwrite.txt");

        atomic_write(&path, "first").expect("first write should succeed");
        atomic_write(&path, "second").expect("second write should succeed");

        let content = fs::read_to_string(&path).expect("file should be readable");
        assert_eq!(content, "second");
    }

    #[test]
    fn atomic_write_with_perms_sets_0o600() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let path = dir.path().join("secret.txt");

        atomic_write_with_perms(&path, "secret data", 0o600)
            .expect("atomic_write_with_perms should succeed");

        let content = fs::read_to_string(&path).expect("file should be readable");
        assert_eq!(content, "secret data");

        let mode = fs::metadata(&path)
            .expect("metadata should be available")
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn atomic_write_with_perms_sets_0o644() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let path = dir.path().join("public.txt");

        atomic_write_with_perms(&path, "public data", 0o644)
            .expect("atomic_write_with_perms should succeed");

        let content = fs::read_to_string(&path).expect("file should be readable");
        assert_eq!(content, "public data");

        let mode = fs::metadata(&path)
            .expect("metadata should be available")
            .mode()
            & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn atomic_write_bytes_handles_binary_content() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let path = dir.path().join("binary.dat");

        let binary_content: &[u8] = &[0x00, 0xFF, 0x80, 0x7F, 0xDE, 0xAD, 0xBE, 0xEF];
        atomic_write_bytes(&path, binary_content).expect("atomic_write_bytes should succeed");

        let read_back = fs::read(&path).expect("file should be readable");
        assert_eq!(read_back, binary_content);
    }

    #[test]
    fn atomic_write_bytes_handles_empty_content() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let path = dir.path().join("empty.dat");

        atomic_write_bytes(&path, &[])
            .expect("atomic_write_bytes with empty content should succeed");

        let read_back = fs::read(&path).expect("file should be readable");
        assert!(read_back.is_empty());
    }

    #[test]
    fn atomic_write_fails_with_no_parent_directory() {
        let path = Path::new("no_such_dir/output.txt");
        let result = atomic_write(path, "content");
        assert!(result.is_err());
    }
}
