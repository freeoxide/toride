//! Advisory file locking for concurrent write coordination.
//!
//! Uses `fd-lock` to acquire exclusive advisory locks on files. This
//! prevents multiple processes from writing to the same config file
//! simultaneously.
//!
//! # Design
//!
//! The lock is held for the duration of a closure execution (RAII via
//! [`fd_lock::RwLockWriteGuard`]). This avoids self-referential structs
//! and keeps the crate `#![deny(unsafe_code)]` clean.

use std::fs::File;
use std::path::Path;
use std::time::{Duration, Instant};

use tracing;

use crate::error::{Error, Result};

/// Poll interval between non-blocking lock attempts in [`with_lock_timeout`].
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(10);

/// Acquire an exclusive advisory lock on `path` and run the given closure
/// while the lock is held.
///
/// Creates the file if it does not exist, acquires an exclusive (write)
/// lock, calls `f`, then drops the lock.
///
/// Blocking contract: this call blocks until the lock is acquired, with no
/// timeout. Under `flock` semantics the lock is per open-file-description,
/// so re-acquiring the same `path` inside `f` deadlocks silently; do not
/// nest. The lock file is created when missing and left in place after
/// release (deleting it would race other lockers' open handles); callers
/// that own the lock file's directory may remove it once no locking
/// concurrency remains. Use [`with_lock_timeout`] when a bounded wait is
/// required.
///
/// # Errors
///
/// Returns [`Error::LockFailed`] if the file cannot be opened or the
/// lock cannot be acquired. Returns any error produced by `f`.
pub fn with_lock<F, T>(path: &Path, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|e| Error::LockFailed(format!("cannot open lock file {}: {e}", path.display())))?;

    let mut lock = fd_lock::RwLock::new(file);
    let _guard = lock.write().map_err(|e| {
        Error::LockFailed(format!("cannot acquire lock on {}: {e}", path.display()))
    })?;

    tracing::debug!(path = %path.display(), "file lock acquired");
    let result = f();
    tracing::debug!(path = %path.display(), "file lock releasing");
    result
}

/// Try to acquire an exclusive advisory lock on `path` for at most
/// `timeout`, then run the given closure while the lock is held.
///
/// The lock is acquired with non-blocking `try_write` attempts retried on a
/// fixed short interval until the deadline, so a closure already holding
/// this lock (in this or another process) delays the call at most
/// `timeout`. The same no-nesting and lock-file-lifecycle rules as
/// [`with_lock`] apply.
///
/// # Errors
///
/// Returns [`Error::LockFailed`] when the lock file cannot be opened, the
/// lock is still held when `timeout` elapses, or the wait itself is longer
/// than `timeout` (the closure is then not run). Returns any error produced
/// by `f`.
pub fn with_lock_timeout<F, T>(path: &Path, timeout: Duration, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|e| Error::LockFailed(format!("cannot open lock file {}: {e}", path.display())))?;

    let mut lock = fd_lock::RwLock::new(file);
    let deadline = Instant::now() + timeout;
    let _guard = loop {
        match lock.try_write() {
            Ok(guard) => break guard,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(Error::LockFailed(format!(
                        "timed out after {} ms waiting for lock on {}",
                        timeout.as_millis(),
                        path.display()
                    )));
                }
                std::thread::sleep(LOCK_RETRY_INTERVAL.min(timeout));
            }
            Err(e) => {
                return Err(Error::LockFailed(format!(
                    "cannot acquire lock on {}: {e}",
                    path.display()
                )));
            }
        }
    };

    tracing::debug!(path = %path.display(), "file lock acquired");
    let result = f();
    tracing::debug!(path = %path.display(), "file lock releasing");
    result
}

/// Acquire an exclusive advisory lock on `path` and run the given closure
/// with the lock file path, while the lock is held.
///
/// This is a convenience variant of [`with_lock`] that passes the lock
/// file path to the closure for informational purposes.
///
/// # Errors
///
/// Returns [`Error::LockFailed`] if the lock cannot be acquired.
/// Returns any error produced by `f`.
pub fn with_lock_path<F, T>(path: &Path, f: F) -> Result<T>
where
    F: FnOnce(&Path) -> Result<T>,
{
    let file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|e| Error::LockFailed(format!("cannot open lock file {}: {e}", path.display())))?;

    let mut lock = fd_lock::RwLock::new(file);
    let _guard = lock.write().map_err(|e| {
        Error::LockFailed(format!("cannot acquire lock on {}: {e}", path.display()))
    })?;

    tracing::debug!(path = %path.display(), "file lock acquired");
    let result = f(path);
    tracing::debug!(path = %path.display(), "file lock releasing");
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn with_lock_executes_the_closure() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let lock_path = dir.path().join("test.lock");

        let result = with_lock(&lock_path, || Ok(42)).expect("with_lock should succeed");
        assert_eq!(result, 42);
    }

    #[test]
    fn with_lock_creates_lock_file() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let lock_path = dir.path().join("created.lock");

        assert!(!lock_path.exists(), "lock file should not exist yet");

        with_lock(&lock_path, || Ok(())).expect("with_lock should succeed");

        assert!(lock_path.exists(), "lock file should be created");
    }

    #[test]
    fn with_lock_propagates_closure_error() {
        use crate::error::Error;
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let lock_path = dir.path().join("error.lock");

        let result: Result<()> = with_lock(&lock_path, || {
            Err(Error::PathInvalid("test error".to_string()))
        });

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("test error"),
            "error should contain the closure error message"
        );
    }

    #[test]
    fn with_lock_path_passes_path_to_closure() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let lock_path = dir.path().join("path.lock");

        let result = with_lock_path(&lock_path, |p| {
            assert_eq!(p, lock_path);
            Ok(())
        });

        assert!(result.is_ok());
    }

    #[test]
    fn with_lock_can_be_called_sequentially() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let lock_path = dir.path().join("seq.lock");

        let r1 = with_lock(&lock_path, || Ok(1)).expect("first lock should succeed");
        let r2 = with_lock(&lock_path, || Ok(2)).expect("second lock should succeed");

        assert_eq!(r1, 1);
        assert_eq!(r2, 2);
    }

    #[test]
    fn with_lock_timeout_acquires_an_uncontended_lock() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let lock_path = dir.path().join("uncontended.lock");

        let result = with_lock_timeout(&lock_path, Duration::from_secs(1), || Ok(7))
            .expect("uncontended acquisition should succeed");
        assert_eq!(result, 7);
    }

    /// A closure already holding the lock must make a bounded attempt fail
    /// with [`Error::LockFailed`] near the timeout, without running the
    /// caller's closure, and a later attempt after release must succeed.
    #[test]
    fn with_lock_timeout_fails_bounded_while_the_lock_is_held() {
        let dir = TempDir::new().expect("temp dir creation should succeed");
        let contended = dir.path().join("contended.lock");
        let uncontended = dir.path().join("post-release.lock");

        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder_path = contended.clone();
        let holder = std::thread::spawn(move || {
            with_lock(&holder_path, || {
                release_rx.recv().expect("release signal");
                Ok(())
            })
        });

        std::thread::sleep(Duration::from_millis(100));
        let started = Instant::now();
        let mut ran = false;
        let outcome = with_lock_timeout(&contended, Duration::from_millis(200), || {
            ran = true;
            Ok(())
        });
        let waited = started.elapsed();

        match outcome {
            Err(Error::LockFailed(detail)) => assert!(
                detail.contains("timed out"),
                "must name the timeout, got: {detail}"
            ),
            other => panic!("expected LockFailed, got {other:?}"),
        }
        assert!(
            !ran,
            "the closure must not run when the lock is not acquired"
        );
        assert!(
            waited >= Duration::from_millis(180),
            "must wait for most of the timeout, waited {waited:?}"
        );
        assert!(
            waited < Duration::from_secs(5),
            "must not block far past the timeout, waited {waited:?}"
        );

        release_tx.send(()).expect("holder closure still waiting");
        holder
            .join()
            .expect("holder thread")
            .expect("holder closure");

        let result = with_lock_timeout(&uncontended, Duration::from_secs(5), || Ok(9))
            .expect("acquisition after release should succeed");
        assert_eq!(result, 9);
    }
}
