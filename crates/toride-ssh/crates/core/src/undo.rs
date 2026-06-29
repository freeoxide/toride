//! Undo/restore mechanism for file mutations.
//!
//! Provides an [`UndoStack`] that captures file snapshots before modifications
//! and can restore them on demand. Callers use it explicitly around mutating
//! operations:
//!
//! ```rust,no_run
//! use toride_ssh_core::undo::{UndoStack, UndoResult};
//! use std::path::Path;
//!
//! # async fn example(config_path: &Path) -> UndoResult<()> {
//! let mut undo = UndoStack::new(20);
//! undo.snapshot(config_path).await?;
//! // ... perform mutation ...
//! // If something goes wrong, roll back:
//! undo.restore_last().await?;
//! # Ok(())
//! # }
//! ```

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::fs;
// tracing available for future instrumentation

/// Captured state of a single file at a point in time.
#[derive(Debug, Clone)]
pub struct FileSnapshot {
    /// Path of the file that was snapshotted.
    path: PathBuf,
    /// File contents at the time of the snapshot (empty string if the file did not exist).
    contents: String,
    /// When the snapshot was taken, as milliseconds since Unix epoch.
    timestamp_ms: u128,
}

impl FileSnapshot {
    /// Returns the path of the snapshotted file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the contents captured in this snapshot.
    #[must_use]
    pub fn contents(&self) -> &str {
        &self.contents
    }

    /// Returns the snapshot timestamp as milliseconds since the Unix epoch.
    #[must_use]
    pub fn timestamp_ms(&self) -> u128 {
        self.timestamp_ms
    }
}

/// Errors specific to undo operations.
#[derive(Debug, thiserror::Error)]
pub enum UndoError {
    /// The undo stack is empty; nothing to restore.
    #[error("undo stack is empty")]
    StackEmpty,
    /// An I/O error occurred during snapshot or restore.
    #[error("undo I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for undo operations.
pub type UndoResult<T> = std::result::Result<T, UndoError>;

/// A stack of [`FileSnapshot`]s that supports restoring files to earlier states.
///
/// The stack has a configurable maximum depth. When the depth is exceeded,
/// the oldest snapshot is discarded.
///
/// # Atomic writes
///
/// [`restore_last`](UndoStack::restore_last) and
/// [`restore_all`](UndoStack::restore_all) write files atomically by first
/// writing to a temporary file in the same directory, then renaming it.
#[derive(Debug)]
pub struct UndoStack {
    snapshots: Vec<FileSnapshot>,
    max_depth: usize,
}

/// Default maximum depth for the undo stack.
pub const DEFAULT_MAX_DEPTH: usize = 20;

impl Default for UndoStack {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_DEPTH)
    }
}

impl UndoStack {
    /// Create a new, empty undo stack with the given maximum depth.
    ///
    /// # Panics
    ///
    /// Panics if `max_depth` is zero.
    #[must_use]
    pub fn new(max_depth: usize) -> Self {
        assert!(max_depth > 0, "UndoStack max_depth must be at least 1");
        Self {
            snapshots: Vec::new(),
            max_depth,
        }
    }

    /// Capture a snapshot of the file at `path`.
    ///
    /// If the file does not exist, an empty-contents snapshot is recorded
    /// (so that restoring will effectively delete the file by writing empty
    /// contents, or more precisely, the restore will write the empty string
    /// back — matching what was there: nothing).
    ///
    /// If the stack is at maximum depth, the oldest snapshot is discarded
    /// before the new one is pushed.
    ///
    /// # Errors
    ///
    /// Returns an error if reading the file fails for a reason other than the
    /// file not existing.
    pub async fn snapshot<P: AsRef<Path>>(&mut self, path: P) -> UndoResult<()> {
        let path = path.as_ref().to_path_buf();
        let contents = match fs::read_to_string(&path).await {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(UndoError::Io(e)),
        };
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        // Evict oldest if at capacity.
        if self.snapshots.len() >= self.max_depth {
            self.snapshots.remove(0);
        }

        self.snapshots.push(FileSnapshot {
            path,
            contents,
            timestamp_ms,
        });

        Ok(())
    }

    /// Restore the most recent snapshot, removing it from the stack.
    ///
    /// The file is written atomically (write to a temp file in the same
    /// directory, then rename).
    ///
    /// # Errors
    ///
    /// Returns [`UndoError::StackEmpty`] if there are no snapshots to restore.
    /// Returns [`UndoError::Io`] if writing the file fails.
    pub async fn restore_last(&mut self) -> UndoResult<FileSnapshot> {
        let snapshot = self.snapshots.pop().ok_or(UndoError::StackEmpty)?;
        atomic_write(&snapshot.path, &snapshot.contents).await?;
        Ok(snapshot)
    }

    /// Restore all snapshots in reverse order (most recent first).
    ///
    /// Each file is written atomically. The stack is emptied after this call
    /// regardless of whether any individual restore fails — snapshots that
    /// were successfully restored are not re-pushed.
    ///
    /// # Errors
    ///
    /// Returns the first error encountered. Snapshots already processed
    /// before the error are restored; those after are lost.
    pub async fn restore_all(&mut self) -> UndoResult<()> {
        // Drain in reverse order (pop from end).
        let drained: Vec<FileSnapshot> = self.snapshots.drain(..).rev().collect();
        for snapshot in drained {
            atomic_write(&snapshot.path, &snapshot.contents).await?;
        }
        Ok(())
    }

    /// Returns `true` if the stack contains no snapshots.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }

    /// Returns the number of snapshots currently on the stack.
    #[must_use]
    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    /// Discard all snapshots without restoring.
    pub fn clear(&mut self) {
        self.snapshots.clear();
    }

    /// Peek at the most recent snapshot without removing or restoring it.
    ///
    /// Returns `None` if the stack is empty.
    #[must_use]
    pub fn peek(&self) -> Option<&FileSnapshot> {
        self.snapshots.last()
    }
}

/// Write `contents` to `path` atomically using `toride_fs::atomic_write`.
///
/// Ensures the parent directory exists, then delegates the actual atomic write
/// to `toride_fs` via `spawn_blocking` so we don't block the tokio runtime.
async fn atomic_write(path: &Path, contents: &str) -> UndoResult<()> {
    if let Some(parent) = path.parent() {
        // Ensure the parent directory exists.
        fs::create_dir_all(parent).await?;
    }

    let path = path.to_path_buf();
    let contents = contents.to_owned();
    tokio::task::spawn_blocking(move || {
        toride_fs::atomic_write(&path, &contents).map_err(std::io::Error::other)
    })
    .await
    .map_err(std::io::Error::other)??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Helper: create a temp file with the given contents, return its path.
    async fn make_file(dir: &TempDir, name: &str, contents: &str) -> PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, contents).await.unwrap();
        path
    }

    /// Helper: read file contents, returning empty string if the file doesn't exist.
    async fn read_file(path: &Path) -> String {
        match fs::read_to_string(path).await {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => panic!("unexpected read error: {e}"),
        }
    }

    #[tokio::test]
    async fn snapshot_and_restore_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = make_file(&dir, "config", "original contents").await;

        let mut undo = UndoStack::new(20);
        undo.snapshot(&path).await.unwrap();

        // Mutate the file.
        fs::write(&path, "mutated contents").await.unwrap();
        assert_eq!(read_file(&path).await, "mutated contents");

        // Restore.
        let snap = undo.restore_last().await.unwrap();
        assert_eq!(snap.path(), path);
        assert_eq!(read_file(&path).await, "original contents");
        assert!(undo.is_empty());
    }

    #[tokio::test]
    async fn restore_last_restores_most_recent() {
        let dir = TempDir::new().unwrap();
        let path = make_file(&dir, "file.txt", "v1").await;

        let mut undo = UndoStack::new(20);
        undo.snapshot(&path).await.unwrap();
        fs::write(&path, "v2").await.unwrap();

        undo.snapshot(&path).await.unwrap();
        fs::write(&path, "v3").await.unwrap();

        // restore_last should bring us back to v2 (the most recent snapshot).
        undo.restore_last().await.unwrap();
        assert_eq!(read_file(&path).await, "v2");

        // And another restore should bring us back to v1.
        undo.restore_last().await.unwrap();
        assert_eq!(read_file(&path).await, "v1");
    }

    #[tokio::test]
    async fn restore_all_restores_in_reverse_order() {
        let dir = TempDir::new().unwrap();
        let path_a = make_file(&dir, "a.txt", "a-v1").await;
        let path_b = make_file(&dir, "b.txt", "b-v1").await;

        let mut undo = UndoStack::new(20);

        // Snapshot a, mutate; snapshot b, mutate.
        undo.snapshot(&path_a).await.unwrap();
        fs::write(&path_a, "a-v2").await.unwrap();

        undo.snapshot(&path_b).await.unwrap();
        fs::write(&path_b, "b-v2").await.unwrap();

        // restore_all should restore b first (most recent), then a.
        undo.restore_all().await.unwrap();
        assert_eq!(read_file(&path_a).await, "a-v1");
        assert_eq!(read_file(&path_b).await, "b-v1");
        assert!(undo.is_empty());
    }

    #[tokio::test]
    async fn max_depth_enforcement() {
        let dir = TempDir::new().unwrap();
        let path = make_file(&dir, "file.txt", "initial").await;

        let mut undo = UndoStack::new(3);

        // Push 4 snapshots. With max_depth=3, the first should be evicted.
        for i in 0..4 {
            fs::write(&path, format!("v{i}")).await.unwrap();
            undo.snapshot(&path).await.unwrap();
        }

        // Stack should have 3 items, not 4.
        assert_eq!(undo.len(), 3);

        // The first snapshot (v0) should have been evicted, so the oldest
        // remaining snapshot captured v1.
        // Restore all: the first restore (pop) is the last snapshot (v3).
        let snap = undo.restore_last().await.unwrap();
        assert_eq!(snap.contents, "v3");
        let snap = undo.restore_last().await.unwrap();
        assert_eq!(snap.contents, "v2");
        let snap = undo.restore_last().await.unwrap();
        assert_eq!(snap.contents, "v1");
        assert!(undo.is_empty());
    }

    #[tokio::test]
    async fn snapshot_of_nonexistent_file_stores_empty() {
        let dir = TempDir::new().unwrap();
        let nonexistent = dir.path().join("does_not_exist.txt");

        let mut undo = UndoStack::new(20);
        undo.snapshot(&nonexistent).await.unwrap();

        let snap = undo.peek().unwrap();
        assert_eq!(snap.contents(), "");
        assert_eq!(snap.path(), nonexistent);
    }

    #[tokio::test]
    async fn restore_when_empty_returns_error() {
        let mut undo = UndoStack::new(20);
        let result = undo.restore_last().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, UndoError::StackEmpty));
    }

    #[tokio::test]
    async fn clear_discards_all_snapshots() {
        let dir = TempDir::new().unwrap();
        let path = make_file(&dir, "f.txt", "hello").await;

        let mut undo = UndoStack::new(20);
        undo.snapshot(&path).await.unwrap();
        undo.snapshot(&path).await.unwrap();
        assert_eq!(undo.len(), 2);

        undo.clear();
        assert!(undo.is_empty());
        assert_eq!(undo.len(), 0);
    }

    #[tokio::test]
    async fn peek_returns_most_recent_without_removing() {
        let dir = TempDir::new().unwrap();
        let path = make_file(&dir, "f.txt", "first").await;

        let mut undo = UndoStack::new(20);
        undo.snapshot(&path).await.unwrap();

        fs::write(&path, "second").await.unwrap();
        undo.snapshot(&path).await.unwrap();

        let snap = undo.peek().unwrap();
        assert_eq!(snap.contents(), "second");
        assert_eq!(undo.len(), 2); // Not removed.

        // Peek on empty stack returns None.
        let empty = UndoStack::new(5);
        assert!(empty.peek().is_none());
    }

    #[tokio::test]
    async fn restore_all_on_empty_stack_is_ok() {
        let mut undo = UndoStack::new(5);
        // restore_all on empty stack should succeed without error.
        undo.restore_all().await.unwrap();
    }

    #[tokio::test]
    async fn default_impl() {
        let undo = UndoStack::default();
        assert_eq!(undo.max_depth, DEFAULT_MAX_DEPTH);
        assert!(undo.is_empty());
    }

    #[tokio::test]
    async fn snapshot_timestamps_increase() {
        let dir = TempDir::new().unwrap();
        let path = make_file(&dir, "f.txt", "data").await;

        let mut undo = UndoStack::new(20);
        undo.snapshot(&path).await.unwrap();

        // Small delay to ensure timestamps differ.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;

        undo.snapshot(&path).await.unwrap();

        let first_ts = undo.snapshots[0].timestamp_ms;
        let second_ts = undo.snapshots[1].timestamp_ms;
        assert!(second_ts >= first_ts, "timestamps should be non-decreasing");
    }
}
