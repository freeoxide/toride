//! Framework file management.
//!
//! Manages controlled blocks within UFW framework files
//! (`before.rules`, `after.rules`, etc.) using marker comments.

use std::path::Path;

use toride_fs::with_lock;

use crate::error::{Error, Result};
use crate::spec::FrameworkRuleBlock;

/// Acquire an exclusive lock on a lock file derived from `path` and run `f`
/// while the lock is held.
///
/// The lock file uses a `.lock` extension alongside the target file so the
/// actual framework file is never corrupted by lock metadata.
fn with_file_lock<T>(path: &Path, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let lock_path = path.with_extension("lock");
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    with_lock(&lock_path, || {
        f().map_err(|e| toride_fs::Error::Io(std::io::Error::other(e.to_string())))
    })
    .map_err(|e| Error::Io(e.to_string()))
}

/// Start marker for a managed block.
fn start_marker(id: &str) -> String {
    format!(">>> ufw-kit {id}")
}

/// End marker for a managed block.
fn end_marker(id: &str) -> String {
    format!("<<< ufw-kit {id}")
}

/// Locate a managed block's byte range (start line through end line,
/// including the end line's trailing newline).
///
/// Markers match only as whole lines (`# >>> ufw-kit <id>` exactly to
/// end-of-line), so id `foo` never matches block `foo-bar`. A start marker
/// without a closing end marker is an error, not an append candidate.
fn block_range(content: &str, id: &str) -> Result<Option<(usize, usize)>> {
    let start_line = format!("# {}", start_marker(id));
    let end_line = format!("# {}", end_marker(id));

    let mut offset = 0usize;
    let mut start_at: Option<usize> = None;
    for line in content.split_inclusive('\n') {
        let line_end = offset + line.len();
        let trimmed = line.trim();
        if start_at.is_none() {
            if trimmed == start_line {
                start_at = Some(offset);
            }
        } else if trimmed == end_line {
            return Ok(Some((start_at.unwrap_or(0), line_end)));
        }
        offset = line_end;
    }

    if start_at.is_some() {
        Err(Error::FrameworkBlockError(format!(
            "managed block '{id}' has a start marker without an end marker"
        )))
    } else {
        Ok(None)
    }
}

/// Insert or replace a managed block in a file's content.
///
/// # Errors
///
/// Returns [`Error::FrameworkBlockError`] when an orphan start marker for
/// the block id exists.
pub fn upsert_block(content: &str, block: &FrameworkRuleBlock) -> Result<String> {
    let block_text = format!(
        "# {}\n{}\n# {}\n",
        start_marker(&block.id),
        block.content.trim_end(),
        end_marker(&block.id)
    );

    if let Some((start, end)) = block_range(content, &block.id)? {
        let mut result = String::with_capacity(content.len());
        result.push_str(&content[..start]);
        result.push_str(&block_text);
        result.push_str(&content[end..]);
        return Ok(result);
    }

    let mut result = content.to_string();
    if !result.ends_with('\n') {
        result.push('\n');
    }
    result.push_str(&block_text);
    Ok(result)
}

/// Remove a managed block from a file's content.
///
/// # Errors
///
/// Returns [`Error::FrameworkBlockError`] when an orphan start marker for
/// the block id exists; content is then left untouched.
pub fn remove_block(content: &str, id: &str) -> Result<String> {
    match block_range(content, id)? {
        Some((start, end)) => {
            let mut result = String::with_capacity(content.len());
            result.push_str(&content[..start]);
            result.push_str(&content[end..]);
            Ok(result)
        }
        None => Ok(content.to_string()),
    }
}

/// List all managed block IDs in content.
pub fn list_blocks(content: &str) -> Vec<String> {
    let mut blocks = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("# >>> ufw-kit ") {
            let id = rest.trim();
            if !id.is_empty() {
                blocks.push(id.to_string());
            }
        }
    }

    blocks
}

/// Read a framework file, returning empty string if it doesn't exist.
pub fn read_framework_file(path: &Path) -> Result<String> {
    if path.exists() {
        std::fs::read_to_string(path)
            .map_err(|e| Error::FrameworkNotFound(format!("{}: {e}", path.display())))
    } else {
        Ok(String::new())
    }
}

/// Write a framework file atomically.
///
/// If `backup_dir` is provided and the file already exists, the current
/// content is backed up before writing.
///
/// Returns the previous content if the file existed (for rollback purposes).
pub fn write_framework_file(
    path: &Path,
    content: &str,
    backup_dir: Option<&Path>,
) -> Result<Option<String>> {
    with_file_lock(path, || {
        // Read existing content for rollback
        let previous = if path.exists() {
            Some(
                std::fs::read_to_string(path)
                    .map_err(|e| Error::FrameworkBlockError(format!("read existing: {e}")))?,
            )
        } else {
            None
        };

        // Backup existing file if requested
        if let Some(dir) = backup_dir {
            if let Some(existing) = &previous {
                std::fs::create_dir_all(dir)
                    .map_err(|e| Error::BackupFailed(format!("create backup dir: {e}")))?;

                let name = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                std::fs::write(dir.join(name), existing)
                    .map_err(|e| Error::BackupFailed(format!("write backup: {e}")))?;
            }
        }

        let dir = path
            .parent()
            .ok_or_else(|| Error::FrameworkBlockError("no parent directory".into()))?;

        std::fs::create_dir_all(dir)
            .map_err(|e| Error::FrameworkBlockError(format!("create dir: {e}")))?;

        let mut tmp = tempfile::NamedTempFile::new_in(dir)
            .map_err(|e| Error::FrameworkBlockError(format!("create temp: {e}")))?;

        std::io::Write::write_all(&mut tmp, content.as_bytes())
            .map_err(|e| Error::FrameworkBlockError(format!("write temp: {e}")))?;

        tmp.persist(path)
            .map_err(|e| Error::FrameworkBlockError(format!("persist: {e}")))?;

        Ok(previous)
    })
}

/// Rollback a framework file to its previous content.
///
/// If `previous` is `None`, the file is removed.
/// If `previous` is `Some(content)`, the file is restored to that content.
pub fn rollback_framework_file(path: &Path, previous: Option<&str>) -> Result<()> {
    match previous {
        Some(content) => {
            std::fs::write(path, content).map_err(|e| {
                Error::FrameworkBlockError(format!("rollback {}: {e}", path.display()))
            })?;
        }
        None => {
            if path.exists() {
                std::fs::remove_file(path).map_err(|e| {
                    Error::FrameworkBlockError(format!("rollback remove {}: {e}", path.display()))
                })?;
            }
        }
    }
    Ok(())
}

// Rollback manager

/// A recorded framework operation for rollback purposes.
#[derive(Debug, Clone)]
struct RollbackEntry {
    /// Path that was modified.
    path: std::path::PathBuf,
    /// Previous content (None if file didn't exist).
    previous_content: Option<String>,
}

/// A rollback manager that records framework changes and can undo them.
///
/// # Example
///
/// ```rust,no_run,ignore
/// use ufw_kit::framework::RollbackManager;
/// use ufw_kit::spec::FrameworkRuleBlock;
/// use std::path::Path;
///
/// let mut mgr = RollbackManager::new();
/// let path = Path::new("/etc/ufw/before.rules");
/// let block = FrameworkRuleBlock {
///     id: "my-nat".into(),
///     content: "*nat\n:POSTROUTING ACCEPT [0:0]\nCOMMIT".into(),
///     ipv6: false,
/// };
///
/// // Apply with rollback tracking
/// mgr.upsert_tracked(path, &block, None).unwrap();
///
/// // If something goes wrong, rollback all tracked operations
/// mgr.rollback_all().unwrap();
/// ```
#[derive(Debug, Default)]
pub struct RollbackManager {
    entries: Vec<RollbackEntry>,
}

impl RollbackManager {
    /// Create a new empty rollback manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Upsert a managed block and record the previous state for rollback.
    ///
    /// If `backup_dir` is provided, a backup copy is also written.
    pub fn upsert_tracked(
        &mut self,
        path: &Path,
        block: &crate::spec::FrameworkRuleBlock,
        backup_dir: Option<&Path>,
    ) -> Result<()> {
        let content = read_framework_file(path)?;
        let new_content = upsert_block(&content, block)?;
        let previous = write_framework_file(path, &new_content, backup_dir)?;

        self.entries.push(RollbackEntry {
            path: path.to_path_buf(),
            previous_content: previous,
        });

        Ok(())
    }

    /// Remove a managed block and record the previous state for rollback.
    pub fn remove_tracked(
        &mut self,
        path: &Path,
        id: &str,
        backup_dir: Option<&Path>,
    ) -> Result<()> {
        let content = read_framework_file(path)?;
        let new_content = remove_block(&content, id)?;

        if is_identical(&content, &new_content) {
            // Nothing changed: no rollback entry needed
            return Ok(());
        }

        let previous = write_framework_file(path, &new_content, backup_dir)?;

        self.entries.push(RollbackEntry {
            path: path.to_path_buf(),
            previous_content: previous,
        });

        Ok(())
    }

    /// Rollback all tracked operations in reverse order (LIFO).
    ///
    /// Returns the number of files restored.
    pub fn rollback_all(&self) -> Result<usize> {
        let mut count = 0;

        // Rollback in reverse order
        for entry in self.entries.iter().rev() {
            rollback_framework_file(&entry.path, entry.previous_content.as_deref())?;
            count += 1;
        }

        Ok(count)
    }

    /// Rollback only the last N operations.
    pub fn rollback_last(&self, n: usize) -> Result<usize> {
        let start = self.entries.len().saturating_sub(n);
        let to_rollback = &self.entries[start..];
        let mut count = 0;

        for entry in to_rollback.iter().rev() {
            rollback_framework_file(&entry.path, entry.previous_content.as_deref())?;
            count += 1;
        }

        Ok(count)
    }

    /// Get the number of tracked operations.
    #[must_use]
    pub fn tracked_count(&self) -> usize {
        self.entries.len()
    }

    /// Discard all tracked rollback entries without performing rollback.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Check if two strings are identical (shared with diff module, inlined here).
fn is_identical(a: &str, b: &str) -> bool {
    a == b
}

#[cfg(test)]
#[path = "framework.test.rs"]
mod tests;
