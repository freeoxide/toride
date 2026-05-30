//! Framework file management.
//!
//! Manages controlled blocks within UFW framework files
//! (`before.rules`, `after.rules`, etc.) using marker comments.

use std::path::Path;

use crate::error::{Error, Result};
use crate::spec::FrameworkRuleBlock;

/// Start marker for a managed block.
fn start_marker(id: &str) -> String {
    format!(">>> ufw-kit {id}")
}

/// End marker for a managed block.
fn end_marker(id: &str) -> String {
    format!("<<< ufw-kit {id}")
}

/// Insert or replace a managed block in a file's content.
pub fn upsert_block(content: &str, block: &FrameworkRuleBlock) -> Result<String> {
    let start = start_marker(&block.id);
    let end = end_marker(&block.id);

    let block_text = format!(
        "# {start}\n{}\n# {end}\n",
        block.content.trim_end()
    );

    // Find existing block
    if let Some(start_idx) = content.find(&start) {
        // Find the end marker after the start
        let after_start = &content[start_idx..];
        if let Some(end_rel) = after_start.find(&end) {
            let end_idx = start_idx + end_rel + end.len();
            // Find the newline after end marker
            let after_end = if content[end_idx..].starts_with('\n') {
                &content[end_idx + 1..]
            } else {
                &content[end_idx..]
            };

            // Replace: everything before start + new block + everything after end
            let mut result = String::new();
            result.push_str(&content[..start_idx]);
            result.push_str(&block_text);
            result.push_str(after_end);
            return Ok(result);
        }
    }

    // Block doesn't exist — append
    let mut result = content.to_string();
    if !result.ends_with('\n') {
        result.push('\n');
    }
    result.push_str(&block_text);
    Ok(result)
}

/// Remove a managed block from a file's content.
pub fn remove_block(content: &str, id: &str) -> Result<String> {
    let start = start_marker(id);
    let end = end_marker(id);

    if let Some(start_idx) = content.find(&start) {
        let after_start = &content[start_idx..];
        if let Some(end_rel) = after_start.find(&end) {
            let end_idx = start_idx + end_rel + end.len();
            let after_end = if content[end_idx..].starts_with('\n') {
                &content[end_idx + 1..]
            } else {
                &content[end_idx..]
            };

            let mut result = String::new();
            result.push_str(&content[..start_idx]);
            result.push_str(after_end);
            return Ok(result);
        }
    }

    // Block not found — return content unchanged
    Ok(content.to_string())
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

#[cfg(test)]
#[path = "framework.test.rs"]
mod tests;
