//! Diff utilities for comparing audit rule sets.
//!
//! Uses the `similar` crate to compute line-level diffs between two sets
//! of audit rules, enabling review of pending changes before application.

use similar::{ChangeTag, TextDiff};

// ---------------------------------------------------------------------------
// DiffEntry
// ---------------------------------------------------------------------------

/// A single diff entry representing an added, removed, or unchanged line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffEntry {
    /// The change type.
    pub tag: DiffTag,
    /// The line content.
    pub line: String,
}

/// The type of change in a diff entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffTag {
    /// Line was removed from the old rules.
    Removed,
    /// Line was added in the new rules.
    Added,
    /// Line is unchanged.
    Unchanged,
}

impl From<ChangeTag> for DiffTag {
    fn from(tag: ChangeTag) -> Self {
        match tag {
            ChangeTag::Delete => Self::Removed,
            ChangeTag::Insert => Self::Added,
            ChangeTag::Equal => Self::Unchanged,
        }
    }
}

impl std::fmt::Display for DiffTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Removed => write!(f, "-"),
            Self::Added => write!(f, "+"),
            Self::Unchanged => write!(f, " "),
        }
    }
}

impl std::fmt::Display for DiffEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.tag, self.line)
    }
}

// ---------------------------------------------------------------------------
// Diff computation
// ---------------------------------------------------------------------------

/// Compute a unified diff between two sets of audit rules.
///
/// Each set is represented as a single string (typically the content of
/// a rules file). Returns a list of [`DiffEntry`] values.
pub fn diff_audit_rules(old_rules: &str, new_rules: &str) -> Vec<DiffEntry> {
    let diff = TextDiff::from_lines(old_rules, new_rules);

    diff.iter_all_changes()
        .map(|change| DiffEntry {
            tag: change.tag().into(),
            line: change.to_string_lossy().into_owned(),
        })
        .collect()
}

/// Returns `true` if the diff contains any additions or removals.
pub fn has_changes(entries: &[DiffEntry]) -> bool {
    entries.iter().any(|e| e.tag != DiffTag::Unchanged)
}

/// Returns only the added lines from a diff.
pub fn added_lines(entries: &[DiffEntry]) -> Vec<&str> {
    entries
        .iter()
        .filter(|e| e.tag == DiffTag::Added)
        .map(|e| e.line.as_str())
        .collect()
}

/// Returns only the removed lines from a diff.
pub fn removed_lines(entries: &[DiffEntry]) -> Vec<&str> {
    entries
        .iter()
        .filter(|e| e.tag == DiffTag::Removed)
        .map(|e| e.line.as_str())
        .collect()
}
