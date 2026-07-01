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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Two multi-line rule sets differing by one added and one removed line.
    fn fixtures() -> (&'static str, &'static str) {
        let old = "\
-D always -F arch=b64 -S unlink -S unlinkat -k delete
-D always -F arch=b64 -S openat -k access
## This is a shared comment
";
        // -S openat line removed, a new -S chmod watch added.
        let new = "\
-D always -F arch=b64 -S unlink -S unlinkat -k delete
## This is a shared comment
-D always -F arch=b64 -S chmod -f a1 -k perm
";
        (old, new)
    }

    #[test]
    fn diff_audit_rules_emits_added_removed_and_unchanged() {
        let (old, new) = fixtures();
        let entries = diff_audit_rules(old, new);
        // Every change must carry the correct tag and the original line text.
        let tags: Vec<DiffTag> = entries.iter().map(|e| e.tag).collect();
        assert!(
            tags.contains(&DiffTag::Added),
            "expected at least one Added entry, got {tags:?}"
        );
        assert!(
            tags.contains(&DiffTag::Removed),
            "expected at least one Removed entry, got {tags:?}"
        );
        assert!(
            tags.contains(&DiffTag::Unchanged),
            "expected at least one Unchanged entry, got {tags:?}"
        );

        // The added line is the chmod watch.
        let added: Vec<&str> = entries
            .iter()
            .filter(|e| e.tag == DiffTag::Added)
            .map(|e| e.line.as_str())
            .collect();
        assert_eq!(added, vec!["-D always -F arch=b64 -S chmod -f a1 -k perm\n"]);

        // The removed line is the openat watch.
        let removed: Vec<&str> = entries
            .iter()
            .filter(|e| e.tag == DiffTag::Removed)
            .map(|e| e.line.as_str())
            .collect();
        assert_eq!(removed, vec!["-D always -F arch=b64 -S openat -k access\n"]);
    }

    #[test]
    fn added_and_removed_helpers_return_only_changed_lines() {
        let (old, new) = fixtures();
        let entries = diff_audit_rules(old, new);

        let added = added_lines(&entries);
        let removed = removed_lines(&entries);

        // Exactly one line added and one removed, with no extras.
        assert_eq!(added.len(), 1);
        assert_eq!(removed.len(), 1);
        assert!(added[0].contains("chmod"));
        assert!(removed[0].contains("openat"));
        // Unchanged lines must never leak into either helper.
        assert!(!added.iter().any(|l| l.contains("unlink")));
        assert!(!removed.iter().any(|l| l.contains("unlink")));
        assert!(!added.iter().any(|l| l.contains("comment")));
    }

    #[test]
    fn has_changes_true_for_diff_and_false_for_identical() {
        let (old, new) = fixtures();
        assert!(has_changes(&diff_audit_rules(old, new)));

        // Identical input -> no additions or removals.
        let identical = "-D always -F arch=b64 -S unlink -k delete\n## shared\n";
        let same = diff_audit_rules(identical, identical);
        assert!(!has_changes(&same));
        // All entries are Unchanged, and the added/removed helpers are empty.
        assert!(added_lines(&same).is_empty());
        assert!(removed_lines(&same).is_empty());
        assert!(same.iter().all(|e| e.tag == DiffTag::Unchanged));
    }

    #[test]
    fn diff_tag_display_round_trips() {
        assert_eq!(DiffTag::Removed.to_string(), "-");
        assert_eq!(DiffTag::Added.to_string(), "+");
        assert_eq!(DiffTag::Unchanged.to_string(), " ");
    }
}
