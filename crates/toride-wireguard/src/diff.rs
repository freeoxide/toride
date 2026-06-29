//! Config diffing via the `similar` crate.
//!
//! Produces unified diffs between two WireGuard configuration strings so that
//! pending changes can be previewed before being applied to disk.

use similar::{ChangeTag, TextDiff};

/// A single line in a unified diff output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffLine {
    /// The change tag for this line.
    pub tag: DiffTag,
    /// The line content (without the +/- prefix).
    pub content: String,
}

/// Classification of a diff line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffTag {
    /// Context line (unchanged).
    Context,
    /// Line added.
    Insert,
    /// Line removed.
    Delete,
}

impl From<ChangeTag> for DiffTag {
    fn from(tag: ChangeTag) -> Self {
        match tag {
            ChangeTag::Equal => DiffTag::Context,
            ChangeTag::Insert => DiffTag::Insert,
            ChangeTag::Delete => DiffTag::Delete,
        }
    }
}

/// Result of comparing two config strings.
#[derive(Debug, Clone)]
pub struct ConfigDiff {
    /// Individual diff lines.
    pub lines: Vec<DiffLine>,
}

impl ConfigDiff {
    /// Compute a diff between two WireGuard config strings.
    pub fn new(old: &str, new: &str) -> Self {
        let diff = TextDiff::from_lines(old, new);
        let lines = diff
            .iter_all_changes()
            .map(|change| DiffLine {
                tag: change.tag().into(),
                content: change.to_string_lossy().to_string(),
            })
            .collect();
        Self { lines }
    }

    /// Returns `true` if there are no insertions or deletions.
    pub fn is_empty(&self) -> bool {
        !self.lines.iter().any(|l| l.tag != DiffTag::Context)
    }

    /// Returns the number of inserted lines.
    pub fn insertions(&self) -> usize {
        self.lines
            .iter()
            .filter(|l| l.tag == DiffTag::Insert)
            .count()
    }

    /// Returns the number of deleted lines.
    pub fn deletions(&self) -> usize {
        self.lines
            .iter()
            .filter(|l| l.tag == DiffTag::Delete)
            .count()
    }

    /// Render the diff as a unified diff string with +/- prefixes.
    pub fn to_unified_string(&self) -> String {
        let mut out = String::new();
        for line in &self.lines {
            let prefix = match line.tag {
                DiffTag::Context => ' ',
                DiffTag::Insert => '+',
                DiffTag::Delete => '-',
            };
            out.push(prefix);
            out.push_str(&line.content);
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_identical_configs() {
        let old = "[Interface]\nAddress = 10.0.0.1/24\n";
        let diff = ConfigDiff::new(old, old);
        assert!(diff.is_empty());
    }

    #[test]
    fn diff_changed_address() {
        let old = "[Interface]\nAddress = 10.0.0.1/24\n";
        let new = "[Interface]\nAddress = 10.0.0.2/24\n";
        let diff = ConfigDiff::new(old, new);
        assert!(!diff.is_empty());
        assert_eq!(diff.insertions(), 1);
        assert_eq!(diff.deletions(), 1);
    }

    #[test]
    fn diff_added_peer() {
        let old = "[Interface]\nAddress = 10.0.0.1/24\n";
        let new = "[Interface]\nAddress = 10.0.0.1/24\n\n[Peer]\nPublicKey = key==\nAllowedIPs = 0.0.0.0/0\n";
        let diff = ConfigDiff::new(old, new);
        assert!(diff.insertions() > 0);
        assert_eq!(diff.deletions(), 0);
    }

    #[test]
    fn unified_string_format() {
        let old = "a\nb\n";
        let new = "a\nc\n";
        let diff = ConfigDiff::new(old, new);
        let unified = diff.to_unified_string();
        // The diff should contain a deleted line with 'b' and an inserted line with 'c'.
        // `similar` preserves trailing newlines in content, so match without newline.
        assert!(
            diff.lines
                .iter()
                .any(|l| l.tag == DiffTag::Delete && l.content.trim() == "b"),
            "expected a deleted line with 'b', got: {unified:?}"
        );
        assert!(
            diff.lines
                .iter()
                .any(|l| l.tag == DiffTag::Insert && l.content.trim() == "c"),
            "expected an inserted line with 'c', got: {unified:?}"
        );
    }
}
