//! Diff utilities for comparing proxy configurations.
//!
//! Provides unified diff output between current and desired configurations
//! using the `similar` crate.

use crate::spec::ServerBlock;

/// Compute a unified diff between two proxy configuration strings.
///
/// Uses `similar::TextDiff` to produce a standard unified diff output.
pub fn diff_configs(old: &str, new: &str) -> String {
    similar::TextDiff::from_lines(old, new)
        .unified_diff()
        .context_radius(3)
        .header("a/current", "b/desired")
        .to_string()
}

/// Compare current server blocks against desired server blocks and return
/// the blocks that would change.
///
/// A block is considered changed if its `server_name` appears in `desired`
/// but with different configuration (port, upstream, TLS settings).
pub fn changed_blocks<'a>(
    current: &[ServerBlock],
    desired: &'a [ServerBlock],
) -> Vec<&'a ServerBlock> {
    desired
        .iter()
        .filter(|d| {
            let current_match = current.iter().find(|c| c.server_name == d.server_name);
            match current_match {
                Some(c) => c != *d,
                None => true,
            }
        })
        .collect()
}

/// Return server blocks that exist in `current` but are absent from `desired`
/// (i.e. they would be removed).
pub fn removed_blocks<'a>(
    current: &'a [ServerBlock],
    desired: &[ServerBlock],
) -> Vec<&'a ServerBlock> {
    current
        .iter()
        .filter(|c| !desired.iter().any(|d| d.server_name == c.server_name))
        .collect()
}

/// Render a summary of changes between current and desired configurations.
pub fn diff_summary(current: &[ServerBlock], desired: &[ServerBlock]) -> String {
    let changed = changed_blocks(current, desired);
    let removed = removed_blocks(current, desired);

    let added_names: Vec<&str> = changed
        .iter()
        .filter(|d| !current.iter().any(|c| c.server_name == d.server_name))
        .map(|b| b.server_name.as_str())
        .collect();

    let modified_names: Vec<&str> = changed
        .iter()
        .filter(|d| current.iter().any(|c| c.server_name == d.server_name))
        .map(|b| b.server_name.as_str())
        .collect();

    let mut lines = Vec::new();

    if !added_names.is_empty() {
        lines.push(format!("Added: {}", added_names.join(", ")));
    }

    if !modified_names.is_empty() {
        lines.push(format!("Modified: {}", modified_names.join(", ")));
    }

    if !removed.is_empty() {
        let removed_names: Vec<&str> = removed.iter().map(|b| b.server_name.as_str()).collect();
        lines.push(format!("Removed: {}", removed_names.join(", ")));
    }

    if lines.is_empty() {
        lines.push("No changes.".into());
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::TlsConfig;

    #[test]
    fn diff_configs_shows_changes() {
        let old = "server {\n    listen 80;\n}\n";
        let new = "server {\n    listen 443 ssl;\n}\n";

        let diff = diff_configs(old, new);
        assert!(diff.contains("-    listen 80;"));
        assert!(diff.contains("+    listen 443 ssl;"));
    }

    #[test]
    fn changed_blocks_detects_new() {
        let current = vec![ServerBlock::new("a.com", 80, "127.0.0.1:3000")];
        let desired = vec![
            ServerBlock::new("a.com", 80, "127.0.0.1:3000"),
            ServerBlock::new("b.com", 80, "127.0.0.1:4000"),
        ];

        let changed = changed_blocks(&current, &desired);
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].server_name, "b.com");
    }

    #[test]
    fn changed_blocks_detects_modification() {
        let current = vec![ServerBlock::new("a.com", 80, "127.0.0.1:3000")];
        let desired = vec![
            ServerBlock::new("a.com", 443, "127.0.0.1:3000").with_tls(TlsConfig::new(
                "a.com",
                "/cert.pem",
                "/key.pem",
            )),
        ];

        let changed = changed_blocks(&current, &desired);
        assert_eq!(changed.len(), 1);
    }

    #[test]
    fn removed_blocks_detects_removals() {
        let current = vec![
            ServerBlock::new("a.com", 80, "127.0.0.1:3000"),
            ServerBlock::new("b.com", 80, "127.0.0.1:4000"),
        ];
        let desired = vec![ServerBlock::new("a.com", 80, "127.0.0.1:3000")];

        let removed = removed_blocks(&current, &desired);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].server_name, "b.com");
    }

    #[test]
    fn diff_summary_no_changes() {
        let blocks = vec![ServerBlock::new("a.com", 80, "127.0.0.1:3000")];
        let summary = diff_summary(&blocks, &blocks);
        assert_eq!(summary, "No changes.");
    }
}
