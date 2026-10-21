//! Diff utilities for comparing proxy configurations.
//!
//! Provides unified diff output between current and desired configurations
//! using the `similar` crate.

use std::collections::{HashMap, HashSet};

use crate::spec::ServerBlock;

/// Below this block count on either side, pairing runs as a direct scan:
/// hashing overhead outweighs the quadratic scan for tiny site sets.
const LINEAR_PAIRING_MAX: usize = 64;

/// Identity of a server block for diffing: `server_name` plus `listen_port`.
///
/// The canonical nginx layout serves one domain from up to two blocks (a
/// port 80 redirect plus a port 443 vhost), so the name alone cannot pair
/// blocks; the port must be part of the key.
fn block_key(block: &ServerBlock) -> (&str, u16) {
    (block.server_name.as_str(), block.listen_port)
}

/// The outcome of pairing desired blocks against current blocks.
struct Pairing<'a> {
    /// Desired blocks with no identical current counterpart (add or modify).
    changed: Vec<&'a ServerBlock>,
    /// Current blocks with no identical desired counterpart (remove).
    removed: Vec<&'a ServerBlock>,
}

/// Pair identical blocks between `current` and `desired`, one-to-one.
fn pair_blocks<'a>(current: &'a [ServerBlock], desired: &'a [ServerBlock]) -> Pairing<'a> {
    if current.len() < LINEAR_PAIRING_MAX && desired.len() < LINEAR_PAIRING_MAX {
        pair_blocks_linear(current, desired)
    } else {
        pair_blocks_hashed(current, desired)
    }
}

/// Direct-scan pairing for small site sets.
fn pair_blocks_linear<'a>(current: &'a [ServerBlock], desired: &'a [ServerBlock]) -> Pairing<'a> {
    let mut consumed = vec![false; current.len()];
    let mut changed = Vec::new();
    for d in desired {
        match current
            .iter()
            .enumerate()
            .find(|(i, c)| !consumed[*i] && *c == d)
        {
            Some((i, _)) => consumed[i] = true,
            None => changed.push(d),
        }
    }
    let removed = current
        .iter()
        .zip(consumed)
        .filter_map(|(c, used)| (!used).then_some(c))
        .collect();
    Pairing { changed, removed }
}

/// Bucketed pairing for large site sets: O(n + m) keyed lookups instead of
/// the quadratic scan.
fn pair_blocks_hashed<'a>(current: &'a [ServerBlock], desired: &'a [ServerBlock]) -> Pairing<'a> {
    let mut buckets: HashMap<(&str, u16), Vec<&ServerBlock>> =
        HashMap::with_capacity(current.len());
    for block in current {
        buckets.entry(block_key(block)).or_default().push(block);
    }
    let mut changed = Vec::new();
    for d in desired {
        let Some(bucket) = buckets.get_mut(&block_key(d)) else {
            changed.push(d);
            continue;
        };
        match bucket.iter().position(|c| **c == *d) {
            Some(index) => {
                bucket.swap_remove(index);
            }
            None => changed.push(d),
        }
    }
    let removed = buckets.into_values().flatten().collect();
    Pairing { changed, removed }
}

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
/// Blocks are paired by `(server_name, listen_port)` and compared for full
/// equality: a desired block with no identical current counterpart (same key
/// and same configuration) is reported. A name match whose port or
/// configuration differs counts as changed, so the two-blocks-per-domain
/// layout (port 80 redirect plus port 443 vhost) neither reports perpetual
/// modification nor hides a dropped block.
pub fn changed_blocks<'a>(
    current: &'a [ServerBlock],
    desired: &'a [ServerBlock],
) -> Vec<&'a ServerBlock> {
    pair_blocks(current, desired).changed
}

/// Return server blocks that exist in `current` but are absent from `desired`
/// (i.e. they would be removed).
///
/// Pairing matches [`changed_blocks`]: a current block survives only when a
/// desired block with the same `(server_name, listen_port)` key and identical
/// configuration exists.
pub fn removed_blocks<'a>(
    current: &'a [ServerBlock],
    desired: &'a [ServerBlock],
) -> Vec<&'a ServerBlock> {
    pair_blocks(current, desired).removed
}

/// Render a summary of changes between current and desired configurations.
pub fn diff_summary(current: &[ServerBlock], desired: &[ServerBlock]) -> String {
    let Pairing { changed, removed } = pair_blocks(current, desired);
    let current_keys: HashSet<(&str, u16)> = current.iter().map(block_key).collect();

    let mut added_names: Vec<&str> = Vec::new();
    let mut modified_names: Vec<&str> = Vec::new();
    for block in &changed {
        if current_keys.contains(&block_key(block)) {
            modified_names.push(block.server_name.as_str());
        } else {
            added_names.push(block.server_name.as_str());
        }
    }

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

    /// The canonical two-blocks-per-domain layout (port 80 redirect plus a
    /// port 443 vhost) with identical desired state must report no changes:
    /// keying on `server_name` alone made this perpetually "modified".
    #[test]
    fn two_block_domain_roundtrip_reports_no_changes() {
        let current = vec![
            ServerBlock::new("a.com", 80, "127.0.0.1:3000"),
            ServerBlock::new("a.com", 443, "127.0.0.1:3000").with_tls(TlsConfig::new(
                "a.com",
                "/cert.pem",
                "/key.pem",
            )),
        ];
        let desired = current.clone();

        assert!(
            changed_blocks(&current, &desired).is_empty(),
            "identical two-block domain must not report changes"
        );
        assert!(
            removed_blocks(&current, &desired).is_empty(),
            "identical two-block domain must not report removals"
        );
        assert_eq!(diff_summary(&current, &desired), "No changes.");
    }

    /// Dropping the port 80 redirect of a two-block domain must surface as a
    /// removal; the old name-only matching could never see it.
    #[test]
    fn removing_the_redirect_block_is_detected() {
        let current = vec![
            ServerBlock::new("a.com", 80, "127.0.0.1:3000"),
            ServerBlock::new("a.com", 443, "127.0.0.1:3000"),
        ];
        let desired = vec![ServerBlock::new("a.com", 443, "127.0.0.1:3000")];

        let removed = removed_blocks(&current, &desired);
        assert_eq!(removed.len(), 1, "the dropped :80 block must be reported");
        assert_eq!(removed[0].listen_port, 80);
        assert!(changed_blocks(&current, &desired).is_empty(), "no changes");
    }

    /// Modifying only the port 443 vhost of a two-block domain must report
    /// exactly that block: the new configuration as a change and the old
    /// block as a removal (add plus remove), never a perpetual modification
    /// of the name.
    #[test]
    fn modifying_only_the_vhost_block_reports_one_change() {
        let current = vec![
            ServerBlock::new("a.com", 80, "127.0.0.1:3000"),
            ServerBlock::new("a.com", 443, "127.0.0.1:3000"),
        ];
        let desired = vec![
            ServerBlock::new("a.com", 80, "127.0.0.1:3000"),
            ServerBlock::new("a.com", 443, "127.0.0.1:9"),
        ];

        let changed = changed_blocks(&current, &desired);
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].listen_port, 443);
        let removed = removed_blocks(&current, &desired);
        assert_eq!(removed.len(), 1, "the superseded :443 block is a removal");
        assert_eq!(removed[0].listen_port, 443);
        let summary = diff_summary(&current, &desired);
        assert!(
            summary.contains("Modified: a.com") && summary.contains("Removed: a.com"),
            "got: {summary}"
        );
    }

    /// Duplicate identical blocks must pair one-to-one: a desired set with
    /// two copies of a block and a current set with one must report the
    /// second copy as a change, and vice versa as a removal.
    #[test]
    fn duplicate_blocks_pair_one_to_one() {
        let block = || ServerBlock::new("a.com", 80, "127.0.0.1:3000");
        let single = vec![block()];
        let double = vec![block(), block()];

        assert_eq!(changed_blocks(&single, &double).len(), 1);
        assert_eq!(removed_blocks(&double, &single).len(), 1);
    }
}
