//! Managed config block markers: `# >>> toride name` / `# <<< toride name`.
//!
//! Toride-managed blocks are delimited by special comment markers so the tool
//! can add, replace, and remove them without touching user-edited content.

use super::ast::{ConfigAst, ConfigNode, DirectiveData, Separator};
use crate::Result;

/// The prefix for a managed block opening marker.
const OPEN_PREFIX: &str = "# >>> toride ";

/// The prefix for a managed block closing marker.
const CLOSE_PREFIX: &str = "# <<< toride ";

/// Build the opening marker comment for a managed block.
fn open_marker(name: &str) -> String {
    format!("{OPEN_PREFIX}{name}")
}

/// Build the closing marker comment for a managed block.
fn close_marker(name: &str) -> String {
    format!("{CLOSE_PREFIX}{name}")
}

/// A managed block extracted from the AST, with its name and directive nodes.
#[derive(Debug, Clone)]
pub struct ManagedBlock {
    /// The name of this managed block (the part after `toride`).
    pub name: String,
    /// The directive nodes inside this managed block.
    pub nodes: Vec<ConfigNode>,
}

/// Extract a managed block by name.
///
/// Scans top-level nodes looking for `# >>> toride {name}` /
/// `# <<< toride {name}` comment pairs at the *top level* of the config.
/// Returns the directive nodes between the markers.
pub fn extract_managed_block(ast: &ConfigAst, name: &str) -> Option<ManagedBlock> {
    let open = open_marker(name);
    let close = close_marker(name);

    let mut inside = false;
    let mut nodes = Vec::new();

    for node in &ast.nodes {
        match node {
            ConfigNode::Comment { text, .. } if text.trim() == open => {
                inside = true;
            }
            ConfigNode::Comment { text, .. } if text.trim() == close => {
                return Some(ManagedBlock {
                    name: name.to_owned(),
                    nodes,
                });
            }
            _ if inside => {
                nodes.push(node.clone());
            }
            _ => {}
        }
    }

    // If we were inside but never hit the closing marker, that is a malformed
    // block — return what we have.
    if inside {
        Some(ManagedBlock {
            name: name.to_owned(),
            nodes,
        })
    } else {
        None
    }
}

/// List all managed block names in the config.
pub fn list_managed_blocks(ast: &ConfigAst) -> Vec<String> {
    let mut names = Vec::new();

    for node in &ast.nodes {
        if let ConfigNode::Comment { text, .. } = node {
            let trimmed = text.trim();
            if let Some(rest) = trimmed.strip_prefix(OPEN_PREFIX) {
                names.push(rest.to_owned());
            }
        }
    }

    names
}

/// Add or replace a managed block.
///
/// If a block with the same name already exists, it is replaced in place.
/// Otherwise the block is appended at the end of the config file.
pub fn upsert_managed_block(
    ast: &mut ConfigAst,
    name: &str,
    directives: Vec<(String, String)>,
) {
    // Try to find and replace existing block.
    let open = open_marker(name);
    let close = close_marker(name);

    let open_idx = ast.nodes.iter().position(|node| {
        matches!(node, ConfigNode::Comment { text, .. } if text.trim() == open)
    });

    if let Some(start) = open_idx {
        // Find the closing marker.
        let end = ast.nodes[start + 1..]
            .iter()
            .position(|node| {
                matches!(node, ConfigNode::Comment { text, .. } if text.trim() == close)
            })
            .map(|i| start + 1 + i);

        if let Some(end) = end {
            // Remove old content between markers, then splice in new content.
            ast.nodes.drain(start + 1..end);
            let insert_at = start + 1;
            ast.nodes.splice(
                insert_at..insert_at,
                directives
                    .into_iter()
                    .map(|(key, value)| ConfigNode::Directive(Box::new(DirectiveData {
                        keyword: key,
                        separator: Separator::Space,
                        value,
                        comment: None,
                        indent: String::new(),
                    }))),
            );
            return;
        }

        // Unclosed block: remove the orphaned opening marker and everything
        // after it (the stale content), then fall through to append a fresh block.
        ast.nodes.drain(start..);
    }

    // No existing block (or unclosed block was cleaned up) — append a new one.
    let open_comment = ConfigNode::Comment { text: open, indent: String::new() };
    let close_comment = ConfigNode::Comment { text: close, indent: String::new() };

    if !ast.nodes.is_empty() {
        ast.nodes.push(ConfigNode::BlankLine);
    }
    ast.nodes.push(open_comment);
    ast.nodes.extend(directives.into_iter().map(|(key, value)| ConfigNode::Directive(Box::new(DirectiveData {
        keyword: key,
        separator: Separator::Space,
        value,
        comment: None,
        indent: String::new(),
    }))));
    ast.nodes.push(close_comment);
}

/// Remove a managed block by name.
///
/// Removes the marker comments, all content between them, and any adjacent
/// blank line to keep the config clean.
pub fn remove_managed_block(ast: &mut ConfigAst, name: &str) -> Result<()> {
    let open = open_marker(name);
    let close = close_marker(name);

    let open_idx = ast.nodes.iter().position(|node| {
        matches!(node, ConfigNode::Comment { text, .. } if text.trim() == open)
    });

    let Some(start) = open_idx else {
        return Err(crate::Error::ManagedBlockNotFound(format!(
            "managed block {name} not found"
        )));
    };

    let end = ast.nodes[start + 1..]
        .iter()
        .position(|node| {
            matches!(node, ConfigNode::Comment { text, .. } if text.trim() == close)
        })
        .map(|i| start + 1 + i);

    let Some(end) = end else {
        return Err(crate::Error::ManagedBlockNotFound(format!(
            "managed block {name} closing marker not found"
        )));
    };

    // Remove from end+1 down to start (inclusive).
    ast.nodes.drain(start..=end);

    // Remove preceding blank line if present.
    if start > 0 && matches!(ast.nodes.get(start - 1), Some(ConfigNode::BlankLine)) {
        ast.nodes.remove(start - 1);
    }

    Ok(())
}

/// Check whether a managed block with the given name exists.
pub fn has_managed_block(ast: &ConfigAst, name: &str) -> bool {
    let open = open_marker(name);
    ast.nodes
        .iter()
        .any(|node| matches!(node, ConfigNode::Comment { text, .. } if text.trim() == open))
}

#[cfg(test)]
#[path = "managed.test.rs"]
mod tests;
