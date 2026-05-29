//! Mutation operations on the SSH config AST.

use super::ast::{ConfigAst, ConfigNode, Separator};
use crate::Result;

/// Add a new Host block to the config AST.
///
/// The block is appended after the last existing Host block (or at the end
/// if there are no Host blocks). A blank line separator is inserted before
/// the new block if needed.
pub fn add_host(
    ast: &mut ConfigAst,
    name: &str,
    directives: Vec<(String, String)>,
) -> Result<()> {
    // Check for duplicate.
    if find_host_index(ast, name).is_some() {
        return Err(crate::Error::DuplicateHost(name.to_owned()));
    }

    let nodes: Vec<ConfigNode> = directives
        .into_iter()
        .map(|(key, value)| ConfigNode::Directive {
            keyword: key,
            separator: Separator::Space,
            value,
            comment: None,
            indent: String::new(),
        })
        .collect();

    let block = ConfigNode::HostBlock {
        header: format!("Host {name}"),
        patterns: vec![name.to_owned()],
        nodes,
    };

    // Find the position after the last Host/Match block.
    let insert_pos = ast
        .nodes
        .iter()
        .rposition(|n| matches!(n, ConfigNode::HostBlock { .. } | ConfigNode::MatchBlock { .. }))
        .map(|i| i + 1)
        .unwrap_or(ast.nodes.len());

    // Insert a blank line separator before the new block if needed.
    if !ast.nodes.is_empty() && insert_pos > 0 {
        let prev_is_blank = insert_pos > 0
            && matches!(ast.nodes.get(insert_pos - 1), Some(ConfigNode::BlankLine));
        if !prev_is_blank {
            ast.nodes.insert(insert_pos, ConfigNode::BlankLine);
            ast.nodes.insert(insert_pos + 1, block);
            return Ok(());
        }
    }

    ast.nodes.insert(insert_pos, block);
    Ok(())
}

/// Remove a Host block from the config AST by name.
///
/// Matches against the first pattern in the block. If a blank line precedes
/// the block, it is also removed to avoid double-blank lines.
pub fn remove_host(ast: &mut ConfigAst, name: &str) -> Result<()> {
    let idx = find_host_index(ast, name)
        .ok_or_else(|| crate::Error::HostNotFound(name.to_owned()))?;

    ast.nodes.remove(idx);

    // Remove a preceding blank line to keep output clean.
    if idx > 0 && matches!(ast.nodes.get(idx - 1), Some(ConfigNode::BlankLine)) {
        ast.nodes.remove(idx - 1);
    }

    Ok(())
}

/// Rename a Host block by updating its header and patterns.
pub fn rename_host(ast: &mut ConfigAst, old_name: &str, new_name: &str) -> Result<()> {
    let idx = find_host_index(ast, old_name)
        .ok_or_else(|| crate::Error::HostNotFound(old_name.to_owned()))?;

    if find_host_index(ast, new_name).is_some() {
        return Err(crate::Error::DuplicateHost(new_name.to_owned()));
    }

    if let ConfigNode::HostBlock {
        header,
        patterns,
        ..
    } = &mut ast.nodes[idx]
    {
        *header = format!("Host {new_name}");
        *patterns = vec![new_name.to_owned()];
    }

    Ok(())
}

/// Add a directive to an existing Host block.
pub fn add_directive_to_host(
    ast: &mut ConfigAst,
    name: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    let idx = find_host_index(ast, name)
        .ok_or_else(|| crate::Error::HostNotFound(name.to_owned()))?;

    if let Some(nodes) = ast.nodes[idx].as_host_block_mut() {
        nodes.push(ConfigNode::Directive {
            keyword: key.to_owned(),
            separator: Separator::Space,
            value: value.to_owned(),
            comment: None,
            indent: String::new(),
        });
    }

    Ok(())
}

/// Remove a directive from an existing Host block by key.
pub fn remove_directive_from_host(ast: &mut ConfigAst, name: &str, key: &str) -> Result<()> {
    let idx = find_host_index(ast, name)
        .ok_or_else(|| crate::Error::HostNotFound(name.to_owned()))?;

    let key_lower = key.to_lowercase();
    if let Some(nodes) = ast.nodes[idx].as_host_block_mut() {
        nodes.retain(|node| {
            if let Some((k, _)) = node.as_directive() {
                !k.eq_ignore_ascii_case(&key_lower)
            } else {
                true
            }
        });
    }

    Ok(())
}

/// Find the index of a Host block by its first pattern (exact match).
pub(crate) fn find_host_index(ast: &ConfigAst, name: &str) -> Option<usize> {
    ast.nodes.iter().position(|node| {
        if let ConfigNode::HostBlock { patterns, .. } = node {
            patterns.iter().any(|p| p == name)
        } else {
            false
        }
    })
}

#[cfg(test)]
#[path = "editor.test.rs"]
mod tests;
