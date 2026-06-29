//! Mutation operations on the SSH config AST.

use super::ast::{ConfigAst, ConfigNode, DirectiveData, HostBlockData, Separator};
use toride_ssh_core::Result;

/// Add a new Host block to the config AST.
///
/// The block is appended after the last existing Host block (or at the end
/// if there are no Host blocks). A blank line separator is inserted before
/// the new block if needed.
///
/// # Errors
///
/// Returns [`Error::DuplicateHost`] if a Host block with the same name
/// already exists.
pub fn add_host(ast: &mut ConfigAst, name: &str, directives: Vec<(String, String)>) -> Result<()> {
    // Check for duplicate.
    if find_host_index(ast, name).is_some() {
        return Err(toride_ssh_core::Error::DuplicateHost(name.to_owned()));
    }

    let nodes: Vec<ConfigNode> = directives
        .into_iter()
        .map(|(key, value)| {
            ConfigNode::Directive(Box::new(DirectiveData {
                keyword: key,
                separator: Separator::Space,
                value,
                comment: None,
                indent: String::new(),
            }))
        })
        .collect();

    let block = ConfigNode::HostBlock(Box::new(HostBlockData {
        header: format!("Host {name}"),
        patterns: vec![name.to_owned()],
        nodes,
    }));

    // Find the position after the last Host/Match block.
    let insert_pos = ast
        .nodes
        .iter()
        .rposition(|n| matches!(n, ConfigNode::HostBlock(_) | ConfigNode::MatchBlock(_)))
        .map_or(ast.nodes.len(), |i| i + 1);

    // Insert a blank line separator before the new block if needed.
    if insert_pos > 0 {
        let prev_is_blank = matches!(ast.nodes.get(insert_pos - 1), Some(ConfigNode::BlankLine));
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
///
/// # Errors
///
/// Returns [`Error::HostNotFound`] if no Host block matches the given name.
pub fn remove_host(ast: &mut ConfigAst, name: &str) -> Result<()> {
    let idx = find_host_index(ast, name)
        .ok_or_else(|| toride_ssh_core::Error::HostNotFound(name.to_owned()))?;

    ast.nodes.remove(idx);

    // Remove a preceding blank line to keep output clean.
    if idx > 0 && matches!(ast.nodes.get(idx - 1), Some(ConfigNode::BlankLine)) {
        ast.nodes.remove(idx - 1);
    }

    Ok(())
}

/// Rename a Host block by updating its header and patterns.
///
/// # Errors
///
/// Returns [`Error::HostNotFound`] if `old_name` does not match any block,
/// or [`Error::DuplicateHost`] if `new_name` already exists.
pub fn rename_host(ast: &mut ConfigAst, old_name: &str, new_name: &str) -> Result<()> {
    let idx = find_host_index(ast, old_name)
        .ok_or_else(|| toride_ssh_core::Error::HostNotFound(old_name.to_owned()))?;

    if find_host_index(ast, new_name).is_some() {
        return Err(toride_ssh_core::Error::DuplicateHost(new_name.to_owned()));
    }

    if let ConfigNode::HostBlock(b) = &mut ast.nodes[idx] {
        b.header = format!("Host {new_name}");
        b.patterns = vec![new_name.to_owned()];
    }

    Ok(())
}

/// Add a directive to an existing Host block.
///
/// # Errors
///
/// Returns [`Error::HostNotFound`] if no Host block matches the given name.
#[allow(dead_code, reason = "public API, not exercised in-workspace")]
pub fn add_directive_to_host(
    ast: &mut ConfigAst,
    name: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    let idx = find_host_index(ast, name)
        .ok_or_else(|| toride_ssh_core::Error::HostNotFound(name.to_owned()))?;

    if let Some(nodes) = ast.nodes[idx].as_host_block_mut() {
        nodes.push(ConfigNode::Directive(Box::new(DirectiveData {
            keyword: key.to_owned(),
            separator: Separator::Space,
            value: value.to_owned(),
            comment: None,
            indent: String::new(),
        })));
    }

    Ok(())
}

/// Remove a directive from an existing Host block by key.
///
/// # Errors
///
/// Returns [`Error::HostNotFound`] if no Host block matches the given name.
#[allow(dead_code, reason = "public API, not exercised in-workspace")]
pub fn remove_directive_from_host(ast: &mut ConfigAst, name: &str, key: &str) -> Result<()> {
    let idx = find_host_index(ast, name)
        .ok_or_else(|| toride_ssh_core::Error::HostNotFound(name.to_owned()))?;

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
        if let ConfigNode::HostBlock(b) = node {
            b.patterns.iter().any(|p| p == name)
        } else {
            false
        }
    })
}

#[cfg(test)]
#[path = "editor.test.rs"]
mod tests;
