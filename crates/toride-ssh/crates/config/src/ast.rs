//! Lossless parse tree for SSH config files.
//!
//! Preserves whitespace, `=` separators, comments, and blank lines.
//! Every byte of the original file is representable.

use serde::{Deserialize, Serialize};

/// Top-level SSH config AST.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigAst {
    /// Top-level nodes in the config file.
    pub nodes: Vec<ConfigNode>,
}

/// Separator between a keyword and its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Separator {
    /// Space or tab separator: `Host example.com`
    Space,
    /// Equals sign separator: `Host=example.com`
    Equals,
}

impl Separator {
    /// Render the separator as a string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Space => " ",
            Self::Equals => "=",
        }
    }
}

/// The default indentation string used when creating new blocks
/// (4 spaces, matching the OpenSSH convention).
const DEFAULT_INDENT: &str = "    ";

/// Data carried by a [`ConfigNode::Directive`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectiveData {
    /// The directive keyword (e.g. `HostName`, `User`, `Include`).
    pub keyword: String,
    /// Separator between keyword and value.
    pub separator: Separator,
    /// The raw value string.
    pub value: String,
    /// Optional trailing inline comment (without the `#`).
    pub comment: Option<String>,
    /// The leading whitespace/indentation before this directive.
    pub indent: String,
}

/// Data carried by a [`ConfigNode::HostBlock`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostBlockData {
    /// The full raw `Host` header line (e.g. `"Host example.com *.example.com"`).
    pub header: String,
    /// Parsed host patterns (e.g. `["example.com", "*.example.com"]`).
    pub patterns: Vec<String>,
    /// Nodes inside this Host block.
    pub nodes: Vec<ConfigNode>,
}

/// Data carried by a [`ConfigNode::MatchBlock`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchBlockData {
    /// The full raw `Match` header line.
    pub header: String,
    /// The raw criteria string (e.g. `"host *.example.com user alice"`).
    pub criteria: String,
    /// Nodes inside this Match block.
    pub nodes: Vec<ConfigNode>,
}

/// A single node in the SSH config AST.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConfigNode {
    /// An empty / blank line.
    BlankLine,
    /// A comment line (including the leading `#`).
    Comment {
        /// The comment text (including the leading `#`).
        text: String,
        /// The leading whitespace before this comment (preserved for round-trip).
        indent: String,
    },
    /// A standalone directive (not inside a Host/Match block).
    Directive(Box<DirectiveData>),
    /// A `Host` block containing nested directives.
    HostBlock(Box<HostBlockData>),
    /// A `Match` block containing nested directives.
    MatchBlock(Box<MatchBlockData>),
}

impl ConfigAst {
    /// Render the AST back to a string suitable for writing to disk.
    #[must_use]
    pub fn to_string_lossless(&self) -> String {
        let mut out = String::new();
        for node in &self.nodes {
            node.render(&mut out, 0);
        }
        out
    }
}

impl ConfigNode {
    /// Render this node (and children) into `out` at the given indent level.
    ///
    /// For nodes that carry their own `indent` string (parsed from the original
    /// file), that string is used instead of the computed prefix, preserving the
    /// original whitespace exactly.
    fn render(&self, out: &mut String, indent_level: usize) {
        let computed_prefix = DEFAULT_INDENT.repeat(indent_level);
        match self {
            Self::BlankLine => {
                out.push('\n');
            }
            Self::Comment { text, indent } => {
                if indent.is_empty() && indent_level > 0 {
                    out.push_str(&computed_prefix);
                } else {
                    out.push_str(indent);
                }
                out.push_str(text);
                out.push('\n');
            }
            Self::Directive(d) => {
                if d.indent.is_empty() && indent_level > 0 {
                    out.push_str(&computed_prefix);
                } else {
                    out.push_str(&d.indent);
                }
                out.push_str(&d.keyword);
                out.push_str(d.separator.as_str());
                out.push_str(&d.value);
                if let Some(ref c) = d.comment {
                    out.push_str(" #");
                    out.push_str(c);
                }
                out.push('\n');
            }
            Self::HostBlock(b) => {
                out.push_str(&computed_prefix);
                out.push_str(&b.header);
                out.push('\n');
                for child in &b.nodes {
                    child.render(out, indent_level + 1);
                }
            }
            Self::MatchBlock(b) => {
                out.push_str(&computed_prefix);
                out.push_str(&b.header);
                out.push('\n');
                for child in &b.nodes {
                    child.render(out, indent_level + 1);
                }
            }
        }
    }

    /// If this is a `HostBlock`, return its patterns and inner nodes.
    #[must_use]
    pub fn as_host_block(&self) -> Option<(&[String], &[Self])> {
        match self {
            Self::HostBlock(b) => Some((&b.patterns, &b.nodes)),
            _ => None,
        }
    }

    /// If this is a `HostBlock`, return mutable access to its nodes.
    pub fn as_host_block_mut(&mut self) -> Option<&mut Vec<Self>> {
        match self {
            Self::HostBlock(b) => Some(&mut b.nodes),
            _ => None,
        }
    }

    /// If this is a `Directive`, return its keyword and value.
    #[must_use]
    pub fn as_directive(&self) -> Option<(&str, &str)> {
        match self {
            Self::Directive(d) => Some((&d.keyword, &d.value)),
            _ => None,
        }
    }

    /// If this is a `Directive`, return mutable access to its fields.
    pub fn as_directive_mut(&mut self) -> Option<(&mut String, &mut String)> {
        match self {
            Self::Directive(d) => Some((&mut d.keyword, &mut d.value)),
            _ => None,
        }
    }
}

/// Parse an SSH config file string into a lossless AST.
///
/// Handles `Host` and `Match` blocks with proper nesting, preserves
/// whitespace, comments, blank lines, and both `=` and space separators.
#[must_use]
pub fn parse(input: &str) -> ConfigAst {
    let mut nodes = Vec::new();
    let mut lines = input.lines().peekable();

    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        let indent = line_indent(line);

        // Blank line
        if trimmed.is_empty() {
            nodes.push(ConfigNode::BlankLine);
            continue;
        }

        // Comment
        if trimmed.starts_with('#') {
            nodes.push(ConfigNode::Comment {
                text: trimmed.to_owned(),
                indent: indent.to_owned(),
            });
            continue;
        }

        // Parse keyword and value
        let (keyword, separator, rest) = parse_directive_parts(trimmed);
        if keyword.eq_ignore_ascii_case("host") {
            let patterns = parse_patterns(rest);
            let header = line.trim().to_owned();
            let inner = parse_block_body(&mut lines);
            nodes.push(ConfigNode::HostBlock(Box::new(HostBlockData {
                header,
                patterns,
                nodes: inner,
            })));
        } else if keyword.eq_ignore_ascii_case("match") {
            let header = line.trim().to_owned();
            let criteria = rest.to_owned();
            let inner = parse_block_body(&mut lines);
            nodes.push(ConfigNode::MatchBlock(Box::new(MatchBlockData {
                header,
                criteria,
                nodes: inner,
            })));
        } else {
            // Regular directive — check for trailing inline comment
            let (value, comment) = split_trailing_comment(rest);
            nodes.push(ConfigNode::Directive(Box::new(DirectiveData {
                keyword: keyword.to_owned(),
                separator,
                value,
                comment,
                indent: indent.to_owned(),
            })));
        }
    }

    ConfigAst { nodes }
}

/// Extract the leading whitespace from a line.
fn line_indent(line: &str) -> &str {
    let end = line
        .find(|c: char| !c.is_whitespace())
        .unwrap_or(line.len());
    &line[..end]
}

/// Parse the body of a Host/Match block, consuming indented lines.
///
/// # Known limitation (tracked followup)
///
/// Membership is gated on indentation: a line belongs to the block only if it
/// starts with whitespace. OpenSSH does **not** require body indentation — a
/// `Host`/`Match` block actually extends until the next `Host`/`Match` header
/// — so an *unindented* block-scoped directive (e.g. a real `sshd_config`
/// `Match User sftpuser` block written as
/// `Match User sftpuser\nChrootDirectory /sftp`) leaks into the global view.
/// In the Security tab this can misreport rare unindented Match-scoped
/// `AllowUsers`/`DenyUsers` as global.
///
/// The obvious fix — header-based membership — is correct but breaks the
/// managed-block feature (`managed.rs`): a `# >>> toride …` managed section
/// placed after a `Host` line would be absorbed into that Host block, and
/// `upsert_managed_block` (which appends at top level) would lose it on
/// re-parse. Reconciling the two needs a design decision (managed blocks as
/// self-contained blocks, or an explicit parser mode), so it is left as a
/// scoped followup rather than risked here.
///
/// IMPORTANT: this is **not** a display-only misreport. Because the leaked
/// directive is reified as a top-level `ConfigNode::Directive`, an editor that
/// scans `ast.nodes` (as `sshd::upsert_user_in_directive` does) would mutate
/// the leaked node and re-render it at indent 0 — permanently relocating a
/// `Match`/`Host`-scoped directive to global scope on disk. `sshd -t` passes
/// (the file is still syntactically valid), so the validation gate does not
/// catch it. The `sshd.rs` editor therefore **fail-closes**: if a directive it
/// is asked to edit is immediately preceded (in document order) by a
/// `Match`/`Host` block, it refuses the edit with `Error::SshdConfigInvalid`
/// rather than risk writing to the wrong scope.
fn parse_block_body<'a, I>(lines: &mut std::iter::Peekable<I>) -> Vec<ConfigNode>
where
    I: Iterator<Item = &'a str>,
{
    let mut body = Vec::new();

    while let Some(line) = lines.peek() {
        // A line that starts with whitespace is inside the block.
        if !line.starts_with(' ') && !line.starts_with('\t') {
            break;
        }

        let Some(line) = lines.next() else {
            break;
        };
        let trimmed = line.trim();
        let indent = line_indent(line);

        if trimmed.is_empty() {
            // A blank indented line is still part of the block.
            body.push(ConfigNode::BlankLine);
            continue;
        }

        if trimmed.starts_with('#') {
            body.push(ConfigNode::Comment {
                text: trimmed.to_owned(),
                indent: indent.to_owned(),
            });
            continue;
        }

        let (keyword, separator, rest) = parse_directive_parts(trimmed);

        // Nested Host/Match inside a block is not standard, but we handle it
        // gracefully by treating it as a directive.
        let (value, comment) = split_trailing_comment(rest);
        body.push(ConfigNode::Directive(Box::new(DirectiveData {
            keyword: keyword.to_owned(),
            separator,
            value,
            comment,
            indent: indent.to_owned(),
        })));
    }

    body
}

/// Split a directive line into (keyword, separator, rest-of-line).
///
/// An `=` is only treated as the separator when it appears immediately after
/// the keyword token with **no intervening whitespace** — i.e. `Key=Value`.
/// If there is whitespace before the `=` (e.g. `SetEnv FOO=bar`) the `=` is
/// part of the value, not the separator.
pub(crate) fn parse_directive_parts(line: &str) -> (&str, Separator, &str) {
    // Find the first whitespace boundary.
    let ws_pos = line.find(|c: char| c.is_whitespace());

    // Check for `=` separator: only valid if it appears before any whitespace
    // (i.e. `Keyword=Value`, not `Keyword Value=thing`).
    if let Some(eq_pos) = line.find('=') {
        let before_eq_has_space = line[..eq_pos].contains(' ') || line[..eq_pos].contains('\t');
        if !before_eq_has_space {
            let keyword = line[..eq_pos].trim();
            let rest = line[eq_pos + 1..].trim();
            return (keyword, Separator::Equals, rest);
        }
    }

    // Fall back to whitespace separator.
    if let Some(ws) = ws_pos {
        let keyword = &line[..ws];
        let rest = line[ws..].trim_start();
        return (keyword, Separator::Space, rest);
    }

    // Keyword only, no value.
    (line, Separator::Space, "")
}

/// Parse space-separated host patterns from a `Host` value string.
fn parse_patterns(value: &str) -> Vec<String> {
    value.split_whitespace().map(str::to_owned).collect()
}

/// Split a value string into (value, `optional_trailing_comment`).
///
/// Handles `# comment` at the end of a line. Quotes are respected so that
/// `#` inside quotes is not treated as a comment.
pub(crate) fn split_trailing_comment(value: &str) -> (String, Option<String>) {
    let mut in_double = false;
    let mut in_single = false;
    let mut comment_start = None;

    for (i, ch) in value.char_indices() {
        if ch == '"' && !in_single {
            in_double = !in_double;
        } else if ch == '\'' && !in_double {
            in_single = !in_single;
        } else if ch == '#' && !in_double && !in_single {
            comment_start = Some(i);
            break;
        }
    }

    match comment_start {
        Some(pos) => {
            let val = value[..pos].trim_end().to_owned();
            let comment = value[pos + 1..].trim().to_owned();
            (val, Some(comment))
        }
        None => (value.to_owned(), None),
    }
}

#[cfg(test)]
#[path = "ast.test.rs"]
mod tests;
