//! Nginx configuration parsing and rendering.
//!
//! Provides utilities for parsing existing Nginx configuration files and
//! rendering new ones from typed specifications. Always compiled (not
//! feature-gated) so that parsing/rendering is available without the `nginx`
//! feature.

use crate::error::Result;

/// A parsed Nginx configuration directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    /// Directive name (e.g. "listen", "server_name", "proxy_pass").
    pub name: String,
    /// Directive arguments (everything after the name, before the semicolon).
    pub args: Vec<String>,
    /// Whether this directive has a block (curly braces).
    pub has_block: bool,
    /// Child directives inside the block, if any.
    pub children: Vec<Directive>,
}

impl Directive {
    /// Create a simple directive with arguments and no block.
    pub fn simple(name: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            name: name.into(),
            args,
            has_block: false,
            children: Vec::new(),
        }
    }

    /// Create a block directive with children.
    pub fn block(name: impl Into<String>, args: Vec<String>, children: Vec<Directive>) -> Self {
        Self {
            name: name.into(),
            args,
            has_block: true,
            children,
        }
    }
}

/// A parsed Nginx server block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedServerBlock {
    /// Directives inside this server block.
    pub directives: Vec<Directive>,
}

impl ParsedServerBlock {
    /// Find the first directive by name.
    pub fn find(&self, name: &str) -> Option<&Directive> {
        self.directives.iter().find(|d| d.name == name)
    }

    /// Extract the server_name value(s).
    pub fn server_names(&self) -> Vec<&str> {
        self.directives
            .iter()
            .filter(|d| d.name == "server_name")
            .flat_map(|d| d.args.iter().map(|s| s.as_str()))
            .collect()
    }

    /// Extract the listen port.
    pub fn listen_port(&self) -> Option<u16> {
        self.directives
            .iter()
            .find(|d| d.name == "listen")
            .and_then(|d| d.args.first())
            .and_then(|s| {
                // Handle "443 ssl http2" -> extract 443
                s.split_whitespace()
                    .next()
                    .and_then(|n| n.parse::<u16>().ok())
            })
    }

    /// Check if this server block has SSL/TLS configured.
    pub fn has_ssl(&self) -> bool {
        self.directives
            .iter()
            .find(|d| d.name == "listen")
            .is_some_and(|d| d.args.iter().any(|a| a == "ssl"))
    }
}

/// Parse an Nginx configuration string into directives.
///
/// This is a simplified parser that handles the most common nginx config
/// constructs. It does not implement a full nginx config grammar.
///
/// # Supported constructs
///
/// - Simple directives: `name arg1 arg2;`
/// - Block directives: `name arg { ... }`
/// - Comments: `# comment`
///
/// # Limitations
///
/// - Does not handle quoted strings with embedded semicolons or braces
/// - Does not handle `if` blocks or complex map/hash constructs
/// - Does not handle `include` directives (they are parsed as simple directives)
pub fn parse_nginx_config(content: &str) -> Result<Vec<Directive>> {
    let mut directives = Vec::new();
    let mut stack: Vec<Directive> = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Remove trailing semicolons for simple directives
        let is_semicolon = trimmed.ends_with(';');
        let cleaned = if is_semicolon {
            &trimmed[..trimmed.len() - 1]
        } else {
            trimmed
        };

        // Check for closing brace
        if cleaned == "}" {
            if let Some(completed) = stack.pop() {
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(completed);
                } else {
                    directives.push(completed);
                }
            }
            continue;
        }

        // Check for opening brace
        let has_brace = cleaned.ends_with('{');
        let content_part = if has_brace {
            &cleaned[..cleaned.len() - 1]
        } else {
            cleaned
        };

        let parts: Vec<&str> = content_part.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let name = parts[0].to_string();
        let args: Vec<String> = parts[1..].iter().map(|s| (*s).to_string()).collect();

        let directive = Directive {
            name,
            args,
            has_block: has_brace,
            children: Vec::new(),
        };

        if has_brace {
            stack.push(directive);
        } else if let Some(parent) = stack.last_mut() {
            parent.children.push(directive);
        } else {
            directives.push(directive);
        }
    }

    Ok(directives)
}

/// Parse Nginx config and extract all server blocks.
pub fn parse_server_blocks(content: &str) -> Result<Vec<ParsedServerBlock>> {
    let directives = parse_nginx_config(content)?;

    let mut blocks = Vec::new();
    extract_server_blocks(&directives, &mut blocks);
    Ok(blocks)
}

/// Recursively extract server blocks from parsed directives.
fn extract_server_blocks(directives: &[Directive], blocks: &mut Vec<ParsedServerBlock>) {
    for directive in directives {
        if directive.name == "server" && directive.has_block {
            blocks.push(ParsedServerBlock {
                directives: directive.children.clone(),
            });
        }
        // Also check nested blocks (e.g. inside `http { ... }`)
        if directive.has_block {
            extract_server_blocks(&directive.children, blocks);
        }
    }
}

/// Render a [`Directive`] back to Nginx config text.
pub fn render_directive(dir: &Directive, indent: usize) -> String {
    let prefix = " ".repeat(indent);
    let args_str = dir.args.join(" ");

    if dir.has_block {
        let mut lines = Vec::new();
        if args_str.is_empty() {
            lines.push(format!("{prefix}{} {{", dir.name));
        } else {
            lines.push(format!("{prefix}{} {args_str} {{", dir.name));
        }
        for child in &dir.children {
            lines.push(render_directive(child, indent + 4));
        }
        lines.push(format!("{prefix}}}"));
        lines.join("\n")
    } else {
        format!("{prefix}{} {args_str};", dir.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_directive() {
        let config = "listen 80;\nserver_name example.com;\n";
        let dirs = parse_nginx_config(config).unwrap();
        assert_eq!(dirs.len(), 2);
        assert_eq!(dirs[0].name, "listen");
        assert_eq!(dirs[0].args, vec!["80"]);
        assert_eq!(dirs[1].name, "server_name");
        assert_eq!(dirs[1].args, vec!["example.com"]);
    }

    #[test]
    fn parse_server_block() {
        let config = "\
server {
    listen 80;
    server_name example.com;
    location / {
        proxy_pass http://127.0.0.1:3000;
    }
}
";
        let blocks = parse_server_blocks(config).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].server_names(), vec!["example.com"]);
        assert_eq!(blocks[0].listen_port(), Some(80));
        assert!(!blocks[0].has_ssl());
    }

    #[test]
    fn parse_ssl_server_block() {
        let config = "\
http {
    server {
        listen 443 ssl http2;
        server_name secure.example.com;
    }
}
";
        let blocks = parse_server_blocks(config).unwrap();
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].has_ssl());
        assert_eq!(blocks[0].listen_port(), Some(443));
    }

    #[test]
    fn render_directive_roundtrip() {
        let config = "listen 80;\n";
        let dirs = parse_nginx_config(config).unwrap();
        let rendered = render_directive(&dirs[0], 0);
        assert_eq!(rendered, "listen 80;");
    }
}
