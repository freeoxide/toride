//! Lossless parse tree for SSH config files.
//!
//! Preserves whitespace, `=` separators, comments, and blank lines.
//! Every byte of the original file is representable.

use crate::Result;

/// Parse an SSH config file into a lossless AST.
pub fn parse(_input: &str) -> Result<()> {
    todo!()
}
