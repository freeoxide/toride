//! Parse and handle authorized_keys option fields.
//!
//! Supports: command, from, no-pty, no-port-forwarding, no-X11-forwarding,
//! no-agent-forwarding, permit-open, environment, tunnel, cert-authority.

use crate::Result;

/// Parse the options field of an authorized_keys line.
pub fn parse_options(_line: &str) -> Result<()> {
    todo!()
}
