//! Full SSH config resolution.
//!
//! Handles Include chains, token/env expansion, first-match-wins
//! (with IdentityFile accumulation), and CanonicalizeHostname double-parse.

use crate::Result;

/// Fully resolve config for a given host alias.
pub async fn resolve(_host: &str) -> Result<()> {
    todo!()
}
