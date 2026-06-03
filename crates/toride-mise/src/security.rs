//! Security policy for controlling mise behaviour in automated contexts.
//!
//! [`SecurityPolicy`] defines conservative defaults for mise invocations
//! driven by automation (CI, editors, daemons) where interactive prompts and
//! untrusted config execution are undesirable.
//!
//! # Example
//!
//! ```rust,ignore
//! use toride_mise::{Mise, SecurityPolicy};
//!
//! let policy = SecurityPolicy {
//!     locked: true,
//!     require_trusted_config: true,
//!     ..SecurityPolicy::default()
//! };
//!
//! let mise = Mise::with_security(policy).build()?;
//! ```

use crate::builder::MiseBuilder;
use crate::client::{LoadPolicy, MiseMode};

// ---------------------------------------------------------------------------
// SecurityPolicy
// ---------------------------------------------------------------------------

/// Security policy applied to every mise invocation.
///
/// Fields translate directly to CLI flags and trust mode settings on the
/// [`Mise`](crate::Mise) client.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityPolicy {
    /// Allow mise hooks to run.
    ///
    /// When `false` (the default), `--no-hooks` is passed on every invocation.
    /// This prevents arbitrary script execution during automated workflows.
    pub allow_hooks: bool,

    /// Allow mise to set environment variables from config files.
    ///
    /// When `false`, `--no-env` is passed on every invocation.
    pub allow_env_from_config: bool,

    /// Pass `--locked` to enforce lockfile usage.
    ///
    /// When `true`, commands that support lockfiles will fail if the lockfile
    /// is out of date.
    pub locked: bool,

    /// Require config files to be explicitly trusted before use.
    ///
    /// When `true`, [`MiseMode::Untrusted`] is used and mise will reject
    /// untrusted config files rather than prompting.
    pub require_trusted_config: bool,

    /// Minimum age a mise release must have before it is considered safe to
    /// use (e.g. `"7d"`, `"24h"`).
    ///
    /// This is informational only -- it does not modify CLI flags. Consumers
    /// may inspect this field to reject freshly released binaries.
    pub minimum_release_age: Option<String>,
}

impl Default for SecurityPolicy {
    /// Return conservative defaults suitable for automated contexts.
    ///
    /// - `allow_hooks` is `false` to prevent arbitrary script execution.
    /// - `allow_env_from_config` is `false` to avoid environment leakage.
    /// - `locked` is `false` (opt-in).
    /// - `require_trusted_config` is `false` (opt-in).
    /// - `minimum_release_age` is `None`.
    fn default() -> Self {
        Self {
            allow_hooks: false,
            allow_env_from_config: false,
            locked: false,
            require_trusted_config: false,
            minimum_release_age: None,
        }
    }
}

impl SecurityPolicy {
    /// Convert this policy into a [`LoadPolicy`] for the mise client.
    ///
    /// Maps `allow_hooks` and `allow_env_from_config` to the corresponding
    /// `--no-*` flags. Config loading is always enabled.
    #[must_use]
    pub fn to_load_policy(&self) -> LoadPolicy {
        LoadPolicy {
            config: true,
            env: self.allow_env_from_config,
            hooks: self.allow_hooks,
        }
    }

    /// Convert this policy into a [`MiseMode`].
    ///
    /// Returns [`MiseMode::Untrusted`] when `require_trusted_config` is `true`,
    /// otherwise [`MiseMode::Trusted`].
    #[must_use]
    pub fn to_mise_mode(&self) -> MiseMode {
        if self.require_trusted_config {
            MiseMode::Untrusted
        } else {
            MiseMode::Trusted
        }
    }
}

// ---------------------------------------------------------------------------
// Mise client extension
// ---------------------------------------------------------------------------

use crate::client::Mise;

impl Mise {
    /// Create a [`MiseBuilder`] pre-configured with the given [`SecurityPolicy`].
    ///
    /// This is a convenience method that maps the policy fields onto the
    /// corresponding builder flags:
    ///
    /// - `allow_hooks` -> `--no-hooks` (inverted)
    /// - `allow_env_from_config` -> `--no-env` (inverted)
    /// - `locked` -> `--locked`
    /// - `require_trusted_config` -> [`MiseMode::Untrusted`]
    ///
    /// The returned builder can be further customised before calling
    /// [`MiseBuilder::build`].
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use toride_mise::{Mise, SecurityPolicy};
    ///
    /// let policy = SecurityPolicy {
    ///     locked: true,
    ///     ..SecurityPolicy::default()
    /// };
    ///
    /// let mise = Mise::with_security(policy).build()?;
    /// ```
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn with_security(policy: SecurityPolicy) -> MiseBuilder {
        let mut builder = MiseBuilder::new()
            .no_hooks(!policy.allow_hooks)
            .no_env(!policy.allow_env_from_config)
            .locked(policy.locked);

        if policy.require_trusted_config {
            builder = builder.mode(crate::client::MiseMode::Untrusted);
        }

        builder
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_conservative() {
        let policy = SecurityPolicy::default();
        assert!(!policy.allow_hooks);
        assert!(!policy.allow_env_from_config);
        assert!(!policy.locked);
        assert!(!policy.require_trusted_config);
        assert!(policy.minimum_release_age.is_none());
    }

    #[test]
    fn to_load_policy_blocks_hooks_and_env() {
        let policy = SecurityPolicy::default();
        let lp = policy.to_load_policy();
        assert!(lp.config);
        assert!(!lp.env);
        assert!(!lp.hooks);
    }

    #[test]
    fn to_load_policy_allows_when_enabled() {
        let policy = SecurityPolicy {
            allow_hooks: true,
            allow_env_from_config: true,
            ..SecurityPolicy::default()
        };
        let lp = policy.to_load_policy();
        assert!(lp.config);
        assert!(lp.env);
        assert!(lp.hooks);
    }

    #[test]
    fn to_mise_mode_trusted_by_default() {
        let policy = SecurityPolicy::default();
        assert_eq!(policy.to_mise_mode(), MiseMode::Trusted);
    }

    #[test]
    fn to_mise_mode_untrusted_when_required() {
        let policy = SecurityPolicy {
            require_trusted_config: true,
            ..SecurityPolicy::default()
        };
        assert_eq!(policy.to_mise_mode(), MiseMode::Untrusted);
    }
}
