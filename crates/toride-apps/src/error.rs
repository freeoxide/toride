//! Error types for the toride-apps crate.

use crate::backend::BackendId;
use toride_registry::Platform;

/// Convenience alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// All errors produced by the toride-apps execution layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A backend command failed — spawn failure, non-zero exit, timeout, or
    /// unparseable output. Raised at the **execute** stage by the runner
    /// seam; wraps the shared runner error verbatim.
    #[error("backend command failed: {0}")]
    Command(#[from] toride_runner::Error),

    /// The registry source marked the app `disabled`, so it cannot be
    /// installed. Raised at the **plan** stage by [`plan_install`]
    /// ([`Availability::Disabled`] on the model; deprecated apps still plan —
    /// warning about them is the caller's/UI's job, not an error).
    ///
    /// [`plan_install`]: crate::plan_install
    /// [`Availability::Disabled`]: toride_registry::Availability::Disabled
    #[error("app `{app}` is disabled by its source and cannot be installed")]
    AppDisabled {
        /// Canonical toride id of the refused app.
        app: String,
    },

    /// The app's platform claims do not cover the host target. Raised at the
    /// **plan** stage; skipped entirely when the app declares no claims
    /// (the model treats empty `platforms` as "unknown", not "universal").
    #[error("app `{app}` does not claim support for target {target}: claims {claims:?}")]
    PlatformMismatch {
        /// Canonical toride id of the app.
        app: String,
        /// Debug rendering of the host [`crate::Target`].
        target: String,
        /// The app's declared platform claims, none of which matched.
        claims: Vec<Platform>,
    },

    /// The install method has no applicable backend on the host target —
    /// wrong OS, wrong distro family, a `Direct` method without the
    /// `direct` feature enabled, or an install technology this crate does
    /// not route yet. Raised at the **plan** stage.
    #[error("no backend can install `{app}` via {method} on target {target}: {reason}")]
    UnsupportedMethod {
        /// Canonical toride id of the app.
        app: String,
        /// Debug rendering of the [`InstallMethod`] that found no backend.
        ///
        /// [`InstallMethod`]: toride_registry::InstallMethod
        method: String,
        /// Debug rendering of the host [`crate::Target`].
        target: String,
        /// Why the method is inapplicable (e.g. "cask requires macOS").
        reason: String,
    },

    /// An operation needs root privileges but the caller did not grant
    /// elevation. Raised at the **execute** stage: distro managers require
    /// root to install/remove, and toride never runs `sudo` itself — the
    /// caller arranges elevation and asserts it via the request's
    /// `elevated` flag, or the backend refuses.
    #[error(
        "`{backend}` requires elevation for {operation}; re-run with privileges granted (toride never auto-sudoes)"
    )]
    ElevationRequired {
        /// Backend that needs root for the operation.
        backend: BackendId,
        /// Operation that needs root (`"install"` / `"uninstall"`).
        operation: &'static str,
    },

    /// A plan marked `dry_run` was handed to an executing backend. Mutating
    /// backends refuse dry-run plans instead of executing them; render the
    /// plan's argv instead of executing it.
    #[error("plan for `{app}` is marked dry-run; refusing to execute — render the plan instead")]
    DryRun {
        /// Canonical toride id of the app whose plan was refused.
        app: String,
    },

    /// A plan (or plan-bearing manifest record) failed to serialize or
    /// deserialize. Raised by the JSON round-trip helpers on the plan types,
    /// which the manifest layer (A5) persists through.
    #[error("plan serialization failed: {0}")]
    PlanJson(#[from] serde_json::Error),

    /// The install options requested a specific version and the routed
    /// method cannot express one. Raised at the **plan** stage: distro
    /// managers take no per-version install operand in this crate's argv
    /// model, so the refusal happens before any backend is selected.
    #[error(
        "cannot install `{app}` at version {version} via {method}: the method takes no version operand — pass version: None"
    )]
    VersionNotSelectable {
        /// Canonical toride id of the app.
        app: String,
        /// Debug rendering of the [`InstallMethod`] that cannot select a
        /// version.
        ///
        /// [`InstallMethod`]: toride_registry::InstallMethod
        method: String,
        /// The requested version's native spelling.
        version: String,
    },

    /// The requested install version cannot be spelled into the method's
    /// native addressing (an empty version, a brew token that already
    /// names a versioned track, a flatpak version carrying the ref
    /// separator). Raised at the **plan** stage — the malformed address
    /// (`token@`, `app/<id>/<arch>/`) is refused here rather than deferred
    /// to a confusing execute-time error.
    #[error("cannot install `{app}` at version {version}: {reason}")]
    InvalidVersion {
        /// Canonical toride id of the app.
        app: String,
        /// The requested version's spelling.
        version: String,
        /// Why the version cannot be addressed.
        reason: String,
    },

    /// The backend cannot hold an item back from upgrades (or release that
    /// hold): only homebrew has a pin concept among the wave-1 managers.
    #[error("`{backend}` cannot {operation} `{id}`: {reason}")]
    PinUnsupported {
        /// Backend the pin or unpin was routed to.
        backend: BackendId,
        /// The refused action (`"pin"` / `"unpin"`).
        operation: &'static str,
        /// Backend-native id the action was requested for.
        id: String,
        /// Why the backend refuses (no pin concept, or the kind cannot pin).
        reason: String,
    },

    /// The toride-installer pipeline failed for a direct download —
    /// resolve, download, digest, verify, extract, or the atomic install
    /// write (gated with the `direct` feature).
    #[cfg(feature = "direct")]
    #[error("direct install failed: {0}")]
    Direct(#[from] toride_installer::Error),

    /// A direct uninstall was refused or failed: only the canonicalized
    /// install-dir binary is ever removed (gated with the `direct`
    /// feature).
    #[cfg(feature = "direct")]
    #[error("direct uninstall of `{path}` failed: {reason}")]
    DirectUninstallFailed {
        /// The recorded binary path the removal was attempted on.
        path: String,
        /// Why the removal was refused or failed.
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use toride_registry::DistroFamily;

    #[test]
    fn display_names_the_app_for_disabled() {
        let error = Error::AppDisabled {
            app: "old-tool".to_owned(),
        };
        assert!(error.to_string().contains("old-tool"), "{error}");
    }

    #[test]
    fn display_names_backend_and_operation_for_elevation() {
        let error = Error::ElevationRequired {
            backend: BackendId::Distro(DistroFamily::Debian),
            operation: "install",
        };
        let text = error.to_string();
        assert!(text.contains("install"), "{text}");
        assert!(text.contains("never auto-sudoes"), "{text}");
    }

    #[test]
    fn command_variant_wraps_the_runner_error_as_source() {
        let inner = toride_runner::Error::BinaryNotFound("brew".to_owned());
        let error = Error::from(inner);
        assert!(matches!(error, Error::Command(_)));
        assert!(
            std::error::Error::source(&error).is_some(),
            "the wrapped runner error must remain reachable via source()"
        );
    }

    #[test]
    fn display_names_method_and_version_for_not_selectable() {
        let error = Error::VersionNotSelectable {
            app: "brave".to_owned(),
            method: "Distro { family: Debian, repo: None, package: \"brave-browser\" }".to_owned(),
            version: "1.4.2".to_owned(),
        };
        let text = error.to_string();
        assert!(text.contains("`brave`"), "{text}");
        assert!(text.contains("1.4.2"), "{text}");
        assert!(text.contains("version: None"), "{text}");
    }

    #[test]
    fn display_names_app_version_and_reason_for_invalid_version() {
        let error = Error::InvalidVersion {
            app: "brave".to_owned(),
            version: "  ".to_owned(),
            reason: "the version is empty".to_owned(),
        };
        let text = error.to_string();
        assert!(text.contains("`brave`"), "{text}");
        assert!(text.contains("the version is empty"), "{text}");
    }

    #[test]
    fn display_names_backend_action_and_reason_for_pin_unsupported() {
        let error = Error::PinUnsupported {
            backend: BackendId::Flatpak,
            operation: "pin",
            id: "com.brave.Browser".to_owned(),
            reason: "this backend has no pin concept".to_owned(),
        };
        let text = error.to_string();
        assert!(text.contains("flatpak"), "{text}");
        assert!(text.contains("pin"), "{text}");
        assert!(text.contains("com.brave.Browser"), "{text}");
        assert!(text.contains("no pin concept"), "{text}");
    }

    #[cfg(feature = "direct")]
    #[test]
    fn direct_error_wraps_the_installer_error_as_source() {
        let inner = toride_installer::Error::NoChecksum {
            tool: "ripgrep".to_owned(),
        };
        let error = Error::from(inner);
        assert!(matches!(error, Error::Direct(_)), "{error:?}");
        assert!(
            std::error::Error::source(&error).is_some(),
            "the wrapped installer error must remain reachable via source()"
        );
        assert!(error.to_string().contains("ripgrep"), "{error}");
    }

    #[cfg(feature = "direct")]
    #[test]
    fn direct_uninstall_failed_names_the_path_and_reason() {
        let error = Error::DirectUninstallFailed {
            path: "/usr/bin/evil".to_owned(),
            reason: "it does not live in the install dir".to_owned(),
        };
        let text = error.to_string();
        assert!(text.contains("/usr/bin/evil"), "{text}");
        assert!(text.contains("install dir"), "{text}");
    }
}
