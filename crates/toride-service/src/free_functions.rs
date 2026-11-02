//! Standalone convenience functions using a default `DuctRunner`.
//!
//! These functions provide quick access to common systemd service queries
//! without requiring explicit construction of a [`ServiceManager`](crate::ServiceManager).
//!
//! Each function creates a temporary `DuctRunner`, so they are intended for
//! one-off calls. For repeated operations, prefer constructing a
//! [`ServiceManager`](crate::ServiceManager) once and reusing it.
//!
//! Only available when the `client` feature is enabled.

#[cfg(feature = "client")]
use crate::Result;

/// Build a one-shot [`crate::ServiceManager`] backed by a `DuctRunner`.
///
/// Routing through the manager gives these functions the same service-name
/// validation and `--` argv guard as [`crate::ServiceManager`].
#[cfg(feature = "client")]
fn manager() -> crate::ServiceManager {
    crate::ServiceManager::new(Box::new(toride_runner::DuctRunner))
}

/// Check whether the given service is currently active (running).
///
/// # Errors
///
/// Returns [`crate::Error::Other`] when the service name is rejected by
/// validation, and [`crate::Error::CommandFailed`] if `systemctl` cannot be
/// executed.
#[cfg(feature = "client")]
pub fn is_active(service: &str) -> Result<bool> {
    manager().is_active(service)
}

/// Start the given service unit.
///
/// # Errors
///
/// Returns [`crate::Error::Other`] when the service name is rejected by
/// validation, and [`crate::Error::CommandFailed`] if `systemctl start` exits
/// non-zero.
#[cfg(feature = "client")]
pub fn start(service: &str) -> Result<()> {
    manager().start(service)
}

/// Stop the given service unit.
///
/// # Errors
///
/// Returns [`crate::Error::Other`] when the service name is rejected by
/// validation, and [`crate::Error::CommandFailed`] if `systemctl stop` exits
/// non-zero.
#[cfg(feature = "client")]
pub fn stop(service: &str) -> Result<()> {
    manager().stop(service)
}

/// Restart the given service unit.
///
/// # Errors
///
/// Returns [`crate::Error::Other`] when the service name is rejected by
/// validation, and [`crate::Error::CommandFailed`] if `systemctl restart`
/// exits non-zero.
#[cfg(feature = "client")]
pub fn restart(service: &str) -> Result<()> {
    manager().restart(service)
}

#[cfg(all(test, feature = "client"))]
mod tests {
    use super::*;
    use crate::Error;

    #[test]
    fn free_functions_reject_flag_shaped_service_names() {
        for err in [
            is_active("-x").unwrap_err(),
            start("-x").unwrap_err(),
            stop("-x").unwrap_err(),
            restart("-x").unwrap_err(),
        ] {
            assert!(
                matches!(err, Error::Other(ref m) if m.contains("must not start with '-'")),
                "expected name validation to reject a flag-shaped name, got {err:?}"
            );
        }
    }

    #[test]
    fn free_functions_reject_empty_and_path_names() {
        let err = is_active("").unwrap_err();
        assert!(matches!(err, Error::Other(_)), "got {err:?}");
        let err = start("../etc/passwd").unwrap_err();
        assert!(matches!(err, Error::Other(_)), "got {err:?}");
    }
}
