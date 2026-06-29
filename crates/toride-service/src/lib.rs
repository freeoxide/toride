//! `toride-service` — shared systemd service management utilities.
//!
//! Provides a [`ServiceManager`] struct that wraps `systemctl` operations
//! behind the [`toride_runner::Runner`] trait, plus standalone convenience
//! functions for common queries.
//!
//! # Architecture
//!
//! The primary entry point is [`ServiceManager`], which accepts any
//! `Box<dyn toride_runner::Runner>` and delegates all `systemctl` invocations
//! through it. This keeps the entire call stack testable and supports dry-run
//! mode automatically.
//!
//! For quick one-off queries where dependency injection is unnecessary, the
//! free functions in [`free_functions`] use a default `DuctRunner` internally.
//!
//! # Example
//!
//! ```ignore
//! use toride_service::ServiceManager;
//! use toride_runner::DuctRunner;
//!
//! let runner = Box::new(DuctRunner::new());
//! let mgr = ServiceManager::new(runner);
//!
//! if mgr.is_active("sshd")? {
//!     mgr.restart("sshd")?;
//! }
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![expect(
    clippy::must_use_candidate,
    reason = "service methods are call-and-forget"
)]
#![expect(clippy::missing_errors_doc, reason = "library is internal")]

pub mod error;
pub mod free_functions;
pub mod manager;

pub use error::{Error, Result};
pub use manager::{ServiceManager, ServiceStatus};
