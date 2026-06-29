//! # toride-proxy
//!
//! Reverse proxy configuration, TLS certificate lifecycle, and WAF management
//! for the toride ecosystem.
//!
//! This crate provides a typed, idempotent, dry-run-capable API for managing
//! reverse proxies (Nginx, Caddy), TLS certificates (certbot/Let's Encrypt,
//! OpenSSL), and web application firewall rules.
//!
//! ## Quick start
//!
//! ```rust,ignore
//! use toride_proxy::ProxyClient;
//!
//! let client = ProxyClient::system()?;
//! let report = client.doctor(toride_proxy::doctor::DoctorScope::All)?;
//! ```
//!
//! # Module layout
//!
//! - [`error`] -- unified error types
//! - [`paths`] -- filesystem paths for proxy configuration
//! - [`spec`] -- strongly typed proxy specifications
//! - [`report`] -- structured report types
//! - [`parse`] -- parse nginx status, certbot, and OpenSSL output
//! - [`render`] -- render nginx server blocks, Caddyfiles, security headers
//! - [`validate`] -- validate server names, ports, cert paths
//! - [`diff`] -- diff proxy configurations
//! - [`backup`] -- pre-mutation backup of proxy configuration files
//!
//! ## Feature flags
//!
//! | Feature   | Default | Description                              |
//! |-----------|---------|------------------------------------------|
//! | `client`  | yes     | High-level ProxyClient                   |
//! | `doctor`  | yes     | Diagnostic checks for proxy/cert/WAF     |
//! | `service` | no      | systemd service integration              |
//! | `nginx`   | yes     | Nginx configuration and management       |
//! | `caddy`   | no      | Caddyfile configuration and management   |
//! | `certs`   | no      | TLS certificate lifecycle                |
//! | `waf`     | no      | Web Application Firewall stub            |
//! | `config`  | no      | Configuration file parsing/writing       |
//! | `serde`   | no      | Serialize/Deserialize on types           |
//! | `cli`     | no      | clap argument parsing                    |

#![deny(unsafe_code)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::module_name_repetitions)]

// ---------------------------------------------------------------------------
// Module declarations -- always compiled
// ---------------------------------------------------------------------------

pub mod backup;
pub mod diff;
pub mod error;
pub mod parse;
pub mod paths;
pub mod render;
pub mod report;
pub mod spec;
pub mod validate;

// ---------------------------------------------------------------------------
// Module declarations -- feature-gated: proxy backends
// ---------------------------------------------------------------------------

#[cfg(feature = "nginx")]
pub mod nginx;
pub mod nginx_config;
pub mod nginx_headers;

#[cfg(feature = "caddy")]
pub mod caddy;

// ---------------------------------------------------------------------------
// Module declarations -- feature-gated: certificate management
// ---------------------------------------------------------------------------

#[cfg(feature = "certs")]
pub mod certs;
pub mod certs_parse;
pub mod certs_renewal;

// ---------------------------------------------------------------------------
// Module declarations -- feature-gated: WAF
// ---------------------------------------------------------------------------

#[cfg(feature = "waf")]
pub mod waf;

// ---------------------------------------------------------------------------
// Module declarations -- feature-gated: client/service/doctor/config/cli
// ---------------------------------------------------------------------------

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "service")]
pub mod service;

#[cfg(feature = "doctor")]
pub mod doctor;

#[cfg(feature = "config")]
pub mod config;

#[cfg(feature = "cli")]
pub mod cli;

// ---------------------------------------------------------------------------
// Crate-level re-exports
// ---------------------------------------------------------------------------

pub use error::{Error, Result};
