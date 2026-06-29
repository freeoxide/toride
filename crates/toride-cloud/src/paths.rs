//! Path resolution for cloud provider configuration and data.
//!
//! [`CloudPaths`] provides typed access to the directories and files used by
//! the toride-cloud crate for storing cloud provider configurations, cached
//! security group state, and provider-specific data.

use std::path::PathBuf;

use crate::{Error, Result};

// ---------------------------------------------------------------------------
// CloudPaths
// ---------------------------------------------------------------------------

/// Resolved paths to the toride-cloud data directories.
///
/// Uses XDG base directories on Linux and standard locations on macOS.
/// Each cloud provider gets its own subdirectory for configuration files.
#[derive(Debug, Clone)]
pub struct CloudPaths {
    /// Root configuration directory for toride-cloud (e.g. `~/.config/toride/cloud/`).
    pub config_dir: PathBuf,
    /// Directory for AWS-specific configuration files.
    pub aws_dir: PathBuf,
    /// Directory for GCP-specific configuration files.
    pub gcp_dir: PathBuf,
    /// Directory for DigitalOcean-specific configuration files.
    pub digitalocean_dir: PathBuf,
    /// Directory for Hetzner-specific configuration files.
    pub hetzner_dir: PathBuf,
    /// Cache directory for provider metadata and security group state.
    pub cache_dir: PathBuf,
}

impl CloudPaths {
    /// Create a `CloudPaths` from the default XDG location.
    ///
    /// Named `discover` rather than `default` because this lookup is fallible
    /// (the XDG config dir may be unresolvable), so it cannot implement the
    /// infallible [`std::default::Default`] trait.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Other`] if the home directory cannot be determined.
    pub fn discover() -> Result<Self> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| Error::Other("cannot determine config directory".to_string()))?
            .join("toride")
            .join("cloud");

        Self::with_config_dir(config_dir)
    }

    /// Create a `CloudPaths` from an explicit config directory.
    pub fn with_config_dir(config_dir: PathBuf) -> Result<Self> {
        Ok(Self {
            aws_dir: config_dir.join("aws"),
            gcp_dir: config_dir.join("gcp"),
            digitalocean_dir: config_dir.join("digitalocean"),
            hetzner_dir: config_dir.join("hetzner"),
            cache_dir: config_dir.join("cache"),
            config_dir,
        })
    }

    /// Ensure all provider directories exist on disk.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if any directory cannot be created.
    pub fn ensure_dirs(&self) -> Result<()> {
        let dirs = [
            &self.config_dir,
            &self.aws_dir,
            &self.gcp_dir,
            &self.digitalocean_dir,
            &self.hetzner_dir,
            &self.cache_dir,
        ];
        for dir in dirs {
            std::fs::create_dir_all(dir)?;
        }
        Ok(())
    }

    /// Return the path for a provider-specific configuration file.
    pub fn provider_config(&self, provider: &str, filename: &str) -> PathBuf {
        let dir = match provider {
            "aws" => &self.aws_dir,
            "gcp" => &self.gcp_dir,
            "digitalocean" => &self.digitalocean_dir,
            "hetzner" => &self.hetzner_dir,
            _ => &self.config_dir,
        };
        dir.join(filename)
    }
}
