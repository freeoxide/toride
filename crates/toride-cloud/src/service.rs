//! Service management for cloud provider agents.
//!
//! Manages the lifecycle of cloud provider agents and helper services
//! (e.g. the AWS SSM agent, GCP guest agent, etc.).

use crate::CloudProvider;
use crate::error::Result;

// ---------------------------------------------------------------------------
// ServiceManager
// ---------------------------------------------------------------------------

/// Manages cloud provider services on the current machine.
///
/// Provides methods for checking service status, enabling/disabling services,
/// and restarting cloud provider agents.
pub struct ServiceManager {
    /// The cloud provider whose services are being managed.
    pub provider: CloudProvider,
}

impl ServiceManager {
    /// Create a new service manager for the given provider.
    #[must_use]
    pub fn new(provider: CloudProvider) -> Self {
        Self { provider }
    }

    /// Create a service manager by auto-detecting the provider.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ProviderNotFound`] if no provider can be detected.
    pub fn detect() -> Result<Self> {
        let provider = crate::detect::detect_provider()?;
        Ok(Self { provider })
    }

    /// Build a [`toride_service::ServiceManager`] for the provider's agent,
    /// backed by the default [`toride_runner::DuctRunner`].
    fn agent_service() -> toride_service::ServiceManager {
        toride_service::ServiceManager::new(Box::new(toride_runner::DuctRunner))
    }

    /// Map a [`toride_service::Error`] into the cloud [`crate::error::Error`].
    fn map_svc_err<T>(r: toride_service::Result<T>) -> Result<T> {
        r.map_err(|e| crate::error::Error::Other(e.to_string()))
    }

    /// Check if the provider's agent service is running.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::Other`] if the systemctl probe fails.
    pub fn is_agent_running(&self) -> Result<bool> {
        Self::map_svc_err(Self::agent_service().is_active(self.agent_service_name()))
    }

    /// Start the provider's agent service.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::Other`] if the start fails.
    pub fn start_agent(&self) -> Result<()> {
        Self::map_svc_err(Self::agent_service().start(self.agent_service_name()))
    }

    /// Stop the provider's agent service.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::Other`] if the stop fails.
    pub fn stop_agent(&self) -> Result<()> {
        Self::map_svc_err(Self::agent_service().stop(self.agent_service_name()))
    }

    /// Restart the provider's agent service.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::Other`] if the restart fails.
    pub fn restart_agent(&self) -> Result<()> {
        Self::map_svc_err(Self::agent_service().restart(self.agent_service_name()))
    }

    /// Check if the provider's agent service is enabled at boot.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::Other`] if the check fails.
    pub fn is_agent_enabled(&self) -> Result<bool> {
        Self::map_svc_err(Self::agent_service().is_enabled(self.agent_service_name()))
    }

    /// Enable the provider's agent service at boot.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::Other`] if the enable fails.
    pub fn enable_agent(&self) -> Result<()> {
        Self::map_svc_err(Self::agent_service().enable(self.agent_service_name()))
    }

    /// Disable the provider's agent service at boot.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::Other`] if the disable fails.
    pub fn disable_agent(&self) -> Result<()> {
        Self::map_svc_err(Self::agent_service().disable(self.agent_service_name()))
    }

    /// Return the name of the agent service for the current provider.
    #[must_use]
    pub fn agent_service_name(&self) -> &'static str {
        match self.provider {
            CloudProvider::Aws => "amazon-ssm-agent",
            CloudProvider::Gcp => "google-guest-agent",
            CloudProvider::DigitalOcean => "do-agent",
            CloudProvider::Hetzner => "hetzner-cloud-init",
            CloudProvider::Unknown => "",
        }
    }
}
