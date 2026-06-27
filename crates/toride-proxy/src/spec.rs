//! Strongly typed models for proxy specifications.
//!
//! [`ProxySpec`] describes the desired state of a reverse proxy configuration,
//! [`ServerBlock`] represents a single virtual host, and [`TlsConfig`]
//! specifies TLS certificate settings.

use crate::error::Result;
use crate::validate::{validate_cert_path, validate_port, validate_server_name, validate_upstream};

/// TLS configuration for a server block.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TlsConfig {
    /// Domain name for the TLS certificate.
    pub domain: String,
    /// Path to the TLS certificate file.
    pub cert_path: String,
    /// Path to the TLS private key file.
    pub key_path: String,
    /// Path to the certificate chain file (optional).
    pub chain_path: Option<String>,
    /// Whether to enable OCSP stapling.
    pub ocsp_stapling: bool,
}

impl TlsConfig {
    /// Create a new TLS configuration for a domain.
    pub fn new(domain: impl Into<String>, cert_path: impl Into<String>, key_path: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            cert_path: cert_path.into(),
            key_path: key_path.into(),
            chain_path: None,
            ocsp_stapling: true,
        }
    }

    /// Set a certificate chain path.
    pub fn with_chain(mut self, chain_path: impl Into<String>) -> Self {
        self.chain_path = Some(chain_path.into());
        self
    }

    /// Disable OCSP stapling.
    pub fn without_ocsp(mut self) -> Self {
        self.ocsp_stapling = false;
        self
    }
}

/// A single server block (virtual host) in a proxy configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServerBlock {
    /// Server name (domain) for this block.
    pub server_name: String,
    /// Port to listen on.
    pub listen_port: u16,
    /// Whether TLS is enabled for this server block.
    pub tls: Option<TlsConfig>,
    /// Upstream (backend) server address, e.g. `127.0.0.1:3000`.
    pub upstream: String,
    /// Additional server directives (raw nginx/caddy config lines).
    pub extra_directives: Vec<String>,
}

impl ServerBlock {
    /// Create a new server block.
    pub fn new(
        server_name: impl Into<String>,
        listen_port: u16,
        upstream: impl Into<String>,
    ) -> Self {
        Self {
            server_name: server_name.into(),
            listen_port,
            tls: None,
            upstream: upstream.into(),
            extra_directives: Vec::new(),
        }
    }

    /// Enable TLS for this server block.
    pub fn with_tls(mut self, tls: TlsConfig) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Add an extra directive.
    pub fn with_directive(mut self, directive: impl Into<String>) -> Self {
        self.extra_directives.push(directive.into());
        self
    }

    /// Validate this server block.
    ///
    /// Checks the server name, listen port, upstream address, and (when TLS is
    /// configured) the certificate / key / chain paths. Previously only the
    /// server name and port were checked, so a block with a missing-port
    /// upstream or a bogus cert path passed validation and was written to disk.
    pub fn validate(&self) -> Result<()> {
        validate_server_name(&self.server_name)?;
        validate_port(self.listen_port)?;
        validate_upstream(&self.upstream)?;
        if let Some(tls) = &self.tls {
            validate_cert_path(&tls.cert_path)?;
            validate_cert_path(&tls.key_path)?;
            if let Some(chain) = &tls.chain_path {
                validate_cert_path(chain)?;
            }
        }
        Ok(())
    }
}

/// A complete proxy specification.
///
/// Describes the desired state of reverse proxy configuration.
/// Contains one or more server blocks and optional global settings.
///
/// # Example
///
/// ```
/// use toride_proxy::spec::{ProxySpec, ServerBlock, TlsConfig};
///
/// let spec = ProxySpec::builder()
///     .block(ServerBlock::new("example.com", 443, "127.0.0.1:3000")
///         .with_tls(TlsConfig::new(
///             "example.com",
///             "/etc/letsencrypt/live/example.com/fullchain.pem",
///             "/etc/letsencrypt/live/example.com/privkey.pem",
///         )))
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProxySpec {
    /// Server blocks in this proxy configuration.
    pub server_blocks: Vec<ServerBlock>,
    /// Global proxy headers to add to all blocks.
    pub global_headers: Vec<(String, String)>,
    /// Whether to enable HTTP/2 support.
    pub http2: bool,
}

impl ProxySpec {
    /// Start building a new proxy spec.
    pub fn builder() -> ProxySpecBuilder {
        ProxySpecBuilder::default()
    }

    /// Validate all server blocks in this spec.
    pub fn validate(&self) -> Result<()> {
        for block in &self.server_blocks {
            block.validate()?;
        }
        Ok(())
    }

    /// Return server blocks that have TLS configured.
    pub fn tls_blocks(&self) -> Vec<&ServerBlock> {
        self.server_blocks.iter().filter(|b| b.tls.is_some()).collect()
    }

    /// Return server blocks without TLS.
    pub fn plaintext_blocks(&self) -> Vec<&ServerBlock> {
        self.server_blocks.iter().filter(|b| b.tls.is_none()).collect()
    }
}

/// Builder for [`ProxySpec`].
#[derive(Debug, Clone, Default)]
pub struct ProxySpecBuilder {
    spec: ProxySpec,
}

impl ProxySpecBuilder {
    /// Add a server block.
    pub fn block(mut self, block: ServerBlock) -> Self {
        self.spec.server_blocks.push(block);
        self
    }

    /// Add multiple server blocks.
    pub fn blocks(mut self, blocks: impl IntoIterator<Item = ServerBlock>) -> Self {
        self.spec.server_blocks.extend(blocks);
        self
    }

    /// Add a global header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.spec.global_headers.push((name.into(), value.into()));
        self
    }

    /// Enable HTTP/2 support.
    pub fn http2(mut self) -> Self {
        self.spec.http2 = true;
        self
    }

    /// Build the spec.
    pub fn build(self) -> ProxySpec {
        self.spec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_block_validation_rejects_empty_name() {
        let block = ServerBlock::new("", 80, "127.0.0.1:3000");
        assert!(block.validate().is_err());
    }

    #[test]
    fn server_block_validation_accepts_valid() {
        let block = ServerBlock::new("example.com", 443, "127.0.0.1:3000");
        assert!(block.validate().is_ok());
    }

    #[test]
    fn server_block_validation_rejects_bad_upstream() {
        // Missing port: validate_upstream must reject this now.
        let block = ServerBlock::new("example.com", 443, "127.0.0.1");
        assert!(block.validate().is_err());
    }

    #[test]
    fn server_block_validation_rejects_bad_cert_path() {
        // Bogus extension on the cert path: validate_cert_path must reject.
        let block = ServerBlock::new("example.com", 443, "127.0.0.1:3000").with_tls(
            TlsConfig::new("example.com", "/etc/ssl/cert.txt", "/etc/ssl/key.pem"),
        );
        assert!(block.validate().is_err());
    }

    #[test]
    fn server_block_validation_accepts_valid_tls() {
        let block = ServerBlock::new("example.com", 443, "127.0.0.1:3000").with_tls(
            TlsConfig::new(
                "example.com",
                "/etc/letsencrypt/live/example.com/fullchain.pem",
                "/etc/letsencrypt/live/example.com/privkey.pem",
            )
            .with_chain("/etc/letsencrypt/live/example.com/chain.pem"),
        );
        assert!(block.validate().is_ok());
    }

    #[test]
    fn proxy_spec_tls_blocks_filter() {
        let spec = ProxySpec::builder()
            .block(ServerBlock::new("example.com", 443, "127.0.0.1:3000")
                .with_tls(TlsConfig::new("example.com", "/cert.pem", "/key.pem")))
            .block(ServerBlock::new("http.example.com", 80, "127.0.0.1:3000"))
            .build();

        assert_eq!(spec.tls_blocks().len(), 1);
        assert_eq!(spec.plaintext_blocks().len(), 1);
    }

    #[test]
    fn tls_config_builder() {
        let tls = TlsConfig::new("example.com", "/cert.pem", "/key.pem")
            .with_chain("/chain.pem")
            .without_ocsp();

        assert_eq!(tls.domain, "example.com");
        assert_eq!(tls.chain_path, Some("/chain.pem".into()));
        assert!(!tls.ocsp_stapling);
    }
}
