mod ca;
mod krl;

/// SSH certificate and CA operations.
#[derive(Default)]
pub struct CertificateService;

impl CertificateService {
    /// Create a new certificate service.
    pub fn new() -> Self {
        Self
    }
}
