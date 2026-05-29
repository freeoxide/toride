use crate::{Diagnostic, Result};

/// A single diagnostic check that can be run independently.
pub trait Check: Send + Sync {
    /// Machine-readable check identifier.
    fn id(&self) -> &'static str;
    /// Module name for diagnostic grouping.
    fn module(&self) -> &'static str;
    /// Execute the check and return any findings.
    fn run(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<Diagnostic>>> + Send + '_>>;
}
