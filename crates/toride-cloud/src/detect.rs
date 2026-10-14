//! Cloud provider detection from the environment and the DMI table.
//!
//! Determines which cloud provider the current machine is running on from
//! well-known environment variables (an explicit override: a set variable
//! classifies the host for that provider) and, when none is set, from the
//! DMI identification files under `/sys/class/dmi/id`. No metadata endpoint
//! is queried; see [`CloudProvider::metadata_url`] when a caller wants the
//! endpoint addresses for its own probing.

use std::fmt;

use crate::Result;

/// Supported cloud providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloudProvider {
    /// Amazon Web Services (EC2).
    Aws,
    /// Google Cloud Platform (GCE).
    Gcp,
    /// `DigitalOcean` (Droplets).
    DigitalOcean,
    /// Hetzner Cloud.
    Hetzner,
    /// Unknown or on-premises provider.
    Unknown,
}

impl fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aws => write!(f, "aws"),
            Self::Gcp => write!(f, "gcp"),
            Self::DigitalOcean => write!(f, "digitalocean"),
            Self::Hetzner => write!(f, "hetzner"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl CloudProvider {
    /// Returns all known (non-unknown) providers.
    #[must_use]
    pub const fn all() -> &'static [CloudProvider] {
        &[Self::Aws, Self::Gcp, Self::DigitalOcean, Self::Hetzner]
    }

    /// Returns the metadata endpoint URL for this provider.
    #[must_use]
    pub fn metadata_url(&self) -> Option<&'static str> {
        match self {
            Self::Aws => Some("http://169.254.169.254/latest/meta-data/"),
            Self::Gcp => Some("http://metadata.google.internal/computeMetadata/v1/"),
            Self::DigitalOcean => Some("http://169.254.169.254/metadata/v1/"),
            Self::Hetzner => Some("http://169.254.169.254/hetzner/v1/metadata/"),
            Self::Unknown => None,
        }
    }

    /// Returns the CLI tool name for this provider.
    #[must_use]
    pub fn cli_tool(&self) -> &'static str {
        match self {
            Self::Aws => "aws",
            Self::Gcp => "gcloud",
            Self::DigitalOcean => "doctl",
            Self::Hetzner => "hcloud",
            Self::Unknown => "",
        }
    }

    /// Parse a provider from a string identifier (case-insensitive).
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "aws" | "ec2" => Self::Aws,
            "gcp" | "gce" | "google" => Self::Gcp,
            "do" | "digitalocean" => Self::DigitalOcean,
            "hetzner" | "hcloud" => Self::Hetzner,
            _ => Self::Unknown,
        }
    }
}

/// Detect the current cloud provider from the environment and DMI files.
///
/// Well-known provider environment variables are treated as an explicit
/// override and checked first (e.g. an exported `AWS_REGION` classifies the
/// host as [`CloudProvider::Aws`] even on a bare-metal box, which matters
/// when firewall operations follow the verdict). When none is set, the DMI
/// identification files under `/sys/class/dmi/id` decide. No metadata
/// endpoint is contacted.
///
/// # Errors
///
/// Returns [`Error::ProviderNotFound`](crate::error::Error::ProviderNotFound)
/// when neither source classifies the host (e.g. bare metal, a local VM, or
/// a container without DMI): proceeding with firewall operations against a
/// guessed provider would target the wrong account, so detection must be
/// explicit (`--provider` in the CLI) rather than defaulted.
pub fn detect_provider() -> Result<CloudProvider> {
    detect_provider_with(&detect_from_env, &detect_from_files)
}

/// The pure detection core: env lookup first (explicit override), then the
/// DMI file probe, then a typed error. Split out so the decision table is
/// testable without mutating the process environment.
fn detect_provider_with(
    env_probe: &dyn Fn() -> Option<CloudProvider>,
    files_probe: &dyn Fn() -> Option<CloudProvider>,
) -> Result<CloudProvider> {
    if let Some(provider) = env_probe() {
        return Ok(provider);
    }
    if let Some(provider) = files_probe() {
        return Ok(provider);
    }
    Err(crate::error::Error::ProviderNotFound(
        "no cloud provider detected (no provider env vars set, no cloud DMI vendor); \
         pass the provider explicitly instead of guessing"
            .to_string(),
    ))
}

/// Try to detect the cloud provider from well-known environment variables.
fn detect_from_env() -> Option<CloudProvider> {
    detect_from_env_with(&|key| std::env::var(key).ok().filter(|v| !v.trim().is_empty()))
}

/// The env-var decision table over an injectable lookup (tests feed a map).
/// A variable set to a blank value does not count as set.
fn detect_from_env_with(var: &dyn Fn(&str) -> Option<String>) -> Option<CloudProvider> {
    let set = |key: &str| var(key).is_some_and(|v| !v.trim().is_empty());

    // AWS
    if set("AWS_EXECUTION_ENV") || set("AWS_REGION") || set("AWS_DEFAULT_REGION") {
        return Some(CloudProvider::Aws);
    }

    // GCP
    if set("GCE_METADATA_HOST") || set("GOOGLE_CLOUD_PROJECT") {
        return Some(CloudProvider::Gcp);
    }

    // DigitalOcean
    if set("DIGITALOCEAN_TOKEN") {
        return Some(CloudProvider::DigitalOcean);
    }

    // Hetzner
    if set("HCLOUD_TOKEN") {
        return Some(CloudProvider::Hetzner);
    }

    None
}

/// Try to detect the cloud provider from well-known system files.
fn detect_from_files() -> Option<CloudProvider> {
    detect_from_files_with(&|path| std::fs::read_to_string(path).ok())
}

/// The DMI decision table over an injectable file reader (tests feed a map;
/// every candidate path lives under `/sys/class/dmi/id`).
fn detect_from_files_with(read: &dyn Fn(&str) -> Option<String>) -> Option<CloudProvider> {
    // AWS
    if let Some(vendor) = read("/sys/class/dmi/id/board_vendor")
        && vendor.trim() == "Amazon EC2"
    {
        return Some(CloudProvider::Aws);
    }

    // GCP
    if let Some(name) = read("/sys/class/dmi/id/product_name")
        && name.trim().starts_with("Google Compute Engine")
    {
        return Some(CloudProvider::Gcp);
    }

    // DigitalOcean
    if let Some(vendor) = read("/sys/class/dmi/id/sys_vendor")
        && vendor.trim() == "DigitalOcean"
    {
        return Some(CloudProvider::DigitalOcean);
    }

    // Hetzner
    if let Some(vendor) = read("/sys/class/dmi/id/board_vendor") {
        let v = vendor.trim();
        if v == "Hetzner" || v == "hcloud" {
            return Some(CloudProvider::Hetzner);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_map(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |key| owned.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    }

    #[test]
    fn env_detection_maps_each_provider() {
        let cases = [
            (vec![("AWS_REGION", "eu-central-1")], CloudProvider::Aws),
            (
                vec![("AWS_DEFAULT_REGION", "us-east-1")],
                CloudProvider::Aws,
            ),
            (
                vec![("GCE_METADATA_HOST", "metadata.google.internal")],
                CloudProvider::Gcp,
            ),
            (vec![("GOOGLE_CLOUD_PROJECT", "proj")], CloudProvider::Gcp),
            (
                vec![("DIGITALOCEAN_TOKEN", "tok")],
                CloudProvider::DigitalOcean,
            ),
            (vec![("HCLOUD_TOKEN", "tok")], CloudProvider::Hetzner),
        ];
        for (env, expected) in cases {
            let probe = env_map(&env);
            assert_eq!(
                detect_from_env_with(&probe),
                Some(expected),
                "env {env:?} must classify as {expected:?}"
            );
        }
        assert_eq!(
            detect_from_env_with(&|_| None),
            None,
            "no provider env vars means no env-based classification"
        );
    }

    /// An env var set to the empty string does not classify the host.
    #[test]
    fn env_detection_ignores_empty_values() {
        let probe = env_map(&[("AWS_REGION", "  ")]);
        assert_eq!(detect_from_env_with(&probe), None);
    }

    /// The documented env-override semantics: `AWS_REGION` wins over the DMI
    /// table even on a Hetzner board.
    #[test]
    fn env_override_takes_precedence_over_dmi() {
        let env = env_map(&[("AWS_REGION", "us-east-1")]);
        let dmi = |_p: &str| Some("Hetzner\n".to_string());
        let verdict = detect_provider_with(&|| detect_from_env_with(&env), &|| {
            detect_from_files_with(&dmi)
        })
        .unwrap();
        assert_eq!(verdict, CloudProvider::Aws);
    }

    #[test]
    fn dmi_detection_maps_each_vendor() {
        let cases = [
            (
                "/sys/class/dmi/id/board_vendor",
                "Amazon EC2\n",
                CloudProvider::Aws,
            ),
            (
                "/sys/class/dmi/id/product_name",
                "Google Compute Engine\n",
                CloudProvider::Gcp,
            ),
            (
                "/sys/class/dmi/id/sys_vendor",
                "DigitalOcean\n",
                CloudProvider::DigitalOcean,
            ),
            (
                "/sys/class/dmi/id/board_vendor",
                "Hetzner\n",
                CloudProvider::Hetzner,
            ),
            (
                "/sys/class/dmi/id/board_vendor",
                "hcloud\n",
                CloudProvider::Hetzner,
            ),
        ];
        for (path, content, expected) in cases {
            let dmi = move |p: &str| (p == path).then(|| content.to_string());
            assert_eq!(
                detect_from_files_with(&dmi),
                Some(expected),
                "DMI {path}={content:?} must classify as {expected:?}"
            );
        }
        assert_eq!(
            detect_from_files_with(&|_| None),
            None,
            "no DMI files means no file-based classification"
        );
    }

    /// Nothing matching is a typed error, not `Ok(Unknown)`: firewall
    /// operations against a guessed provider would target the wrong account.
    #[test]
    fn no_detection_is_a_typed_error() {
        let err = detect_provider_with(&|| None, &|| None).unwrap_err();
        assert!(
            matches!(err, crate::Error::ProviderNotFound(_)),
            "got {err:?}"
        );
        let unrelated_dmi =
            move |p: &str| (p == "/sys/class/dmi/id/board_vendor").then(|| "QEMU\n".to_string());
        let err =
            detect_provider_with(&|| None, &|| detect_from_files_with(&unrelated_dmi)).unwrap_err();
        assert!(matches!(err, crate::Error::ProviderNotFound(_)));
    }

    /// The live probes stay consistent with their decision tables (no env
    /// mutation: the live call either resolves a provider or errors).
    #[test]
    fn live_detect_provider_matches_decision_tables() {
        let live = detect_provider();
        let expected = detect_from_env().or_else(detect_from_files);
        match expected {
            Some(provider) => assert_eq!(live.unwrap(), provider),
            None => assert!(matches!(
                live.unwrap_err(),
                crate::Error::ProviderNotFound(_)
            )),
        }
    }

    #[test]
    fn from_str_loose_aws() {
        assert_eq!(CloudProvider::from_str_loose("aws"), CloudProvider::Aws);
    }

    #[test]
    fn from_str_loose_ec2() {
        assert_eq!(CloudProvider::from_str_loose("EC2"), CloudProvider::Aws);
    }

    #[test]
    fn from_str_loose_gcp() {
        assert_eq!(CloudProvider::from_str_loose("gcp"), CloudProvider::Gcp);
    }

    #[test]
    fn from_str_loose_gce() {
        assert_eq!(CloudProvider::from_str_loose("gce"), CloudProvider::Gcp);
    }

    #[test]
    fn from_str_loose_google() {
        assert_eq!(CloudProvider::from_str_loose("google"), CloudProvider::Gcp);
    }

    #[test]
    fn from_str_loose_do() {
        assert_eq!(
            CloudProvider::from_str_loose("do"),
            CloudProvider::DigitalOcean
        );
    }

    #[test]
    fn from_str_loose_digitalocean() {
        assert_eq!(
            CloudProvider::from_str_loose("digitalocean"),
            CloudProvider::DigitalOcean
        );
    }

    #[test]
    fn from_str_loose_hetzner() {
        assert_eq!(
            CloudProvider::from_str_loose("hetzner"),
            CloudProvider::Hetzner
        );
    }

    #[test]
    fn from_str_loose_hcloud() {
        assert_eq!(
            CloudProvider::from_str_loose("hcloud"),
            CloudProvider::Hetzner
        );
    }

    #[test]
    fn from_str_loose_unknown() {
        assert_eq!(
            CloudProvider::from_str_loose("something-else"),
            CloudProvider::Unknown
        );
        assert_eq!(CloudProvider::from_str_loose(""), CloudProvider::Unknown);
    }

    #[test]
    fn from_str_loose_case_insensitive() {
        assert_eq!(CloudProvider::from_str_loose("AWS"), CloudProvider::Aws);
        assert_eq!(CloudProvider::from_str_loose("Aws"), CloudProvider::Aws);
        assert_eq!(CloudProvider::from_str_loose("GCP"), CloudProvider::Gcp);
        assert_eq!(
            CloudProvider::from_str_loose("DO"),
            CloudProvider::DigitalOcean
        );
        assert_eq!(
            CloudProvider::from_str_loose("HETZNER"),
            CloudProvider::Hetzner
        );
        assert_eq!(
            CloudProvider::from_str_loose("HCloud"),
            CloudProvider::Hetzner
        );
    }

    #[test]
    fn all_returns_four_providers() {
        let providers = CloudProvider::all();
        assert_eq!(providers.len(), 4);
        assert!(providers.contains(&CloudProvider::Aws));
        assert!(providers.contains(&CloudProvider::Gcp));
        assert!(providers.contains(&CloudProvider::DigitalOcean));
        assert!(providers.contains(&CloudProvider::Hetzner));
        assert!(!providers.contains(&CloudProvider::Unknown));
    }

    #[test]
    fn metadata_url_known_providers_return_some() {
        assert!(CloudProvider::Aws.metadata_url().is_some());
        assert!(CloudProvider::Gcp.metadata_url().is_some());
        assert!(CloudProvider::DigitalOcean.metadata_url().is_some());
        assert!(CloudProvider::Hetzner.metadata_url().is_some());
    }

    #[test]
    fn metadata_url_unknown_returns_none() {
        assert!(CloudProvider::Unknown.metadata_url().is_none());
    }

    #[test]
    fn cli_tool_returns_correct_names() {
        assert_eq!(CloudProvider::Aws.cli_tool(), "aws");
        assert_eq!(CloudProvider::Gcp.cli_tool(), "gcloud");
        assert_eq!(CloudProvider::DigitalOcean.cli_tool(), "doctl");
        assert_eq!(CloudProvider::Hetzner.cli_tool(), "hcloud");
        assert_eq!(CloudProvider::Unknown.cli_tool(), "");
    }

    #[test]
    fn display_formats_correctly() {
        assert_eq!(CloudProvider::Aws.to_string(), "aws");
        assert_eq!(CloudProvider::Gcp.to_string(), "gcp");
        assert_eq!(CloudProvider::DigitalOcean.to_string(), "digitalocean");
        assert_eq!(CloudProvider::Hetzner.to_string(), "hetzner");
        assert_eq!(CloudProvider::Unknown.to_string(), "unknown");
    }
}
