//! Error types for the toride-installer crate.

/// Convenience alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur while resolving, downloading, verifying, or
/// extracting a release artifact.
///
/// The variants mirror the stages of [`crate::Installer::install`] so callers
/// can react to a specific failure (e.g. retry on [`Error::Download`] but
/// surface [`Error::ChecksumMismatch`] as a hard security failure).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The requested OS/architecture combination is not supported by the
    /// target [`crate::Tool`].
    #[error("unsupported target for tool `{tool}`: {os}/{arch}")]
    UnsupportedTarget {
        /// Tool name.
        tool: String,
        /// Operating system string (e.g. `linux`, `macos`).
        os: String,
        /// Architecture string (e.g. `x86_64`, `aarch64`).
        arch: String,
    },

    /// A required [`crate::Tool`] field was not configured (e.g. a tarball
    /// tool with no `bin_path`).
    #[error("tool `{tool}` is missing required configuration: {field}")]
    MissingConfig {
        /// Tool name.
        tool: String,
        /// The unconfigured field name.
        field: String,
    },

    /// The artifact URL could not be resolved (bad version, missing release,
    /// or a malformed [`crate::Tool`] URL template).
    #[error("failed to resolve artifact URL for `{tool}`: {reason}")]
    Resolve {
        /// Tool name.
        tool: String,
        /// Why resolution failed.
        reason: String,
    },

    /// An HTTP request failed (transport, redirect loop, timeout, …).
    #[error("download failed for {url}: {source}")]
    Download {
        /// The URL being fetched.
        url: String,
        /// Underlying reqwest error.
        #[source]
        source: reqwest::Error,
    },

    /// The download body stalled: no chunk was received within the per-read
    /// deadline. A server that opens the connection and then never sends
    /// (or drips ~1 byte/minute) never trips the size cap, so the chunk loop
    /// races each read against [`crate::DEFAULT_CHUNK_TIMEOUT`] and surfaces
    /// this error when the deadline elapses.
    #[error("download of {url} stalled: no data within {timeout:?}")]
    DownloadStalled {
        /// The URL being fetched.
        url: String,
        /// The per-read deadline that elapsed.
        timeout: std::time::Duration,
    },

    /// The server returned a non-success HTTP status.
    #[error("download of {url} failed with HTTP {status}")]
    HttpStatus {
        /// The URL being fetched.
        url: String,
        /// The HTTP status code returned by the server.
        status: u16,
    },

    /// The downloaded artifact exceeded the configured maximum byte size.
    ///
    /// This is a defensive guard against accidental huge downloads (a
    /// misconfigured tool pointing at the wrong asset, a redirected HTML
    /// error page parsed as a binary, …).
    #[error("artifact from {url} is {size} bytes which exceeds the {max} byte cap")]
    TooLarge {
        /// The URL being fetched.
        url: String,
        /// Observed (declared or partial) size in bytes.
        size: u64,
        /// The configured maximum.
        max: u64,
    },

    /// The downloaded artifact was smaller than the configured sane minimum.
    ///
    /// Tools that publish no sha256 checksum are still guarded by a
    /// non-zero size floor so that a 404 HTML body or an empty response is
    /// never silently written to disk as the "binary".
    #[error("artifact from {url} is only {size} bytes, below the {min} byte sanity floor")]
    TooSmall {
        /// The URL being fetched.
        url: String,
        /// Observed size in bytes.
        size: u64,
        /// The configured minimum.
        min: u64,
    },

    /// The sha256 checksum of the downloaded bytes did not match the
    /// expected digest published by the tool.
    #[error("checksum mismatch for {tool}@{version}: expected {expected}, got {actual}")]
    ChecksumMismatch {
        /// Tool name.
        tool: String,
        /// Version being installed.
        version: String,
        /// Expected hex digest.
        expected: String,
        /// Actual hex digest.
        actual: String,
    },

    /// The tool's checksum file was fetched but did not contain a line whose
    /// filename component matched the configured asset name (or any parseable
    /// `<hex>` digest). The artifact is therefore treated as unverified and
    /// rejected rather than silently installed.
    #[error("checksum file at {url} had no matching entry for `{asset}`")]
    NoChecksumEntry {
        /// The checksum-file URL that was fetched.
        url: String,
        /// The asset name that was being looked up.
        asset: String,
    },

    /// The tool publishes no checksum; verification fell back to the size
    /// floor only. Returned only when a caller explicitly requests strict
    /// verification via [`crate::Verifier::Strict`].
    #[error("no checksum source available for `{tool}`; cannot verify in strict mode")]
    NoChecksum {
        /// Tool name.
        tool: String,
    },

    /// An archive could not be read or decompressed.
    #[error("failed to read {kind} archive: {source}")]
    Archive {
        /// Human-readable archive kind (e.g. `"tar.gz"`, `"tar.xz"`).
        kind: &'static str,
        /// Underlying I/O / decode error.
        #[source]
        source: std::io::Error,
    },

    /// The expected executable was not found inside a tarball.
    #[error("archive did not contain the expected entry `{bin_path}` for tool `{tool}`")]
    EntryNotFound {
        /// Tool name.
        tool: String,
        /// The entry path that was being looked up (relative to the archive).
        bin_path: String,
    },

    /// A filesystem I/O error occurred while writing the installed binary.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// An error from the [`toride-fs`] atomic-write helper.
    #[error(transparent)]
    Atomic(#[from] toride_fs::Error),

    /// The user's home directory could not be determined, so the default
    /// install directory (`~/.local/bin`) is unavailable.
    #[error("cannot determine home directory for default install path")]
    NoHomeDir,
}
