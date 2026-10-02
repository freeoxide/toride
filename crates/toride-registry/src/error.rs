//! Error types for the toride-registry crate.

/// Convenience alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur while normalizing external registry sources into
/// [`App`](crate::App)s.
///
/// The variants mirror the adapter pipeline stages (DESIGN.md §3): a fetch
/// client produces [`Error::Http`], a pure parser produces
/// [`Error::Parse`], and dispatch/plan code produces
/// [`Error::UnsupportedSource`]. The enum is `#[non_exhaustive]` because
/// the source set grows across waves (winget, nixpkgs, Fedora RPM
/// repodata, …).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A registry payload could not be parsed into the normalized model.
    ///
    /// Produced by the adapters' pure parse half (`&str` in →
    /// `App` out); the payload text itself is never echoed back here.
    #[error("failed to parse {kind} payload for `{id}`: {message}")]
    Parse {
        /// Wire format that failed (`json`, `yaml`, …).
        kind: &'static str,
        /// Source-native id whose payload was being parsed
        /// (diagnostic only — the adapter that owns the payload knows it).
        id: String,
        /// Why the payload was rejected (deserializer message).
        message: String,
    },

    /// An HTTP request to a registry source failed (transport error,
    /// timeout, redirect loop, non-success status, …).
    ///
    /// Produced by the per-source fetch clients, which land together with
    /// the crate's `http` feature (DESIGN.md §9); until that phase the
    /// cause is carried as text in `message`. Once the clients exist the
    /// underlying transport error becomes a typed `#[source]` field, the
    /// same treatment as toride-installer's gated `Download` variant.
    #[error("request to {url} failed: {message}")]
    Http {
        /// The URL being fetched.
        url: String,
        /// Transport or status detail.
        message: String,
    },

    /// A [`SourceRef`](crate::model::SourceRef) named a
    /// [`SourceKind`](crate::model::SourceKind) the receiving code does not
    /// handle — an adapter asked to look up a row from a different source,
    /// or dispatch/plan code asked about a source with no adapter.
    #[error("no adapter handles source `{kind:?}` (id `{id}`)")]
    UnsupportedSource {
        /// The source kind nobody claimed.
        kind: crate::model::SourceKind,
        /// The source-native id involved.
        id: String,
    },

    /// A candidate [`TorideId`](crate::model::TorideId) violated the slug
    /// grammar (non-empty lowercase `[a-z0-9]` plus `-`, no
    /// leading/trailing/double hyphen). Returned by
    /// `TorideId::parse`; `TorideId::slugify` never produces it.
    #[error("invalid toride id `{input}`: {reason}")]
    InvalidTorideId {
        /// The rejected input, verbatim.
        input: String,
        /// The first grammar rule the input violated.
        reason: String,
    },

    /// Every source the [`Registry`](crate::Registry) fan-out asked
    /// failed — an empty hit list would look complete when it is not.
    #[error("every registry source failed for `{context}`")]
    AllSourcesFailed {
        /// The query or id whose fan-out failed on every source.
        context: String,
        /// One failure per registered adapter, in registration order.
        failures: Vec<SourceFailure>,
    },
}

/// One adapter's failure inside a [`Registry`](crate::Registry) fan-out —
/// which source failed and the error it failed with.
#[derive(Debug)]
pub struct SourceFailure {
    /// The failed adapter's source kind.
    pub source: crate::model::SourceKind,
    /// The failure that adapter reported.
    pub error: Error,
}

impl std::fmt::Display for SourceFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:?}: {}", self.source, self.error)
    }
}
