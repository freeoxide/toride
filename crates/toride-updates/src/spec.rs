//! Declarative update specification types.
//!
//! [`UpdateSpec`] describes the desired state of automatic security updates.
//! It is backend-agnostic: the same spec can be rendered into either APT or
//! DNF configuration files.

// ---------------------------------------------------------------------------
// Schedule
// ---------------------------------------------------------------------------

/// How often automatic updates should run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Schedule {
    /// Run once per day.
    Daily,
    /// Run once per week.
    Weekly,
    /// Run once per month.
    Monthly,
    /// A custom cron/systemd calendar expression, e.g. `"Mon *-*-* 04:00:00"`.
    Custom(String),
}

impl std::fmt::Display for Schedule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Daily => write!(f, "daily"),
            Self::Weekly => write!(f, "weekly"),
            Self::Monthly => write!(f, "monthly"),
            Self::Custom(expr) => write!(f, "custom({expr})"),
        }
    }
}

// ---------------------------------------------------------------------------
// RebootPolicy
// ---------------------------------------------------------------------------

/// When to reboot after applying updates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RebootPolicy {
    /// Never reboot automatically.
    Never,
    /// Reboot only when required by an updated package.
    WhenNeeded,
    /// Always reboot after applying updates.
    Always,
}

impl std::fmt::Display for RebootPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Never => write!(f, "never"),
            Self::WhenNeeded => write!(f, "when-needed"),
            Self::Always => write!(f, "always"),
        }
    }
}

// ---------------------------------------------------------------------------
// UpdateSpec
// ---------------------------------------------------------------------------

/// Declarative specification for automatic security updates.
///
/// `UpdateSpec` describes the *desired state* of the automatic update
/// subsystem. It is rendered into backend-specific config files by the
/// [`render`](crate::render) module and validated by the
/// [`validate`](crate::validate) module.
///
/// # Example
///
/// ```
/// use toride_updates::spec::{UpdateSpec, Schedule, RebootPolicy};
///
/// let spec = UpdateSpec {
///     auto_update: true,
///     security_only: true,
///     schedule: Schedule::Daily,
///     reboot: RebootPolicy::WhenNeeded,
///     origins: vec!["origin=Debian,codename=${distro_codename},label=Debian-Security".into()],
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateSpec {
    /// Whether automatic updates are enabled.
    pub auto_update: bool,
    /// Only install security updates (skip feature/bugfix updates).
    pub security_only: bool,
    /// How often to check for and apply updates.
    pub schedule: Schedule,
    /// Reboot policy after updates are applied.
    pub reboot: RebootPolicy,
    /// APT origin patterns to match for update selection.
    ///
    /// On Debian/Ubuntu, each entry is an `Unattended-Upgrade::Allowed-Origins`
    /// pattern. Ignored on DNF-backed systems.
    pub origins: Vec<String>,
}

impl Default for UpdateSpec {
    fn default() -> Self {
        Self {
            auto_update: true,
            security_only: true,
            schedule: Schedule::Daily,
            reboot: RebootPolicy::WhenNeeded,
            origins: vec!["origin=Debian,codename=${distro_codename},label=Debian-Security".into()],
        }
    }
}

impl UpdateSpec {
    /// Create a spec with security-only daily updates and conditional reboot.
    #[must_use]
    pub fn secure_default() -> Self {
        Self::default()
    }

    /// Create a spec that disables automatic updates entirely.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            auto_update: false,
            ..Self::default()
        }
    }
}
