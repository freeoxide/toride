//! Host target detection.
//!
//! A [`Target`] captures the operating system and CPU architecture of the
//! machine an artifact will run on. It is detected from
//! [`std::env::consts`] and mapped — per tool — to the release-asset naming
//! that tool uses (e.g. `linux-x64`, `macos-arm64`).

use crate::error::{Error, Result};

/// The operating system half of a [`Target`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Os {
    /// Linux (any libc).
    Linux,
    /// macOS.
    Macos,
}

impl Os {
    /// Detect the host operating system.
    ///
    /// Returns `None` on platforms the framework does not bootstrap
    /// (anything other than `Linux`/`macOS`).
    #[must_use]
    pub fn host() -> Option<Self> {
        if cfg!(target_os = "linux") {
            Some(Self::Linux)
        } else if cfg!(target_os = "macos") {
            Some(Self::Macos)
        } else {
            None
        }
    }

    /// The conventional lowercase release-asset name for this OS.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Macos => "macos",
        }
    }
}

impl std::fmt::Display for Os {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The architecture half of a [`Target`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Arch {
    /// 64-bit ARM (`aarch64`).
    Arm64,
    /// 64-bit x86 (`x86_64`).
    X64,
}

impl Arch {
    /// Detect the host CPU architecture.
    ///
    /// Returns `None` on architectures the framework does not bootstrap
    /// (anything other than `x86_64`/`aarch64`).
    #[must_use]
    pub fn host() -> Option<Self> {
        if cfg!(target_arch = "aarch64") {
            Some(Self::Arm64)
        } else if cfg!(target_arch = "x86_64") {
            Some(Self::X64)
        } else {
            None
        }
    }

    /// The conventional lowercase release-asset name for this architecture.
    ///
    /// Tools following the GitHub-asset convention use `arm64`/`x64`
    /// (NOT `aarch64`/`x86_64`); this matches that convention.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Arm64 => "arm64",
            Self::X64 => "x64",
        }
    }
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A resolved (OS, arch) pair describing where an artifact will run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Target {
    /// Operating system.
    pub os: Os,
    /// CPU architecture.
    pub arch: Arch,
}

impl Target {
    /// Detect the host target from `std::env::consts`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedTarget`] if the host OS or architecture is
    /// not one of the bootstrappable combinations.
    pub fn host() -> Result<Self> {
        let os = Os::host().ok_or_else(|| Error::UnsupportedTarget {
            tool: String::new(),
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
        })?;
        let arch = Arch::host().ok_or_else(|| Error::UnsupportedTarget {
            tool: String::new(),
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
        })?;
        Ok(Self { os, arch })
    }

    /// The `<os>-<arch>` asset keyword (e.g. `linux-x64`, `macos-arm64`).
    #[must_use]
    pub fn keyword(self) -> String {
        format!("{}-{}", self.os, self.arch)
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.os, self.arch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyword_format() {
        let t = Target {
            os: Os::Linux,
            arch: Arch::X64,
        };
        assert_eq!(t.keyword(), "linux-x64");
        assert_eq!(t.to_string(), "linux-x64");
    }

    #[test]
    fn keyword_macos_arm64() {
        let t = Target {
            os: Os::Macos,
            arch: Arch::Arm64,
        };
        assert_eq!(t.keyword(), "macos-arm64");
    }

    #[test]
    fn host_detects_current_platform() {
        // The test host is linux or macos on x64/arm64; this must always
        // resolve since CI/dev runs on supported platforms.
        let t = Target::host().expect("host target should be supported");
        assert!(matches!(t.os, Os::Linux | Os::Macos));
        assert!(matches!(t.arch, Arch::Arm64 | Arch::X64));
    }

    #[test]
    fn arch_str_uses_github_convention() {
        assert_eq!(Arch::Arm64.as_str(), "arm64");
        assert_eq!(Arch::X64.as_str(), "x64");
        // Not aarch64/x86_64.
        assert_ne!(Arch::Arm64.as_str(), "aarch64");
    }

    #[test]
    fn os_str_values() {
        assert_eq!(Os::Linux.as_str(), "linux");
        assert_eq!(Os::Macos.as_str(), "macos");
    }
}
