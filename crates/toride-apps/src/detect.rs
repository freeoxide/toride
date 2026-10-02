//! Multi-source detection: every hit for one name across `$PATH`, mise
//! shims, and the attached backends' own listing probes — merged by
//! canonical path, never silently picked among.

use std::path::PathBuf;

use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};
use toride_registry::{Arch, DistroFamily};

use crate::backend::{Backend, ListQuery};
#[cfg(feature = "mise")]
use crate::backends::MiseBackend;
use crate::backends::{
    CargoBackend, DistroBackend, FlatpakBackend, HomebrewBackend, NpmBackend, PipxBackend,
    UvBackend,
};
use crate::error::{Error, Result};
use crate::plan::Target;
use crate::runner::{CommandRunner, command};

/// How one detection was found.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionSource {
    /// A `$PATH` directory resolved the name at the carried rank.
    Path,
    /// A mise shim file exists under mise's shim directory.
    MiseShim,
    /// The homebrew backend's installed listing carries the token.
    Homebrew,
    /// The flatpak backend's installed listing carries the app id.
    Flatpak,
    /// The distro backend's installed listing carries the package.
    Distro(DistroFamily),
    /// The npm backend's global listing carries the package.
    Npm,
    /// The cargo backend's `cargo install --list` carries the crate.
    Cargo,
    /// The pipx backend's listing carries the package.
    Pipx,
    /// The uv backend's tool listing carries the package.
    Uv,
    /// The mise backend's installed listing carries the tool.
    Mise,
}

impl std::fmt::Display for DetectionSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Path => f.write_str("path"),
            Self::MiseShim => f.write_str("mise_shim"),
            Self::Homebrew => f.write_str("homebrew"),
            Self::Flatpak => f.write_str("flatpak"),
            Self::Distro(family) => {
                let slug = format!("distro-{family:?}").to_ascii_lowercase();
                f.write_str(&slug)
            }
            Self::Npm => f.write_str("npm"),
            Self::Cargo => f.write_str("cargo"),
            Self::Pipx => f.write_str("pipx"),
            Self::Uv => f.write_str("uv"),
            Self::Mise => f.write_str("mise"),
        }
    }
}

/// Confidence of one detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionConfidence {
    /// A managed source reporting a version, or two sources merged at one path.
    High,
    /// A single solid signal: a `$PATH` or shim hit, a version-less row.
    Medium,
    /// Degraded evidence, today a mise shim whose tool is no longer installed.
    Low,
}

fn confidence_rank(confidence: DetectionConfidence) -> u8 {
    match confidence {
        DetectionConfidence::High => 2,
        DetectionConfidence::Medium => 1,
        DetectionConfidence::Low => 0,
    }
}

/// One hit for a detected name; every hit is returned, never picked among.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detection {
    /// The detected name (echoes the query the sources matched against).
    pub name: String,
    /// The version a probe reported, when one did.
    pub version: Option<String>,
    /// The filesystem path, when the hit is filesystem-grounded.
    pub path: Option<String>,
    /// How the hit was found.
    pub source: DetectionSource,
    /// Confidence in the hit.
    pub confidence: DetectionConfidence,
    /// Zero-based `$PATH` rank when the path sits on `$PATH`; `None` otherwise.
    pub path_rank: Option<usize>,
    /// An earlier `$PATH` rank resolved to a **different** artifact for the
    /// name, so this copy cannot run; the same file sighted again through a
    /// duplicate or symlinked `$PATH` entry never shadows.
    pub shadowed: bool,
    /// The artifact exists but its source reports it unusable (broken shim).
    pub broken: bool,
    /// The artifact's architecture differs from the host target's.
    pub arch_mismatch: bool,
}

impl Detection {
    /// A hit for `name` found via `source` at `confidence`, all flags clear.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        source: DetectionSource,
        confidence: DetectionConfidence,
    ) -> Self {
        Self {
            name: name.into(),
            version: None,
            path: None,
            source,
            confidence,
            path_rank: None,
            shadowed: false,
            broken: false,
            arch_mismatch: false,
        }
    }

    /// Ground the hit at a filesystem path — consume-and-return.
    #[must_use]
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Record the reported version — consume-and-return.
    #[must_use]
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Record the `$PATH` rank the path occupies — consume-and-return.
    #[must_use]
    pub const fn with_path_rank(mut self, rank: usize) -> Self {
        self.path_rank = Some(rank);
        self
    }
}

/// The injectable detection seam: implementors answer with **every** hit
/// they know for `target`, never a silently picked subset.
pub trait Detector: Send + Sync {
    /// Every detection for `target`; a source that fails or knows the name
    /// not contributes no hits rather than an error.
    fn detect(&self, target: &str) -> Vec<Detection>;
}

#[derive(PartialEq, Eq)]
enum MergeKey {
    Path(PathBuf),
    Source(DetectionSource, String),
}

fn canonical(path: &str) -> PathBuf {
    let literal = PathBuf::from(path);
    std::fs::canonicalize(&literal).unwrap_or(literal)
}

fn merge_key(detection: &Detection) -> MergeKey {
    match &detection.path {
        Some(path) => MergeKey::Path(canonical(path)),
        None => MergeKey::Source(detection.source.clone(), detection.name.clone()),
    }
}

fn join_rank(existing: Option<usize>, incoming: Option<usize>) -> Option<usize> {
    match (existing, incoming) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn absorb(existing: &mut Detection, incoming: Detection) {
    if existing.source == DetectionSource::Path && incoming.source != DetectionSource::Path {
        existing.source = incoming.source;
    }
    if existing.version.is_none() {
        existing.version = incoming.version;
    }
    existing.path_rank = join_rank(existing.path_rank, incoming.path_rank);
    if confidence_rank(incoming.confidence) > confidence_rank(existing.confidence) {
        existing.confidence = incoming.confidence;
    }
    if incoming.path.is_none() {
        existing.shadowed |= incoming.shadowed;
    }
    existing.broken |= incoming.broken;
    existing.arch_mismatch |= incoming.arch_mismatch;
}

/// Merge hits that ground at one canonical path into single entries;
/// path-less hits dedup by `(source, name)`; distinct paths never collapse.
#[must_use]
pub fn merge_by_canonical_path(detections: Vec<Detection>) -> Vec<Detection> {
    let mut merged: Vec<Detection> = Vec::new();
    for detection in detections {
        let key = merge_key(&detection);
        match merged
            .iter_mut()
            .find(|existing| merge_key(existing) == key)
        {
            Some(existing) => absorb(existing, detection),
            None => merged.push(detection),
        }
    }
    merged
}

/// The built-in [`Detector`]: `$PATH` ranks, mise shims, and one probe per
/// attached backend's own listing, merged by canonical path.
pub struct MultiSourceDetector {
    target: Target,
    runner: CommandRunner,
    path_dirs: Option<Vec<Utf8PathBuf>>,
    mise_shim_dir: Option<Utf8PathBuf>,
    homebrew: Option<HomebrewBackend>,
    flatpak: Option<FlatpakBackend>,
    distro: Option<DistroBackend>,
    npm: Option<NpmBackend>,
    cargo: Option<CargoBackend>,
    pipx: Option<PipxBackend>,
    uv: Option<UvBackend>,
    #[cfg(feature = "mise")]
    mise: Option<MiseBackend>,
}

impl MultiSourceDetector {
    /// Start building a detector — see [`MultiSourceDetectorBuilder`].
    #[must_use]
    pub fn builder() -> MultiSourceDetectorBuilder {
        MultiSourceDetectorBuilder::new()
    }

    fn resolve_path_dirs(&self) -> Vec<Utf8PathBuf> {
        if let Some(dirs) = &self.path_dirs {
            return dirs.clone();
        }
        std::env::var_os("PATH")
            .map(|path| split_path_value(&path))
            .unwrap_or_default()
    }

    fn resolve_mise_shim_dir(&self) -> Option<Utf8PathBuf> {
        if let Some(dir) = &self.mise_shim_dir {
            return Some(dir.clone());
        }
        // mise's Windows data dir is %LOCALAPPDATA%\mise, unlike the unix
        // ${XDG_DATA_HOME:-~/.local/share}/mise (mise.jdx.dev/directories.html).
        #[cfg(unix)]
        let (xdg_data_home, default_base) = (
            std::env::var_os("XDG_DATA_HOME"),
            dirs::home_dir().map(|home| home.join(".local/share")),
        );
        #[cfg(not(unix))]
        let (xdg_data_home, default_base) =
            (None, std::env::var_os("LOCALAPPDATA").map(PathBuf::from));
        mise_shim_dir_from(
            std::env::var_os("MISE_SHIMS_DIR"),
            std::env::var_os("MISE_DATA_DIR"),
            xdg_data_home,
            default_base,
        )
    }

    fn path_hits(&self, name: &str) -> Vec<Detection> {
        let mut seen: Vec<PathBuf> = Vec::new();
        let mut hits: Vec<Detection> = Vec::new();
        for (rank, dir) in self.resolve_path_dirs().iter().enumerate() {
            let candidate = dir.join(name);
            if !is_executable_file(&candidate) {
                continue;
            }
            let artifact = canonical(candidate.as_str());
            if seen.contains(&artifact) {
                continue;
            }
            seen.push(artifact);
            let mut hit = Detection::new(name, DetectionSource::Path, DetectionConfidence::Medium)
                .with_path(candidate.to_string())
                .with_path_rank(rank);
            hit.shadowed = !hits.is_empty();
            hit.arch_mismatch = self.probe_arch_mismatch(candidate.as_str());
            hits.push(hit);
        }
        hits
    }

    fn probe_arch_mismatch(&self, path: &str) -> bool {
        let spec = command("file", ["-b", path]);
        let Ok(output) = self.runner.run_sync(spec) else {
            return false;
        };
        if !output.success {
            return false;
        }
        let arches = arches_from_file_output(&output.stdout);
        !arches.is_empty() && !arches.contains(&self.target.arch)
    }

    fn mise_shim_hits(&self, name: &str) -> Vec<Detection> {
        let Some(dir) = self.resolve_mise_shim_dir() else {
            return Vec::new();
        };
        let candidate = dir.join(name);
        if !is_executable_file(&candidate) {
            return Vec::new();
        }
        let mut hit = Detection::new(name, DetectionSource::MiseShim, DetectionConfidence::Medium)
            .with_path(candidate.to_string());
        self.refine_mise_shim(&mut hit);
        vec![hit]
    }

    #[cfg(feature = "mise")]
    fn refine_mise_shim(&self, hit: &mut Detection) {
        let Some(mise) = &self.mise else {
            return;
        };
        if let Ok(rows) = mise.list_installed_sync(ListQuery::id(&hit.name)) {
            if let Some(row) = rows.first() {
                hit.version.clone_from(&row.version);
                hit.confidence = DetectionConfidence::High;
            } else {
                hit.broken = true;
                hit.confidence = DetectionConfidence::Low;
            }
        }
    }

    #[cfg(not(feature = "mise"))]
    #[expect(clippy::unused_self)]
    fn refine_mise_shim(&self, _hit: &mut Detection) {}
}

fn backend_hits(backend: &dyn Backend, source: &DetectionSource, name: &str) -> Vec<Detection> {
    backend
        .list_installed_sync(ListQuery::id(name))
        .unwrap_or_default()
        .into_iter()
        .map(|app| Detection {
            confidence: if app.version.is_some() {
                DetectionConfidence::High
            } else {
                DetectionConfidence::Medium
            },
            name: app.id,
            version: app.version,
            path: None,
            source: source.clone(),
            path_rank: None,
            shadowed: false,
            broken: false,
            arch_mismatch: false,
        })
        .collect()
}

impl Detector for MultiSourceDetector {
    fn detect(&self, target: &str) -> Vec<Detection> {
        let mut hits = self.path_hits(target);
        hits.extend(self.mise_shim_hits(target));
        if let Some(backend) = &self.homebrew {
            hits.extend(backend_hits(backend, &DetectionSource::Homebrew, target));
        }
        if let Some(backend) = &self.flatpak {
            hits.extend(backend_hits(backend, &DetectionSource::Flatpak, target));
        }
        if let Some(backend) = &self.distro {
            let source = DetectionSource::Distro(backend.family());
            hits.extend(backend_hits(backend, &source, target));
        }
        if let Some(backend) = &self.npm {
            hits.extend(backend_hits(backend, &DetectionSource::Npm, target));
        }
        if let Some(backend) = &self.cargo {
            hits.extend(backend_hits(backend, &DetectionSource::Cargo, target));
        }
        if let Some(backend) = &self.pipx {
            hits.extend(backend_hits(backend, &DetectionSource::Pipx, target));
        }
        if let Some(backend) = &self.uv {
            hits.extend(backend_hits(backend, &DetectionSource::Uv, target));
        }
        #[cfg(feature = "mise")]
        if let Some(backend) = &self.mise {
            hits.extend(backend_hits(backend, &DetectionSource::Mise, target));
        }
        merge_by_canonical_path(hits)
    }
}

fn is_executable_file(path: &Utf8PathBuf) -> bool {
    let Ok(metadata) = std::fs::metadata(path.as_std_path()) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn arches_from_file_output(stdout: &str) -> Vec<Arch> {
    let lower = stdout.to_ascii_lowercase();
    let x86_64 = lower.contains("x86-64") || lower.contains("x86_64") || lower.contains("amd64");
    let aarch64 = lower.contains("aarch64") || lower.contains("arm64");
    let mut arches = Vec::new();
    if x86_64 {
        arches.push(Arch::X86_64);
    }
    if aarch64 {
        arches.push(Arch::Aarch64);
    }
    if !x86_64
        && (lower.contains("80386")
            || lower.contains("i386")
            || lower.contains("i686")
            || lower.contains("x86"))
    {
        arches.push(Arch::X86);
    }
    arches
}

fn split_path_value(value: &std::ffi::OsStr) -> Vec<Utf8PathBuf> {
    std::env::split_paths(value)
        .filter(|dir| !dir.as_os_str().is_empty())
        .filter_map(|dir| Utf8PathBuf::from_path_buf(dir).ok())
        .collect()
}

fn mise_shim_dir_from(
    shims_dir: Option<std::ffi::OsString>,
    data_dir: Option<std::ffi::OsString>,
    xdg_data_home: Option<std::ffi::OsString>,
    default_base: Option<PathBuf>,
) -> Option<Utf8PathBuf> {
    if let Some(shims) = shims_dir {
        return Utf8PathBuf::from_path_buf(PathBuf::from(shims)).ok();
    }
    if let Some(data) = data_dir {
        return Utf8PathBuf::from_path_buf(PathBuf::from(data))
            .ok()
            .map(|dir| dir.join("shims"));
    }
    let base = xdg_data_home.map(PathBuf::from).or(default_base);
    base.and_then(|base| Utf8PathBuf::from_path_buf(base).ok())
        .map(|base| base.join("mise/shims"))
}

/// Builder for [`MultiSourceDetector`], mirroring [`crate::AppsBuilder`]:
/// consume-and-return setters, backends attached pre-built, the host
/// detection arm in [`MultiSourceDetectorBuilder::detect_backends`].
#[derive(Default)]
pub struct MultiSourceDetectorBuilder {
    target: Option<Target>,
    runner: Option<CommandRunner>,
    path_dirs: Option<Vec<Utf8PathBuf>>,
    mise_shim_dir: Option<Utf8PathBuf>,
    homebrew: Option<HomebrewBackend>,
    flatpak: Option<FlatpakBackend>,
    distro: Option<DistroBackend>,
    npm: Option<NpmBackend>,
    cargo: Option<CargoBackend>,
    pipx: Option<PipxBackend>,
    uv: Option<UvBackend>,
    #[cfg(feature = "mise")]
    mise: Option<MiseBackend>,
}

fn attach<B>(slot: &mut Option<B>, detected: Result<B>) -> Result<()> {
    match detected {
        Ok(backend) => {
            *slot = Some(backend);
            Ok(())
        }
        Err(Error::Command(toride_runner::Error::BinaryNotFound(_))) => Ok(()),
        Err(error) => Err(error),
    }
}

impl MultiSourceDetectorBuilder {
    /// Create a builder with all defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the host target architecture comparisons run against —
    /// consume-and-return.
    #[must_use]
    pub fn target(mut self, target: Target) -> Self {
        self.target = Some(target);
        self
    }

    /// Set the seam the `file` arch probe executes through —
    /// consume-and-return.
    #[must_use]
    pub fn runner(mut self, runner: CommandRunner) -> Self {
        self.runner = Some(runner);
        self
    }

    /// Override the `$PATH` directories probed in rank order (tests and
    /// deterministic callers) — consume-and-return.
    #[must_use]
    pub fn path_dirs(mut self, dirs: Vec<Utf8PathBuf>) -> Self {
        self.path_dirs = Some(dirs);
        self
    }

    /// Override mise's shim directory (tests and deterministic callers) —
    /// consume-and-return.
    #[must_use]
    pub fn mise_shim_dir(mut self, dir: impl Into<Utf8PathBuf>) -> Self {
        self.mise_shim_dir = Some(dir.into());
        self
    }

    /// Attach the homebrew backend — consume-and-return.
    #[must_use]
    pub fn homebrew(mut self, backend: HomebrewBackend) -> Self {
        self.homebrew = Some(backend);
        self
    }

    /// Attach the flatpak backend — consume-and-return.
    #[must_use]
    pub fn flatpak(mut self, backend: FlatpakBackend) -> Self {
        self.flatpak = Some(backend);
        self
    }

    /// Attach the distro backend — consume-and-return.
    #[must_use]
    pub fn distro(mut self, backend: DistroBackend) -> Self {
        self.distro = Some(backend);
        self
    }

    /// Attach the npm backend — consume-and-return.
    #[must_use]
    pub fn npm(mut self, backend: NpmBackend) -> Self {
        self.npm = Some(backend);
        self
    }

    /// Attach the cargo backend — consume-and-return.
    #[must_use]
    pub fn cargo(mut self, backend: CargoBackend) -> Self {
        self.cargo = Some(backend);
        self
    }

    /// Attach the pipx backend — consume-and-return.
    #[must_use]
    pub fn pipx(mut self, backend: PipxBackend) -> Self {
        self.pipx = Some(backend);
        self
    }

    /// Attach the uv backend — consume-and-return.
    #[must_use]
    pub fn uv(mut self, backend: UvBackend) -> Self {
        self.uv = Some(backend);
        self
    }

    /// Attach the mise backend (the `mise` feature) — consume-and-return.
    #[cfg(feature = "mise")]
    #[must_use]
    pub fn mise(mut self, backend: MiseBackend) -> Self {
        self.mise = Some(backend);
        self
    }

    /// Attach every backend whose binary resolves on this host `$PATH`
    /// (distro via os-release(5) family detection). No command executes;
    /// an absent binary or unknown family is a skip, never an error.
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when a detection fails for a reason other than
    /// the skip modes above.
    pub fn detect_backends(self) -> Result<Self> {
        let runner = self
            .runner
            .clone()
            .unwrap_or_else(|| CommandRunner::builder().build());
        let mut builder = self;
        attach(
            &mut builder.homebrew,
            HomebrewBackend::detect(runner.clone()),
        )?;
        attach(&mut builder.flatpak, FlatpakBackend::detect(runner.clone()))?;
        match DistroBackend::detect(runner.clone()) {
            Ok(backend) => builder.distro = Some(backend),
            Err(Error::Command(
                toride_runner::Error::BinaryNotFound(_) | toride_runner::Error::Other(_),
            )) => {}
            Err(error) => return Err(error),
        }
        attach(&mut builder.npm, NpmBackend::detect(runner.clone()))?;
        attach(&mut builder.cargo, CargoBackend::detect(runner.clone()))?;
        attach(&mut builder.pipx, PipxBackend::detect(runner.clone()))?;
        attach(&mut builder.uv, UvBackend::detect(runner.clone()))?;
        #[cfg(feature = "mise")]
        attach(&mut builder.mise, MiseBackend::detect(runner.clone()))?;
        builder.runner = Some(runner);
        Ok(builder)
    }

    /// Consume the builder and produce the detector, defaulting the target
    /// to `Target::host()` and the seam to a fresh DuctRunner-backed one.
    #[must_use]
    pub fn build(self) -> MultiSourceDetector {
        MultiSourceDetector {
            target: self.target.unwrap_or_else(Target::host),
            runner: self
                .runner
                .unwrap_or_else(|| CommandRunner::builder().build()),
            path_dirs: self.path_dirs,
            mise_shim_dir: self.mise_shim_dir,
            homebrew: self.homebrew,
            flatpak: self.flatpak,
            distro: self.distro,
            npm: self.npm,
            cargo: self.cargo,
            pipx: self.pipx,
            uv: self.uv,
            #[cfg(feature = "mise")]
            mise: self.mise,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use toride_registry::Os;
    use toride_runner::CommandOutput;
    use toride_runner::fake::FakeRunner;

    fn temp_dir(label: &str) -> Utf8PathBuf {
        let dir =
            std::env::temp_dir().join(format!("toride-apps-detect-{label}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("unique temp dir is creatable");
        Utf8PathBuf::from_path_buf(dir).expect("system temp dir is valid UTF-8")
    }

    #[cfg(unix)]
    fn write_executable(dir: &Utf8PathBuf, name: &str) -> Utf8PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(path.as_std_path(), b"#!/bin/sh\n").expect("executable is writable");
        std::fs::set_permissions(path.as_std_path(), std::fs::Permissions::from_mode(0o755))
            .expect("permissions are settable");
        path
    }

    fn seam(fake: &FakeRunner) -> CommandRunner {
        CommandRunner::new(Arc::new(fake.clone()))
    }

    fn file_spec(path: &str) -> toride_runner::CommandSpec {
        command("file", ["-b", path])
    }

    fn aarch64_target() -> Target {
        Target::new(Os::Linux, Arch::Aarch64)
    }

    #[test]
    fn sources_display_stable_slugs() {
        assert_eq!(DetectionSource::Path.to_string(), "path");
        assert_eq!(DetectionSource::MiseShim.to_string(), "mise_shim");
        assert_eq!(DetectionSource::Npm.to_string(), "npm");
        assert_eq!(
            DetectionSource::Distro(DistroFamily::Debian).to_string(),
            "distro-debian"
        );
    }

    #[test]
    fn detection_round_trips_through_serde() {
        let detection =
            Detection::new("node", DetectionSource::MiseShim, DetectionConfidence::High)
                .with_path("/home/u/.local/share/mise/shims/node")
                .with_version("22.1.0")
                .with_path_rank(0);
        let json = serde_json::to_string(&detection).unwrap();
        assert!(json.contains("\"mise_shim\""), "{json}");
        assert!(json.contains("\"high\""), "{json}");
        assert_eq!(serde_json::from_str::<Detection>(&json).unwrap(), detection);
    }

    #[cfg(unix)]
    #[test]
    fn merge_collapses_hits_that_canonicalize_to_one_path() {
        let dir = temp_dir("merge-canonical");
        let real = write_executable(&dir, "tool");
        let link = dir.join("tool-link");
        std::os::unix::fs::symlink(real.as_std_path(), link.as_std_path())
            .expect("symlink is creatable");
        let mut path_hit =
            Detection::new("tool", DetectionSource::Path, DetectionConfidence::Medium)
                .with_path(real.to_string())
                .with_path_rank(0);
        path_hit.shadowed = true;
        let shim_hit = Detection::new("tool", DetectionSource::MiseShim, DetectionConfidence::High)
            .with_path(link.to_string())
            .with_version("1.0");
        let merged = merge_by_canonical_path(vec![path_hit, shim_hit]);
        assert_eq!(merged.len(), 1, "{merged:?}");
        assert_eq!(merged[0].source, DetectionSource::MiseShim);
        assert_eq!(merged[0].path_rank, Some(0));
        assert_eq!(merged[0].version.as_deref(), Some("1.0"));
        assert_eq!(merged[0].confidence, DetectionConfidence::High);
        assert_eq!(merged[0].path.as_deref(), Some(real.as_str()));
    }

    #[test]
    fn merge_keeps_distinct_paths_and_unions_flags() {
        let mut first = Detection::new("t", DetectionSource::Path, DetectionConfidence::Medium)
            .with_path("/a/t")
            .with_path_rank(0);
        first.shadowed = true;
        first.arch_mismatch = true;
        let mut second = Detection::new("t", DetectionSource::Path, DetectionConfidence::Medium)
            .with_path("/b/t")
            .with_path_rank(1);
        second.broken = true;
        let merged = merge_by_canonical_path(vec![first, second]);
        assert_eq!(merged.len(), 2, "{merged:?}");
        assert_eq!(merged[0].path.as_deref(), Some("/a/t"));
        assert!(merged[0].shadowed && merged[0].arch_mismatch);
        assert_eq!(merged[1].path.as_deref(), Some("/b/t"));
        assert!(merged[1].broken);
        assert!(!merged[1].shadowed);
    }

    #[test]
    fn merge_dedups_pathless_hits_by_source_and_name_only() {
        let npm_first = Detection::new("t", DetectionSource::Npm, DetectionConfidence::High);
        let npm_second = Detection::new("t", DetectionSource::Npm, DetectionConfidence::High)
            .with_version("2.0.0");
        let cargo_hit = Detection::new("t", DetectionSource::Cargo, DetectionConfidence::High);
        let merged = merge_by_canonical_path(vec![npm_first, npm_second, cargo_hit]);
        assert_eq!(merged.len(), 2, "{merged:?}");
        assert_eq!(merged[0].source, DetectionSource::Npm);
        assert_eq!(merged[0].version.as_deref(), Some("2.0.0"));
        assert_eq!(merged[1].source, DetectionSource::Cargo);
    }

    #[cfg(unix)]
    #[test]
    fn path_hits_report_every_rank_and_flag_shadowed_copies() {
        let first_dir = temp_dir("rank-a");
        let second_dir = temp_dir("rank-b");
        let first_bin = write_executable(&first_dir, "tool");
        let second_bin = write_executable(&second_dir, "tool");
        let fake = FakeRunner::new()
            .strict()
            .respond(
                file_spec(first_bin.as_str()),
                CommandOutput::from_stdout(
                    "ELF 64-bit LSB pie executable, x86-64, dynamically linked",
                ),
            )
            .respond(
                file_spec(second_bin.as_str()),
                CommandOutput::from_stdout("a /usr/bin/python3 script text executable"),
            );
        let detector = MultiSourceDetector::builder()
            .runner(seam(&fake))
            .target(aarch64_target())
            .path_dirs(vec![first_dir, second_dir])
            .build();
        let hits = detector.detect("tool");
        assert_eq!(hits.len(), 2, "{hits:?}");
        assert_eq!(hits[0].source, DetectionSource::Path);
        assert_eq!(hits[0].path_rank, Some(0));
        assert!(!hits[0].shadowed);
        assert!(hits[0].arch_mismatch, "x86-64 on an aarch64 target");
        assert_eq!(hits[1].path_rank, Some(1));
        assert!(hits[1].shadowed);
        assert!(
            !hits[1].arch_mismatch,
            "an arch-less script never mismatches"
        );
        fake.assert_called_with(&file_spec(first_bin.as_str()));
        fake.assert_called_with(&file_spec(second_bin.as_str()));
    }

    #[cfg(unix)]
    #[test]
    fn path_hits_skip_directories_and_non_executable_files() {
        let dir = temp_dir("skip");
        std::fs::create_dir_all(dir.join("tool")).expect("subdirectory is creatable");
        std::fs::write(dir.join("data"), b"not executable").expect("file is writable");
        let fake = FakeRunner::new().strict();
        let detector = MultiSourceDetector::builder()
            .runner(seam(&fake))
            .path_dirs(vec![dir])
            .build();
        assert!(
            detector.detect("tool").is_empty(),
            "a directory is not a hit"
        );
        assert!(
            detector.detect("data").is_empty(),
            "a non-executable file is not a hit"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_unavailable_or_unparseable_file_probe_claims_no_mismatch() {
        let dir = temp_dir("file-probe");
        let bin = write_executable(&dir, "tool");
        let fake = FakeRunner::new().strict().respond(
            file_spec(bin.as_str()),
            CommandOutput::from_stdout("some future file format"),
        );
        let detector = MultiSourceDetector::builder()
            .runner(seam(&fake))
            .target(aarch64_target())
            .path_dirs(vec![dir.clone()])
            .build();
        assert!(!detector.detect("tool")[0].arch_mismatch);

        let failing = FakeRunner::new().strict();
        let detector = MultiSourceDetector::builder()
            .runner(seam(&failing))
            .path_dirs(vec![dir])
            .build();
        assert!(!detector.detect("tool")[0].arch_mismatch);
    }

    #[test]
    fn arches_from_file_output_collects_every_arch_a_fat_binary_carries() {
        assert_eq!(
            arches_from_file_output(
                "Mach-O 64-bit universal binary with 2 architectures: \
                 (x86_64: Mach-O 64-bit executable x86_64) \
                 (arm64: Mach-O 64-bit executable arm64)"
            ),
            vec![Arch::X86_64, Arch::Aarch64]
        );
        assert_eq!(
            arches_from_file_output("ELF 64-bit LSB pie executable, x86-64, dynamically linked"),
            vec![Arch::X86_64]
        );
        assert_eq!(
            arches_from_file_output("Mach-O 64-bit arm64 executable, arm64"),
            vec![Arch::Aarch64]
        );
        assert_eq!(
            arches_from_file_output("ELF 32-bit LSB executable, Intel 80386"),
            vec![Arch::X86]
        );
        assert!(
            arches_from_file_output("a /usr/bin/python3 script text executable").is_empty(),
            "an arch-less script reports no architecture"
        );
    }

    #[test]
    fn split_path_value_drops_empty_segments_and_keeps_order() {
        let value = std::ffi::OsStr::new("/a::/b:");
        assert_eq!(
            split_path_value(value),
            [Utf8PathBuf::from("/a"), Utf8PathBuf::from("/b")]
        );
        assert!(split_path_value(std::ffi::OsStr::new("")).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn split_path_value_skips_non_utf8_segments() {
        use std::os::unix::ffi::OsStrExt;
        let value = std::ffi::OsStr::from_bytes(b"/ok:/\xff\xfe");
        assert_eq!(split_path_value(value), [Utf8PathBuf::from("/ok")]);
    }

    #[test]
    fn mise_shim_dir_from_follows_the_mise_directory_resolution_order() {
        let shims = std::ffi::OsString::from("/custom/shims");
        let data = std::ffi::OsString::from("/data/mise");
        let xdg = std::ffi::OsString::from("/xdg/data");
        let unix_base = Some(PathBuf::from("/home/u/.local/share"));
        let windows_base = Some(PathBuf::from("/localappdata"));
        assert_eq!(
            mise_shim_dir_from(
                Some(shims.clone()),
                Some(data.clone()),
                Some(xdg.clone()),
                unix_base.clone()
            ),
            Some(Utf8PathBuf::from("/custom/shims")),
            "MISE_SHIMS_DIR wins outright"
        );
        assert_eq!(
            mise_shim_dir_from(None, Some(data), Some(xdg.clone()), unix_base.clone()),
            Some(Utf8PathBuf::from("/data/mise/shims")),
            "MISE_DATA_DIR is the mise dir itself, so shims sit directly under it"
        );
        assert_eq!(
            mise_shim_dir_from(None, None, Some(xdg), unix_base.clone()),
            Some(Utf8PathBuf::from("/xdg/data/mise/shims")),
            "XDG_DATA_HOME replaces the default base only"
        );
        assert_eq!(
            mise_shim_dir_from(None, None, None, unix_base),
            Some(Utf8PathBuf::from("/home/u/.local/share/mise/shims"))
        );
        assert_eq!(
            mise_shim_dir_from(None, None, None, windows_base),
            Some(Utf8PathBuf::from("/localappdata/mise/shims")),
            "the Windows default base is %LOCALAPPDATA%, joined the same way"
        );
        assert_eq!(mise_shim_dir_from(None, None, None, None), None);
    }

    #[test]
    fn attach_skips_absent_binaries_and_propagates_other_errors() {
        let mut slot: Option<u8> = None;
        attach(&mut slot, Ok(3)).expect("a successful detection attaches");
        assert_eq!(slot, Some(3));
        attach(
            &mut slot,
            Err(Error::Command(toride_runner::Error::BinaryNotFound(
                "x".into(),
            ))),
        )
        .expect("an absent binary is a skip, never an error");
        assert_eq!(slot, Some(3), "the skip leaves the slot untouched");
        let error = attach(
            &mut slot,
            Err(Error::Command(toride_runner::Error::Other("boom".into()))),
        )
        .unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::Other(_))),
            "{error:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn one_artifact_sighted_through_two_path_entries_is_a_single_unshadowed_hit() {
        let real_dir = temp_dir("shadow-real");
        let real = write_executable(&real_dir, "tool");
        let link_dir = temp_dir("shadow-link");
        let link = link_dir.join("tool");
        std::os::unix::fs::symlink(real.as_std_path(), link.as_std_path())
            .expect("symlink is creatable");
        let fake = FakeRunner::new().strict().respond(
            file_spec(real.as_str()),
            CommandOutput::from_stdout("a /bin/sh script text executable"),
        );
        let detector = MultiSourceDetector::builder()
            .runner(seam(&fake))
            .path_dirs(vec![real_dir, link_dir])
            .build();
        let hits = detector.detect("tool");
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].path_rank, Some(0));
        assert!(
            !hits[0].shadowed,
            "the artifact that runs is not shadowed by its own symlinked re-sighting"
        );
        assert_eq!(hits[0].path.as_deref(), Some(real.as_str()));
        fake.assert_called_with(&file_spec(real.as_str()));
    }

    #[test]
    fn merge_never_marks_one_artifact_as_shadowing_itself() {
        let winner = Detection::new("t", DetectionSource::Path, DetectionConfidence::Medium)
            .with_path("/x/t")
            .with_path_rank(0);
        let mut re_sighting =
            Detection::new("t", DetectionSource::Path, DetectionConfidence::Medium)
                .with_path("/x/t")
                .with_path_rank(1);
        re_sighting.shadowed = true;
        let merged = merge_by_canonical_path(vec![winner, re_sighting]);
        assert_eq!(merged.len(), 1, "{merged:?}");
        assert!(!merged[0].shadowed);
        assert_eq!(merged[0].path_rank, Some(0));
    }

    #[cfg(unix)]
    #[test]
    fn a_universal_binary_matching_the_host_arch_claims_no_mismatch() {
        let dir = temp_dir("file-universal");
        let bin = write_executable(&dir, "tool");
        let universal = "Mach-O 64-bit universal binary with 2 architectures: \
                         (x86_64: Mach-O 64-bit executable x86_64) \
                         (arm64: Mach-O 64-bit executable arm64)";
        let fake = FakeRunner::new().strict().respond(
            file_spec(bin.as_str()),
            CommandOutput::from_stdout(universal),
        );
        let detector = MultiSourceDetector::builder()
            .runner(seam(&fake))
            .target(aarch64_target())
            .path_dirs(vec![dir])
            .build();
        let hits = detector.detect("tool");
        assert!(!hits[0].arch_mismatch, "{hits:?}");
    }

    #[test]
    fn npm_backend_probes_contribute_managed_hits_and_misses_contribute_none() {
        let list_spec = command("npm", ["list", "--global", "--depth=0", "--json"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(
                list_spec.clone(),
                CommandOutput::from_stdout(
                    r#"{"dependencies": {"typescript": {"version": "5.4.5"}}}"#,
                ),
            )
            .respond(list_spec.clone(), CommandOutput::from_stdout("{}"));
        let detector = MultiSourceDetector::builder()
            .runner(seam(&fake))
            .path_dirs(Vec::new())
            .npm(NpmBackend::new(seam(&fake)))
            .build();
        let hits = detector.detect("typescript");
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].source, DetectionSource::Npm);
        assert_eq!(hits[0].version.as_deref(), Some("5.4.5"));
        assert_eq!(hits[0].confidence, DetectionConfidence::High);
        assert_eq!(hits[0].path, None);
        assert!(
            detector.detect("left-pad").is_empty(),
            "a listing without the row answers no hits"
        );
        fake.assert_called_with(&list_spec);
    }

    #[test]
    fn a_failing_backend_probe_contributes_no_hits_and_never_fails_the_scan() {
        let list_spec = command("npm", ["list", "--global", "--depth=0", "--json"]);
        let fake = FakeRunner::new().strict().respond_err(
            list_spec.clone(),
            toride_runner::Error::BinaryNotFound("npm".into()),
        );
        let detector = MultiSourceDetector::builder()
            .runner(seam(&fake))
            .path_dirs(Vec::new())
            .npm(NpmBackend::new(seam(&fake)))
            .build();
        assert!(detector.detect("typescript").is_empty());
    }

    #[test]
    fn brew_flatpak_and_distro_probes_map_their_native_sources() {
        let brew_spec = command("brew", ["info", "--json=v2", "--installed"]);
        let flatpak_spec = command(
            "flatpak",
            [
                "list",
                "--app",
                "--columns=application,version,origin,installation",
            ],
        );
        let dpkg_spec = command(
            "dpkg-query",
            [
                "--show",
                "--showformat=${db:Status-Abbrev}${Package}\\t${Version}\\n",
                "firefox-esr",
            ],
        )
        .env("LC_ALL", "C");
        let brew_document = r#"{"formulae": [{"name": "ripgrep", "installed": [{"version": "15.2.0"}]}], "casks": []}"#;
        let flatpak_row = "org.mozilla.firefox\t141.0.3\tflathub\tsystem\n";
        let dpkg_row = "ii firefox-esr\t128.0esr-1\n";
        let mut fake = FakeRunner::new().strict();
        for _ in 0..3 {
            fake = fake
                .respond(brew_spec.clone(), CommandOutput::from_stdout(brew_document))
                .respond(
                    flatpak_spec.clone(),
                    CommandOutput::from_stdout(flatpak_row),
                )
                .respond(dpkg_spec.clone(), CommandOutput::from_stdout(dpkg_row));
        }
        let runner = seam(&fake);
        let detector = MultiSourceDetector::builder()
            .runner(runner.clone())
            .path_dirs(Vec::new())
            .homebrew(HomebrewBackend::new(runner.clone()))
            .flatpak(FlatpakBackend::new(runner.clone()))
            .distro(DistroBackend::new(DistroFamily::Debian, runner.clone()))
            .build();
        let brew_hit = detector.detect("ripgrep");
        assert_eq!(brew_hit.len(), 1, "{brew_hit:?}");
        assert_eq!(brew_hit[0].source, DetectionSource::Homebrew);
        let flatpak_hit = detector.detect("org.mozilla.firefox");
        assert_eq!(flatpak_hit.len(), 1, "{flatpak_hit:?}");
        assert_eq!(flatpak_hit[0].source, DetectionSource::Flatpak);
        let distro_hit = detector.detect("firefox-esr");
        assert_eq!(distro_hit.len(), 1, "{distro_hit:?}");
        assert_eq!(
            distro_hit[0].source,
            DetectionSource::Distro(DistroFamily::Debian)
        );
        assert_eq!(distro_hit[0].version.as_deref(), Some("128.0esr-1"));
        fake.assert_called_with(&brew_spec);
        fake.assert_called_with(&flatpak_spec);
        fake.assert_called_with(&dpkg_spec);
    }

    #[cfg(unix)]
    #[test]
    fn mise_shim_hits_without_a_mise_backend_and_without_any_command() {
        let shim_dir = temp_dir("shim-plain");
        let shim = write_executable(&shim_dir, "node");
        let fake = FakeRunner::new().strict();
        let detector = MultiSourceDetector::builder()
            .runner(seam(&fake))
            .path_dirs(Vec::new())
            .mise_shim_dir(shim_dir)
            .build();
        let hits = detector.detect("node");
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].source, DetectionSource::MiseShim);
        assert_eq!(hits[0].path.as_deref(), Some(shim.as_str()));
        assert_eq!(hits[0].confidence, DetectionConfidence::Medium);
        assert!(!hits[0].broken);
        assert_eq!(hits[0].version, None);
        assert!(
            fake.calls().is_empty(),
            "the filesystem shim probe runs no command"
        );
    }

    #[cfg(unix)]
    #[test]
    fn path_and_shim_hits_at_one_path_merge_into_one_detection() {
        let shim_dir = temp_dir("shim-merge");
        let shim = write_executable(&shim_dir, "node");
        let fake = FakeRunner::new().strict().respond(
            file_spec(shim.as_str()),
            CommandOutput::from_stdout("ELF 64-bit LSB executable, aarch64"),
        );
        let detector = MultiSourceDetector::builder()
            .runner(seam(&fake))
            .target(aarch64_target())
            .path_dirs(vec![shim_dir.clone()])
            .mise_shim_dir(shim_dir)
            .build();
        let hits = detector.detect("node");
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].source, DetectionSource::MiseShim);
        assert_eq!(hits[0].path_rank, Some(0));
        assert!(!hits[0].arch_mismatch);
        fake.assert_called_with(&file_spec(shim.as_str()));
    }

    #[cfg(all(unix, feature = "mise"))]
    #[test]
    fn mise_shim_reads_version_and_broken_state_from_the_mise_listing() {
        use toride_mise::MiseBinary;
        let shim_dir = temp_dir("shim-mise");
        write_executable(&shim_dir, "node");
        let list_spec = command("mise", ["ls", "--installed", "--json"]);
        let installed_document = r#"{"node": [{"version": "22.1.0", "active": true}]}"#;
        let mut fake = FakeRunner::new().strict();
        for response in [installed_document, installed_document, "{}", "{}"] {
            fake = fake.respond(list_spec.clone(), CommandOutput::from_stdout(response));
        }
        let mise = toride_mise::Mise::builder()
            .runner(Arc::new(fake.clone()) as Arc<dyn toride_runner::AsyncRunner>)
            .binary(MiseBinary::from_path("mise"))
            .build()
            .unwrap();
        let detector = MultiSourceDetector::builder()
            .runner(seam(&fake))
            .path_dirs(Vec::new())
            .mise_shim_dir(shim_dir.clone())
            .mise(crate::backends::MiseBackend::new(mise, seam(&fake)))
            .build();
        let hits = detector.detect("node");
        assert_eq!(hits.len(), 2, "{hits:?}");
        let managed = hits
            .iter()
            .find(|hit| hit.source == DetectionSource::Mise)
            .expect("the managed listing row is kept alongside the shim");
        assert_eq!(managed.version.as_deref(), Some("22.1.0"));
        let shim = hits
            .iter()
            .find(|hit| hit.source == DetectionSource::MiseShim)
            .expect("the shim hit survives");
        assert_eq!(shim.version.as_deref(), Some("22.1.0"));
        assert_eq!(shim.confidence, DetectionConfidence::High);
        assert!(!shim.broken);

        let emptied = MultiSourceDetector::builder()
            .runner(seam(&fake))
            .path_dirs(Vec::new())
            .mise_shim_dir(shim_dir)
            .mise(crate::backends::MiseBackend::new(
                toride_mise::Mise::builder()
                    .runner(Arc::new(fake.clone()) as Arc<dyn toride_runner::AsyncRunner>)
                    .binary(MiseBinary::from_path("mise"))
                    .build()
                    .unwrap(),
                seam(&fake),
            ))
            .build();
        let hits = emptied.detect("node");
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(
            hits[0].broken,
            "a shim whose tool the listing no longer carries is broken"
        );
        assert_eq!(hits[0].confidence, DetectionConfidence::Low);
    }

    #[test]
    fn a_bare_builder_answers_no_hits_and_the_trait_is_object_safe() {
        let detector: Box<dyn Detector> = Box::new(
            MultiSourceDetector::builder()
                .path_dirs(Vec::new())
                .mise_shim_dir(temp_dir("nothing"))
                .build(),
        );
        assert!(detector.detect("nothing-here").is_empty());
    }

    #[test]
    fn detect_backends_skips_absent_binaries_and_never_errors() {
        let fake = FakeRunner::new();
        let detector = MultiSourceDetector::builder()
            .runner(seam(&fake))
            .detect_backends()
            .expect("an absent binary or unknown family is a skip, never an error")
            .build();
        assert!(
            detector
                .detect("definitely-not-an-installed-tool-xyzq")
                .is_empty()
        );
    }
}
