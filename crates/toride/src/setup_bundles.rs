//! Curated setup bundles: license-labeled tool recommendations whose
//! load-bearing axis is commercial use. Data model + compiled-in registry;
//! evaluation, planning, and hint application build on these types.

use toride_apps::{DistroFamily, InstallMethod, Os};
use toride_installer::Tool;
use toride_installer::status::{Detector as InstallerDetector, ToolStatus as InstallerToolStatus};

/// Commercial-use axis of a tool's license — the load-bearing label.
/// Anything but [`LicenseKind::Free`] sets [`LicenseKind::requires_consent`]
/// and blocks install until the linked terms are accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum LicenseKind {
    /// Unrestricted commercial use. GPL tools land here too: distribution
    /// obligations, not use restrictions — the summary says so.
    Free,
    /// Free for personal or non-commercial use only.
    FreePersonal,
    /// Requires payment for any commercial use.
    PaidForCommercial,
    /// Free for commercial use under stated conditions: head-count or
    /// revenue caps, competing-offering bans.
    FreeWithTerms,
}

impl LicenseKind {
    /// The single gate the install path consults.
    #[must_use]
    pub const fn requires_consent(self) -> bool {
        !matches!(self, Self::Free)
    }
}

/// The full label a consent dialog renders: kind, terms URL, and the date
/// the classification was verified.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LicenseInfo {
    /// Which commercial-use class this row falls in.
    pub kind: LicenseKind,
    /// SPDX expression where the project publishes one, `None` for
    /// proprietary rows. Curated per row, never joined at runtime.
    pub spdx: Option<&'static str>,
    /// One-line condition, e.g. Docker Desktop's employee and revenue caps.
    pub summary: &'static str,
    /// Terms or pricing page the consent dialog links.
    pub terms_url: &'static str,
    /// `YYYY-MM-DD` the classification was last verified against
    /// [`LicenseInfo::terms_url`].
    pub verified: &'static str,
}

/// When a recommendation applies; evaluated at plan time against the host
/// and tool presence. The registry holds data, not closures, so evaluation
/// is snapshot-testable.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum Condition {
    /// Host OS gate.
    Os(Os),
    /// Linux host of this distro family; `Target::distro` stays `None`
    /// until a backend fills it from os-release.
    Distro(DistroFamily),
    /// Holds when the named tool was not found by the presence check.
    Missing {
        /// Canonical tool name the presence check answers for.
        tool: &'static str,
    },
    /// Every sub-condition holds; an empty `All` always holds.
    All(Vec<Condition>),
}

/// Answers whether any of a row's candidate binaries is already installed,
/// so evaluation never touches `$PATH` in unit tests.
pub trait ToolPresence: Send + Sync {
    /// True when any alias in `binaries` resolves to an install.
    fn is_present(&self, binaries: &[&str]) -> bool;
}

/// Production [`ToolPresence`] over the toride-installer `Detector`:
/// `$PATH`-plus-managed-dir probe per alias, first hit wins.
pub struct DetectorPresence(InstallerDetector);

impl DetectorPresence {
    /// Wrap a configured detector: `InstallerDetector::new()`, or
    /// `with_runner` in tests.
    #[must_use]
    pub fn new(detector: InstallerDetector) -> Self {
        Self(detector)
    }
}

impl ToolPresence for DetectorPresence {
    fn is_present(&self, binaries: &[&str]) -> bool {
        binaries.iter().any(|bin| {
            let tool = Tool {
                name: (*bin).to_owned(),
                bin_name: (*bin).to_owned(),
                ..Tool::default()
            };
            !matches!(self.0.detect(&tool), InstallerToolStatus::NotInstalled)
        })
    }
}

/// A curated tool bundle: one ecosystem, one default pick, ordered
/// recommendations.
#[derive(Clone, Debug, serde::Serialize)]
pub struct SetupBundle {
    /// Stable slug (`rust`, `containers`, `iac`).
    pub id: &'static str,
    /// Sidebar heading.
    pub title: &'static str,
    /// Id of the preselected recommendation; always the FOSS row.
    pub default_pick: &'static str,
    /// Rows in display order.
    pub recommendations: Vec<Recommendation>,
}

/// One installable suggestion inside a [`SetupBundle`], with its license
/// label and apply steps.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Recommendation {
    /// Registry-unique slug, `<bundle>-<tool>[-<route>]`.
    pub id: &'static str,
    /// Tool name as shown in the list.
    pub title: &'static str,
    /// One sentence under the title.
    pub rationale: &'static str,
    /// The consent-gating label; see [`LicenseInfo`].
    pub license: LicenseInfo,
    /// Host gate evaluated at plan time.
    pub condition: Condition,
    /// Presence-check aliases, tried in order like `ToolSpec.binaries`.
    pub binaries: &'static [&'static str],
    /// Ordered steps: installs first, trailing config hints.
    pub actions: Vec<InstallAction>,
    /// Id of the FOSS row this one defers to; the UI shows the defer link
    /// on non-Free rows.
    pub alternative: Option<&'static str>,
}

/// One step of a recommendation: a package install, a config hint, or a
/// deliberate manual step.
#[derive(Clone, Debug, serde::Serialize)]
#[non_exhaustive]
pub enum InstallAction {
    /// Package install planned through toride-apps.
    Install(InstallSpec),
    /// Config-only step, written only after the exact bytes are shown and
    /// accepted.
    Hint(ConfigHint),
    /// Route no backend expresses in v1, e.g. `rustup component add
    /// rust-analyzer`.
    Manual {
        /// The exact command or steps for the user.
        instructions: &'static str,
    },
}

/// Package install descriptor: manifest name plus the toride-apps install
/// method.
#[derive(Clone, Debug, serde::Serialize)]
pub struct InstallSpec {
    /// Canonical id for the manifest and plan.
    pub name: &'static str,
    /// Backend-native install method routed by the planner.
    pub method: InstallMethod,
}

/// Config-only step targeting one file; the exact bytes are shown before
/// anything is written.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConfigHint {
    /// Stable slug (`sccache-cargo-wrapper`).
    pub id: &'static str,
    /// Dialog heading.
    pub title: &'static str,
    /// Exact bytes that would be written.
    pub content: &'static str,
    /// Destination file; may start with `~` for tilde expansion.
    pub path: &'static str,
    /// What happens when the file already exists.
    pub on_exists: OnExists,
}

/// What [`ConfigHint`] does when the destination file already exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum OnExists {
    /// An existing file is never modified; the snippet is shown for
    /// hand-merging.
    Skip,
}

const SCCACHE_WRAPPER: ConfigHint = ConfigHint {
    id: "sccache-cargo-wrapper",
    title: "Point cargo's rustc-wrapper at sccache",
    content: "[build]\nrustc-wrapper = \"sccache\"\n",
    path: "~/.cargo/config.toml",
    on_exists: OnExists::Skip,
};

const DIRENV_HOOK_ZSH: ConfigHint = ConfigHint {
    id: "direnv-hook",
    title: "Hook direnv into zsh",
    content: "eval \"$(direnv hook zsh)\"",
    path: "~/.zshrc",
    on_exists: OnExists::Skip,
};

const DIRENV_HOOK_BASH: ConfigHint = ConfigHint {
    id: "direnv-hook",
    title: "Hook direnv into bash",
    content: "eval \"$(direnv hook bash)\"",
    path: "~/.bashrc",
    on_exists: OnExists::Skip,
};

#[expect(
    clippy::too_many_arguments,
    reason = "a registry row is one record; splitting the call hides fields"
)]
fn rec(
    id: &'static str,
    title: &'static str,
    rationale: &'static str,
    license: LicenseInfo,
    condition: Condition,
    binaries: &'static [&'static str],
    actions: Vec<InstallAction>,
    alternative: Option<&'static str>,
) -> Recommendation {
    Recommendation {
        id,
        title,
        rationale,
        license,
        condition,
        binaries,
        actions,
        alternative,
    }
}

fn license(
    kind: LicenseKind,
    spdx: Option<&'static str>,
    summary: &'static str,
    terms_url: &'static str,
    verified: &'static str,
) -> LicenseInfo {
    LicenseInfo {
        kind,
        spdx,
        summary,
        terms_url,
        verified,
    }
}

fn brew(token: &'static str) -> InstallMethod {
    InstallMethod::Homebrew {
        cask: false,
        token: token.to_owned(),
    }
}

fn cask(token: &'static str) -> InstallMethod {
    InstallMethod::Homebrew {
        cask: true,
        token: token.to_owned(),
    }
}

fn cargo(crate_: &'static str) -> InstallMethod {
    InstallMethod::Cargo {
        crate_: crate_.to_owned(),
        version: None,
    }
}

fn npm(package: &'static str) -> InstallMethod {
    InstallMethod::Npm {
        package: package.to_owned(),
        version: None,
    }
}

fn pipx(package: &'static str) -> InstallMethod {
    InstallMethod::Pipx {
        package: package.to_owned(),
    }
}

fn mise_tool(tool: &'static str) -> InstallMethod {
    InstallMethod::Mise {
        tool: tool.to_owned(),
        version: None,
    }
}

fn distro(family: DistroFamily, package: &'static str) -> InstallMethod {
    InstallMethod::Distro {
        family,
        repo: None,
        package: package.to_owned(),
    }
}

fn install(name: &'static str, method: InstallMethod) -> InstallAction {
    InstallAction::Install(InstallSpec { name, method })
}

fn manual(instructions: &'static str) -> InstallAction {
    InstallAction::Manual { instructions }
}

/// The compiled-in registry, in bundle display order. Runtime-built because
/// [`InstallMethod`] carries `String` fields.
#[must_use]
pub fn bundles() -> Vec<SetupBundle> {
    vec![
        rust_bundle(),
        node_bundle(),
        python_bundle(),
        ruby_php_go_bundle(),
        containers_bundle(),
        iac_bundle(),
        qol_bundle(),
        version_managers_bundle(),
    ]
}

#[expect(
    clippy::too_many_lines,
    reason = "data manifest: one block per registry row"
)]
fn rust_bundle() -> SetupBundle {
    SetupBundle {
        id: "rust",
        title: "Rust build tools",
        default_pick: "rust-sccache",
        recommendations: vec![
            rec(
                "rust-sccache",
                "sccache",
                "Caches Rust compilations across projects.",
                license(
                    LicenseKind::Free,
                    Some("Apache-2.0"),
                    "Apache-2.0; commercial use unrestricted.",
                    "https://github.com/mozilla/sccache",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["sccache"],
                vec![
                    install("sccache", brew("sccache")),
                    InstallAction::Hint(SCCACHE_WRAPPER),
                ],
                None,
            ),
            rec(
                "rust-sccache-linux",
                "sccache",
                "The same compile cache for Linux hosts, via mise's cargo backend.",
                license(
                    LicenseKind::Free,
                    Some("Apache-2.0"),
                    "Apache-2.0; commercial use unrestricted.",
                    "https://github.com/mozilla/sccache",
                    "2026-10-12",
                ),
                Condition::Os(Os::Linux),
                &["sccache"],
                vec![
                    install("sccache", mise_tool("cargo:sccache")),
                    InstallAction::Hint(SCCACHE_WRAPPER),
                ],
                None,
            ),
            rec(
                "rust-mold",
                "mold",
                "Links ELF binaries; the macOS alternatives are lld and Xcode's default linker.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT since 2.0; ELF and Linux only, never the macOS pick.",
                    "https://github.com/rui314/mold",
                    "2026-10-12",
                ),
                Condition::Os(Os::Linux),
                &["mold"],
                vec![install("mold", cargo("mold"))],
                None,
            ),
            rec(
                "rust-lld",
                "lld",
                "LLVM's linker; Xcode 15+'s default linker is the other macOS option.",
                license(
                    LicenseKind::Free,
                    Some("Apache-2.0 WITH LLVM-exception"),
                    "Apache-2.0 WITH LLVM-exception; commercial use unrestricted.",
                    "https://raw.githubusercontent.com/llvm/llvm-project/main/LICENSE.TXT",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["lld", "ld.lld", "ld64.lld"],
                vec![install("lld", brew("lld"))],
                None,
            ),
            rec(
                "rust-cargo-nextest",
                "cargo-nextest",
                "Runs each Rust test in its own process, with retries and structured output.",
                license(
                    LicenseKind::Free,
                    Some("MIT OR Apache-2.0"),
                    "MIT OR Apache-2.0; commercial use unrestricted.",
                    "https://github.com/nextest-rs/nextest",
                    "2026-10-12",
                ),
                Condition::All(Vec::new()),
                &["cargo-nextest"],
                vec![install("cargo-nextest", cargo("cargo-nextest"))],
                None,
            ),
            rec(
                "rust-cargo-binstall",
                "cargo-binstall",
                "Installs prebuilt Rust binaries from releases instead of compiling from source.",
                license(
                    LicenseKind::Free,
                    Some("GPL-3.0-only"),
                    "GPL-3.0-only; free for commercial use, distribution carries source obligations.",
                    "https://crates.io/api/v1/crates/cargo-binstall",
                    "2026-10-12",
                ),
                Condition::All(Vec::new()),
                &["cargo-binstall"],
                vec![install("cargo-binstall", cargo("cargo-binstall"))],
                None,
            ),
            rec(
                "rust-rust-analyzer",
                "rust-analyzer",
                "Language server for Rust, added through rustup so it tracks your toolchain.",
                license(
                    LicenseKind::Free,
                    Some("MIT OR Apache-2.0"),
                    "MIT OR Apache-2.0; commercial use unrestricted.",
                    "https://github.com/rust-lang/rust-analyzer",
                    "2026-10-12",
                ),
                Condition::All(Vec::new()),
                &["rust-analyzer"],
                vec![manual("rustup component add rust-analyzer")],
                None,
            ),
        ],
    }
}

fn node_bundle() -> SetupBundle {
    SetupBundle {
        id: "node",
        title: "Node tooling",
        default_pick: "node-pnpm",
        recommendations: vec![
            rec(
                "node-fnm",
                "fnm",
                "Node version manager written in Rust, one binary.",
                license(
                    LicenseKind::Free,
                    Some("GPL-3.0"),
                    "GPL-3.0; free for commercial use, distribution carries source obligations.",
                    "https://github.com/Schniz/fnm",
                    "2026-10-12",
                ),
                Condition::All(Vec::new()),
                &["fnm"],
                vec![install("fnm", cargo("fnm"))],
                None,
            ),
            rec(
                "node-pnpm",
                "pnpm",
                "Stores each package version once on disk and links projects to it.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT for the CLI; the repo's pnpr/ directory is PolyForm Shield 1.0.0.",
                    "https://github.com/pnpm/pnpm",
                    "2026-10-12",
                ),
                Condition::All(Vec::new()),
                &["pnpm"],
                vec![install("pnpm", npm("pnpm"))],
                None,
            ),
            rec(
                "node-tsx",
                "tsx",
                "Runs TypeScript files directly with Node, no build step.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://github.com/privatenumber/tsx",
                    "2026-10-12",
                ),
                Condition::All(Vec::new()),
                &["tsx"],
                vec![install("tsx", npm("tsx"))],
                None,
            ),
        ],
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "data manifest: one block per registry row"
)]
fn python_bundle() -> SetupBundle {
    SetupBundle {
        id: "python",
        title: "Python tooling",
        default_pick: "python-uv",
        recommendations: vec![
            rec(
                "python-uv",
                "uv",
                "One tool for Python packages, projects, and tool installs.",
                license(
                    LicenseKind::Free,
                    Some("MIT OR Apache-2.0"),
                    "MIT OR Apache-2.0; commercial use unrestricted.",
                    "https://github.com/astral-sh/uv",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["uv"],
                vec![install("uv", brew("uv"))],
                None,
            ),
            rec(
                "python-uv-linux",
                "uv",
                "The same package manager for Linux hosts, installed through pipx.",
                license(
                    LicenseKind::Free,
                    Some("MIT OR Apache-2.0"),
                    "MIT OR Apache-2.0; commercial use unrestricted.",
                    "https://github.com/astral-sh/uv",
                    "2026-10-12",
                ),
                Condition::Os(Os::Linux),
                &["uv"],
                vec![install("uv", pipx("uv"))],
                None,
            ),
            rec(
                "python-ruff",
                "ruff",
                "Lints and formats Python from one binary.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://github.com/astral-sh/ruff",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["ruff"],
                vec![install("ruff", brew("ruff"))],
                None,
            ),
            rec(
                "python-ruff-linux",
                "ruff",
                "The same linter and formatter for Linux hosts, installed through pipx.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://github.com/astral-sh/ruff",
                    "2026-10-12",
                ),
                Condition::Os(Os::Linux),
                &["ruff"],
                vec![install("ruff", pipx("ruff"))],
                None,
            ),
            rec(
                "python-pipx",
                "pipx",
                "Installs Python CLI apps into their own environments.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://github.com/pypa/pipx",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["pipx"],
                vec![install("pipx", brew("pipx"))],
                None,
            ),
            rec(
                "python-pipx-linux",
                "pipx",
                "The same app installer for Linux hosts, via mise.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://github.com/pypa/pipx",
                    "2026-10-12",
                ),
                Condition::Os(Os::Linux),
                &["pipx"],
                vec![install("pipx", mise_tool("pipx"))],
                None,
            ),
        ],
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "data manifest: one block per registry row"
)]
fn ruby_php_go_bundle() -> SetupBundle {
    SetupBundle {
        id: "ruby-php-go",
        title: "Ruby, PHP, and Go tooling",
        default_pick: "ruby-php-go-bundler",
        recommendations: vec![
            rec(
                "ruby-php-go-bundler",
                "bundler",
                "Installs the gem versions a Gemfile.lock pins, in isolation.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://raw.githubusercontent.com/rubygems/bundler/master/LICENSE.md",
                    "2026-10-12",
                ),
                Condition::All(Vec::new()),
                &["bundler"],
                vec![manual("gem install bundler")],
                None,
            ),
            rec(
                "ruby-php-go-composer-debian",
                "composer",
                "PHP dependency manager, from the distro repository.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://getcomposer.org/",
                    "2026-10-12",
                ),
                Condition::Distro(DistroFamily::Debian),
                &["composer"],
                vec![install(
                    "composer",
                    distro(DistroFamily::Debian, "composer"),
                )],
                None,
            ),
            rec(
                "ruby-php-go-composer-ubuntu",
                "composer",
                "PHP dependency manager, from the distro repository.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://getcomposer.org/",
                    "2026-10-12",
                ),
                Condition::Distro(DistroFamily::Ubuntu),
                &["composer"],
                vec![install(
                    "composer",
                    distro(DistroFamily::Ubuntu, "composer"),
                )],
                None,
            ),
            rec(
                "ruby-php-go-composer-fedora",
                "composer",
                "PHP dependency manager, from the distro repository.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://getcomposer.org/",
                    "2026-10-12",
                ),
                Condition::Distro(DistroFamily::Fedora),
                &["composer"],
                vec![install(
                    "composer",
                    distro(DistroFamily::Fedora, "composer"),
                )],
                None,
            ),
            rec(
                "ruby-php-go-composer-arch",
                "composer",
                "PHP dependency manager, from the distro repository.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://getcomposer.org/",
                    "2026-10-12",
                ),
                Condition::Distro(DistroFamily::Arch),
                &["composer"],
                vec![install("composer", distro(DistroFamily::Arch, "composer"))],
                None,
            ),
            rec(
                "ruby-php-go-golangci-lint",
                "golangci-lint",
                "Runs a configurable set of Go linters in one pass.",
                license(
                    LicenseKind::Free,
                    Some("GPL-3.0"),
                    "GPL-3.0; free for commercial use, distribution carries source obligations.",
                    "https://github.com/golangci/golangci-lint",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["golangci-lint"],
                vec![install("golangci-lint", brew("golangci-lint"))],
                None,
            ),
            rec(
                "ruby-php-go-golangci-lint-linux",
                "golangci-lint",
                "The same linter bundle for Linux hosts, via mise.",
                license(
                    LicenseKind::Free,
                    Some("GPL-3.0"),
                    "GPL-3.0; free for commercial use, distribution carries source obligations.",
                    "https://github.com/golangci/golangci-lint",
                    "2026-10-12",
                ),
                Condition::Os(Os::Linux),
                &["golangci-lint"],
                vec![install("golangci-lint", mise_tool("golangci-lint"))],
                None,
            ),
            rec(
                "ruby-php-go-gofumpt",
                "gofumpt",
                "Applies stricter formatting than gofmt.",
                license(
                    LicenseKind::Free,
                    Some("BSD-3-Clause"),
                    "BSD-3-Clause; commercial use unrestricted.",
                    "https://github.com/mvdan/gofumpt",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["gofumpt"],
                vec![install("gofumpt", brew("gofumpt"))],
                None,
            ),
            rec(
                "ruby-php-go-gofumpt-linux",
                "gofumpt",
                "The same formatter for Linux hosts, via mise.",
                license(
                    LicenseKind::Free,
                    Some("BSD-3-Clause"),
                    "BSD-3-Clause; commercial use unrestricted.",
                    "https://github.com/mvdan/gofumpt",
                    "2026-10-12",
                ),
                Condition::Os(Os::Linux),
                &["gofumpt"],
                vec![install("gofumpt", mise_tool("gofumpt"))],
                None,
            ),
        ],
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "data manifest: one block per registry row"
)]
fn containers_bundle() -> SetupBundle {
    SetupBundle {
        id: "containers",
        title: "Containers",
        default_pick: "containers-colima",
        recommendations: vec![
            rec(
                "containers-colima",
                "colima",
                "Container runtime on a Lima VM; drives the docker CLI without Docker Desktop.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://github.com/abiosoft/colima",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["colima"],
                vec![install("colima", brew("colima"))],
                None,
            ),
            rec(
                "containers-lima",
                "Lima",
                "Manages Linux VMs on macOS; colima builds on it.",
                license(
                    LicenseKind::Free,
                    Some("Apache-2.0"),
                    "Apache-2.0; commercial use unrestricted.",
                    "https://github.com/lima-vm/lima",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["lima", "limactl"],
                vec![install("lima", brew("lima"))],
                None,
            ),
            rec(
                "containers-podman",
                "Podman",
                "Daemonless container engine compatible with the docker CLI.",
                license(
                    LicenseKind::Free,
                    Some("Apache-2.0"),
                    "Apache-2.0; commercial use unrestricted.",
                    "https://github.com/containers/podman",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["podman"],
                vec![install("podman", brew("podman"))],
                None,
            ),
            rec(
                "containers-podman-desktop",
                "Podman Desktop",
                "GUI for Podman containers and pods.",
                license(
                    LicenseKind::Free,
                    Some("Apache-2.0"),
                    "Apache-2.0; commercial use unrestricted.",
                    "https://github.com/containers/podman-desktop",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["podman"],
                vec![install("podman-desktop", cask("podman-desktop"))],
                None,
            ),
            rec(
                "containers-orbstack",
                "OrbStack",
                "Docker engine and Linux VMs for macOS in one app.",
                license(
                    LicenseKind::PaidForCommercial,
                    None,
                    "Proprietary freemium: personal and non-commercial use free; \
                     commercial use requires Pro at $8/user/mo ($96/yr).",
                    "https://orbstack.dev/pricing",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["orb", "orbctl"],
                vec![install("orbstack", cask("orbstack"))],
                Some("containers-colima"),
            ),
            rec(
                "containers-docker-desktop",
                "Docker Desktop",
                "Docker's official desktop app for macOS.",
                license(
                    LicenseKind::FreeWithTerms,
                    None,
                    "Proprietary under the Docker Subscription Service Agreement: free only \
                     under 250 employees AND under $10M annual revenue.",
                    "https://docs.docker.com/subscription/desktop-license/",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["docker"],
                vec![install("docker-desktop", cask("docker-desktop"))],
                Some("containers-colima"),
            ),
        ],
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "data manifest: one block per registry row"
)]
fn iac_bundle() -> SetupBundle {
    SetupBundle {
        id: "iac",
        title: "Infrastructure as code",
        default_pick: "iac-opentofu",
        recommendations: vec![
            rec(
                "iac-opentofu",
                "OpenTofu",
                "The Linux Foundation's MPL-2.0 Terraform fork; its CLI is `tofu`.",
                license(
                    LicenseKind::Free,
                    Some("MPL-2.0"),
                    "MPL-2.0, Linux Foundation; commercial use unrestricted.",
                    "https://github.com/opentofu/opentofu",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["tofu"],
                vec![install("opentofu", brew("opentofu"))],
                None,
            ),
            rec(
                "iac-opentofu-linux",
                "OpenTofu",
                "The same Terraform fork for Linux hosts, via mise.",
                license(
                    LicenseKind::Free,
                    Some("MPL-2.0"),
                    "MPL-2.0, Linux Foundation; commercial use unrestricted.",
                    "https://github.com/opentofu/opentofu",
                    "2026-10-12",
                ),
                Condition::Os(Os::Linux),
                &["tofu"],
                vec![install("opentofu", mise_tool("opentofu"))],
                None,
            ),
            rec(
                "iac-terraform",
                "Terraform",
                "HashiCorp's infrastructure-as-code CLI.",
                license(
                    LicenseKind::FreeWithTerms,
                    Some("BUSL-1.1"),
                    "BUSL 1.1 since 1.6.0, licensor IBM: production use allowed, competing \
                     hosted or embedded offerings are not.",
                    "https://raw.githubusercontent.com/hashicorp/terraform/main/LICENSE",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["terraform"],
                vec![install("terraform", brew("hashicorp/tap/terraform"))],
                Some("iac-opentofu"),
            ),
            rec(
                "iac-terraform-linux",
                "Terraform",
                "HashiCorp's infrastructure-as-code CLI for Linux hosts, via mise.",
                license(
                    LicenseKind::FreeWithTerms,
                    Some("BUSL-1.1"),
                    "BUSL 1.1 since 1.6.0, licensor IBM: production use allowed, competing \
                     hosted or embedded offerings are not.",
                    "https://raw.githubusercontent.com/hashicorp/terraform/main/LICENSE",
                    "2026-10-12",
                ),
                Condition::Os(Os::Linux),
                &["terraform"],
                vec![install("terraform", mise_tool("terraform"))],
                Some("iac-opentofu"),
            ),
            rec(
                "iac-tflint",
                "tflint",
                "Lints Terraform against provider schemas before you plan.",
                license(
                    LicenseKind::Free,
                    Some("MPL-2.0"),
                    "MPL-2.0 for most files; some terraform-pkg files are BUSL 1.1, so \
                     binaries are bound by both. Commercial use fine.",
                    "https://github.com/terraform-linters/tflint",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["tflint"],
                vec![install("tflint", cask("terraform-linters/tap/tflint"))],
                None,
            ),
            rec(
                "iac-tflint-linux",
                "tflint",
                "The same Terraform linter for Linux hosts, via mise.",
                license(
                    LicenseKind::Free,
                    Some("MPL-2.0"),
                    "MPL-2.0 for most files; some terraform-pkg files are BUSL 1.1, so \
                     binaries are bound by both. Commercial use fine.",
                    "https://github.com/terraform-linters/tflint",
                    "2026-10-12",
                ),
                Condition::Os(Os::Linux),
                &["tflint"],
                vec![install("tflint", mise_tool("tflint"))],
                None,
            ),
            rec(
                "iac-trivy",
                "trivy",
                "Scans IaC and containers for misconfigurations and CVEs; the maintained \
                 successor to tfsec.",
                license(
                    LicenseKind::Free,
                    Some("Apache-2.0"),
                    "Apache-2.0; commercial use unrestricted.",
                    "https://api.github.com/repos/aquasecurity/trivy",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["trivy"],
                vec![install("trivy", brew("trivy"))],
                None,
            ),
            rec(
                "iac-trivy-linux",
                "trivy",
                "The same scanner for Linux hosts, via mise.",
                license(
                    LicenseKind::Free,
                    Some("Apache-2.0"),
                    "Apache-2.0; commercial use unrestricted.",
                    "https://api.github.com/repos/aquasecurity/trivy",
                    "2026-10-12",
                ),
                Condition::Os(Os::Linux),
                &["trivy"],
                vec![install("trivy", mise_tool("trivy"))],
                None,
            ),
            rec(
                "iac-terragrunt",
                "terragrunt",
                "Runs Terraform across many modules without copy-pasted config.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://github.com/gruntwork-io/terragrunt",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["terragrunt"],
                vec![install("terragrunt", brew("terragrunt"))],
                None,
            ),
            rec(
                "iac-terragrunt-linux",
                "terragrunt",
                "The same Terraform wrapper for Linux hosts, via mise.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://github.com/gruntwork-io/terragrunt",
                    "2026-10-12",
                ),
                Condition::Os(Os::Linux),
                &["terragrunt"],
                vec![install("terragrunt", mise_tool("terragrunt"))],
                None,
            ),
        ],
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "data manifest: one block per registry row"
)]
fn qol_bundle() -> SetupBundle {
    SetupBundle {
        id: "qol-cli",
        title: "Shell tools",
        default_pick: "qol-ripgrep",
        recommendations: vec![
            rec(
                "qol-direnv",
                "direnv",
                "Loads .envrc variables per directory, on cd.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://formulae.brew.sh/api/formula/direnv.json",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["direnv"],
                vec![
                    install("direnv", brew("direnv")),
                    InstallAction::Hint(DIRENV_HOOK_ZSH),
                ],
                None,
            ),
            rec(
                "qol-direnv-linux",
                "direnv",
                "The same per-directory environment loader for Linux hosts, via mise.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://formulae.brew.sh/api/formula/direnv.json",
                    "2026-10-12",
                ),
                Condition::Os(Os::Linux),
                &["direnv"],
                vec![
                    install("direnv", mise_tool("direnv")),
                    InstallAction::Hint(DIRENV_HOOK_BASH),
                ],
                None,
            ),
            rec(
                "qol-starship",
                "starship",
                "Cross-shell prompt configured from one TOML file.",
                license(
                    LicenseKind::Free,
                    Some("ISC"),
                    "ISC; commercial use unrestricted.",
                    "https://formulae.brew.sh/api/formula/starship.json",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["starship"],
                vec![install("starship", brew("starship"))],
                None,
            ),
            rec(
                "qol-starship-linux",
                "starship",
                "The same prompt for Linux hosts, via mise.",
                license(
                    LicenseKind::Free,
                    Some("ISC"),
                    "ISC; commercial use unrestricted.",
                    "https://formulae.brew.sh/api/formula/starship.json",
                    "2026-10-12",
                ),
                Condition::Os(Os::Linux),
                &["starship"],
                vec![install("starship", mise_tool("starship"))],
                None,
            ),
            rec(
                "qol-zoxide",
                "zoxide",
                "Remembers visited directories and jumps by fragment: z proj.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://formulae.brew.sh/api/formula/zoxide.json",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["zoxide"],
                vec![install("zoxide", brew("zoxide"))],
                None,
            ),
            rec(
                "qol-zoxide-linux",
                "zoxide",
                "The same directory jumper for Linux hosts, via mise.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://formulae.brew.sh/api/formula/zoxide.json",
                    "2026-10-12",
                ),
                Condition::Os(Os::Linux),
                &["zoxide"],
                vec![install("zoxide", mise_tool("zoxide"))],
                None,
            ),
            rec(
                "qol-fzf",
                "fzf",
                "Fuzzy-filters files, shell history, and any stdin list.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://formulae.brew.sh/api/formula/fzf.json",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["fzf"],
                vec![install("fzf", brew("fzf"))],
                None,
            ),
            rec(
                "qol-fzf-linux",
                "fzf",
                "The same fuzzy finder for Linux hosts, via mise.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://formulae.brew.sh/api/formula/fzf.json",
                    "2026-10-12",
                ),
                Condition::Os(Os::Linux),
                &["fzf"],
                vec![install("fzf", mise_tool("fzf"))],
                None,
            ),
            rec(
                "qol-ripgrep",
                "ripgrep",
                "Regex search that respects .gitignore.",
                license(
                    LicenseKind::Free,
                    Some("MIT OR Unlicense"),
                    "MIT OR Unlicense; Homebrew's API lists Unlicense.",
                    "https://formulae.brew.sh/api/formula/ripgrep.json",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["rg", "ripgrep"],
                vec![install("ripgrep", brew("ripgrep"))],
                None,
            ),
            rec(
                "qol-ripgrep-linux",
                "ripgrep",
                "The same search tool for Linux hosts, via mise.",
                license(
                    LicenseKind::Free,
                    Some("MIT OR Unlicense"),
                    "MIT OR Unlicense; Homebrew's API lists Unlicense.",
                    "https://formulae.brew.sh/api/formula/ripgrep.json",
                    "2026-10-12",
                ),
                Condition::Os(Os::Linux),
                &["rg", "ripgrep"],
                vec![install("ripgrep", mise_tool("ripgrep"))],
                None,
            ),
            rec(
                "qol-fd",
                "fd",
                "find with gitignore awareness and simpler syntax.",
                license(
                    LicenseKind::Free,
                    Some("MIT OR Apache-2.0"),
                    "MIT OR Apache-2.0; commercial use unrestricted.",
                    "https://formulae.brew.sh/api/formula/fd.json",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["fd"],
                vec![install("fd", brew("fd"))],
                None,
            ),
            rec(
                "qol-fd-linux",
                "fd",
                "The same find alternative for Linux hosts, via mise.",
                license(
                    LicenseKind::Free,
                    Some("MIT OR Apache-2.0"),
                    "MIT OR Apache-2.0; commercial use unrestricted.",
                    "https://formulae.brew.sh/api/formula/fd.json",
                    "2026-10-12",
                ),
                Condition::Os(Os::Linux),
                &["fd"],
                vec![install("fd", mise_tool("fd"))],
                None,
            ),
            rec(
                "qol-lazygit",
                "lazygit",
                "Terminal UI for staging, branching, and rebasing.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://formulae.brew.sh/api/formula/lazygit.json",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["lazygit"],
                vec![install("lazygit", brew("lazygit"))],
                None,
            ),
            rec(
                "qol-lazygit-linux",
                "lazygit",
                "The same git UI for Linux hosts, via mise.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://formulae.brew.sh/api/formula/lazygit.json",
                    "2026-10-12",
                ),
                Condition::Os(Os::Linux),
                &["lazygit"],
                vec![install("lazygit", mise_tool("lazygit"))],
                None,
            ),
            rec(
                "qol-git-delta",
                "git-delta",
                "Git pager with syntax highlighting and side-by-side diffs.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://formulae.brew.sh/api/formula/git-delta.json",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["delta"],
                vec![install("git-delta", brew("git-delta"))],
                None,
            ),
            rec(
                "qol-git-delta-linux",
                "git-delta",
                "The same pager for Linux hosts, built from its crate.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://formulae.brew.sh/api/formula/git-delta.json",
                    "2026-10-12",
                ),
                Condition::Os(Os::Linux),
                &["delta"],
                vec![install("git-delta", cargo("git-delta"))],
                None,
            ),
            rec(
                "qol-jq",
                "jq",
                "Transforms JSON on the command line.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://formulae.brew.sh/api/formula/jq.json",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["jq"],
                vec![install("jq", brew("jq"))],
                None,
            ),
            rec(
                "qol-jq-linux",
                "jq",
                "The same JSON processor for Linux hosts, via mise.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://formulae.brew.sh/api/formula/jq.json",
                    "2026-10-12",
                ),
                Condition::Os(Os::Linux),
                &["jq"],
                vec![install("jq", mise_tool("jq"))],
                None,
            ),
            rec(
                "qol-yq",
                "yq",
                "jq-style filtering for YAML, TOML, and XML.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://formulae.brew.sh/api/formula/yq.json",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["yq"],
                vec![install("yq", brew("yq"))],
                None,
            ),
            rec(
                "qol-yq-linux",
                "yq",
                "The same YAML processor for Linux hosts, via mise.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://formulae.brew.sh/api/formula/yq.json",
                    "2026-10-12",
                ),
                Condition::Os(Os::Linux),
                &["yq"],
                vec![install("yq", mise_tool("yq"))],
                None,
            ),
        ],
    }
}

fn version_managers_bundle() -> SetupBundle {
    SetupBundle {
        id: "version-managers",
        title: "Version managers",
        default_pick: "vm-mise",
        recommendations: vec![
            rec(
                "vm-mise",
                "mise",
                "Pins tool versions per project in mise.toml and activates them on cd.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://github.com/jdx/mise",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["mise"],
                vec![install("mise", brew("mise"))],
                None,
            ),
            rec(
                "vm-mise-linux",
                "mise",
                "The same version manager for Linux hosts, from the official installer.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://github.com/jdx/mise",
                    "2026-10-12",
                ),
                Condition::Os(Os::Linux),
                &["mise"],
                vec![manual("curl https://mise.run | sh")],
                None,
            ),
            rec(
                "vm-asdf",
                "asdf",
                "Per-project tool versions via shell plugin hooks.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://github.com/asdf-vm/asdf",
                    "2026-10-12",
                ),
                Condition::Os(Os::MacOs),
                &["asdf"],
                vec![install("asdf", brew("asdf"))],
                None,
            ),
            rec(
                "vm-asdf-linux",
                "asdf",
                "The same version manager for Linux hosts, cloned to ~/.asdf.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://github.com/asdf-vm/asdf",
                    "2026-10-12",
                ),
                Condition::Os(Os::Linux),
                &["asdf"],
                vec![manual(
                    "git clone https://github.com/asdf-vm/asdf.git ~/.asdf and put \
                     ~/.asdf/bin on your PATH",
                )],
                None,
            ),
        ],
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use super::*;
    use toride_runner::FakeRunner;

    fn index(bundles: &[SetupBundle]) -> BTreeMap<&'static str, &Recommendation> {
        bundles
            .iter()
            .flat_map(|bundle| bundle.recommendations.iter())
            .map(|rec| (rec.id, rec))
            .collect()
    }

    #[test]
    fn registry_has_the_eight_planned_bundles() {
        let bundles = bundles();
        let ids: Vec<_> = bundles.iter().map(|b| b.id).collect();
        assert_eq!(bundles.len(), 8);
        assert_eq!(
            ids,
            [
                "rust",
                "node",
                "python",
                "ruby-php-go",
                "containers",
                "iac",
                "qol-cli",
                "version-managers"
            ]
        );
    }

    #[test]
    fn recommendation_ids_are_registry_unique() {
        let bundles = bundles();
        let all = index(&bundles);
        let total: usize = bundles.iter().map(|b| b.recommendations.len()).sum();
        assert_eq!(all.len(), total, "duplicate recommendation id");
    }

    #[test]
    fn alternatives_and_default_picks_resolve() {
        let bundles = bundles();
        let all = index(&bundles);
        for bundle in &bundles {
            assert!(
                all.contains_key(bundle.default_pick),
                "{}: default_pick {} unresolved",
                bundle.id,
                bundle.default_pick
            );
            for rec in &bundle.recommendations {
                if let Some(alt) = rec.alternative {
                    assert!(
                        all.contains_key(alt),
                        "{}: alternative {alt} unresolved",
                        rec.id
                    );
                }
            }
        }
    }

    #[test]
    fn default_picks_are_always_free() {
        let bundles = bundles();
        let all = index(&bundles);
        for bundle in &bundles {
            let pick = all[bundle.default_pick];
            assert_eq!(
                pick.license.kind,
                LicenseKind::Free,
                "{} defaults to {} ({:?})",
                bundle.id,
                bundle.default_pick,
                pick.license.kind
            );
        }
    }

    #[test]
    fn every_row_is_linked_and_dated() {
        for rec in bundles()
            .iter()
            .flat_map(|bundle| bundle.recommendations.iter())
        {
            assert!(
                rec.license.terms_url.starts_with("https://"),
                "{}: terms_url {:?}",
                rec.id,
                rec.license.terms_url
            );
            assert_eq!(rec.license.verified, "2026-10-12", "{}", rec.id);
            assert!(!rec.license.summary.is_empty(), "{}", rec.id);
        }
    }

    #[test]
    fn every_row_has_presence_candidates() {
        for rec in bundles()
            .iter()
            .flat_map(|bundle| bundle.recommendations.iter())
        {
            assert!(!rec.binaries.is_empty(), "{}", rec.id);
        }
    }

    #[test]
    fn requires_consent_is_true_for_exactly_the_non_free_kinds() {
        fn expected(kind: LicenseKind) -> bool {
            match kind {
                LicenseKind::Free => false,
                LicenseKind::FreePersonal
                | LicenseKind::PaidForCommercial
                | LicenseKind::FreeWithTerms => true,
            }
        }
        let kinds = [
            LicenseKind::Free,
            LicenseKind::FreePersonal,
            LicenseKind::PaidForCommercial,
            LicenseKind::FreeWithTerms,
        ];
        for kind in kinds {
            assert_eq!(kind.requires_consent(), expected(kind), "{kind:?}");
        }
    }

    #[test]
    fn consent_rows_are_exactly_the_terms_rows() {
        let mut consented: Vec<_> = bundles()
            .iter()
            .flat_map(|bundle| bundle.recommendations.iter())
            .filter(|rec| rec.license.kind.requires_consent())
            .map(|rec| rec.id)
            .collect();
        consented.sort_unstable();
        assert_eq!(
            consented,
            [
                "containers-docker-desktop",
                "containers-orbstack",
                "iac-terraform",
                "iac-terraform-linux"
            ]
        );
    }

    #[test]
    fn consent_rows_defer_to_a_free_alternative() {
        let bundles = bundles();
        let all = index(&bundles);
        for rec in all.values() {
            if !rec.license.kind.requires_consent() {
                continue;
            }
            let alt = rec.alternative.expect("non-Free row carries a defer link");
            assert_eq!(
                all[alt].license.kind,
                LicenseKind::Free,
                "{} defers to non-Free {alt}",
                rec.id
            );
        }
    }

    #[test]
    fn gate_tools_each_have_a_recommendation() {
        let gate_tools = [
            ("sccache", "rust-sccache"),
            ("mold", "rust-mold"),
            ("orbstack", "containers-orbstack"),
            ("docker", "containers-docker-desktop"),
            ("colima", "containers-colima"),
            ("podman", "containers-podman"),
            ("uv", "python-uv"),
            ("opentofu", "iac-opentofu"),
            ("terraform", "iac-terraform"),
        ];
        let bundles = bundles();
        let all = index(&bundles);
        for (tool, id) in gate_tools {
            let rec = all
                .get(id)
                .unwrap_or_else(|| panic!("{tool} has no recommendation ({id})"));
            let named =
                rec.binaries.contains(&tool) || rec.title.to_ascii_lowercase().contains(tool);
            assert!(named, "{id} does not name {tool} in binaries or title");
        }
    }

    #[test]
    fn license_kind_round_trips_through_json() -> Result<(), serde_json::Error> {
        for kind in [
            LicenseKind::Free,
            LicenseKind::FreePersonal,
            LicenseKind::PaidForCommercial,
            LicenseKind::FreeWithTerms,
        ] {
            let json = serde_json::to_string(&kind)?;
            let back: LicenseKind = serde_json::from_str(&json)?;
            assert_eq!(back, kind);
        }
        Ok(())
    }

    #[test]
    fn license_info_serializes_and_deserializes_from_json() -> Result<(), serde_json::Error> {
        let info = license(
            LicenseKind::PaidForCommercial,
            None,
            "Proprietary freemium.",
            "https://orbstack.dev/pricing",
            "2026-10-12",
        );
        let json = serde_json::to_string(&info)?;
        assert!(json.contains("PaidForCommercial"));
        assert!(json.contains("https://orbstack.dev/pricing"));
        let back: LicenseInfo = serde_json::from_str(
            r#"{"kind":"FreeWithTerms","spdx":"BUSL-1.1","summary":"thresholds",
                "terms_url":"https://docs.docker.com/subscription/desktop-license/",
                "verified":"2026-10-12"}"#,
        )?;
        assert_eq!(back.kind, LicenseKind::FreeWithTerms);
        assert_eq!(back.spdx, Some("BUSL-1.1"));
        assert_eq!(back.verified, "2026-10-12");
        Ok(())
    }

    #[test]
    fn detector_presence_probes_nothing_for_empty_candidate_lists() {
        let detector = InstallerDetector::with_runner(Arc::new(FakeRunner::new().strict()));
        let presence = DetectorPresence::new(detector);
        assert!(!presence.is_present(&[]));
    }
}
