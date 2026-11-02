//! Curated setup bundles: license-labeled tool recommendations whose
//! load-bearing axis is commercial use. Data model + compiled-in registry;
//! evaluation, planning, and hint application build on these types.

use toride_apps::{
    DistroFamily, InstallMethod, InstallOptions, InstallPlan, InstallRecord, NativeIds, Os, Target,
    TorideId, plan_install,
};
use toride_installer::Tool;
use toride_installer::status::{Detector as InstallerDetector, ToolStatus as InstallerToolStatus};
use toride_registry::{App, Availability};

/// Commercial-use axis of a tool's license: the load-bearing label.
/// Anything but [`LicenseKind::Free`] sets [`LicenseKind::requires_consent`]
/// and blocks install until the linked terms are accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum LicenseKind {
    /// Unrestricted commercial use. GPL tools land here too: distribution
    /// obligations, not use restrictions: the summary says so.
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

impl Condition {
    /// Whether the condition holds for `target` under `presence`:
    /// [`Condition::Os`] matches the target's OS, [`Condition::Distro`] the
    /// target's known distro family, [`Condition::Missing`] probes the tool
    /// through [`ToolPresence`], and [`Condition::All`] requires every
    /// sub-condition.
    #[must_use]
    pub fn holds(&self, target: &Target, presence: &dyn ToolPresence) -> bool {
        match self {
            Self::Os(os) => *os == target.os,
            Self::Distro(family) => target.distro == Some(*family),
            Self::Missing { tool } => !presence.is_present(&[*tool]),
            Self::All(conditions) => conditions.iter().all(|c| c.holds(target, presence)),
        }
    }
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

/// One step of a recommendation: a package install, a config hint, a
/// deliberate manual step, a systemd unit deploy, or a firewall port.
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
    /// Deploy a systemd unit through toride-service, consent-gated like
    /// [`InstallAction::Hint`]: the exact `contents` are shown before
    /// anything is written. Execution wiring is a follow-up, so planning
    /// skips this step today and no bundle carries one yet.
    Unit {
        /// Unit name ending in `.service`.
        name: &'static str,
        /// Exact unit file contents.
        contents: &'static str,
    },
    /// Open or close one firewall port through ufw-kit, consent-gated
    /// like [`InstallAction::Hint`]. Execution wiring is a follow-up, so
    /// planning skips this step today and no bundle carries one yet.
    Firewall {
        /// The port rule to apply.
        spec: FirewallRule,
    },
}

/// One firewall-port step of an [`InstallAction::Firewall`] action: the
/// minimal typed shape setup bundles express, widened to a ufw-kit
/// `RuleSpec` when the execution wiring lands.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FirewallRule {
    /// Port the rule covers.
    pub port: u16,
    /// Protocol the rule covers.
    pub protocol: FirewallProtocol,
    /// Whether the port is opened or closed.
    pub allow: bool,
}

/// Protocol of a [`FirewallRule`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum FirewallProtocol {
    /// TCP traffic only.
    Tcp,
    /// UDP traffic only.
    Udp,
    /// Both TCP and UDP.
    Both,
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
        terminal_mux_bundle(),
        terminal_emulators_bundle(),
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

#[expect(
    clippy::too_many_lines,
    reason = "data manifest: one block per registry row"
)]
fn terminal_mux_bundle() -> SetupBundle {
    SetupBundle {
        id: "terminal-mux",
        title: "Terminal multiplexers",
        default_pick: "mux-tmux-debian",
        recommendations: vec![
            rec(
                "mux-tmux-debian",
                "tmux",
                "Multiplexes terminals into sessions that survive a dropped connection.",
                license(
                    LicenseKind::Free,
                    Some("ISC"),
                    "ISC; commercial use unrestricted.",
                    "https://github.com/tmux/tmux",
                    "2026-10-23",
                ),
                Condition::Distro(DistroFamily::Debian),
                &["tmux"],
                vec![install("tmux", distro(DistroFamily::Debian, "tmux"))],
                None,
            ),
            rec(
                "mux-tmux-ubuntu",
                "tmux",
                "The same multiplexer from the Ubuntu archive.",
                license(
                    LicenseKind::Free,
                    Some("ISC"),
                    "ISC; commercial use unrestricted.",
                    "https://github.com/tmux/tmux",
                    "2026-10-23",
                ),
                Condition::Distro(DistroFamily::Ubuntu),
                &["tmux"],
                vec![install("tmux", distro(DistroFamily::Ubuntu, "tmux"))],
                None,
            ),
            rec(
                "mux-tmux-fedora",
                "tmux",
                "The same multiplexer from the Fedora archive.",
                license(
                    LicenseKind::Free,
                    Some("ISC"),
                    "ISC; commercial use unrestricted.",
                    "https://github.com/tmux/tmux",
                    "2026-10-23",
                ),
                Condition::Distro(DistroFamily::Fedora),
                &["tmux"],
                vec![install("tmux", distro(DistroFamily::Fedora, "tmux"))],
                None,
            ),
            rec(
                "mux-tmux-arch",
                "tmux",
                "The same multiplexer from the Arch extra repository.",
                license(
                    LicenseKind::Free,
                    Some("ISC"),
                    "ISC; commercial use unrestricted.",
                    "https://github.com/tmux/tmux",
                    "2026-10-23",
                ),
                Condition::Distro(DistroFamily::Arch),
                &["tmux"],
                vec![install("tmux", distro(DistroFamily::Arch, "tmux"))],
                None,
            ),
            rec(
                "mux-zellij",
                "zellij",
                "Rust multiplexer with a status bar, layouts, and plugins.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://github.com/zellij-org/zellij",
                    "2026-10-23",
                ),
                Condition::All(Vec::new()),
                &["zellij"],
                vec![install("zellij", cargo("zellij"))],
                None,
            ),
            rec(
                "mux-screen-debian",
                "GNU screen",
                "The GNU multiplexer that predates tmux, offered only when the binary is missing.",
                license(
                    LicenseKind::Free,
                    Some("GPL-3.0-or-later"),
                    "GPL-3.0-or-later; free for commercial use, distribution carries source \
                     obligations.",
                    "https://cgit.git.savannah.gnu.org/cgit/screen.git/plain/COPYING",
                    "2026-10-23",
                ),
                Condition::All(vec![
                    Condition::Distro(DistroFamily::Debian),
                    Condition::Missing { tool: "screen" },
                ]),
                &["screen"],
                vec![install("screen", distro(DistroFamily::Debian, "screen"))],
                None,
            ),
            rec(
                "mux-screen-ubuntu",
                "GNU screen",
                "The same GNU multiplexer from the Ubuntu archive.",
                license(
                    LicenseKind::Free,
                    Some("GPL-3.0-or-later"),
                    "GPL-3.0-or-later; free for commercial use, distribution carries source \
                     obligations.",
                    "https://cgit.git.savannah.gnu.org/cgit/screen.git/plain/COPYING",
                    "2026-10-23",
                ),
                Condition::All(vec![
                    Condition::Distro(DistroFamily::Ubuntu),
                    Condition::Missing { tool: "screen" },
                ]),
                &["screen"],
                vec![install("screen", distro(DistroFamily::Ubuntu, "screen"))],
                None,
            ),
            rec(
                "mux-screen-fedora",
                "GNU screen",
                "The same GNU multiplexer from the Fedora archive.",
                license(
                    LicenseKind::Free,
                    Some("GPL-3.0-or-later"),
                    "GPL-3.0-or-later; free for commercial use, distribution carries source \
                     obligations.",
                    "https://cgit.git.savannah.gnu.org/cgit/screen.git/plain/COPYING",
                    "2026-10-23",
                ),
                Condition::All(vec![
                    Condition::Distro(DistroFamily::Fedora),
                    Condition::Missing { tool: "screen" },
                ]),
                &["screen"],
                vec![install("screen", distro(DistroFamily::Fedora, "screen"))],
                None,
            ),
            rec(
                "mux-screen-arch",
                "GNU screen",
                "The same GNU multiplexer from the Arch extra repository.",
                license(
                    LicenseKind::Free,
                    Some("GPL-3.0-or-later"),
                    "GPL-3.0-or-later; free for commercial use, distribution carries source \
                     obligations.",
                    "https://cgit.git.savannah.gnu.org/cgit/screen.git/plain/COPYING",
                    "2026-10-23",
                ),
                Condition::All(vec![
                    Condition::Distro(DistroFamily::Arch),
                    Condition::Missing { tool: "screen" },
                ]),
                &["screen"],
                vec![install("screen", distro(DistroFamily::Arch, "screen"))],
                None,
            ),
        ],
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "data manifest: one block per registry row"
)]
fn terminal_emulators_bundle() -> SetupBundle {
    SetupBundle {
        id: "terminal-emulators",
        title: "Terminal emulators",
        default_pick: "term-alacritty-debian",
        recommendations: vec![
            rec(
                "term-alacritty-debian",
                "alacritty",
                "GPU-accelerated emulator configured from one TOML file.",
                license(
                    LicenseKind::Free,
                    Some("Apache-2.0"),
                    "Apache-2.0; commercial use unrestricted.",
                    "https://github.com/alacritty/alacritty",
                    "2026-10-23",
                ),
                Condition::Distro(DistroFamily::Debian),
                &["alacritty"],
                vec![install(
                    "alacritty",
                    distro(DistroFamily::Debian, "alacritty"),
                )],
                None,
            ),
            rec(
                "term-alacritty-ubuntu",
                "alacritty",
                "The same emulator from the Ubuntu archive.",
                license(
                    LicenseKind::Free,
                    Some("Apache-2.0"),
                    "Apache-2.0; commercial use unrestricted.",
                    "https://github.com/alacritty/alacritty",
                    "2026-10-23",
                ),
                Condition::Distro(DistroFamily::Ubuntu),
                &["alacritty"],
                vec![install(
                    "alacritty",
                    distro(DistroFamily::Ubuntu, "alacritty"),
                )],
                None,
            ),
            rec(
                "term-alacritty-fedora",
                "alacritty",
                "The same emulator from the Fedora archive.",
                license(
                    LicenseKind::Free,
                    Some("Apache-2.0"),
                    "Apache-2.0; commercial use unrestricted.",
                    "https://github.com/alacritty/alacritty",
                    "2026-10-23",
                ),
                Condition::Distro(DistroFamily::Fedora),
                &["alacritty"],
                vec![install(
                    "alacritty",
                    distro(DistroFamily::Fedora, "alacritty"),
                )],
                None,
            ),
            rec(
                "term-alacritty-arch",
                "alacritty",
                "The same emulator from the Arch extra repository.",
                license(
                    LicenseKind::Free,
                    Some("Apache-2.0"),
                    "Apache-2.0; commercial use unrestricted.",
                    "https://github.com/alacritty/alacritty",
                    "2026-10-23",
                ),
                Condition::Distro(DistroFamily::Arch),
                &["alacritty"],
                vec![install(
                    "alacritty",
                    distro(DistroFamily::Arch, "alacritty"),
                )],
                None,
            ),
            rec(
                "term-kitty-debian",
                "kitty",
                "GPU-accelerated emulator; the package is `kitty`, `kitten` its CLI helper.",
                license(
                    LicenseKind::Free,
                    Some("GPL-3.0"),
                    "GPL-3.0; free for commercial use, distribution carries source obligations.",
                    "https://github.com/kovidgoyal/kitty",
                    "2026-10-23",
                ),
                Condition::Distro(DistroFamily::Debian),
                &["kitty", "kitten"],
                vec![install("kitty", distro(DistroFamily::Debian, "kitty"))],
                None,
            ),
            rec(
                "term-kitty-ubuntu",
                "kitty",
                "The same emulator from the Ubuntu archive.",
                license(
                    LicenseKind::Free,
                    Some("GPL-3.0"),
                    "GPL-3.0; free for commercial use, distribution carries source obligations.",
                    "https://github.com/kovidgoyal/kitty",
                    "2026-10-23",
                ),
                Condition::Distro(DistroFamily::Ubuntu),
                &["kitty", "kitten"],
                vec![install("kitty", distro(DistroFamily::Ubuntu, "kitty"))],
                None,
            ),
            rec(
                "term-kitty-fedora",
                "kitty",
                "The same emulator from the Fedora archive.",
                license(
                    LicenseKind::Free,
                    Some("GPL-3.0"),
                    "GPL-3.0; free for commercial use, distribution carries source obligations.",
                    "https://github.com/kovidgoyal/kitty",
                    "2026-10-23",
                ),
                Condition::Distro(DistroFamily::Fedora),
                &["kitty", "kitten"],
                vec![install("kitty", distro(DistroFamily::Fedora, "kitty"))],
                None,
            ),
            rec(
                "term-kitty-arch",
                "kitty",
                "The same emulator from the Arch extra repository.",
                license(
                    LicenseKind::Free,
                    Some("GPL-3.0"),
                    "GPL-3.0; free for commercial use, distribution carries source obligations.",
                    "https://github.com/kovidgoyal/kitty",
                    "2026-10-23",
                ),
                Condition::Distro(DistroFamily::Arch),
                &["kitty", "kitten"],
                vec![install("kitty", distro(DistroFamily::Arch, "kitty"))],
                None,
            ),
            rec(
                "term-wezterm-arch",
                "wezterm",
                "GPU-accelerated emulator with a built-in mux server, configured in Lua.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted; bundled fonts are OFL 1.1.",
                    "https://github.com/wezterm/wezterm",
                    "2026-10-23",
                ),
                Condition::Distro(DistroFamily::Arch),
                &["wezterm"],
                vec![install("wezterm", distro(DistroFamily::Arch, "wezterm"))],
                None,
            ),
            rec(
                "term-ghostty-ubuntu",
                "ghostty",
                "Native GUI emulator focused on performance and platform correctness.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://github.com/ghostty-org/ghostty",
                    "2026-10-23",
                ),
                Condition::Distro(DistroFamily::Ubuntu),
                &["ghostty"],
                vec![install("ghostty", distro(DistroFamily::Ubuntu, "ghostty"))],
                None,
            ),
            rec(
                "term-ghostty-arch",
                "ghostty",
                "The same emulator from the Arch extra repository.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://github.com/ghostty-org/ghostty",
                    "2026-10-23",
                ),
                Condition::Distro(DistroFamily::Arch),
                &["ghostty"],
                vec![install("ghostty", distro(DistroFamily::Arch, "ghostty"))],
                None,
            ),
            rec(
                "term-ghostty-debian",
                "ghostty",
                "No Debian package exists, so this row hands off to upstream's build guide.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://github.com/ghostty-org/ghostty",
                    "2026-10-23",
                ),
                Condition::Distro(DistroFamily::Debian),
                &["ghostty"],
                vec![manual(
                    "no distro package; build from source per \
                     https://ghostty.org/docs/install/build",
                )],
                None,
            ),
            rec(
                "term-ghostty-fedora",
                "ghostty",
                "No Fedora package exists, so this row hands off to upstream's build guide.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://github.com/ghostty-org/ghostty",
                    "2026-10-23",
                ),
                Condition::Distro(DistroFamily::Fedora),
                &["ghostty"],
                vec![manual(
                    "no distro package; build from source per \
                     https://ghostty.org/docs/install/build",
                )],
                None,
            ),
            rec(
                "term-foot-debian",
                "foot",
                "Wayland-only emulator with a client-daemon split and low resource use.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://codeberg.org/dnkl/foot",
                    "2026-10-23",
                ),
                Condition::Distro(DistroFamily::Debian),
                &["foot", "footclient"],
                vec![install("foot", distro(DistroFamily::Debian, "foot"))],
                None,
            ),
            rec(
                "term-foot-ubuntu",
                "foot",
                "The same Wayland-only emulator from the Ubuntu archive.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://codeberg.org/dnkl/foot",
                    "2026-10-23",
                ),
                Condition::Distro(DistroFamily::Ubuntu),
                &["foot", "footclient"],
                vec![install("foot", distro(DistroFamily::Ubuntu, "foot"))],
                None,
            ),
            rec(
                "term-foot-fedora",
                "foot",
                "The same Wayland-only emulator from the Fedora archive.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://codeberg.org/dnkl/foot",
                    "2026-10-23",
                ),
                Condition::Distro(DistroFamily::Fedora),
                &["foot", "footclient"],
                vec![install("foot", distro(DistroFamily::Fedora, "foot"))],
                None,
            ),
            rec(
                "term-foot-arch",
                "foot",
                "The same Wayland-only emulator from the Arch extra repository.",
                license(
                    LicenseKind::Free,
                    Some("MIT"),
                    "MIT; commercial use unrestricted.",
                    "https://codeberg.org/dnkl/foot",
                    "2026-10-23",
                ),
                Condition::Distro(DistroFamily::Arch),
                &["foot", "footclient"],
                vec![install("foot", distro(DistroFamily::Arch, "foot"))],
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

/// What evaluation hands the UI: only the rows whose condition holds and
/// whose tool is not already present, grouped by bundle in registry order.
/// Bundles left with no rows are dropped.
#[derive(Clone, Debug)]
pub struct SetupOffers {
    /// Offered bundles, registry order.
    pub bundles: Vec<SetupBundle>,
    /// Ids of rows suppressed because their tool is already present, in
    /// registry order (shared presence keys list every suppressed row).
    /// Rows whose condition failed are absent, never listed here.
    pub satisfied: Vec<&'static str>,
}

/// Evaluate the whole registry against `target` and `presence`. Never
/// errors: a row whose condition fails is absent from the offers.
#[must_use]
pub fn evaluate(target: &Target, presence: &dyn ToolPresence) -> SetupOffers {
    let mut satisfied = Vec::new();
    let mut offered = Vec::new();
    for mut bundle in bundles() {
        bundle.recommendations.retain(|rec| {
            if !rec.condition.holds(target, presence) {
                return false;
            }
            if presence.is_present(rec.binaries) {
                satisfied.push(rec.id);
                return false;
            }
            true
        });
        if !bundle.recommendations.is_empty() {
            offered.push(bundle);
        }
    }
    SetupOffers {
        bundles: offered,
        satisfied,
    }
}

/// The user's verdict on a row's linked terms: the only input
/// [`require_consent`] consults beyond the row's license label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Consent {
    /// The dialog has not been answered.
    Pending,
    /// The user accepted the linked terms.
    Accepted,
    /// The user declined the linked terms.
    Refused,
}

/// The refusal [`require_consent`] returns for a consent-gated row without
/// an accepted verdict; carries everything the consent dialog renders.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentRequired {
    /// Id of the row that needs consent.
    pub recommendation: &'static str,
    /// The row's full license label: kind, terms URL, verified date.
    pub license: LicenseInfo,
    /// The verdict that failed the gate.
    pub consent: Consent,
}

impl std::fmt::Display for ConsentRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            recommendation,
            license,
            consent,
        } = self;
        write!(
            f,
            "`{recommendation}` requires accepting its terms before install \
             (consent: {consent:?}); terms: {}",
            license.terms_url
        )
    }
}

impl std::error::Error for ConsentRequired {}

/// The gate every non-`Free` row passes only with [`Consent::Accepted`];
/// `Free` rows pass regardless: there are no terms to accept.
///
/// # Errors
///
/// [`ConsentRequired`] when `rec.license.kind.requires_consent()` and
/// `consent` is any verdict but [`Consent::Accepted`].
pub fn require_consent(rec: &Recommendation, consent: Consent) -> Result<(), ConsentRequired> {
    if rec.license.kind.requires_consent() && consent != Consent::Accepted {
        return Err(ConsentRequired {
            recommendation: rec.id,
            license: rec.license.clone(),
            consent,
        });
    }
    Ok(())
}

/// Plan the row's install actions at plan time through the toride-apps
/// planner, whose availability and platform gates apply. Each action builds
/// its registry `App` inline: `TorideId::slugify(name)`, the declared
/// method, no platform claims (the method's own scope governs), and
/// [`Availability::Available`]. `Hint`, `Manual`, `Unit`, and `Firewall`
/// steps have no planner shape and are absent from the result: a
/// manual-only row plans nothing.
#[must_use]
pub fn plan_row(
    rec: &Recommendation,
    target: &Target,
) -> Vec<Result<InstallPlan, toride_apps::Error>> {
    rec.actions
        .iter()
        .filter_map(|action| match action {
            InstallAction::Install(spec) => Some(plan_install(
                &registry_app(spec),
                target,
                &InstallOptions::new(),
            )),
            InstallAction::Hint(_)
            | InstallAction::Manual { .. }
            | InstallAction::Unit { .. }
            | InstallAction::Firewall { .. } => None,
        })
        .collect()
}

fn registry_app(spec: &InstallSpec) -> App {
    App {
        id: TorideId::slugify(spec.name),
        name: spec.name.to_owned(),
        aliases: Vec::new(),
        summary: None,
        description: None,
        homepage: None,
        license: None,
        developer: None,
        binaries: Vec::new(),
        latest: None,
        platforms: Vec::new(),
        artifacts: Vec::new(),
        install: spec.method.clone(),
        sources: Vec::new(),
        availability: Availability::Available,
    }
}

/// The backend-native identifiers an executed install records under,
/// derived from the row's declared method: the same values the planner
/// rendered into the plan's operation. `None` for methods the registry
/// never routes today (flatpak, direct) and for future `InstallMethod`
/// variants.
#[must_use]
pub fn record_ids(spec: &InstallSpec) -> Option<NativeIds> {
    match &spec.method {
        InstallMethod::Homebrew { cask, token } => Some(NativeIds::Homebrew {
            token: token.clone(),
            cask: *cask,
        }),
        InstallMethod::Distro {
            family, package, ..
        } => Some(NativeIds::Distro {
            package: package.clone(),
            family: *family,
        }),
        InstallMethod::Npm { package, .. } => Some(NativeIds::Npm {
            package: package.clone(),
        }),
        InstallMethod::Cargo { crate_, .. } => Some(NativeIds::Cargo {
            crate_: crate_.clone(),
        }),
        InstallMethod::Pipx { package } => Some(NativeIds::Pipx {
            package: package.clone(),
        }),
        InstallMethod::Uv { package, .. } => Some(NativeIds::Uv {
            package: package.clone(),
        }),
        InstallMethod::Mise { tool, .. } => Some(NativeIds::Mise { tool: tool.clone() }),
        _ => None,
    }
}

/// The manifest record for an executed install: the executed `plan`, the
/// ids derived from the row's [`InstallSpec`], and the backend-reported
/// post-verify `version`. `None` when [`record_ids`] is `None`: the
/// operation has no post-execution native identity to record.
#[must_use]
pub fn install_record(
    plan: InstallPlan,
    spec: &InstallSpec,
    version: Option<String>,
) -> Option<InstallRecord> {
    let ids = record_ids(spec)?;
    Some(InstallRecord::new(plan, ids, version))
}

mod hints;

pub use hints::{HintResult, apply_hint};

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::Arc;

    use super::hints::apply_hint_with;
    use super::*;
    use toride_apps::InstallManifest;
    use toride_apps::backend::ensure_install_allowed;
    use toride_apps::{Arch, BackendId, Error, InstallRequest, Operation, PackageManager};
    use toride_runner::FakeRunner;

    struct FixedPresence {
        installed: &'static [&'static str],
    }

    impl ToolPresence for FixedPresence {
        fn is_present(&self, binaries: &[&str]) -> bool {
            binaries.iter().any(|bin| self.installed.contains(bin))
        }
    }

    fn empty() -> FixedPresence {
        FixedPresence { installed: &[] }
    }

    fn find_bundle<'a>(offers: &'a SetupOffers, id: &str) -> Option<&'a SetupBundle> {
        offers.bundles.iter().find(|bundle| bundle.id == id)
    }

    fn find_rec<'a>(offers: &'a SetupOffers, id: &str) -> Option<&'a Recommendation> {
        offers
            .bundles
            .iter()
            .flat_map(|bundle| bundle.recommendations.iter())
            .find(|rec| rec.id == id)
    }

    fn install_spec(rec: &Recommendation) -> &InstallSpec {
        match &rec.actions[0] {
            InstallAction::Install(spec) => spec,
            other => panic!("{}: first action is {other:?}, not an install", rec.id),
        }
    }

    fn index(bundles: &[SetupBundle]) -> BTreeMap<&'static str, &Recommendation> {
        bundles
            .iter()
            .flat_map(|bundle| bundle.recommendations.iter())
            .map(|rec| (rec.id, rec))
            .collect()
    }

    #[test]
    fn registry_has_the_ten_planned_bundles() {
        let bundles = bundles();
        let ids: Vec<_> = bundles.iter().map(|b| b.id).collect();
        assert_eq!(bundles.len(), 10);
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
                "terminal-mux",
                "terminal-emulators",
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
        const VERIFICATION_DATES: [&str; 2] = ["2026-10-12", "2026-10-23"];
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
            assert!(
                VERIFICATION_DATES.contains(&rec.license.verified),
                "{}: verified {} is not a registry verification date",
                rec.id,
                rec.license.verified
            );
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
            ("tmux", "mux-tmux-debian"),
            ("zellij", "mux-zellij"),
            ("screen", "mux-screen-debian"),
            ("kitty", "term-kitty-debian"),
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

    fn condition_target(condition: &Condition) -> Option<Target> {
        match condition {
            Condition::Os(os) => Some(Target::new(*os, Arch::Aarch64)),
            Condition::Distro(family) => Some(Target::linux(Arch::X86_64, *family)),
            Condition::All(subs) => subs
                .iter()
                .find_map(condition_target)
                .or(Some(Target::linux(Arch::X86_64, DistroFamily::Debian))),
            Condition::Missing { .. } => None,
        }
    }

    #[test]
    fn every_install_action_routes_on_a_target_its_condition_accepts() {
        for bundle in bundles() {
            for rec in &bundle.recommendations {
                let Some(target) = condition_target(&rec.condition) else {
                    continue;
                };
                for outcome in plan_row(rec, &target) {
                    assert!(
                        outcome.is_ok(),
                        "{} does not route on {:?}: {:?}",
                        rec.id,
                        target,
                        outcome.err()
                    );
                }
            }
        }
    }

    #[test]
    fn linux_evaluation_offers_tmux_and_presence_gates_screen() {
        let debian = Target::linux(Arch::X86_64, DistroFamily::Debian);
        let offers = evaluate(&debian, &empty());
        let mux = find_bundle(&offers, "terminal-mux").expect("mux offered on Debian");
        let offered: Vec<_> = mux.recommendations.iter().map(|rec| rec.id).collect();
        assert_eq!(
            offered,
            ["mux-tmux-debian", "mux-zellij", "mux-screen-debian"]
        );
        assert_eq!(mux.default_pick, "mux-tmux-debian");

        let offers = evaluate(
            &debian,
            &FixedPresence {
                installed: &["screen"],
            },
        );
        let mux =
            find_bundle(&offers, "terminal-mux").expect("mux still offered with screen present");
        let offered: Vec<_> = mux.recommendations.iter().map(|rec| rec.id).collect();
        assert_eq!(offered, ["mux-tmux-debian", "mux-zellij"]);
        assert!(
            !offers.satisfied.contains(&"mux-screen-debian"),
            "a condition-failed row is absent, never satisfied-listed"
        );
    }

    #[test]
    fn macos_evaluation_offers_only_zellij_from_the_terminal_bundles() {
        let offers = evaluate(&Target::macos(Arch::Aarch64), &empty());
        let mux = find_bundle(&offers, "terminal-mux").expect("mux bundle offered on macOS");
        let offered: Vec<_> = mux.recommendations.iter().map(|rec| rec.id).collect();
        assert_eq!(offered, ["mux-zellij"]);
        assert!(
            find_bundle(&offers, "terminal-emulators").is_none(),
            "the all-distro emulators bundle is dropped on macOS"
        );
    }

    #[test]
    fn linux_evaluation_offers_the_debian_emulator_rows() {
        let debian = Target::linux(Arch::X86_64, DistroFamily::Debian);
        let offers = evaluate(&debian, &empty());
        let emulators =
            find_bundle(&offers, "terminal-emulators").expect("emulators offered on Debian");
        let offered: Vec<_> = emulators.recommendations.iter().map(|rec| rec.id).collect();
        assert_eq!(
            offered,
            [
                "term-alacritty-debian",
                "term-kitty-debian",
                "term-ghostty-debian",
                "term-foot-debian"
            ]
        );
        assert_eq!(emulators.default_pick, "term-alacritty-debian");
    }

    #[test]
    fn terminal_rows_route_through_their_declared_backends() -> Result<(), Error> {
        let bundles = bundles();
        let all = index(&bundles);
        let debian = Target::linux(Arch::X86_64, DistroFamily::Debian);
        let tmux = plan_row(all["mux-tmux-debian"], &debian)
            .into_iter()
            .next()
            .unwrap()?;
        assert_eq!(tmux.backend, BackendId::Distro(DistroFamily::Debian));
        assert!(tmux.requires_elevation);
        assert_eq!(
            tmux.operation,
            Operation::DistroInstall {
                manager: PackageManager::Apt,
                package: "tmux".to_owned(),
            }
        );
        let zellij = plan_row(all["mux-zellij"], &Target::macos(Arch::Aarch64))
            .into_iter()
            .next()
            .unwrap()?;
        assert_eq!(zellij.backend, BackendId::Cargo);
        assert_eq!(
            zellij.operation,
            Operation::CargoInstall {
                crate_: "zellij".to_owned(),
                version: None,
            }
        );
        assert_eq!(
            record_ids(install_spec(all["term-ghostty-arch"])),
            Some(NativeIds::Distro {
                package: "ghostty".to_owned(),
                family: DistroFamily::Arch,
            })
        );
        let fedora = Target::linux(Arch::X86_64, DistroFamily::Fedora);
        assert!(
            plan_row(all["term-ghostty-fedora"], &fedora).is_empty(),
            "a manual-only row plans nothing"
        );
        Ok(())
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

    #[test]
    fn detector_presence_reports_absent_binaries_as_absent() {
        let detector = InstallerDetector::with_runner(Arc::new(FakeRunner::new().strict()));
        let presence = DetectorPresence::new(detector);
        assert!(!presence.is_present(&["toride-setup-bundles-absence-probe"]));
    }

    #[test]
    fn os_conditions_gate_by_target_os() {
        let macos = Target::macos(Arch::Aarch64);
        let linux = Target::linux(Arch::X86_64, DistroFamily::Fedora);
        assert!(Condition::Os(Os::MacOs).holds(&macos, &empty()));
        assert!(!Condition::Os(Os::MacOs).holds(&linux, &empty()));
        assert!(Condition::Os(Os::Linux).holds(&linux, &empty()));
        assert!(!Condition::Os(Os::Linux).holds(&macos, &empty()));
    }

    #[test]
    fn distro_conditions_need_the_targets_known_family() {
        let presence = empty();
        let debian = Target::linux(Arch::X86_64, DistroFamily::Debian);
        let fedora = Target::linux(Arch::X86_64, DistroFamily::Fedora);
        let unknown = Target::new(Os::Linux, Arch::X86_64);
        assert!(Condition::Distro(DistroFamily::Debian).holds(&debian, &presence));
        assert!(!Condition::Distro(DistroFamily::Debian).holds(&fedora, &presence));
        assert!(!Condition::Distro(DistroFamily::Debian).holds(&unknown, &presence));
        assert!(
            !Condition::Distro(DistroFamily::Debian)
                .holds(&Target::macos(Arch::Aarch64), &presence)
        );
    }

    #[test]
    fn missing_conditions_probe_presence() {
        let target = Target::macos(Arch::Aarch64);
        let missing = Condition::Missing { tool: "mold" };
        assert!(missing.holds(&target, &empty()));
        assert!(!missing.holds(
            &target,
            &FixedPresence {
                installed: &["mold"]
            }
        ));
    }

    #[test]
    fn all_conditions_require_every_subcondition() {
        let target = Target::macos(Arch::Aarch64);
        let both = Condition::All(vec![
            Condition::Os(Os::MacOs),
            Condition::Missing { tool: "mold" },
        ]);
        assert!(both.holds(&target, &empty()));
        assert!(!both.holds(&Target::linux(Arch::X86_64, DistroFamily::Debian), &empty()));
        assert!(!both.holds(
            &target,
            &FixedPresence {
                installed: &["mold"]
            }
        ));
        assert!(Condition::All(Vec::new()).holds(&target, &empty()));
    }

    #[test]
    fn macos_evaluation_offers_the_container_rows_and_hides_mold() {
        let offers = evaluate(&Target::macos(Arch::Aarch64), &empty());
        let containers = find_bundle(&offers, "containers").expect("containers offered on macOS");
        let offered: Vec<_> = containers
            .recommendations
            .iter()
            .map(|rec| rec.id)
            .collect();
        for id in [
            "containers-colima",
            "containers-podman",
            "containers-orbstack",
            "containers-docker-desktop",
        ] {
            assert!(offered.contains(&id), "{id} not offered on macOS");
        }
        assert_eq!(containers.default_pick, "containers-colima");
        let colima = find_rec(&offers, "containers-colima").unwrap();
        assert_eq!(colima.license.kind, LicenseKind::Free);
        let orbstack = find_rec(&offers, "containers-orbstack").unwrap();
        assert_eq!(orbstack.license.kind, LicenseKind::PaidForCommercial);
        let docker = find_rec(&offers, "containers-docker-desktop").unwrap();
        assert_eq!(docker.license.kind, LicenseKind::FreeWithTerms);
        assert!(
            find_rec(&offers, "rust-mold").is_none(),
            "mold hidden on macOS"
        );
    }

    #[test]
    fn linux_evaluation_offers_mold_and_drops_the_macos_rows() {
        let offers = evaluate(&Target::linux(Arch::X86_64, DistroFamily::Debian), &empty());
        let mold = find_rec(&offers, "rust-mold").expect("mold offered on Linux");
        assert_eq!(mold.license.kind, LicenseKind::Free);
        assert!(
            find_bundle(&offers, "containers").is_none(),
            "the all-macOS containers bundle is dropped on Linux"
        );
        for id in ["containers-colima", "containers-orbstack", "rust-sccache"] {
            assert!(find_rec(&offers, id).is_none(), "{id} is macOS-only");
        }
    }

    #[test]
    fn evaluation_suppresses_present_tools_into_satisfied() {
        let offers = evaluate(
            &Target::macos(Arch::Aarch64),
            &FixedPresence {
                installed: &["podman"],
            },
        );
        let containers = find_bundle(&offers, "containers").unwrap();
        let offered: Vec<_> = containers
            .recommendations
            .iter()
            .map(|rec| rec.id)
            .collect();
        assert!(!offered.contains(&"containers-podman"));
        assert!(!offered.contains(&"containers-podman-desktop"));
        assert!(offered.contains(&"containers-colima"));
        assert_eq!(
            offers.satisfied,
            vec!["containers-podman", "containers-podman-desktop"]
        );
    }

    #[test]
    fn orbstack_row_plans_the_brew_cask_install() -> Result<(), Error> {
        let bundles = bundles();
        let all = index(&bundles);
        let macos = Target::macos(Arch::Aarch64);
        let plans = plan_row(all["containers-orbstack"], &macos);
        assert_eq!(plans.len(), 1);
        let plan = plans.into_iter().next().unwrap()?;
        assert_eq!(plan.backend, BackendId::Homebrew);
        assert!(!plan.dry_run);
        assert!(!plan.requires_elevation);
        assert!(
            plan.summary().contains("brew install --cask orbstack"),
            "{}",
            plan.summary()
        );
        Ok(())
    }

    #[test]
    fn opentofu_rows_route_per_their_declared_methods() -> Result<(), Error> {
        let bundles = bundles();
        let all = index(&bundles);
        let macos_plan = plan_row(all["iac-opentofu"], &Target::macos(Arch::Aarch64))
            .into_iter()
            .next()
            .unwrap()?;
        assert_eq!(macos_plan.backend, BackendId::Homebrew);
        assert_eq!(
            macos_plan.operation,
            Operation::BrewInstall {
                cask: false,
                token: "opentofu".to_owned(),
            }
        );
        assert_eq!(macos_plan.operation.argv(), ["brew", "install", "opentofu"]);
        let linux_plan = plan_row(
            all["iac-opentofu-linux"],
            &Target::linux(Arch::X86_64, DistroFamily::Debian),
        )
        .into_iter()
        .next()
        .unwrap()?;
        assert_eq!(linux_plan.backend, BackendId::Mise);
        assert_eq!(
            linux_plan.operation,
            Operation::MiseInstall {
                tool: "opentofu".to_owned(),
                version: None,
            }
        );
        Ok(())
    }

    #[test]
    fn plan_row_degrades_planner_refusals_to_err_values() {
        let bundles = bundles();
        let all = index(&bundles);
        let linux = Target::linux(Arch::X86_64, DistroFamily::Debian);
        let cask_on_linux = plan_row(all["containers-orbstack"], &linux);
        assert_eq!(cask_on_linux.len(), 1);
        assert!(
            matches!(
                cask_on_linux[0],
                Err(toride_apps::Error::UnsupportedMethod { .. })
            ),
            "{:?}",
            cask_on_linux[0]
        );
        let wrong_family = plan_row(
            all["ruby-php-go-composer-debian"],
            &Target::linux(Arch::X86_64, DistroFamily::Fedora),
        );
        assert!(matches!(
            wrong_family[0],
            Err(toride_apps::Error::UnsupportedMethod { .. })
        ));
    }

    #[test]
    fn plan_row_plans_only_the_install_steps() {
        let bundles = bundles();
        let all = index(&bundles);
        let macos = Target::macos(Arch::Aarch64);
        assert_eq!(plan_row(all["rust-sccache"], &macos).len(), 1);
        assert_eq!(plan_row(all["qol-direnv"], &macos).len(), 1);
        let linux = Target::linux(Arch::X86_64, DistroFamily::Debian);
        assert!(plan_row(all["vm-mise-linux"], &linux).is_empty());
        assert!(plan_row(all["ruby-php-go-bundler"], &macos).is_empty());
    }

    #[test]
    fn pending_and_refused_consent_block_the_consent_rows() {
        let bundles = bundles();
        let consent_rows: Vec<&Recommendation> = bundles
            .iter()
            .flat_map(|bundle| bundle.recommendations.iter())
            .filter(|rec| rec.license.kind.requires_consent())
            .collect();
        assert_eq!(
            consent_rows.len(),
            4,
            "orbstack, docker-desktop, terraform x2"
        );
        for rec in consent_rows {
            for consent in [Consent::Pending, Consent::Refused] {
                let error = require_consent(rec, consent).expect_err("gate must refuse");
                assert_eq!(error.recommendation, rec.id);
                assert_eq!(error.consent, consent);
                assert_eq!(error.license, rec.license);
                assert!(error.to_string().contains(rec.license.terms_url));
            }
            assert!(require_consent(rec, Consent::Accepted).is_ok());
        }
    }

    #[test]
    fn free_rows_pass_the_consent_gate_regardless_of_the_verdict() {
        for rec in bundles()
            .iter()
            .flat_map(|bundle| bundle.recommendations.iter())
            .filter(|rec| !rec.license.kind.requires_consent())
        {
            for consent in [Consent::Pending, Consent::Accepted, Consent::Refused] {
                assert!(
                    require_consent(rec, consent).is_ok(),
                    "{} refused with {consent:?}",
                    rec.id
                );
            }
        }
    }

    #[test]
    fn dry_run_plans_are_refused_by_the_backend_execution_guard() -> Result<(), Error> {
        let bundles = bundles();
        let all = index(&bundles);
        let macos = Target::macos(Arch::Aarch64);
        let plan = plan_row(all["containers-orbstack"], &macos)
            .into_iter()
            .next()
            .unwrap()?;
        let request = InstallRequest::new(&plan, &macos);
        ensure_install_allowed(&request)?;
        let dry_plan = plan.clone().dry_run(true);
        let dry = InstallRequest::new(&dry_plan, &macos);
        let error = ensure_install_allowed(&dry).expect_err("dry-run plans must be refused");
        assert!(matches!(error, Error::DryRun { .. }), "{error:?}");
        Ok(())
    }

    #[test]
    fn unelevated_distro_plans_are_refused_by_the_execution_guard() -> Result<(), Error> {
        let bundles = bundles();
        let all = index(&bundles);
        let debian = Target::linux(Arch::X86_64, DistroFamily::Debian);
        let plan = plan_row(all["ruby-php-go-composer-debian"], &debian)
            .into_iter()
            .next()
            .unwrap()?;
        assert!(plan.requires_elevation);
        let request = InstallRequest::new(&plan, &debian);
        let error = ensure_install_allowed(&request).expect_err("elevation must be granted");
        assert!(
            matches!(error, Error::ElevationRequired { .. }),
            "{error:?}"
        );
        Ok(())
    }

    #[test]
    fn record_ids_follow_the_declared_install_methods() {
        let bundles = bundles();
        let all = index(&bundles);
        assert_eq!(
            record_ids(install_spec(all["containers-orbstack"])),
            Some(NativeIds::Homebrew {
                token: "orbstack".to_owned(),
                cask: true,
            })
        );
        assert_eq!(
            record_ids(install_spec(all["iac-opentofu-linux"])),
            Some(NativeIds::Mise {
                tool: "opentofu".to_owned(),
            })
        );
        assert_eq!(
            record_ids(install_spec(all["rust-mold"])),
            Some(NativeIds::Cargo {
                crate_: "mold".to_owned(),
            })
        );
        assert_eq!(
            record_ids(install_spec(all["node-pnpm"])),
            Some(NativeIds::Npm {
                package: "pnpm".to_owned(),
            })
        );
        assert_eq!(
            record_ids(install_spec(all["python-pipx-linux"])),
            Some(NativeIds::Mise {
                tool: "pipx".to_owned(),
            })
        );
        assert_eq!(
            record_ids(install_spec(all["ruby-php-go-composer-debian"])),
            Some(NativeIds::Distro {
                package: "composer".to_owned(),
                family: DistroFamily::Debian,
            })
        );
    }

    #[test]
    fn executed_plans_record_into_the_manifest_and_round_trip()
    -> Result<(), Box<dyn std::error::Error>> {
        let bundles = bundles();
        let all = index(&bundles);
        let macos = Target::macos(Arch::Aarch64);
        let plan = plan_row(all["containers-orbstack"], &macos)
            .into_iter()
            .next()
            .unwrap()?;
        let record = install_record(
            plan.clone(),
            install_spec(all["containers-orbstack"]),
            Some("4.7.1".to_owned()),
        )
        .expect("brew installs record ids");
        assert_eq!(
            record.ids,
            NativeIds::Homebrew {
                token: "orbstack".to_owned(),
                cask: true,
            }
        );
        assert_eq!(record.version.as_deref(), Some("4.7.1"));
        assert_eq!(record.plan.as_ref(), Some(&plan));
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("apps-manifest.json");
        let path = path.to_str().expect("utf-8 temp path");
        let mut manifest = InstallManifest::at(path);
        let id = TorideId::slugify("orbstack");
        manifest.record(&id, record);
        manifest.save()?;
        let reloaded = InstallManifest::load(path)?;
        let saved = reloaded.get(&id).expect("record survives the round trip");
        assert_eq!(saved.plan.as_ref(), Some(&plan));
        assert_eq!(plan.app.as_str(), id.as_str());
        Ok(())
    }

    fn expand_under(root: PathBuf) -> impl Fn(&str) -> PathBuf {
        move |path| {
            root.join(
                path.strip_prefix("~/")
                    .expect("hint paths are home-relative"),
            )
        }
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("directory should be readable")
            .map(|entry| {
                entry
                    .expect("directory entry should be readable")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    #[test]
    fn apply_hint_writes_a_tilde_hint_under_the_temp_home_byte_for_byte()
    -> Result<(), Box<dyn std::error::Error>> {
        let home = tempfile::tempdir()?;
        std::fs::create_dir_all(home.path().join(".cargo"))?;
        let expected = home.path().join(".cargo/config.toml");

        let outcome = apply_hint_with(&SCCACHE_WRAPPER, expand_under(home.path().to_path_buf()))?;

        assert_eq!(
            outcome,
            HintResult::Written {
                path: expected.clone()
            }
        );
        assert_eq!(
            std::fs::read(&expected)?,
            SCCACHE_WRAPPER.content.as_bytes()
        );
        assert_eq!(entries(home.path()), [".cargo"]);
        assert_eq!(entries(&home.path().join(".cargo")), ["config.toml"]);
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn apply_hint_skips_an_existing_file_untouched_including_its_mode()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::tempdir()?;
        let target = home.path().join(".zshrc");
        std::fs::write(&target, b"# user's own rc\n")?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640))?;

        let outcome = apply_hint_with(&DIRENV_HOOK_ZSH, expand_under(home.path().to_path_buf()))?;

        assert_eq!(
            outcome,
            HintResult::SkippedExisting {
                path: target.clone()
            }
        );
        assert_eq!(std::fs::read(&target)?, b"# user's own rc\n");
        let mode = std::fs::metadata(&target)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        assert_eq!(entries(home.path()), [".zshrc"]);
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn apply_hint_skips_a_pre_existing_non_utf8_file_untouched()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::tempdir()?;
        let target = home.path().join(".zshrc");
        std::fs::write(&target, [0xFF, 0xFE])?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640))?;

        let outcome = apply_hint_with(&DIRENV_HOOK_ZSH, expand_under(home.path().to_path_buf()))?;

        assert_eq!(
            outcome,
            HintResult::SkippedExisting {
                path: target.clone()
            }
        );
        assert_eq!(std::fs::read(&target)?, [0xFF, 0xFE]);
        let mode = std::fs::metadata(&target)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        assert_eq!(entries(home.path()), [".zshrc"]);
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn apply_hint_refuses_to_replace_a_dangling_symlink_destination()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let home = tempfile::tempdir()?;
        let target = home.path().join(".zshrc");
        symlink("/nonexistent/editor-backup", &target)?;

        let outcome = apply_hint_with(&DIRENV_HOOK_ZSH, expand_under(home.path().to_path_buf()))?;

        assert_eq!(
            outcome,
            HintResult::SkippedExisting {
                path: target.clone()
            }
        );
        assert_eq!(
            std::fs::read_link(&target)?,
            std::path::Path::new("/nonexistent/editor-backup"),
            "the symlink itself must be left in place, not replaced by hint bytes"
        );
        Ok(())
    }

    #[test]
    fn apply_hint_errors_without_creating_any_directory_when_the_parent_is_missing()
    -> Result<(), Box<dyn std::error::Error>> {
        let home = tempfile::tempdir()?;

        let outcome = apply_hint_with(&SCCACHE_WRAPPER, expand_under(home.path().to_path_buf()));

        assert!(outcome.is_err(), "a missing parent directory must surface");
        assert!(
            entries(home.path()).is_empty(),
            "no file or directory may be created for the user"
        );
        Ok(())
    }

    #[test]
    fn hint_application_creates_destinations_exclusively() {
        let hints = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/setup_bundles/hints.rs"
        ));
        assert!(
            hints.contains("toride_fs::expand_tilde"),
            "~ expansion must route through toride-fs"
        );
        assert!(
            hints.contains(".create_new(true)"),
            "hint destinations must be created O_EXCL so an existing file can never be replaced"
        );
        for banned in [
            "with_lock",
            "fs::write",
            "create_dir_all",
            "append",
            ".truncate(true)",
        ] {
            assert!(
                !hints.contains(banned),
                "no overwrite/append path may exist in hint application: found {banned}"
            );
        }
    }

    #[test]
    fn filesystem_use_stays_confined_to_the_hints_submodule() {
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/setup_bundles.rs"));
        let non_test = source
            .split("#[cfg(test)]")
            .next()
            .expect("split yields a head");
        for banned in [
            "toride_fs",
            "with_lock",
            "OpenOptions",
            "fs::write",
            "write_all",
            "create_dir_all",
            "append",
        ] {
            assert!(
                !non_test.contains(banned),
                "filesystem use lives in the hints submodule; move it there or widen this \
                 tripwire consciously: found {banned}"
            );
        }
    }

    #[test]
    fn seeded_hints_carry_the_recorded_bytes_on_home_relative_paths() {
        let mut hints: Vec<(&str, &str, &str)> = bundles()
            .iter()
            .flat_map(|bundle| &bundle.recommendations)
            .flat_map(|rec| &rec.actions)
            .filter_map(|action| match action {
                InstallAction::Hint(hint) => Some((hint.id, hint.path, hint.content)),
                _ => None,
            })
            .collect();
        for (id, path, _) in &hints {
            assert!(
                path.starts_with("~/"),
                "{id} must target a home-relative path"
            );
        }
        hints.sort_unstable();
        hints.dedup();
        assert_eq!(
            hints,
            vec![
                ("direnv-hook", "~/.bashrc", "eval \"$(direnv hook bash)\""),
                ("direnv-hook", "~/.zshrc", "eval \"$(direnv hook zsh)\""),
                (
                    "sccache-cargo-wrapper",
                    "~/.cargo/config.toml",
                    "[build]\nrustc-wrapper = \"sccache\"\n"
                ),
            ]
        );
    }

    #[test]
    fn every_seeded_hint_skips_when_the_destination_exists() {
        for hint in bundles()
            .iter()
            .flat_map(|bundle| &bundle.recommendations)
            .flat_map(|rec| &rec.actions)
            .filter_map(|action| match action {
                InstallAction::Hint(hint) => Some(hint),
                _ => None,
            })
        {
            assert_eq!(hint.on_exists, OnExists::Skip, "{}", hint.id);
        }
    }

    /// compat-28: the typed Unit and Firewall steps must be expressible
    /// and serializable even though execution wiring is deferred, and
    /// planning must skip them rather than fail.
    #[test]
    fn unit_and_firewall_steps_are_typed_serializable_and_unplanned() {
        let rule = FirewallRule {
            port: 443,
            protocol: FirewallProtocol::Tcp,
            allow: true,
        };
        let unit = InstallAction::Unit {
            name: "toride-web.service",
            contents: "[Unit]\nDescription=toride web\n",
        };
        let firewall = InstallAction::Firewall { spec: rule.clone() };

        let serialized = serde_json::to_string(&unit).unwrap();
        assert!(
            serialized.contains("toride-web.service") && serialized.contains("Unit"),
            "the unit step must serialize its payload: {serialized}"
        );
        let serialized = serde_json::to_string(&firewall).unwrap();
        assert!(
            serialized.contains("\"port\":443") && serialized.contains("Firewall"),
            "the firewall step must serialize its payload: {serialized}"
        );
        let spec_json = serde_json::to_string(&rule).unwrap();
        assert_eq!(
            serde_json::from_str::<FirewallRule>(&spec_json).unwrap(),
            rule
        );

        let row = rec(
            "compat-28-probe",
            "probe",
            "synthetic row exercising the deferred steps",
            license(
                LicenseKind::Free,
                Some("MIT"),
                "MIT; commercial use unrestricted.",
                "https://example.com/",
                "2026-10-21",
            ),
            Condition::All(Vec::new()),
            &[],
            vec![unit, firewall],
            None,
        );
        let target = Target {
            os: Os::Linux,
            arch: Arch::X86_64,
            distro: None,
        };
        assert!(
            plan_row(&row, &target).is_empty(),
            "Unit and Firewall steps have no planner shape yet"
        );
    }
}
