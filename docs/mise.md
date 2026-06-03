# Rust Library Plan: `toride-mise` Typed Mise Wrapper

## 0. Product Goal

Build `toride-mise`, a Rust workspace crate that lets Toride and other Rust applications manage developer tools and language runtimes through `mise`.

This is not a CLI app.

This is not a reimplementation of `nvm`, `gvm`, `pyenv`, `rustup`, `rbenv`, `asdf`, or mise.

This is a typed Rust integration layer over mise that gives Rust apps a clean API for:

* discovering supported tools
* listing remote versions
* installing versions
* uninstalling versions
* setting project/global versions
* reading current active versions
* resolving executable paths
* generating runtime environments
* running commands inside a tool environment
* checking missing/outdated/prunable tools
* managing lockfiles
* managing mise config safely
* doing diagnostics
* supporting many languages dynamically

The core philosophy:

> Use mise as the proven engine. Use Rust to provide a safe, typed, ergonomic library API around it.

### 0.1 Repository Placement

This crate belongs in the existing Toride workspace:

```text
crates/toride-mise/
  Cargo.toml
  src/
```

The root workspace manifest should include it through the existing `members = ["crates/*", "crates/toride-ssh/crates/*"]` pattern.

Follow existing workspace conventions:

* crate name: `toride-mise`
* library name: `toride_mise`
* edition: `2024`
* lints inherited from workspace
* shared dependency versions in root `[workspace.dependencies]`
* no standalone root `src/` crate layout
* command execution delegated to `toride-runner` (`AsyncRunner`, `TokioRunner`, `FakeRunner`, streaming support already implemented behind `tokio-runner` and `stream` features)

Current repo realities to account for:

* Rust code is a Cargo workspace, not a single package.
* `web/` is an Astro/npm project with `package-lock.json`.
* `web/package.json` requires Node `>=22.12.0`, so Node helpers should support project bootstrap and verification flows without assuming a committed mise config already exists.
* There is currently no repo-level mise config; `toride-mise` must not assume one during tests or examples.

## 1. Why Mise Is the Right Engine

Mise already solves the hard parts:

* language version management
* tool installation
* version discovery
* project-local config
* global config
* environment activation
* shims / PATH management
* lockfile support
* backend abstraction
* core language plugins
* third-party backends
* registry aliases
* plugin support
* install cache
* pruning unused versions
* detecting outdated versions
* running commands inside a selected runtime

This means `toride-mise` should avoid home-cooked installers.

Bad approach:

```text
toride-mise downloads Node itself
toride-mise installs Go itself
toride-mise compiles Ruby itself
toride-mise shells into nvm/gvm/pyenv manually
toride-mise parses every language's upstream release feed
```

Good approach:

```text
toride-mise asks mise what versions exist
toride-mise asks mise to install the requested version
toride-mise reads mise JSON output
toride-mise writes/edits mise.toml safely
toride-mise exposes a typed Rust API
```

## 2. Hard Decision: Wrapper, Not Vendored Internal API

### 2.1 Do not vendor mise internals

Vendoring mise source directly sounds attractive because mise is Rust, but it is the wrong default.

Problems:

* mise is primarily an application, not a stable public library API
* internal modules can change without semver guarantees for external users
* you inherit mise's full dependency graph
* you need to keep rebasing patches
* private assumptions will break between releases
* async/runtime/globals/config paths may not be designed for embedding
* the crate becomes tightly coupled to mise internals
* upstream security fixes require painful merges
* build times and binary size may explode
* your public API accidentally mirrors mise internals

### 2.2 Use the mise binary as an engine

This is the better architecture:

```text
Rust app / Toride app
  |
toride-mise
  |
mise command adapter
  |
mise binary
  |
mise backends / registry / installs / config
```

This is not unstructured shelling-out if done properly.

The primary runner uses `toride-runner`'s `TokioRunner` (backed by `tokio::process::Command`), not the blocking standard-library process API.

Process execution is delegated to the shared `toride-runner` crate which already provides:

* `AsyncRunner` trait — async-first runner contract with `run` and `run_checked`
* `TokioRunner` — real async runner using `tokio::process::Command` with timeouts, stdin piping, env/cwd, and process kill on timeout
* `FakeRunner` — test double implementing both sync `Runner` and async `AsyncRunner` traits, with strict mode and response queuing
* `AsyncStreamingRunner` — streaming extension emitting `CommandEvent` variants (`Started`, `StdoutLine`, `StderrLine`, `StdoutChunk`, `StderrChunk`, `Exited`) to an `CommandEventSink`
* `CommandSpec` — typed command specification (program, args, stdin, timeout, env, cwd, redact)
* `CommandOutput` — structured result (stdout, stderr, exit_code, success)
* `OutputMode` — capture/stream/inherit selection
* `Error` — structured errors (`CommandFailed`, `CommandTimeout`, `SpawnFailed`, `BinaryNotFound`, etc.)

`toride-mise` must not reimplement any of this. It adds a thin adapter that translates mise-specific request types into `CommandSpec` and maps `toride_runner::Error` into `MiseError`.

Additional dependencies for mise-specific logic:

* `serde_json` for JSON output parsing
* `camino` for UTF-8 paths
* `fs-err` for better filesystem errors
* `semver` for version parsing
* `tempfile` for tests
* `thiserror` for library errors
* optional `miette` for richer app-facing diagnostics
* `tracing` for observability

The wrapper must be centralized in one adapter layer so the rest of the crate never manually constructs shell commands.

## 3. Crate Name

Use:

```text
toride-mise
```

Reason:

* matches the workspace naming pattern
* makes ownership clear
* avoids occupying a generic crates.io namespace prematurely
* can still be published later as a normal library crate

## 4. Target Users

This crate is for Rust applications that need to manage toolchains dynamically.

Examples:

* IDEs
* desktop apps
* dev environment managers
* coding agent platforms
* server automation tools
* project bootstrap tools
* CI preparation tools
* local development dashboards
* language runtime selectors
* monorepo tooling
* self-hosted deployment helpers
* Toride's own app/runtime management flows

Not for:

* replacing mise CLI
* writing another package manager
* managing system packages like apt/pacman/brew
* installing OS libraries required to compile Ruby/Python
* being a full shell activation framework

## 5. High-Level Capabilities

The crate should expose these major capability areas:

```text
Mise discovery
Mise installation/bootstrap
Tool registry
Remote version listing
Installed version listing
Active version resolution
Tool install
Tool uninstall
Tool use / pin / unuse
Environment generation
Command execution inside environments
Path resolution
Outdated checks
Upgrade planning
Pruning
Cache clearing
Lockfile management
Config read/write
Settings read/write
Diagnostics
Language-specific convenience helpers
```

## 6. Core API Shape

### 6.1 Main client

```rust
pub struct Mise {
    runner: Arc<dyn AsyncRunner>,  // from toride-runner
    binary: MiseBinary,
    cwd: Option<Utf8PathBuf>,
    env: BTreeMap<String, String>,
    mode: MiseMode,
}
```

The `runner` field holds a `toride_runner::AsyncRunner` trait object. In production this is `TokioRunner`; in tests it is `FakeRunner`. All command execution flows through this runner — the crate never calls `tokio::process::Command` directly.

### 6.2 Builder

```rust
let mise = Mise::builder()
    .runner(Arc::new(TokioRunner))  // or Arc::new(FakeRunner::new()) in tests
    .binary("mise")
    .cwd("/path/to/project")
    .no_config(false)
    .no_env(false)
    .no_hooks(false)
    .locked(false)
    .build()?;
```

If no runner is provided, the builder defaults to `TokioRunner`.

### 6.3 Async-first design

Start async-first.

This crate will be consumed by async applications and potentially by Toride's TUI/app runtime. Blocking process calls in the primary API are an avoidable footgun because they can freeze event loops, UI rendering, and background task scheduling.

```rust
mise.install(["node@22"]).await?;
mise.use_tool(UseRequest::global("node@22")).await?;
let env = mise.env_json(["node@22"]).await?;
```

If a blocking facade is needed later, add it explicitly as a thin compatibility layer:

```rust
features = ["blocking"]
```

Do not make blocking execution the default architecture.

## 7. Command Adapter Layer

All command execution is delegated to `toride-runner` (`crates/toride-runner`), which already provides the async runner infrastructure this crate needs. `toride-mise` adds only a thin adapter module that translates mise-specific requests into `toride-runner` types:

```text
src/command/
  mod.rs          — re-exports and adapter wiring
  adapter.rs      — builds CommandSpecs from MiseRequest types
  mapping.rs      — maps toride_runner::Error → MiseError
```

### 7.1 Runner trait — provided by toride-runner

`toride-runner` already defines the async runner contract. `toride-mise` does not define its own trait.

```rust
// From toride_runner (feature "tokio-runner"):
#[async_trait]
pub trait AsyncRunner: Send + Sync {
    async fn run(&self, spec: &CommandSpec) -> Result<CommandOutput>;
    async fn run_checked(&self, spec: &CommandSpec) -> Result<CommandOutput>; // default impl
}
```

`toride-mise` holds an `Arc<dyn AsyncRunner>` internally. The `Mise` client struct injects this runner, and all command execution flows through it:

```rust
pub struct Mise {
    runner: Arc<dyn AsyncRunner>,
    binary: MiseBinary,
    cwd: Option<Utf8PathBuf>,
    env: BTreeMap<String, String>,
    mode: MiseMode,
}
```

### 7.2 Real runner — TokioRunner from toride-runner

`toride-runner` provides `TokioRunner` behind the `tokio-runner` feature. It handles all responsibilities that were previously planned as mise-internal:

* set cwd
* set env
* pass args without shell interpolation (via `CommandSpec` builder)
* capture stdout and stderr
* capture exit code
* enforce timeouts with `tokio::time::timeout` (default 60s)
* redact secrets in display output (via `CommandSpec::redact(true)`)
* normalize UTF-8 output
* kill child process on timeout
* structured errors with command context (`Error::CommandFailed`, `Error::CommandTimeout`, `Error::SpawnFailed`)
* never block an async runtime thread

`toride-mise` uses `TokioRunner` in production and `FakeRunner` in tests. The adapter layer only builds `CommandSpec` instances and interprets `CommandOutput`.

### 7.3 Fake runner — FakeRunner from toride-runner

`toride-runner` provides `FakeRunner` behind the `fake` feature. It implements both sync `Runner` and async `AsyncRunner` traits.

```rust
// From toride_runner (feature "fake"):
pub struct FakeRunner { /* internal state */ }

impl Runner for FakeRunner { ... }           // always
impl AsyncRunner for FakeRunner { ... }      // behind "tokio-runner"
```

Capabilities:

* lenient mode: unmatched calls return empty success
* strict mode: error on unmatched calls
* response queuing: `push_response()` / `push_result()` for FIFO responses
* exact-match responses: `respond(spec, output)` / `respond_err(spec, error)`
* call recording: `calls()` returns snapshot of all recorded `CommandSpec`s
* assertions: `assert_called_with()`, `assert_no_unmatched_calls()`

This is critical because we do not want every unit test to download tools.

### 7.4 Streaming — AsyncStreamingRunner from toride-runner

`toride-runner` provides streaming execution behind the `stream` feature:

```rust
// From toride_runner (feature "stream"):
#[async_trait]
pub trait AsyncStreamingRunner: AsyncRunner {
    async fn run_streaming(
        &self,
        spec: &CommandSpec,
        sink: &mut dyn CommandEventSink,
    ) -> Result<CommandOutput>;
}
```

Events:

```rust
pub enum CommandEvent {
    Started { program: String, args: Vec<String> },
    StdoutChunk(Vec<u8>),
    StderrChunk(Vec<u8>),
    StdoutLine(String),   // newline-stripped
    StderrLine(String),   // newline-stripped
    Exited { exit_code: Option<i32> },
}
```

`toride-mise` uses streaming for long-running operations like `mise install` (progress reporting) and `mise exec` (live output forwarding). The sink trait provides backpressure and abort-on-error semantics.

### 7.5 Adapter layer responsibilities

The `src/command/` module in `toride-mise` is intentionally thin. It does NOT reimplement process execution. Its only jobs are:

1. **Build `CommandSpec`**: translate mise request types (`InstallRequest`, `UseRequest`, `ListToolsRequest`, etc.) into `CommandSpec` instances with correct program (`"mise"`), args, env, cwd, and timeout.
2. **Map errors**: convert `toride_runner::Error` into `MiseError` with mise-specific context.
3. **Parse output**: extract structured data from `CommandOutput::stdout` (JSON parsing, line splitting, etc.).
4. **Wire runner**: construct `Mise` client with `TokioRunner` by default, or `FakeRunner` in test configs.

## 8. Error Model

Create structured errors.

```rust
pub enum MiseError {
    BinaryNotFound,
    UnsupportedVersion { version_output: String },
    CommandFailed {
        command: String,
        exit_code: Option<i32>,
        stdout: String,
        stderr: String,
    },
    JsonParse {
        command: String,
        source: serde_json::Error,
        stdout: String,
    },
    Io(std::io::Error),
    Config(ConfigError),
    Timeout,
}
```

Expose clean user-facing errors:

```rust
pub enum ToolInstallError {
    ToolNotFound,
    VersionNotFound,
    NetworkFailed,
    ChecksumFailed,
    DependencyMissing,
    PermissionDenied,
    MiseFailed(MiseError),
}
```

Do not collapse everything into strings.

## 9. Main Modules

Recommended structure:

```text
crates/toride-mise/
  Cargo.toml
  fixtures/
  src/
  lib.rs

  client.rs
  builder.rs
  error.rs

  command/
    mod.rs
    adapter.rs        — builds CommandSpecs from MiseRequest types
    mapping.rs        — maps toride_runner::Error → MiseError

  binary/
    mod.rs
    discovery.rs
    install.rs
    version.rs

  tool/
    mod.rs
    spec.rs
    registry.rs
    remote.rs
    installed.rs
    active.rs
    install.rs
    uninstall.rs
    upgrade.rs
    prune.rs

  config/
    mod.rs
    model.rs
    read.rs
    write.rs
    merge.rs
    path.rs

  env/
    mod.rs
    generated.rs
    activation.rs
    shell.rs

  exec/
    mod.rs
    request.rs
    result.rs

  lockfile/
    mod.rs
    model.rs
    update.rs
    verify.rs

  diagnostics/
    mod.rs
    doctor.rs
    path.rs
    checks.rs

  languages/
    mod.rs
    node.rs
    bun.rs
    deno.rs
    go.rs
    python.rs
    rust.rs
    ruby.rs
    java.rs
    generic.rs

  serde/
    mod.rs
    json_outputs.rs

  tests/
```

## 10. Tool Spec Model

The entire crate should revolve around a normalized tool spec.

```rust
pub struct ToolSpec {
    pub raw: String,
    pub backend: Option<String>,
    pub name: String,
    pub version: Option<VersionRequest>,
    pub options: BTreeMap<String, ToolOptionValue>,
}

pub enum ToolOptionValue {
    Bool(bool),
    Integer(i64),
    String(String),
    StringList(Vec<String>),
    Raw(String),
}
```

`raw` is required.

Parsing is for validation, display, and typed helpers. Rendering must be lossless and should use `raw` unless the caller intentionally constructed a new `ToolSpec` through the builder.

Examples:

```text
node@22
bun@latest
deno@2
go@1.23
python@3.12
rust@stable
ruby@3.3
java@temurin-21
npm:prettier@latest
cargo:ripgrep@latest
go:github.com/jesseduffield/lazygit@latest
ubi:BurntSushi/ripgrep[exe=rg]
```

### 10.1 VersionRequest

```rust
pub enum VersionRequest {
    Latest,
    Prefix(String),
    Exact(String),
    Alias(String),
    Channel(String),
}
```

Do not force everything into `semver::Version`.

Many tool versions are not pure semver:

* `lts`
* `latest`
* `stable`
* `beta`
* `temurin-21`
* `prefix:1.20`
* `anaconda`
* `3.12t`
* `graalvm-21`
* `nightly`
* `1.82`

Do not assume the parser understands every future mise backend. Unknown-but-valid-looking specs should be preserved and passed through when the caller opts into permissive mode.

## 11. Registry Support

Expose registry APIs:

```rust
mise.registry().await?;
mise.registry_tool("poetry").await?;
mise.registry_by_backend("aqua").await?;
mise.search_registry(SearchRequest::new("jq")).await?;
```

Model:

```rust
pub struct RegistryTool {
    pub name: String,
    pub full_name: String,
    pub backend: Option<String>,
    pub security: Option<RegistrySecurity>,
}
```

Use `mise registry --json`.

Support `--security` as optional because it can be slower.

Use `mise search` for fuzzy registry lookup. It is text/table output today, so expose raw output and parse conservatively.

## 12. Version Discovery

Expose:

```rust
mise.list_remote("node").await?;
mise.list_remote_prefix("node", "22").await?;
mise.list_remote_json("github:cli/cli").await?;
mise.latest("node@22").await?;
mise.latest_installed("node").await?;
```

Request model:

```rust
pub struct ListRemoteRequest {
    pub tool: ToolName,
    pub prefix: Option<String>,
    pub all: bool,
    pub prerelease: bool,
    pub minimum_release_age: Option<String>,
    pub strict_metadata: bool,
    pub no_versions_host: bool,
}
```

Important features to support:

* JSON output
* prereleases
* minimum release age
* strict metadata
* prefix search
* no versions host
* cache caveat
* all tools

Use this for dynamic UI dropdowns.

## 13. Installed / Active Tool Listing

Expose:

```rust
mise.list().await?;
mise.list_installed().await?;
mise.list_current().await?;
mise.list_missing().await?;
mise.list_prunable().await?;
mise.list_outdated().await?;
mise.tool_info("node").await?;
```

Request model:

```rust
pub struct ListToolsRequest {
    pub installed_only: bool,
    pub current_only: bool,
    pub global_only: bool,
    pub local_only: bool,
    pub missing_only: bool,
    pub prunable_only: bool,
    pub outdated: bool,
    pub all_sources: bool,
    pub prefix: Option<String>,
}
```

Use `mise ls --json`.

Use `mise tool --json <tool>` for single-tool backend/requested/installed/active/config-source detail.

Return:

```rust
pub struct ToolStatus {
    pub tool: String,
    pub version: String,
    pub requested: Option<String>,
    pub installed: bool,
    pub active: bool,
    pub missing: bool,
    pub source: Option<Utf8PathBuf>,
    pub outdated: Option<bool>,
}
```

## 14. Install API

Expose:

```rust
mise.install(["node@22", "python@3.12"]).await?;
mise.install_into("node@22", "/opt/toride/tools/node-22").await?;
mise.link(LinkRequest::new("node@22", "/opt/toride/tools/node-22")).await?;
mise.reshim().await?;
```

Request:

```rust
pub struct InstallRequest {
    pub tools: Vec<ToolSpec>,
    pub jobs: Option<usize>,
    pub force: bool,
    pub verbose: bool,
    pub raw: bool,
    pub shared: Option<Utf8PathBuf>,
    pub system: bool,
    pub locked: bool,
    pub yes: bool,
    pub dry_run: bool,
    pub dry_run_code: bool,
    pub minimum_release_age: Option<String>,
}
```

Support:

* install all tools from current config
* install selected tools
* install into explicit app-managed directories
* link externally managed installs only when explicitly requested
* install with jobs
* install in locked mode
* install with force
* install to explicit shared/system locations only when the caller opts in
* install dry-run and dry-run-code previews
* install with current working directory

Important behavior:

* `mise install` installs tools from config if no tool is supplied.
* `mise use` also installs if the tool is not already installed.
* The crate should expose both behaviors separately.

## 15. Uninstall API

Expose:

```rust
mise.uninstall(["node@20.0.0"]).await?;
```

Request:

```rust
pub struct UninstallRequest {
    pub tools: Vec<ToolSpec>,
    pub all: bool,
    pub dry_run: bool,
    pub dry_run_code: bool,
}
```

This removes installed tool versions.

It should not necessarily remove references from `mise.toml`.

That is a different operation: `unuse`.

## 16. Use / Pin / Unuse API

### 16.1 Use

Expose:

```rust
mise.use_tool(UseRequest::local("node@22")).await?;
mise.use_tool(UseRequest::global("python@3.12")).await?;
```

Request:

```rust
pub struct UseRequest {
    pub tools: Vec<ToolSpec>,
    pub scope: UseScope,
    pub pin: bool,
    pub fuzzy: bool,
    pub force: bool,
    pub jobs: Option<usize>,
    pub path: Option<Utf8PathBuf>,
    pub env_name: Option<String>,
    pub dry_run: bool,
    pub dry_run_code: bool,
    pub raw: bool,
    pub minimum_release_age: Option<String>,
}
```

Scope:

```rust
pub enum UseScope {
    Local,
    Global,
    Path(Utf8PathBuf),
    Env(String),
}
```

Support flags:

* global config
* path-specific config
* env-specific config
* pin exact version
* force reinstall
* fuzzy versions
* multiple tools in one call
* dry-run and dry-run-code previews
* minimum release age

### 16.2 Pin

Pin should be a first-class helper:

```rust
mise.pin(["node@lts", "npm@latest"]).await?;
```

Internally uses `mise use --pin`.

Purpose:

* resolve aliases like `latest`, `lts`, etc.
* write exact versions into config
* improve reproducibility

### 16.3 Unuse

Expose:

```rust
mise.unuse(["node@22"]).await?;
mise.unuse_global(["node@22"]).await?;
```

This removes tool entries from config.

Request:

```rust
pub struct UnuseRequest {
    pub tools: Vec<ToolSpec>,
    pub scope: UseScope,
    pub no_prune: bool,
}
```

Important mise behavior:

* `mise unuse` also prunes the installed version if no other config uses it.
* Expose `no_prune` because config removal and install deletion are different risk levels.
* Prefer exact installed specs where possible.
* If the wrapper accepts an unversioned tool name, resolve it explicitly before invoking mise or return a clear ambiguity error.

Important distinction:

```text
uninstall = remove installed files
unuse = remove config reference, and may prune unless --no-prune is set
```

Both are needed.

## 17. Environment API

This is one of the most important parts for library consumers.

Expose:

```rust
let env = mise.env(EnvRequest::for_tools(["node@22"])).await?;
```

Use `mise env --json` or `mise env --json-extended`.

Return:

```rust
pub struct MiseEnv {
    pub vars: BTreeMap<String, String>,
    pub extended: Option<Vec<EnvEntry>>,
}
```

Extended:

```rust
pub struct EnvEntry {
    pub key: String,
    pub value: String,
    pub source: Option<String>,
    pub tool: Option<String>,
}
```

Support:

* JSON output
* JSON extended
* dotenv output
* shell-specific output
* redacted output
* values-only output

### 17.1 Use cases

Rust app wants to spawn a Node script with Node 22:

```rust
let env = mise.env_for(["node@22"]).await?;
tokio::process::Command::new("node")
    .envs(env.vars)
    .arg("script.js")
    .status()
    .await?;
```

But preferably, use `mise exec`.

## 18. Exec API

Expose:

```rust
mise.exec()
    .tool("node@22")
    .arg("node")
    .arg("--version")
    .run()
    .await?;
```

Request:

```rust
pub struct ExecRequest {
    pub tools: Vec<ToolSpec>,
    pub command: Vec<String>,
    pub cwd: Option<Utf8PathBuf>,
    pub jobs: Option<usize>,
    pub fresh_env: bool,
    pub no_deps: bool,
    pub sandbox: Option<SandboxPolicy>,
}
```

Sandbox support should exist because mise has experimental flags for denying/allowing reads, writes, network, and env inheritance.

```rust
pub struct SandboxPolicy {
    pub deny_all: bool,
    pub deny_read: bool,
    pub deny_write: bool,
    pub deny_net: bool,
    pub deny_env: bool,
    pub allow_read: Vec<Utf8PathBuf>,
    pub allow_write: Vec<Utf8PathBuf>,
    pub allow_net: Vec<String>,
    pub allow_env: Vec<String>,
}
```

Caveat:

* mark sandbox APIs as experimental
* OS behavior differs
* Linux/macOS support may differ depending on mise behavior

## 19. Path Resolution API

Expose:

```rust
mise.where_tool("node@22").await?;
mise.which("node").await?;
mise.which_with_tool("npm", "node@22").await?;
mise.which_version("node").await?;
mise.which_plugin("node").await?;
```

Types:

```rust
pub struct ToolInstallPath {
    pub path: Utf8PathBuf,
}

pub struct BinResolution {
    pub bin: String,
    pub path: Option<Utf8PathBuf>,
    pub version: Option<String>,
    pub plugin: Option<String>,
}
```

Important commands:

* `mise where <tool@version>`
* `mise which <bin>`
* `mise which <bin> --tool=<tool@version>`
* `mise which <bin> --version`
* `mise which <bin> --plugin`

This gives app UIs a way to show exactly which binary will run.

## 20. Config API

### 20.1 Read config

Expose:

```rust
mise.config_ls().await?;
mise.config_get("tools.node").await?;
```

Support:

* config hierarchy
* local/global/project config
* environment configs
* source-aware output where mise provides it
* current mise precedence rules without hard-coding them in `toride-mise`

Do not maintain a hand-written authoritative config path list in this crate.

Use `mise config ls`, `mise config get`, and source metadata first. Config path discovery should ask mise where possible because mise's supported paths and precedence rules evolve.

### 20.2 Write config

Expose:

```rust
mise.config_set("tools.node", "22").await?;
mise.config_set_typed("settings.jobs", 4).await?;
mise.config_set_list("settings.disable_tools", ["node", "rust"]).await?;
```

Use `mise config set` when possible.

Do not home-cook config mutation unless needed.

If direct TOML editing is needed:

* use `toml_edit`
* preserve formatting where possible
* only edit known keys
* atomic write through temp file + rename
* never silently reorder whole file
* validate with `mise config ls` after write

### 20.3 Strongly typed config model

```rust
pub struct MiseToml {
    pub tools: BTreeMap<String, ToolConfig>,
    pub env: BTreeMap<String, String>,
    pub settings: MiseSettings,
    pub tasks: BTreeMap<String, TaskConfig>,
}
```

But keep raw TOML access available.

Mise config evolves. The crate should not reject unknown keys.

Use:

```rust
#[serde(flatten)]
pub extra: BTreeMap<String, toml::Value>
```

## 21. Settings API

Expose:

```rust
mise.settings().await?;
mise.settings_all().await?;
mise.settings_local().await?;
mise.settings_get("python").await?;
mise.settings_set("jobs", "8").await?;
mise.settings_add("disable_tools", "node").await?;
mise.settings_unset("jobs").await?;
```

Support:

* JSON output
* TOML output
* extended source output
* local/global distinction

Settings matter for:

* lockfiles
* jobs
* idiomatic version files
* tool disabling
* language-specific behavior
* Ruby compile mode
* Python options
* Java shorthand vendor
* Rust cargo/rustup isolation behavior

## 22. Lockfile API

Expose:

```rust
mise.lock().await?;
mise.lock_tool("node").await?;
mise.lock_platforms(["linux-x64", "macos-arm64"]).await?;
mise.lock_dry_run().await?;
```

Request:

```rust
pub struct LockRequest {
    pub tools: Vec<String>,
    pub global: bool,
    pub local_lock: bool,
    pub platforms: Vec<String>,
    pub jobs: Option<usize>,
    pub dry_run: bool,
    pub minimum_release_age: Option<String>,
}
```

Also expose:

```rust
mise.install_locked().await?;
```

This must use per-command `--locked` or an isolated command environment such as `MISE_LOCKED=1`.

Do not mutate global mise settings inside this helper. `settings.locked=true` is global in scope and can affect unrelated global tools. Only the explicit settings API may change settings.

Purpose:

* reproducible installs
* no surprise upstream resolution
* better CI behavior
* safer deployment environments
* fewer API calls to GitHub/aqua/etc.

## 23. Outdated / Upgrade API

### 23.1 Outdated

Expose:

```rust
mise.outdated().await?;
mise.outdated_tool("node").await?;
mise.outdated_local().await?;
mise.outdated_inactive().await?;
```

Return:

```rust
pub struct OutdatedTool {
    pub plugin: String,
    pub requested: String,
    pub current: String,
    pub latest: String,
}
```

Support:

* JSON output
* bump mode
* inactive mode
* local-only mode

### 23.2 Upgrade

Expose:

```rust
mise.upgrade().await?;
mise.upgrade_tools(["node@22", "python@3.12"]).await?;
mise.upgrade_bump().await?;
mise.upgrade_dry_run().await?;
```

Request:

```rust
pub struct UpgradeRequest {
    pub tools: Vec<ToolSpec>,
    pub bump: bool,
    pub dry_run: bool,
    pub dry_run_code: bool,
    pub inactive: bool,
    pub local_only: bool,
    pub raw: bool,
    pub exclude: Vec<String>,
    pub jobs: Option<usize>,
    pub minimum_release_age: Option<String>,
}
```

Important behavior:

* default upgrade should respect the range in `mise.toml`
* `--bump` can update the config to a newer major/minor range
* dry-run must be exposed for safe app previews

## 24. Prune API

Expose:

```rust
mise.prune_dry_run().await?;
mise.prune_tools().await?;
mise.prune_configs().await?;
```

Request:

```rust
pub struct PruneRequest {
    pub tools: Vec<String>,
    pub dry_run: bool,
    pub dry_run_code: bool,
    pub only_tools: bool,
    pub only_configs: bool,
}
```

Return dry-run deletion candidates:

```rust
pub struct PrunePlan {
    pub paths: Vec<Utf8PathBuf>,
}
```

This is needed for cleanup UIs.

## 25. Cache API

Expose:

```rust
mise.cache_clear().await?;
mise.cache_clear_tools(["node", "python"]).await?;
mise.cache_path().await?;
mise.cache_prune(CachePruneRequest::new()).await?;
mise.cache_prune(CachePruneRequest::dry_run(["node"])).await?;
```

Request:

```rust
pub struct CachePruneRequest {
    pub tools: Vec<String>,
    pub dry_run: bool,
    pub verbose: bool,
}
```

Purpose:

* refresh version listings
* recover from bad downloads
* force new upstream metadata
* cleanup disk usage

## 26. Backends / Plugins / Aliases / Tasks / Bin Paths

Complete integration also needs typed wrappers for the mise surfaces that support tool management but do not fit a single language helper.

Expose:

```rust
mise.backends().await?;
mise.bin_paths(BinPathsRequest::new()).await?;

mise.plugins().list().await?;
mise.plugins().list_remote().await?;
mise.plugins().install(PluginInstallRequest::new("node")).await?;
mise.plugins().link(PluginLinkRequest::new("custom", "/path/to/plugin")).await?;
mise.plugins().uninstall(["node"]).await?;
mise.plugins().update(["node"]).await?;

mise.tool_aliases().list("node").await?;
mise.tool_aliases().get("node", "lts").await?;
mise.tool_aliases().set("node", "lts", "22").await?;
mise.tool_aliases().unset("node", "lts").await?;

mise.tasks().list(TaskListRequest::new()).await?;
mise.tasks().add(TaskAddRequest::new("build").run(["cargo", "build"])).await?;
mise.tasks().deps(TaskDepsRequest::new(["build"])).await?;
mise.tasks().edit_path("build").await?;
mise.tasks().info("build").await?;
mise.tasks().run(TaskRunRequest::new("build")).await?;
mise.tasks().validate(TaskValidateRequest::new()).await?;
```

Rules:

* Parse JSON where the command supports JSON.
* Preserve raw output for commands that are text-only.
* Treat task execution like `mise exec`: explicit command result, timeout, output mode, and cancellation behavior.
* Do not invoke editor-driven commands directly; expose path/query forms such as `mise tasks edit --path`.
* Plugin install/link/update/uninstall are destructive or networked operations and need dry-run or plan-style APIs where mise supports them.

## 27. Doctor / Diagnostics API

Expose:

```rust
mise.doctor().await?;
mise.doctor_path().await?;
```

Return:

```rust
pub struct DoctorReport {
    pub ok: bool,
    pub raw_output: String,
    pub warnings: Vec<Diagnostic>,
    pub errors: Vec<Diagnostic>,
}
```

Use `mise doctor --json` as the primary path.

Keep raw-text fallback for older mise versions or unexpected JSON failures, but do not prefer text parsing when structured output exists.

Diagnostics should include wrapper-side checks too:

* mise binary exists
* mise version supported
* PATH contains mise
* project config found
* config trusted or not
* lockfile status
* missing tools
* outdated tools
* invalid config
* tool executable resolution
* shell activation presence
* OS dependencies warning for Ruby/Python compile flows
* network/proxy env availability
* permissions on mise data/cache dirs

## 28. Trust / Security API

Mise has trust/untrust concepts around config.

Expose:

```rust
mise.trust(path).await?;
mise.untrust(path).await?;
```

Also provide safe defaults:

```rust
pub struct SecurityPolicy {
    pub allow_hooks: bool,
    pub allow_env_from_config: bool,
    pub locked: bool,
    pub require_trusted_config: bool,
    pub minimum_release_age: Option<String>,
}
```

`locked` maps to command-scoped behavior. It must not write `settings.locked=true` unless the caller uses the settings API directly.

For hostile/untrusted project directories, allow:

```rust
mise.no_config()
mise.no_env()
mise.no_hooks()
mise.locked()
```

This is important for AI agents opening random repos.

Default wrapper policy should be conservative for automation:

```text
local trusted project mode:
  config/env/hooks allowed

untrusted repo mode:
  --no-hooks
  optionally --no-env
  maybe require explicit trust before install
```

## 29. Language-Specific Convenience Layer

The crate should have generic APIs first, then small typed helpers.

### 29.1 Node.js

Capabilities:

* install Node version
* use global/local Node
* pin Node and npm
* list remote Node versions
* resolve `node`, `npm`, `npx`, `corepack`
* support npm as separate tool when pinned

API:

```rust
mise.node().install("22").await?;
mise.node().use_global("22").await?;
mise.node().pin_lts_with_npm_latest().await?;
```

Important behavior:

* Node can be managed like nvm/fnm/volta replacement.
* npm can be pinned separately.
* Do not run `npm install -g` from this crate unless using `npm:` backend intentionally.

### 29.2 Bun

Capabilities:

* install Bun
* list Bun versions
* use Bun globally/locally
* resolve `bun`

Important caveat:

* Do not use `bun upgrade` behind mise's back.
* All upgrades should go through mise.

### 29.3 Deno

Capabilities:

* install Deno
* list Deno versions
* use Deno globally/locally
* resolve `deno`

Important caveat:

* Do not use `deno upgrade` behind mise's back.
* All upgrades should go through mise.

### 29.4 Go

Capabilities:

* install Go version
* support `prefix:` behavior for older minor versions
* support `.go-version` if idiomatic files are enabled
* install Go CLIs using `go:` backend

API:

```rust
mise.go().use_global("1.23").await?;
mise.go().install_cli("github.com/jesseduffield/lazygit", "latest").await?;
```

Important:

* `go:` backend requires Go to compile the tool.
* For prebuilt binaries, prefer `aqua` or `github` when available.
* Do not recreate gvm behavior.

### 29.5 Python

Capabilities:

* install CPython versions
* install multiple Python versions
* support `.python-version`
* support `.python-versions`
* support virtualenv behavior through mise config
* integrate with uv behavior where mise supports it

API:

```rust
mise.python().use_local("3.12").await?;
mise.python().use_multiple_global(["3.11", "3.12"]).await?;
```

Important:

* Do not become pip/venv manager unless explicitly scoped.
* Python package tools should use `pipx:` or `uv`/project tooling outside this core crate.
* Keep runtime management separate from dependency management.

### 29.6 Rust

Capabilities:

* select Rust toolchain through mise
* support stable/beta/nightly/specific versions
* support components
* support targets
* understand that rustup still manages actual toolchains

API:

```rust
mise.rust().use_global("stable").await?;
mise.rust().use_local("1.82").await?;
mise.rust().with_components("1.83.0", ["rust-src", "llvm-tools"]).await?;
```

Important:

* Rust is special because mise uses rustup under the hood.
* Installs may not live under normal mise install paths.
* Do not replace rustup.
* Allow isolation via env like `MISE_RUSTUP_HOME` and `MISE_CARGO_HOME`.

### 29.7 Ruby

Capabilities:

* install Ruby versions
* use global/local Ruby
* support compiled or precompiled behavior through settings
* warn about OS build dependencies when compiling

API:

```rust
mise.ruby().use_global("3.3").await?;
mise.ruby().set_precompiled(true).await?;
```

Important:

* Ruby builds can fail due to missing system packages.
* Wrapper should classify this as `DependencyMissing` when possible.
* Do not implement ruby-build yourself.

### 29.8 Java

Capabilities:

* install Java by vendor/version
* support OpenJDK shorthand
* support vendors like Temurin, Zulu, Corretto
* resolve `JAVA_HOME` from generated env

API:

```rust
mise.java().use_global("temurin-21").await?;
mise.java().java_home().await?;
```

Important:

* Shims alone may not set `JAVA_HOME`; generated env / activation matters.

### 29.9 Generic tools

Everything else must still work.

```rust
mise.tool("terraform").use_local("1.9").await?;
mise.tool("aws-cli").install("latest").await?;
mise.tool("github:cli/cli").install("latest").await?;
mise.tool("aqua:aws/aws-cli").install("latest").await?;
mise.tool("cargo:ripgrep").install("latest").await?;
mise.tool("npm:prettier").install("3").await?;
mise.tool("pipx:black").install("latest").await?;
mise.tool("gem:rubocop").install("latest").await?;
```

This is the real power.

Do not overfit to languages.

## 30. Backend Coverage

The crate should understand backend prefixes:

```text
core:
asdf:
aqua:
cargo:
conda:
dotnet:
forgejo:
gem:
github:
gitlab:
go:
http:
npm:
pipx:
spm:
ubi:
vfox:
```

But it should not need custom logic for every backend.

Model them as strings.

Add typed helpers only where useful.

Important backend policy:

* prefer core tools for major languages
* prefer aqua/github/gitlab for prebuilt binaries
* use cargo/npm/pipx/gem/go only when that ecosystem is actually required
* warn when a backend requires a runtime already installed
* expose backend security info where mise provides it

## 31. Mise Binary Management

The crate should not assume `mise` is installed.

Provide:

```rust
MiseBinary::discover()
MiseBinary::from_path(path)
MiseBinary::ensure_installed()
```

### 31.1 Discovery order

```text
explicit path passed by user
MISE_BIN env var
PATH lookup with which
well-known install paths
app-bundled binary path
```

### 31.2 Installing mise

This is optional and should be behind a feature:

```toml
features = ["bootstrap"]
```

Options:

* tell user how to install mise
* download release binary
* use package manager hints
* use self-contained app bundle

Do not silently curl-shell-install in library code.

A library should never surprise-install global tools unless explicitly asked.

## 32. Version Compatibility

On client creation:

```rust
mise --version
```

Parse version.

Support policy:

```text
minimum supported mise version: configurable by crate release
warn on old versions
error on unsupported versions if strict mode enabled
```

Types:

```rust
pub struct MiseVersion {
    pub raw: String,
    pub parsed: Option<semver::Version>,
}
```

Feature:

```rust
Mise::capabilities()
```

Returns:

```rust
pub struct MiseCapabilities {
    pub json_ls: bool,
    pub json_env: bool,
    pub json_doctor: bool,
    pub json_tool: bool,
    pub json_bin_paths: bool,
    pub json_settings_extended: bool,
    pub json_tasks_ls: bool,
    pub json_tasks_info: bool,
    pub json_tasks_validate: bool,
    pub dry_run_code: bool,
    pub registry_security: bool,
    pub lockfile: bool,
    pub sandbox_exec: bool,
}
```

This prevents brittle assumptions.

## 33. Config Safety

Writing config is dangerous if sloppy.

Rules:

* prefer `mise use` and `mise config set`
* only direct-edit TOML for features mise CLI cannot express
* preserve unknown keys
* preserve comments when direct-editing via `toml_edit`
* write atomically
* validate after write
* never delete user config without explicit request
* distinguish global/local/env/path config
* surface target file in result

Return write result:

```rust
pub struct ConfigWriteResult {
    pub file: Utf8PathBuf,
    pub changed: bool,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}
```

## 34. Execution Safety

Never build shell strings.

Bad:

```rust
format!("mise exec {} -- {}", tool, command)
```

Good — use `toride-runner`'s `CommandSpec` builder:

```rust
let spec = CommandSpec::new("mise")
    .arg("exec")
    .arg(tool)
    .arg("--")
    .args(command)
    .timeout(Duration::from_secs(30))
    .redact(true);
let output = self.runner.run_checked(&spec).await?;
```

This guarantees:

* args are passed as a vector, never interpolated into a shell string
* timeout is enforced by the runner, not by the caller
* secrets can be redacted in display/debug output via `CommandSpec::redact(true)`
* errors include the full command context (`Error::CommandFailed { program, args, exit_code, stderr }`)

Also:

* validate tool specs before building `CommandSpec`
* reject empty command
* no shell by default
* support shell execution only explicitly
* redact env secrets
* timeout support (built into `CommandSpec` and enforced by `TokioRunner`)
* stream output via `AsyncStreamingRunner` + `CommandEventSink`
* capture output via standard `AsyncRunner::run`
* cancellation-safe: dropping the async future kills the child process

## 35. Output Modes

Some consumers need captured output; some need streaming.

These are provided by `toride-runner`:

```rust
// From toride_runner::OutputMode (always available):
pub enum OutputMode {
    Capture,   // default — buffer stdout/stderr into CommandOutput
    Stream,    // real-time events via CommandEventSink
    Inherit,   // pass-through to parent stdio
}
```

Captured output uses `CommandOutput`:

```rust
// From toride_runner::CommandOutput:
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub success: bool,
}
```

For streaming, use `AsyncStreamingRunner` with a `CommandEventSink`. Events include `Started`, `StdoutLine`, `StderrLine`, `StdoutChunk`, `StderrChunk`, and `Exited`. The sink receives backpressure-aware events and can abort streaming by returning an error.

## 36. Hooks and Env Handling

Mise can load environment variables and hooks from config.

Wrapper options:

```rust
pub struct LoadPolicy {
    pub config: bool,
    pub env: bool,
    pub hooks: bool,
}
```

Mapping:

```text
config=false => --no-config
env=false    => --no-env
hooks=false  => --no-hooks
```

Default:

* for normal trusted project use: allow all
* for automation over unknown repos: no hooks until trusted

## 37. Project Context

A central concept:

```rust
pub struct MiseProject {
    pub root: Utf8PathBuf,
    pub mise: Mise,
}
```

Capabilities:

```rust
project.detect_config_files().await?;
project.list_tools().await?;
project.install_missing().await?;
project.env().await?;
project.exec(["node", "--version"]).await?;
project.lock().await?;
```

This is useful for IDEs/agents.

## 38. Dynamic Runtime Manager API

For app-level use, expose a generic manager:

```rust
pub struct RuntimeManager {
    mise: Mise,
}
```

Methods:

```rust
manager.ensure("node", "22").await?;
manager.ensure_many([
    ("node", "22"),
    ("bun", "latest"),
    ("python", "3.12"),
]).await?;

manager.run_with("node@22", ["node", "--version"]).await?;
manager.resolve_bin("node").await?;
```

This gives the high-level UX you want.

## 39. Example Public API

### 39.1 Install Node and run npm

```rust
let mise = Mise::discover().await?;

mise.use_tool(UseRequest::local("node@22")).await?;

let result = mise.exec(ExecRequest::new()
    .tool("node@22")
    .command(["npm", "install"]))
    .await?;
```

### 39.2 Ensure Python and get env

```rust
let mise = Mise::discover().await?;

mise.install(["python@3.12"]).await?;

let env = mise.env(EnvRequest::new()
    .tool("python@3.12")
    .json_extended(true))
    .await?;
```

### 39.3 Global Bun

```rust
mise.use_tool(UseRequest::global("bun@latest")).await?;
```

### 39.4 Rust with components

```rust
mise.use_tool(
    UseRequest::global(
        ToolSpec::new("rust")
            .version("1.83.0")
            .option("components", "rust-src,llvm-tools")
    )
).await?;
```

### 39.5 Check project health

```rust
let report = mise.diagnostics()
    .check_binary()
    .check_config()
    .check_missing_tools()
    .check_outdated()
    .run()
    .await?;
```

## 40. Feature Flags

Recommended crate features:

```toml
default = ["json", "toml", "diagnostics"]

json = ["dep:serde", "dep:serde_json"]
toml = ["dep:toml_edit", "dep:toml"]
diagnostics = []
bootstrap = ["dep:reqwest"]
tracing = ["dep:tracing"]
miette = ["dep:miette"]
blocking = []
```

Async execution is not a feature flag. It is the baseline API.

`blocking` may add a small wrapper facade later, but it must not introduce a separate implementation path.

## 41. Dependencies

Use the root workspace for shared dependency versions. The current workspace already owns `tokio`, `serde`, `serde_json`, `thiserror`, `tracing`, `dirs`, `async-trait`, `which`, `duct`, and `camino`; keep using those entries instead of pinning duplicate versions in `crates/toride-mise/Cargo.toml`.

### 41.1 Primary execution dependency: toride-runner

`toride-mise` depends on `toride-runner` for all process execution. This provides transitively:

* `tokio` (process, io-util, time, rt, macros) — async runtime and process management
* `async-trait` — async trait support for `AsyncRunner` and `AsyncStreamingRunner`
* `duct` — only needed if the `duct-runner` feature is enabled (not required for `toride-mise`)

The runner types `CommandSpec`, `CommandOutput`, `OutputMode`, `Error`, `AsyncRunner`, `TokioRunner`, `FakeRunner`, `AsyncStreamingRunner`, `CommandEvent`, and `CommandEventSink` all come from `toride-runner`.

`toride-mise` does NOT need `tokio`, `async-trait`, or `duct` as direct dependencies. They come through `toride-runner`.

### 41.2 Additional workspace dependencies

Dependencies not provided by `toride-runner` that are already in the workspace:

```toml
which = "8"           # binary discovery (also used by toride-runner internally)
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
tracing = "0.1"
dirs = "6"
camino = { version = "1", features = ["serde1"] }
fs-err = "3"
semver = "1"
toml = "1"
toml_edit = "0.23"
insta = "1"
tempfile = "3"
```

Feature-gated package versions should still live at the workspace root. Mark them optional only in `crates/toride-mise/Cargo.toml`:

```toml
miette = "7"
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
```

Note: `reqwest` version must match the workspace root (`0.12`), not the version proposed earlier.

### 41.3 Recommended `crates/toride-mise/Cargo.toml` dependency shape

```toml
[dependencies]
toride-runner = { path = "../toride-runner", features = ["tokio-runner", "stream", "fake"] }

which = { workspace = true }
serde = { workspace = true, optional = true }
serde_json = { workspace = true, optional = true }
thiserror = { workspace = true }
tracing = { workspace = true, optional = true }

camino = { workspace = true }
fs-err = { workspace = true }
semver = { workspace = true }
toml = { workspace = true, optional = true }
toml_edit = { workspace = true, optional = true }
miette = { workspace = true, optional = true }
reqwest = { workspace = true, optional = true }

[dev-dependencies]
tempfile = { workspace = true }
insta = { workspace = true }
toride-runner = { path = "../toride-runner", features = ["tokio-runner", "stream", "fake", "duct-runner"] }
```

Notes:

* `tokio`, `async-trait`, and `duct` are NOT direct dependencies — they come through `toride-runner`.
* The `toride-runner` dependency enables `tokio-runner` (async execution), `stream` (streaming events), and `fake` (test doubles) by default.
* In dev-dependencies, `duct-runner` is also enabled for parity tests that verify sync and async runners produce identical results.
* Do not pin duplicate dependency versions inside `toride-mise` when the root workspace already owns that dependency.

## 42. Testing Strategy

### 42.1 Unit tests

Use `toride_runner::FakeRunner` (feature `fake`), which implements both `Runner` (sync) and `AsyncRunner` (async behind `tokio-runner`).

```rust
let fake = FakeRunner::new();
fake.push_response(CommandOutput::from_stdout(r#"{"node": "22.0.0"}"#));

let mise = Mise::builder()
    .runner(Arc::new(fake))
    .build()?;

let result = mise.list_current().await?;
assert_eq!(result[0].version, "22.0.0");
```

For strict verification:

```rust
let fake = FakeRunner::strict();
// Errors if any call is made without a matching response
```

Test:

* command construction (verify `FakeRunner::calls()` produces correct `CommandSpec` args)
* argument vector construction
* JSON parsing from `CommandOutput::stdout`
* error mapping from `toride_runner::Error` to `MiseError`
* config model
* tool spec parsing
* lossless tool spec round-tripping
* path handling
* lockfile request construction
* registry parsing
* env parsing
* timeout behavior — `FakeRunner` can return `Error::CommandTimeout` directly to test error paths
* exact-call assertions via `FakeRunner::assert_called_with()`

### 42.2 Snapshot tests

Use `insta`.

Snapshot:

* generated `CommandSpec` args (program + args vector)
* parsed JSON fixtures from `CommandOutput::stdout`
* error outputs (mapped `MiseError` display)
* diagnostics report rendering

### 42.3 Integration tests

Require real mise.

Gate behind:

```text
TORIDE_MISE_INTEGRATION=1
```

Tests:

* `mise --version`
* `mise registry --json`
* `mise ls --json`
* `mise env --json`
* `mise doctor --json`
* install tiny/fast tools only
* avoid massive downloads by default

### 42.4 Expensive tests

Gate behind:

```text
TORIDE_MISE_EXPENSIVE=1
```

Can test:

* install Node
* install Bun
* install Deno
* install Python
* install Go
* install Ruby only in CI image with dependencies

### 42.5 CI Matrix

Test on:

* Linux x86_64
* Linux arm64 if possible
* macOS arm64
* macOS x86_64 if available
* Windows later, if path and shell behavior is supported

## 43. Fixture Strategy

Keep JSON fixtures from real mise output:

```text
crates/toride-mise/fixtures/
  ls/
    installed.json
    missing.json
    current.json
  ls_remote/
    node.json
    github_cli.json
  env/
    basic.json
    extended.json
  registry/
    basic.json
    security.json
  outdated/
    basic.json
  settings/
    all.json
```

Tests should not depend on current upstream versions.

## 44. Error Classification Heuristics

Mise stderr can be human text.

The adapter layer maps `toride_runner::Error` first, then classifies remaining stderr:

```rust
// toride_runner::Error variants that map directly:
//   CommandFailed { program, args, exit_code, stderr } → MiseError::CommandFailed
//   CommandTimeout { program, args, timeout }          → MiseError::Timeout
//   SpawnFailed { program, detail }                     → MiseError::BinaryNotFound or Io
//   BinaryNotFound(String)                              → MiseError::BinaryNotFound
//
// For CommandFailed cases, classify stderr text:

pub enum FailureKind {
    BinaryMissing,
    ToolUnknown,
    VersionUnknown,
    Network,
    Checksum,
    Permission,
    DependencyMissing,
    ConfigUntrusted,
    ConfigInvalid,
    LockfileMissing,
    CommandFailed,
    Unknown,
}
```

Start conservative.

Do not over-parse.

Expose raw stderr always (available from `toride_runner::Error::CommandFailed { stderr, .. }`).

## 45. Security Considerations

Important for AI agents and automation:

* never execute hooks from unknown repos unless allowed
* support `--no-hooks`
* support `--no-env`
* support `--no-config`
* support `--locked`
* support minimum release age
* support lockfiles
* redact secrets in logs
* never run shell strings by default
* do not trust project config automatically in agent workflows
* require explicit opt-in for shared/system install targets and external links
* show dry-run plans before destructive actions
* require explicit confirmation for prune/uninstall helpers at app level
* do not silently install mise itself
* avoid invoking language-native self-updaters like `bun upgrade`, `deno upgrade`, etc.
* do not mutate global mise settings as a side effect of convenience helpers

## 46. Destructive Operation Policy

Destructive or high-risk mutating operations:

* install into shared/system locations
* link external tool paths
* uninstall
* unuse
* prune
* cache clear
* config overwrite
* settings unset
* lockfile overwrite
* plugin install/link/update/uninstall

For library API:

* allow direct calls
* return detailed result
* provide dry-run helpers where mise supports them
* never prompt inside the library
* prompting belongs to the app/CLI layer

## 47. Documentation Plan

Docs should be practical.

Pages:

```text
README.md
docs/
  architecture.md
  why-wrapper-not-vendor.md
  installation.md
  quickstart.md
  tool-management.md
  project-config.md
  running-commands.md
  environments.md
  lockfiles.md
  diagnostics.md
  security.md
  language-node.md
  language-bun.md
  language-deno.md
  language-go.md
  language-python.md
  language-rust.md
  language-ruby.md
  language-java.md
  testing.md
```

README should include:

* crate goal
* not a mise replacement
* requirements
* basic install/use example
* project-local example
* exec example
* diagnostics example
* security note for untrusted repos

## 48. Complete Integration Scope

There is no MVP/V1/V2 product split.

`toride-mise` should be designed as a complete typed integration over the mise command surface needed for tool/runtime management, environment generation, command execution, diagnostics, and safe automation.

Implementation can still be sequenced internally, but public architecture should not treat core capabilities as optional future products.

### 48.1 Command Coverage

Required command coverage:

* discover mise binary
* `mise --version`
* `mise version --json`
* `mise registry --json`
* `mise registry --json --security`
* `mise search`
* `mise backends ls`
* `mise ls --json`
* `mise ls-remote --json`
* `mise latest`
* `mise tool --json`
* `mise install`
* `mise install-into`
* `mise link`
* `mise uninstall`
* `mise use`
* `mise unuse`
* `mise env --json`
* `mise env --json-extended`
* `mise exec`
* `mise where`
* `mise which`
* `mise outdated --json`
* `mise upgrade`
* `mise prune --dry-run`
* `mise cache clear`
* `mise cache path`
* `mise cache prune`
* `mise reshim`
* `mise settings ls --json`
* `mise settings ls --json-extended`
* `mise settings get`
* `mise settings set`
* `mise settings add`
* `mise settings unset`
* `mise config ls`
* `mise config get`
* `mise config set`
* `mise lock`
* `mise lock --dry-run`
* `mise doctor --json`
* `mise doctor path`
* `mise trust`
* `mise untrust`
* `mise plugins ls`
* `mise plugins ls-remote`
* `mise plugins install`
* `mise plugins link`
* `mise plugins uninstall`
* `mise plugins update`
* `mise tool-alias get`
* `mise tool-alias ls`
* `mise tool-alias set`
* `mise tool-alias unset`
* `mise tasks ls`
* `mise tasks add`
* `mise tasks deps`
* `mise tasks edit`
* `mise tasks info --json`
* `mise run`
* `mise tasks run`
* `mise tasks validate --json`
* `mise bin-paths --json`
* `mise bin-paths --bin-names --json`

### 48.2 Helper Coverage

Required helper coverage:

* generic tool helpers
* Node.js helpers
* Bun helpers
* Deno helpers
* Go helpers
* Python helpers
* Rust helpers
* Ruby helpers
* Java helpers
* backend helpers
* plugin helpers
* lockfile helpers
* config and settings helpers
* shell/env helpers
* diagnostics helpers
* trust/security helpers

### 48.3 Must-Have Safety

Required safety behavior:

* async-native process execution via `toride-runner` (`AsyncRunner` / `TokioRunner`)
* no shell strings by default (enforced by `CommandSpec` builder — args are a `Vec<String>`)
* typed errors — `toride_runner::Error` mapped to `MiseError` with mise-specific context
* dry-run support wherever mise supports it
* dry-run-code support wherever mise supports it
* timeout support (built into `CommandSpec` and enforced by `TokioRunner`)
* cancellation-safe async APIs (dropping the future kills the child process)
* streaming output via `AsyncStreamingRunner` + `CommandEventSink` with backpressure
* no-hooks/no-env/no-config support
* per-command locked support
* redacted logging (via `CommandSpec::redact(true)`)
* JSON-first parsing with raw-output fallback
* lossless tool spec round-tripping
* no global setting mutation from convenience helpers
* explicit opt-in for shared/system install paths and external tool links
* explicit opt-in for bootstrap/installing mise itself
* explicit app-layer confirmation for destructive operations

### 48.4 Implementation Sequencing

Sequencing is allowed for engineering delivery, but all slices belong to the complete integration.

Suggested sequence:

1. Workspace crate skeleton, wire `toride-runner` dependency (`tokio-runner` + `stream` + `fake` features), `MiseError` error model (mapping `toride_runner::Error`), `MiseBinary` discovery, `Mise` client struct with `Arc<dyn AsyncRunner>`.
2. Command adapter layer: build `CommandSpec` from mise request types, map errors. JSON command adapters and fixtures for registry/list/list-remote/env/doctor.
3. Mutation commands with dry-run and destructive-operation results.
4. Config/settings/lockfile/trust APIs.
5. Exec/path/sandbox APIs using `AsyncStreamingRunner` for live output, `OutputMode` for capture/inherit selection.
6. Language helpers and generic backend helpers.
7. Plugins, tool aliases, tasks, cache, and advanced diagnostics.
8. Bootstrap/app-bundled mise support behind explicit features.

Note: Step 1 no longer includes building an async runner or fake runner — those come from `toride-runner` (`TokioRunner`, `FakeRunner`, `AsyncStreamingRunner`). The mise crate only adds the adapter layer on top.

## 49. What We Should Not Build

Do not build:

* Node installer
* Python installer
* Ruby compiler
* Go bootstrapper
* Rustup replacement
* dependency manager
* package manager UI
* shell framework
* plugin system clone
* version feed scraper
* download cache
* checksum database
* custom registry
* asdf plugin runner

Let mise do all of that.

## 50. Resolved Implementation Decisions

Use these decisions unless a later design review explicitly changes them:

1. The crate is `toride-mise` under `crates/toride-mise`.
2. The target is complete integration, not an MVP subset.
3. The primary API is async-native, powered by `toride-runner` (`AsyncRunner`, `TokioRunner`).
4. Blocking behavior is optional facade work only.
5. Doctor uses JSON first and text fallback second.
6. Locked installs use per-command `--locked` or isolated env, not global setting mutation.
7. Config reads/writes ask mise where possible instead of hard-coding path precedence.
8. Tool specs are parsed for typed access but preserved losslessly.
9. Language helpers are included because generic + ergonomic typed helpers are both part of the value.
10. A minimum supported mise version must be defined and tested by `toride-mise`.
11. All process execution is delegated to `toride-runner`. `toride-mise` never calls `tokio::process::Command` or `duct` directly.
12. The command adapter layer is thin: build `CommandSpec`, map `Error`, parse `CommandOutput`.
13. Test doubles use `toride_runner::FakeRunner` which implements both `Runner` and `AsyncRunner`.
14. Streaming uses `toride_runner::AsyncStreamingRunner` + `CommandEventSink` from the `stream` feature.

## 51. Final Architecture

```text
Toride / Consumer Rust App
    |
    | calls typed async Rust API
    v
toride-mise crate
    |
    | validates requests
    | builds CommandSpec via adapter
    | delegates to toride-runner
    | parses JSON where possible
    | maps toride_runner::Error → MiseError
    v
toride-runner (AsyncRunner / TokioRunner / AsyncStreamingRunner)
    |
    | tokio::process::Command
    | timeout enforcement
    | output capture / streaming
    v
mise binary
    |
    | uses core tools / registry / backends / config / lockfile
    v
installed tools and language runtimes
```

## 52. Final Recommendation

Build `toride-mise` as a typed mise engine wrapper.

Do not vendor mise internals.

Do not recreate language managers.

Do not call language-native upgrade/install flows behind mise's back.

Use mise's documented CLI, JSON outputs, lockfiles, config system, registry, and backend architecture.

The value of `toride-mise` is not "installing Node better than mise."

The value is:

```text
safe Rust API
typed requests
typed results
good errors
diagnostics
project automation
runtime execution
agent-friendly security
multi-language abstraction
```

That is the right abstraction layer.
