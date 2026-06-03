# toride-mise

Typed mise integration: query tool versions, config files, and environment state.

> **Status:** Work in progress. The API may change between minor versions.

## Requirements

- [mise](https://mise.jdx.dev/) binary installed and available on `$PATH` (or pointed to by the `MISE_BIN` environment variable).
- Rust 2024 edition.

## Quick start

```rust
use toride_mise::Mise;

let mise = Mise::builder().build()?;   // discovers mise on $PATH
let tools = mise.list_installed().await?;
for tool in &tools {
    println!("{} @ {}", tool.name, tool.version.as_deref().unwrap_or("?"));
}
```

## Examples

### Discover the binary and check the version

```rust
use toride_mise::{Mise, MiseBinary, MiseVersion};

// Discover the binary without building a full client.
let binary = MiseBinary::discover()?;
println!("mise is at: {}", binary.path);

// Or query the version through the client.
let mise = Mise::builder().build()?;
let version: MiseVersion = mise.version().await?;
println!("mise {}", version);

// Check which CLI capabilities are available for this version.
let caps = mise.check_capabilities().await?;
if caps.json_ls {
    println!("mise ls --json is supported");
}
```

### List installed tools

```rust
use toride_mise::{Mise, ListToolsRequest};

let mise = Mise::builder().build()?;

// All known tools (installed, missing, and active).
let all = mise.list().await?;

// Only tools that are installed on disk.
let installed = mise.list_installed().await?;

// Currently active (resolved) versions.
let current = mise.list_current().await?;

// Tools referenced in config but not yet installed.
let missing = mise.list_missing().await?;

// Full control with a request builder.
let node_tools = mise.list_with(
    ListToolsRequest::new()
        .installed_only()
        .prefix("node")
).await?;
```

### Install a tool

```rust
use toride_mise::{Mise, InstallRequest, UseRequest};

let mise = Mise::builder().build()?;

// Simple install.
mise.install("node@22").await?;

// Install with full control over flags.
mise.install_with(
    InstallRequest::new(["node@22", "python@3.12"])
        .force()
        .jobs(4)
        .verbose(),
).await?;

// Activate (use) a tool in the local project config.
mise.use_tool(
    UseRequest::new(["node@22"])
        .local()
        .pin(),
).await?;
```

### Run a command in a tool environment

```rust
use toride_mise::{Mise, ExecRequest, ToolSpec};

let mise = Mise::builder().build()?;

// Run `node --version` inside the node@22 environment.
let req = ExecRequest::new(
    [ToolSpec::new("node@22")],
    ["node", "--version"],
);
let output = mise.exec(&req).await?;
println!("{}", output.stdout_trimmed());

// Resolve the path to a binary managed by mise.
let bin = mise.which("node").await?;
println!("node binary at: {}", bin.path);

// Find where a tool is installed on disk.
let install_dir = mise.where_tool(&ToolSpec::new("node@22")).await?;
println!("node installed at: {}", install_dir);
```

### Project context

[`MiseProject`] wraps a directory with its own mise config and tools.

```rust
use toride_mise::{Mise, MiseProject};
use camino::Utf8PathBuf;

let mise = Mise::builder().build()?;
let project = MiseProject::new(Utf8PathBuf::from("/projects/my-app"), mise);

// Detect config files in the project root.
let configs = project.detect_config_files()?;
for path in &configs {
    println!("found config: {}", path);
}

// Install any tools the project requires.
project.install_missing().await?;

// Run a command in the project's mise environment.
let output = project.exec(["cargo", "test"]).await?;
```

### Runtime manager

[`RuntimeManager`] manages runtime installations for a set of tools.

```rust
use toride_mise::{Mise, RuntimeManager};

let mise = Mise::builder().build()?;
let mgr = RuntimeManager::new(mise);

// Ensure specific versions are installed.
mgr.ensure_many(&[
    ("node", "22"),
    ("python", "3.12"),
    ("go", "1.22"),
]).await?;

// Run a command with a specific tool available.
let output = mgr.run_with("node@22", ["node", "-e", "console.log(1+1)"]).await?;

// Resolve the filesystem path to a binary.
let node = mgr.resolve_bin("node").await?;
println!("node is at: {}", node);
```

## Security

When driving mise from automated contexts (CI, editors, daemons), use
[`SecurityPolicy`] with [`LoadPolicy`] to prevent arbitrary script execution:

```rust
use toride_mise::{Mise, SecurityPolicy};

// Conservative defaults: hooks disabled, env from config disabled.
let policy = SecurityPolicy {
    locked: true,
    require_trusted_config: true,
    ..SecurityPolicy::default()
};

let mise = Mise::with_security(policy).build()?;
```

This is especially important when working with **untrusted repositories**.
Always set `allow_hooks: false` (the default) to prevent config-level hook scripts
from running during automated workflows.

## Feature flags

| Feature        | Default | Description                                                  |
|----------------|---------|--------------------------------------------------------------|
| `json`         | Yes     | JSON parsing via `serde` / `serde_json`                      |
| `toml`         | Yes     | TOML config file reading via `toml` / `toml_edit`            |
| `diagnostics`  | Yes     | `mise doctor` parsing and [`Diagnostic`] types               |
| `tracing`      | No      | Emit `tracing` spans for mise invocations                    |
| `bootstrap`    | No      | Bootstrap / auto-install the mise binary                     |
| `miette`       | No      | `miette` error reporting integration                         |
| `blocking`     | No      | Blocking wrappers around async methods                       |

## Testing

### Unit tests

Unit tests use [`FakeRunner`](toride_runner::FakeRunner) to mock the mise binary.
No mise installation is required:

```rust
use std::sync::Arc;
use toride_runner::{CommandOutput, FakeRunner};
use toride_mise::Mise;

let fake = Arc::new(FakeRunner::new().push_response(
    CommandOutput::from_stdout(r#"[{"name":"node","version":"22.1.0"}]"#),
));
let mise = Mise::builder()
    .runner(fake.clone() as Arc<dyn toride_runner::AsyncRunner>)
    .binary(toride_mise::MiseBinary::from_path("/usr/bin/mise"))
    .build()?;

let tools = mise.list_installed().await?;
assert_eq!(tools[0].name, "node");
```

Run unit tests:

```sh
cargo test -p toride-mise
```

### Integration tests

Integration tests hit the real mise binary. Enable them with the environment
variable `TORIDE_MISE_INTEGRATION=1`:

```sh
TORIDE_MISE_INTEGRATION=1 cargo test -p toride-mise
```

## Architecture

```
+--------------------------------------------------+
|  App                                             |
|    |                                             |
|    v                                             |
|  toride-mise   (typed API, request structs)      |
|    |                                             |
|    v                                             |
|  toride-runner  (command execution, FakeRunner)  |
|    |                                             |
|    v                                             |
|  mise binary                                     |
|    |                                             |
|    v                                             |
|  tools (node, python, go, ...)                   |
+--------------------------------------------------+
```

- **toride-mise** provides typed Rust types for every mise subcommand. It does
  not execute commands directly.
- **toride-runner** handles process spawning, output capture, streaming, and
  the `FakeRunner` used in tests.
- The **mise binary** does the actual work of managing tool installations.

## Disclaimer

**toride-mise is not a replacement for mise.** It is a typed Rust wrapper
around the mise CLI. You still need mise installed on the system. For direct
tool and runtime management, use [mise](https://mise.jdx.dev/) directly.
