# Toride Runner Extension Plan

## 0. Goal

Extend `toride-runner` so it remains the shared command execution foundation for sync VPS/security crates while also supporting async, cancellable, and eventually streaming command execution for `toride-mise` and other async Toride surfaces.

The important constraint:

```text
Do not force async consumers through sync `DuctRunner` + spawn_blocking as the primary path.
```

`DuctRunner` should remain useful for crates like `ufw-kit`, `toride-fail2ban`, and the VPS security crates. `toride-mise` needs a real `tokio::process` runner because mise installs, upgrades, plugin operations, and `mise exec` can be long-running and should integrate cleanly with async runtimes.

## 1. Current `toride-runner` State

The current crate provides:

* `CommandSpec`
* `CommandOutput`
* sync `Runner`
* `DuctRunner` behind `duct-runner`
* `FakeRunner` behind `fake`
* redaction helpers
* binary discovery helpers

Current `CommandSpec` fields:

```rust
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub stdin: Option<String>,
    pub timeout: Option<Duration>,
    pub env: Vec<(String, String)>,
}
```

Current runner trait:

```rust
pub trait Runner: Send + Sync {
    fn run(&self, spec: &CommandSpec) -> Result<CommandOutput>;
    fn run_checked(&self, spec: &CommandSpec) -> Result<CommandOutput>;
}
```

This is a good sync foundation. It is not enough for `toride-mise` as the real execution layer.

## 2. Why Mise Needs More

`toride-mise` will wrap commands such as:

* `mise install`
* `mise use`
* `mise upgrade`
* `mise exec`
* `mise plugins install`
* `mise plugins update`
* `mise doctor --json`
* `mise env --json`
* `mise tasks run`

Most JSON-returning commands can use captured output. Long-running mutation and execution commands benefit from async process handling and future streaming progress.

Requirements:

* async-native execution
* command cancellation
* timeout enforcement without blocking runtime worker threads
* cwd support
* exact argv construction and test assertions
* stdout/stderr capture
* future stdout/stderr streaming
* controlled environment overrides
* redacted command display
* no shell strings
* no runner-level dry-run as the main safety mechanism

For mise, dry-run is usually a mise CLI flag such as `--dry-run` or `--dry-run-code`. The output and exit code are meaningful API results, so the runner should not silently replace those commands with empty success.

## 3. Recommended Feature Shape

Keep sync defaults stable:

```toml
[features]
default = ["duct-runner"]
duct-runner = ["dep:duct"]
tokio-runner = ["dep:tokio"]
fake = []
serde = ["dep:serde", "dep:serde_json"]
stream = ["tokio-runner"]
```

`toride-mise` should depend on:

```toml
toride-runner = {
    path = "../toride-runner",
    default-features = false,
    features = ["tokio-runner", "fake", "serde"]
}
```

Existing sync crates can keep using the default `duct-runner` path.

## 4. Extend `CommandSpec`

Add cwd support first:

```rust
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub stdin: Option<String>,
    pub timeout: Option<Duration>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<PathBuf>,
    pub redact: bool,
}
```

Builder additions:

```rust
impl CommandSpec {
    pub fn cwd(mut self, cwd: impl Into<PathBuf>) -> Self;
    pub fn redact(mut self, redact: bool) -> Self;
}
```

Rules:

* `cwd` maps to `duct` current directory and `tokio::process::Command::current_dir`.
* `redact` controls command display/logging only.
* `redact` must not mutate the actual args passed to the child process.
* Serialization should include `cwd` and `redact` when `serde` is enabled.

Do not add mise-specific fields to `CommandSpec`. Mise global flags, lock behavior, hooks/env/config policy, and dry-run flags belong in `toride-mise`.

## 5. Add Async Runner

Add a separate async trait:

```rust
#[async_trait::async_trait]
pub trait AsyncRunner: Send + Sync {
    async fn run(&self, spec: &CommandSpec) -> Result<CommandOutput>;

    async fn run_checked(&self, spec: &CommandSpec) -> Result<CommandOutput> {
        let output = self.run(spec).await?;
        if !output.success {
            return Err(Error::CommandFailed {
                program: spec.program.clone(),
                args: spec.args.join(" "),
                exit_code: output.exit_code,
                stderr: output.stderr.clone(),
            });
        }
        Ok(output)
    }
}
```

Implementation:

```text
src/async_runner.rs       # trait
src/tokio_runner.rs       # TokioRunner implementation
```

`TokioRunner` behavior:

* use `tokio::process::Command`
* pass args as argv, never through a shell
* apply `cwd`
* apply env overrides
* pipe stdin when present
* capture stdout and stderr
* enforce timeout with `tokio::time::timeout`
* kill the child on timeout
* return non-zero exits as `CommandOutput`, not immediate errors
* reserve errors for spawn/wait/timeout failures

This matches current `Runner`/`DuctRunner` semantics while avoiding runtime blocking.

## 6. Improve Fake Runner

The current `FakeRunner` is FIFO-only and returns empty success by default. That is convenient for broad tests, but too permissive for command-builder tests.

Keep FIFO behavior, but add exact matching:

```rust
impl FakeRunner {
    pub fn respond(self, spec: CommandSpec, output: CommandOutput) -> Self;
    pub fn respond_err(self, spec: CommandSpec, error: Error) -> Self;
    pub fn calls(&self) -> Vec<CommandSpec>;
    pub fn assert_called_with(&self, spec: &CommandSpec);
    pub fn assert_no_unmatched_calls(&self);
}
```

Matching rules:

* exact match includes `program`, `args`, `stdin`, `env`, and `cwd`
* timeout may be ignored by default or controlled by a strict mode
* unmatched calls should optionally error instead of returning empty success

Recommended API:

```rust
FakeRunner::new()
    .strict()
    .respond(
        CommandSpec::new("mise").args(["ls", "--json"]),
        CommandOutput::from_stdout("[]"),
    );
```

This is important for `toride-mise`, where command construction is the core safety boundary.

`FakeRunner` should implement both:

```rust
impl Runner for FakeRunner
impl AsyncRunner for FakeRunner
```

## 7. Add Streaming as a Separate Async Capability

Do not make streaming the baseline API.

Keep this stable:

```rust
AsyncRunner::run(&CommandSpec) -> CommandOutput
```

Add streaming separately:

```rust
#[async_trait::async_trait]
pub trait AsyncStreamingRunner: AsyncRunner {
    async fn run_streaming(
        &self,
        spec: &CommandSpec,
        sink: &mut dyn CommandEventSink,
    ) -> Result<CommandOutput>;
}
```

Event model:

```rust
pub enum CommandEvent {
    Started {
        program: String,
        args: Vec<String>,
    },
    StdoutLine(String),
    StderrLine(String),
    Exited {
        exit_code: Option<i32>,
    },
}

pub trait CommandEventSink: Send {
    fn on_event(&mut self, event: CommandEvent);
}
```

Use streaming for:

* long-running installs
* upgrades
* plugin installs/updates
* `mise exec`
* bootstrap/installing mise itself

Use captured output for:

* `mise ls --json`
* `mise registry --json`
* `mise env --json`
* `mise doctor --json`
* `mise settings ls --json`
* `mise tasks info --json`
* `mise bin-paths --json`

## 8. Cancellation and Timeout Semantics

For `TokioRunner`:

* timeout must terminate the child process
* dropping the future should not leave unmanaged long-running children when possible
* tests should verify a timed-out child is killed
* cancellation behavior should be documented explicitly

For `DuctRunner`:

* keep current `wait_timeout` behavior
* kill the child on timeout
* no async cancellation guarantee

For `BlockingRunnerAdapter` if added later:

```rust
pub struct BlockingRunnerAdapter<R> {
    inner: R,
}
```

It may implement `AsyncRunner` via `tokio::task::spawn_blocking`, but it should be documented as compatibility-only. It is not the default for `toride-mise`.

## 9. Redaction Rules

Current redaction helpers are useful, but `toride-runner` should expose a command display helper:

```rust
pub fn display_command(spec: &CommandSpec, flags: &[&str]) -> String;
```

Rules:

* never mutate actual args
* redact only display/logging output
* support domain-specific redaction flags
* keep default `REDACT_FLAGS` broad but overrideable

`toride-mise` may add mise-specific redaction for tokens and env values, but the base runner should provide the generic mechanism.

## 10. What Not To Put In `toride-runner`

Do not add:

* mise-specific flags
* service-specific behavior
* package-manager semantics
* config-file mutation helpers
* prompting/confirmation
* runner-level dry-run as a substitute for CLI-native dry-run

`toride-runner` should execute commands safely. Domain crates should decide what commands mean.

## 11. Implementation Order

1. Add `cwd` and `redact` to `CommandSpec`.
2. Update `DuctRunner` to honor `cwd`.
3. Update serde support for new fields.
4. Add `AsyncRunner` trait.
5. Add `TokioRunner` behind `tokio-runner`.
6. Make `FakeRunner` implement `AsyncRunner`.
7. Add strict exact-match fake responses.
8. Add command display/redaction helper.
9. Add streaming event types.
10. Add `AsyncStreamingRunner` for `TokioRunner`.
11. Add timeout/cancellation tests.
12. Update `docs/mise.md` to depend on `toride-runner` async primitives.

## 12. Acceptance Criteria

Before wiring `toride-mise` to `toride-runner`, verify:

* `CommandSpec` supports cwd and env overrides.
* `TokioRunner` exists and uses `tokio::process`.
* `TokioRunner` does not block runtime worker threads.
* `TokioRunner` kills child processes on timeout.
* `FakeRunner` can assert exact command construction.
* `FakeRunner` can be strict for unmatched calls.
* Captured-output APIs remain simple.
* Streaming is available but optional.
* Existing sync crates can still use `DuctRunner` without depending on Tokio.

## 13. Recommended `toride-mise` Boundary

`toride-mise` should still keep a mise-specific command builder:

```text
MiseRequest
  |
MiseCommandBuilder
  |
toride_runner::CommandSpec
  |
toride_runner::TokioRunner
```

The mise layer owns:

* `mise` binary resolution
* global flags
* `--json` and JSON fallback behavior
* `--dry-run` and `--dry-run-code`
* `--locked`
* `--no-hooks`
* `--no-env`
* `--no-config`
* mise-specific error classification
* tool spec validation

The runner layer owns:

* process spawning
* cwd/env/stdin plumbing
* timeout
* output capture
* streaming events
* redacted display
* fake command recording

That boundary keeps `toride-runner` reusable and keeps `toride-mise` semantically correct.
