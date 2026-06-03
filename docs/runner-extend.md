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

Current limitations to account for before implementation:

* `CommandSpec` has public fields, so adding fields is a source-breaking change for callers using struct literals.
* `CommandSpec` has no `cwd`, so callers cannot model project-local execution without custom runner wrappers.
* `CommandSpec::stdin` is `String`, which is fine for current use but cannot represent arbitrary bytes.
* `FakeRunner` queues only `CommandOutput`, so it cannot model runner errors such as spawn failures or timeouts.
* `FakeRunner` is FIFO-only and permissive by default, so tests can pass even when command construction is wrong.
* `DuctRunner` always captures stdout/stderr and has no streaming/inherit mode.
* There is no async trait or `tokio::process` implementation.
* Redaction helpers exist, but no single display function ties redaction to `CommandSpec`.

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
* deterministic tests for exact command specs
* feature combinations that do not pull Tokio into sync-only crates

For mise, dry-run is usually a mise CLI flag such as `--dry-run` or `--dry-run-code`. The output and exit code are meaningful API results, so the runner should not silently replace those commands with empty success.

## 3. Recommended Feature Shape

Keep sync defaults stable:

```toml
[features]
default = ["duct-runner"]
duct-runner = ["dep:duct"]
tokio-runner = ["dep:tokio", "dep:async-trait"]
fake = []
serde = ["dep:serde", "dep:serde_json"]
stream = ["tokio-runner"]
```

Both `tokio` and `async-trait` already exist as workspace dependencies. The
optional dep declarations must reference them as `workspace = true` with a
minimal feature set to avoid pulling the full tokio runtime into sync-only
builds:

```toml
[dependencies]
tokio = { workspace = true, features = ["process", "io-util", "time", "rt", "macros"], optional = true }
async-trait = { workspace = true, optional = true }
```

Note: the workspace defines `tokio` with `features = ["full"]`. When a crate
enables the `tokio-runner` feature, it gets the subset listed above. If the
same build also pulls in tokio via another crate with `full`, Cargo merges the
features — there is no conflict, just a larger final feature set.

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

Because `CommandSpec` currently exposes public fields, choose one of these migration paths:

1. Accept a workspace-internal breaking change and update all struct literals in the same PR.
2. Make fields private and commit to builder-style construction before wider downstream use.
3. Add `#[non_exhaustive]` after the migration to prevent future external struct-literal construction.

Option 2 is the cleanest long-term API. Option 1 is acceptable if this crate is still workspace-internal and the change is made before publishing.

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
* `cwd` should be serialized as a path string and deserialized lossily only if the target platform supports it.
* Environment ordering must remain stable for fake matching and snapshots.
* Timeout serialization should not truncate sub-second durations. Current `serde` support uses seconds, which loses values like `50ms`.

Do not add mise-specific fields to `CommandSpec`. Mise global flags, lock behavior, hooks/env/config policy, and dry-run flags belong in `toride-mise`.

Defer these until there is a concrete need:

```rust
pub stdin_bytes: Option<Vec<u8>>;
pub env_clear: bool;
pub kill_on_drop: bool;
```

Do not add them speculatively unless an implementation or caller needs them.

## 5. Output Modes

The current runner always captures stdout and stderr. Keep that as the default.

When streaming lands, add explicit output mode instead of overloading `run`:

```rust
pub enum OutputMode {
    Capture,
    Stream,
    Inherit,
}
```

Rules:

* `Capture` returns full stdout/stderr in `CommandOutput`.
* `Stream` emits events and may also return collected stdout/stderr depending on request options.
* `Inherit` connects child stdio to the parent process and should return empty captured strings.
* `Inherit` is unsafe for libraries by default because it can leak output and interfere with app UI; use it only when the caller opts in.
* `toride-mise` should prefer `Capture` for JSON commands and `Stream` for long-running commands.

Do not add `OutputMode` until `TokioRunner` or streaming implementation work begins. Adding it before then creates API surface without behavior.

## 6. Add Async Runner

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
* wait/reap the child after kill
* return non-zero exits as `CommandOutput`, not immediate errors
* reserve errors for spawn/wait/timeout failures
* use lossy UTF-8 conversion initially to match `DuctRunner`
* preserve stdout/stderr separation
* avoid logging unredacted args

Timeout handling must avoid orphaned children. The minimum acceptable behavior is:

```text
timeout fires
  |
kill child
  |
wait for child termination
  |
return Error::CommandTimeout
```

Process-tree termination is a separate, harder problem. Document that the first implementation kills the direct child. Add process-group support later only if a domain command needs it.

This matches current `Runner`/`DuctRunner` semantics while avoiding runtime blocking.

## 7. Error Model Audit

Current errors are sufficient for the sync migration, but async process execution needs more precise classification.

Existing variants to keep unchanged:

```rust
pub enum Error {
    // ... existing variants (kept as-is) ...
    Io(String),
    BinaryNotFound(String),
    OutputParse(String),
    Other(String),
}
```

Recommended additions:

```rust
pub enum Error {
    // ... existing variants above ...

    // New variants for async process execution:
    SpawnFailed {
        program: String,
        source: String,
    },
    WaitFailed {
        program: String,
        source: String,
    },
    StdinFailed {
        program: String,
        source: String,
    },
    CommandTimeout {
        program: String,
        args: Vec<String>,
        timeout: Duration,
    },
    CommandFailed {
        program: String,
        args: String,
        exit_code: Option<i32>,
        stderr: String,
    },
}
```

The existing `CommandTimeout(String)` variant becomes `CommandTimeout { program, args, timeout }` — a source-breaking change for pattern matches. This is safe because `Error` is `#[non_exhaustive]` and no consumer pattern-matches on `CommandTimeout` directly; they all convert via `From<toride_runner::Error>`.

Rules:

* Keep non-zero exits as `CommandOutput` from `run`.
* Return `CommandFailed` only from `run_checked`.
* Preserve enough context for domain crates to classify errors.
* Do not put parsed domain failures in `toride-runner`; `toride-mise` should map mise stderr/stdout into mise-specific errors.
* Be careful with `Clone` on errors if storing `std::io::Error` directly. String sources are less rich but clone cleanly.

## 8. Improve Fake Runner

The current `FakeRunner` is FIFO-only and returns empty success by default. That is convenient for broad tests, but too permissive for command-builder tests.

Keep FIFO behavior, but add exact matching:

```rust
impl FakeRunner {
    pub fn respond(self, spec: CommandSpec, output: CommandOutput) -> Self;
    pub fn respond_err(self, spec: CommandSpec, error: Error) -> Self;
    pub fn push_result(self, result: Result<CommandOutput>) -> Self;
    pub fn calls(&self) -> Vec<CommandSpec>;
    pub fn assert_called_with(&self, spec: &CommandSpec);
    pub fn assert_no_unmatched_calls(&self);
}
```

Matching rules:

* exact match includes `program`, `args`, `stdin`, `env`, and `cwd`
* timeout may be ignored by default or controlled by a strict mode
* unmatched calls should optionally error instead of returning empty success
* strict mode should return a runner error on unmatched calls
* FIFO mode can remain for broad migration tests
* exact matching should require `PartialEq` on `CommandSpec`

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

Internally, fake responses should be:

```rust
type FakeResult = Result<CommandOutput>;
```

not plain `CommandOutput`, otherwise tests cannot model spawn errors, timeout errors, or permission failures.

## 9. Add Streaming as a Separate Async Capability

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
    StdoutChunk(Vec<u8>),
    StderrChunk(Vec<u8>),
    StdoutLine(String),
    StderrLine(String),
    Exited {
        exit_code: Option<i32>,
    },
}

#[async_trait::async_trait]
pub trait CommandEventSink: Send {
    async fn on_event(&mut self, event: CommandEvent) -> Result<()>;
}
```

Chunks are required because some commands emit progress without newline boundaries. Line events are convenient but should be derived by the runner or helper adapters, not the only primitive.

The event sink should be async to allow backpressure. A blocking sink in an async runner can stall process output handling and deadlock if buffers fill.

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

## 10. Cancellation and Timeout Semantics

For `TokioRunner`:

* timeout must terminate the child process
* dropping the future should not leave unmanaged long-running children when possible
* tests should verify a timed-out child is killed
* cancellation behavior should be documented explicitly
* stdout and stderr tasks must be joined or aborted cleanly
* stdin write errors must surface unless the child has already exited

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

## 11. Redaction Rules

Current redaction helpers are useful, but `toride-runner` should expose a command display helper:

```rust
pub fn display_command(spec: &CommandSpec, flags: &[&str]) -> String;
pub fn display_env(spec: &CommandSpec, keys: &[&str]) -> Vec<(String, String)>;
```

Rules:

* never mutate actual args
* redact only display/logging output
* support domain-specific redaction flags
* keep default `REDACT_FLAGS` broad but overrideable
* support env var redaction for token/password-like keys
* avoid treating common short flags like `-p` as sensitive globally if that creates false positives for commands where `-p` means port

The current default redaction list includes short flags such as `-p` and `-k`. That may be too broad for generic command display because many CLIs use `-p` for port, path, project, or protocol. Prefer long-form flags in global defaults and let domain crates opt into short flags.

`toride-mise` may add mise-specific redaction for tokens and env values, but the base runner should provide the generic mechanism.

## 12. Feature Compatibility Matrix

The crate should compile in these combinations:

```text
cargo test -p toride-runner --no-default-features
cargo test -p toride-runner --no-default-features --features fake
cargo test -p toride-runner --no-default-features --features serde
cargo test -p toride-runner --features duct-runner
cargo test -p toride-runner --no-default-features --features tokio-runner
cargo test -p toride-runner --no-default-features --features tokio-runner,fake,serde
cargo test -p toride-runner --all-features
```

Feature rules:

* `duct-runner` must not require Tokio.
* `tokio-runner` must not require `duct`.
* `fake` should work without `duct` or Tokio for sync tests.
* `fake + tokio-runner` should make `FakeRunner` implement `AsyncRunner`.
* `serde` should not pull in any runner implementation.
* `stream` implies `tokio-runner`.

## 13. Backward Compatibility Plan

`toride-runner` is already used by new workspace crates. Avoid breaking all consumers accidentally.

Migration rules:

* Add builders before making fields private.
* Update internal workspace users to use builders instead of struct literals.
* Add new fields with safe defaults in `CommandSpec::new`.
* If fields remain public, document the source-breaking nature of future field additions.
* Prefer one coordinated PR for `CommandSpec` field changes.
* Keep `Runner` and `DuctRunner` behavior unchanged except for honoring `cwd`.
* Do not change `run` to error on non-zero exits; existing callers rely on inspecting `CommandOutput.success`.

## 14. What Not To Put In `toride-runner`

Do not add:

* mise-specific flags
* service-specific behavior
* package-manager semantics
* config-file mutation helpers
* prompting/confirmation
* runner-level dry-run as a substitute for CLI-native dry-run
* command retries
* JSON parsing
* progress parsing
* process supervision beyond direct child lifecycle

`toride-runner` should execute commands safely. Domain crates should decide what commands mean.

## 15. Implementation Order

1. Add `cwd` and `redact` to `CommandSpec`.
2. Update `DuctRunner` to honor `cwd`.
3. Fix timeout serde to preserve milliseconds or nanoseconds.
4. Update serde support for new fields.
5. Add command display/redaction helper.
6. Add strict exact-match fake responses.
7. Change fake responses internally to `Result<CommandOutput>`.
8. Add `AsyncRunner` trait.
9. Add `TokioRunner` behind `tokio-runner`.
10. Make `FakeRunner` implement `AsyncRunner`.
11. Add timeout/cancellation tests.
12. Add output mode design only when implementing streaming.
13. Add streaming event types.
14. Add `AsyncStreamingRunner` for `TokioRunner`.
15. Update `docs/mise.md` to depend on `toride-runner` async primitives.

## 16. `toride-mise` Integration Gate

Do not block initial `toride-mise` implementation on streaming.

`toride-mise` can safely start using `toride-runner` after these are done:

* `CommandSpec.cwd`
* `AsyncRunner`
* `TokioRunner`
* strict exact-match `FakeRunner`
* `FakeRunner` implements `AsyncRunner`
* timeout and child-kill tests
* redacted command display

Streaming can land after `toride-mise` has captured-output support for JSON commands and basic mutation commands.

Initial `toride-mise` commands that can use captured output:

* `mise --version`
* `mise version --json`
* `mise registry --json`
* `mise ls --json`
* `mise ls-remote --json`
* `mise env --json`
* `mise doctor --json`
* `mise settings ls --json`
* `mise tasks info --json`
* `mise bin-paths --json`

Initial mutation commands can also start as captured-output commands:

* `mise install`
* `mise use`
* `mise uninstall`
* `mise unuse`
* `mise upgrade`
* `mise plugins install`

They should expose captured stdout/stderr and duration first. Streaming improves UX but is not required for correctness.

## 17. Acceptance Criteria

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
* `cargo test -p toride-runner --all-features` passes.
* `cargo test -p toride-runner --no-default-features --features tokio-runner,fake,serde` passes.
* `DuctRunner` and `TokioRunner` produce equivalent `CommandOutput` for basic success and failure commands.
* Sub-second timeout values survive serde round-trips when `serde` is enabled.
* Redacted display output does not redact actual child process args.
* `run` returns non-zero exits as output and `run_checked` returns an error.

## 18. Recommended `toride-mise` Boundary

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

## 19. Out of Scope: `toride-ssh` `CliRunner`

`toride-ssh` defines its own `CliRunner` trait in `crates/toride-ssh/crates/core/src/runner.rs` with a different shape:

* `run_for_output`, `run_checked_for_output` — return parsed domain types, not `CommandOutput`
* `tool_exists` — binary presence check
* `read_file`, `write_file` — file I/O helpers

This trait is intentionally separate from `toride_runner::Runner`. The `toride-ssh` sub-crates (`doctor`, `agent`, `key`, `known-hosts`) depend on its domain-specific methods. Unification with `toride-runner` would require either embedding SSH semantics into the shared runner or creating a bridge adapter. Neither is warranted now; revisit only if the duplication becomes a maintenance burden.
