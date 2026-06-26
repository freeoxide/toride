# Duct Runner Full-Fledged Plan

## Goal

Make `toride-runner::DuctRunner` a full synchronous process runner, not just a minimal captured-output wrapper. It should remain compatible with the existing `Runner` trait and `CommandSpec`, but support the execution controls, safety guarantees, diagnostics, and parity tests needed for production use across Toride crates.

## Current State

After the current implementation pass, `crates/toride-runner/src/duct_runner.rs`
supports:

- program and argv execution through `duct::cmd`
- optional cwd
- additive environment variables
- string stdin
- captured stdout and stderr through `OutputMode::Capture`
- inherited parent stdio through `OutputMode::Inherit`
- explicit rejection of `OutputMode::Stream` for sync Duct execution
- non-zero exits returned as `CommandOutput`
- default 60 second timeout when `CommandSpec::timeout` is absent, unless a
  configured runner disables the fallback timeout
- configurable fallback timeout and command logging through
  `DuctRunnerOptions`
- structured spawn, wait, timeout, and checked-command errors
- redacted checked-command failure arguments when `CommandSpec::redact` is true
- timeout cleanup that kills and reaps the Duct handle, with warning logs for
  kill/reap failures
- focused tests for cwd, failures, redaction, timeout metadata, timeout cleanup,
  stdout/stderr separation, large output, output modes, options, and serde
  compatibility

This is stronger than the initial minimal wrapper, but it is not a complete
runner abstraction yet.

## Implementation Status

- Phase 1 is implemented: Duct spawn/wait errors are mapped to structured error variants, command completion logs include redacted display strings and elapsed time, `run_checked()` uses redacted args when requested, and the Duct test suite now covers cwd, checked failure, redaction, spawn failure, timeout metadata, timeout cleanup, stdout/stderr separation, large output, and exit-code preservation.
- Phase 2 is implemented: `DuctRunnerOptions`, `DuctRunnerBuilder`, and `ConfiguredDuctRunner` provide configurable fallback timeouts, no-default-timeout mode, and command logging control while preserving `DuctRunner` unit-struct usage.
- Phase 3 is implemented: `CommandSpec` now carries `OutputMode` with serde backward compatibility, `DuctRunner` honors `Capture` and `Inherit`, `Stream` is explicitly unsupported for sync Duct execution, and `FakeRunner` exact matching includes output mode.
- Phase 4 is implemented: `CommandSpec` can remove env vars and request a
  clean environment, DuctRunner and TokioRunner both honor the policy,
  FakeRunner exact matching includes the new fields, and serde keeps older
  specs compatible.
- Phases 5-7 remain open: output limits/raw bytes, process-tree cleanup policy,
  expanded parity coverage, and docs/examples.

## Progress Audit

Audit date: 2026-06-26.

Latest plan-only audit: 2026-06-26.

Scope guard for plan-only audits:

- These audit passes are documentation-only. Do not implement Phase 5, Phase 6,
  or Phase 7 code from this audit without a separate implementation request.
- The plan must be precise enough that a later implementation can be reviewed
  against it without guessing API semantics.
- Any planned runner behavior must explain how it avoids hidden unbounded memory
  or disk growth, not merely how it reports an error after capture.
- Cleanup and parity plans must identify evidence that proves behavior, not just
  list broad intentions.

The plan was checked against the current code three ways:

- API surface: `CommandSpec`, `DuctRunner`, `ConfiguredDuctRunner`,
  `DuctRunnerOptions`, `OutputMode`, and `FakeRunner` exact matching were
  compared against the planned phases.
- Behavior: the current Duct implementation was checked for timeout defaults,
  spawn/wait mapping, checked failure redaction, output-mode handling, and
  timeout cleanup behavior.
- Tests: runner and sidebar tests were re-run after the plan update before
  committing.

Completed before this plan-only audit:

- configurable fallback timeout
- no-default-timeout mode
- runner-level options and builder
- command logging control
- `CommandSpec::output_mode`
- serde backward compatibility for specs without `output_mode`
- `OutputMode::Capture` and `OutputMode::Inherit` in DuctRunner
- explicit unsupported error for `OutputMode::Stream`
- fake-runner exact matching for output mode
- `Error::SpawnFailed` and `Error::WaitFailed` mapping
- redacted `run_checked()` failure arguments
- duration and redacted command display in completion logs
- timeout kill/reap warning logs
- focused DuctRunner tests for the above behavior
- `CommandSpec::env_remove`
- `CommandSpec::clear_env`
- DuctRunner, TokioRunner, and streaming Tokio execution honor environment
  policy
- fake-runner exact matching for environment policy
- env policy serde compatibility and parity tests

## Remaining Gaps

### Execution Policy

- No option to merge stderr into stdout.
- No option to suppress stdout/stderr.
- No explicit shell mode. This is good by default, but there is no deliberate escape hatch for shell syntax when a caller truly needs it.

### Environment Control

- Additive env vars, env removal, and clean environment mode are supported.
- Clean environment preserves only minimal Windows process variables where
  available; Unix/macOS starts from an empty child environment and then applies
  explicit env values.
- If a key appears in both `env_remove` and `env`, the explicit `env` value
  wins.
- Crate-level examples still need to document this policy for callers.
- Fake runner exact-match comparison still ignores timeout and redaction. That
  is currently intentional for timeout because it is a runtime policy concern,
  but it should be re-audited when environment policy and additional
  `CommandSpec` fields are added.

### Error Semantics

- Stdin setup/write failures are not distinguished.
- Timeout diagnostics include program, args, and duration, but there is no
  richer structured context such as cwd, output mode, or sanitized env summary.

### Process Cleanup

- Timeout cleanup relies on `handle.kill()` plus `handle.wait()`, but the
  platform and process-tree guarantees are not documented in crate docs.
- No explicit process-group or job-object policy.
- Tests cover a direct timed-out command, but not grandchild survival behavior.
- No platform-specific notes for Unix vs Windows cleanup behavior.

### Output Handling

- Output is lossy UTF-8 only (`String::from_utf8_lossy`).
- `CommandOutput` cannot preserve raw bytes.
- No output size limit to guard against commands producing unbounded data.
- The safe shape for output limits is not “capture everything, then check
  length”; Duct and Tokio must avoid unbounded memory or disk growth when a
  limit is configured.
- No streaming support for sync callers beyond the current explicit unsupported
  error for `OutputMode::Stream`.
- No line/event callback for progress output.
- No output redirection to file.

### Diagnostics and Redaction

- Env display redaction exists but is not integrated into runner logs.
- No tracing span around command execution.
- Completion logs include redacted command display, program, exit code, and
  duration, but failures do not yet share a common tracing span or sanitized env
  summary.

### Parity With TokioRunner

- Basic parity tests exist, but coverage is thin.
- Some focused DuctRunner tests cover spawn error classification, timeout
  metadata, specific non-zero exit codes, and stdout/stderr separation with
  larger output. Shared Duct/Tokio parity coverage still needs to be expanded.
- No parity for cwd resolution edge cases.

### API Shape

- `DuctRunner` remains a unit struct for compatibility, with configured behavior
  available through `ConfiguredDuctRunner`.
- `CommandSpec` lacks fields for byte stdin, output limits, and shell opt-in.
- Adding fields to `CommandSpec` affects serde compatibility and fake-runner exact matching.

## Target Behavior

### Minimal Compatibility Target

Existing code should keep working:

```rust
let runner = DuctRunner;
let output = runner.run(&CommandSpec::new("echo").arg("ok"))?;
```

The unit struct can remain as the default runner. Advanced behavior should be available through a configuration type or constructor, for example:

```rust
let runner = DuctRunner::builder()
    .default_timeout(Duration::from_secs(10))
    .log_commands(true)
    .build();
```

`DuctRunner` remains a unit struct for compatibility. Configured behavior lives
in `ConfiguredDuctRunner`, built through `DuctRunner::builder()` or
`DuctRunner::with_options(options)`.

### CommandSpec Extensions

Add only when needed, and preserve serde backward compatibility:

- `stdin_bytes: Option<Vec<u8>>` or a `CommandStdin` enum
- `timeout_policy: TimeoutPolicy` if `None` must distinguish “use runner default” from “no timeout”
- `output_limit: Option<usize>`
- `shell: Option<ShellSpec>` for deliberate shell execution

Recommended rule: `CommandSpec` describes command intent; `DuctRunnerOptions` describes operational defaults and safety policy.

### Error Mapping

Map errors consistently:

- spawn error -> `Error::SpawnFailed`
- wait error -> `Error::WaitFailed`
- stdin setup/write error -> `Error::StdinFailed`
- timeout -> `Error::CommandTimeout`
- non-zero exit from `run()` -> successful `CommandOutput`
- non-zero exit from `run_checked()` -> `Error::CommandFailed`

`run_checked()` uses redacted display args in error messages when `spec.redact`
is true.

### Output Modes

Support at least:

- `Capture`: current behavior, captured stdout/stderr
- `Inherit`: child inherits parent stdio, returned `CommandOutput` has empty stdout/stderr and exit code
- `Stream`: currently unsupported for sync Duct with a clear error; future work
  may add a blocking event sink/callback trait separate from async streaming

Do not silently treat `Stream` as `Capture`; that hides caller intent.

### Cleanup Policy

Document and test:

- direct child is killed on timeout
- pipes are closed
- process is reaped where possible
- process-tree cleanup is not guaranteed unless explicitly implemented

If process-tree cleanup becomes required, add a platform-specific process group mode:

- Unix: spawn in a new process group and signal the group on timeout
- Windows: use job objects or document direct-child-only cleanup

## Implementation Phases

### Phase 1: Harden Current DuctRunner

Keep public API stable.

Status: implemented.

- Map spawn errors to `Error::SpawnFailed`.
- Map wait errors to `Error::WaitFailed`.
- Add cwd test matching Tokio’s cwd test.
- Add `run_checked()` failure test.
- Add specific exit-code preservation test.
- Add stdout/stderr separation test.
- Add large-output capture test.
- Add timeout metadata test.
- Add timeout-kills-child test.
- Use `display_command()` in tracing logs.
- Redact args in `run_checked()` failure errors when `spec.redact` is true.

Exit criteria:

- Existing tests pass.
- New DuctRunner tests pass.
- Basic parity tests still pass.

### Phase 2: Add Runner Options

Introduce configuration without forcing all callers to change.

Status: implemented.

- Add `DuctRunnerOptions`.
- Add `DuctRunner::builder()` or `DuctRunner::with_options(options)`.
- Support configurable default timeout.
- Support no default timeout.
- Support command logging on/off.
- Preserve `DuctRunner` default behavior.

Exit criteria:

- Existing unit-struct usage still compiles.
- Tests prove default timeout and no-default-timeout behavior.

### Phase 3: Wire OutputMode

Make `OutputMode` meaningful for sync execution.

Status: implemented.

- Add `output_mode` to `CommandSpec` with serde defaults.
- Implement `Capture`.
- Implement `Inherit`.
- Decide whether sync `Stream` is unsupported or backed by a sync streaming trait.
- Update fake runner matching to include `output_mode`.
- Add tests for inherited stdio exit code and empty captured output.

Exit criteria:

- `OutputMode::Capture` preserves current behavior.
- `OutputMode::Inherit` behaves predictably.
- `OutputMode::Stream` has explicit behavior.

### Phase 4: Environment Policy

Add deliberate environment control.

Status: implemented.

- Add `env_remove`.
- Add `clear_env`.
- Decide whether `clear_env` preserves minimal platform env vars.
- Implement through Duct’s `env_remove` and `full_env`.
- Update fake runner exact matching.
- Add tests for env removal and clean environment.

Exit criteria:

- Callers can add, remove, and clear env vars intentionally.
- Behavior is documented for Unix/macOS/Windows.

### Phase 5: Output Safety

Prevent pathological command output from destabilizing the app.

Status: planned. Do not implement as part of a plan-only audit.

Decisions:

- Add `CommandSpec::output_limit: Option<usize>`.
- Interpret the limit as a combined byte cap for captured stdout plus stderr.
- `None` preserves current unlimited capture behavior.
- `OutputMode::Inherit` ignores the limit because output is not captured.
- `OutputMode::Stream` remains explicitly unsupported by DuctRunner until a sync
  streaming API exists.
- Exceeding the limit is an error, not silent truncation.
- Add a structured error variant such as
  `Error::OutputLimitExceeded { program, limit }`.
- Keep `CommandOutput` lossy UTF-8 for Phase 5; raw bytes are a separate API
  change and should not be mixed into the first output-limit PR.

Implementation notes:

- DuctRunner must not use `stdout_capture()` / `stderr_capture()` when
  `output_limit` is set, because that can still allocate unbounded memory before
  the limit is checked.
- Preferred Duct approach: redirect stdout and stderr to owned pipes, read both
  pipes with cap-aware reader threads, keep only up to the configured combined
  byte limit in memory, and signal the main thread to kill/reap the handle when
  the next chunk would exceed the cap.
- Temporary files are acceptable only if the implementation also enforces a disk
  cap while the process is running. Redirecting to temp files and checking size
  after process exit is not sufficient because it can still consume unbounded
  disk.
- TokioRunner should enforce the same semantics by counting bytes while reading
  stdout/stderr pipes. It must stop retaining bytes beyond the limit and must
  kill/reap the child when the cap is crossed.
- Streaming Tokio execution should count emitted stdout/stderr chunks and return
  `OutputLimitExceeded` as soon as the next chunk would exceed the cap.
- If a process exceeds the output limit before exiting, the process should be
  killed immediately and reaped. Allowing it to finish is only acceptable for a
  separately documented discard-drain strategy that proves bounded memory and
  disk use.
- Limit accounting is byte-based, not character-based. UTF-8 replacement through
  `String::from_utf8_lossy` happens only after the byte-limit decision.
- For stderr/stdout split behavior, preserve separate strings when under limit.
  If the combined limit is exceeded, return an error and do not expose partial
  output.

Required tests:

- DuctRunner preserves current unlimited capture behavior by default.
- DuctRunner returns `OutputLimitExceeded` when stdout alone exceeds the limit.
- DuctRunner returns `OutputLimitExceeded` when stderr alone exceeds the limit.
- DuctRunner counts stdout plus stderr together.
- DuctRunner does not allocate unbounded captured output when a limit is set.
  Use a command that writes substantially more than the limit and assert a fast,
  bounded error path.
- DuctRunner kills and reaps a still-running process after output-limit breach.
- TokioRunner matches DuctRunner limit behavior for stdout, stderr, combined
  output, and default unlimited capture.
- TokioRunner kills and reaps a still-running process after output-limit breach.
- Streaming Tokio execution returns `OutputLimitExceeded` before emitting output
  beyond the configured cap.
- `OutputMode::Inherit` with an output limit still returns empty captured output
  and the real exit code.
- Serde defaults older specs to `output_limit: None` and round-trips explicit
  limits.
- FakeRunner exact matching includes `output_limit` if the field is added to
  `CommandSpec`.
- Non-UTF-8 output under the byte limit remains lossy UTF-8 exactly as today.
  Non-UTF-8 output over the byte limit fails by byte count before decoding.

Exit criteria:

- No unbounded memory or disk growth for captured commands when callers opt into
  limits.
- Non-UTF-8 behavior is explicit.
- The default behavior for callers that do not set `output_limit` is unchanged.
- DuctRunner, TokioRunner, FakeRunner, serde, and streaming tests cover the new
  field and behavior.
- Cleanup behavior on output-limit breach is documented and tested.

### Phase 6: Process-Tree Cleanup

Only do this if direct-child cleanup is insufficient for real Toride commands.

Status: planned. Do not implement as part of a plan-only audit.

Decision gate:

- Do not add process-tree cleanup by default unless real Toride command usage
  shows that child processes commonly spawn grandchildren that survive timeout
  or output-limit cleanup.
- Before implementation, audit call sites and command specs that can invoke
  shells, service managers, package managers, SSH tooling, or other process
  launchers.
- If the audit finds no real process-tree risk, document direct-child-only
  cleanup as the supported policy and move platform process groups to a later
  optional hardening phase.

If stronger cleanup is needed, add an explicit policy:

- Add a runner option such as `process_cleanup: ProcessCleanupPolicy`.
- Initial variants should be conservative:
  - `DirectChild` as the default and current behavior.
  - `ProcessTree` or `ProcessGroup` as opt-in behavior.
- Do not make process-tree cleanup implicit. It can change signal behavior for
  commands that intentionally spawn detached work.
- Preserve current behavior for existing callers.

Platform plan:

- Unix/macOS: start the child in a new process group/session where practical and
  signal the group on timeout or output-limit breach.
- Windows: use job objects if implemented; otherwise keep `DirectChild` and
  document that process-tree cleanup is unsupported on Windows.
- If one platform cannot provide equivalent behavior, expose that difference in
  docs and tests rather than pretending parity exists.

Required tests and evidence:

- A direct child is killed and reaped on timeout under the default policy.
- Under opt-in process-tree cleanup, a grandchild that would normally survive is
  terminated on supported platforms.
- A command that exits normally is not over-killed.
- Cleanup after output-limit breach uses the same policy as timeout cleanup.
- Unsupported platforms either skip process-tree tests with an explicit reason
  or assert a documented direct-child-only behavior.
- Tests must avoid global process-name matching where possible. Prefer marker
  files, child PIDs, or controlled scripts in temp directories.
- No zombies remain after timeout/output-limit cleanup in the tested paths.

Exit criteria:

- The selected cleanup policy is explicit in `DuctRunnerOptions` or crate docs.
- Timeout and output-limit cleanup use the same documented cleanup semantics.
- Tests prove grandchildren do not survive where process-tree cleanup is
  supported.
- Tests prove direct-child-only behavior remains stable where process-tree
  cleanup is not supported or not enabled.
- Crate docs describe Unix/macOS and Windows guarantees separately.

### Phase 7: Full Parity and Documentation

Status: planned. Do not implement as part of a plan-only audit.

Parity scope:

- Expand `parity_tests.rs` only for behavior shared by DuctRunner and
  TokioRunner.
- Do not force parity for intentional differences such as async streaming versus
  sync unsupported streaming.
- Each shared `CommandSpec` field should have at least one parity test or a
  documented reason why parity is not meaningful.

Required parity coverage:

- success output and zero exit
- non-zero exit with exact exit code
- stdout/stderr separation
- stdin
- cwd
- additive env
- env removal
- clean env
- redacted checked failures where both runners expose checked execution
- timeout metadata and cleanup classification
- output mode `Capture`
- output mode `Inherit`, if TokioRunner supports it by then; otherwise document
  the difference
- output limit behavior after Phase 5
- process cleanup policy after Phase 6 if implemented

Documentation scope:

- Crate-level docs must show which runner to choose:
  - DuctRunner for synchronous callers.
  - TokioRunner for async callers and streaming.
  - FakeRunner for tests.
- Public examples should cover:
  - captured output
  - inherited stdio
  - checked execution
  - custom timeout
  - no default timeout via configured DuctRunner
  - additive env
  - env removal
  - clean env
  - redaction
  - output limits after Phase 5
- Capability tables should distinguish supported, unsupported, and intentionally
  different behavior across DuctRunner, TokioRunner, streaming Tokio, and
  FakeRunner.
- Docs must explicitly state lossy UTF-8 behavior and any future raw-byte
  limitations.
- Docs must state process cleanup guarantees by platform after Phase 6 is
  decided.

Required verification:

- `cargo test -p toride-runner --features 'duct-runner tokio-runner serde stream fake'`
- rustdoc examples compile or are deliberately marked `ignore` with a reason.
- Search docs for stale claims after each phase status changes.

Exit criteria:

- Users can choose Duct vs Tokio based on documented tradeoffs.
- The sync runner no longer has hidden behavior gaps.
- The parity suite covers every shared behavior that the docs claim is shared.
- Public docs and examples match the implemented feature set.

## Recommended Next PR

Phases 1-4 are implemented. The next highest-value slice is Phase 5: output
safety. It is the remaining gap most likely to destabilize the app under
pathological command output.

Suggested files for Phase 5:

- `crates/toride-runner/Cargo.toml` if a direct pipe/tempfile dependency is
  needed for bounded capture
- `crates/toride-runner/src/duct_runner.rs`
- `crates/toride-runner/src/error.rs`
- `crates/toride-runner/src/fake.rs`
- `crates/toride-runner/src/spec.rs`
- `crates/toride-runner/src/streaming_tests.rs`
- `crates/toride-runner/src/tokio_runner.rs`

Suggested tests:

- DuctRunner preserves current unlimited capture behavior by default.
- DuctRunner fails with `OutputLimitExceeded` when an output limit is exceeded.
- TokioRunner matches the same output-limit behavior.
- Non-UTF-8 output behavior is explicit and tested.
- Serde round trips new `CommandSpec` fields and defaults older JSON safely.

Do not combine Phase 5 with process-tree cleanup or shell execution. Those are
separate risk areas and should be reviewed independently.

## Definition of Done

The Duct wrapper is full-fledged when:

- `DuctRunner` has configurable execution policy.
- `CommandSpec` can express output mode and environment policy.
- errors are structured and consistent with TokioRunner.
- sensitive args/env are redacted in diagnostics and checked errors.
- timeout cleanup behavior is documented and tested.
- output handling has clear capture, inherit, and streaming/unsupported-stream semantics.
- captured output limits are bounded in memory and disk use, with explicit
  `OutputLimitExceeded` behavior.
- parity tests cover all shared Duct/Tokio behavior.
- crate docs explain capability boundaries clearly.
