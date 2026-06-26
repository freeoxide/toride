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
- Phase 5 is implemented: `CommandSpec::output_limit` enforces a combined
  stdout+stderr byte cap with a structured `Error::OutputLimitExceeded`,
  bounded-read enforcement across DuctRunner (cap-aware `os_pipe` reader
  threads), TokioRunner (concurrent-draining + `tokio::select!` bounded reads),
  and streaming (bounded reads replacing `read_line`, interleaved stdout/stderr,
  retained+aborted stderr task). The non-streaming TokioRunner path was first
  converted to concurrent pipe draining, fixing a latent pipe-buffer deadlock.
  Serde round-trips the field in both hand-written halves, and `output_limit`
  is excluded from FakeRunner exact matching.
- Phases 6-8 remain open: command intent and output policy, process-tree
  cleanup policy, expanded parity coverage, and docs/examples.

## Progress Audit

Audit date: 2026-06-26.

Latest plan-only audit: 2026-06-26.
Latest implementation audit (Phase 5): 2026-06-26.

Implementation audit (Phase 5) verified the following evidence:

- `cargo test -p toride-runner --features 'duct-runner tokio-runner serde stream fake'`
  → 135 unit tests + 7 doc-tests pass; 0 failures.
- `cargo test ... output_limit` is stable across repeated runs (~0.6 s, no
  hangs), including the bounded-memory and newline-free-stream cases.
- `cargo fmt -p toride-runner -- --check` → clean.
- `cargo clippy -p toride-runner --all-features --all-targets` → no warnings
  introduced by Phase 5 in the cap-aware logic (remaining warnings are all
  pre-existing pedantic style warnings the baseline already shipped with).
- All feature combinations build (`duct-runner`, `tokio-runner`/`stream`,
  `serde`, `fake`, and each in isolation).
- The DuctRunner cap-aware EOF behavior was verified against duct's internals:
  the `Expression` retains the original write-fd `OwnedFd` until dropped, so the
  expression is scoped to drop immediately after `start()` (a standalone duct
  reproduction confirmed the hang before the fix and the fix's correctness).
- `toride-status` fails to compile on this checkout, but the failure
  (`SysconfVariable::ClkTck`) is pre-existing and unrelated to Phase 5 — it
  reproduces identically on the unmodified baseline.

Independent sub-agent audits (3 dispatched) found and the fixes were applied:

- **TokioRunner cap path: drain not bounded by timeout.** A quiet under-cap
  child that never exited was not bounded by the configured timeout because the
  outer `select!` raced a 1 ms-polling latch against the drain with no outer
  `tokio::time::timeout`. Fixed by racing the drain against `child.wait()`
  inside a single outer `tokio::time::timeout`, so a non-emitting child times
  out. Regression test: `output_limit_quiet_child_times_out`.
- **TokioRunner cap path: breach misrouted and child not killed promptly.** The
  biased `select!` usually resolved the drain arm as "Done" rather than
  "Limit", so a breach was reported as `CommandTimeout` and the child kept
  running until self-exit/timeout. Fixed by making the drain return a
  `DrainOutcome::Breach` synchronously (no latch race) and killing+reaping on
  that arm. Regression test: `output_limit_breach_kills_promptly`.
- **TokioRunner: stdin write failure leaked the child.** `write_stdin` returned
  early via `?` on a write error, dropping the still-running `Child` without
  killing it. Fixed by killing+reaping the child inside `write_stdin` before
  returning `Error::StdinFailed`.
- **DuctRunner cap path: late-breach race on the clean path.** A breach by a
  lingering grandchild's detached reader could occur after the final
  latch check, returning `Ok` with partial output. Fixed by gating the `Ok`
  return on both the latch *and* the authoritative shared byte counter
  (`counter > cap`), which is monotonic and cannot miss a breach.
- Serde, FakeRunner matching, feature gating, and the streaming path were
  audited clean (no correctness bugs).

Scope guard for plan-only audits:

- These audit passes are documentation-only. Do not implement Phase 5, Phase 6,
  Phase 7, or Phase 8 code from this audit without a separate implementation
  request.
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
- Phase 5 output safety: `CommandSpec::output_limit`, `Error::OutputLimitExceeded`,
  bounded-read enforcement in DuctRunner (cap-aware `os_pipe` reader threads),
  TokioRunner (concurrent-draining + `tokio::select!` bounded reads), and
  streaming (bounded reads replacing `read_line`, interleaved streams, retained
  + aborted stderr task); non-streaming TokioRunner converted to concurrent
  pipe draining (fixes the pipe-buffer deadlock); serde round-trips the field
  in both halves; `output_limit` excluded from FakeRunner matching

## Remaining Gaps

### Execution Policy

- No option to merge stderr into stdout.
- No option to suppress stdout/stderr.
- No explicit shell mode. This is good by default, but there is no deliberate escape hatch for shell syntax when a caller truly needs it.
- Timeout intent is still implicit: `CommandSpec::timeout = None` means “use
  runner default,” while configured DuctRunner can disable the default globally.
  There is no per-command “no timeout” policy yet.

### Environment Control

- Additive env vars, env removal, and clean environment mode are supported.
- Clean environment preserves only minimal Windows process variables where
  available; Unix/macOS starts from an empty child environment and then applies
  explicit env values.
- If a key appears in both `env_remove` and `env`, the explicit `env` value
  wins.
- Crate-level examples still need to document this policy for callers.
- On Unix, `clear_env` leaves `PATH` empty, so a PATH-relative program fails to
  spawn. Callers must use an absolute program path or add an explicit `PATH` via
  `env`. This must be documented, not just implied by the tests using `/bin/sh`.
- Fake runner exact-match comparison still ignores timeout and redaction. That
  is currently intentional for timeout because it is a runtime policy concern,
  but it should be re-audited when environment policy and additional
  `CommandSpec` fields are added.

### Error Semantics

- Stdin setup/write failures are not distinguished by DuctRunner. It pipes
  stdin via `cmd.stdin_bytes(...)`, so a write failure surfaces as a wait error
  rather than `Error::StdinFailed`. TokioRunner already maps `Error::StdinFailed`
  for its stdin writes, so this gap is Duct-specific.
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
- Output size limits **are** now supported via `CommandSpec::output_limit`
  (Phase 5). The cap-aware paths avoid unbounded memory/disk growth by
  enforcing the cap *while* capturing (bounded reads + kill-on-breach), not by
  capturing everything and checking length afterward.
- No streaming support for sync callers beyond the current explicit unsupported
  error for `OutputMode::Stream`.
- No line/event callback for progress output.
- No output redirection to file.

### Diagnostics and Redaction

- `display_env` redacts env values by key, but it is dead code: it is referenced
  only by its own unit tests and wired into no log or error path. There is no
  sanitized env summary anywhere at runtime, and `redact.rs` handles args only.
- No tracing span around command execution.
- Completion logs include redacted command display, program, exit code, and
  duration, but failures do not yet share a common tracing span or sanitized env
  summary.
- Diagnostics redaction is opt-in per spec: `display_command` redacts only when
  `spec.redact` is true, which defaults to false, so the Duct completion `debug!`
  and timeout `warn!` logs print raw args (including any secrets) by default.
  Consider a runner-level redaction toggle or redact-by-default for logs.
- `Error::CommandTimeout` stores raw `args: Vec<String>` and the `Error` enum
  derives `Debug`. Even with `redact(true)`, any `{:?}` / `tracing::?err` of the
  error prints the secret args verbatim — no path redacts them. Store an
  already-redacted display (or redact `args` at construction) in both runners.
- Both runners copy `stderr` raw into `Error::CommandFailed`, and its Display
  prints it. Failed auth/key commands routinely echo tokens or passphrases to
  stderr, so checked-failure errors can leak secrets the arg redaction never
  touches. A stderr-redaction policy (at minimum a length cap and opt-in scrub)
  is missing.

### Parity With TokioRunner

- Basic parity tests exist, but coverage is thin.
- Some focused DuctRunner tests cover spawn error classification, timeout
  metadata, specific non-zero exit codes, and stdout/stderr separation with
  larger output. Shared Duct/Tokio parity coverage still needs to be expanded.
- No parity for cwd resolution edge cases.
- TokioRunner has no options struct: it hardcodes a 60s timeout and cannot
  disable the default or toggle command logging, while `ConfiguredDuctRunner`
  can. Configurable and no-default timeout is currently Duct-only. Resolve
  before claiming full parity: add `TokioRunnerOptions` or document the
  difference as intentional and test it. Note the parity suite only ever exercises
  the unit `DuctRunner` vs unit `TokioRunner`; it never exercises
  `ConfiguredDuctRunner`, the streaming path, or `FakeRunner`.
- `AsyncRunner::run_checked` does not redact args: it uses `spec.args.join(" ")`
  unconditionally, while `Runner::run_checked` redacts when `spec.redact` is set.
  A `redact(true)` spec that fails under TokioRunner or FakeRunner leaks the raw
  secret args into `CommandFailed`. Factor the arg-formatting into one shared
  helper so the two trait defaults cannot drift, then add a parity test. This is
  a credential-leak parity gap, not cosmetic.
- TokioRunner ignores `output_mode` entirely — it always pipes and never inspects
  the spec. `Inherit` therefore captures output (observably divergent from Duct,
  which returns empty) and `Stream` is silently treated as `Capture` instead of
  rejected. Honor `Inherit` (use `Stdio::inherit()`, return empty captures) and
  reject `Stream` with the same error Duct uses, or document the divergence and
  drop those rows from the parity claim.
- The parity `failure` test only asserts `exit_code` equality, never a specific
  code; strengthen it to assert an exact non-zero code (e.g. 42).

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
- stdin setup/write error -> `Error::StdinFailed` (Tokio only today; DuctRunner
  pipes stdin via `cmd.stdin_bytes()` and never emits `StdinFailed`. To reach
  parity, DuctRunner must switch to an owned stdin pipe and write so write
  failures map to `StdinFailed`.)
- timeout -> `Error::CommandTimeout`
- non-zero exit from `run()` -> successful `CommandOutput`
- non-zero exit from `run_checked()` -> `Error::CommandFailed`

`run_checked()` uses redacted display args in error messages when `spec.redact`
is true — for the sync `Runner` only. The async `AsyncRunner::run_checked` does
not redact yet and must be aligned (see Parity gaps). Both paths also copy
`stderr` raw into `CommandFailed`; add an stderr-redaction policy so checked
failures cannot leak secrets echoed to stderr.

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

Status: implemented.

Implementation summary:

- `CommandSpec::output_limit: Option<usize>` and a builder method were added.
- `Error::OutputLimitExceeded { program, args, limit, observed }` carries the
  same shape as the sibling variants; `args` is redacted via the shared
  display helper when `spec.redact` is true.
- `output_limit` is excluded from `FakeRunner` exact matching (runtime policy,
  like `timeout`) — proven by `specs_match_ignores_output_limit`.
- Serde round-trips the field in both hand-written halves: the
  `serialize_struct("CommandSpec", 11)` count and `serialize_field`, plus the
  `Deserialize` helper field with `#[serde(default)]`. Older payloads default
  to `output_limit: None` — proven by `output_limit_defaults_to_none_for_old_payloads`.

DuctRunner cap-aware path (`run_duct_command_limited`):

- Two `os_pipe::pipe()` pairs in the parent are passed to the child via
  `stdout_file`/`stderr_file`. The duct `Expression` is scoped so it drops
  immediately after `start()` — otherwise the `Expression` keeps the original
  write-fd `OwnedFd` alive and the read ends never reach EOF.
- `.unchecked().start()` spawns no internal capture threads (both streams are
  caller-owned pipes), so the handle holds no hidden buffer.
- Two cap-aware reader threads drain the read ends with bounded
  `read(&mut [u8; N])` (8 KB), sharing a combined `AtomicUsize` counter and an
  `AtomicBool` "killed" latch. Reserve-then-check via `fetch_add` bounds
  retained memory to `cap + 2 * CAP_READ_BUF`. The thread that pushes the total
  past `cap` wins the latch (`compare_exchange`) and calls `handle.kill()`
  directly, unblocking the main `wait_timeout`.
- Reader bytes are delivered over an `mpsc::channel`; the main thread uses a
  bounded `recv_timeout` (not an unconditional join) because a grandchild
  holding an inherited write end keeps the read end from EOF. The clean path
  waits up to 2 s; error/cleanup paths wait up to 200 ms then detach.
- On breach/timeout, the child is killed and reaped; no partial output is
  returned. A late breach (bytes arriving after `wait` returns) is re-checked.
- On Apple targets, caller-opened pipes cannot set `CLOEXEC` atomically, so
  pipe creation is guarded by a process-wide mutex (`spawn_under_apple_lock`).
- `OutputMode::Inherit` ignores the limit (no capture); proven by
  `output_limit_inherit_mode_is_ignored`.

TokioRunner cap-aware path (`run_tokio_limited`):

- The non-streaming path was first converted from read-after-`wait()` to
  concurrent draining (`tokio::join!(read_stdout, read_stderr, child.wait())`
  inside a single outer `tokio::time::timeout`), fixing the latent pipe-buffer
  deadlock — proven by `large_output_does_not_deadlock` (>512 KB to stdout).
- The cap-aware path uses bounded `read(&mut [u8; N])` (8 KB) on both streams,
  interleaved with `tokio::select!`, a shared `AtomicUsize` counter, and an
  `AtomicBool` latch raced against the drain via `wait_until_true`. The first
  read crossing the cap kills the child; other arms are dropped. Done streams
  use `std::future::pending()` so the select focuses on the remaining stream
  (no busy-polling).

Streaming cap-aware path (`run_streaming_command`):

- `read_line` was replaced with bounded `read(&mut [u8; N])` on both stdout
  (inline) and stderr (detached task), so a single newline-free stream cannot
  buffer unbounded memory before the cap fires.
- stdout and stderr are interleaved with `tokio::select!` (the old
  drain-stdout-then-stderr sequencing was a latent deadlock and hid stderr
  from the cap).
- The stderr task's `JoinHandle` is retained and `abort()`ed on every
  terminating path (breach, sink error, timeout), so a lingering grandchild
  inheriting the stderr pipe can't keep the task and its fd alive.
- The mpsc channel carries fixed-size chunks (64 slots of ≤ 8 KB), not whole
  lines, so the channel itself is bounded.
- `StdoutLine`/`StderrLine` events are reconstructed from chunks via a
  bounded per-stream line accumulator (flushed each read, so ≤ 8 KB), keeping
  line-event semantics without unbounded buffering.

Limit accounting is byte-based; UTF-8 lossy decoding happens only after the
byte-limit decision. Non-UTF-8 output over the cap fails by byte count before
decoding — proven by `output_limit_non_utf8_over_limit_errors_by_byte_count`.

Decisions:

- Add `CommandSpec::output_limit: Option<usize>`.
- Interpret the limit as a combined byte cap for captured stdout plus stderr.
- `None` preserves current unlimited capture behavior.
- `OutputMode::Inherit` ignores the limit because output is not captured.
- `OutputMode::Stream` remains explicitly unsupported by DuctRunner until a sync
  streaming API exists.
- Exceeding the limit is an error, not silent truncation.
- Added the structured `Error::OutputLimitExceeded { program, args, limit, observed }`
  variant. All fields are `Clone` (the `Error` enum derives `Clone`), it has a
  `#[error("...")]` Display string, and `Error` is `#[non_exhaustive]` so the
  variant is non-breaking. `args` is redacted at construction via the shared
  display helper when `spec.redact` is true.
- `output_limit` is a runtime/safety policy, excluded from `FakeRunner` exact
  matching — same reasoning that excludes `timeout`.
- `CommandOutput` stays lossy UTF-8; raw bytes are a separate API change.

Implementation notes:

- DuctRunner must not use `stdout_capture()` / `stderr_capture()` when
  `output_limit` is set, because that can still allocate unbounded memory before
  the limit is checked.
- Do not use `Expression::reader()` for the limited path: it exposes only
  stdout, and routes stderr to an internal duct thread that reads it fully into
  memory unbounded — which defeats a combined cap. The correct Duct mechanism is
  to create two OS pipes in the parent (`os_pipe::pipe()`, already a transitive
  dep via duct), pass the write ends to `cmd.stdout_file(w_out)` and
  `cmd.stderr_file(w_err)`, then `.unchecked().start()` to get a `duct::Handle`.
  Because both streams are redirected to caller-owned files/pipes, the handle
  spawns no internal capture threads and holds no hidden buffer. In this mode the
  `Output.stdout` / `Output.stderr` from `wait_timeout` are empty; the captured
  bytes come solely from the parent's reader threads, and a breach latch (not the
  exit status) is what makes the run return `OutputLimitExceeded`.
- Spawn two cap-aware reader threads over the read ends. The `duct::Handle` is
  `Send + Sync` and `kill()` takes `&self`, so share it with the reader threads
  and have a reader call `handle.kill()` directly while the main thread is
  blocked in `wait_timeout`.
- On Apple targets, `pipe2()` is unavailable so caller-opened pipes cannot set
  `CLOEXEC` atomically; guard pipe creation plus spawn under a process-wide mutex
  (as duct does internally for its own pipes) to avoid leaking fds into unrelated
  children. After spawn, the parent must drop its copies of the write ends or the
  read ends never reach EOF; a surviving grandchild holding an inherited write
  end has the same effect, so reader-thread joins after `kill()` must be bounded
  or detached, never an unconditional blocking join.
- The combined stdout+stderr cap is shared across the two reader threads via a
  shared `AtomicUsize`. Reserve-then-check with `fetch_add(n)` and inspect the
  pre/post value before retaining a chunk, so worst-case retained memory is
  bounded to `cap + 2 * buf_size`. Exactly one thread performs the kill, gated by
  an `AtomicBool` "killed" latch (the thread that pushes the total past `cap`
  wins) so `kill()` is never called twice. On breach, unblock and join/abort both
  readers and the `wait_timeout` main thread and discard partial buffers — do not
  expose partial output.
- The cap-aware readers must use bounded reads (fixed-size buffer / `read`),
  never `read_line`/`read_to_end`, because those buffer an unbounded amount
  before the cap can be checked. A single newline-free stream
  (e.g. `yes | tr -d '\n'`) would otherwise allocate without limit before the
  cap can trigger.
- Temporary files are acceptable only if the implementation also enforces a disk
  cap while the process is running. Redirecting to temp files and checking size
  after process exit is not sufficient because it can still consume unbounded
  disk.
- TokioRunner should enforce the same semantics by counting bytes while reading
  stdout/stderr pipes. It must stop retaining bytes beyond the limit and must
  kill/reap the child when the cap is crossed. This requires first converting the
  non-streaming Tokio path from read-after-`wait()` to concurrent draining (read
  both pipes while waiting). The current model reads pipes only after the process
  exits, so it cannot enforce a mid-run cap and carries a latent pipe-buffer
  deadlock (a child that fills the ~64 KB OS pipe buffer with no reader blocks on
  write, so `wait()` never returns and only the timeout saves it). The
  concurrent-draining conversion fixes that deadlock too. Do it as a reviewable
  prerequisite step, ideally in its own commit, before adding the limit.
- Concrete shape, in two steps. For the no-limit deadlock-fix prerequisite, wrap
  `tokio::join!(read_stdout, read_stderr, child.wait())` in the single outer
  `tokio::time::timeout`; the reads operate on the already-`take()`n
  `child.stdout` / `child.stderr` handles, so they do not alias the `&mut child`
  that `wait()` needs — no `tokio::spawn` + `Arc<Mutex<Child>>` is required. For
  the limited path, `join!` is insufficient because it cannot break early on a
  breach; use `tokio::select!` over the two bounded reads and `child.wait()` with
  a per-read cap check, so the first read that crosses the cap wins, kills the
  child, and the other arms are dropped. On the timeout or breach arm, kill the
  child and drop the in-flight reads.
- Streaming Tokio execution should count emitted stdout/stderr bytes and return
  `OutputLimitExceeded` as soon as the next chunk would exceed the cap. The
  streaming path currently uses `read_line` for both stdout (inline) and stderr
  (a detached task), which buffers a whole line before emitting anything. The
  limited path needs four changes, not just "switch to bounded reads": (1) use
  bounded `read(&mut [u8; N])` on both streams so a single newline-free line
  cannot allocate unbounded memory; (2) interleave stdout and stderr with
  `tokio::select!` rather than draining stdout to EOF before stderr — the current
  sequencing is itself a latent deadlock (child blocked writing stderr while the
  parent only reads stdout) and prevents the cap from observing stderr bytes
  until stdout ends; (3) retain the stderr task's `JoinHandle` (it is currently
  dropped immediately, so it cannot be aborted) and `abort()` it on the breach
  path; (4) if a bounded mpsc channel is kept, it must carry fixed-size chunks,
  not whole lines — a 64-slot channel of unbounded-length lines is still
  unbounded.
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
  Use a command that writes substantially more than the limit (e.g. `cat
  /dev/zero`, or `yes | tr -d '\n'` for the newline-free case) and assert the
  result is `Err(OutputLimitExceeded)`. Prove bounded memory by behavior, not
  wall-clock time: assert via an instrumented/counting sink or a small cap that
  no buffer exceeded `cap + buf_size` bytes. Do not assert `elapsed() < X`; it is
  flaky under CI load.
- DuctRunner kills and reaps a still-running process after output-limit breach.
- TokioRunner matches DuctRunner limit behavior for stdout, stderr, combined
  output, and default unlimited capture.
- TokioRunner kills and reaps a still-running process after output-limit breach.
- TokioRunner (no limit set) captures output larger than the OS pipe buffer
  (well over 64 KB) without deadlocking, proving the concurrent-draining
  conversion.
- Streaming Tokio execution returns `OutputLimitExceeded` before emitting output
  beyond the configured cap.
- Streaming/limited execution bounds memory on a single newline-free stream: a
  command emitting many bytes with no newline under a limit fails fast with
  `OutputLimitExceeded` rather than buffering the whole line.
- Streaming execution kills and reaps a still-running process after an
  output-limit breach, and the detached stderr task is aborted (no lingering
  task or held fd).
- If a tempfile capture strategy is implemented, a process writing past the disk
  cap is killed before exceeding it (the disk-cap analogue of the memory test).
- `OutputMode::Inherit` with an output limit still returns empty captured output
  and the real exit code. Scope this test to DuctRunner; TokioRunner does not
  honor `Inherit` today (it always pipes), so either implement Tokio `Inherit`
  first or keep this test Duct-only.
- Serde defaults older specs to `output_limit: None` and round-trips explicit
  limits. Add the field to *both* hand-written serde halves: bump the
  `serialize_struct("CommandSpec", N)` count and add the `serialize_field`, and
  add the field to the `Deserialize` helper with `#[serde(default)]`. Adding it to
  only one half compiles but silently drops or mis-defaults the value. Back-compat
  holds for self-describing formats (JSON); binary formats are out of scope.
- `output_limit` is excluded from `FakeRunner` exact matching (runtime policy,
  like `timeout`); add a test asserting two specs differing only in
  `output_limit` still match, and update the `specs_match` doc comments.
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
- The TokioRunner non-streaming path drains pipes concurrently with waiting, and
  the limited paths use bounded reads instead of `read_line`.

### Phase 6: Command Intent And Output Policy

Close the remaining command-spec expressiveness gaps after output safety.

Status: planned. Do not implement as part of a plan-only audit.

Decision rule:

- Keep `CommandSpec` focused on command intent.
- Keep runner defaults and safety behavior in runner options.
- Do not add a new field unless at least one Toride caller needs it or the lack
  of the field forces unsafe ad hoc behavior.

Candidate `CommandSpec` additions:

- `stdin_bytes` or a `CommandStdin` enum so callers can pass non-UTF-8 input
  without lossy conversion.
- `timeout_policy` if per-command intent needs to distinguish:
  - use runner default
  - no timeout
  - explicit timeout
  Add this as a *new* field; do not change the existing public
  `timeout: Option<Duration>` field into an enum, since that would break the
  public API and serde shape. Define precedence explicitly (e.g. `timeout_policy`
  wins when set, otherwise fall back to `timeout` then runner default) and keep
  serde defaulting old payloads to "use runner default."
- `shell: Option<ShellSpec>` for deliberate shell execution.
- output disposition fields only if `OutputMode` is not enough, for example:
  - merge stderr into stdout
  - suppress stdout
  - suppress stderr
  - redirect stdout/stderr to files

Shell policy:

- Shell execution must be opt-in and visible in code review.
- Default execution remains direct program plus argv, not shell parsing.
- `ShellSpec` should avoid a raw free-form shell string where possible. Prefer
  an explicit shell executable plus command string, or a small enum for platform
  defaults.
- Shell mode must integrate with redaction. `display_command()` must not leak
  secrets from shell command strings when redaction is enabled.
- Shell mode must document injection risk and should not be used to avoid proper
  argv construction.

Byte stdin and raw output:

- `stdin_bytes` should be handled before raw output support. It is smaller,
  easier to test, and does not force `CommandOutput` API changes.
- Raw output support should not be mixed into Phase 5 output limits. If needed,
  add it here through a deliberate type such as byte fields on `CommandOutput`
  or a separate `RawCommandOutput`.
- Any raw-output design must preserve the existing string API or provide a clear
  migration path.

Output disposition:

- Merging stderr into stdout must preserve exit code and success semantics.
- Suppressing stdout/stderr must avoid unnecessary capture work.
- File redirection should return empty captured strings for redirected streams
  and document whether output limits apply to redirected file bytes.
- FakeRunner exact matching includes fields that change what command is run, and
  excludes runtime/safety policy (the same rule that excludes `timeout`). Rulings
  for the candidate fields: `stdin_bytes` / `CommandStdin` — include (changes
  process input, like `stdin` already is); `shell` / `ShellSpec` — include
  (changes how argv is assembled); `timeout_policy` — exclude (runtime policy,
  like `timeout`); `output_limit` — exclude (already decided in Phase 5).
- Each new field needs the same dual-impl serde edit as Phase 5: bump the
  `serialize_struct` count, add the `serialize_field`, and add the field to the
  `Deserialize` helper with `#[serde(default)]` (its `Default` must mean the
  back-compat behavior, e.g. `TimeoutPolicy::default()` = "use runner default").
  Prove back-compat with an "old payload missing the key" JSON test. If raw bytes
  are added to `CommandOutput`, it has the same hand-written-serde footgun (count
  literal `4`) and `success` is persisted independently of `exit_code`, so any
  new constructor must keep them consistent.
- Prefer additive fields over retyping existing public fields. `stdin_bytes` as a
  new field is purely additive; replacing `stdin: Option<String>` with a
  `CommandStdin` enum is a double break (public field type + serde wire shape) and
  is rejected — if a unified stdin enum is ever wanted it must be a new field, the
  same way `timeout_policy` is added beside `timeout` rather than replacing it.

Required tests:

- Serde defaults older specs for every new field.
- FakeRunner exact matching includes every new command-construction field.
- DuctRunner and TokioRunner match shared behavior for byte stdin.
- Shell mode is opt-in, preserves arguments as documented, and redacts display
  output when requested.
- Per-command no-timeout behavior works without changing runner defaults.
- Merge/suppress/redirect behavior is tested independently for stdout and
  stderr.

Exit criteria:

- Every remaining `CommandSpec` expressiveness gap is either implemented,
  explicitly rejected, or deferred with a documented reason.
- No new field silently changes current defaults.
- Docs explain when to use direct argv execution versus shell mode.

### Phase 7: Process-Tree Cleanup

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

- Both runners only ever kill the direct child today. duct's `handle.kill()`
  documents that it kills only the processes duct started directly, never
  grandchildren — and that remains true even after the child is placed in a new
  process group. So setting a new group is not enough; the runner must signal the
  group itself.
- Unix/macOS: place the child in a new process group/session at spawn —
  DuctRunner via `Expression::before_spawn(|cmd| { cmd.process_group(0); })`
  (`CommandExt::process_group`, or `pre_exec` + `setsid`), TokioRunner via
  `tokio::process::Command::process_group(0)`. Record the pgid (duct exposes it
  via `Handle::pids()`), and on timeout or output-limit breach signal the group
  with `nix::sys::signal::killpg` / `libc::killpg` rather than `handle.kill()` /
  `child.kill()`, then reap.
- Windows: use job objects (`CreateJobObjectW` + `AssignProcessToJobObject` +
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) if implemented; otherwise keep
  `DirectChild` and document that process-tree cleanup is unsupported. Note that
  both duct `before_spawn` and tokio hand you the pre-spawn `Command`, but
  assigning to the job needs the post-spawn handle.
- The streaming Tokio path's detached stderr task must be aborted as part of
  cleanup; otherwise a grandchild inheriting the stderr pipe keeps the read end
  from reaching EOF and the task (and its fd) leaks even after the direct child is
  killed.
- If one platform cannot provide equivalent behavior, expose that difference in
  docs and tests rather than pretending parity exists.

Required tests and evidence:

- A direct child is killed and reaped on timeout under the default policy.
- Under opt-in process-tree cleanup, a grandchild that would normally survive is
  terminated on supported platforms. The current `sleep 10 && echo SURVIVED >
  marker` timeout tests do NOT prove this: `bash` is the direct child, so killing
  it means `&& echo` never runs and the marker is never written regardless of
  whether the `sleep` grandchild survives — they only prove the direct child is
  killed. A real grandchild test needs a grandchild that writes the marker
  independently of the parent (e.g. `setsid sh -c "sleep 1; echo SURVIVED >
  $MARKER" &` with the parent exiting immediately), then assert the marker is
  absent under `ProcessTree`/`ProcessGroup` and present under `DirectChild`, so
  the test actually distinguishes the two policies.
- A command that exits normally is not over-killed.
- Cleanup after output-limit breach uses the same policy as timeout cleanup, and
  on the streaming path the detached stderr task is aborted (assert via its
  `JoinHandle` completing or an fd count, not just absence of the grandchild).
- Unsupported platforms either skip process-tree tests with an explicit reason
  or assert a documented direct-child-only behavior.
- Tests must avoid global process-name matching where possible. Prefer marker
  files, child PIDs, or controlled scripts in temp directories, and use a unique
  temp path per test (pid + an atomic counter, or `tempfile::TempDir`). The
  current Tokio timeout test hardcodes `/tmp/toride_runner_timeout_test`, which
  collides across parallel/CI runs; the Duct one scopes by pid but still appends a
  constant suffix. Prefer waiting on the child pid/pgid to be gone
  (`kill(pid, 0)` → `ESRCH`) over a fixed `sleep`.
- No zombies remain after timeout/output-limit cleanup in the tested paths.

Exit criteria:

- The selected cleanup policy is explicit in `DuctRunnerOptions` or crate docs.
- Timeout and output-limit cleanup use the same documented cleanup semantics.
- Tests prove grandchildren do not survive where process-tree cleanup is
  supported.
- Tests prove direct-child-only behavior remains stable where process-tree
  cleanup is not supported or not enabled.
- Crate docs describe Unix/macOS and Windows guarantees separately.

### Phase 8: Full Parity and Documentation

Status: planned. Do not implement as part of a plan-only audit.

Parity scope:

- Expand `parity_tests.rs` only for behavior shared by DuctRunner and
  TokioRunner.
- Do not force parity for intentional differences such as async streaming versus
  sync unsupported streaming.
- Each shared `CommandSpec` field should have at least one parity test or a
  documented reason why parity is not meaningful.
- The current suite compares only unit `DuctRunner` vs unit `TokioRunner`. Either
  extend it to exercise `ConfiguredDuctRunner`, the streaming path, and
  `FakeRunner`, or document exactly which rows are intentionally excluded (no-
  default-timeout asymmetry, async streaming vs sync unsupported streaming). Do
  not claim "parity covers all shared behavior" while those are untested.
- Two divergences must be fixed (or explicitly documented as intentional) before
  the parity rows for them are honest: async `run_checked` arg redaction, and
  TokioRunner honoring `OutputMode::Inherit`/rejecting `Stream`.

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
- configurable default timeout and no-default-timeout mode, once TokioRunner
  exposes options; until then, document the asymmetry explicitly
- output mode `Capture`
- output mode `Inherit`, if TokioRunner supports it by then; otherwise document
  the difference
- output limit behavior after Phase 5
- command intent and output policy after Phase 6
- process cleanup policy after Phase 7 if implemented

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
  - clean env (and the Unix `PATH` footgun: clean env requires an absolute
    program path or an explicit `PATH` entry)
  - redaction
  - output limits after Phase 5
  - shell opt-in after Phase 6 if implemented
  - byte stdin after Phase 6 if implemented
- Capability tables should distinguish supported, unsupported, and intentionally
  different behavior across DuctRunner, TokioRunner, streaming Tokio, and
  FakeRunner.
- Docs must explicitly state lossy UTF-8 behavior and any future raw-byte
  limitations.
- Docs must state process cleanup guarantees by platform after Phase 7 is
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

Phases 1-5 are implemented. The next highest-value slice is Phase 6: command
intent and output policy (byte stdin, shell opt-in, timeout policy, output
disposition). Phase 7 (process-tree cleanup) is gated on a real call-site
audit showing grandchild-survival risk; Phase 8 (full parity + docs) closes
out the capability tables and remaining divergences.

Phase 5 was sequenced in reviewable steps, all now complete:

1. Converted the TokioRunner non-streaming path to concurrent pipe draining —
   fixes the latent pipe-buffer deadlock; added the >64 KB no-deadlock test.
2. Added `CommandSpec::output_limit`, the `OutputLimitExceeded` error, and the
   bounded-read enforcement across Duct (owned `os_pipe` write ends into
   `stdout_file`/`stderr_file` with a process-wide spawn lock on Apple
   targets), Tokio (`tokio::select!` bounded reads), and streaming.
3. Added serde defaults for the new field (both hand-written halves).
   `output_limit` is excluded from FakeRunner matching, proven by a test.

Suggested files for Phase 5:

- `crates/toride-runner/Cargo.toml` to add `os_pipe` (or a tempfile dependency)
  for bounded capture
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

Do not combine Phase 5 with command-intent changes, process-tree cleanup, or
shell execution. Those are separate risk areas and should be reviewed
independently.

## Definition of Done

The Duct wrapper is full-fledged when:

- `DuctRunner` has configurable execution policy.
- `CommandSpec` can express output mode and environment policy.
- Remaining command intent gaps such as byte stdin, shell opt-in, timeout
  policy, and output disposition are implemented, explicitly rejected, or
  documented as deferred with rationale.
- errors are structured and consistent with TokioRunner, including stdin failure
  mapping and identical `run_checked` redaction across sync and async.
- sensitive args/env are redacted in diagnostics and checked errors — covering
  `Debug`/`{:?}` formatting of `CommandTimeout`, stderr in `CommandFailed`, and
  default (non-opt-in) log output, not just `Display` of redacted args.
- timeout cleanup behavior is documented and tested.
- output handling has clear capture, inherit, and streaming/unsupported-stream semantics.
- captured output limits are bounded in memory and disk use, with explicit
  `OutputLimitExceeded` behavior.
- parity tests cover the behavior the capability table lists as shared, with
  intentionally-excluded rows enumerated (rather than an unqualified "all shared
  behavior" claim the current suite does not back).
- crate docs explain capability boundaries clearly.
