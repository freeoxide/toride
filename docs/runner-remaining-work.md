# Toride Runner — Remaining Work (closed out)

Single source of truth for the formerly-unimplemented work on
`crates/toride-runner`. Extracted 2026-10-09 from the duct-runner
full-fledged plan; **closed out 2026-10-11** — every item in areas 1–5 is
implemented or explicitly rejected with its ruling recorded below, and area
6 remains deferred by decision. This file is now a status record, not a
worklist. The full audit trail (round-by-round implementation notes, judge
verdicts, mutation-testing evidence) lives in the orchestration state file
and the linked commits; each entry below names where its ruling is recorded.

Verification for every implemented item: `cargo test -p toride-runner
--features 'duct-runner tokio-runner serde stream fake'` plus fmt, clippy
(no new warning lines over the 2 pre-existing pedantic ones), and
`cargo doc` with compiling rustdoc examples.

## 1. Parity closeout — IMPLEMENTED (area A1)

Commit `52ffcc4` "feat(runner): mirror DuctRunner options on TokioRunner
and close parity test gaps"; ruling recorded in
`crates/toride-runner/src/parity_tests.rs` module docs (covered rows +
intentional exclusions).

- 1.1 `parity_failure` asserts the exact non-zero exit code (`bash -c
  "exit 42"` → `Some(42)`) per runner, not just mutual equality —
  IMPLEMENTED.
- 1.2 `TokioRunnerOptions`/`TokioRunnerBuilder`/`ConfiguredTokioRunner`
  mirror the Duct trio (default 60 s timeout, `log_commands`, later
  `redact_logs`); unit `TokioRunner` runs with default options —
  IMPLEMENTED (the mirror, not a documented asymmetry).
- 1.3 Parity rows for the configured runners, the streaming path
  (Tokio-vs-Tokio aggregate), and `FakeRunner` (replay-only) are in
  `parity_tests.rs`; the four intentional exclusions (duct streaming,
  FakeRunner process behavior, command-log emission, kill-and-reap tree
  effects) are enumerated in that module's docs, not claimed by omission —
  IMPLEMENTED.

## 2. Crate documentation — IMPLEMENTED (area A5, this change)

All in `crates/toride-runner/src/lib.rs`; every rustdoc example compiles
and runs as a doctest (feature-gated so reduced feature sets still build).

- 2.1 Capability matrix distinguishing supported / unsupported /
  intentionally-different behavior across `DuctRunner`, `TokioRunner`,
  streaming Tokio, and `FakeRunner` — every row names its runner(s) and
  the intentional differences are called out beneath the table.
- 2.2 Examples covering captured output, inherited stdio, checked
  execution, custom timeout (+ `TimeoutPolicy`), no-default timeout via a
  configured runner, additive env, env removal, clean env — including the
  Unix footgun that `clear_env` under default `OsSearch` leaves the child
  with no `PATH` (mitigations: absolute program path, explicit `PATH`
  entry, or `PathResolution::ChildEnvNoCwd`) — redaction (error variants,
  captured output, and the default-on `redact_logs` log display), and
  output limits.
- 2.3 Lossy-UTF-8 output behavior stated explicitly: `from_utf8_lossy` on
  every capture path, byte-accounted caps decided before decoding,
  `stdin_bytes` in / lossy out, streaming chunks raw vs lines/aggregate
  lossy; raw-byte output stays deferred (6.2).
- 2.4 Cleanup policy restated in crate docs: direct-child-only
  kill-and-reap on timeout, output-limit breach, and stdin-write failure;
  grandchild survival out of scope; bounded detach for grandchildren
  holding pipe ends; `kill_on_drop` on Tokio paths.

## 3. Command-intent extensions — all four candidates resolved (area A2)

Commit `2367b2d` "feat(runner): add stdin_bytes and timeout_policy intent
fields with recorded rulings"; rulings recorded in the field/policy docs in
`crates/toride-runner/src/spec.rs` and `crates/toride-runner/src/policy.rs`
and mirrored here.

- 3.1 Byte stdin — IMPLEMENTED: additive `stdin_bytes: Option<Vec<u8>>`
  (raw bytes that `stdin: Option<String>` cannot express; `stdin_bytes`
  wins over `stdin`), `#[serde(default)]` in both hand-written serde
  halves + old-payload tests, consumed by both runners and streaming via
  `spec.effective_stdin_bytes()`, and INCLUDED in `FakeRunner` matching
  (command construction, like `stdin`).
- 3.2 Per-command timeout policy — IMPLEMENTED: `TimeoutPolicy`
  (`SpecOrRunnerDefault` | `Never` | `Explicit`) in `policy.rs` takes
  precedence over `CommandSpec::timeout`; old payloads serde-default to
  `SpecOrRunnerDefault`, preserving the legacy resolution exactly; resolved
  via `spec.effective_timeout(runner_default)` at all four execution sites;
  EXCLUDED from `FakeRunner` matching (runtime policy, like `timeout`).
- 3.3 Shell opt-in — REJECTED, permanently: direct argv only, no
  `ShellSpec` ever. Ruling recorded in `policy.rs` module docs ("Shell
  execution: rejected, permanently"): a shell command string re-introduces
  the injection risk the argv model exists to prevent and cannot be
  token-redacted; `ArgvPolicy::RejectShellMetachars` plus the
  review-visible `CommandSpec::new("bash").args(["-c", script])` escape
  hatch cover genuine shell needs.
- 3.4 Output disposition — REJECTED, no real caller: a workspace search
  found zero consumers of merged/suppressed/redirected output; the only
  merged-output desires live inside shell script text already served by
  the `bash -c` escape hatch. Merge/suppress/redirect stay unimplemented
  per the standing rule (add a field only when a real caller needs it);
  revisit only on demonstrated call-site need.

## 4. Duct stdin error mapping — IMPLEMENTED (area A3)

Commits `3e1dd3c` "fix(runner): map duct stdin write failures to
StdinFailed with kill-and-reap parity" and `cb39a42` "fix(runner): kill
and reap before StdinFailed on the tokio streaming path" (fix round
committed separately); design rulings recorded in
`crates/toride-runner/src/duct_runner.rs` docs/comments and
`crates/toride-runner/src/error.rs` (`StdinFailed` documents the
kill-and-reap contract for both real runners).

`DuctRunner` writes piped payloads over an owned stdin pipe from a
dedicated writer thread, so a write failure (child exits before reading a
large payload) classifies as `Error::StdinFailed` after kill-and-reap —
parity with `TokioRunner` on every path including streaming (both route
stdin writes through the shared `write_stdin` helper / equivalent duct
plumbing sourcing `spec.effective_stdin_bytes()`). Tests were written
RED-first and their non-vacuity proven by mutation testing.

## 5. Diagnostics hardening — IMPLEMENTED (area A4)

Commit `a6e3cfd` "feat(runner): redact runner logs by default and add
command spans plus sanitized env summaries"; rulings recorded in
`DuctRunnerOptions`/`TokioRunnerOptions` docs, `display.rs`
(`display_command_for_log`, `display_env_summary`), and the crate docs in
`lib.rs` (Diagnostics section).

- 5.1 Redact-by-default logs — IMPLEMENTED as the runner-level toggle
  `redact_logs: bool` on BOTH options structs, DEFAULT `true`: every runner
  log display renders redacted even for specs without `spec.redact`.
  Error variants unchanged — they honor `spec.redact` alone (pinned by
  tests). `redact_logs(false)` restores the raw log display.
- 5.2 Execution span — IMPLEMENTED: a shared INFO `command` span
  (program + log-redacted display) wraps the ENTIRE execution — success
  and every failure path — on all three real-runner paths (duct captured,
  tokio captured, tokio streaming). Suppressed by `log_commands(false)`,
  the single diagnostics switch.
- 5.3 Sanitized env summary — IMPLEMENTED: completion debug events of both
  runners carry `display_env_summary(spec)` whenever the spec sets explicit
  env vars; sensitive values are `***` regardless of `spec.redact`. The
  streaming path has no completion event (pre-existing); its span wraps
  the session — recorded in the capability matrix.
- Sub-ruling: tokio completion events also gained the `command` field
  (log-redacted display) for diagnostic parity with duct.

## 6. Deferred by decision — do not implement without new evidence

Deferred at tracker extraction and re-affirmed at closeout; no new
evidence has appeared.

- 6.1 Process-tree cleanup: direct-child-only cleanup is the supported
  policy (restated in the crate docs, area 2.4). Revive only if a real
  Toride call site demonstrates grandchild survival. The archived plan
  carries the platform design (Unix process groups + `killpg`; Windows
  job objects) and the testing pitfalls: a `sleep 10 && echo MARKER`
  child does NOT prove grandchild kill (killing the parent prevents the
  marker regardless); use a grandchild that writes the marker
  independently, scope temp paths per test, and assert reaping via
  `kill(pid, 0)` → `ESRCH` rather than fixed sleeps.
- 6.2 Raw-byte output: `CommandOutput` is string-only (lossy UTF-8, now
  documented in the crate docs). Only with a real caller need, via a
  deliberate type rather than retyping existing fields.
- 6.3 Sync streaming / line callbacks: sync callers get `Stream` rejected
  with a clear error; a blocking event sink remains possible future work.

## Verification

`cargo test -p toride-runner --features 'duct-runner tokio-runner serde
stream fake'` with fmt and clippy clean is the gate for every change
above; doc changes must additionally keep rustdoc examples compiling.
All gates green at closeout: 286 unit tests + 23 running doctests (2
pre-existing `rust,ignore` examples in the runner modules), fmt clean,
clippy at the 2-line pre-existing baseline, `cargo doc` clean, and
`cargo check --workspace --all-targets` green (no consumer breakage from
the new root re-exports).
