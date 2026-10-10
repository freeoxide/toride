# Toride Runner — Remaining Work

Single source of truth for unimplemented work on `crates/toride-runner`.
Extracted 2026-10-09 from the duct-runner full-fledged plan after its
implemented phases landed (Phases 1–5 implemented, Phase 7 closed by
decision, Phase 8 substantially done). The old plan and the finished-plan
archive were removed from the tree; git history carries them and the full
audit trail.

Baseline at extraction (2026-10-09):

- `cargo test -p toride-runner --features 'duct-runner tokio-runner serde
  stream fake'` → 227 unit tests + 9 doctests pass.
- `cargo fmt` clean; clippy shows only 2 pre-existing pedantic test-style
  warnings.
- Both runners share redaction at error construction (checked failures,
  timeout args, scrubbed stderr), honor `Capture`/`Inherit`, reject
  `Stream` outside the streaming API, and enforce output caps while
  capturing.

Work areas are listed in recommended order. "Ruling needed" marks a
decision that must be recorded before implementation, per the standing
rule from the old plan: add a field only when a real Toride caller needs
it or its absence forces unsafe ad hoc behavior.

## 1. Parity closeout (small, high value)

1.1 `parity_failure` must assert an exact non-zero exit code (e.g. 42),
    not just equality between runners.

1.2 `TokioRunnerOptions`: TokioRunner hardcodes `DEFAULT_TIMEOUT_SECS = 60`
    and its command logging is not toggleable, while `ConfiguredDuctRunner`
    can do both. Either add a `TokioRunnerOptions`/builder mirroring the
    Duct one, or document the asymmetry as intentional and test the
    documented behavior.

1.3 Parity rows or documented exclusions for `ConfiguredDuctRunner`, the
    streaming path, and `FakeRunner` — the suite currently compares only
    unit `DuctRunner` vs unit `TokioRunner`.

Acceptance: all three land with tests; any intentionally excluded parity
rows are enumerated in `parity_tests.rs` rather than claimed by omission.

## 2. Crate documentation

`lib.rs` currently has two basic examples and no capability guidance.

2.1 Capability table distinguishing supported / unsupported /
    intentionally-different behavior across DuctRunner, TokioRunner,
    streaming Tokio, and FakeRunner.

2.2 Examples covering: captured output, inherited stdio, checked
    execution, custom timeout, no-default timeout via a configured runner,
    additive env, env removal, clean env — including the Unix footgun that
    `clear_env` under default `OsSearch` leaves `PATH` empty (use an
    absolute program path, an explicit `PATH` entry, or
    `PathResolution::ChildEnvNoCwd`) — redaction, and output limits.

2.3 State lossy-UTF-8 output behavior explicitly.

2.4 Restate the cleanup policy in crate docs: direct-child-only
    kill-and-reap on timeout and output-limit breach; grandchild survival
    out of scope. Today this lives only in `duct_runner.rs` comments.

Acceptance: rustdoc examples compile; every capability row names its
runner support; docs carry no stale claims after areas 3–5 are decided.

## 3. Command-intent extensions (ruling needed per item)

Decision rules: keep `CommandSpec` focused on command intent; keep runner
defaults and safety policy in runner options; prefer additive fields over
retyping existing public fields.

Candidates, none ruled on yet:

3.1 Byte stdin — `stdin_bytes: Option<Vec<u8>>` as a new additive field.
    Do NOT retype `stdin: Option<String>` into an enum; that is a double
    break (public field type + serde wire shape). Include in FakeRunner
    matching (it changes process input, like `stdin` already is).

3.2 Per-command timeout policy — new `timeout_policy` field
    distinguishing use-runner-default / no-timeout / explicit, taking
    precedence over the existing `timeout` field; serde defaults old
    payloads to "runner default". Exclude from FakeRunner matching
    (runtime policy, like `timeout`).

3.3 Shell opt-in — undecided. The code went the inverse direction from
    the original plan: `ArgvPolicy::RejectShellMetachars` refuses shell
    syntax, and no `ShellSpec` exists. If opt-in is ever wanted it must be
    visible in review, integrate with redaction (`display_command` must
    not leak secrets from shell command strings), and document injection
    risk. A rejection — "direct argv only, permanently" — is a valid
    ruling and needs only a doc paragraph.

3.4 Output disposition — merge stderr into stdout, suppress stdout/stderr,
    redirect to files; only if `OutputMode` proves insufficient for a real
    caller. Merging must preserve exit-code and success semantics;
    suppression must avoid capture work; redirection returns empty
    captured strings for redirected streams and must document whether
    output caps apply to file bytes.

Field-addition pattern (applies to every candidate): additive field +
`#[serde(default)]` in both hand-written serde halves (bump the
`serialize_struct` count literal, add the `serialize_field`, extend the
`Deserialize` helper) + an old-payload JSON test + an explicit FakeRunner
included/excluded ruling. If raw bytes ever land on `CommandOutput`: its
hand-written serde persists `success` independently of `exit_code`, so any
new constructor must keep them consistent.

Acceptance: each candidate is implemented, explicitly rejected, or
deferred with a recorded reason; no new field silently changes defaults.

## 4. Duct stdin error mapping

DuctRunner pipes stdin via `cmd.stdin_bytes(...)`, so a stdin write
failure surfaces as a wait error, never `Error::StdinFailed`.
TokioRunner already maps `StdinFailed` and kills-and-reaps the child on
write failure. To reach parity, DuctRunner must switch to an owned stdin
pipe it writes explicitly, so write failures map to `StdinFailed`
(kill-and-reap before returning, matching Tokio).

Acceptance: a test forcing a stdin write failure (child exits before
reading a large stdin) classifies as `StdinFailed` under DuctRunner, and a
parity test asserts the same classification across both runners.

## 5. Diagnostics hardening (optional)

5.1 Redaction is opt-in per spec (`redact = false` by default), so
    completion `debug!` logs print raw args by default. Add a runner-level
    redaction toggle or a redact-by-default mode for logs.

5.2 No tracing span around command execution — only discrete events. Add
    a span (program + redacted display) if callers need correlated failure
    diagnostics.

5.3 `display_env` is used by `toride-cloud` but wired into no runner log
    or error path; a sanitized env summary at runtime is still absent.

Acceptance: with the toggle on (or by default, whichever is ruled), logs
never print unredacted args; the span, if added, wraps both success and
failure paths.

## 6. Deferred by decision — do not implement without new evidence

6.1 Process-tree cleanup: direct-child-only cleanup is the supported
    policy. Revive only if a real Toride call site demonstrates grandchild
    survival. The archived plan carries the platform design (Unix process
    groups + `killpg`; Windows job objects) and the testing pitfalls:
    a `sleep 10 && echo MARKER` child does NOT prove grandchild kill
    (killing the parent prevents the marker regardless); use a
    grandchild that writes the marker independently, scope temp paths per
    test, and assert reaping via `kill(pid, 0)` → `ESRCH` rather than
    fixed sleeps.

6.2 Raw-byte output: `CommandOutput` is string-only (lossy UTF-8). Only
    with a real caller need, via a deliberate type rather than retyping
    existing fields.

6.3 Sync streaming / line callbacks: sync callers get `Stream` rejected
    with a clear error; a blocking event sink remains possible future
    work.

## Verification

`cargo test -p toride-runner --features 'duct-runner tokio-runner serde
stream fake'` with fmt and clippy clean is the gate for every change
above; doc changes must additionally keep rustdoc examples compiling.
