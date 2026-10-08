# Publishing the workspace crates

How the toride workspace lands on crates.io. Every workspace member is
publishable (no manifest sets `publish = false`): the embedder-facing
library layer, the domain crates around it (firewall, ssh, monitoring, …),
and the TUI crate.

## The release set

All 33 crates, dependency-first order (`cargo publish` resolves every
intra-set path dependency against the live registry, so a dependent
cannot go up before its dependency):

1. `toride-diagnostic-types`
2. `toride-fs`
3. `toride-runner`
4. `toride-installer` (depends on toride-runner)
5. `toride-registry` (dev-depends on toride-installer)
6. `toride-mise` (depends on toride-runner, toride-installer)
7. `toride-apps` (depends on toride-runner, toride-registry;
   optional deps on toride-installer, toride-mise)
8. `toride-service` (depends on toride-runner)
9. `toride-ssh-core` (depends on toride-diagnostic-types, toride-fs,
   toride-runner)
10. `toride-status`, `toride-audit`, `toride-backup`, `toride-cloud`,
    `toride-fail2ban`, `toride-harden`, `toride-monitor`, `toride-proxy`,
    `toride-tailscale`, `toride-updates`, `toride-users`,
    `toride-wireguard`, `ufw-kit` (each depends on the shared crates
    above)
11. `toride-ssh-agent`, `toride-ssh-authorized-keys`,
    `toride-ssh-certificate`, `toride-ssh-config`, `toride-ssh-forward`,
    `toride-ssh-known-hosts` (depend on toride-ssh-core; the config and
    authorized-keys crates also on toride-fs)
12. `toride-ssh-doctor` (depends on toride-ssh-config, toride-ssh-core)
13. `toride-ssh-key` (depends on toride-ssh-agent, toride-ssh-config,
    toride-ssh-core)
14. `ufw-kit-test-support` (depends on ufw-kit)
15. `toride-ssh` (facade over the nine toride-ssh sub-crates)
16. `toride` (the TUI; depends on the domain crates and toride-ssh)

The canonical machine-checked order is `PUBLISH_ORDER` in
`.github/workflows/ci.yml`; `PUBLISH_SET` in
`.github/workflows/publish.yml` mirrors it and drives the upload.

All crates inherit `version.workspace` from the root manifest, so one
version number is released at a time. `scripts/publish-crates.sh`
predates the registry and apps crates (neither is in its list); the
`.github/workflows/publish.yml` workflow is the authoritative path for
this set.

## The per-crate state machine

Before touching any crate, the workflow classifies it against the live
registry (sparse index first, crates.io API as a cross-check against
index lag) and writes a plan. `scripts/publish-state.sh` holds the
classification logic and `scripts/test-publish-state.sh` exercises it
against fixture index states (new / update / skip / regress / error
kinds); the workflow runs those tests before gating anything.

- registry has the crate at the target version → **skip** (already
  indexed; never re-published, never an error)
- registry has the crate at an *older* version only → **update**:
  publish the new version normally
- registry lacks the crate → **new**: first publish
- registry has a *newer* version than this run targets → the run
  aborts before the first upload (a lockstep regression, not something
  to publish under)

Crates are processed strictly in `PUBLISH_SET` order. A failed crate
stops the run: no later crate is attempted. A successful upload is held
until the sparse index resolves the new version before the next crate
starts.

## Preparing a release

Applies to the first publish and every update alike:

1. Bump `version` in the root `Cargo.toml` `[workspace.package]`.
2. Update every intra-set dependency requirement in the crate
   manifests to match (`toride-xyz = { path = "...", version = "<new>" }`).
   The workflow's lockstep gate fails the run before any upload if a
   requirement is not exactly `^<new>` — that is the "satisfiable by
   the versions published in this same run" rule; a crate needing a
   newer in-set dep than this run publishes aborts the run up front
   instead of failing halfway.
3. For each crate that has a `CHANGELOG.md`, move its changes from
   `[Unreleased]` into a new `## [<version>] - <date>` section. This
   move is a deliberate manual step. If a crate that is about to be
   published still shows the version under `[Unreleased]` (no
   `## [<version>]` heading), the workflow fails before uploading
   anything, naming the crate.

## Dispatching

Run the **Publish crates** workflow (Actions → Publish crates → Run
workflow):

- With `dry_run` enabled, every crate is verified with
  `cargo publish --dry-run` and nothing is uploaded. The only
  downgraded failure is the order-blocked one — an intra-set dependency
  absent from crates.io ("no matching package") or not yet published at
  the required version ("failed to select a version"); that becomes a
  warning because it is the expected state before a first publish.
  Anything else fails the run.
- With `dry_run` disabled, each publishable crate is packaged
  (`cargo publish --dry-run`), uploaded, and held until the sparse
  index resolves it.

Both modes re-run fmt, clippy (`-D warnings`), tests, and the
non-default feature configurations first, plus the state-machine tests
and the lockstep/satisfiability gate.

`CARGO_REGISTRY_TOKEN` must be configured as a repository secret.

## Rate limits (HTTP 429)

crates.io throttles how many *new* crates an account may publish in a
short window — the October 8, 2026 run hit it after five crates with
`429 Too Many Requests … Please try again after <timestamp>`.

The workflow parses that RFC 1123 timestamp, sleeps past it (plus a
small margin), and retries the **same** crate, up to five attempts per
crate. Multiple windows in one run are survived the same way, which is
why the job timeout is six hours. If a crate is still rate-limited
after five attempts, that crate is marked `failed:rate-limit`, the run
stops in order, and the fix is simply: re-dispatch later. Everything
already published is detected and skipped; the run resumes exactly
where it died.

Transient errors (5xx, network, timeouts) get a separate short retry:
three attempts with growing backoff. Auth failures (401/403/credential
problems) abort the whole run immediately with a pointer at
`CARGO_REGISTRY_TOKEN` — retrying those is pointless.

## Crash-safe resume

The plan is rebuilt from the live registry on every dispatch, so a
re-dispatch after any failure — rate limit, crash, cancelled run —
continues where the previous run stopped:

- crates already at the target version are skipped,
- crates at an older version publish the update,
- crates never published publish for the first time.

There is no separate resume switch; run the same workflow again. The
concurrency group (`publish-crates`) serializes runs so two dispatches
never race the same set.

## Tags and the end-of-run summary

After a real (non-dry) run, every crate that reached the registry in
this run — whether published now or skipped because an earlier run
already uploaded it — gets a `<crate>-v<version>` tag created and
pushed if it does not exist. Those tags are exactly what the CHANGELOG
`[Unreleased]: …/compare/<crate>-v<version>...HEAD` and
`[<version>]: …/releases/tag/<crate>-v<version>` links point at.
Tagging skipped crates too is what heals links after a failed run
published some crates but died before the tagging step.

The final **Publish summary** step lists every crate's disposition
(`published-new` / `published-update` / `skipped-already-indexed` /
`failed:<reason>`, plus `would-publish-*` in dry runs), any crate the
run never reached, and the counts. The job exits nonzero if anything
failed or was left unattempted.

## Rolling back a bad version: yank

There is no unpublish on crates.io; the rollback is a yank, and it is
manual on purpose — automating it risks yanking good versions on a
flaky signal. To pull a bad version:

```console
$ cargo yank toride-xyz@0.2.0
```

(run with `CARGO_REGISTRY_TOKEN` set, or from a machine with
`cargo login`). A yanked version:

- cannot be newly resolved — new `cargo add` / builds picking the
  version fail,
- keeps working for every existing `Cargo.lock` that already pins it,
- leaves the version listed on crates.io, marked "yanked".

Undo with `cargo yank --undo toride-xyz@0.2.0` if the version turns
out fine. A yanked version number can never be re-uploaded, so the
fix itself is always a new version: bump, changelog entry, dispatch.

## Verifying locally

- `cargo package -p <crate> --list` — what will ship in the tarball
  (pass `--allow-dirty` when the working tree has uncommitted changes).
- `cargo publish --dry-run -p toride-diagnostic-types` (any crate
  without intra-set deps) — full packaging verification including the
  tarball build.
- `bash scripts/test-publish-state.sh` — the classification unit
  tests, no network needed.
- Name availability: `curl -s -o /dev/null -w '%{http_code}' -A
  "toride-publish-check" https://crates.io/api/v1/crates/<name>` — 404
  means the name is free. A User-Agent is required; bare curl gets 403.

## Crates.io pages

- https://crates.io/crates/toride-diagnostic-types
- https://crates.io/crates/toride-fs
- https://crates.io/crates/toride-runner
- https://crates.io/crates/toride-installer
- https://crates.io/crates/toride-registry
- https://crates.io/crates/toride-mise
- https://crates.io/crates/toride-apps
- https://crates.io/crates/toride-service
- https://crates.io/crates/toride-ssh-core
- https://crates.io/crates/toride-status
- https://crates.io/crates/toride-audit
- https://crates.io/crates/toride-backup
- https://crates.io/crates/toride-cloud
- https://crates.io/crates/toride-fail2ban
- https://crates.io/crates/toride-harden
- https://crates.io/crates/toride-monitor
- https://crates.io/crates/toride-proxy
- https://crates.io/crates/toride-ssh-agent
- https://crates.io/crates/toride-ssh-authorized-keys
- https://crates.io/crates/toride-ssh-certificate
- https://crates.io/crates/toride-ssh-config
- https://crates.io/crates/toride-ssh-forward
- https://crates.io/crates/toride-ssh-known-hosts
- https://crates.io/crates/toride-tailscale
- https://crates.io/crates/toride-updates
- https://crates.io/crates/toride-users
- https://crates.io/crates/toride-wireguard
- https://crates.io/crates/ufw-kit
- https://crates.io/crates/toride-ssh-doctor
- https://crates.io/crates/toride-ssh-key
- https://crates.io/crates/ufw-kit-test-support
- https://crates.io/crates/toride-ssh
- https://crates.io/crates/toride
