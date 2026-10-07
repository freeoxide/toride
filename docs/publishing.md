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

## Feature policy

Heavy features stay off the default sets, so depending on any of the
library-layer crates with bare `version = "0.x"` pulls the minimal graph
(plan 3.1):

| Crate | Off default | Opt-in pulls |
|-------|-------------|--------------|
| toride-runner | `tokio-runner`, `stream`, `serde`, `fake` | tokio, async-trait |
| toride-registry | `http` | reqwest, flate2, tokio, dirs |
| toride-installer | `http` | reqwest, sha2, tar, flate2, xz2 |
| toride-mise | `bootstrap`, `tracing`, `miette`, `blocking` | reqwest, tar |
| toride-apps | `tokio`, `registry-http`, `direct`, `mise` | tokio, reqwest, xz2 |

Changing a default feature set after a release is breaking: flip
defaults only in a release that bumps the minor (0.x) or major version,
and record the flip in the crate's CHANGELOG.

## Releasing

1. Bump `version` in the root `Cargo.toml` `[workspace.package]`.
2. Update every intra-set dependency requirement in the crate
   manifests to match (`toride-xyz = { path = "...", version = "<new>" }`).
   The publish workflow fails the run if any requirement drifts from the
   released version.
3. Add a CHANGELOG.md entry to each crate that changed.
4. Run the **Publish crates** workflow (Actions → Publish crates → Run
   workflow) with `dry_run` enabled. The gate step re-runs fmt, clippy
   (`-D warnings`), tests, and the non-default feature configurations,
   and fails the run if the `PUBLISH_SET` order, the version lockstep,
   or the single-version rule regresses. Only the order-blocked dry-run
   failure — an intra-set dependency absent from crates.io ("no matching
   package") or not yet published at the required version ("failed to
   select a version") — is downgraded to a warning; any other dry-run
   failure fails the run.
5. Re-run with `dry_run` disabled. Each crate is verified with
   `cargo publish --dry-run`, uploaded, and held until crates.io
   resolves it before the next crate starts. Afterwards the workflow
   tags each crate as `<crate>-v<version>` and pushes the tags — the
   references the CHANGELOG `[Unreleased]` and `[0.1.0]` links point
   at.

Partial failures are safe to re-run: versions already on crates.io are
detected and skipped.

`CARGO_REGISTRY_TOKEN` must be configured as a repository secret.

## Verifying locally

- `cargo package -p <crate> --list` — what will ship in the tarball (pass
  `--allow-dirty` when the working tree has uncommitted changes).
- `cargo publish --dry-run -p toride-diagnostic-types` (any crate
  without intra-set deps) — full packaging verification including the
  tarball build.
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
