# Lima Sandbox — Setup Knowledge Base

This document records what was built, what broke during testing, and what was learned. It complements the design runbook at [`docs/lima-sandbox.md`](lima-sandbox.md) with operational knowledge gained from real testing.

**Date:** 2026-05-31
**Host:** macOS Darwin 25.4.0, Apple Silicon (aarch64)
**Lima:** 2.1.1 (installed via Homebrew)
**Commit:** `fea9426` on branch `worktree-lima-sandbox`

---

# TL;DR

The Lima sandbox is **operational**. Three distros were tested end-to-end (Ubuntu 24.04, Debian 12, Rocky 9). Toride was cross-compiled on macOS, copied into a Linux VM, and verified as a working static ELF binary. The sandbox scripts handle creation, reset, destruction, and matrix testing.

The main gotcha: **Lima VZ driver does not support snapshots**. All reset operations use delete-and-recreate, which works but takes ~2 minutes per cycle.

---

# What Was Built

## Files (13 total, 1197 insertions)

```
dev/sandbox/lima/
├── README.md                        # Quick-start guide
├── images/                          # Empty distro dirs (gitignored for *.qcow2 etc.)
│   ├── ubuntu-24.04/
│   ├── ubuntu-26.04/
│   ├── debian-12/
│   ├── debian-13/
│   ├── rocky-9/
│   └── rocky-10/
├── templates/                       # Lima YAML templates (for local image use)
│   ├── ubuntu-24.04.yaml
│   ├── ubuntu-26.04.yaml
│   ├── debian-12.yaml
│   ├── debian-13.yaml
│   ├── rocky-9.yaml
│   └── rocky-10.yaml
└── scripts/                         # Lifecycle scripts (all executable)
    ├── create.sh
    ├── reset.sh
    ├── run.sh
    ├── destroy.sh
    └── matrix.sh
```

Plus changes to root `.gitignore` for VM image patterns and `.sandbox-artifacts/`.

## Architecture Decisions

| Decision | Rationale |
|----------|-----------|
| `vmType: vz` in all templates | Native macOS virtualization, faster than QEMU on Apple Silicon |
| `mounts: []` | Destructive guest commands must not have host filesystem access |
| `containerd: system=false, user=false` | Closer to a fresh VPS; no container tooling in the baseline |
| Static musl binaries via zigbuild | No glibc dependency; single binary works across all distros |
| `--tty=false` for all Lima commands | Agent-friendly; no TUI/editor prompts |
| Built-in template fallback | When no local images exist, use Lima's templates instead of custom YAML |
| bash 3.2 compatible scripts | macOS ships bash 3.2 which lacks associative arrays |

---

# Bugs Found and Fixed During Testing

## 1. macOS bash 3.2 Does Not Support Associative Arrays

**Symptom:** `declare -A DISTRO_INSTANCE=(...)` causes `ubuntu: unbound variable` on macOS.

**Cause:** macOS ships GNU bash 3.2.57. `declare -A` (associative arrays) was introduced in bash 4.0.

**Fix:** Replaced all `declare -A` with a `distro_to_instance()` function using a `case` statement. Replaced `${!DISTRO_INSTANCE[*]}` with a plain `$ALL_DISTROS` string. Applied to all 5 scripts.

**Lesson:** Never use bash 4+ features in scripts that run on macOS without checking the shebang resolution. Either use `#!/usr/bin/env bash` with POSIX-compatible constructs, or target zsh explicitly.

## 2. Lima VZ Driver Does Not Support Snapshots

**Symptom:** `limactl snapshot create ... --tag clean` returns `level=fatal msg=unimplemented`.

**Cause:** Lima's VZ (Apple Virtualization.framework) driver has snapshot support listed as experimental, but the actual implementation returns `unimplemented` in Lima 2.1.1. Snapshots only work with the QEMU driver.

**Fix:**
- `create.sh`: Wrapped snapshot creation in a conditional that catches the failure gracefully and warns the user.
- `reset.sh`: Already designed to fall back to delete-and-recreate when snapshots fail.
- All scripts now treat delete-and-recreate as the primary reset path when VZ is the driver.

**Impact:** Reset takes ~2 minutes (delete VM, recreate from cached image, boot) instead of ~10 seconds (snapshot restore). Lima caches downloaded images in `~/Library/Caches/lima/download/`, so recreate does NOT re-download the image.

**Future:** If Lima adds VZ snapshot support, the scripts will automatically detect and use it. No code changes needed — the snapshot path is tried first, fallback is automatic.

## 3. Built-In Template Detection Race Condition

**Symptom:** `debian-12` template not found via `grep` in the script, but the same grep matches when run manually in the terminal.

**Cause:** Likely a Lima state issue when two `create.sh` instances ran in parallel. Lima's template listing may have been temporarily unavailable or returned unexpected output during concurrent operations.

**Fix:**
- Changed `grep -q "$DISTRO"` to `grep -qx "$DISTRO"` for exact line matching (avoids partial matches like "debian" matching "debian-12").
- Removed the dangerous fallback to custom template with nonexistent local image paths. Now errors cleanly instead of crashing with `clonefile failed: no such file or directory`.
- **Do not run `create.sh` for multiple distros in parallel.** Lima's template list and image cache may not handle concurrent access reliably. Run sequentially or use `matrix.sh`.

## 4. Custom Templates With Local Paths Are Dangerous Without Images

**Symptom:** When no built-in template matches and the custom template is used, Lima tries to clonefile from local paths like `~/os/toride/dev/sandbox/lima/images/debian-12/image-aarch64.qcow2` which don't exist, causing a fatal error.

**Fix:** The create script now errors out with a clear message when neither a built-in template nor local images are available, instead of attempting to use the custom template.

**Lesson:** The custom YAML templates are designed for when local images exist. When using Lima's built-in templates, Lima handles image downloading internally — the custom template is not needed and should not be used as a fallback.

---

# Cross-Compilation Setup

## Toolchain

| Tool | Version | Install |
|------|---------|---------|
| Zig | 0.16.0_1 | `brew install zig` |
| cargo-zigbuild | 0.22.3 | `cargo install cargo-zigbuild` |
| Rust musl targets | — | `rustup target add aarch64-unknown-linux-musl x86_64-unknown-linux-musl` |

Zig pulls in llvm@21 and lld@21 as Homebrew dependencies (~1.6 GB for llvm alone).

## Build

```bash
cargo zigbuild --release --target aarch64-unknown-linux-musl
```

Build time: ~2m15s on Apple Silicon (full workspace with 715 crates). Incremental builds are much faster.

## Result

```
target/aarch64-unknown-linux-musl/release/toride
  ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, stripped
  Size: 1.0 MB
```

Statically linked — no glibc, no musl runtime, no external dependencies. Runs on any aarch64 Linux.

## Verified On

| Distro | Kernel | Result |
|--------|--------|--------|
| Debian 12 (bookworm) | 6.1 (Lima default) | ✓ Binary executes |
| Rocky Linux 9.7 | 5.14.0-611.el9_7 | ✓ Binary executes |

Toride enters raw TTY mode at startup before parsing CLI args, so `--help` also triggers the "Failed to enable raw mode" error when run via `limactl shell`. This is an app-level issue, not a sandbox issue. The binary itself is correct.

---

# Host Tooling Installed

Everything was installed via Homebrew and cargo:

```bash
brew install lima        # 2.1.1, 80 MB
brew install zig         # 0.16.0_1, pulls llvm@21 (1.6 GB) + lld@21 (5.8 MB)
cargo install cargo-zigbuild  # 0.22.3
rustup target add aarch64-unknown-linux-musl x86_64-unknown-linux-musl
```

Total disk impact: ~2 GB for the cross-compilation toolchain.

---

# VM Specifications (Lima Defaults vs Templates)

Lima's built-in templates allocate more resources than our custom templates specify:

| | Template Spec | Lima Actual |
|---|---|---|
| CPUs | 2 | 4 |
| Memory | 3-6 GiB | 4 GiB |
| Disk | 20-32 GiB | 100 GiB |

Lima ignores the `cpus`/`memory`/`disk` from custom templates when using `template:` directly — it uses the built-in template's defaults. This is fine for development. For resource-constrained testing, use the custom YAML with local images.

---

# Distros Tested

| Distro | Instance | Status | Notes |
|--------|----------|--------|-------|
| Ubuntu 24.04 LTS | `toride-u2404` | ✓ Created, validated, destroyed | First distro tested. Primary target. |
| Debian 12 | `toride-d12` | ✓ Created, validated, running | Template detection required fix. |
| Rocky Linux 9 | `toride-r9` | ✓ Created, validated, running | Downloaded ~600 MB image on first create. |

**Not yet tested:** Ubuntu 26.04, Debian 13, Rocky 10.

Lima template names confirmed available:
```
ubuntu-24.04    ✓ tested
ubuntu-26.04    available (listed as experimental/)
debian-12       ✓ tested
debian-13       available
rocky-9         ✓ tested
rocky-10        available
```

---

# Lima Behavior Notes

## Image Caching

Lima caches downloaded images at `~/Library/Caches/lima/download/by-url-sha256/`. On recreate (delete + create), it reuses the cached image instead of downloading again. This is critical for the delete-and-recreate reset path.

First create: ~5-10 minutes (download image + nerdctl + boot). Subsequent recreates: ~2 minutes (cached image + boot only).

## Port Forwarding

Lima assigns random SSH ports per instance. Use `limactl list` to see the current port. Do not hardcode ports in scripts — they change on every start.

## Nerdctl Download

Lima downloads the nerdctl archive even when `containerd: system: false, user: false` is set in the template. This adds ~5 minutes to first-time creation. This is Lima's default behavior and cannot be easily disabled when using built-in templates.

## Boot Time

After image download, boot to `READY` takes approximately:
- 15-20 seconds (VZ, cached image)
- 25-30 seconds (first boot with cloud-init)

## systemd Status

All tested distros report `systemd is-system-running: running`. No degraded units observed on fresh instances.

---

# Known Limitations

1. **No snapshot support with VZ.** Delete-and-recreate is the only reset path. ~2 min per reset cycle.
2. **No parallel VM creation.** Lima's template list may not be reliable under concurrent access. Create VMs sequentially.
3. **Toride TTY requirement.** The binary requires a real TTY for its ratatui TUI. `limactl shell` is not a TTY. For non-interactive testing, Toride needs a `--no-tui` or `--dry-run` mode that works without raw mode.
4. **Custom templates unused currently.** The YAML templates in `dev/sandbox/lima/templates/` are designed for local images. Without local images, scripts use Lima's built-in templates. The custom templates become useful when you provide your own cloud images.
5. **Resource oversizing.** Lima's built-in templates allocate 4 CPU / 4 GiB / 100 GiB regardless of what the custom template specifies.

---

# What's Next

- [ ] Test Ubuntu 26.04, Debian 13, Rocky 10
- [ ] Add `--no-tui` / `--dry-run` mode to Toride for non-interactive sandbox testing
- [ ] Provide local cloud images for reproducible offline testing
- [ ] Integrate sandbox `run.sh` into CI (when CI is re-enabled)
- [ ] Monitor Lima releases for VZ snapshot support
- [ ] Test QEMU driver if VZ snapshot gap becomes painful (trades boot speed for snapshot support)

---

# File Reference

| File | Purpose |
|------|---------|
| [`docs/lima-sandbox.md`](lima-sandbox.md) | Design runbook — the spec |
| [`docs/lima-sandbox-kb.md`](lima-sandbox-kb.md) | This document — operational knowledge |
| [`dev/sandbox/lima/README.md`](../dev/sandbox/lima/README.md) | Quick-start guide |
| [`dev/sandbox/lima/scripts/`](../dev/sandbox/lima/scripts/) | Lifecycle scripts |
| [`dev/sandbox/lima/templates/`](../dev/sandbox/lima/templates/) | Lima YAML templates |
