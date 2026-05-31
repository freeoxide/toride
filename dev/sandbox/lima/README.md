# Toride Lima Sandbox

Destructive integration testing for Toride using [Lima](https://lima-vm.io/) Linux VMs on macOS.

## Prerequisites

- macOS (Apple Silicon or Intel)
- [Homebrew](https://brew.sh/)
- [Lima](https://lima-vm.io/) ≥ 2.0 — `brew install lima`
- [Zig](https://ziglang.org/) + [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild) — for cross-compiling Linux binaries

```bash
brew install lima zig
cargo install cargo-zigbuild
rustup target add aarch64-unknown-linux-musl x86_64-unknown-linux-musl
```

Verify:

```bash
limactl --version          # >= 2.0
rustup target list --installed  # should include both musl targets
```

## Quick Start

```bash
# Create an Ubuntu 24.04 sandbox VM
dev/sandbox/lima/scripts/create.sh ubuntu-24.04

# Build Toride for Linux and run it in the VM
dev/sandbox/lima/scripts/run.sh ubuntu-24.04

# Reset to clean state before next test
dev/sandbox/lima/scripts/reset.sh ubuntu-24.04

# Destroy when done
dev/sandbox/lima/scripts/destroy.sh ubuntu-24.04
```

## Scripts

| Script | Purpose |
|--------|---------|
| `create.sh <distro>` | Create VM, install baseline tools, snapshot as `clean` |
| `reset.sh <distro>` | Restore `clean` snapshot (falls back to delete+recreate) |
| `run.sh <distro>` | Build/copy binary, reset VM, run dry-run, collect artifacts |
| `destroy.sh <distro>` | Delete VM (preserves images and artifacts) |
| `matrix.sh` | Run a command against multiple distros |

All scripts accept `--help`.

## Distro Matrix

| Distro | Instance Name | Resources | Priority |
|--------|--------------|-----------|----------|
| Ubuntu 24.04 LTS | `toride-u2404` | 2 CPU / 4 GiB / 24 GiB | Primary |
| Ubuntu 26.04 LTS | `toride-u2604` | 2 CPU / 6 GiB / 32 GiB | Primary |
| Debian 12 | `toride-d12` | 2 CPU / 3 GiB / 20 GiB | Primary |
| Debian 13 | `toride-d13` | 2 CPU / 4 GiB / 24 GiB | Primary |
| Rocky Linux 9 | `toride-r9` | 2 CPU / 4 GiB / 24 GiB | Secondary |
| Rocky Linux 10 | `toride-r10` | 2 CPU / 4 GiB / 24 GiB | Secondary |

## Directory Layout

```text
dev/sandbox/lima/
├── README.md           ← you are here
├── images/             ← user-supplied cloud images (gitignored)
│   ├── ubuntu-24.04/
│   ├── ubuntu-26.04/
│   ├── debian-12/
│   ├── debian-13/
│   ├── rocky-9/
│   └── rocky-10/
├── templates/          ← Lima YAML templates
│   ├── ubuntu-24.04.yaml
│   ├── ubuntu-26.04.yaml
│   ├── debian-12.yaml
│   ├── debian-13.yaml
│   ├── rocky-9.yaml
│   └── rocky-10.yaml
└── scripts/            ← lifecycle scripts
    ├── create.sh
    ├── reset.sh
    ├── run.sh
    ├── destroy.sh
    └── matrix.sh
```

## Images

Place cloud images under `images/<distro>/`:

```text
images/ubuntu-24.04/
├── image-aarch64.qcow2
├── image-x86_64.qcow2
└── SHA256SUMS
```

If no local images are provided, scripts fall back to Lima's built-in templates (which download official cloud images automatically).

**Do not commit VM images.** The `.gitignore` excludes `*.qcow2`, `*.img`, `*.raw`, `*.iso` under `images/`.

## Agent Safety Rules

- Never run Toride apply on the macOS host
- Never mount the repo writable into a destructive guest
- Never reuse a VM without restoring `clean` first
- Never assume a distro from instance name — check `/etc/os-release`
- Never assume `systemd`, `apt`, or `dnf` locks are ready after boot
- Never assume Lima SSH survives firewall/SSH-hardening tests
- Always collect logs before destroying a failed VM

## More Details

See [`docs/lima-sandbox.md`](../../../docs/lima-sandbox.md) for the full runbook including:
- Built-in template fallback strategy
- Snapshot lifecycle and delete-and-recreate fallback
- SSH and firewall risk model
- Artifact collection
- Distro-specific notes
