# Lima Sandbox Runbook

This document defines how Toride should use Lima for destructive Linux testing.

Toride is a guided VPS setup tool. Its apply path will intentionally mutate a machine: package manager state, users, groups, SSH daemon configuration, firewall rules, Docker, services, files under `/etc`, and sometimes reboot-required state. The sandbox must therefore be a real Linux VM that can be destroyed or restored quickly.

Lima is the preferred local sandbox runner because it is CLI-first, lightweight on macOS, supports multiple Linux distributions, provides SSH access, file sharing, port forwarding, and snapshot commands, and can be driven by an AI agent without a GUI.

Audit status:

* Lima is not installed in the current development workspace, so local command execution could not be validated here.
* Commands and template names in this document were cross-checked against Lima's current public docs on 2026-05-14.
* Lima snapshots are documented but marked experimental by Lima. Scripts must support a delete-and-recreate fallback.
* The sandbox flow is workable for the current repo state, but Toride itself is not implemented yet beyond `src/main.rs`. The destructive apply examples describe the intended CLI once Toride has apply/dry-run commands.

---

# Goals

The Lima sandbox must support:

* Repeated destructive Toride runs without damaging the host.
* Fast reset back to a known-clean baseline.
* Multiple target distributions.
* Real `systemd`, real package managers, real users, real services, and real network behavior.
* Host-to-guest binary transfer for locally built Toride artifacts.
* Agent-friendly commands that can be scripted without opening a GUI.
* Clear teardown when a VM is corrupted beyond repair.

The sandbox is not a substitute for unit tests, dry-run tests, or PTY E2E tests. It is the destructive integration layer.

---

# Recommended Distro Matrix

Toride should keep a small but representative matrix.

## Primary

These should be tested before trusting a release:

* Ubuntu 24.04 LTS
* Ubuntu 26.04 LTS
* Debian 12
* Debian 13

## Secondary

These are important for later compatibility work:

* Rocky Linux 9
* Rocky Linux 10

## Optional Later

Add only after the primary matrix is reliable:

* AlmaLinux 9 / 10
* Fedora Server
* openSUSE Leap
* Arch Linux

---

# Why Not Docker

Docker containers are useful for narrow tests, but they are not the main sandbox for Toride.

Containers do not reliably match VPS behavior for:

* `systemd`
* SSH daemon lifecycle
* UFW and nftables behavior
* Docker installation and Docker-in-Docker
* kernel modules and cgroups
* reboot-required state
* service enablement
* cloud-init behavior
* package lock timing on fresh boot

Use containers only for command rendering, package detection, and dry-run checks. Use Lima VMs for destructive apply tests.

---

# Host Requirements

Assumed host:

* macOS
* Homebrew installed
* Enough disk for multiple VM disks
* Apple Silicon or Intel Mac

Install Lima:

```bash
brew install lima
```

Verify:

```bash
limactl --version
limactl list
```

On macOS, prefer Lima's native virtualization backend where possible:

```yaml
vmType: vz
```

If a guest image fails under `vz`, fall back to QEMU for that distro:

```yaml
vmType: qemu
```

For automation, prefer non-interactive Lima commands:

```bash
limactl start -y ...
limactl create -y ...
```

`-y` disables Lima's TUI/editor prompts.

---

# Directory Layout

Use a repo-local sandbox directory for templates and agent scripts:

```text
dev/
`-- sandbox/
    `-- lima/
        |-- README.md
        |-- images/
        |   |-- ubuntu-24.04/
        |   |-- ubuntu-26.04/
        |   |-- debian-12/
        |   |-- debian-13/
        |   |-- rocky-9/
        |   `-- rocky-10/
        |-- templates/
        |   |-- ubuntu-24.04.yaml
        |   |-- ubuntu-26.04.yaml
        |   |-- debian-12.yaml
        |   |-- debian-13.yaml
        |   |-- rocky-9.yaml
        |   `-- rocky-10.yaml
        `-- scripts/
            |-- create.sh
            |-- reset.sh
            |-- run.sh
            |-- destroy.sh
            `-- matrix.sh
```

The user may provide initial images under `dev/sandbox/lima/images/<distro>/`. The agent should use those images when present. If no local image is present, the agent may use a Lima built-in template or an official cloud image URL.

Do not commit large VM image files. Add this ignore rule when the directory is created:

```gitignore
dev/sandbox/lima/images/**/*.qcow2
dev/sandbox/lima/images/**/*.img
dev/sandbox/lima/images/**/*.raw
dev/sandbox/lima/images/**/*.iso
```

---

# Image Input Contract

The AI agent expects each supplied image directory to contain:

```text
dev/sandbox/lima/images/<distro>/
|-- image-aarch64.qcow2
|-- image-x86_64.qcow2
`-- SHA256SUMS
```

Preferred image format:

* `qcow2` cloud image

Accepted with caveats:

* `.img` cloud image
* `.raw` disk image
* `.iso` installer image

Avoid ISO images for the normal test loop. ISO installation is slower and harder to automate. Cloud images are the right default because Lima can boot them with cloud-init-style provisioning.

The `SHA256SUMS` file should contain a hash for the image:

```text
<sha256>  image-aarch64.qcow2
<sha256>  image-x86_64.qcow2
```

Verify before use:

```bash
cd dev/sandbox/lima/images/ubuntu-24.04
shasum -a 256 -c SHA256SUMS
```

If only one architecture is provided, the template for that distro must set `arch` to that architecture and must not pretend the same image supports both `aarch64` and `x86_64`.

For Apple Silicon Macs, use `aarch64` images by default. Use `x86_64` only when testing x86-specific behavior, and expect it to be slower because it requires emulation. For Intel Macs, use `x86_64`.

Cross-architecture testing on Apple Silicon should use QEMU:

```yaml
vmType: qemu
arch: x86_64
```

Native-architecture testing should use `vz` where possible.

---

# Instance Naming

Use stable names:

```text
toride-u2404
toride-u2604
toride-d12
toride-d13
toride-r9
toride-r10
```

Do not use random instance names in scripts. Stable names make cleanup and agent recovery simpler.

---

# Baseline Lifecycle

Every distro follows the same lifecycle:

1. Create VM from template.
2. Boot VM.
3. Wait for cloud-init and package manager locks.
4. Install only baseline tools needed for testing.
5. Stop VM.
6. Create `clean` snapshot.
7. For each destructive test, restore `clean`, start, run Toride, collect logs.
8. Destroy and recreate if restore cannot recover the VM.

The important invariant:

> Toride apply tests always start from the `clean` snapshot.

---

# Generic Lima Template

Use this as the baseline shape for templates.

```yaml
# dev/sandbox/lima/templates/ubuntu-24.04.yaml
minimumLimaVersion: "2.0.0"
vmType: vz
arch: default
cpus: 2
memory: 4GiB
disk: 24GiB

images:
  - location: "/ABS/PATH/TO/dev/sandbox/lima/images/ubuntu-24.04/image-aarch64.qcow2"
    arch: "aarch64"
  - location: "/ABS/PATH/TO/dev/sandbox/lima/images/ubuntu-24.04/image-x86_64.qcow2"
    arch: "x86_64"

mounts: []

containerd:
  system: false
  user: false

provision:
  - mode: system
    script: |
      set -eux
      if command -v cloud-init >/dev/null 2>&1; then
        cloud-init status --wait || true
      fi
      if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y ca-certificates curl sudo openssh-server systemd systemd-sysv iproute2
      elif command -v dnf >/dev/null 2>&1; then
        dnf install -y ca-certificates curl sudo openssh-server systemd iproute
      fi
      systemctl enable ssh || systemctl enable sshd || true
      systemctl start ssh || systemctl start sshd || true
```

Notes:

* Host mounts are disabled by default. This is intentional: destructive guest commands should not receive direct filesystem access to the host repo.
* Copy test binaries into `/tmp` or `/opt/toride-test` inside the guest before running them.
* Use absolute local image paths in generated YAML. This avoids ambiguity about whether Lima resolves relative paths from the repo root, current shell directory, or template location.
* Use `4GiB` memory by default. Increase to `6GiB` or `8GiB` for Ubuntu 26.04 if heavy package flows become slow.
* For Rocky 10, verify the image supports the host CPU architecture. Rocky 10 changed some architecture baselines on x86.
* If a distro only works under QEMU, change `vmType` to `qemu`. Do not use QEMU `9p` mounts with Rocky/Alma-style guests; Lima documents 9p incompatibility with those kernels.

---

# Built-In Template Fallback

If no user-supplied image exists, use Lima's templates where available:

```bash
limactl start -y --name=toride-u2404 --mount-none template:ubuntu-24.04
limactl start -y --name=toride-u2604 --mount-none template:ubuntu-26.04
limactl start -y --name=toride-d12 --mount-none template:debian-12
limactl start -y --name=toride-d13 --mount-none template:debian-13
limactl start -y --name=toride-r9 --mount-none template:rocky-9
limactl start -y --name=toride-r10 --mount-none template:rocky-10
```

Template names can change by Lima version. The agent must check available templates before assuming a name:

```bash
limactl start --list-templates
```

If the exact distro template is missing, use a custom YAML with an official cloud image URL or ask the user for the image.

Do not use `template:ubuntu` for the Ubuntu LTS test lane. Lima's `ubuntu` alias may point at the newest interim release, not the LTS version Toride wants to validate.

---

# Creating a VM

From the repo root:

```bash
limactl create -y --name=toride-u2404 --mount-none dev/sandbox/lima/templates/ubuntu-24.04.yaml
limactl start toride-u2404
```

Check status:

```bash
limactl list
limactl shell toride-u2404 uname -a
limactl shell toride-u2404 cat /etc/os-release
```

Check `systemd`:

```bash
limactl shell toride-u2404 systemctl is-system-running
```

`degraded` is acceptable immediately after boot if the failed unit is irrelevant to the test. `offline` or `Failed to connect to bus` is not acceptable for Toride integration testing.

---

# Creating the Clean Snapshot

After the baseline setup finishes:

```bash
limactl stop toride-u2404
limactl snapshot create toride-u2404 --tag clean
limactl snapshot list toride-u2404
```

The `clean` snapshot should represent a fresh VPS-like state:

* package metadata updated once
* SSH server installed and running
* sudo available
* no Toride changes applied
* no Docker installed unless the base cloud image already includes it
* no UFW changes unless the base cloud image already includes them
* no extra users except image defaults

Do not create a snapshot after running Toride unless it is explicitly named for debugging.

---

# Resetting Before Every Test

Before every destructive apply test:

```bash
limactl stop toride-u2404 || true
limactl snapshot apply toride-u2404 --tag clean
limactl start toride-u2404
```

Then verify the guest identity:

```bash
limactl shell toride-u2404 cat /etc/os-release
limactl shell toride-u2404 id
limactl shell toride-u2404 systemctl is-system-running || true
```

The agent should treat failed snapshot restore as a reason to destroy and recreate the instance.

Because Lima snapshots are experimental, every script must support this slower fallback:

```bash
limactl stop toride-u2404 || true
limactl delete -f toride-u2404
limactl create -y --name=toride-u2404 --mount-none dev/sandbox/lima/templates/ubuntu-24.04.yaml
limactl start toride-u2404
limactl stop toride-u2404
limactl snapshot create toride-u2404 --tag clean
limactl start toride-u2404
```

If snapshots prove unreliable for a given Lima version or VM driver, delete-and-recreate becomes the canonical reset path for that lane.

---

# Snapshots Are Not Backups

For Toride testing, a Lima snapshot is a fast local reset point, not a durable backup.

Keep these durable inputs instead:

* the original user-supplied cloud image
* the image checksum file
* the generated Lima template
* sandbox scripts
* collected test artifacts

If a VM becomes valuable for debugging, export evidence from it before deleting it:

```bash
mkdir -p .sandbox-artifacts/toride-u2404/debug
limactl shell toride-u2404 journalctl -b --no-pager > .sandbox-artifacts/toride-u2404/debug/journal.txt
limactl shell toride-u2404 systemctl --failed --no-pager > .sandbox-artifacts/toride-u2404/debug/systemd-failed.txt
limactl shell toride-u2404 cat /etc/os-release > .sandbox-artifacts/toride-u2404/debug/os-release.txt
```

Do not depend on snapshots to move state between machines. Recreate VMs from images and templates instead.

---

# Running Toride in the Guest

Do not copy `target/release/toride` from a macOS host into the Linux guest. That binary is a macOS binary and will not execute in Linux.

Recommended build path: produce static Linux binaries on the host, matching the guest architecture. This aligns with Toride's release plan for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`.

Install the cross-build tooling once on the host:

```bash
brew install zig
cargo install cargo-zigbuild
rustup target add aarch64-unknown-linux-musl
rustup target add x86_64-unknown-linux-musl
```

Build both Linux binaries:

```bash
cargo zigbuild --release --target aarch64-unknown-linux-musl
cargo zigbuild --release --target x86_64-unknown-linux-musl
```

Select the binary that matches the guest:

```bash
limactl shell toride-u2404 uname -m
```

Mapping:

```text
aarch64 -> target/aarch64-unknown-linux-musl/release/toride
x86_64  -> target/x86_64-unknown-linux-musl/release/toride
```

Copy into the guest:

```bash
limactl copy ./target/aarch64-unknown-linux-musl/release/toride toride-u2404:/tmp/toride
limactl shell toride-u2404 chmod +x /tmp/toride
```

Verify it is executable in Linux:

```bash
limactl shell toride-u2404 /tmp/toride --version || limactl shell toride-u2404 /tmp/toride
```

Run dry-run first:

```bash
limactl shell toride-u2404 /tmp/toride --dry-run
```

Run apply only after dry-run is sane:

```bash
limactl shell toride-u2404 sudo /tmp/toride apply --profile sandbox
```

If Toride is interactive-only at that point in development, run an interactive shell:

```bash
limactl shell toride-u2404
sudo /tmp/toride
```

The final scripted CLI shape may change as Toride evolves. The sandbox contract should remain stable: reset, copy binary, run dry-run, run apply, collect logs.

Current repo reality: as of this document, `src/main.rs` only prints `Hello, world!`. The sandbox can already validate that a Linux binary transfers and executes, but it cannot validate destructive Toride behavior until the executor and CLI commands exist.

Fallback build path: if host cross-compilation is blocked, build inside a separate non-destructive builder VM, not inside the clean destructive test VM. The destructive VM should start as close to a fresh VPS as possible before Toride runs.

---

# Collecting Logs

Create a host artifact directory:

```bash
mkdir -p .sandbox-artifacts/toride-u2404
```

Collect guest state:

```bash
limactl shell toride-u2404 journalctl -b --no-pager > .sandbox-artifacts/toride-u2404/journal.txt
limactl shell toride-u2404 systemctl --failed --no-pager > .sandbox-artifacts/toride-u2404/systemd-failed.txt
limactl shell toride-u2404 cat /etc/os-release > .sandbox-artifacts/toride-u2404/os-release.txt
limactl shell toride-u2404 ss -tulpn > .sandbox-artifacts/toride-u2404/ports.txt
```

For Debian/Ubuntu:

```bash
limactl shell toride-u2404 sudo tail -n 300 /var/log/apt/history.log > .sandbox-artifacts/toride-u2404/apt-history.txt
limactl shell toride-u2404 sudo tail -n 500 /var/log/dpkg.log > .sandbox-artifacts/toride-u2404/dpkg.txt
```

For Rocky:

```bash
limactl shell toride-r10 sudo dnf history > .sandbox-artifacts/toride-r10/dnf-history.txt
limactl shell toride-r10 rpm -qa > .sandbox-artifacts/toride-r10/rpm-qa.txt
```

If Toride writes its own logs, copy those too:

```bash
limactl shell toride-u2404 -- bash -lc 'find ~/.local/state ~/.cache /var/log -iname "*toride*" 2>/dev/null'
```

---

# Destroying a Broken VM

If a test breaks SSH, systemd, package management, or Lima connectivity:

```bash
limactl stop toride-u2404 || true
limactl delete -f toride-u2404
```

Then recreate from template and remake the clean snapshot.

Do not spend time manually repairing a sandbox unless the broken state is the bug being investigated.

---

# Script Contracts

The future `dev/sandbox/lima/scripts/` commands should be thin wrappers around Lima.

## create.sh

Create or recreate one instance.

```bash
dev/sandbox/lima/scripts/create.sh ubuntu-24.04
```

Expected behavior:

* validates Lima is installed
* validates the Lima version has `snapshot`, `copy`, `start --list-templates`, and `--mount-none`
* validates the template exists
* runs `limactl validate <template>`
* validates the image checksum when using local images
* creates the named instance
* starts it
* waits for boot readiness
* creates the `clean` snapshot, replacing an existing clean snapshot only after explicit `--recreate`

## reset.sh

Restore an instance to `clean`.

```bash
dev/sandbox/lima/scripts/reset.sh ubuntu-24.04
```

Expected behavior:

* stops the VM if needed
* applies `clean`
* starts the VM
* checks `/etc/os-release`
* checks `systemd`
* falls back to delete-and-recreate when snapshots are unavailable or fail

## run.sh

Run Toride in one VM.

```bash
dev/sandbox/lima/scripts/run.sh ubuntu-24.04 --profile sandbox
```

Expected behavior:

* builds or accepts a host binary path
* resets the VM first
* copies the binary into `/tmp/toride`
* runs dry-run
* optionally runs apply
* collects artifacts

## matrix.sh

Run a command against multiple VMs.

```bash
dev/sandbox/lima/scripts/matrix.sh ubuntu-24.04 debian-13 rocky-10
```

Expected behavior:

* runs each distro independently
* keeps artifacts separate
* continues after a distro fails unless `--fail-fast` is passed
* exits non-zero if any distro failed

## destroy.sh

Delete one instance.

```bash
dev/sandbox/lima/scripts/destroy.sh ubuntu-24.04
```

Expected behavior:

* stops the VM if needed
* deletes the VM
* does not delete user-supplied images
* does not delete artifacts unless `--artifacts` is passed

---

# Agent Safety Rules

An AI agent operating these sandboxes must follow these rules:

* Never run Toride apply directly on the macOS host.
* Never mount the repo writable into a destructive guest by default.
* Never reuse a VM for apply testing without restoring `clean` first.
* Never assume a distro from the instance name; check `/etc/os-release`.
* Never assume `systemd` works; check it.
* Never assume `apt` or `dnf` locks are free immediately after boot.
* Never repair a broken sandbox manually unless debugging that exact failure.
* Never commit downloaded VM images or generated VM disks.
* Always collect logs before destroying a failed VM when possible.

---

# Validation Checklist

Each sandbox image is acceptable when these pass:

```bash
limactl shell <instance> cat /etc/os-release
limactl shell <instance> uname -m
limactl shell <instance> systemctl is-system-running || true
limactl shell <instance> command -v sudo
limactl shell <instance> command -v curl
limactl shell <instance> -- bash -lc 'command -v sshd || command -v ssh'
```

For Debian/Ubuntu:

```bash
limactl shell <instance> command -v apt-get
limactl shell <instance> sudo apt-get update
```

For Rocky:

```bash
limactl shell <instance> command -v dnf
limactl shell <instance> sudo dnf makecache
```

Snapshot validation:

```bash
limactl stop <instance>
limactl snapshot create <instance> --tag clean
limactl snapshot apply <instance> --tag clean
limactl start <instance>
limactl shell <instance> cat /etc/os-release
```

---

# Distro-Specific Notes

## Ubuntu 24.04 LTS

This should be the first and most frequently used sandbox. It is a current common VPS baseline and already listed as a Toride target.

Recommended resources:

```text
2 CPU
4 GiB memory
24 GiB disk
```

## Ubuntu 26.04 LTS

Use this as the forward-looking Ubuntu target. It may require more memory for heavier flows.

Recommended resources:

```text
2 CPU
6 GiB memory
32 GiB disk
```

## Debian 12

Use this as the conservative Debian target. It remains important for existing VPS providers and older production machines.

Recommended resources:

```text
2 CPU
3 GiB memory
20 GiB disk
```

## Debian 13

Use this as the current Debian stable target.

Recommended resources:

```text
2 CPU
4 GiB memory
24 GiB disk
```

## Rocky Linux 9

Use this for RHEL-compatible behavior with mature package support.

Recommended resources:

```text
2 CPU
4 GiB memory
24 GiB disk
```

## Rocky Linux 10

Use this for current RHEL-compatible behavior. Verify architecture compatibility early, especially on Intel hosts, because newer enterprise distributions may raise CPU baselines.

Recommended resources:

```text
2 CPU
4 GiB memory
24 GiB disk
```

---

# Failure Modes To Expect

## Cloud-init still running

Fresh cloud images may still be initializing when the agent connects.

Check:

```bash
limactl shell <instance> cloud-init status --wait
```

## Package manager locks

APT and DNF can be busy immediately after boot.

Toride itself should handle this, but sandbox scripts may also wait before test setup.

## SSH service name differs

Debian/Ubuntu often use `ssh`; Rocky commonly uses `sshd`.

Use both:

```bash
systemctl status ssh || systemctl status sshd
```

## systemd degraded

Some cloud images boot with harmless degraded units. Capture the failed unit list before deciding:

```bash
systemctl --failed --no-pager
```

## Snapshot chain gets slow

Long snapshot chains can hurt performance. Keep only:

* `clean`
* one temporary debug snapshot when actively investigating

Delete old debug snapshots.

---

# References

* Lima docs: https://lima-vm.io/docs/
* Lima templates: https://lima-vm.io/docs/templates/
* Lima command reference: https://lima-vm.io/docs/reference/
* Debian cloud images: https://wiki.debian.org/Cloud
* Debian 13 release information: https://www.debian.org/releases/stable/
* Ubuntu 26.04 release notes: https://documentation.ubuntu.com/release-notes/26.04/
* Ubuntu release cycle: https://ubuntu.com/about/release-cycle
* Rocky Linux images: https://wiki.rockylinux.org/rocky/image/
* Rocky Linux versions: https://wiki.rockylinux.org/rocky/version/
