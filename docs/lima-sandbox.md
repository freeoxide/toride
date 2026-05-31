# Lima Sandbox Runbook

This document defines how Toride should use Lima for destructive Linux testing.

Toride mutates real Linux state: packages, users, groups, SSH daemon config, firewall rules, Docker, services, files under `/etc`, and reboot-persistent settings. Docker is useful for narrow dry-run checks, but destructive apply tests need real Linux VMs that can be reset or recreated.

Audit status, last checked 2026-05-30:

* Lima docs were checked through Context7 and the live Lima docs.
* Lima is not installed in this workspace, so local `limactl` execution was not validated here.
* Current upstream Lima templates include the target lanes used below: Ubuntu 24.04, Ubuntu 26.04, Debian 12, Debian 13, Rocky 9, and Rocky 10.
* `limactl snapshot *` is documented but experimental. In current upstream source, the VZ driver returns snapshot operations as unimplemented; use QEMU for snapshot-based reset, or use delete/recreate for VZ.
* `limactl show-ssh` is deprecated. Use Lima's generated SSH config: `ssh -F ~/.lima/<instance>/ssh.config lima-<instance>`.
* Current Toride repo state has a TUI welcome app, but no destructive `dry-run` or `apply` executor yet. CLI examples below describe the intended contract.

---

# What Lima Must Prove

The Lima lane is the destructive integration layer. It must prove that Toride can safely mutate real Linux machines and still preserve access.

Required behavior:

* Every destructive test starts from a known clean VM state.
* The target distro is verified with `/etc/os-release`, not inferred from the instance name.
* SSH reconnect is tested before and after SSH/firewall changes.
* Firewall allow/block assertions are tested from outside the target VM, not from inside the same guest.
* Reboot persistence is tested after service, SSH, firewall, sudoers, Docker, or Fail2Ban changes.
* Logs and state are collected before a broken VM is destroyed when SSH still works.

---

# Distro Matrix

Primary release gates:

| Lane | Instance | Lima template | Notes |
| --- | --- | --- | --- |
| Ubuntu 24.04 LTS | `toride-u2404` | `ubuntu-24.04` | First lane to keep green. |
| Ubuntu 26.04 LTS | `toride-u2604` | `ubuntu-26.04` | Current forward-looking Ubuntu LTS. |
| Debian 12 | `toride-d12` | `debian-12` | Existing VPS baseline; now oldstable. |
| Debian 13 | `toride-d13` | `debian-13` | Current Debian stable. |
| Rocky Linux 9 | `toride-r9` | `rocky-9` | Mature RHEL-compatible lane. |
| Rocky Linux 10 | `toride-r10` | `rocky-10` | Requires x86-64-v3 on x86_64. |

Optional later: AlmaLinux 9/10, Fedora, openSUSE Leap, Arch Linux.

Always check available templates first:

```bash
limactl create --list-templates
```

Do not use `template:ubuntu` for an LTS lane; Lima's `ubuntu` alias tracks a current Ubuntu template and may not be the LTS target. Do not use `template:default` for destructive Toride tests; it includes Lima defaults such as container tooling that are less VPS-like.

---

# Host Requirements

Assumed host:

* macOS with Homebrew
* Apple Silicon or Intel Mac
* Enough disk for multiple VM disks and artifact output

Install and verify Lima:

```bash
brew install lima
limactl --version
limactl list
limactl create --list-templates
```

Require Lima 2.x or newer for this plan. If a needed template, `--mount-none`, `--network`, `limactl copy`, `limactl validate`, or `limactl snapshot` is missing, upgrade Lima before continuing.

For automation, use explicit non-interactive flags:

```bash
limactl create --tty=false ...
limactl start --tty=false ...
```

The command reference still lists `-y, --yes` as an alias for `--tty=false`, but the deprecated-features page marks `limactl --yes` deprecated in Lima 2.0.0. Use `--tty=false` in scripts.

---

# VM Driver And Reset Strategy

Choose the driver based on the reset mechanism, not just performance.

| Driver | Use for | Reset strategy | Notes |
| --- | --- | --- | --- |
| `vz` | Fast native macOS smoke/destructive runs | Delete/recreate | Snapshot operations are not implemented by current VZ driver. |
| `qemu` | Snapshot-based destructive loops | `limactl snapshot create/apply --tag clean` | Slower, but supports Lima snapshot operations. Required for cross-arch VM testing. |

Recommended default:

* Use `vz` for quick smoke runs and normal local iteration when delete/recreate is acceptable.
* Use `qemu` for repeated destructive matrix runs that need fast rollback through Lima snapshots.
* If using Apple Silicon to run `x86_64` guests, use QEMU and expect it to be slow.

Snapshot commands:

```bash
limactl stop toride-u2404
limactl snapshot create toride-u2404 --tag clean
limactl snapshot apply toride-u2404 --tag clean
limactl snapshot list toride-u2404
```

Delete/recreate fallback:

```bash
limactl stop toride-u2404 || true
limactl delete -f toride-u2404
limactl create --tty=false --name=toride-u2404 --mount-none dev/sandbox/lima/templates/ubuntu-24.04.yaml
limactl start toride-u2404
```

Snapshots are reset points, not durable backups. Keep the source image, checksum, generated template, scripts, and artifact logs as the durable evidence.

---

# Network Test Modes

Lima networking has distinct behaviors. Every firewall test must declare its mode.

| Mode | Lima network | Use for | Not enough for |
| --- | --- | --- | --- |
| A | Default user-mode | Package, users, sudo, services, local smoke tests | Proving external port blocking. |
| B | Host SSH config | Reconnect guard for Lima control path | Public internet behavior. |
| C | VM IP from host | Host-to-guest service checks via `vzNAT` or `socket_vmnet` | VM-to-VM attacker model. |
| D | `lima:user-v2` or shared named network | Guest-to-guest attacker/prober checks | Provider/public IPv4/IPv6 behavior. |
| E | Real VPS | Final canary before release | Fast local iteration. |

Important Lima networking facts:

* The default guest IP is not reachable from the host or other guests.
* `user-v2` supports VM-to-VM communication and `lima-<name>.internal` names from inside guests.
* Enabling `user-v2` disables the default user-mode network; do not mix default-network assumptions into user-v2 tests.
* Host access to `user-v2` VM names needs `limactl tunnel`, which is experimental.
* `vzNAT` gives a VZ VM an IP reachable from the host, not from other guests.
* `socket_vmnet` can give a guest IP reachable from the host and other guests, but it needs secure root-owned installation and sudoers setup.
* Bridged behavior and public internet exposure still require a real VPS canary.

Attacker VM examples:

```bash
limactl start --tty=false --name=toride-netprobe --network=lima:user-v2 template:ubuntu-24.04
limactl start --tty=false --name=toride-u2404 --network=lima:user-v2 template:ubuntu-24.04
limactl shell toride-netprobe -- nc -vz lima-toride-u2404.internal 22
limactl shell toride-netprobe -- nc -vz -w 3 lima-toride-u2404.internal 8080
```

---

# Directory Layout

Create Lima assets under `dev/sandbox/lima/` when implementation starts:

```text
dev/sandbox/lima/
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
    |-- netprobe.sh
    |-- destroy.sh
    `-- matrix.sh
```

Do not commit VM images or generated disks:

```gitignore
dev/sandbox/lima/images/**/*.qcow2
dev/sandbox/lima/images/**/*.img
dev/sandbox/lima/images/**/*.raw
dev/sandbox/lima/images/**/*.iso
```

---

# Image Contract

Preferred local image layout:

```text
dev/sandbox/lima/images/<distro>/
|-- image-aarch64.qcow2
|-- image-x86_64.qcow2
`-- SHA256SUMS
```

Rules:

* Prefer cloud images with cloud-init support.
* Accept `.qcow2`, `.img`, or `.raw` cloud images.
* Avoid ISO installer images in the normal loop; they are slower and harder to automate.
* Verify checksums before use.
* If only one architecture is supplied, set the template `arch` to that architecture.

Checksum example:

```bash
cd dev/sandbox/lima/images/ubuntu-24.04
shasum -a 256 -c SHA256SUMS
```

---

# Template Shape

Use this as the generated template baseline. Set `vmType` to `qemu` for snapshot lanes and `vz` for fast delete/recreate lanes.

```yaml
minimumLimaVersion: "2.0.0"
vmType: qemu
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
      #!/bin/sh
      set -eux
      if command -v cloud-init >/dev/null 2>&1; then
        cloud-init status --wait || true
      fi
      if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y ca-certificates curl sudo openssh-server systemd systemd-sysv iproute2 netcat-openbsd
      elif command -v dnf >/dev/null 2>&1; then
        dnf install -y ca-certificates curl sudo openssh-server systemd iproute nmap-ncat
      fi
      systemctl enable ssh || systemctl enable sshd || true
      systemctl start ssh || systemctl start sshd || true
```

Notes:

* `mounts: []` is intentional; destructive guest commands should not touch the host repo.
* Copy binaries into `/tmp` or `/opt/toride-test`.
* Use absolute local image paths.
* Avoid QEMU `9p` mounts for destructive test lanes; mounts are disabled anyway.
* For Ubuntu 26.04, use at least `6GiB` memory if package-heavy flows are slow.
* For Rocky 10 on x86_64, verify CPU compatibility with x86-64-v3 early.

Built-in template fallback:

```bash
limactl start --tty=false --name=toride-u2404 --mount-none template:ubuntu-24.04
limactl start --tty=false --name=toride-u2604 --mount-none template:ubuntu-26.04
limactl start --tty=false --name=toride-d12 --mount-none template:debian-12
limactl start --tty=false --name=toride-d13 --mount-none template:debian-13
limactl start --tty=false --name=toride-r9 --mount-none template:rocky-9
limactl start --tty=false --name=toride-r10 --mount-none template:rocky-10
```

---

# Baseline Lifecycle

For every distro:

1. Create VM from template.
2. Boot and wait for cloud-init/package locks.
3. Install only baseline test tools.
4. Verify OS, architecture, SSH, sudo, package manager, and systemd.
5. For QEMU lanes, stop and create `clean` snapshot.
6. Before each destructive test, restore `clean` or delete/recreate.
7. Copy the Linux Toride binary.
8. Run dry-run, then apply.
9. Run reconnect, network, syntax, IPv6, and reboot checks.
10. Collect logs.

Basic validation:

```bash
limactl shell <instance> cat /etc/os-release
limactl shell <instance> uname -m
limactl shell <instance> systemctl is-system-running || true
limactl shell <instance> command -v sudo
limactl shell <instance> command -v curl
limactl shell <instance> -- bash -lc 'command -v sshd || test -x /usr/sbin/sshd'
```

---

# Running Toride In The Guest

Do not copy a macOS `target/release/toride` binary into Linux. Build Linux targets on the host or in a separate builder VM.

Host cross-build setup:

```bash
brew install zig
cargo install cargo-zigbuild
rustup target add aarch64-unknown-linux-musl
rustup target add x86_64-unknown-linux-musl
```

Build:

```bash
cargo zigbuild --release --target aarch64-unknown-linux-musl
cargo zigbuild --release --target x86_64-unknown-linux-musl
```

Guest architecture mapping:

```text
aarch64 -> target/aarch64-unknown-linux-musl/release/toride
x86_64  -> target/x86_64-unknown-linux-musl/release/toride
```

Copy and smoke test:

```bash
limactl copy ./target/aarch64-unknown-linux-musl/release/toride toride-u2404:/tmp/toride
limactl shell toride-u2404 chmod +x /tmp/toride
limactl shell toride-u2404 /tmp/toride --version || true
```

Intended future destructive contract:

```bash
limactl shell toride-u2404 /tmp/toride --dry-run
limactl shell toride-u2404 sudo /tmp/toride apply --profile sandbox
```

Until Toride has non-interactive `dry-run` and `apply`, Lima can only validate binary transfer/execution and interactive TUI startup.

---

# Required Destructive Cases

Each primary distro should eventually pass:

* Dry-run changes nothing.
* Apply is idempotent: first run changes, second run no-ops.
* SSH password login is disabled while key login still works.
* Root SSH login is disabled.
* A configured sudo user can reconnect and run the expected sudo flow.
* SSH is allowed before enabling firewall rules.
* A known closed test port is blocked from the attacker VM.
* Explicitly opened ports are reachable from the attacker VM.
* Fail2Ban installs, starts, and creates expected jail state when enabled.
* Docker installs, starts, is enabled, and survives reboot when enabled.
* Reboot after apply preserves SSH access.
* Toride prints recovery guidance before risky SSH/firewall steps.

---

# Dangerous-Change Gates

Toride should validate syntax before activating dangerous config:

```bash
sudo /usr/sbin/sshd -t
sudo visudo -cf /etc/sudoers
sudo visudo -cf /etc/sudoers.d/<toride-file>
sudo nft -c -f <ruleset-file>
sudo ufw --dry-run enable
```

These gates catch syntax errors only. They do not replace reconnect and attacker-VM tests.

---

# SSH Reconnect Guard

Lima control commands depend on guest SSH:

```bash
limactl shell <instance> ...
limactl copy <source> <instance>:<target>
```

Any Toride profile that touches SSH, users, sudo, UFW, nftables, or Fail2Ban must prove the future login path before and after the risky step:

```bash
INSTANCE=toride-u2404
SSH_CONFIG="$HOME/.lima/$INSTANCE/ssh.config"
SSH_ALIAS="lima-$INSTANCE"
ssh -F "$SSH_CONFIG" "$SSH_ALIAS" true
```

If this fails before hardening, Toride should refuse to continue. If it fails after hardening, collect what is still reachable and reset the VM.

---

# Reboot Checks

Run a reboot phase after successful apply when persistent system state changed:

```bash
INSTANCE=toride-u2404
SSH_CONFIG="$HOME/.lima/$INSTANCE/ssh.config"
SSH_ALIAS="lima-$INSTANCE"

limactl shell "$INSTANCE" sudo reboot || true

for _ in $(seq 1 60); do
  if ssh -F "$SSH_CONFIG" "$SSH_ALIAS" true; then
    break
  fi
  sleep 2
done

ssh -F "$SSH_CONFIG" "$SSH_ALIAS" 'systemctl is-system-running || true'
ssh -F "$SSH_CONFIG" "$SSH_ALIAS" 'systemctl is-enabled docker 2>/dev/null || true'
ssh -F "$SSH_CONFIG" "$SSH_ALIAS" 'systemctl is-active fail2ban 2>/dev/null || true'
```

The pass condition is not merely that the VM boots; the supported login method and enabled services must survive boot.

---

# IPv6 Firewall Checks

If the guest has IPv6, firewall tests must cover IPv6. Collect:

```bash
limactl shell <instance> ip -6 addr
limactl shell <instance> sudo ss -tulpn
limactl shell <instance> sudo nft list ruleset
limactl shell <instance> sudo ufw status verbose || true
limactl shell <instance> sudo ufw status numbered || true
limactl shell <instance> -- bash -lc 'test -f /etc/default/ufw && grep "^IPV6=" /etc/default/ufw || true'
```

Expected checks:

* UFW profiles should keep `IPV6=yes` unless Toride explicitly documents IPv4-only behavior.
* `nft list ruleset` should show equivalent IPv4 and IPv6 intent, or a documented asymmetry.
* Attacker VM probes should test IPv4 and IPv6 separately when both are present.
* A service bound to `::` must be considered externally exposed unless firewall rules block it.

---

# Artifact Collection

Create a host artifact directory per instance/test:

```bash
mkdir -p .sandbox-artifacts/toride-u2404
```

Collect generic state:

```bash
limactl shell toride-u2404 journalctl -b --no-pager > .sandbox-artifacts/toride-u2404/journal.txt
limactl shell toride-u2404 systemctl --failed --no-pager > .sandbox-artifacts/toride-u2404/systemd-failed.txt
limactl shell toride-u2404 cat /etc/os-release > .sandbox-artifacts/toride-u2404/os-release.txt
limactl shell toride-u2404 sudo ss -tulpn > .sandbox-artifacts/toride-u2404/ports.txt
limactl shell toride-u2404 ip -6 addr > .sandbox-artifacts/toride-u2404/ipv6-addresses.txt
limactl shell toride-u2404 sudo nft list ruleset > .sandbox-artifacts/toride-u2404/nft-ruleset.txt || true
limactl shell toride-u2404 sudo ufw status verbose > .sandbox-artifacts/toride-u2404/ufw-status.txt || true
```

Debian/Ubuntu:

```bash
limactl shell toride-u2404 sudo tail -n 300 /var/log/apt/history.log > .sandbox-artifacts/toride-u2404/apt-history.txt
limactl shell toride-u2404 sudo tail -n 500 /var/log/dpkg.log > .sandbox-artifacts/toride-u2404/dpkg.txt
```

Rocky:

```bash
limactl shell toride-r10 sudo dnf history > .sandbox-artifacts/toride-r10/dnf-history.txt
limactl shell toride-r10 rpm -qa > .sandbox-artifacts/toride-r10/rpm-qa.txt
```

If SSH is broken, stop using `limactl shell` for diagnosis and reset or recreate the VM.

---

# Script Contracts

`create.sh <distro>`:

* Validate Lima version and required commands.
* Validate template existence with `limactl create --list-templates`.
* Validate generated YAML with `limactl validate <template>`.
* Verify local image checksums.
* Create and start the instance.
* Wait for cloud-init and boot readiness.
* Create `clean` snapshot only for QEMU lanes.

`reset.sh <distro>`:

* For QEMU snapshot lanes, stop, apply `clean`, start, and validate OS/systemd.
* For VZ lanes, delete/recreate.
* Never delete user-supplied source images.

`run.sh <distro> --profile sandbox`:

* Reject macOS binaries.
* Match binary architecture to `uname -m`.
* Reset first.
* Copy to `/tmp/toride`.
* Run binary smoke test, dry-run, optional apply, syntax gates, reconnect, netprobe, reboot checks, and artifact collection.

`netprobe.sh <target> --from <probe>`:

* Ensure probe and target are different VMs.
* Discover or accept target address/name.
* Probe SSH, a known blocked port, explicitly opened ports, IPv4, and IPv6 where present.
* Store output under target artifacts.

`matrix.sh <distro...>`:

* Run lanes independently.
* Keep artifacts separate.
* Continue after failures unless `--fail-fast` is set.
* Exit non-zero if any lane fails.

`destroy.sh <distro>`:

* Stop and delete the VM.
* Do not delete user-supplied images.
* Delete artifacts only with an explicit flag.

---

# Agent Safety Rules

* Never run Toride apply on the macOS host.
* Never mount the host repo writable into destructive guests by default.
* Never reuse a destructive VM without reset/recreate first.
* Never infer distro from instance name; check `/etc/os-release`.
* Never assume systemd, apt, dnf, SSH, or firewall state.
* Never treat same-VM firewall probes as external proof.
* Never apply SSH hardening unless the future SSH login path works first.
* Never rely on VZ snapshots; use QEMU snapshots or delete/recreate.
* Never run a macOS-built binary in a Linux guest.
* Never manually repair a broken sandbox unless debugging that exact failure.
* Always collect logs before destroying when SSH still works.

---

# Real VPS Canary

Run a disposable VPS canary before release after the Lima matrix passes.

Validate:

* provider image differences
* public IPv4 and IPv6 exposure
* provider firewall interaction
* Cloudflare-only allowlists, if supported by Toride profiles
* SSH hardening on a public address
* reboot persistence on provider boot paths
* recovery instructions before risky changes

The VPS canary is not the development loop. If it fails, capture artifacts, destroy it if needed, and reproduce locally in Lima or a focused VPS repro.

---

# References

* Lima docs: https://lima-vm.io/docs/
* Lima installation: https://lima-vm.io/docs/installation/
* Lima templates: https://lima-vm.io/docs/templates/
* Lima command reference: https://lima-vm.io/docs/reference/
* Lima start flags: https://lima-vm.io/docs/reference/limactl_start/
* Lima SSH usage: https://lima-vm.io/docs/usage/ssh/
* Lima deprecated features: https://lima-vm.io/docs/releases/deprecated/
* Lima experimental features: https://lima-vm.io/docs/releases/experimental/
* Lima networking: https://lima-vm.io/docs/config/network/
* Lima default user-mode networking: https://lima-vm.io/docs/config/network/user/
* Lima user-v2 networking: https://lima-vm.io/docs/config/network/user-v2/
* Lima VMNet networking: https://lima-vm.io/docs/config/network/vmnet/
* Lima snapshots: https://lima-vm.io/docs/reference/limactl_snapshot/
* Lima snapshot command source audited at `06fb9e3945a1c103677d8fe488dfa87bc5ffd3f1`: https://github.com/lima-vm/lima/blob/06fb9e3945a1c103677d8fe488dfa87bc5ffd3f1/cmd/limactl/snapshot.go
* Lima VZ driver source audited at `06fb9e3945a1c103677d8fe488dfa87bc5ffd3f1`: https://github.com/lima-vm/lima/blob/06fb9e3945a1c103677d8fe488dfa87bc5ffd3f1/pkg/driver/vz/vz_driver_darwin.go
* Lima copy: https://lima-vm.io/docs/reference/limactl_copy/
* Lima validate: https://lima-vm.io/docs/reference/limactl_validate/
* Ubuntu 26.04 release notes: https://documentation.ubuntu.com/release-notes/26.04/
* Debian releases: https://www.debian.org/releases/
* Rocky Linux images: https://wiki.rockylinux.org/rocky/image/
* Rocky Linux 10 release notes: https://docs.rockylinux.org/release_notes/10_0/
* Rocky Linux 10 minimum hardware requirements: https://docs.rockylinux.org/guides/minimum_hardware_requirements/
* UFW man page: https://manpages.ubuntu.com/manpages/jammy/man8/ufw.8.html
* nftables man page: https://manpages.ubuntu.com/manpages/noble/man8/nftables.8.html
* OpenSSH `sshd` man page: https://man7.org/linux/man-pages/man8/sshd.8.html
* sudo `visudo` man page: https://www.sudo.ws/docs/man/visudo.man/
