#!/usr/bin/env bash
# reset.sh — Restore a Lima sandbox VM to its 'clean' snapshot.
# See docs/lima-sandbox.md → Script Contracts → reset.sh
#
# Falls back to delete-and-recreate when snapshots are unavailable or fail.
#
# Usage:
#   dev/sandbox/lima/scripts/reset.sh ubuntu-24.04
#
set -euo pipefail

# ── Constants ──────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TEMPLATE_DIR="$SANDBOX_DIR/templates"
REPO_ROOT="$(cd "$SANDBOX_DIR/../.." && pwd)"

ALL_DISTROS="ubuntu-24.04 ubuntu-26.04 debian-12 debian-13 rocky-9 rocky-10"

distro_to_instance() {
  case "$1" in
    ubuntu-24.04) echo "toride-u2404" ;;
    ubuntu-26.04) echo "toride-u2604" ;;
    debian-12)    echo "toride-d12" ;;
    debian-13)    echo "toride-d13" ;;
    rocky-9)      echo "toride-r9" ;;
    rocky-10)     echo "toride-r10" ;;
    *)            return 1 ;;
  esac
}

# ── Helpers ────────────────────────────────────────────────────────────────────

info()  { printf '\033[1;34m[reset]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[reset]\033[0m %s\n' "$*" >&2; }
error() { printf '\033[1;31m[reset]\033[0m %s\n' "$*" >&2; exit 1; }

verify_distro() {
  local instance="$1" distro="$2"
  local os_release guest_id guest_ver expected_id expected_ver

  os_release="$(limactl shell "$instance" -- cat /etc/os-release 2>/dev/null || true)"
  if [[ -z "$os_release" ]]; then
    error "Could not read /etc/os-release from '$instance'. VM may be broken."
  fi

  guest_id="$(echo "$os_release" | grep '^ID=' | head -1 | cut -d= -f2)"
  guest_ver="$(echo "$os_release" | grep '^VERSION_ID=' | head -1 | cut -d= -f2 | tr -d '"')"
  expected_id="${distro%%-*}"
  expected_ver="${distro#*-}"

  if [[ "$guest_id" != "$expected_id" || "$guest_ver" != "$expected_ver" ]]; then
    error "Guest distro mismatch: expected '$expected_id $expected_ver' but got '$guest_id $guest_ver' (instance '$instance'). Consider delete-and-recreate."
  fi

  info "Guest identity confirmed: $guest_id $guest_ver"
}

# ── Arg parsing ────────────────────────────────────────────────────────────────

DISTRO=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      echo "Usage: $0 <distro>"
      echo "Distros: $ALL_DISTROS"
      exit 0
      ;;
    *) DISTRO="$1"; shift ;;
  esac
done

[[ -z "$DISTRO" ]] && error "Usage: $0 <distro>  (distros: $ALL_DISTROS)"
INSTANCE="$(distro_to_instance "$DISTRO")" || error "Unknown distro: $DISTRO"
TEMPLATE="$TEMPLATE_DIR/${DISTRO}.yaml"

# ── Verify instance exists ────────────────────────────────────────────────────

if ! limactl list --format '{{.Name}}' 2>/dev/null | grep -qxF "$INSTANCE"; then
  error "Instance '$INSTANCE' does not exist. Create it first: dev/sandbox/lima/scripts/create.sh $DISTRO"
fi

# ── Stop the VM ───────────────────────────────────────────────────────────────

info "Stopping '$INSTANCE'..."
limactl stop "$INSTANCE" 2>/dev/null || true

# ── Try snapshot restore ─────────────────────────────────────────────────────

SNAPSHOT_OK=false

if limactl snapshot --help &>/dev/null; then
  if limactl snapshot list "$INSTANCE" 2>/dev/null | grep -q "clean"; then
    info "Restoring 'clean' snapshot..."
    if limactl snapshot apply "$INSTANCE" --tag clean; then
      SNAPSHOT_OK=true
      info "Snapshot restored."
    else
      warn "Snapshot restore failed. Falling back to delete-and-recreate."
    fi
  else
    warn "No 'clean' snapshot found for '$INSTANCE'. Falling back to delete-and-recreate."
  fi
else
  warn "Snapshot support not available. Falling back to delete-and-recreate."
fi

# ── Fallback: delete and recreate ────────────────────────────────────────────

if [[ "$SNAPSHOT_OK" != true ]]; then
  info "Delete-and-recreate fallback for '$INSTANCE'..."
  limactl stop "$INSTANCE" 2>/dev/null || true
  limactl delete -f "$INSTANCE" 2>/dev/null || true

  # Delegate to create.sh which handles template selection, validation, etc.
  "$SCRIPT_DIR/create.sh" "$DISTRO" --recreate
  # create.sh handles start + snapshot creation; we're done.
  exit 0
fi

# ── Start the VM ──────────────────────────────────────────────────────────────

info "Starting '$INSTANCE'..."
limactl start "$INSTANCE"

# ── Verify guest state ───────────────────────────────────────────────────────

info "Verifying guest identity..."
verify_distro "$INSTANCE" "$DISTRO"

SYSTEMD_STATUS="$(limactl shell "$INSTANCE" -- systemctl is-system-running 2>/dev/null || echo 'unknown')"
info "systemd status: $SYSTEMD_STATUS"

if [[ "$SYSTEMD_STATUS" == "degraded" ]]; then
  warn "systemd is degraded. Listing failed units:"
  limactl shell "$INSTANCE" -- systemctl --failed --no-pager 2>/dev/null || true
fi

if [[ "$SYSTEMD_STATUS" == "offline" || "$SYSTEMD_STATUS" == "unknown" ]]; then
  warn "systemd is not operational ($SYSTEMD_STATUS). Falling back to delete-and-recreate."
  limactl stop "$INSTANCE" 2>&1 || true
  limactl delete -f "$INSTANCE" 2>&1 || true
  "$SCRIPT_DIR/create.sh" "$DISTRO" --recreate
  exit 0
fi

info "'$INSTANCE' ($DISTRO) reset to 'clean' snapshot and ready."
