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

declare -A DISTRO_INSTANCE=(
  [ubuntu-24.04]=toride-u2404
  [ubuntu-26.04]=toride-u2604
  [debian-12]=toride-d12
  [debian-13]=toride-d13
  [rocky-9]=toride-r9
  [rocky-10]=toride-r10
)

# ── Helpers ────────────────────────────────────────────────────────────────────

info()  { printf '\033[1;34m[reset]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[reset]\033[0m %s\n' "$*" >&2; }
error() { printf '\033[1;31m[reset]\033[0m %s\n' "$*" >&2; exit 1; }

# ── Arg parsing ────────────────────────────────────────────────────────────────

DISTRO=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      echo "Usage: $0 <distro>"
      echo "Distros: ${!DISTRO_INSTANCE[*]}"
      exit 0
      ;;
    *) DISTRO="$1"; shift ;;
  esac
done

[[ -z "$DISTRO" ]] && error "Usage: $0 <distro>  (distros: ${!DISTRO_INSTANCE[*]})"
INSTANCE="${DISTRO_INSTANCE[$DISTRO]:?Unknown distro: $DISTRO}"
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

OS_RELEASE="$(limactl shell "$INSTANCE" -- cat /etc/os-release 2>/dev/null || true)"
if [[ -z "$OS_RELEASE" ]]; then
  error "Could not read /etc/os-release from '$INSTANCE'. VM may be broken."
fi
info "$OS_RELEASE"

SYSTEMD_STATUS="$(limactl shell "$INSTANCE" -- systemctl is-system-running 2>/dev/null || echo 'unknown')"
info "systemd status: $SYSTEMD_STATUS"

if [[ "$SYSTEMD_STATUS" == "offline" || "$SYSTEMD_STATUS" == "unknown" ]]; then
  warn "systemd is not operational ($SYSTEMD_STATUS). Consider delete-and-recreate."
fi

info "'$INSTANCE' ($DISTRO) reset to 'clean' snapshot and ready."
