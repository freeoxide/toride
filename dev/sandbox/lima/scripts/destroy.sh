#!/usr/bin/env bash
# destroy.sh — Delete a Lima sandbox VM.
# See docs/lima-sandbox.md → Script Contracts → destroy.sh
#
# Usage:
#   dev/sandbox/lima/scripts/destroy.sh ubuntu-24.04
#   dev/sandbox/lima/scripts/destroy.sh ubuntu-24.04 --artifacts
#
set -euo pipefail

# ── Constants ──────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$SANDBOX_DIR/../.." && pwd)"
ARTIFACTS_DIR="$REPO_ROOT/.sandbox-artifacts"
IMAGES_DIR="$SANDBOX_DIR/images"

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

info()  { printf '\033[1;34m[destroy]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[destroy]\033[0m %s\n' "$*" >&2; }
error() { printf '\033[1;31m[destroy]\033[0m %s\n' "$*" >&2; exit 1; }

# ── Arg parsing ────────────────────────────────────────────────────────────────

DISTRO=""
REMOVE_ARTIFACTS=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifacts) REMOVE_ARTIFACTS=true; shift ;;
    -h|--help)
      echo "Usage: $0 <distro> [--artifacts]"
      echo ""
      echo "Options:"
      echo "  --artifacts   Also remove collected artifacts"
      echo ""
      echo "Distros: $ALL_DISTROS"
      exit 0
      ;;
    *)
      if [[ -z "$DISTRO" ]]; then
        DISTRO="$1"
      else
        error "Unknown argument: $1"
      fi
      shift
      ;;
  esac
done

[[ -z "$DISTRO" ]] && error "Usage: $0 <distro> [--artifacts]  (distros: $ALL_DISTROS)"
INSTANCE="$(distro_to_instance "$DISTRO")" || error "Unknown distro: $DISTRO"

# ── Check instance exists ────────────────────────────────────────────────────

if ! limactl list --format '{{.Name}}' 2>/dev/null | grep -qxF "$INSTANCE"; then
  warn "Instance '$INSTANCE' does not exist. Nothing to destroy."
  exit 0
fi

# ── Collect logs before destroying (if possible) ──────────────────────────────

ARTIFACT_DIR="$ARTIFACTS_DIR/$INSTANCE"
mkdir -p "$ARTIFACT_DIR"

info "Collecting final artifacts from '$INSTANCE'..."

limactl shell "$INSTANCE" -- journalctl -b --no-pager > "$ARTIFACT_DIR/journal-final.txt" 2>/dev/null || true
limactl shell "$INSTANCE" -- systemctl --failed --no-pager > "$ARTIFACT_DIR/systemd-failed-final.txt" 2>/dev/null || true
limactl shell "$INSTANCE" -- cat /etc/os-release > "$ARTIFACT_DIR/os-release-final.txt" 2>/dev/null || true

info "Final artifacts saved to $ARTIFACT_DIR"

# ── Stop and delete VM ───────────────────────────────────────────────────────

info "Stopping '$INSTANCE'..."
limactl stop "$INSTANCE" 2>/dev/null || true

info "Deleting '$INSTANCE'..."
limactl delete -f "$INSTANCE" 2>/dev/null || true

info "Instance '$INSTANCE' deleted."

# ── Remove artifacts if requested ────────────────────────────────────────────

if [[ "$REMOVE_ARTIFACTS" == true ]]; then
  if [[ -d "$ARTIFACT_DIR" ]]; then
    info "Removing artifacts: $ARTIFACT_DIR"
    rm -rf "$ARTIFACT_DIR"
  fi
fi

# ── Never delete user-supplied images ────────────────────────────────────────

info "User-supplied images in $IMAGES_DIR/$DISTRO are preserved."

info "Done. To recreate: dev/sandbox/lima/scripts/create.sh $DISTRO"
