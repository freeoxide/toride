#!/usr/bin/env bash
# create.sh — Create or recreate a Lima sandbox VM for Toride testing.
# See docs/lima-sandbox.md → Script Contracts → create.sh
#
# Usage:
#   dev/sandbox/lima/scripts/create.sh ubuntu-24.04
#   dev/sandbox/lima/scripts/create.sh ubuntu-24.04 --recreate
#
set -euo pipefail

# ── Constants ──────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TEMPLATE_DIR="$SANDBOX_DIR/templates"
IMAGES_DIR="$SANDBOX_DIR/images"
REPO_ROOT="$(cd "$SANDBOX_DIR/../.." && pwd)"
ARTIFACTS_DIR="$REPO_ROOT/.sandbox-artifacts"

MINIMUM_LIMA_VERSION="2.0.0"

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

info()  { printf '\033[1;34m[create]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[create]\033[0m %s\n' "$*" >&2; }
error() { printf '\033[1;31m[create]\033[0m %s\n' "$*" >&2; exit 1; }

# Verify guest /etc/os-release matches expected distro.
# Usage: verify_distro <instance> <distro>
# e.g. verify_distro toride-u2404 ubuntu-24.04
verify_distro() {
  local instance="$1" distro="$2"
  local os_release guest_id guest_ver expected_id expected_ver

  os_release="$(limactl shell "$instance" -- cat /etc/os-release 2>/dev/null || true)"
  if [[ -z "$os_release" ]]; then
    error "Could not read /etc/os-release from '$instance'. VM may be broken."
  fi

  guest_id="$(echo "$os_release" | grep '^ID=' | head -1 | cut -d= -f2)"
  guest_ver="$(echo "$os_release" | grep '^VERSION_ID=' | head -1 | cut -d= -f2 | tr -d '"')"

  # ubuntu-24.04 -> ubuntu, 24.04  |  rocky-9 -> rocky, 9
  expected_id="${distro%%-*}"
  expected_ver="${distro#*-}"

  if [[ "$guest_id" != "$expected_id" || "$guest_ver" != "$expected_ver" ]]; then
    error "Guest distro mismatch: expected '$expected_id $expected_ver' but got '$guest_id $guest_ver' (instance '$instance'). Consider delete-and-recreate."
  fi

  info "Guest identity confirmed: $guest_id $guest_ver"
}

# ── Arg parsing ────────────────────────────────────────────────────────────────

DISTRO=""
RECREATE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --recreate) RECREATE=true; shift ;;
    -h|--help)
      echo "Usage: $0 <distro> [--recreate]"
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

[[ -z "$DISTRO" ]] && error "Usage: $0 <distro> [--recreate]  (distros: $ALL_DISTROS)"

INSTANCE="$(distro_to_instance "$DISTRO")" || error "Unknown distro: $DISTRO"
TEMPLATE="$TEMPLATE_DIR/${DISTRO}.yaml"

# ── Validate Lima installation ────────────────────────────────────────────────

info "Checking Lima installation..."

if ! command -v limactl &>/dev/null; then
  error "limactl not found. Install Lima: brew install lima"
fi

LIMA_VERSION="$(limactl --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
if [[ -z "$LIMA_VERSION" ]]; then
  error "Could not detect Lima version."
fi

# Simple version comparison (major.minor.patch)
# Avoids bash 4.0+ features (<<<, ${!arr[@]}) for macOS bash 3.2 compat.
version_gte() {
  local v1="$1" v2="$2"
  local IFS=.
  # shellcheck disable=SC2206
  local a=($v1) b=($v2)
  local i len=${#b[@]}
  for (( i=0; i<len; i++ )); do
    local ai="${a[$i]:-0}"
    local bi="${b[$i]:-0}"
    (( ai > bi )) && return 0
    (( ai < bi )) && return 1
  done
  return 0
}

if ! version_gte "$LIMA_VERSION" "$MINIMUM_LIMA_VERSION"; then
  error "Lima $LIMA_VERSION is older than required $MINIMUM_LIMA_VERSION. Upgrade: brew upgrade lima"
fi

info "Lima $LIMA_VERSION detected (>= $MINIMUM_LIMA_VERSION)"

# ── Validate Lima features ────────────────────────────────────────────────────

# Check that Lima supports the commands/flags we need.
if ! limactl snapshot --help &>/dev/null; then
  warn "Lima snapshot subcommand not found. Snapshots may not be supported."
  warn "Delete-and-recreate will be the only reset path for $DISTRO."
fi

if ! limactl copy --help &>/dev/null; then
  error "Lima 'copy' subcommand not found. Upgrade Lima: brew upgrade lima"
fi

if ! limactl start --list-templates &>/dev/null; then
  error "Lima 'start --list-templates' not supported. Upgrade Lima: brew upgrade lima"
fi

if ! limactl start --help 2>&1 | grep -q -- '--mount-none'; then
  error "Lima 'start --mount-none' not supported. Upgrade Lima: brew upgrade lima"
fi

# ── Validate template ─────────────────────────────────────────────────────────

if [[ ! -f "$TEMPLATE" ]]; then
  error "Template not found: $TEMPLATE"
fi

info "Validating template: $TEMPLATE"
VALIDATE_ERR=""
if ! VALIDATE_ERR="$(limactl validate "$TEMPLATE" 2>&1)"; then
  error "Template validation failed: $TEMPLATE"$'\n'"$VALIDATE_ERR"
fi

# ── Validate local image checksums (when present) ─────────────────────────────

IMAGE_DIR="$IMAGES_DIR/$DISTRO"
if [[ -f "$IMAGE_DIR/SHA256SUMS" ]]; then
  info "Verifying image checksums in $IMAGE_DIR"
  if ! (cd "$IMAGE_DIR" && shasum -a 256 -c SHA256SUMS); then
    error "Image checksum verification failed. Re-download or remove corrupt images."
  fi
  info "Image checksums verified."
else
  if [[ -d "$IMAGE_DIR" ]] && compgen -G "$IMAGE_DIR/*.qcow2" &>/dev/null; then
    warn "Images found in $IMAGE_DIR but no SHA256SUMS file. Skipping checksum verification."
  else
    info "No local images for $DISTRO. Lima will use built-in template or download."
  fi
fi

# ── Handle existing instance ──────────────────────────────────────────────────

if limactl list --format '{{.Name}}' 2>/dev/null | grep -qxF "$INSTANCE"; then
  if [[ "$RECREATE" != true ]]; then
    error "Instance '$INSTANCE' already exists. Use --recreate to delete and recreate."
  fi
  info "Instance '$INSTANCE' exists. Recreating (--recreate)..."
  limactl stop "$INSTANCE" 2>&1 || warn "limactl stop $INSTANCE failed (may already be stopped)"
  limactl delete -f "$INSTANCE" 2>&1 || warn "limactl delete $INSTANCE failed"
fi

# ── Create instance ───────────────────────────────────────────────────────────

info "Creating instance '$INSTANCE' from $DISTRO template..."

# If local images exist, use the custom template.
# Otherwise, fall back to Lima's built-in template.
if [[ -d "$IMAGE_DIR" ]] && compgen -G "$IMAGE_DIR/*.qcow2" &>/dev/null; then
  info "Using local images from $IMAGE_DIR"
  limactl create --tty=false --name="$INSTANCE" --mount-none "$TEMPLATE"
else
  # Fall back to Lima's built-in template
  BUILTIN_TEMPLATE="template:${DISTRO}"
  info "No local images. Trying built-in template: $BUILTIN_TEMPLATE"

  # Check for exact distro name in Lima's template list.
  # Use grep -x for exact line match to avoid partial hits
  # (e.g. "debian" matching "debian-12").
  if limactl start --list-templates 2>/dev/null | grep -qx "$DISTRO"; then
    limactl start --tty=false --name="$INSTANCE" --mount-none "$BUILTIN_TEMPLATE"
  else
    error "Built-in template '$DISTRO' not found in Lima and no local images available. Install a Lima template for $DISTRO or provide images under $IMAGE_DIR"
  fi
fi

# ── Start instance ────────────────────────────────────────────────────────────

info "Starting instance '$INSTANCE'..."
limactl start "$INSTANCE"

# ── Wait for boot readiness ──────────────────────────────────────────────────

info "Waiting for boot readiness..."
sleep 5

# Wait for cloud-init
limactl shell "$INSTANCE" -- bash -c '
  if command -v cloud-init >/dev/null 2>&1; then
    cloud-init status --wait 2>/dev/null || true
  fi
' || true

# Wait for package manager locks to clear (Debian/Ubuntu)
limactl shell "$INSTANCE" -- bash -c '
  if command -v apt-get >/dev/null 2>&1; then
    for i in $(seq 1 30); do
      fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || break
      sleep 2
    done
  fi
' || true

# ── Verify guest identity ────────────────────────────────────────────────────

info "Verifying guest identity..."
verify_distro "$INSTANCE" "$DISTRO"
limactl shell "$INSTANCE" -- uname -a

SYSTEMD_STATUS="$(limactl shell "$INSTANCE" -- systemctl is-system-running 2>/dev/null || echo 'unknown')"
info "systemd status: $SYSTEMD_STATUS"

if [[ "$SYSTEMD_STATUS" == "degraded" ]]; then
  warn "systemd is degraded. Listing failed units:"
  limactl shell "$INSTANCE" -- systemctl --failed --no-pager 2>/dev/null || true
fi

if [[ "$SYSTEMD_STATUS" == "offline" || "$SYSTEMD_STATUS" == "unknown" ]]; then
  warn "systemd is not operational ($SYSTEMD_STATUS). May not be suitable for integration testing."
fi

# ── Create clean snapshot ────────────────────────────────────────────────────

info "Stopping instance to create 'clean' snapshot..."
limactl stop "$INSTANCE"

if limactl snapshot --help &>/dev/null; then
  # Delete existing clean snapshot if present (safe on first create)
  limactl snapshot delete "$INSTANCE" --tag clean 2>/dev/null || true

  info "Creating 'clean' snapshot..."
  if limactl snapshot create "$INSTANCE" --tag clean 2>&1; then
    info "Snapshot 'clean' created."
    limactl snapshot list "$INSTANCE" 2>/dev/null || true
  else
    warn "Snapshot creation failed (VZ driver does not support snapshots in this Lima version)."
    warn "Delete-and-recreate will be the only reset path."
  fi
else
  warn "Snapshot support not available. Delete-and-recreate will be the only reset path."
fi

# ── Final status ──────────────────────────────────────────────────────────────

info "Starting instance '$INSTANCE'..."
limactl start "$INSTANCE"

info "Instance '$INSTANCE' ($DISTRO) is ready."
info ""
info "  Verify:  limactl shell $INSTANCE uname -a"
info "  Reset:   dev/sandbox/lima/scripts/reset.sh $DISTRO"
info "  Destroy: dev/sandbox/lima/scripts/destroy.sh $DISTRO"
