#!/usr/bin/env bash
# run.sh — Build or accept a Toride binary and run it in a sandbox VM.
# See docs/lima-sandbox.md → Script Contracts → run.sh
#
# Usage:
#   dev/sandbox/lima/scripts/run.sh ubuntu-24.04
#   dev/sandbox/lima/scripts/run.sh ubuntu-24.04 --profile sandbox
#   dev/sandbox/lima/scripts/run.sh ubuntu-24.04 --binary ./target/aarch64-unknown-linux-musl/release/toride
#   dev/sandbox/lima/scripts/run.sh ubuntu-24.04 --skip-reset
#   dev/sandbox/lima/scripts/run.sh ubuntu-24.04 --apply
#   dev/sandbox/lima/scripts/run.sh ubuntu-24.04 --collect-only
#
set -euo pipefail

# ── Constants ──────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$SANDBOX_DIR/../.." && pwd)"
ARTIFACTS_DIR="$REPO_ROOT/.sandbox-artifacts"

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

info()  { printf '\033[1;34m[run]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[run]\033[0m %s\n' "$*" >&2; }
error() { printf '\033[1;31m[run]\033[0m %s\n' "$*" >&2; exit 1; }

# ── Arg parsing ────────────────────────────────────────────────────────────────

DISTRO=""
BINARY=""
PROFILE="sandbox"
SKIP_RESET=false
APPLY=false
COLLECT_ONLY=false
BUILD=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)    BINARY="$2"; BUILD=false; shift 2 ;;
    --profile)   PROFILE="$2"; shift 2 ;;
    --skip-reset) SKIP_RESET=true; shift ;;
    --apply)     APPLY=true; shift ;;
    --collect-only) COLLECT_ONLY=true; shift ;;
    --no-build)  BUILD=false; shift ;;
    -h|--help)
      echo "Usage: $0 <distro> [options]"
      echo ""
      echo "Options:"
      echo "  --binary PATH       Use pre-built binary instead of building"
      echo "  --profile NAME      Toride profile (default: sandbox)"
      echo "  --skip-reset        Skip VM reset before running"
      echo "  --apply             Run apply after dry-run"
      echo "  --collect-only      Only collect artifacts (no binary/run)"
      echo "  --no-build          Skip building, require --binary"
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

[[ -z "$DISTRO" ]] && error "Usage: $0 <distro> [options]  (distros: $ALL_DISTROS)"
INSTANCE="$(distro_to_instance "$DISTRO")" || error "Unknown distro: $DISTRO"

# ── Artifact directory ────────────────────────────────────────────────────────

ARTIFACT_DIR="$ARTIFACTS_DIR/$INSTANCE"
mkdir -p "$ARTIFACT_DIR"

# ── Artifact collection (defined early for --collect-only) ────────────────────

collect_artifacts() {
  info "Collecting artifacts to $ARTIFACT_DIR..."

  limactl shell "$INSTANCE" -- journalctl -b --no-pager > "$ARTIFACT_DIR/journal.txt" 2>/dev/null || true
  limactl shell "$INSTANCE" -- systemctl --failed --no-pager > "$ARTIFACT_DIR/systemd-failed.txt" 2>/dev/null || true
  limactl shell "$INSTANCE" -- cat /etc/os-release > "$ARTIFACT_DIR/os-release.txt" 2>/dev/null || true
  limactl shell "$INSTANCE" -- ss -tulpn > "$ARTIFACT_DIR/ports.txt" 2>/dev/null || true

  # Debian/Ubuntu artifacts
  if limactl shell "$INSTANCE" -- command -v apt-get &>/dev/null; then
    limactl shell "$INSTANCE" -- sudo tail -n 300 /var/log/apt/history.log > "$ARTIFACT_DIR/apt-history.txt" 2>/dev/null || true
    limactl shell "$INSTANCE" -- sudo tail -n 500 /var/log/dpkg.log > "$ARTIFACT_DIR/dpkg.txt" 2>/dev/null || true
  fi

  # Rocky/EL artifacts
  if limactl shell "$INSTANCE" -- command -v dnf &>/dev/null; then
    limactl shell "$INSTANCE" -- sudo dnf history > "$ARTIFACT_DIR/dnf-history.txt" 2>/dev/null || true
    limactl shell "$INSTANCE" -- rpm -qa > "$ARTIFACT_DIR/rpm-qa.txt" 2>/dev/null || true
  fi

  # Toride-specific logs
  limactl shell "$INSTANCE" -- bash -lc 'find ~/.local/state ~/.cache /var/log -iname "*toride*" 2>/dev/null' \
    | while read -r f; do
        limactl shell "$INSTANCE" -- cat "$f" > "$ARTIFACT_DIR/$(basename "$f")" 2>/dev/null || true
      done

  info "Artifacts collected in $ARTIFACT_DIR"
}

# ── Collect-only mode ─────────────────────────────────────────────────────────

if [[ "$COLLECT_ONLY" == true ]]; then
  info "Collect-only mode. Skipping build, reset, and run."
  collect_artifacts
  exit 0
fi

# ── Reset the VM ──────────────────────────────────────────────────────────────

if [[ "$SKIP_RESET" != true ]]; then
  info "Resetting VM to clean state..."
  "$SCRIPT_DIR/reset.sh" "$DISTRO"
fi

# ── Determine guest architecture ──────────────────────────────────────────────

info "Detecting guest architecture..."
GUEST_ARCH="$(limactl shell "$INSTANCE" -- uname -m)"
info "Guest architecture: $GUEST_ARCH"

case "$GUEST_ARCH" in
  aarch64|arm64) RUST_TARGET="aarch64-unknown-linux-musl" ;;
  x86_64|amd64)  RUST_TARGET="x86_64-unknown-linux-musl" ;;
  *) error "Unsupported guest architecture: $GUEST_ARCH" ;;
esac

# ── Build or validate binary ─────────────────────────────────────────────────

if [[ -z "$BINARY" ]]; then
  if [[ "$BUILD" == true ]]; then
    info "Building Toride for $RUST_TARGET..."

    if ! command -v cargo-zigbuild &>/dev/null && ! cargo zigbuild --version &>/dev/null 2>&1; then
      error "cargo-zigbuild not found. Install: cargo install cargo-zigbuild && brew install zig"
    fi

    (cd "$REPO_ROOT" && cargo zigbuild --release --target "$RUST_TARGET")
    BINARY="$REPO_ROOT/target/$RUST_TARGET/release/toride"
  else
    error "No binary specified and --no-build set. Use --binary PATH or remove --no-build."
  fi
fi

# ── Reject macOS binaries ────────────────────────────────────────────────────

if [[ -f "$BINARY" ]]; then
  BINARY_TYPE="$(file "$BINARY" 2>/dev/null || true)"
  if echo "$BINARY_TYPE" | grep -qi "mach-o"; then
    error "Binary '$BINARY' is a macOS binary (Mach-O). Cannot run in Linux guest."
  fi
  if ! echo "$BINARY_TYPE" | grep -qi "elf"; then
    warn "Binary '$BINARY' does not appear to be a Linux ELF binary. Type: $BINARY_TYPE"
  fi
else
  error "Binary not found: $BINARY"
fi

# ── Copy binary into guest ────────────────────────────────────────────────────

info "Copying binary into guest..."
limactl copy "$BINARY" "$INSTANCE:/tmp/toride"
limactl shell "$INSTANCE" -- chmod +x /tmp/toride

# ── Verify binary executes ────────────────────────────────────────────────────

info "Verifying binary executes in guest..."
if ! limactl shell "$INSTANCE" -- /tmp/toride --version 2>/dev/null && \
   ! limactl shell "$INSTANCE" -- /tmp/toride 2>/dev/null; then
  error "Binary failed to execute in guest. Check architecture compatibility."
fi
info "Binary is executable in guest."

# ── Run dry-run ───────────────────────────────────────────────────────────────

info "Running Toride dry-run..."
DRY_RUN_LOG="$ARTIFACT_DIR/dry-run.log"

if limactl shell "$INSTANCE" -- /tmp/toride --dry-run --profile "$PROFILE" 2>&1 | tee "$DRY_RUN_LOG"; then
  info "Dry-run completed."
else
  DRY_EXIT=$?
  warn "Dry-run exited with code $DRY_EXIT. Check $DRY_RUN_LOG"
fi

# ── Run apply (optional) ────────────────────────────────────────────────────

if [[ "$APPLY" == true ]]; then
  info "Running Toride apply..."
  APPLY_LOG="$ARTIFACT_DIR/apply.log"

  if limactl shell "$INSTANCE" -- sudo /tmp/toride apply --profile "$PROFILE" 2>&1 | tee "$APPLY_LOG"; then
    info "Apply completed."
  else
    APPLY_EXIT=$?
    warn "Apply exited with code $APPLY_EXIT. Check $APPLY_LOG"
    warn "Lima SSH may be broken if apply modified SSH/firewall settings."
  fi
fi

# ── Collect artifacts ─────────────────────────────────────────────────────────

collect_artifacts

info "Done. Instance '$INSTANCE' ($DISTRO) is in post-test state."
info "  Reset:   dev/sandbox/lima/scripts/reset.sh $DISTRO"
info "  Destroy: dev/sandbox/lima/scripts/destroy.sh $DISTRO"
