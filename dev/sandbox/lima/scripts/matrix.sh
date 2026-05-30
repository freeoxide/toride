#!/usr/bin/env bash
# matrix.sh — Run a command against multiple Lima sandbox VMs.
# See docs/lima-sandbox.md → Script Contracts → matrix.sh
#
# Usage:
#   dev/sandbox/lima/scripts/matrix.sh ubuntu-24.04 debian-13 rocky-10
#   dev/sandbox/lima/scripts/matrix.sh --all
#   dev/sandbox/lima/scripts/matrix.sh --all --fail-fast
#   dev/sandbox/lima/scripts/matrix.sh --primary
#
set -euo pipefail

# ── Constants ──────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ALL_DISTROS=(ubuntu-24.04 ubuntu-26.04 debian-12 debian-13 rocky-9 rocky-10)
PRIMARY_DISTROS=(ubuntu-24.04 ubuntu-26.04 debian-12 debian-13)

# ── Helpers ────────────────────────────────────────────────────────────────────

info()  { printf '\033[1;34m[matrix]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[matrix]\033[0m %s\n' "$*" >&2; }
error() { printf '\033[1;31m[matrix]\033[0m %s\n' "$*" >&2; exit 1; }

# ── Arg parsing ────────────────────────────────────────────────────────────────

DISTROS=()
FAIL_FAST=false
COMMAND="run"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --all)      DISTROS=("${ALL_DISTROS[@]}"); shift ;;
    --primary)  DISTROS=("${PRIMARY_DISTROS[@]}"); shift ;;
    --fail-fast) FAIL_FAST=true; shift ;;
    --create)   COMMAND="create"; shift ;;
    --reset)    COMMAND="reset"; shift ;;
    --destroy)  COMMAND="destroy"; shift ;;
    --run)      COMMAND="run"; shift ;;
    -h|--help)
      echo "Usage: $0 [distro...] [options]"
      echo ""
      echo "Distros:"
      echo "  ubuntu-24.04  ubuntu-26.04  debian-12  debian-13  rocky-9  rocky-10"
      echo ""
      echo "Selectors:"
      echo "  --all        Run against all supported distros"
      echo "  --primary    Run against primary distros (Ubuntu + Debian)"
      echo ""
      echo "Options:"
      echo "  --fail-fast  Stop on first failure"
      echo ""
      echo "Commands (default: run):"
      echo "  --create     Run create.sh for each distro"
      echo "  --reset      Run reset.sh for each distro"
      echo "  --destroy    Run destroy.sh for each distro"
      echo "  --run        Run run.sh for each distro (default)"
      echo ""
      echo "Examples:"
      echo "  $0 --all --create"
      echo "  $0 --primary --run --fail-fast"
      echo "  $0 ubuntu-24.04 debian-13 --destroy"
      exit 0
      ;;
    *)
      DISTROS+=("$1")
      shift
      ;;
  esac
done

if [[ ${#DISTROS[@]} -eq 0 ]]; then
  error "No distros specified. Use --all, --primary, or list distros explicitly."
fi

# ── Resolve script for command ────────────────────────────────────────────────

case "$COMMAND" in
  create)  RUN_SCRIPT="$SCRIPT_DIR/create.sh" ;;
  reset)   RUN_SCRIPT="$SCRIPT_DIR/reset.sh" ;;
  destroy) RUN_SCRIPT="$SCRIPT_DIR/destroy.sh" ;;
  run)     RUN_SCRIPT="$SCRIPT_DIR/run.sh" ;;
  *)       error "Unknown command: $COMMAND" ;;
esac

if [[ ! -x "$RUN_SCRIPT" ]]; then
  error "Script not found or not executable: $RUN_SCRIPT"
fi

# ── Execute per distro ────────────────────────────────────────────────────────

FAILED=()
SUCCEEDED=()

info "Running '$COMMAND' against ${#DISTROS[@]} distro(s): ${DISTROS[*]}"

for distro in "${DISTROS[@]}"; do
  info ""
  info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  info "  $distro — $COMMAND"
  info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  if "$RUN_SCRIPT" "$distro"; then
    SUCCEEDED+=("$distro")
    info "✓ $distro — $COMMAND succeeded"
  else
    FAILED+=("$distro")
    warn "✗ $distro — $COMMAND failed (exit code $?)"
    if [[ "$FAIL_FAST" == true ]]; then
      error "Fail-fast: stopping after $distro failure."
    fi
  fi
done

# ── Summary ───────────────────────────────────────────────────────────────────

info ""
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "  Matrix summary: $COMMAND"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ ${#SUCCEEDED[@]} -gt 0 ]]; then
  info "  Succeeded (${#SUCCEEDED[@]}): ${SUCCEEDED[*]}"
fi
if [[ ${#FAILED[@]} -gt 0 ]]; then
  warn "  Failed (${#FAILED[@]}): ${FAILED[*]}"
fi

info "  Total: ${#DISTROS[@]} | Passed: ${#SUCCEEDED[@]} | Failed: ${#FAILED[@]}"

# Exit non-zero if any distro failed
if [[ ${#FAILED[@]} -gt 0 ]]; then
  exit 1
fi

exit 0
