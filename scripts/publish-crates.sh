#!/usr/bin/env bash
# Publish the toride workspace crates to crates.io in dependency order.
#
# After each publish, poll the crates.io API until the crate is resolvable
# (HTTP 200) or a timeout elapses, so dependent crates can resolve it when
# their own turn comes. cargo publish requires every normal path dependency
# to already exist on the registry, so this order must not be changed.
#
# Requires CARGO_REGISTRY_TOKEN (or an existing `cargo login` session).
set -euo pipefail

CRATES=(
  toride-diagnostic-types
  toride-fs
  toride-installer
  toride-runner
  toride-mise
  toride-service
  toride-audit
  toride-backup
  toride-cloud
  toride-fail2ban
  toride-harden
  toride-monitor
  toride-proxy
  toride-ssh-core
  toride-ssh-agent
  toride-ssh-authorized-keys
  toride-ssh-certificate
  toride-ssh-config
  toride-ssh-doctor
  toride-ssh-forward
  toride-ssh-key
  toride-ssh-known-hosts
  toride-ssh
  toride-status
  toride-tailscale
  toride-updates
  toride-users
  toride-wireguard
  ufw-kit
  toride
  ufw-kit-test-support
)

# Seconds to wait for a freshly published crate to become resolvable.
READINESS_TIMEOUT="${READINESS_TIMEOUT:-30}"
# Seconds between readiness polls.
POLL_INTERVAL="${POLL_INTERVAL:-2}"

wait_until_published() {
  local crate="$1"
  local deadline elapsed status
  deadline=$((SECONDS + READINESS_TIMEOUT))
  while :; do
    status=$(curl -sS -o /dev/null -w '%{http_code}' \
      -A "toride-publish-script/0.1 (https://github.com/freeoxide/toride)" \
      "https://crates.io/api/v1/crates/${crate}") || status="curl-error"
    if [[ "$status" == "200" ]]; then
      echo "ready: ${crate} is published and resolvable"
      return 0
    fi
    if (( SECONDS >= deadline )); then
      echo "error: ${crate} not resolvable on crates.io after ${READINESS_TIMEOUT}s (last status: ${status})" >&2
      return 1
    fi
    echo "waiting for ${crate} to appear on crates.io (status: ${status})..."
    sleep "$POLL_INTERVAL"
  done
}

for crate in "${CRATES[@]}"; do
  echo "==> publishing ${crate}"
  cargo publish -p "$crate"
  wait_until_published "$crate"
done

echo "all ${#CRATES[@]} crates published"
