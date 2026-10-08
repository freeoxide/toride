#!/usr/bin/env bash
publish_state::index_prefix() {
  local crate="$1"
  case ${#crate} in
    1) printf '1/%s\n' "$crate" ;;
    2) printf '2/%s\n' "$crate" ;;
    3) printf '3/%s/%s\n' "${crate:0:1}" "$crate" ;;
    *) printf '%s/%s/%s\n' "${crate:0:2}" "${crate:2:2}" "$crate" ;;
  esac
}

publish_state::classify() {
  local status="$1" version="$2" body="$3"
  case "$status" in
    404) printf 'new\n' ;;
    200)
      CLASSIFY_VERSION="$version" CLASSIFY_BODY="$body" python3 - <<'PY'
import json, os, sys

def version_key(v):
    core, _, pre = v.partition("-")
    nums = tuple(int(p) for p in core.split("."))
    return (nums, not pre, pre)

version = os.environ["CLASSIFY_VERSION"]
try:
    vers = []
    for line in os.environ["CLASSIFY_BODY"].splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            vers.append(json.loads(line)["vers"])
        except (ValueError, KeyError, TypeError):
            continue
    if not vers:
        print("unresolved:body")
    elif version in vers:
        print("skip")
    else:
        keys = {v: version_key(v) for v in vers + [version]}
        best = max(vers, key=keys.get)
        print(f"regress:{best}" if keys[best] > keys[version] else "update")
except ValueError:
    print("unresolved:body")
PY
      ;;
    *) printf 'unresolved:%s\n' "$status" ;;
  esac
}

publish_state::classify_api() {
  local status="$1" version="$2" body="$3"
  case "$status" in
    404) printf 'new\n' ;;
    200)
      CLASSIFY_VERSION="$version" CLASSIFY_BODY="$body" python3 - <<'PY'
import json, os

def version_key(v):
    core, _, pre = v.partition("-")
    nums = tuple(int(p) for p in core.split("."))
    return (nums, not pre, pre)

version = os.environ["CLASSIFY_VERSION"]
try:
    data = json.loads(os.environ["CLASSIFY_BODY"])
    nums = [entry.get("num") for entry in data.get("versions", [])]
    nums = [n for n in nums if isinstance(n, str)]
    if not nums:
        print("unresolved:body")
    elif version in nums:
        print("skip")
    else:
        keys = {v: version_key(v) for v in nums + [version]}
        best = max(nums, key=keys.get)
        print(f"regress:{best}" if keys[best] > keys[version] else "update")
except ValueError:
    print("unresolved:body")
PY
      ;;
    *) printf 'unresolved:%s\n' "$status" ;;
  esac
}

publish_state::seconds_until() {
  local timestamp="$1" now="${2:-}" target
  target="$(date -u -d "$timestamp" +%s 2>/dev/null)" || return 1
  if [[ -z "$now" ]]; then
    now="$(date -u +%s)"
  fi
  local delta=$(( target - now ))
  if (( delta > 0 )); then
    printf '%s\n' "$delta"
  else
    printf '0\n'
  fi
}

publish_state::retry_after_seconds() {
  local output="$1" now="${2:-}" timestamp margin wait_for
  margin="${PUBLISH_STATE_429_MARGIN_SECS:-15}"
  case "$margin" in
    ''|*[!0-9]*) margin=15 ;;
  esac
  timestamp="$(printf '%s\n' "$output" | grep -oE 'try again after [A-Za-z]{3}, [0-9]{1,2} [A-Za-z]{3} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT' | head -n 1 | sed 's/^try again after //')" || return 1
  if [[ -z "$timestamp" ]]; then
    return 1
  fi
  wait_for="$(publish_state::seconds_until "$timestamp" "$now")" || return 1
  printf '%s\n' "$(( wait_for + margin ))"
}

publish_state::error_kind() {
  local output="$1"
  if printf '%s' "$output" | grep -qiE 'status 40[13]|unauthorized|forbidden|credential provider|invalid token'; then
    printf 'auth\n'
  elif printf '%s' "$output" | grep -qiE 'status 429|too many requests'; then
    printf 'rate-limit\n'
  elif printf '%s' "$output" | grep -qiE 'status 5[0-9][0-9]|timed out|timeout|connection (reset|refused|closed)|broken pipe|network failure|dns (error|failure)|failed to connect|temporarily unavailable'; then
    printf 'transient\n'
  else
    printf 'fatal\n'
  fi
}
