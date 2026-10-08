#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${script_dir}/publish-state.sh"

pass_count=0
fail_count=0

expect_eq() {
  local description="$1" want="$2" got="$3"
  if [[ "$want" == "$got" ]]; then
    pass_count=$((pass_count + 1))
    printf 'ok %s\n' "$description"
  else
    fail_count=$((fail_count + 1))
    printf 'not ok %s: want %s got %s\n' "$description" "$want" "$got" >&2
  fi
}

expect_failure() {
  local description="$1"
  shift
  if "$@" 2>/dev/null; then
    fail_count=$((fail_count + 1))
    printf 'not ok %s: expected nonzero exit\n' "$description" >&2
  else
    pass_count=$((pass_count + 1))
    printf 'ok %s\n' "$description"
  fi
}

expect_eq "prefix for 1-char name" "1/a" "$(publish_state::index_prefix a)"
expect_eq "prefix for 2-char name" "2/ab" "$(publish_state::index_prefix ab)"
expect_eq "prefix for 3-char name" "3/a/abc" "$(publish_state::index_prefix abc)"
expect_eq "prefix for toride-fs" "to/ri/toride-fs" "$(publish_state::index_prefix toride-fs)"
expect_eq "prefix for ufw-kit" "uf/w-/ufw-kit" "$(publish_state::index_prefix ufw-kit)"

index_one=$'{"name":"toride-runner","vers":"0.1.0","deps":[],"features":{},"yanked":false}\n'
index_two=$'{"name":"toride-fs","vers":"0.1.0","deps":[],"yanked":false}\n{"name":"toride-fs","vers":"0.2.0","deps":[],"yanked":false}\n'
index_higher=$'{"name":"toride-fs","vers":"0.2.0","deps":[],"yanked":false}\n'
index_pre=$'{"name":"toride","vers":"0.2.0-beta.1","deps":[],"yanked":false}\n'
index_xml=$'<?xml version="1.0" encoding="UTF-8"?>\n<Error><Code>NoSuchKey</Code></Error>\n'

expect_eq "index 404 classifies new" "new" "$(publish_state::classify 404 0.1.0 "$index_one")"
expect_eq "index has target version" "skip" "$(publish_state::classify 200 0.1.0 "$index_one")"
expect_eq "index older only" "update" "$(publish_state::classify 200 0.2.0 "$index_one")"
expect_eq "index newer than target" "regress:0.2.0" "$(publish_state::classify 200 0.1.0 "$index_higher")"
expect_eq "target present alongside newer" "skip" "$(publish_state::classify 200 0.2.0 "$index_two")"
expect_eq "prerelease max below target" "update" "$(publish_state::classify 200 0.2.0 "$index_pre")"
expect_eq "index 503 unresolved" "unresolved:503" "$(publish_state::classify 503 0.1.0 "$index_one")"
expect_eq "index 200 non-json body" "unresolved:body" "$(publish_state::classify 200 0.1.0 "$index_xml")"

api_one='{"crate":{"name":"toride-runner","max_version":"0.1.0"},"versions":[{"num":"0.1.0"}]}'
api_higher='{"crate":{"name":"toride-fs","max_version":"0.2.0"},"versions":[{"num":"0.2.0"}]}'
api_garbage='{"errors":[{"detail":"Unexpected response"}]}'

expect_eq "api 404 classifies new" "new" "$(publish_state::classify_api 404 0.1.0 "$api_one")"
expect_eq "api has target version" "skip" "$(publish_state::classify_api 200 0.1.0 "$api_one")"
expect_eq "api older only" "update" "$(publish_state::classify_api 200 0.2.0 "$api_one")"
expect_eq "api newer than target" "regress:0.2.0" "$(publish_state::classify_api 200 0.1.0 "$api_higher")"
expect_eq "api 200 body without versions" "unresolved:body" "$(publish_state::classify_api 200 0.1.0 "$api_garbage")"
expect_eq "api 500 unresolved" "unresolved:500" "$(publish_state::classify_api 500 0.1.0 "$api_one")"

rfc1123="Thu, 08 Oct 2026 10:13:28 GMT"
expect_eq "seconds_until future" "108" "$(publish_state::seconds_until "$rfc1123" 1791454300)"
expect_eq "seconds_until exact" "0" "$(publish_state::seconds_until "$rfc1123" 1791454408)"
expect_eq "seconds_until past" "0" "$(publish_state::seconds_until "$rfc1123" 1791454500)"
expect_failure "seconds_until rejects garbage" publish_state::seconds_until "not a timestamp" 1791454300

rate_body="error: failed to publish to registry

Caused by:
  the server responded with status 429 Too Many Requests

  You have published too many new crates in a short period of time. Please try again after ${rfc1123}"

expect_eq "retry_after parses window plus margin" "123" "$(publish_state::retry_after_seconds "$rate_body" 1791454300)"
expect_eq "retry_after honors margin override" "108" "$(PUBLISH_STATE_429_MARGIN_SECS=0 publish_state::retry_after_seconds "$rate_body" 1791454300)"
expect_failure "retry_after without timestamp" publish_state::retry_after_seconds "error: status 429 Too Many Requests" 1791454300
expect_failure "retry_after malformed timestamp" publish_state::retry_after_seconds "Please try again after soon-ish" 1791454300

auth_body="error: failed to publish to registry

Caused by:
  the server responded with status 401 Unauthorized"

expect_eq "401 is auth" "auth" "$(publish_state::error_kind "$auth_body")"
expect_eq "forbidden is auth" "auth" "$(publish_state::error_kind 'the server responded with status 403 Forbidden')"
expect_eq "429 is rate-limit" "rate-limit" "$(publish_state::error_kind "$rate_body")"
expect_eq "too many requests is rate-limit" "rate-limit" "$(publish_state::error_kind 'status 429: Too Many Requests')"
expect_eq "503 is transient" "transient" "$(publish_state::error_kind 'the server responded with status 503 Service Unavailable')"
expect_eq "network timeout is transient" "transient" "$(publish_state::error_kind 'error: network failure seems to have happened; the request timed out')"
expect_eq "connection reset is transient" "transient" "$(publish_state::error_kind 'error: Connection reset by peer (os error 104)')"
expect_eq "packaging error is fatal" "fatal" "$(publish_state::error_kind 'error: failed to verify the tarball')"
expect_eq "auth outranks rate-limit" "auth" "$(publish_state::error_kind 'status 403 Forbidden while 429 Too Many Requests was expected')"

printf 'passed %d, failed %d\n' "$pass_count" "$fail_count"
if (( fail_count > 0 )); then
  exit 1
fi
